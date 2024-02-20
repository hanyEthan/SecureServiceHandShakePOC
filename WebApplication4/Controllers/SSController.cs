using ClassLibrary1.Utilities;
using Common.MessageDefinitions;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication4.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class SSController : ControllerBase
    {
        #region ...

        private static readonly Dictionary<string, Object> _db = new Dictionary<string, object>();

        #endregion

        [HttpPost("activate")]
        public async Task<IActionResult> InitiateActivation([FromBody] InitiateActivationRequest request)
        {
            ValidateSDKInfo(request);

            var deviceId = request.DeviceId;

            var K1 = new KeyPair() { PublicKey = request.K1PublicKey };
            var K2 = SecurityUtilities.GenerateRSAKeyPair();

            var C1 = GenerateClientCertificate(K2);
            var C2 = GenerateCustomerSigningCertificate(K1);

            Persist($"{deviceId}.C2", C2);
            Persist($"{deviceId}.K2.public", K2.PublicKey);
            Persist($"{deviceId}.K1.public", K1.PublicKey);

            return Ok(new InitiateActivationResponse()
            {
                K2 = K2,
                C1 = C1,
                C2 = C2,
            });
        }

        [HttpPost("initiatelogin")]
        [ServiceFilter(typeof(RequireMTLSFilter))]
        public async Task<IActionResult> LoginActivation([FromBody] LoginActivationRequest request)
        {
            var context = new Dictionary<string, object>()
            {
                { "C1", base.HttpContext.Connection.ClientCertificate },
                { "C2", Get<string>($"{request.DeviceId}.C2") },
                { "K2_publicKey_extracted", SecurityUtilities.ExtractRSAPublicKeyFromCertificate(base.HttpContext.Connection.ClientCertificate) },
                { "K2_publicKey_stored", Get<string>($"{request.DeviceId}.K2.public") },
                { "K1_publicKey_stored", Get<string>($"{request.DeviceId}.K1.public") },
            };

            if (!IsValidDeviceIdentity(context))
            {
                return Unauthorized("Invalid Device");
            }

            var challenge = GenerateNonceChallenge(context);
            Persist($"{request.DeviceId}.challenge", challenge);
            
            // todo : for challenge storage, here're our options ...
            //     1. session store (not recommended, stateful).
            //     2. JWT token (reommended, stateless).
            //     3. DB store (not recommended, stateful).

            return Ok(new ChallengeRequest()
            {
                Challenge = challenge,
            });
        }

        [HttpPost("verifylogin")]
        [ServiceFilter(typeof(RequireMTLSFilter))]
        public async Task<IActionResult> LoginVerification([FromBody] LoginVerificationRequest request)
        {
            var context = new Dictionary<string, object>()
            {
                { "C1", base.HttpContext.Connection.ClientCertificate },
                { "C2", Get<string>($"{request.DeviceId}.C2") },
                { "K2_publicKey_extracted", SecurityUtilities.ExtractRSAPublicKeyFromCertificate(base.HttpContext.Connection.ClientCertificate) },
                { "K2_publicKey_stored", Get<string>($"{request.DeviceId}.K2.public") },
                { "challenge_extracted", request.Challenge },
                { "challenge_stored", Get<string>($"{request.DeviceId}.challenge") },
                { "challengeSignature", request.ChallengeSignature },
                { "K1_publicKey_stored", Get<string>($"{request.DeviceId}.K1.public") },
            };

            if (!IsValidDeviceIdentity(context))
            {
                return Unauthorized("Invalid Device");
            }

            if (!VerifyNonceChallenge(context))
            {
                return Unauthorized("Invalid challenge");
            }

            if (!IsValidCredentials(request.Username, request.Password))
            {
                return Unauthorized("Invalid user");
            }

            return Ok(new LoginVerificationResponse()
            {
                Success = true,
            });
        }

        #region helpers.

        private void ValidateSDKInfo(InitiateActivationRequest request)
        {
        }
        private string GenerateClientCertificate(KeyPair keyPair)
        {
            var C1 = SecurityUtilities.GenerateSelfSignedCertificatePfx(keyPair: keyPair,
                                                                        certificateSubject: "ClientCertSubject",
                                                                        validFrom: DateTimeOffset.Now,
                                                                        validUntil: DateTimeOffset.Now.AddDays(90));

            return Convert.ToBase64String(C1);
        }
        private string GenerateCustomerSigningCertificate(KeyPair keyPair)
        {
            var C2 = SecurityUtilities.GenerateSelfSignedCertificatePfx(keyPair: keyPair,
                                                                        certificateSubject: "ClientCertSubject",
                                                                        validFrom: DateTimeOffset.Now,
                                                                        validUntil: DateTimeOffset.Now.AddDays(90));

            return Convert.ToBase64String(C2);
        }
        private void Persist<T>(string id, T item)
        {
            _db.Add(id, item);
        }
        private T? Get<T>(string id)
        {
            _db.TryGetValue(id, out object? item);
            return (T?)item;
        }

        private bool IsValidCredentials(string? username, string? password)
        {
            // todo : validate username/password.
         
            return true;
        }
        private bool IsValidDeviceIdentity(Dictionary<string, object> context)
        {
            var isValid = true;

            // validate client certificate
            var K2_extracted = context["K2_publicKey_extracted"];
            var K2_stored = context["K2_publicKey_stored"];
            isValid = isValid
                    && K2_extracted != null
                    && K2_stored != null
                    && string.Equals((string)K2_extracted, (string)K2_stored);

            // todo : check device pairing and authoriation against some list in our system.
            // todo : check if certificate is revoked against some list in our system.

            return isValid;
        }
        private string GenerateNonceChallenge(Dictionary<string, object> context)
        {
            var K1_publicKey = (string)context["K1_publicKey_stored"];
            var nonceChallenge = SecurityUtilities.GenerateSecureNonceChallenge();
            var nonceChallengeEncrypted = SecurityUtilities.EncryptContent(nonceChallenge, K1_publicKey);

            return nonceChallengeEncrypted;
        }
        private bool VerifyNonceChallenge(Dictionary<string, object> context)
        {
            var challenge_extracted = (string) context["challenge_extracted"];
            var challenge_stored = (string) context["challenge_stored"];
            var signature = (string) context["challengeSignature"];
            var publicKey = (string) context["K1_publicKey_stored"];

            return string.Equals(challenge_extracted, challenge_stored)
                && SecurityUtilities.VerifySignedContent(challenge_stored, signature, publicKey);
        }

        #endregion
    }
}
