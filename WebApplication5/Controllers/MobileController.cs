using System.Security.Cryptography.X509Certificates;
using ClassLibrary1.Utilities;
using Common.MessageDefinitions;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace WebApplication5.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class MobileController : ControllerBase
    {
        #region ...

        private static readonly string _deviceId = Guid.NewGuid().ToString();
        private static readonly Dictionary<string, Object> _db = new Dictionary<string, object>();

        #endregion

        [HttpGet("activate")]
        public async Task<IActionResult> Start()
        {
            var K1 = SecurityUtilities.GenerateRSAKeyPair();
            var C2 = GenerateCustomerSigningCertificate(_deviceId, K1);

            var R = await HandShake(K1);

            Persist($"{_deviceId}.K1", K1);
            Persist($"{_deviceId}.C2", C2);
            Persist($"{_deviceId}.K2", R.K2);
            Persist($"{_deviceId}.C1", R.C1);

            return Ok(new
            {
            });
        }

        [HttpGet("Login")]
        public async Task<IActionResult> Login()
        {
            var C1 = Get<string>($"{_deviceId}.C1");
            var K1 = Get<KeyPair>($"{_deviceId}.K1");

            var R1 = await InitiateLogin(C1);
            var R2 = await VerifyLogin(C1, K1, R1);

            return Ok(new
            {
            });
        }

        #region helpers.

        private async Task<InitiateActivationResponse> HandShake(KeyPair K1)
        {
            var request = new InitiateActivationRequest()
            {
                DeviceId = _deviceId,
                K1PublicKey = K1.PublicKey,
            };

            var responseJon = await WebUtilities.Post(baseUrl: "https://localhost:7118/",
                                                      requestUrl: "ss/activate",
                                                      request: request);

            var response = JsonConvert.DeserializeObject<InitiateActivationResponse>(responseJon);

            return response;
        }
        private async Task<LoginActivationResponse> InitiateLogin(string C1)
        {
            var C1_x509 = new X509Certificate2(Convert.FromBase64String(C1));
            //var C1_x509 = new X509Certificate2(Convert.FromBase64String(C1), pfxPassword, X509KeyStorageFlags.MachineKeySet);

            var request = new LoginActivationRequest()
            {
                DeviceId = _deviceId,
            };

            var responseJon = await WebUtilities.Post(baseUrl: "https://localhost:7118/",
                                                      requestUrl: "ss/initiatelogin",
                                                      request: request,
                                                      clientCertificate: C1_x509);

            var response = JsonConvert.DeserializeObject<LoginActivationResponse>(responseJon);

            return response;
        }
        private async Task<LoginVerificationResponse> VerifyLogin(string C1, KeyPair K1, ChallengeRequest challenge)
        {
            var nonce = SecurityUtilities.DecryptContent(challenge.Challenge, K1.PrivateKey);
            var NonceSignature = SecurityUtilities.SignContent(nonce, K1.PrivateKey);

            var C1_x509 = new X509Certificate2(Convert.FromBase64String(C1));
            //var C1_x509 = new X509Certificate2(Convert.FromBase64String(C1), pfxPassword, X509KeyStorageFlags.MachineKeySet);

            var request = new LoginVerificationRequest()
            {
                DeviceId = _deviceId,
                Challenge = nonce,
                ChallengeSignature = NonceSignature,
                Username = "x",
                Password = "y",
            };

            var responseJon = await WebUtilities.Post(baseUrl: "https://localhost:7118/",
                                                      requestUrl: "ss/verifylogin",
                                                      request: request,
                                                      clientCertificate: C1_x509);

            var response = JsonConvert.DeserializeObject<LoginVerificationResponse>(responseJon);

            return response;
        }

        private string GenerateCustomerSigningCertificate(string? deviceId, KeyPair keyPair)
        {
            var C2_cer = SecurityUtilities.GenerateSelfSignedCertificate(pemPublicKey: keyPair.PublicKey,
                                                                          pemPrivateKey: keyPair.PrivateKey,
                                                                          issuer: $"CN=VP.SDK",
                                                                          subject: $"CN={deviceId}.C2",
                                                                          validFrom: DateTimeOffset.Now,
                                                                          validUntil: DateTimeOffset.Now.AddDays(90));
            var C2_pfx = SecurityUtilities.ToPFX(C2_cer);

            return Convert.ToBase64String(C2_pfx);
        }

        private void Persist<T>(string id, T item)
        {
            _db.Add(id, item);
        }
        private T? Get<T>(string id)
        {
            _db.TryGetValue(id, out object? item);
            return (T?) item;
        }

        #endregion
    }
}
