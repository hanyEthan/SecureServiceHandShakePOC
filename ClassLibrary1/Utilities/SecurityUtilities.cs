using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Common.MessageDefinitions;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ClassLibrary1.Utilities
{
    public static class SecurityUtilities
    {
        public static KeyPair GenerateRSAKeyPair(int keySize = 2048)
        {
            using (var rsa = RSA.Create(keySize))
            {
                var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());
                var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());

                return new KeyPair()
                {
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                };
            }
        }

        public static X509Certificate2 GenerateSelfSignedCertificate(KeyPair keyPair, 
                                                                     string certificateSubject,
                                                                     DateTimeOffset validFrom,
                                                                     DateTimeOffset validUntil)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(Convert.FromBase64String(keyPair.PublicKey), out _);

                var certificateRequest = new CertificateRequest($"cn={certificateSubject}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                var certificate = certificateRequest.CreateSelfSigned(validFrom, validUntil);

                return certificate.CopyWithPrivateKey(rsa); // Include the private key
            }
        }
        public static byte[] GenerateSelfSignedCertificatePfx(KeyPair keyPair,
                                                              string certificateSubject,
                                                              DateTimeOffset validFrom,
                                                              DateTimeOffset validUntil)
        {
            var vertificate = GenerateSelfSignedCertificate(keyPair: keyPair,
                                                            certificateSubject: certificateSubject,
                                                            validFrom: validFrom,
                                                            validUntil: validUntil);
            
            var pfx = vertificate.Export(X509ContentType.Pfx);

            return pfx;
        }
        public static string ExtractRSAPublicKeyFromCertificate(X509Certificate2 certificate)
        {
            using (var rsa = certificate.GetRSAPublicKey())
            {
                return Convert.ToBase64String(rsa.ExportRSAPublicKey());
            }
        }
        public static string GenerateSecureNonceChallenge()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                const int byteLength = 32;  // Adjust as needed, security trade-off 
                var randomBytes = new byte[byteLength];
                rng.GetBytes(randomBytes);

                return Convert.ToBase64String(randomBytes)
                              .TrimEnd('=')
                              .Replace('+', '-')
                              .Replace('/', '_');
            }
        }
        
        public static string EncryptContent(string content, string publicKey)
        {
            var contentBytes = Encoding.UTF8.GetBytes(content);

            using (var rsa = RSA.Create())
            {
                var pubKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));

                var encryptEngine = new OaepEncoding(new RsaEngine(), new Sha256Digest());
                encryptEngine.Init(true, pubKeyParam);

                var encryptedBytes = encryptEngine.ProcessBlock(contentBytes, 0, contentBytes.Length);
                return Convert.ToBase64String(encryptedBytes);
            }
        }
        public static string DecryptContent(string content, string privateKey)
        {
            var encryptedBytes = Convert.FromBase64String(content);

            using (var rsa = RSA.Create())
            {
                var privKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

                var decryptEngine = new OaepEncoding(new RsaEngine(), new Sha256Digest()); // Adjust hash choice if needed
                decryptEngine.Init(false, privKeyParam);

                var decryptedBytes = decryptEngine.ProcessBlock(encryptedBytes, 0, encryptedBytes.Length);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
        public static string SignContent(string content, string privateKey)
        {
            using (var rsa = RSA.Create())
            {
                rsa.ImportFromPem(privateKey);

                // Important: Proper Hashing and Signing Logic
                var challengeBytes = Encoding.UTF8.GetBytes(content);
                var hash = SHA256.HashData(challengeBytes); // Or chosen SHA family function

                var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                return Convert.ToBase64String(signature);
            }
        }
        public static bool VerifySignedContent(string content, string signature, string publicKey)
        {
            var signatureBytes = Convert.FromBase64String(signature);
            using (var rsa = RSA.Create())
            {
                rsa.ImportFromPem(publicKey);

                //  Get Hashed version of original content
                var contentBytes = Encoding.UTF8.GetBytes(content);
                var challengeHash = SHA256.HashData(contentBytes);

                return rsa.VerifyHash(challengeHash, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
