using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Common.MessageDefinitions;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace ClassLibrary1.Utilities
{
    public static class SecurityUtilities
    {
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
            var publicKeyParam = FromPemToRSAPublicKey(publicKey);
            var publicKeyParamRSA = (RsaKeyParameters)publicKeyParam;

            var encryptEngine = new OaepEncoding(new RsaEngine(), new Sha256Digest());
            encryptEngine.Init(true, publicKeyParamRSA);

            var encryptedBytes = encryptEngine.ProcessBlock(contentBytes, 0, contentBytes.Length);
            return Convert.ToBase64String(encryptedBytes);
        }
        public static string DecryptContent(string content, string privateKey)
        {
            var encryptedBytes = Convert.FromBase64String(content);

            var privateKeyParam = FromPemToRSAPrivateKey(privateKey);
            var privateKeyParamRSA = (RsaPrivateCrtKeyParameters)privateKeyParam;

            var decryptEngine = new OaepEncoding(new RsaEngine(), new Sha256Digest()); // Adjust hash choice if needed
            decryptEngine.Init(false, privateKeyParamRSA);

            var decryptedBytes = decryptEngine.ProcessBlock(encryptedBytes, 0, encryptedBytes.Length);
            return Encoding.UTF8.GetString(decryptedBytes);
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

        public static X509Certificate2 GenerateSelfSignedCertificate(string pemPublicKey,
                                                                     string pemPrivateKey,
                                                                     string issuer,
                                                                     string subject,
                                                                     DateTimeOffset validFrom,
                                                                     DateTimeOffset validUntil)
        {
            var eeKey = FromPemToRSAKeyPair(pemPrivateKey);

            var privateKey = eeKey.Private;
            var publicKey = eeKey.Public;

            var issuerParam = new X509Name(issuer);
            var subjectParam = new X509Name(subject);
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), _secureRandom);

            var signatureFactory = privateKey is ECPrivateKeyParameters
                                 ? new Asn1SignatureFactory(X9ObjectIdentifiers.ECDsaWithSha256.ToString(), privateKey)
                                 : new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), privateKey);

            var certGenerator = new X509V3CertificateGenerator();
            certGenerator.SetIssuerDN(issuerParam);
            certGenerator.SetSubjectDN(subjectParam);
            certGenerator.SetSerialNumber(serialNumber);
            certGenerator.SetNotAfter(validUntil.DateTime);
            certGenerator.SetNotBefore(validFrom.DateTime);
            certGenerator.SetPublicKey(publicKey);

            var certificate = certGenerator.Generate(signatureFactory);
            var certificate_native1 = Org.BouncyCastle.Security.DotNetUtilities.ToX509Certificate(certificate);
            var certificate_native2 = new X509Certificate2(certificate_native1);

            return certificate_native2;
        }
        public static byte[] ToPFX(X509Certificate2 certificate)
        {
            return certificate.Export(X509ContentType.Pfx);
        }
        public static KeyPair GenerateRSAKeyPair(int keySize = 2048)
        {
            AsymmetricCipherKeyPair cipherKeyPair = GenerateRSACipherKeyPair(keySize);
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)cipherKeyPair.Private);
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
            csp.ImportParameters(rsaParams);

            var keyPair = new KeyPair()
            {
                PrivateKey = ExportPrivateKey(csp),
                PublicKey = ExportPublicKey(csp),
            };

            return keyPair;
        }
        public static X509Certificate2 ExtractCertificateFromPem(string pemString)
        {
            using (var reader = new StringReader(pemString))
            {
                var pemObject = new PemReader(reader).ReadObject();
                if (!(pemObject is Org.BouncyCastle.X509.X509Certificate)) // Type Check 
                {
                    throw new ArgumentException("PEM string does not contain a certificate");
                }

                var certificate = (Org.BouncyCastle.X509.X509Certificate)pemObject;
                var certificate_native1 = Org.BouncyCastle.Security.DotNetUtilities.ToX509Certificate(certificate);
                var certificate_native2 = new X509Certificate2(certificate_native1);

                return certificate_native2;
            }
        }

        #region helpers.

        private static readonly SecureRandom _secureRandom = new SecureRandom();
        private static AsymmetricCipherKeyPair GenerateRSACipherKeyPair(int keySize = 2048)
        {
            var param = new KeyGenerationParameters(_secureRandom, keySize);

            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(param);

            var keys = keyGen.GenerateKeyPair();
            return keys;
        }

        private static AsymmetricKeyParameter FromPemToRSAPublicKey(string pemPublicKey)
        {
            using (var sr = new StringReader(pemPublicKey))
            {
                PemReader pr = new PemReader(sr);
                AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();

                return publicKey;
            }
        }
        private static AsymmetricKeyParameter FromPemToRSAPrivateKey(string pemPrivateKey)
        {
            using (var sr = new StringReader(pemPrivateKey))
            {
                PemReader pr = new PemReader(sr);
                AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();

                return KeyPair.Private;
            }
        }
        private static AsymmetricCipherKeyPair FromPemToRSAKeyPair(string pemPrivateKey)
        {
            using (var sr = new StringReader(pemPrivateKey))
            {
                PemReader pr = new PemReader(sr);
                AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();

                return KeyPair;
            }
        }
        private static RSACryptoServiceProvider FromPemToPublicRSA(string pemPublicKey)
        {
            using (var sr = new StringReader(pemPublicKey))
            {
                PemReader pr = new PemReader(sr);
                AsymmetricKeyParameter publicKey = (AsymmetricKeyParameter)pr.ReadObject();
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaKeyParameters)publicKey);

                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
                csp.ImportParameters(rsaParams);
                return csp;
            }
        }
        private static RSACryptoServiceProvider FromPemToPivateRSA(string pemPrivateKey)
        {
            using (var sr = new StringReader(pemPrivateKey))
            {
                PemReader pr = new PemReader(sr);
                AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);

                RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
                csp.ImportParameters(rsaParams);

                return csp;
            }
        }

        private static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            if (csp.PublicOnly) throw new ArgumentException("CSP does not contain a private key", "csp");
            var parameters = csp.ExportParameters(true);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }); // Version
                    EncodeIntegerBigEndian(innerWriter, parameters.Modulus);
                    EncodeIntegerBigEndian(innerWriter, parameters.Exponent);
                    EncodeIntegerBigEndian(innerWriter, parameters.D);
                    EncodeIntegerBigEndian(innerWriter, parameters.P);
                    EncodeIntegerBigEndian(innerWriter, parameters.Q);
                    EncodeIntegerBigEndian(innerWriter, parameters.DP);
                    EncodeIntegerBigEndian(innerWriter, parameters.DQ);
                    EncodeIntegerBigEndian(innerWriter, parameters.InverseQ);
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN RSA PRIVATE KEY-----\n");
                // Output as Base64 with lines chopped at 64 characters
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END RSA PRIVATE KEY-----");
            }

            return outputStream.ToString();
        }
        private static string ExportPublicKey(RSACryptoServiceProvider csp)
        {
            StringWriter outputStream = new StringWriter();
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); // BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus); // Modulus
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent); // Exponent
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                // WriteLine terminates with \r\n, we want only \n
                outputStream.Write("-----BEGIN PUBLIC KEY-----\n");
                for (var i = 0; i < base64.Length; i += 64)
                {
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
                    outputStream.Write("\n");
                }
                outputStream.Write("-----END PUBLIC KEY-----");
            }

            return outputStream.ToString();
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException("length", "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }
        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        #endregion
    }
}
