//using ClassLibrary1.Models;
//using Org.BouncyCastle.Asn1.Pkcs;
//using Org.BouncyCastle.Asn1.X509;
//using Org.BouncyCastle.Asn1.X9;
//using Org.BouncyCastle.Crypto;
//using Org.BouncyCastle.Crypto.Generators;
//using Org.BouncyCastle.Crypto.Operators;
//using Org.BouncyCastle.Crypto.Parameters;
//using Org.BouncyCastle.Math;
//using Org.BouncyCastle.Security;
//using Org.BouncyCastle.X509;
//using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

//namespace Common.Utilities
//{
//    public static class SecurityUtilities2
//    {
//        private static readonly SecureRandom _secureRandom = new SecureRandom();

//        public static X509Certificate GenerateSelfSignedCertificate(KeyPair keyPair,
//                                                                    string issuer,
//                                                                    string subject,
//                                                                    DateTimeOffset validFrom,
//                                                                    DateTimeOffset validUntil)
//        {
//            var eeKey = GenerateRsaKeyPair(2048);

//            var privateKey = eeKey.Private;
//            var publicKey = eeKey.Public;

//            var issuerParam = new X509Name(issuer);
//            var subjectParam = new X509Name(subject);

//            var signatureFactory = privateKey is ECPrivateKeyParameters
//                                 ? new Asn1SignatureFactory(X9ObjectIdentifiers.ECDsaWithSha256.ToString(), privateKey)
//                                 : new Asn1SignatureFactory(PkcsObjectIdentifiers.Sha256WithRsaEncryption.ToString(), privateKey);

//            var certGenerator = new X509V3CertificateGenerator();
//            certGenerator.SetIssuerDN(issuerParam);
//            certGenerator.SetSubjectDN(subjectParam);
//            certGenerator.SetSerialNumber(BigInteger.ValueOf(_secureRandom.NextLong()));
//            certGenerator.SetNotAfter(validUntil.DateTime);
//            certGenerator.SetNotBefore(validFrom.DateTime);
//            certGenerator.SetPublicKey(publicKey);

//            var certificate = certGenerator.Generate(signatureFactory);

//            return certificate;
//        }
//        public static X509Certificate GenerateSelfSignedCertificatePFX(KeyPair keyPair,
//                                                                       string issuer,
//                                                                       string subject,
//                                                                       DateTimeOffset validFrom,
//                                                                       DateTimeOffset validUntil)
//        {
//            var certificate = GenerateSelfSignedCertificate(keyPair, issuer, subject, validFrom, validUntil);


//            //var pfx = certificate.Export(X509ContentType.Pfx);

//            return certificate;
//        }

//        private static AsymmetricCipherKeyPair GenerateRsaKeyPair(int keySize = 2048)
//        {
//            var keygenParam = new KeyGenerationParameters(_secureRandom, keySize);

//            var keyGenerator = new RsaKeyPairGenerator();
//            keyGenerator.Init(keygenParam);
//            return keyGenerator.GenerateKeyPair();
//        }
//    }
//}
