using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace ClassLibrary1.Utilities
{
    public static class MTLSUtilities
    {
        public static KestrelServerOptions UseMutualAuthentication(this KestrelServerOptions kestrelServerOptions)
        {
            kestrelServerOptions.ConfigureHttpsDefaults(options =>
            {
                options.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                options.ClientCertificateValidation = (X509Certificate2 cert, X509Chain chain, SslPolicyErrors sslPolicyErrors) => true;
            });

            return kestrelServerOptions;
        }
    }
}
