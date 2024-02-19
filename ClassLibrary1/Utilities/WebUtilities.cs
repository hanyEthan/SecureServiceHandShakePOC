using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;

namespace ClassLibrary1.Utilities
{
    public static class WebUtilities
    {
        public static async Task<string?> Post<TRequest>(string baseUrl, 
                                                         string requestUrl, 
                                                         TRequest request,
                                                         X509Certificate? clientCertificate = null)
        {
            using (var handler = new HttpClientHandler())
            {
                if (clientCertificate != null)
                {
                    handler.ClientCertificates.Add(clientCertificate); // Configure mTLS
                }

                using (var client = new HttpClient(handler))
                {
                    client.BaseAddress = new Uri(baseUrl);

                    var response = await client.PostAsJsonAsync(requestUrl, request);

                    if (response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadAsStringAsync();
                        return result;
                    }
                    else
                    {
                        throw new Exception(response.StatusCode.ToString());
                    }
                }
            }
        }
    }
}
