using Microsoft.AspNetCore.Mvc.Filters;

namespace ClassLibrary1.Utilities
{
    public class RequireMTLSFilter : IAsyncAuthorizationFilter
    {
        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            var includeClientCertificate = context.HttpContext.Connection.ClientCertificate != null;
            if (includeClientCertificate)
            {
                throw new Exception("Invalid mTLS.");
            }
        }
    }
}
