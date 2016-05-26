using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Filters;

namespace SecureTaskAPI.Filters
{
    public class CertificateAuthenticationFilter : Attribute, IAuthenticationFilter
    {
        public virtual bool AllowMultiple
        {
            get { return false; }
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            var certificate = HttpContext.Current.Request.ClientCertificate;
            //var certificate = context.Request.GetClientCertificate();
            if (certificate != null)
            {
                X509Certificate2 cert = new X509Certificate2(certificate.Certificate);
                if (cert != null)
                {
                    var thumbPrint = ConfigurationManager.AppSettings["Certificate_Thumbprint"].ToUpper();
                    if (cert.Thumbprint == thumbPrint)
                    {
                        // Authentication was attempted and succeeded. Set Principal to the authenticated user.
                        // Create a ClaimsIdentity with all the claims for this user.
                        Claim nameClaim = new Claim(ClaimTypes.Name, "TaskAPIUser");
                        List<Claim> claims = new List<Claim> { nameClaim };

                        // important to set the identity this way, otherwise IsAuthenticated will be false
                        ClaimsIdentity identity = new ClaimsIdentity(claims, "Basic");

                        context.Principal = new ClaimsPrincipal(identity);
                        return Task.FromResult(0);
                    }
                    else
                    {
                        context.ErrorResult = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { GetChallengeHeader() }, context.Request);
                    }
                }
            }
            else
            {
                context.ErrorResult = new System.Web.Http.Results.UnauthorizedResult(new List<AuthenticationHeaderValue> { GetChallengeHeader() }, context.Request);
            }

            return Task.FromResult(1);
        }




        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(HttpContext.Current.User.Identity.Name))
            {

            }
            return Task.FromResult(0);
        }

        private static AuthenticationHeaderValue GetChallengeHeader()
        {
            string parameter = "realm=\"Certificate Error\"";
            AuthenticationHeaderValue header = new AuthenticationHeaderValue("Basic", parameter);
            return header;
        }
    }
}