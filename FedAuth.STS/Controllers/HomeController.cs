using System;
using System.IdentityModel.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Web.Configuration;
using FedAuth.STS.Security;


namespace FedAuth.STS.Controllers
{
    public class HomeController : Controller
    {
        public const string Action = "wa";
        public const string SignIn = "wsignin1.0";
        public const string SignOut = "wsignout1.0";

        public ActionResult Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                var action = Request.QueryString[Action];

                if (action == SignIn)
                {
                    var formData = ProcessSignIn(Request.Url, User as ClaimsPrincipal);
                    return new ContentResult()
                    {
                        Content = formData,
                        ContentType = "text/html"
                    };
                }
                else if (action == SignOut)
                {
                    ProcessSignOut(Request.Url, User as ClaimsPrincipal);
                }
            }

            return View();
        }

        private static string ProcessSignIn(Uri url, ClaimsPrincipal user)
        {
            var requestMessage = (SignInRequestMessage)WSFederationMessage.CreateFromUri(url);
            var signingCredentials = new X509SigningCredentials(CustomSecurityTokenService.GetCertificate(WebConfigurationManager.AppSettings["SigningCertificateName"]));

            // Cache?
            var config = new SecurityTokenServiceConfiguration(WebConfigurationManager.AppSettings["IssuerName"], signingCredentials);

            var sts = new CustomSecurityTokenService(config);
            var responseMessage = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(requestMessage, user, sts);

            return responseMessage.WriteFormPost();
        }

        private static void ProcessSignOut(Uri url, ClaimsPrincipal user)
        {
            var requestMessage = (SignOutRequestMessage)WSFederationMessage.CreateFromUri(url);

            FederatedPassiveSecurityTokenServiceOperations.ProcessSignOutRequest(requestMessage, user, requestMessage.Reply, System.Web.HttpContext.Current.Response);
        }
    }
}
