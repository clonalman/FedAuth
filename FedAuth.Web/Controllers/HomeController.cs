using System;
using System.Web;
using System.Web.Configuration;
using System.Web.Mvc;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Services.Configuration;

namespace FedAuth.Web.Controllers
{
    public class HomeController : Controller
    {
        //
        // GET: /Home/

        public ActionResult Index()
        {
            return View();
        }

        public ActionResult Logout()
        {
            // Load Identity Configuration
            FederationConfiguration config = FederatedAuthentication.FederationConfiguration;
            
            // Sign out of WIF.
            WSFederationAuthenticationModule.FederatedSignOut(new Uri(WebConfigurationManager.AppSettings["ida:Issuer"]), new Uri(config.WsFederationConfiguration.Realm));

            return View();
        }
    }
}
