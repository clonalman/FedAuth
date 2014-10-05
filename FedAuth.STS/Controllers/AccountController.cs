using System;
using System.Web.Mvc;
using System.Web.Security;
using FedAuth.STS.Models;

namespace FedAuth.STS.Controllers
{
    public class AccountController : Controller
    {
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginModel model, string returnUrl)
        {
            if (ModelState.IsValid &&
                model.UserName.Equals("user", StringComparison.OrdinalIgnoreCase) && 
                model.Password.Equals("password"))
            {
                FormsAuthentication.SetAuthCookie(model.UserName, model.RememberMe);
                return Redirect(returnUrl);
            }

            ViewBag.ReturnUrl = returnUrl;
            ModelState.AddModelError("", "The user name or password provided is incorrect.");
            return View(model);
        }
    }
}
