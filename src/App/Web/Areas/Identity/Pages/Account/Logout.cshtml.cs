using Web.Interfaces;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Web.Areas.Identity.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly ILogger<LogoutModel> _logger;
        private readonly IAuthencticationHelper _authencticationHelper;


        public LogoutModel(ILogger<LogoutModel> logger, IAuthencticationHelper authencticationHelper)
        {
            _logger = logger;
            _authencticationHelper = authencticationHelper;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPost(string returnUrl = null)
        {
            return await OnGetSignOut(returnUrl);
        }

        [Authorize]
        public async Task<IActionResult> OnGetSignOut(string returnUrl = null)
        {

            _logger.LogInformation("User logged out.");


            if (await _authencticationHelper.SignOutAsync())
                return LocalRedirect(returnUrl ?? "/");

            HttpContext.Request.Headers.TryGetValue("referer", out var referer);
            return LocalRedirect(referer);
        }
    }
}