using IdentityModel.Client;
using App.Share.Consts;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Web.Interfaces;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Web.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        [BindProperty]
        public string Email { get; set; }
        [BindProperty]
        public string Password { get; set; }


        private readonly IAuthencticationHelper _authencticationHelper;
        private readonly PasswordTokenRequest _passwordTokenRequest;
        private readonly IConfiguration _configuration;

        public LoginModel(IAuthencticationHelper authencticationHelper, PasswordTokenRequest passwordTokenRequest, IConfiguration configuration)
        {
            _authencticationHelper = authencticationHelper;
            _passwordTokenRequest = passwordTokenRequest;
            _configuration = configuration;
        }
        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPost([FromQuery] string? returnUrl)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            _passwordTokenRequest.UserName = Email;
            _passwordTokenRequest.Password = Password;

            var token = await _authencticationHelper.GetTokenAsync(_passwordTokenRequest);

            if (token.IsError)
                return Challenge(JwtBearerDefaults.AuthenticationScheme);

            Response.Cookies.Append(AuthenticationConst.CoockieName, token.AccessToken, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Strict });
            Response.Cookies.Append("X-Refresh-Token", token.RefreshToken, new CookieOptions() { HttpOnly = true, SameSite = SameSiteMode.Strict });

            return Redirect(!string.IsNullOrEmpty(returnUrl) ? returnUrl : "/");
        }
    }
}
