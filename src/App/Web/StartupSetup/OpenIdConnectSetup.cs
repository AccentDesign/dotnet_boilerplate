using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Service.Share.StartupSetup.Authentication;
using Web.Helpers;

namespace Web.StartupSetup;

public static class OpenIdConnectSetup
{
    public static IServiceCollection AddOpenIdConnect(this IServiceCollection services, IConfiguration config, IWebHostEnvironment env)
    {

        // To not map claims name to default JWT ones
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        services.ConfigureIdentityOptions()
            .AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddCookie(options =>
                {

                    options.LoginPath = new PathString("/Identity/Account/Login");
                    options.LogoutPath = "/Identity/Account/Logout";
                })
               
                .AddJwtBearer(options => JwtBearerSetup.DefaultOptions(options, env, AuthencticationHelper.GetAuthority(env, config)));
        services.AddAuthorization(options =>
        {
            var defaultAuthorizationPolicyBuilder = new AuthorizationPolicyBuilder(
                JwtBearerDefaults.AuthenticationScheme);
            defaultAuthorizationPolicyBuilder =
                defaultAuthorizationPolicyBuilder.RequireAuthenticatedUser();
            options.DefaultPolicy = defaultAuthorizationPolicyBuilder.Build();
        });

        return services;
    }
}

