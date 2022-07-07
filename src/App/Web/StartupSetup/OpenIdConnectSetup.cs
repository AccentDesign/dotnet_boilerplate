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
using Web.Helpers;

namespace Web.StartupSetup;

public static class OpenIdConnectSetup
{
    public static IServiceCollection AddOpenIdConnect(this IServiceCollection services, IConfiguration config, IWebHostEnvironment env)
    {

        // To not map claims name to default JWT ones
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddCookie(options =>
                {
                    
                    options.LoginPath = new PathString("/Identity/Account/Login");
                    options.LogoutPath = "/Identity/Account/Logout";
                })

            .AddJwtBearer(options =>
            {
                var isDevelopmentOrStaging = env.IsDevelopment() || env.IsStaging();

                options.Authority = AuthencticationHelper.GetAuthority(env, config);
                options.RequireHttpsMetadata = env.IsProduction();
                options.SaveToken = true;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = !isDevelopmentOrStaging,
                    //ValidIssuer = config["Jwt:Issuer"],
                    ValidateIssuerSigningKey = true,
                    ValidateAudience = false,
                    RoleClaimType = OpenIddictConstants.Claims.Role,
                    NameClaimType = OpenIddictConstants.Claims.Name,

                    ValidateLifetime = true,
                    ClockSkew = TokenValidationParameters.DefaultClockSkew,
                };
            });
        services.AddAuthorization(options =>
        {
            var defaultAuthorizationPolicyBuilder = new AuthorizationPolicyBuilder(
                JwtBearerDefaults.AuthenticationScheme);
            defaultAuthorizationPolicyBuilder =
                defaultAuthorizationPolicyBuilder.RequireAuthenticatedUser();
            options.DefaultPolicy = defaultAuthorizationPolicyBuilder.Build();
        });

        services.Configure<IdentityOptions>(options =>
        {
            options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Username;
            options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
            options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;
            options.ClaimsIdentity.EmailClaimType = OpenIddictConstants.Claims.Email;
            options.ClaimsIdentity.SecurityStampClaimType = "secret_value";
        });

        return services;
    }
}

