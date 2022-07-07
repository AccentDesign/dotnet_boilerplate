using System.Net;
using App.Share.Providers;
using Application.StartupSetup;
using Mapping.StartupSetup;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.Routing;
using Web.Helpers;
using Web.StartupSetup;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddOpenIdConnect(builder.Configuration, builder.Environment)
    .AddHttpClients(builder.Configuration, builder.Environment)
    .AddSession(options =>
    {
        options.IdleTimeout = TimeSpan.FromMinutes(60);
    })
    .AddApplicationServices(builder.Configuration, "PostgreConnection", builder.Configuration.GetConnectionString("HangfireConnection"))
    .AddMappers()
    .AddSingleton<IActionContextAccessor, ActionContextAccessor>()
    .AddSingleton<IHttpContextAccessor, HttpContextAccessor>()

    .AddScoped(x =>
    {
        ActionContext actionContext = x.GetRequiredService<IActionContextAccessor>().ActionContext;
        IUrlHelperFactory factory = x.GetRequiredService<IUrlHelperFactory>();

        return factory.GetUrlHelper(actionContext);
    })

    .AddSingleton<IDateTimeProvider, DateTimeProvider>()
    .AddRazorPages(options =>
    {
        options.Conventions.AddAreaPageRoute("Admin", "/Index", "/admin");
        options.Conventions.AddAreaPageRoute("Admin", "/Index", "");
    });

var app = builder.Build();


// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment()) {
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

//if (app.Environment.IsProduction())
app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();
app.UseSession();


app.UseApplication(app.Services);

app.Use(async (context, next) =>
{
    var cookie = AuthencticationHelper.GetToken(context);
    if (!string.IsNullOrEmpty(cookie)) {
        context.Request.Headers.Add("Authorization", "Bearer " + cookie);
    }
    await next();
});

app.UseStatusCodePages(async context =>
{
    var response = context.HttpContext.Response;

    if (response.StatusCode == (int)HttpStatusCode.Unauthorized) {
        response.Redirect(
            $"/Identity/Account/Login{(context.HttpContext.Request.Path.Value.ToLower().Contains("login") ? string.Empty : "?returnUrl=" + context.HttpContext.Request.Path)}");
    }
});

app.UseAuthorization();

app.MapRazorPages();

app.Run();
