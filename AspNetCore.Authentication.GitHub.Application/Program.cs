using AspNetCore.Authentication.GitHub;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
})
.AddCookie(IdentityConstants.ExternalScheme)    
.AddGitHub(options =>
{
    options.SaveTokens = true;
    options.ClientId = "client_id";
    options.ClientSecret = "secret";
    options.SignInScheme = IdentityConstants.ExternalScheme;

    options.Scope.Add("user:email");
    options.Scope.Add("user:follow");
});

builder.Services.AddAuthorization(p => {

    p.AddPolicy("authenticated", r => r.AddAuthenticationSchemes(IdentityConstants.ExternalScheme)
    .RequireAuthenticatedUser());
});

var app = builder.Build(); 
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/protected", (HttpContext httpContext) =>
{
    return httpContext.User.Claims.Select(d => new { d.Type, d.Value }).ToList();
}).RequireAuthorization("authenticated");

app.MapGet("/login", () =>
{
    return TypedResults.Challenge(authenticationSchemes: new List<string>
       {
            GitHubDefaults.AuthenticationScheme
       });
});

app.MapGet("/oauth/signin-github", () =>
{
    return TypedResults.Ok("you logged in!");
});
 
app.Run();