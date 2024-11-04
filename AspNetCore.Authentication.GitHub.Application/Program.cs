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
    options.ClientId = "";
    options.ClientSecret = "";
    options.SignInScheme = IdentityConstants.ExternalScheme;
});

builder.Services.AddAuthorization(p => {

    p.AddPolicy("nabi", r => r.AddAuthenticationSchemes(IdentityConstants.ExternalScheme)
    .RequireAuthenticatedUser());
});

var app = builder.Build(); 
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/protected", () =>
{
    return "protected";
}).RequireAuthorization("nabi");


app.MapGet("/login", () =>
{
    return TypedResults.Challenge(authenticationSchemes: new List<string>
       {
            GitHubDefaults.AuthenticationScheme
       });
});

app.Run();