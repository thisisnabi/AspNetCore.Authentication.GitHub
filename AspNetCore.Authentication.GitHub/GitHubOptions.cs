using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace AspNetCore.Authentication.GitHub;
public class GitHubOptions : OAuthOptions
{
    public string UserEmailsEndpoint { get; set; } 
    
    public GitHubOptions()
    {
        CallbackPath = new PathString("/signin-github");

        AuthorizationEndpoint = GitHubDefaults.AuthorizationEndpoint;
        TokenEndpoint = GitHubDefaults.TokenEndpoint;
        UserInformationEndpoint = GitHubDefaults.UserInformationEndpoint;
        UserEmailsEndpoint = "https://api.github.com/user/emails"; 
        
        UsePkce = true;

        Scope.Add("read:user");

        ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
        ClaimActions.MapJsonKey(ClaimTypes.Name, "login");
        ClaimActions.MapJsonKey("avatar", "avatar_url");
        ClaimActions.MapJsonKey("profile", "html_url");
        ClaimActions.MapJsonKey("profile.api", "url");
        ClaimActions.MapJsonKey(ClaimTypes.Surname, "name");
    }

    public string? AccessType { get; set; }
}