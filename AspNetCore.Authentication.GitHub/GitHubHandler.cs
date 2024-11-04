using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AspNetCore.Authentication.GitHub;

public class GitHubHandler(IOptionsMonitor<GitHubOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : OAuthHandler<GitHubOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticationTicket> CreateTicketAsync(
        ClaimsIdentity identity,
        AuthenticationProperties properties,
        OAuthTokenResponse tokens)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        using var response = await Backchannel.SendAsync(request, Context.RequestAborted);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"An error occurred when retrieving GitHub user information ({response.StatusCode}). Please check if the authentication information is correct.");
        }

        using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Context.RequestAborted));

        var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, payload.RootElement);
        context.RunClaimActions();
        await Events.CreatingTicket(context);
        await AppendUserEmailOnCreateTicket(context);
        
        return new AuthenticationTicket(context.Principal!, context.Properties, Scheme.Name);
    }


    private async Task AppendUserEmailOnCreateTicket(OAuthCreatingTicketContext context)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, Options.UserEmailsEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", context.AccessToken);
        
        using var response = await Backchannel.SendAsync(request, Context.RequestAborted);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException($"An error occurred when retrieving GitHub user emails ({response.StatusCode}). Please check if the authentication information is correct.");
        }

        using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Context.RequestAborted));

        var primaryEmail = payload.RootElement.EnumerateArray()
            .FirstOrDefault(email =>
                email.GetProperty("primary").GetBoolean() &&
                email.GetProperty("verified").GetBoolean())
            .GetProperty("email").GetString();

        if (!string.IsNullOrEmpty(primaryEmail))
        {
            context.Identity?.AddClaim(new Claim(ClaimTypes.Email, primaryEmail));
        }
    }
    
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        properties.RedirectUri = "/dashboard";
        return base.HandleChallengeAsync(properties);
    }
}

