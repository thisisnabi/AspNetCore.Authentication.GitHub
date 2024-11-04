using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCore.Authentication.GitHub;
public static class GitHubExtensions
{

    public static AuthenticationBuilder AddGitHub(this AuthenticationBuilder builder)
        => builder.AddGitHub(GitHubDefaults.AuthenticationScheme, _ => { });

    public static AuthenticationBuilder AddGitHub(this AuthenticationBuilder builder, Action<GitHubOptions> configureOptions)
        => builder.AddGitHub(GitHubDefaults.AuthenticationScheme, configureOptions);

    public static AuthenticationBuilder AddGitHub(this AuthenticationBuilder builder, string authenticationScheme, Action<GitHubOptions> configureOptions)
        => builder.AddGitHub(authenticationScheme, GitHubDefaults.DisplayName, configureOptions);

    public static AuthenticationBuilder AddGitHub(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<GitHubOptions> configureOptions)
        => builder.AddOAuth<GitHubOptions, GitHubHandler>(authenticationScheme, displayName, configureOptions);
}
