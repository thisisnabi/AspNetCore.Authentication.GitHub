namespace AspNetCore.Authentication.GitHub;

public static class GitHubDefaults
{
    public const string AuthenticationScheme = "GitHub";

    public static readonly string DisplayName = "GitHub";

    public static readonly string CallbackEndpoint = "/oauth/signin-github/";

    public static readonly string AuthorizationEndpoint = "https://github.com/login/oauth/authorize";

    public static readonly string TokenEndpoint = "https://github.com/login/oauth/access_token";

    public static readonly string UserInformationEndpoint = "https://api.github.com/user";

    public static readonly string UserEmailsEndpoint = "https://api.github.com/user/emails";
}


