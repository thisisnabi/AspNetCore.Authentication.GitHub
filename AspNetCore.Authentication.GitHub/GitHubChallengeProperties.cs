using Microsoft.AspNetCore.Authentication.OAuth;

namespace AspNetCore.Authentication.GitHub;
public class GitHubChallengeProperties : OAuthChallengeProperties
{
    public static readonly string AccessTypeKey = "access_type";

    public static readonly string ApprovalPromptKey = "approval_prompt";

    public static readonly string IncludeGrantedScopesKey = "include_granted_scopes";

    public static readonly string LoginHintKey = "login_hint";

    public static readonly string PromptParameterKey = "prompt";

    public GitHubChallengeProperties()
    { }
    public GitHubChallengeProperties(IDictionary<string, string?> items)
        : base(items)
    { }

    public GitHubChallengeProperties(IDictionary<string, string?> items, IDictionary<string, object?> parameters)
        : base(items, parameters)
    { }
 
    public string? AccessType
    {
        get => GetParameter<string>(AccessTypeKey);
        set => SetParameter(AccessTypeKey, value);
    }

     public string? ApprovalPrompt
    {
        get => GetParameter<string>(ApprovalPromptKey);
        set => SetParameter(ApprovalPromptKey, value);
    }

     public bool? IncludeGrantedScopes
    {
        get => GetParameter<bool?>(IncludeGrantedScopesKey);
        set => SetParameter(IncludeGrantedScopesKey, value);
    }

    public string? LoginHint
    {
        get => GetParameter<string>(LoginHintKey);
        set => SetParameter(LoginHintKey, value);
    }

     public string? Prompt
    {
        get => GetParameter<string>(PromptParameterKey);
        set => SetParameter(PromptParameterKey, value);
    }
}