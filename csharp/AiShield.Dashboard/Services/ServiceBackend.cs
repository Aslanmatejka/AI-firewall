using AiShield.Core.Ipc;

namespace AiShield.Dashboard.Services;

/// <summary>
/// The installed AI Firewall service, over its protected pipe. Anything that loosens protection opens the
/// secure prompt, so these calls can wait until the user answers.
/// </summary>
public sealed class ServiceBackend : IShieldBackend
{
    private const string NotYet = "Not available with the AI Firewall service yet";
    private static readonly TimeSpan ConfirmationWait = TimeSpan.FromMinutes(3);

    private readonly ShieldPipeClient _pipe = new() { ConnectTimeout = TimeSpan.FromMilliseconds(500) };

    public async Task<bool> IsOnlineAsync()
    {
        var hello = await _pipe.GetAsync<HelloDto>(PipeOps.Hello).ConfigureAwait(false);
        return hello is { Trusted: true };
    }

    public Task<StatusDto?> GetStatusAsync() => _pipe.GetAsync<StatusDto>(PipeOps.Status);
    public Task<ConfigDto?> GetConfigAsync() => _pipe.GetAsync<ConfigDto>(PipeOps.Config);
    public async Task<List<AuditEntryDto>> GetAuditAsync(int limit = 100) => await _pipe.GetAsync<List<AuditEntryDto>>(PipeOps.Audit, new { limit }).ConfigureAwait(false) ?? [];
    public Task<List<ExtensionDto>> GetExtensionsAsync() => Task.FromResult(new List<ExtensionDto>());
    public Task<List<ModelFileDto>> GetModelsAsync() => Task.FromResult(new List<ModelFileDto>());
    public async Task<List<AppPolicyDto>> GetAppPoliciesAsync() => await _pipe.GetAsync<List<AppPolicyDto>>(PipeOps.AppPolicies).ConfigureAwait(false) ?? [];

    public async Task<string?> GetAuditCsvAsync()
    {
        var entries = await _pipe.GetAsync<List<AuditEntryDto>>(PipeOps.Audit, new { limit = 5000 }).ConfigureAwait(false);
        return entries is null ? null : AuditCsv.Write(entries);
    }

    public Task<ActionResultDto> ApproveRequestAsync(string requestId, bool allow)
        => allow ? Send(PipeOps.Review, new { id = requestId }, ConfirmationWait) : Send(PipeOps.Deny, new { id = requestId });

    public Task<ActionResultDto> TerminateProcessAsync(int pid) => Send(PipeOps.Terminate, new { pid });

    public async Task<ActionResultDto> TerminateAllAiAsync()
    {
        var status = await GetStatusAsync().ConfigureAwait(false);
        if (status is null)
            return Failed("The AI Firewall service didn't respond");
        var failed = 0;
        foreach (var process in status.AiProcesses)
        {
            if (!(await TerminateProcessAsync(process.Pid).ConfigureAwait(false)).Ok)
                failed++;
        }
        return failed == 0
            ? new ActionResultDto { Ok = true, Message = $"Stopped {status.AiProcesses.Count} AI app(s)" }
            : Failed($"Couldn't stop {failed} of {status.AiProcesses.Count} AI app(s)");
    }

    public Task<ActionResultDto> BlockAppAsync(string appName) => SetAppResourcePolicyAsync(appName, "all", "block");
    public Task<ActionResultDto> AllowAppAsync(string appName) => SetAppResourcePolicyAsync(appName, "all", "allow");
    public Task<ActionResultDto> AskAppAsync(string appName) => SetAppResourcePolicyAsync(appName, "all", "ask");

    public Task<ActionResultDto> SetAppResourcePolicyAsync(string appName, string resource, string policy)
        => Send(PipeOps.SetAppPolicy, new { app_name = appName, resource, policy }, ConfirmationWait);

    public Task<ActionResultDto> RemoveAppPolicyAsync(string appName)
        => Send(PipeOps.RemoveAppPolicy, new { app_name = appName }, ConfirmationWait);

    public Task<ActionResultDto> SetGlobalPolicyAsync(string key, string value)
        => Send(PipeOps.SetGlobalPolicy, new { key, value }, ConfirmationWait);

    public Task<ActionResultDto> LockdownAsync() => Send(PipeOps.LockdownOn);
    public Task<ActionResultDto> RestoreDefaultsAsync() => Send(PipeOps.RestoreDefaults, null, ConfirmationWait);

    public Task<ActionResultDto> SetFolderPolicyAsync(string folderName, string policy) => Task.FromResult(Failed(NotYet));
    public Task<ActionResultDto> AddFolderAsync(string name, string path, string policy = "ask") => Task.FromResult(Failed(NotYet));
    public Task<ActionResultDto> RemoveFolderAsync(string folderName) => Task.FromResult(Failed(NotYet));
    public Task<ActionResultDto> BlockConnectionAsync(int pid) => Task.FromResult(Failed(NotYet));
    public Task<ActionResultDto> BlockDomainAsync(string domain) => Task.FromResult(Failed(NotYet));
    public Task<ActionResultDto> UnblockDomainAsync(string domain) => Task.FromResult(Failed(NotYet));
    public Task<ActionResultDto> BlockAllAiAsync() => Task.FromResult(Failed(NotYet));
    public Task<ActionResultDto> ScanExtensionsAsync() => Task.FromResult(Failed(NotYet));
    public Task<ActionResultDto> BlockWebsitesAsync() => Task.FromResult(Failed(NotYet));
    public Task<ActionResultDto> ScanModelsAsync() => Task.FromResult(Failed(NotYet));

    /// <summary>Tells the service the user closed the app on purpose, so it isn't restarted.</summary>
    public Task NotifyExitingAsync() => _pipe.SendAsync(PipeOps.HelperExit);

    public void Dispose()
    {
    }

    private async Task<ActionResultDto> Send(string op, object? args = null, TimeSpan? timeout = null)
    {
        var response = await _pipe.SendAsync(op, args, timeout).ConfigureAwait(false);
        if (response is null)
            return Failed("The AI Firewall service didn't respond");
        if (response.Ok)
            return new ActionResultDto { Ok = true, Message = response.Consent == "approved" ? "Confirmed and applied" : null };
        return Failed(Explain(response));
    }

    private static string Explain(PipeResponse response) => (response.Error, response.Consent) switch
    {
        (PipeErrors.NotApproved, "denied") => "Not changed: you chose not to allow it",
        (PipeErrors.NotApproved, "dismissed") => "Not changed: the confirmation was closed or timed out",
        (PipeErrors.NotApproved, "busy") => "Not changed: another confirmation is already open, or one was just refused",
        (PipeErrors.NotApproved, _) => "Not changed: the secure confirmation screen couldn't be shown",
        (PipeErrors.NotFound, _) => "That request or app no longer exists",
        (PipeErrors.UntrustedClient, _) => "The service doesn't trust this copy of the app. Use the installed AI Firewall.",
        (PipeErrors.InvalidArgs, _) => "The service refused the request as invalid",
        _ => $"The service refused the request ({response.Error})",
    };

    private static ActionResultDto Failed(string error) => new() { Ok = false, Error = error };
}
