using AiShield.Core.Ipc;

namespace AiShield.Dashboard.Services;

public enum BackendKind
{
    None,
    Service,
    Python,
}

/// <summary>
/// Uses the installed AI Firewall service when it's running and trusts this app, and otherwise the
/// Python engine started from scripts\start.ps1.
/// </summary>
public sealed class BackendSwitch : IShieldBackend
{
    private readonly ServiceBackend _service = new();
    private readonly ShieldApiClient _python = new();
    private IShieldBackend _current;

    public BackendSwitch() => _current = _python;

    public BackendKind Kind { get; private set; } = BackendKind.None;

    public async Task<bool> IsOnlineAsync()
    {
        if (await _service.IsOnlineAsync().ConfigureAwait(false))
        {
            (_current, Kind) = (_service, BackendKind.Service);
            return true;
        }
        if (await _python.IsOnlineAsync().ConfigureAwait(false))
        {
            (_current, Kind) = (_python, BackendKind.Python);
            return true;
        }
        Kind = BackendKind.None;
        return false;
    }

    public Task NotifyExitingAsync() => Kind == BackendKind.Service ? _service.NotifyExitingAsync() : Task.CompletedTask;

    public Task<StatusDto?> GetStatusAsync() => _current.GetStatusAsync();
    public Task<ConfigDto?> GetConfigAsync() => _current.GetConfigAsync();
    public Task<List<AuditEntryDto>> GetAuditAsync(int limit = 100) => _current.GetAuditAsync(limit);
    public Task<List<ExtensionDto>> GetExtensionsAsync() => _current.GetExtensionsAsync();
    public Task<List<ModelFileDto>> GetModelsAsync() => _current.GetModelsAsync();
    public Task<List<AppPolicyDto>> GetAppPoliciesAsync() => _current.GetAppPoliciesAsync();
    public Task<string?> GetAuditCsvAsync() => _current.GetAuditCsvAsync();
    public Task<ActionResultDto> ApproveRequestAsync(string requestId, bool allow) => _current.ApproveRequestAsync(requestId, allow);
    public Task<ActionResultDto> TerminateProcessAsync(int pid) => _current.TerminateProcessAsync(pid);
    public Task<ActionResultDto> TerminateAllAiAsync() => _current.TerminateAllAiAsync();
    public Task<ActionResultDto> BlockAppAsync(string appName) => _current.BlockAppAsync(appName);
    public Task<ActionResultDto> AllowAppAsync(string appName) => _current.AllowAppAsync(appName);
    public Task<ActionResultDto> AskAppAsync(string appName) => _current.AskAppAsync(appName);
    public Task<ActionResultDto> SetAppResourcePolicyAsync(string appName, string resource, string policy) => _current.SetAppResourcePolicyAsync(appName, resource, policy);
    public Task<ActionResultDto> RemoveAppPolicyAsync(string appName) => _current.RemoveAppPolicyAsync(appName);
    public Task<ActionResultDto> SetGlobalPolicyAsync(string key, string value) => _current.SetGlobalPolicyAsync(key, value);
    public Task<ActionResultDto> LockdownAsync() => _current.LockdownAsync();
    public Task<ActionResultDto> RestoreDefaultsAsync() => _current.RestoreDefaultsAsync();
    public Task<ActionResultDto> SetFolderPolicyAsync(string folderName, string policy) => _current.SetFolderPolicyAsync(folderName, policy);
    public Task<ActionResultDto> AddFolderAsync(string name, string path, string policy = "ask") => _current.AddFolderAsync(name, path, policy);
    public Task<ActionResultDto> RemoveFolderAsync(string folderName) => _current.RemoveFolderAsync(folderName);
    public Task<ActionResultDto> BlockConnectionAsync(int pid) => _current.BlockConnectionAsync(pid);
    public Task<ActionResultDto> BlockDomainAsync(string domain) => _current.BlockDomainAsync(domain);
    public Task<ActionResultDto> UnblockDomainAsync(string domain) => _current.UnblockDomainAsync(domain);
    public Task<ActionResultDto> BlockAllAiAsync() => _current.BlockAllAiAsync();
    public Task<ActionResultDto> ScanExtensionsAsync() => _current.ScanExtensionsAsync();
    public Task<ActionResultDto> BlockWebsitesAsync() => _current.BlockWebsitesAsync();
    public Task<ActionResultDto> ScanModelsAsync() => _current.ScanModelsAsync();

    public void Dispose()
    {
        _service.Dispose();
        _python.Dispose();
    }
}
