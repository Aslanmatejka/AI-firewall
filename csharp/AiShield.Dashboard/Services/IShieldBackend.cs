using AiShield.Core.Ipc;

namespace AiShield.Dashboard.Services;

/// <summary>What the desktop app needs from AI Firewall, whichever engine is running.</summary>
public interface IShieldBackend : IDisposable
{
    Task<bool> IsOnlineAsync();
    Task<StatusDto?> GetStatusAsync();
    Task<ConfigDto?> GetConfigAsync();
    Task<List<AuditEntryDto>> GetAuditAsync(int limit = 100);
    Task<List<ExtensionDto>> GetExtensionsAsync();
    Task<List<ModelFileDto>> GetModelsAsync();
    Task<List<AppPolicyDto>> GetAppPoliciesAsync();
    Task<string?> GetAuditCsvAsync();

    Task<ActionResultDto> ApproveRequestAsync(string requestId, bool allow);
    Task<ActionResultDto> TerminateProcessAsync(int pid);
    Task<ActionResultDto> TerminateAllAiAsync();
    Task<ActionResultDto> BlockAppAsync(string appName);
    Task<ActionResultDto> AllowAppAsync(string appName);
    Task<ActionResultDto> AskAppAsync(string appName);
    Task<ActionResultDto> SetAppResourcePolicyAsync(string appName, string resource, string policy);
    Task<ActionResultDto> RemoveAppPolicyAsync(string appName);
    Task<ActionResultDto> SetGlobalPolicyAsync(string key, string value);
    Task<ActionResultDto> LockdownAsync();
    Task<ActionResultDto> RestoreDefaultsAsync();

    Task<ActionResultDto> SetFolderPolicyAsync(string folderName, string policy);
    Task<ActionResultDto> AddFolderAsync(string name, string path, string policy = "ask");
    Task<ActionResultDto> RemoveFolderAsync(string folderName);
    Task<ActionResultDto> BlockConnectionAsync(int pid);
    Task<ActionResultDto> BlockDomainAsync(string domain);
    Task<ActionResultDto> UnblockDomainAsync(string domain);
    Task<ActionResultDto> BlockAllAiAsync();
    Task<ActionResultDto> ScanExtensionsAsync();
    Task<ActionResultDto> BlockWebsitesAsync();
    Task<ActionResultDto> ScanModelsAsync();
}
