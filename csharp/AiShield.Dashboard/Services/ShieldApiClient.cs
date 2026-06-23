using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace AiShield.Dashboard.Services;

public sealed class ShieldApiClient : IDisposable
{
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    public string BaseUrl { get; }

    public ShieldApiClient(string baseUrl = "http://127.0.0.1:9470")
    {
        BaseUrl = baseUrl.TrimEnd('/');
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
    }

    public async Task<bool> IsOnlineAsync()
    {
        try
        {
            var res = await _http.GetAsync($"{BaseUrl}/api/health");
            if (res.IsSuccessStatusCode) return true;
        }
        catch { /* fall through to named pipe */ }

        try
        {
            using var pipe = new NamedPipeClient();
            return await pipe.IsAvailableAsync();
        }
        catch { return false; }
    }

    public async Task<StatusDto?> GetStatusAsync() => await GetAsync<StatusDto>("/api/status");
    public async Task<ConfigDto?> GetConfigAsync() => await GetAsync<ConfigDto>("/api/config");
    public async Task<List<EventDto>> GetEventsAsync(int limit = 50) => await GetAsync<List<EventDto>>($"/api/events?limit={limit}") ?? [];
    public async Task<List<AuditEntryDto>> GetAuditAsync(int limit = 100) => await GetAsync<List<AuditEntryDto>>($"/api/audit?limit={limit}") ?? [];
    public async Task<List<ExtensionDto>> GetExtensionsAsync() => await GetAsync<List<ExtensionDto>>("/api/extensions") ?? [];
    public async Task<List<ModelFileDto>> GetModelsAsync() => await GetAsync<List<ModelFileDto>>("/api/models") ?? [];
    public async Task<List<AppPolicyDto>> GetAppPoliciesAsync() => await GetAsync<List<AppPolicyDto>>("/api/policies/apps") ?? [];

    public Task<ActionResultDto> ApproveRequestAsync(string requestId, bool allow)
        => PostAsync($"/api/approve/{requestId}?allow={allow.ToString().ToLower()}", null);

    public Task<ActionResultDto> TerminateProcessAsync(int pid)
        => PostAsync("/api/process/terminate", new { pid });

    public Task<ActionResultDto> BlockAppAsync(string appName)
        => PostAsync("/api/process/block", new { app_name = appName, action = "block" });

    public Task<ActionResultDto> AllowAppAsync(string appName)
        => PostAsync("/api/process/allow", new { app_name = appName, action = "allow" });

    public Task<ActionResultDto> AskAppAsync(string appName)
        => PostAsync("/api/process/ask", new { app_name = appName, action = "ask" });

    public Task<ActionResultDto> TerminateAllAiAsync()
        => PostAsync("/api/process/terminate-all", null);

    public Task<ActionResultDto> SetFolderPolicyAsync(string folderName, string policy)
        => PostAsync("/api/policy/folder", new { folder_name = folderName, policy });

    public Task<ActionResultDto> AddFolderAsync(string name, string path, string policy = "ask")
        => PostAsync("/api/folders/add", new { name, path, policy });

    public Task<ActionResultDto> RemoveFolderAsync(string folderName)
        => PostAsync("/api/folders/remove", new { folder_name = folderName });

    public Task<ActionResultDto> RemoveAppPolicyAsync(string appName)
        => PostAsync("/api/policy/app/remove", new { app_name = appName });

    public Task<ActionResultDto> SetAppResourcePolicyAsync(string appName, string resource, string policy)
        => PostAsync("/api/policy/app/resource", new { app_name = appName, resource, policy });

    public Task<ActionResultDto> SetGlobalPolicyAsync(string key, string value)
        => PostAsync("/api/policy/global", new { key, value });

    public Task<ActionResultDto> BlockDomainAsync(string domain)
        => PostAsync("/api/firewall/block-domain", new { domain });

    public Task<ActionResultDto> UnblockDomainAsync(string domain)
        => PostAsync("/api/firewall/unblock-domain", new { domain });

    public Task<ActionResultDto> BlockAllAiAsync()
        => PostAsync("/api/firewall/block-all", null);

    public Task<ActionResultDto> BlockConnectionAsync(int pid)
        => PostAsync("/api/firewall/block-connection", new { pid });

    public Task<ActionResultDto> ScanExtensionsAsync()
        => PostAsync("/api/browser/scan", null);

    public Task<ActionResultDto> BlockWebsitesAsync()
        => PostAsync("/api/browser/block-websites", null);

    public Task<ActionResultDto> ScanModelsAsync()
        => PostAsync("/api/models/scan", null);

    public Task<ActionResultDto> LockdownAsync()
        => PostAsync("/api/lockdown", null);

    public Task<ActionResultDto> RestoreDefaultsAsync()
        => PostAsync("/api/restore-defaults", null);

    public string GetAuditExportUrl() => $"{BaseUrl}/api/audit/export";

    private async Task<T?> GetAsync<T>(string path)
    {
        var res = await _http.GetAsync($"{BaseUrl}{path}");
        if (!res.IsSuccessStatusCode) return default;
        return JsonSerializer.Deserialize<T>(await res.Content.ReadAsStringAsync(), JsonOpts);
    }

    private async Task<ActionResultDto> PostAsync(string path, object? body)
    {
        try
        {
            HttpResponseMessage res;
            if (body is null)
                res = await _http.PostAsync($"{BaseUrl}{path}", null);
            else
            {
                var json = JsonSerializer.Serialize(body, JsonOpts);
                res = await _http.PostAsync($"{BaseUrl}{path}",
                    new StringContent(json, Encoding.UTF8, "application/json"));
            }
            var text = await res.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<ActionResultDto>(text, JsonOpts) ?? new ActionResultDto();
            if (res.IsSuccessStatusCode && !result.Ok && string.IsNullOrEmpty(result.Error))
                result.Ok = true;
            return result;
        }
        catch (Exception ex)
        {
            return new ActionResultDto { Ok = false, Error = ex.Message };
        }
    }

    public void Dispose() => _http.Dispose();
}

public class ActionResultDto
{
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public string? Message { get; set; }
}

public record StatusDto(
    bool Running, List<AiProcessDto> AiProcesses, List<NetworkConnDto> ActiveConnections,
    List<AccessRequestDto> PendingRequests, List<EventDto> RecentEvents,
    List<ProtectedFolderDto> ProtectedFolders, StatsDto? Stats);

public record ConfigDto(
    string NetworkPolicy, string ClipboardPolicy, string ScreenshotPolicy,
    string MicrophonePolicy, string CameraPolicy, string GlobalPolicy);

public record AiProcessDto(int Pid, string Name, string Exe, string AiType, int Confidence, double GpuMb);
public record NetworkConnDto(int Pid, string ProcessName, string LocalAddr, string RemoteAddr, string RemoteHost, string Status, bool IsAiTraffic);
public record AccessRequestDto(string Id, string Timestamp, string AppName, int AppPid, string ResourceType, string ResourcePath, string Policy);
public record EventDto(string Id, string Timestamp, string Severity, string ResourceType, string Action, string SourceApp, string Resource, string Message);
public record ProtectedFolderDto(string Name, string Path, string Policy);
public record StatsDto(PermStatsDto? Permissions, NetStatsDto? Network, int ExtensionsFound);
public record PermStatsDto(int Grants, int AuditEntries, int Blocked);
public record NetStatsDto(int AiConnections, int BlockedRules, int TotalSeen);
public record AuditEntryDto(int Id, string Timestamp, string AppName, string ResourceType, string Resource, string Action, string Decision, string Message);
public record ExtensionDto(string Browser, string Id, string Name, string Path);
public record ModelFileDto(string Path, double SizeMb, string Type);
public record AppPolicyDto(
    string AppName, string DefaultAction, string Files, string Network,
    string Clipboard, string Microphone, string Camera);
