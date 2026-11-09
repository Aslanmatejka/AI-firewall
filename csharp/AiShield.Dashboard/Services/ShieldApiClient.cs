using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AiShield.Dashboard.Services;

public sealed class ShieldApiClient : IDisposable
{
    private const string ServiceNotRunning = "The AI Firewall service isn't running";
    private static readonly string TokenPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "AiShield", "api-token.json");
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
    };

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private ApiEndpoint? _endpoint;

    private sealed record ApiEndpoint(string BaseUrl, string Token);

    public async Task<bool> IsOnlineAsync()
    {
        using var response = await SendAsync(HttpMethod.Get, "/api/health", null);
        if (response is null || !response.IsSuccessStatusCode) return false;
        return ReadBool(await response.Content.ReadAsStringAsync(), "ok");
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

    public async Task<string?> GetAuditCsvAsync()
    {
        using var response = await SendAsync(HttpMethod.Get, "/api/audit/export", null);
        if (response is null || !response.IsSuccessStatusCode) return null;
        return await response.Content.ReadAsStringAsync();
    }

    private async Task<T?> GetAsync<T>(string path)
    {
        using var response = await SendAsync(HttpMethod.Get, path, null);
        if (response is null || !response.IsSuccessStatusCode) return default;
        try
        {
            return JsonSerializer.Deserialize<T>(await response.Content.ReadAsStringAsync(), JsonOpts);
        }
        catch (JsonException ex)
        {
            DashboardLog.Error($"Unexpected response from {path}", ex);
            return default;
        }
    }

    private async Task<ActionResultDto> PostAsync(string path, object? body)
    {
        var json = body is null ? null : JsonSerializer.Serialize(body, JsonOpts);
        using var response = await SendAsync(HttpMethod.Post, path, json);
        if (response is null) return new ActionResultDto { Ok = false, Error = ServiceNotRunning };

        var text = await response.Content.ReadAsStringAsync();
        var ok = response.IsSuccessStatusCode && ReadBool(text, "ok");
        return new ActionResultDto
        {
            Ok = ok,
            Message = ReadString(text, "message"),
            Error = ok ? null : ReadString(text, "error") ?? ReadString(text, "detail") ?? $"Request failed ({(int)response.StatusCode})",
        };
    }

    /// <summary>Returns null if the service can't be reached. Never throws for network failures.</summary>
    private async Task<HttpResponseMessage?> SendAsync(HttpMethod method, string path, string? json)
    {
        _endpoint ??= ReadEndpoint();
        if (_endpoint is null) return null;
        try
        {
            var response = await SendOnceAsync(_endpoint, method, path, json);
            if (response.StatusCode != HttpStatusCode.Unauthorized) return response;

            // The service makes a new token each time it starts.
            response.Dispose();
            _endpoint = ReadEndpoint();
            return _endpoint is null ? null : await SendOnceAsync(_endpoint, method, path, json);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            _endpoint = null;
            return null;
        }
    }

    private async Task<HttpResponseMessage> SendOnceAsync(ApiEndpoint endpoint, HttpMethod method, string path, string? json)
    {
        using var request = new HttpRequestMessage(method, endpoint.BaseUrl + path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", endpoint.Token);
        if (json is not null) request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        return await _http.SendAsync(request);
    }

    private static ApiEndpoint? ReadEndpoint()
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(TokenPath));
            var token = doc.RootElement.GetProperty("token").GetString();
            var port = doc.RootElement.GetProperty("port").GetInt32();
            return string.IsNullOrEmpty(token) ? null : new ApiEndpoint($"http://127.0.0.1:{port}", token);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException
            or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            return null;
        }
    }

    private static bool ReadBool(string json, string name)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty(name, out var value)
                && value.ValueKind == JsonValueKind.True;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static string? ReadString(string json, string name)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind == JsonValueKind.Object
                && doc.RootElement.TryGetProperty(name, out var value)
                && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
        }
        catch (JsonException)
        {
            return null;
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
public record NetStatsDto(int AiConnections, int TotalSeen);
public record AuditEntryDto(int Id, string Timestamp, string AppName, string ResourceType, string Resource, string Action, string Decision, string Message);
public record ExtensionDto(string Browser, string Id, string Name, string Path);
public record ModelFileDto(string Path, double SizeMb, string Type);
public record AppPolicyDto(
    string AppName, string DefaultAction, string Files, string Network,
    string Clipboard, string Microphone, string Camera);
