namespace AiShield.Core.Ipc;

// The shapes the dashboard reads, from either the service pipe or the older Python API.
// Both use snake_case JSON, so one set of records serves both.

public class ActionResultDto
{
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public string? Message { get; set; }
}

public record StatusDto(
    bool Running,
    List<AiProcessDto> AiProcesses,
    List<NetworkConnDto> ActiveConnections,
    List<AccessRequestDto> PendingRequests,
    List<EventDto> RecentEvents,
    List<ProtectedFolderDto> ProtectedFolders,
    StatsDto? Stats,
    List<GuardStatusDto>? Guards = null,
    bool Lockdown = false,
    string? Backend = null);

public record ConfigDto(
    string NetworkPolicy,
    string ClipboardPolicy,
    string ScreenshotPolicy,
    string MicrophonePolicy,
    string CameraPolicy,
    string GlobalPolicy);

public record AiProcessDto(int Pid, string Name, string Exe, string AiType, int Confidence, double GpuMb, string? DetectedBy = null);

public record NetworkConnDto(int Pid, string ProcessName, string LocalAddr, string RemoteAddr, string RemoteHost, string Status, bool IsAiTraffic);

public record AccessRequestDto(
    string Id,
    string Timestamp,
    string AppName,
    int AppPid,
    string ResourceType,
    string ResourcePath,
    string Policy,
    int Count = 1);

public record EventDto(
    string Id,
    string Timestamp,
    string Severity,
    string ResourceType,
    string Action,
    string SourceApp,
    string Resource,
    string Message);

public record ProtectedFolderDto(string Name, string Path, string Policy);

public record StatsDto(PermStatsDto? Permissions, NetStatsDto? Network, int ExtensionsFound);

public record PermStatsDto(int Grants, int AuditEntries, int Blocked);

public record NetStatsDto(int AiConnections, int TotalSeen);

public record AuditEntryDto(
    int Id,
    string Timestamp,
    string AppName,
    string ResourceType,
    string Resource,
    string Action,
    string Decision,
    string Message);

public record ExtensionDto(string Browser, string Id, string Name, string Path);

public record ModelFileDto(string Path, double SizeMb, string Type);

public record AppPolicyDto(
    string AppName,
    string DefaultAction,
    string Files,
    string Network,
    string Clipboard,
    string Microphone,
    string Camera);

public record GuardStatusDto(string Name, string State, string Reason, string Promise, string? LastEvidence);

public record HelloDto(string Version, bool Trusted, string Backend);
