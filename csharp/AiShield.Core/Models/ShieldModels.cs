namespace AiShield.Core.Models;

public enum PolicyAction { Allow, Block, Ask }

public enum ResourceType { File, Network, Clipboard, Screenshot, Microphone, Camera, Process }

public enum EventSeverity { Info, Warning, Critical }

public record AiProcess(
    int Pid, string Name, string Exe, string AiType,
    int Confidence, double GpuMb = 0);

public record ShieldEvent(
    string Id, DateTime Timestamp, EventSeverity Severity,
    ResourceType ResourceType, PolicyAction Action,
    string SourceApp, string Resource, string Message,
    string? UserDecision = null);

public record AccessRequest(
    string Id, DateTime Timestamp, string AppName, int AppPid,
    ResourceType ResourceType, string ResourcePath, PolicyAction Policy);

public record ProtectedFolder(string Name, string Path, PolicyAction Policy);

public record NetworkConnection(
    int Pid, string ProcessName, string LocalAddr, string RemoteAddr,
    string RemoteHost, string Status, bool IsAiTraffic);
