using System.Security.Cryptography;
using System.Text;

namespace AiShield.Core.Models;

/// <summary>Ordered from least to most strict, so a lower value is a weaker policy.</summary>
public enum PolicyAction
{
    Allow = 0,
    Ask = 1,
    Block = 2,
}

public enum ResourceType
{
    File,
    Network,
    Clipboard,
    Screenshot,
    Microphone,
    Camera,
    Process,
}

public enum EventSeverity
{
    Info,
    Warning,
    Critical,
}

public sealed record ShieldEvent(
    string Id,
    DateTimeOffset Timestamp,
    EventSeverity Severity,
    ResourceType ResourceType,
    PolicyAction Action,
    string SourceApp,
    string Resource,
    string Message,
    string? UserDecision = null);

/// <summary>The lower-case names used in config files, the database and the wire format.</summary>
public static class Wire
{
    public static string ToWire(this PolicyAction action) => action switch
    {
        PolicyAction.Allow => "allow",
        PolicyAction.Ask => "ask",
        _ => "block",
    };

    public static string ToWire(this ResourceType type) => type switch
    {
        ResourceType.File => "file",
        ResourceType.Network => "network",
        ResourceType.Clipboard => "clipboard",
        ResourceType.Screenshot => "screenshot",
        ResourceType.Microphone => "microphone",
        ResourceType.Camera => "camera",
        _ => "process",
    };

    public static string ToWire(this EventSeverity severity) => severity switch
    {
        EventSeverity.Info => "info",
        EventSeverity.Warning => "warning",
        _ => "critical",
    };

    public static bool TryParsePolicy(string? value, out PolicyAction action)
    {
        switch (value)
        {
            case "allow":
                action = PolicyAction.Allow;
                return true;
            case "ask":
                action = PolicyAction.Ask;
                return true;
            case "block":
                action = PolicyAction.Block;
                return true;
            default:
                action = PolicyAction.Ask;
                return false;
        }
    }

    public static bool TryParseResource(string? value, out ResourceType type)
    {
        foreach (var candidate in Enum.GetValues<ResourceType>())
        {
            if (candidate.ToWire() == value)
            {
                type = candidate;
                return true;
            }
        }
        type = ResourceType.Process;
        return false;
    }
}

public static class Ids
{
    public static string New() => Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
}

/// <summary>Makes text from other programs safe to show the user: one line, bounded, and no tricks.</summary>
public static class DisplayText
{
    public static string Clean(string? value, int maxLength = 120)
    {
        if (string.IsNullOrEmpty(value))
            return "";

        var text = new StringBuilder(Math.Min(value.Length, maxLength));
        foreach (var ch in value)
        {
            if (text.Length >= maxLength)
                break;
            // Control and bidirectional-override characters can fake line breaks or reverse text.
            int code = ch;
            var hidden = char.IsControl(ch)
                || code is 0x200E or 0x200F or 0x2028 or 0x2029
                || code is >= 0x202A and <= 0x202E
                || code is >= 0x2066 and <= 0x2069;
            text.Append(hidden ? ' ' : ch);
        }

        var cleaned = text.ToString().Trim();
        return value.Length > maxLength ? cleaned + "…" : cleaned;
    }
}
