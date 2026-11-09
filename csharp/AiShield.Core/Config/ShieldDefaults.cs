using System.Text.Json;
using AiShield.Core.Models;

namespace AiShield.Core.Config;

public sealed record AiSignature(string Name, IReadOnlyList<string> Patterns, IReadOnlyList<string> CommandLinePatterns);

public static class GlobalPolicyKeys
{
    public const string Global = "global_policy";
    public const string Network = "network_policy";
    public const string Clipboard = "clipboard_policy";
    public const string Screenshot = "screenshot_policy";
    public const string Microphone = "microphone_policy";
    public const string Camera = "camera_policy";

    public static IReadOnlyList<string> All { get; } = [Global, Network, Clipboard, Screenshot, Microphone, Camera];

    public static bool IsKnown(string? key) => key is not null && All.Contains(key);

    public static string ForResource(ResourceType type) => type switch
    {
        ResourceType.Network => Network,
        ResourceType.Clipboard => Clipboard,
        ResourceType.Screenshot => Screenshot,
        ResourceType.Microphone => Microphone,
        ResourceType.Camera => Camera,
        _ => Global,
    };

    public static string Label(string key) => key switch
    {
        Network => "network access",
        Clipboard => "clipboard access",
        Screenshot => "screenshots",
        Microphone => "microphone access",
        Camera => "camera access",
        _ => "file and other access",
    };
}

/// <summary>The shipped defaults from config/default.json. Users change policy through the service, never this file.</summary>
public sealed class ShieldDefaults
{
    public required IReadOnlyDictionary<string, PolicyAction> GlobalPolicies { get; init; }
    public required IReadOnlyList<AiSignature> Signatures { get; init; }
    public required IReadOnlyList<string> AiDomains { get; init; }
    public TimeSpan ApprovalTimeout { get; init; } = TimeSpan.FromSeconds(120);
    public int HeuristicThreshold { get; init; } = 65;
    public double GpuThresholdMb { get; init; } = 512;

    public static ShieldDefaults Load(string path) => Parse(File.ReadAllText(path));

    public static ShieldDefaults Parse(string json)
    {
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
        });
        var root = doc.RootElement;

        var policies = new Dictionary<string, PolicyAction>(StringComparer.Ordinal);
        foreach (var key in GlobalPolicyKeys.All)
            policies[key] = Wire.TryParsePolicy(ReadString(root, key), out var parsed) ? parsed : PolicyAction.Ask;

        return new ShieldDefaults
        {
            GlobalPolicies = policies,
            Signatures = ReadSignatures(root),
            AiDomains = ReadStrings(root, "ai_domains"),
            ApprovalTimeout = TimeSpan.FromSeconds(Math.Clamp(ReadNumber(root, "approval_timeout_seconds", 120), 10, 3600)),
            HeuristicThreshold = (int)Math.Clamp(ReadNumber(root, "ml_heuristic_threshold", 65), 1, 100),
            GpuThresholdMb = Math.Max(1, ReadNumber(root, "gpu_threshold_mb", 512)),
        };
    }

    private static List<AiSignature> ReadSignatures(JsonElement root)
    {
        var signatures = new List<AiSignature>();
        if (!root.TryGetProperty("ai_process_signatures", out var array) || array.ValueKind != JsonValueKind.Array)
            return signatures;

        foreach (var item in array.EnumerateArray())
        {
            var name = ReadString(item, "name");
            if (string.IsNullOrWhiteSpace(name))
                continue;
            signatures.Add(new AiSignature(name, ReadStrings(item, "patterns"), ReadStrings(item, "command_line_patterns")));
        }
        return signatures;
    }

    private static string? ReadString(JsonElement element, string name)
        => element.ValueKind == JsonValueKind.Object
            && element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static double ReadNumber(JsonElement element, string name, double fallback)
        => element.TryGetProperty(name, out var value) && value.TryGetDouble(out var number) ? number : fallback;

    private static List<string> ReadStrings(JsonElement element, string name)
    {
        var values = new List<string>();
        if (!element.TryGetProperty(name, out var array) || array.ValueKind != JsonValueKind.Array)
            return values;
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } text)
                values.Add(text);
        }
        return values;
    }
}
