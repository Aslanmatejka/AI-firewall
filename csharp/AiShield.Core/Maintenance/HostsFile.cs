namespace AiShield.Core.Maintenance;

/// <summary>
/// Removes the hosts-file blocks older versions added. Only lines exactly like the ones those versions
/// wrote are removed, so anything the user added themselves stays.
/// </summary>
public static class HostsFile
{
    public const string ScriptStart = "# AI-FIREWALL-START";
    public const string ScriptEnd = "# AI-FIREWALL-END";
    public const string EngineMarker = "# AiShield blocked domains";

    public static string Path { get; } =
        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers", "etc", "hosts");

    public static string RemoveLegacyEntries(string text, IEnumerable<string> aiDomains, out int removed)
    {
        var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var domain in aiDomains)
        {
            blocked.Add(domain);
            blocked.Add("www." + domain);
        }

        var newline = text.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";
        var kept = new List<string>();
        removed = 0;
        var inBlock = false;
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            var trimmed = line.Trim();
            if (trimmed is ScriptStart or EngineMarker)
            {
                inBlock = true;
                removed++;
                continue;
            }
            if (inBlock)
            {
                if (trimmed == ScriptEnd)
                {
                    inBlock = false;
                    removed++;
                    continue;
                }
                if (IsBlockEntry(trimmed, blocked))
                {
                    removed++;
                    continue;
                }
                // Anything else ends the block: it isn't ours to remove.
                inBlock = false;
            }
            kept.Add(line);
        }
        return removed == 0 ? text : string.Join(newline, kept);
    }

    private static bool IsBlockEntry(string line, HashSet<string> blocked)
    {
        var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 2 && parts[0] is ("127.0.0.1" or "0.0.0.0") && blocked.Contains(parts[1]);
    }
}
