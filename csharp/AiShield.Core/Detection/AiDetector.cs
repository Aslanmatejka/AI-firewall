using System.Collections.Frozen;
using AiShield.Core.Config;

namespace AiShield.Core.Detection;

public sealed record AiMatch(string AppName, int Confidence, string DetectedBy);

/// <summary>Recognizes AI programs by file name, and AI command-line tools by what their interpreter runs.</summary>
public sealed class AiDetector(IReadOnlyList<AiSignature> signatures)
{
    // Command-line agents such as Claude Code run as node.exe or python.exe. Only their command line says what they are.
    private static readonly FrozenSet<string> InterpreterHosts = new[]
    {
        "node.exe", "bun.exe", "deno.exe", "python.exe", "pythonw.exe", "py.exe",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenSet<string> NeverAi = new[]
    {
        "conhost.exe", "pet.exe",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    // Extension tooling that lives inside an AI app's folder but isn't the app.
    private static readonly string[] HelperFolders = [@"\.cursor\extensions\", @"\helpers\"];

    public AiMatch? Match(string imagePath, string? commandLine)
    {
        var fileName = Path.GetFileName(imagePath);
        if (fileName.Length == 0 || NeverAi.Contains(fileName))
            return null;

        var path = imagePath.Replace('/', '\\');
        if (HelperFolders.Any(folder => path.Contains(folder, StringComparison.OrdinalIgnoreCase)))
            return null;

        return InterpreterHosts.Contains(fileName) ? MatchCommandLine(commandLine) : MatchFileName(fileName);
    }

    private AiMatch? MatchFileName(string fileName)
    {
        // Only the program's own name counts. Folder names on its path would flag anything run from ".claude".
        AiMatch? best = null;
        foreach (var signature in signatures)
        {
            foreach (var pattern in signature.Patterns)
            {
                // "cursor.exe" names one program exactly; a bare word like "ollama" may appear anywhere in the name.
                var matches = pattern.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? fileName.Equals(pattern, StringComparison.OrdinalIgnoreCase)
                    : pattern.Length > 0 && fileName.Contains(pattern, StringComparison.OrdinalIgnoreCase);
                if (!matches)
                    continue;
                var confidence = Math.Min(99, 70 + pattern.Length * 2);
                if (best is null || confidence > best.Confidence)
                    best = new AiMatch(signature.Name, confidence, "program name");
            }
        }
        return best;
    }

    private AiMatch? MatchCommandLine(string? commandLine)
    {
        if (string.IsNullOrEmpty(commandLine))
            return null;

        var normalized = commandLine.Replace('\\', '/');
        AiMatch? best = null;
        foreach (var signature in signatures)
        {
            foreach (var pattern in signature.CommandLinePatterns)
            {
                var wanted = pattern.Replace('\\', '/');
                if (wanted.Length == 0 || !normalized.Contains(wanted, StringComparison.OrdinalIgnoreCase))
                    continue;
                var confidence = Math.Min(99, 75 + wanted.Length);
                if (best is null || confidence > best.Confidence)
                    best = new AiMatch(signature.Name, confidence, "command line");
            }
        }
        return best;
    }
}
