using System.Text;

namespace AiShield.Core.Ipc;

/// <summary>The audit log as CSV that's safe to open in a spreadsheet.</summary>
public static class AuditCsv
{
    private static readonly char[] FormulaStarts = ['=', '+', '-', '@', '\t', '\r'];

    public static string Write(IEnumerable<AuditEntryDto> entries)
    {
        var csv = new StringBuilder("timestamp,app_name,resource_type,resource,action,decision,message");
        foreach (var e in entries.Reverse())
        {
            csv.Append('\n');
            csv.AppendJoin(',', new[] { e.Timestamp, e.AppName, e.ResourceType, e.Resource, e.Action, e.Decision, e.Message }.Select(Cell));
        }
        return csv.ToString();
    }

    private static string Cell(string? value)
    {
        var text = value ?? "";
        // Values come from other programs. A spreadsheet would run one that starts like a formula.
        if (text.Length > 0 && FormulaStarts.Contains(text[0]))
            text = "'" + text;
        return text.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + text.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : text;
    }
}
