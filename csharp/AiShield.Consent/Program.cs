using System.IO;
using System.Text.Json;
using System.Windows;
using AiShield.Core.Ipc;
using AiShield.Core.Models;

namespace AiShield.Consent;

/// <summary>
/// The secure prompt. The service starts it as SYSTEM in the user's session. Stage one creates a private
/// desktop that only SYSTEM can reach and switches the screen to it; stage two shows the question there.
/// Programs running as the user can't see, read or click it, the same way UAC prompts work.
/// </summary>
internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            // Stage one starts stage two; stage two never starts anything.
            AiShield.Core.Windows.ProcessHardening.Apply(allowChildProcesses: !args.Contains("--stage2"));
            var request = Argument(args, "--request");
            if (request is null)
                return ConsentExitCodes.Error;

            var text = Decode(request);
            if (!args.Contains("--stage2"))
                return PrivateDesktop.Run(request);

            var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
            var window = new ConsentWindow(text, Argument(args, "--desktop") ?? "");
            window.Closed += (_, _) => app.Shutdown(window.Result);
            return app.Run(window);
        }
        catch (Exception)
        {
            // Never approve by accident: any failure is reported as an error, which the service treats as no.
            return ConsentExitCodes.Error;
        }
    }

    internal static string? Argument(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    /// <summary>Decodes the question and cleans every field again, whatever the service already did.</summary>
    internal static ConsentText Decode(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + ((4 - base64.Length % 4) % 4), '=');
        var text = JsonSerializer.Deserialize<ConsentText>(Convert.FromBase64String(base64), PipeProtocol.Json)
            ?? throw new InvalidDataException("Empty request");
        return new ConsentText(
            DisplayText.Clean(text.Title, 80),
            DisplayText.Clean(text.Summary, 200),
            (text.Details ?? []).Take(8).Select(d => DisplayText.Clean(d, 200)).ToList(),
            DisplayText.Clean(text.RequestedBy, 120));
    }
}
