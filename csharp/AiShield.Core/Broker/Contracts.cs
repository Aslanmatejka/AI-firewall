using System.Collections.Frozen;
using System.Diagnostics;
using AiShield.Core.Detection;
using AiShield.Core.Ipc;

namespace AiShield.Core.Broker;

/// <summary>Who is on the other end of a pipe connection, as Windows reports it.</summary>
public sealed record PipeCaller(int ProcessId, int SessionId, string? ImagePath, bool Trusted);

/// <summary>Shows the secure confirmation prompt in a user's session.</summary>
public interface IConsentPrompter
{
    Task<ConsentOutcome> AskAsync(int sessionId, ConsentText text, CancellationToken ct);
}

public interface IAiProcessView
{
    IReadOnlyList<TrackedAiProcess> AiApps();
    TrackedAiProcess? Find(int pid);
}

public interface IHelperControl
{
    /// <summary>The user closed the desktop app on purpose, so don't restart it in this session.</summary>
    void SuppressSession(int sessionId);
}

public interface IProcessStopper
{
    StopResult Stop(int pid);
}

public sealed record StopResult(bool Stopped, string Name, string Reason);

/// <summary>The one place that decides whether AI Firewall may stop a process.</summary>
public sealed class ProcessStopper : IProcessStopper
{
    // Stopping any of these takes down far more than an AI feature: Windows itself,
    // every open browser tab, or whatever the user was running in a terminal.
    public static FrozenSet<string> ProtectedNames { get; } = new[]
    {
        "csrss.exe", "ctfmon.exe", "dwm.exe", "explorer.exe", "fontdrvhost.exe", "lsass.exe", "registry",
        "runtimebroker.exe", "searchhost.exe", "services.exe", "sihost.exe", "smss.exe", "spoolsv.exe",
        "startmenuexperiencehost.exe", "svchost.exe", "system", "system idle process", "taskhostw.exe",
        "textinputhost.exe", "wininit.exe", "winlogon.exe",
        "arc.exe", "brave.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "msedge.exe", "msedgewebview2.exe",
        "opera.exe", "vivaldi.exe",
        "bash.exe", "cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "wsl.exe",
        "wslhost.exe", "wt.exe",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    public StopResult Stop(int pid)
    {
        if (pid == Environment.ProcessId)
            return new StopResult(false, "AI Firewall", "AI Firewall won't stop itself");
        try
        {
            using var process = Process.GetProcessById(pid);
            var name = process.ProcessName + ".exe";
            if (ProtectedNames.Contains(name))
                return new StopResult(false, name, $"{name} is protected and won't be stopped");
            process.Kill(entireProcessTree: false);
            return process.WaitForExit(TimeSpan.FromSeconds(5))
                ? new StopResult(true, name, "")
                : new StopResult(false, name, $"{name} didn't exit in time");
        }
        catch (ArgumentException)
        {
            return new StopResult(false, "", "Process not found");
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return new StopResult(false, "", ex.Message);
        }
    }
}
