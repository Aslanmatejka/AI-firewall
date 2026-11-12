using System.Collections.Concurrent;
using System.ComponentModel;
using AiShield.Core.Broker;
using AiShield.Core.Ipc;
using AiShield.Service.Native;

namespace AiShield.Service.Sessions;

/// <summary>
/// Keeps the desktop app running in every signed-in session and brings it back if it's killed. If the
/// user closes it on purpose, it stays closed until they next sign in.
/// </summary>
internal sealed class HelperSupervisor(ServiceLayout layout, ILogger<HelperSupervisor> log) : CriticalService(log), IHelperControl
{
    private static readonly TimeSpan Tick = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan StableRun = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(60);

    private sealed class Slot
    {
        public LaunchedProcess? Process { get; set; }
        public DateTimeOffset StartedAt { get; set; }
        public TimeSpan Backoff { get; set; } = Tick;
        public DateTimeOffset NextAttempt { get; set; }
        public bool Suppressed { get; set; }
    }

    private readonly ConcurrentDictionary<int, Slot> _slots = new();

    public void SuppressSession(int sessionId)
    {
        _slots.GetOrAdd(sessionId, _ => new Slot()).Suppressed = true;
        log.LogInformation("The desktop app in session {Session} was closed on purpose and won't be restarted", sessionId);
    }

    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        if (!layout.IsService || !layout.InstallProtected || !File.Exists(layout.DashboardExe))
        {
            log.LogWarning("Not starting the desktop app in user sessions: {Reason}",
                !layout.IsService ? "not running as a service" : layout.InstallProtected ? "it isn't installed" : layout.InstallProblem);
            return;
        }

        using var timer = new PeriodicTimer(Tick);
        do
        {
            try
            {
                Supervise(DateTimeOffset.UtcNow);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Supervising the desktop app failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    private void Supervise(DateTimeOffset now)
    {
        var active = SessionNative.ActiveUserSessions().ToHashSet();
        foreach (var gone in _slots.Keys.Where(id => !active.Contains(id)).ToList())
        {
            // Signing out clears the slot, so the next sign-in starts the app again.
            if (_slots.TryRemove(gone, out var slot))
                slot.Process?.Dispose();
        }

        foreach (var sessionId in active)
        {
            var slot = _slots.GetOrAdd(sessionId, _ => new Slot());
            if (slot.Process is { } process)
            {
                if (!process.HasExited)
                    continue;
                OnExited(sessionId, slot, process, now);
            }

            if (slot.Suppressed || now < slot.NextAttempt)
                continue;

            // After a service restart the desktop app is usually still running. Watch it rather than
            // start a second copy that would only see the first and exit.
            if (FindRunningApp(sessionId) is { } running)
            {
                slot.Process = running;
                slot.StartedAt = now - StableRun;
                log.LogInformation("Watching the desktop app already running in session {Session} as PID {Pid}", sessionId, running.Id);
                continue;
            }
            try
            {
                slot.Process = SessionNative.StartAsUser(sessionId, layout.DashboardExe, "--background");
                slot.StartedAt = now;
                log.LogInformation("Started the desktop app in session {Session} as PID {Pid}", sessionId, slot.Process.Id);
            }
            catch (Win32Exception ex)
            {
                slot.NextAttempt = now + TimeSpan.FromSeconds(30);
                log.LogWarning(ex, "Couldn't start the desktop app in session {Session}", sessionId);
            }
        }
    }

    private LaunchedProcess? FindRunningApp(int sessionId)
    {
        foreach (var process in System.Diagnostics.Process.GetProcessesByName(Path.GetFileNameWithoutExtension(layout.DashboardExe)))
        {
            using (process)
            {
                if (process.SessionId != sessionId)
                    continue;
                var image = AiShield.Core.Windows.NativeProcess.TryGetImagePath(process.Id);
                if (image is not null && string.Equals(Path.GetFullPath(image), layout.DashboardExe, StringComparison.OrdinalIgnoreCase))
                    return SessionNative.Adopt(process.Id);
            }
        }
        return null;
    }

    private void OnExited(int sessionId, Slot slot, LaunchedProcess process, DateTimeOffset now)
    {
        var exitCode = process.ExitCode;
        process.Dispose();
        slot.Process = null;

        if (exitCode == HelperExitCodes.AnotherInstanceRunning)
        {
            // A copy is already running, started by the user or left from before a service restart.
            // Check again later in case it closes.
            slot.NextAttempt = now + TimeSpan.FromSeconds(60);
            return;
        }

        // Quick crashes back off, so a broken install doesn't spin. A long-running app comes straight back.
        slot.Backoff = now - slot.StartedAt < StableRun
            ? TimeSpan.FromTicks(Math.Min(slot.Backoff.Ticks * 2, MaxBackoff.Ticks))
            : Tick;
        slot.NextAttempt = now - slot.StartedAt < StableRun ? now + slot.Backoff : now;
        if (!slot.Suppressed)
            log.LogWarning("The desktop app in session {Session} exited with code {Code}; restarting", sessionId, exitCode);
    }

    public override void Dispose()
    {
        foreach (var slot in _slots.Values)
            slot.Process?.Dispose();
        base.Dispose();
    }
}
