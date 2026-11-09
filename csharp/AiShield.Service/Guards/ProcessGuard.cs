using System.Collections.Concurrent;
using System.Diagnostics;
using AiShield.Core.Detection;
using AiShield.Core.Guards;
using AiShield.Core.Windows;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace AiShield.Service.Guards;

/// <summary>
/// Watches process starts with Windows event tracing, so even short-lived command-line agents are seen.
/// A scan every 10 seconds catches anything the event stream missed.
/// </summary>
internal sealed class ProcessGuard(ProcessTracker tracker, ILogger<ProcessGuard> log) : IGuard, IDisposable
{
    public const string SessionName = "AiShield-ProcessGuard";
    private const string GuardName = "AI apps";
    private const string Promise = "Notices AI apps and command-line agents as they start, and what they launch";
    private const ulong ProcessKeyword = 0x10;
    private static readonly Guid KernelProcessProvider = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
    private static readonly TimeSpan ScanInterval = TimeSpan.FromSeconds(10);

    private readonly ConcurrentDictionary<int, byte> _seenByEvents = new();
    private readonly CancellationTokenSource _stopping = new();
    private TraceEventSession? _session;
    private Thread? _thread;
    private Timer? _scanTimer;
    private volatile GuardStatus _status = new(GuardName, GuardState.Off, "Starting", Promise);
    private DateTimeOffset _lastEvent;

    public string Name => GuardName;

    public GuardStatus Status => _status.State == GuardState.Active && _lastEvent > (_status.LastEvidence ?? default)
        ? _status with { LastEvidence = _lastEvent }
        : _status;

    public Task StartAsync(CancellationToken ct)
    {
        Scan();
        _thread = new Thread(RunEventSession) { IsBackground = true, Name = "ProcessGuard events" };
        _thread.Start();
        _scanTimer = new Timer(_ => SafeScan(), null, ScanInterval, ScanInterval);
        _ = Task.Run(() => ProveAsync(_stopping.Token), CancellationToken.None);
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken ct)
    {
        _stopping.Cancel();
        _scanTimer?.Dispose();
        _session?.Dispose();
        _thread?.Join(TimeSpan.FromSeconds(5));
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _stopping.Dispose();
        _scanTimer?.Dispose();
        _session?.Dispose();
    }

    private void RunEventSession()
    {
        try
        {
            // Creating a session with this name replaces one a previous crash left behind.
            using var session = new TraceEventSession(SessionName) { StopOnDispose = true };
            _session = session;
            var parser = new RegisteredTraceEventParser(session.Source);
            parser.All += OnEvent;
            session.EnableProvider(KernelProcessProvider, TraceEventLevel.Informational, ProcessKeyword);
            session.Source.Process();
        }
        catch (Exception ex) when (!_stopping.IsCancellationRequested)
        {
            log.LogError(ex, "Process event tracing failed");
            _status = new GuardStatus(GuardName, GuardState.Degraded,
                $"Event tracing failed ({ex.Message}). Scanning every 10 seconds instead, which can miss short-lived programs.",
                Promise);
        }
    }

    private void OnEvent(TraceEvent data)
    {
        if (data.ProviderGuid != KernelProcessProvider)
            return;
        try
        {
            switch ((int)data.ID)
            {
                case 1:
                    OnProcessStart(data);
                    break;
                case 2:
                    if (ReadInt(data, "ProcessID") is { } stopped)
                        tracker.OnStop(stopped);
                    break;
            }
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Couldn't handle process event {Id}", data.ID);
        }
    }

    private void OnProcessStart(TraceEvent data)
    {
        if (ReadInt(data, "ProcessID") is not { } pid)
            return;
        _lastEvent = DateTimeOffset.UtcNow;
        _seenByEvents[pid] = 0;

        var image = NativeProcess.TryGetImagePath(pid) ?? ReadString(data, "ImageName") ?? "";
        tracker.OnStart(new ProcessStart(
            pid, ReadInt(data, "ParentProcessID") ?? 0, image, NativeProcess.TryGetCommandLine(pid),
            ReadInt(data, "SessionID") ?? -1, DateTimeOffset.UtcNow));
    }

    /// <summary>Starts a harmless process and checks the event stream reports it, so "Active" is earned.</summary>
    private async Task ProveAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(3), ct).ConfigureAwait(false);
            if (_status.State == GuardState.Degraded)
                return;

            using var canary = Process.Start(new ProcessStartInfo("cmd.exe", "/c exit 0")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
            });
            if (canary is null)
                return;

            for (var waited = 0; waited < 40 && !_seenByEvents.ContainsKey(canary.Id); waited++)
                await Task.Delay(TimeSpan.FromMilliseconds(250), ct).ConfigureAwait(false);

            _status = _seenByEvents.ContainsKey(canary.Id)
                ? new GuardStatus(GuardName, GuardState.Active, "Watching process starts with event tracing", Promise, DateTimeOffset.UtcNow)
                : new GuardStatus(GuardName, GuardState.Degraded,
                    "Event tracing isn't reporting process starts. Scanning every 10 seconds instead, which can miss short-lived programs.",
                    Promise);
            log.LogInformation("Process guard: {State} ({Reason})", _status.State, _status.Reason);
        }
        catch (OperationCanceledException)
        {
            // Stopping.
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            log.LogWarning(ex, "Couldn't run the process guard self-check");
        }
    }

    private void SafeScan()
    {
        try
        {
            Scan();
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Process scan failed");
        }
    }

    private void Scan()
    {
        var snapshot = NativeProcess.Snapshot();
        var running = snapshot.ToDictionary(e => e.Pid, e => e.ExeName);

        foreach (var pid in tracker.KnownPids())
        {
            // Gone, or the PID now belongs to a different program because a stop event was missed.
            if (!running.TryGetValue(pid, out var exe)
                || !string.Equals(Path.GetFileName(tracker.ImageOf(pid)), exe, StringComparison.OrdinalIgnoreCase))
            {
                tracker.OnStop(pid);
            }
        }

        var now = DateTimeOffset.UtcNow;
        tracker.Seed(snapshot
            .Where(e => !tracker.Knows(e.Pid))
            .Select(e => new ProcessStart(
                e.Pid, e.ParentPid, NativeProcess.TryGetImagePath(e.Pid) ?? e.ExeName,
                NativeProcess.TryGetCommandLine(e.Pid), NativeProcess.GetSessionId(e.Pid) ?? -1, now))
            .ToList());
    }

    private static object? Payload(TraceEvent data, string name)
    {
        var names = data.PayloadNames;
        for (var i = 0; i < names.Length; i++)
        {
            if (string.Equals(names[i], name, StringComparison.OrdinalIgnoreCase))
                return data.PayloadValue(i);
        }
        return null;
    }

    private static int? ReadInt(TraceEvent data, string name) => Payload(data, name) switch
    {
        int i => i,
        uint u => (int)u,
        long l => (int)l,
        ulong ul => (int)ul,
        _ => null,
    };

    private static string? ReadString(TraceEvent data, string name) => Payload(data, name) as string;
}
