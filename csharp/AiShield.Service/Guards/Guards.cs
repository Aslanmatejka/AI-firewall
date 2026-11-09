using System.Collections.Concurrent;
using AiShield.Core.Guards;

namespace AiShield.Service.Guards;

internal interface IGuard
{
    string Name { get; }
    GuardStatus Status { get; }
    Task StartAsync(CancellationToken ct);
    Task StopAsync(CancellationToken ct);
}

/// <summary>Starts every guard and reports each one's honest status, including guards that failed.</summary>
internal sealed class GuardHost(IEnumerable<IGuard> guards, ILogger<GuardHost> log) : IHostedService, IGuardStatusView
{
    private readonly IReadOnlyList<IGuard> _guards = guards.ToList();
    private readonly ConcurrentDictionary<string, GuardStatus> _failures = new();

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        foreach (var guard in _guards)
        {
            try
            {
                await guard.StartAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "The {Guard} guard failed to start", guard.Name);
                _failures[guard.Name] = guard.Status with { State = GuardState.Unavailable, Reason = $"Failed to start: {ex.Message}" };
            }
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (var guard in _guards)
        {
            try
            {
                await guard.StopAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                log.LogWarning(ex, "The {Guard} guard didn't stop cleanly", guard.Name);
            }
        }
    }

    public IReadOnlyList<GuardStatus> Current()
        => _guards.Select(g => _failures.TryGetValue(g.Name, out var failed) ? failed : g.Status).ToList();
}

/// <summary>A protection the service doesn't provide yet, listed so the UI never implies it does.</summary>
internal sealed class PlannedGuard(string name, string reason, string promise) : IGuard
{
    public string Name => name;
    public GuardStatus Status { get; } = new(name, GuardState.Unavailable, reason, promise);
    public Task StartAsync(CancellationToken ct) => Task.CompletedTask;
    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;

    public static IEnumerable<IGuard> All()
    {
        yield return new PlannedGuard(
            "Network",
            "Not in this version. The previous network check recognized none of the AI services it was given.",
            "Block network access per app");
        yield return new PlannedGuard(
            "Files",
            "Not in this version yet.",
            "Notice when an AI app opens files in protected folders, within about a second");
        yield return new PlannedGuard(
            "Microphone and camera",
            "Not in this version yet.",
            "Notice when an AI app starts using the microphone or camera");
        yield return new PlannedGuard(
            "Clipboard",
            "Not in this version yet.",
            "Notice sensitive text copied while an AI app is in front");
    }
}
