using System.Globalization;
using AiShield.Core.Ipc;

namespace AiShield.Core.Guards;

public enum GuardState
{
    Active,
    Degraded,
    Unavailable,
    Off,
}

/// <summary>
/// What a guard can honestly claim right now. Active needs recent evidence that it works, not just
/// that it started.
/// </summary>
public sealed record GuardStatus(string Name, GuardState State, string Reason, string Promise, DateTimeOffset? LastEvidence = null)
{
    public GuardStatusDto ToDto() => new(
        Name,
        State.ToString().ToLowerInvariant(),
        Reason,
        Promise,
        LastEvidence?.ToString("O", CultureInfo.InvariantCulture));
}

public interface IGuardStatusView
{
    IReadOnlyList<GuardStatus> Current();
}
