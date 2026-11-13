using AiShield.Core.Broker;
using AiShield.Core.Ipc;
using AiShield.Core.Models;
using AiShield.Core.Policy;

namespace AiShield.Core.Tests;

public sealed class EventThrottleTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RecordsEachAppOncePerWindowAndCountsTheRest()
    {
        var throttle = new EventThrottle(TimeSpan.FromMinutes(10), maxPerMinute: 30);
        Assert.True(throttle.ShouldRecord("Ollama", T0, out _));
        for (var i = 1; i <= 50; i++)
            Assert.False(throttle.ShouldRecord("ollama", T0.AddSeconds(i), out _));

        Assert.True(throttle.ShouldRecord("Ollama", T0.AddMinutes(11), out var suppressed));
        Assert.Equal(50, suppressed);
    }

    [Fact]
    public void ChangingNamesDoesntGetPastTheOverallLimit()
    {
        var throttle = new EventThrottle(TimeSpan.FromMinutes(10), maxPerMinute: 30);
        var recorded = Enumerable.Range(0, 1000).Count(i => throttle.ShouldRecord($"claude{i}", T0.AddMilliseconds(i), out _));
        Assert.Equal(30, recorded);
        Assert.True(throttle.ShouldRecord("claude-later", T0.AddMinutes(2), out _));
    }

    [Fact]
    public void RemembersABoundedNumberOfNames()
    {
        var throttle = new EventThrottle(TimeSpan.FromMinutes(10), maxPerMinute: int.MaxValue, maxKeys: 10);
        for (var i = 0; i < 100; i++)
            throttle.ShouldRecord($"app{i}", T0.AddSeconds(i), out _);
        // The newest names are still remembered; memory stays bounded however many names an attacker uses.
        Assert.False(throttle.ShouldRecord("app99", T0.AddSeconds(100), out _));
    }
}

public sealed class RefusalBackoffTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void EachRefusalDoublesTheWaitUpToAMinute()
    {
        var backoff = new RefusalBackoff(TimeSpan.FromSeconds(3), TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(10));
        Assert.Equal(DateTimeOffset.MinValue, backoff.QuietUntil(T0));

        var waits = new List<TimeSpan>();
        var now = T0;
        for (var i = 0; i < 7; i++)
        {
            backoff.Refused(now);
            waits.Add(backoff.QuietUntil(now) - now);
            now = backoff.QuietUntil(now);
        }
        Assert.Equal([3, 6, 12, 24, 48, 60, 60], waits.Select(w => (int)w.TotalSeconds));
    }

    [Fact]
    public void ApprovalOrAQuietSpellResetsIt()
    {
        var backoff = new RefusalBackoff(TimeSpan.FromSeconds(3), TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(10));
        backoff.Refused(T0);
        backoff.Refused(T0.AddSeconds(5));
        backoff.Approved();
        Assert.Equal(DateTimeOffset.MinValue, backoff.QuietUntil(T0.AddSeconds(6)));

        backoff.Refused(T0.AddSeconds(10));
        Assert.Equal(DateTimeOffset.MinValue, backoff.QuietUntil(T0.AddMinutes(30)));
    }
}

public sealed class PipeHardeningTests
{
    [Fact]
    public void PipeNamesAreRandomAndStrictlyFormed()
    {
        var a = PipeProtocol.NewPipeName();
        var b = PipeProtocol.NewPipeName();
        Assert.NotEqual(a, b);
        Assert.True(PipeProtocol.IsValidPipeName(a));
        Assert.Matches("^AiShield\\.v1\\.[0-9a-f]{16}$", a);

        foreach (var bad in new[] { null, "", "AiShield.v1", "AiShield.v1.ABCDEF0123456789", "AiShield.v1.0123456789abcdeg",
                     "AiShield.v1.0123456789abcdef0", @"..\..\pipe\x" })
        {
            Assert.False(PipeProtocol.IsValidPipeName(bad), bad);
        }
    }

    [Fact]
    public async Task UntrustedSizeLimitIsCheckedBeforeReading()
    {
        // A header promising 5 KB is refused at once, without waiting for or setting aside the body.
        using var stream = new MemoryStream([0x00, 0x14, 0x00, 0x00]);
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            PipeProtocol.ReadMessageAsync(stream, TestContext.Current.CancellationToken, PipeProtocol.MaxUntrustedMessageBytes));
    }

    [Fact]
    public void AuditLogKeepsOnlyTheNewestEntries()
    {
        using var dir = new TempDirectory();
        using var store = new PolicyStore(Path.Combine(dir.Path, "policy.db"), TestDefaults.Create(), maxAuditRows: 50);
        for (var i = 0; i < 500; i++)
        {
            store.Audit(new ShieldEvent(Ids.New(), DateTimeOffset.UtcNow, EventSeverity.Info, ResourceType.Process,
                PolicyAction.Ask, "AI", "x", $"entry {i}"));
        }
        var stats = store.GetStats();
        Assert.True(stats.AuditEntries <= 100, $"{stats.AuditEntries} entries kept");
        Assert.Equal("entry 499", store.GetAudit(1)[0].Message);
    }
}
