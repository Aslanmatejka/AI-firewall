using AiShield.Core.Approvals;
using AiShield.Core.Models;

namespace AiShield.Core.Tests;

public sealed class ApprovalQueueTests
{
    private readonly ManualClock _clock = new(new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero));

    private ApprovalQueue NewQueue() => new(TimeSpan.FromSeconds(120), () => _clock.Now);

    private static AccessRequestDraft Draft(string target = "api.openai.com", string app = "Cursor")
        => new(app, 42, ResourceType.Network, target, PolicyAction.Ask);

    [Fact]
    public void RepeatedRequestsShareOnePrompt()
    {
        var queue = NewQueue();
        var answers = new List<PolicyAction>();
        var first = queue.Submit(Draft(), r => answers.Add(r.Decision));
        var second = queue.Submit(Draft(target: "API.OPENAI.COM", app: "cursor"), r => answers.Add(r.Decision));

        Assert.Equal(first.Id, second.Id);
        Assert.Equal(2, second.Count);
        Assert.Single(queue.Snapshot());

        Assert.True(queue.Resolve(first.Id, PolicyAction.Allow, DecisionSource.User));
        Assert.Equal([PolicyAction.Allow, PolicyAction.Allow], answers);
    }

    [Fact]
    public void DifferentTargetsAreDifferentPrompts()
    {
        var queue = NewQueue();
        queue.Submit(Draft("a.example"));
        queue.Submit(Draft("b.example"));
        Assert.Equal(2, queue.Snapshot().Count);
    }

    [Fact]
    public void ARequestIsDecidedOnlyOnce()
    {
        var queue = NewQueue();
        var resolved = new List<ResolvedRequest>();
        queue.Resolved += resolved.Add;
        var request = queue.Submit(Draft());

        Assert.True(queue.Resolve(request.Id, PolicyAction.Block, DecisionSource.User));
        Assert.False(queue.Resolve(request.Id, PolicyAction.Allow, DecisionSource.User));
        Assert.Single(resolved);
        Assert.Equal(PolicyAction.Block, resolved[0].Decision);
    }

    [Fact]
    public void UnansweredRequestsAreBlockedAfterTheTimeout()
    {
        var queue = NewQueue();
        var resolved = new List<ResolvedRequest>();
        queue.Resolved += resolved.Add;
        var request = queue.Submit(Draft());

        _clock.Advance(TimeSpan.FromSeconds(119));
        Assert.Equal(0, queue.ExpireOverdue());
        _clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(1, queue.ExpireOverdue());

        Assert.Equal(DecisionSource.Timeout, resolved.Single().Source);
        Assert.Equal(PolicyAction.Block, resolved.Single().Decision);
        Assert.False(queue.Resolve(request.Id, PolicyAction.Allow, DecisionSource.User), "a late Allow must not count");
    }

    [Fact]
    public void ConcurrentAnswersProduceExactlyOneDecision()
    {
        for (var round = 0; round < 50; round++)
        {
            var queue = NewQueue();
            var request = queue.Submit(Draft());
            var decisions = 0;
            queue.Resolved += _ => Interlocked.Increment(ref decisions);

            Parallel.Invoke(
                () => queue.Resolve(request.Id, PolicyAction.Allow, DecisionSource.User),
                () => queue.Resolve(request.Id, PolicyAction.Block, DecisionSource.User),
                () => queue.ExpireOverdue(),
                () => queue.BlockAll(DecisionSource.Shutdown));

            Assert.Equal(1, decisions);
        }
    }

    [Fact]
    public void ShutdownBlocksEverythingPending()
    {
        var queue = NewQueue();
        var answers = new List<PolicyAction>();
        queue.Submit(Draft("a"), r => answers.Add(r.Decision));
        queue.Submit(Draft("b"), r => answers.Add(r.Decision));
        queue.BlockAll(DecisionSource.Shutdown);
        Assert.Equal([PolicyAction.Block, PolicyAction.Block], answers);
        Assert.Empty(queue.Snapshot());
    }
}
