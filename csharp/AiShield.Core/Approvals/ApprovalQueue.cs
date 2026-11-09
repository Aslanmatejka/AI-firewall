using AiShield.Core.Models;

namespace AiShield.Core.Approvals;

public enum DecisionSource
{
    User,
    Timeout,
    Shutdown,
}

public sealed record AccessRequestDraft(string AppName, int AppPid, ResourceType ResourceType, string Target, PolicyAction Policy)
{
    /// <summary>Requests with the same key are one prompt, however often the app asks.</summary>
    public string CoalescingKey => $"{AppName.ToUpperInvariant()}|{ResourceType.ToWire()}|{Target.ToUpperInvariant()}";
}

public sealed record PendingRequest(string Id, DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, AccessRequestDraft Draft, int Count);

public sealed record ResolvedRequest(PendingRequest Request, PolicyAction Decision, DecisionSource Source);

/// <summary>
/// Requests waiting for the user. Guards never wait on it: they hand in a callback. Each request
/// moves from pending to resolved exactly once, so a late answer can't follow a timeout.
/// </summary>
public sealed class ApprovalQueue(TimeSpan timeout, Func<DateTimeOffset>? clock = null)
{
    private sealed class Entry(PendingRequest request)
    {
        public PendingRequest Request { get; set; } = request;
        public List<Action<ResolvedRequest>> Callbacks { get; } = [];
    }

    private readonly Func<DateTimeOffset> _clock = clock ?? (() => DateTimeOffset.UtcNow);
    private readonly Lock _gate = new();
    private readonly Dictionary<string, Entry> _byId = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Entry> _byKey = new(StringComparer.Ordinal);

    /// <summary>Raised once per resolution, before the requesters' callbacks.</summary>
    public event Action<ResolvedRequest>? Resolved;

    public PendingRequest Submit(AccessRequestDraft draft, Action<ResolvedRequest>? onResolved = null)
    {
        lock (_gate)
        {
            if (_byKey.TryGetValue(draft.CoalescingKey, out var existing))
            {
                existing.Request = existing.Request with { Count = existing.Request.Count + 1 };
                if (onResolved is not null)
                    existing.Callbacks.Add(onResolved);
                return existing.Request;
            }

            var now = _clock();
            var entry = new Entry(new PendingRequest(Ids.New(), now, now + timeout, draft, 1));
            if (onResolved is not null)
                entry.Callbacks.Add(onResolved);
            _byId[entry.Request.Id] = entry;
            _byKey[draft.CoalescingKey] = entry;
            return entry.Request;
        }
    }

    public PendingRequest? Find(string id)
    {
        lock (_gate)
            return _byId.TryGetValue(id, out var entry) ? entry.Request : null;
    }

    public IReadOnlyList<PendingRequest> Snapshot()
    {
        lock (_gate)
            return _byId.Values.Select(e => e.Request).OrderBy(r => r.CreatedAt).ToList();
    }

    /// <summary>Returns false if the request was already resolved or never existed.</summary>
    public bool Resolve(string id, PolicyAction decision, DecisionSource source)
    {
        Entry? entry;
        lock (_gate)
        {
            if (!_byId.Remove(id, out entry))
                return false;
            _byKey.Remove(entry.Request.Draft.CoalescingKey);
        }

        var resolved = new ResolvedRequest(entry.Request, decision, source);
        Resolved?.Invoke(resolved);
        foreach (var callback in entry.Callbacks)
            callback(resolved);
        return true;
    }

    /// <summary>Blocks every request nobody answered in time. Returns how many it blocked.</summary>
    public int ExpireOverdue()
    {
        List<string> overdue;
        var now = _clock();
        lock (_gate)
            overdue = _byId.Values.Where(e => e.Request.ExpiresAt <= now).Select(e => e.Request.Id).ToList();
        return overdue.Count(id => Resolve(id, PolicyAction.Block, DecisionSource.Timeout));
    }

    public void BlockAll(DecisionSource source)
    {
        List<string> ids;
        lock (_gate)
            ids = [.. _byId.Keys];
        foreach (var id in ids)
            Resolve(id, PolicyAction.Block, source);
    }
}
