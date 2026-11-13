namespace AiShield.Core.Broker;

/// <summary>
/// Limits how often the same kind of event is recorded, so a program can't flood the audit log by
/// starting the same, or ever-differently named, process over and over.
/// </summary>
public sealed class EventThrottle(TimeSpan perKeyWindow, int maxPerMinute, int maxKeys = 1024)
{
    private readonly Lock _gate = new();
    private readonly Dictionary<string, (DateTimeOffset Since, int Suppressed)> _windows = new(StringComparer.OrdinalIgnoreCase);
    private readonly Queue<DateTimeOffset> _recent = new();

    /// <summary>
    /// True if this event should be recorded. <paramref name="suppressed"/> says how many like it were
    /// dropped since the last one recorded for the same key.
    /// </summary>
    public bool ShouldRecord(string key, DateTimeOffset now, out int suppressed)
    {
        lock (_gate)
        {
            suppressed = 0;
            if (_windows.TryGetValue(key, out var window) && now - window.Since < perKeyWindow)
            {
                _windows[key] = window with { Suppressed = window.Suppressed + 1 };
                return false;
            }

            while (_recent.Count > 0 && now - _recent.Peek() >= TimeSpan.FromMinutes(1))
                _recent.Dequeue();
            if (_recent.Count >= maxPerMinute)
                return false;

            if (window != default)
                suppressed = window.Suppressed;
            if (!_windows.ContainsKey(key) && _windows.Count >= maxKeys)
                Evict(now);
            _windows[key] = (now, 0);
            _recent.Enqueue(now);
            return true;
        }
    }

    private void Evict(DateTimeOffset now)
    {
        foreach (var expired in _windows.Where(w => now - w.Value.Since >= perKeyWindow).Select(w => w.Key).ToList())
            _windows.Remove(expired);
        if (_windows.Count >= maxKeys)
            _windows.Remove(_windows.MinBy(w => w.Value.Since).Key);
    }
}

/// <summary>
/// After the user turns down a prompt, the next one waits longer and longer, so a misbehaving program
/// can't wear them down by asking again and again. The wait resets after a quiet spell or a yes.
/// </summary>
public sealed class RefusalBackoff(TimeSpan first, TimeSpan max, TimeSpan forgiveAfter)
{
    private readonly Lock _gate = new();
    private int _refusals;
    private DateTimeOffset _lastRefusal;

    public DateTimeOffset QuietUntil(DateTimeOffset now)
    {
        lock (_gate)
        {
            if (_refusals == 0 || now - _lastRefusal >= forgiveAfter)
                return DateTimeOffset.MinValue;
            var wait = TimeSpan.FromTicks(Math.Min(first.Ticks << Math.Min(_refusals - 1, 16), max.Ticks));
            return _lastRefusal + wait;
        }
    }

    public void Refused(DateTimeOffset now)
    {
        lock (_gate)
        {
            if (now - _lastRefusal >= forgiveAfter)
                _refusals = 0;
            _refusals++;
            _lastRefusal = now;
        }
    }

    public void Approved()
    {
        lock (_gate)
            _refusals = 0;
    }
}
