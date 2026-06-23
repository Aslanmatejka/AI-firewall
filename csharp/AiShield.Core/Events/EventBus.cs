using AiShield.Core.Models;

namespace AiShield.Core.Events;

public sealed class EventBus
{
    private readonly List<ShieldEvent> _events = [];
    private readonly object _lock = new();

    public event Action<ShieldEvent>? EventPublished;

    public void Emit(ShieldEvent evt)
    {
        lock (_lock)
        {
            _events.Insert(0, evt);
            if (_events.Count > 500) _events.RemoveAt(_events.Count - 1);
        }
        EventPublished?.Invoke(evt);
    }

    public IReadOnlyList<ShieldEvent> GetRecent(int limit = 50)
    {
        lock (_lock)
            return _events.Take(limit).ToList();
    }
}
