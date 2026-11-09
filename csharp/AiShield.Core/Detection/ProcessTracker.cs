using AiShield.Core.Broker;

namespace AiShield.Core.Detection;

public sealed record ProcessStart(int Pid, int ParentPid, string ImagePath, string? CommandLine, int SessionId, DateTimeOffset Seen);

public sealed record TrackedAiProcess(
    int Pid,
    string Name,
    string ImagePath,
    string AppName,
    int Confidence,
    string DetectedBy,
    int SessionId,
    DateTimeOffset Seen,
    int? RootPid);

/// <summary>
/// Every running process, with AI apps and everything they start marked. An AI app's child processes
/// count as that app, because agents do their work through shells and helpers.
/// </summary>
public sealed class ProcessTracker(AiDetector detector) : IAiProcessView
{
    private sealed record Entry(ProcessStart Start, TrackedAiProcess? Ai);

    private readonly Lock _gate = new();
    private readonly Dictionary<int, Entry> _processes = [];

    /// <summary>Raised once for each new AI app, not for the processes it starts.</summary>
    public event Action<TrackedAiProcess>? AiAppStarted;

    public bool Knows(int pid)
    {
        lock (_gate)
            return _processes.ContainsKey(pid);
    }

    public IReadOnlyCollection<int> KnownPids()
    {
        lock (_gate)
            return [.. _processes.Keys];
    }

    public void OnStart(ProcessStart start)
    {
        TrackedAiProcess? newApp = null;
        lock (_gate)
        {
            if (_processes.TryGetValue(start.Pid, out var existing)
                && string.Equals(existing.Start.ImagePath, start.ImagePath, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var parentAi = _processes.TryGetValue(start.ParentPid, out var parent) && start.ParentPid != start.Pid
                ? parent.Ai
                : null;
            var match = detector.Match(start.ImagePath, start.CommandLine);
            var name = Path.GetFileName(start.ImagePath);

            TrackedAiProcess? ai = null;
            if (parentAi is not null && (match is null || match.AppName == parentAi.AppName))
            {
                // A helper of an app we already know, such as one of Cursor's own processes or a shell an agent opened.
                ai = new TrackedAiProcess(
                    start.Pid, name, start.ImagePath, parentAi.AppName, parentAi.Confidence,
                    $"started by {parentAi.AppName}", start.SessionId, start.Seen, parentAi.RootPid ?? parentAi.Pid);
            }
            else if (match is not null)
            {
                ai = new TrackedAiProcess(
                    start.Pid, name, start.ImagePath, match.AppName, match.Confidence,
                    match.DetectedBy, start.SessionId, start.Seen, RootPid: null);
                newApp = ai;
            }

            _processes[start.Pid] = new Entry(start, ai);
        }

        if (newApp is not null)
            AiAppStarted?.Invoke(newApp);
    }

    public string? ImageOf(int pid)
    {
        lock (_gate)
            return _processes.TryGetValue(pid, out var entry) ? entry.Start.ImagePath : null;
    }

    public void OnStop(int pid)
    {
        lock (_gate)
            _processes.Remove(pid);
    }

    /// <summary>One entry per AI app instance, leaving out the processes it started.</summary>
    public IReadOnlyList<TrackedAiProcess> AiApps()
    {
        lock (_gate)
        {
            return _processes.Values
                .Select(e => e.Ai)
                .OfType<TrackedAiProcess>()
                .Where(ai => ai.RootPid is null)
                .OrderBy(ai => ai.AppName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(ai => ai.Pid)
                .ToList();
        }
    }

    public TrackedAiProcess? Find(int pid)
    {
        lock (_gate)
            return _processes.TryGetValue(pid, out var entry) ? entry.Ai : null;
    }

    /// <summary>Feeds a snapshot of already-running processes in parent-first order, so children inherit correctly.</summary>
    public void Seed(IEnumerable<ProcessStart> running)
    {
        var byPid = running.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
        var visited = new HashSet<int>();
        foreach (var pid in byPid.Keys)
            Visit(pid);

        void Visit(int pid)
        {
            // Walk up iteratively: parent chains can be long, and PIDs can form loops after reuse.
            var chain = new Stack<ProcessStart>();
            var current = pid;
            while (byPid.TryGetValue(current, out var start) && visited.Add(current))
            {
                chain.Push(start);
                current = start.ParentPid;
            }
            while (chain.Count > 0)
                OnStart(chain.Pop());
        }
    }
}
