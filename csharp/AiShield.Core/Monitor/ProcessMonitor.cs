using System.Diagnostics;
using System.Text.Json;
using AiShield.Core.Models;

namespace AiShield.Core.Monitor;

public sealed class ProcessMonitor : IDisposable
{
    private readonly Timer _timer;
    private readonly List<(string Name, string[] Patterns)> _signatures;
    private readonly HashSet<int> _knownPids = new();
    public event Action<AiProcess>? AiDetected;

    public List<AiProcess> AiProcesses { get; private set; } = new();

    public ProcessMonitor(string configPath)
    {
        var json = File.ReadAllText(configPath);
        using var doc = JsonDocument.Parse(json);
        _signatures = doc.RootElement.GetProperty("ai_process_signatures")
            .EnumerateArray()
            .Select(s => (
                s.GetProperty("name").GetString()!,
                s.GetProperty("patterns").EnumerateArray().Select(p => p.GetString()!.ToLower()).ToArray()
            )).ToList();

        _timer = new Timer(Scan, null, 0, 2000);
    }

    private void Scan(object? _)
    {
        var detected = new List<AiProcess>();
        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                var name = proc.ProcessName.ToLower();
                var exe = proc.MainModule?.FileName?.ToLower() ?? "";
                var combined = $"{name} {exe}";

                foreach (var (typeName, patterns) in _signatures)
                {
                    if (patterns.Any(p => combined.Contains(p)))
                    {
                        var ai = new AiProcess(proc.Id, proc.ProcessName, exe, typeName, 85);
                        detected.Add(ai);
                        if (!_knownPids.Contains(proc.Id))
                        {
                            _knownPids.Add(proc.Id);
                            AiDetected?.Invoke(ai);
                        }
                        break;
                    }
                }
            }
            catch { /* access denied */ }
        }
        AiProcesses = detected;
    }

    public void Dispose() => _timer.Dispose();
}
