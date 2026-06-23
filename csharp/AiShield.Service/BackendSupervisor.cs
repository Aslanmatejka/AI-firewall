using System.Diagnostics;
using System.Net.Http;
using AiShield.Core.Config;

namespace AiShield.Service;

/// <summary>
/// Ensures the Python AI Firewall backend is running and reachable.
/// </summary>
public sealed class BackendSupervisor : IDisposable
{
    private readonly ILogger<BackendSupervisor> _logger;
    private readonly ShieldConfig _config;
    private Process? _backendProcess;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };

    public BackendSupervisor(ILogger<BackendSupervisor> logger, ShieldConfig config)
    {
        _logger = logger;
        _config = config;
    }

    public string ApiBase => $"http://{_config.DashboardHost}:{_config.DashboardPort}";

    public async Task EnsureBackendRunningAsync(CancellationToken ct)
    {
        if (await IsBackendOnlineAsync())
            return;

        _logger.LogWarning("Python backend offline — attempting to start");
        StartBackendProcess();

        for (var i = 0; i < 15; i++)
        {
            await Task.Delay(1000, ct);
            if (await IsBackendOnlineAsync())
            {
                _logger.LogInformation("Python backend online at {Url}", ApiBase);
                return;
            }
        }
        _logger.LogError("Python backend failed to start within 15 seconds");
    }

    public async Task<bool> IsBackendOnlineAsync()
    {
        try
        {
            var res = await _http.GetAsync($"{ApiBase}/api/status");
            return res.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }

    private void StartBackendProcess()
    {
        if (_backendProcess is { HasExited: false })
            return;

        var pythonDir = ResolvePythonDir();
        if (pythonDir is null)
        {
            _logger.LogError("Could not locate python/aishield directory");
            return;
        }

        var psi = new ProcessStartInfo
        {
            FileName = "python",
            Arguments = "-m aishield --log-level WARNING",
            WorkingDirectory = pythonDir,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        try
        {
            _backendProcess = Process.Start(psi);
            _logger.LogInformation("Started python -m aishield (PID {Pid})", _backendProcess?.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start Python backend");
        }
    }

    private static string? ResolvePythonDir()
    {
        var candidates = new[]
        {
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "python")),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AiShield", "python"),
        };
        return candidates.FirstOrDefault(Directory.Exists);
    }

    public void Dispose()
    {
        _http.Dispose();
        if (_backendProcess is { HasExited: false })
        {
            try { _backendProcess.Kill(entireProcessTree: true); } catch { /* ignore */ }
        }
    }
}
