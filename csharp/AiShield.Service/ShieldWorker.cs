using AiShield.Core.Config;
using AiShield.Core.Events;
using AiShield.Core.Monitor;
using AiShield.Core.Permissions;

namespace AiShield.Service;

public sealed class ShieldWorker : BackgroundService
{
    private readonly ILogger<ShieldWorker> _logger;
    private readonly BackendSupervisor _supervisor;
    private ProcessMonitor? _monitor;
    private NetworkMonitor? _network;
    private PermissionManager? _permissions;
    private EventBus? _bus;
    private ShieldConfig? _config;

    public ShieldWorker(ILogger<ShieldWorker> logger, BackendSupervisor supervisor)
    {
        _logger = logger;
        _supervisor = supervisor;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _config = ConfigLoader.Load();
        var configPath = ConfigLoader.ResolveConfigPath();
        _permissions = new PermissionManager();
        _bus = new EventBus();
        _bus.EventPublished += evt => _permissions.LogEvent(evt);

        _monitor = new ProcessMonitor(configPath);
        _monitor.AiDetected += proc =>
        {
            _logger.LogWarning("AI process detected: {Type} PID {Pid}", proc.AiType, proc.Pid);
            _permissions!.LogDetection(proc.AiType, proc.Pid, $"AI process detected: {proc.AiType} (PID {proc.Pid})");
        };

        _network = new NetworkMonitor(configPath);
        _network.AiConnectionDetected += conn =>
        {
            _logger.LogWarning("AI network traffic: {Proc} -> {Host}", conn.ProcessName, conn.RemoteHost);
            _permissions!.LogDetection(conn.ProcessName, conn.Pid,
                $"AI network connection to {conn.RemoteHost} ({conn.RemoteAddr})");
        };

        _logger.LogInformation("AI Firewall Windows Service started (process + network monitors active)");
        await _supervisor.EnsureBackendRunningAsync(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            if (!await _supervisor.IsBackendOnlineAsync())
            {
                _logger.LogWarning("Backend offline — restarting");
                await _supervisor.EnsureBackendRunningAsync(stoppingToken);
            }
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }

        _network?.Dispose();
        _monitor?.Dispose();
        _permissions?.Dispose();
    }
}
