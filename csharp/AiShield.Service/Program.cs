using AiShield.Core.Approvals;
using AiShield.Core.Broker;
using AiShield.Core.Config;
using AiShield.Core.Detection;
using AiShield.Core.Guards;
using AiShield.Core.Ipc;
using AiShield.Core.Models;
using AiShield.Core.Policy;
using AiShield.Core.Security;
using AiShield.Service;
using AiShield.Service.Guards;
using AiShield.Service.Ipc;
using AiShield.Service.Logging;
using AiShield.Service.Native;
using AiShield.Service.Sessions;
using Microsoft.Extensions.Logging.EventLog;

// First thing, before anything else loads: close the usual routes for code to get into a SYSTEM process.
var mitigations = AiShield.Core.Windows.ProcessHardening.Apply(allowChildProcesses: true);

// The installer runs maintenance tasks through the service's own executable, as SYSTEM.
if (args.Length == 2 && args[0] == "--maintenance")
    return Maintenance.Run(args[1]);

var layout = ServiceLayout.Resolve(args);

// Everything the service stores lives where only SYSTEM and administrators can reach it.
SecureDataDirectory.Ensure(layout.DataDirectory, layout.DataOwners);
var logDirectory = Path.Combine(layout.DataDirectory, "logs");
Directory.CreateDirectory(logDirectory);

if (layout.IsService)
{
    SessionNative.EnablePrivileges("SeTcbPrivilege", "SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege");
    // Restart after any failed exit, not only crashes. The installer can't set this reliably.
    ServiceSelfConfig.RestartOnErrorExit(PipeProtocol.ServiceName);
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = PipeProtocol.ServiceName);
builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(15));

builder.Logging.ClearProviders();
builder.Logging.AddProvider(new FileLoggerProvider(Path.Combine(logDirectory, "service.log")));
if (layout.IsService)
{
    builder.Logging.AddEventLog(new EventLogSettings
    {
        SourceName = "AiShield",
        LogName = "Application",
        Filter = (_, level) => level >= LogLevel.Warning,
    });
}
else
{
    builder.Logging.AddSimpleConsole();
}

var defaults = ShieldDefaults.Load(layout.ConfigPath);
var tracker = new ProcessTracker(new AiDetector(defaults.Signatures));

builder.Services.AddSingleton(layout);
builder.Services.AddSingleton(defaults);
builder.Services.AddSingleton(tracker);
builder.Services.AddSingleton(_ => new PolicyStore(Path.Combine(layout.DataDirectory, "policy.db"), defaults));
builder.Services.AddSingleton(_ => new ApprovalQueue(defaults.ApprovalTimeout));

builder.Services.AddSingleton<ProcessGuard>();
builder.Services.AddSingleton<IGuard>(sp => sp.GetRequiredService<ProcessGuard>());
foreach (var planned in PlannedGuard.All())
    builder.Services.AddSingleton(planned);
builder.Services.AddSingleton<GuardHost>();
builder.Services.AddSingleton<IGuardStatusView>(sp => sp.GetRequiredService<GuardHost>());

builder.Services.AddSingleton<ConsentPrompter>();
builder.Services.AddSingleton<IConsentPrompter>(sp => sp.GetRequiredService<ConsentPrompter>());
builder.Services.AddSingleton<HelperSupervisor>();
builder.Services.AddSingleton<IHelperControl>(sp => sp.GetRequiredService<HelperSupervisor>());
builder.Services.AddSingleton<IProcessStopper, ProcessStopper>();
builder.Services.AddSingleton<ClientVerifier>();

builder.Services.AddSingleton(sp =>
{
    var broker = new ShieldBroker(new BrokerDependencies(
        sp.GetRequiredService<PolicyStore>(),
        defaults,
        sp.GetRequiredService<ApprovalQueue>(),
        sp.GetRequiredService<IConsentPrompter>(),
        tracker,
        sp.GetRequiredService<IGuardStatusView>(),
        sp.GetRequiredService<IProcessStopper>(),
        sp.GetRequiredService<IHelperControl>(),
        sp.GetRequiredService<ILoggerFactory>().CreateLogger("Broker")));
    // One entry per app every 10 minutes, and at most 30 a minute overall, so starting processes in a
    // loop, even under ever-changing names, can't flood the audit log.
    var throttle = new EventThrottle(TimeSpan.FromMinutes(10), maxPerMinute: 30);
    tracker.AiAppStarted += app =>
    {
        if (!throttle.ShouldRecord(app.AppName, DateTimeOffset.UtcNow, out var suppressed))
            return;
        var more = suppressed > 0 ? $"; {suppressed} more start(s) since the last entry" : "";
        broker.Emit(
            ResourceType.Process, PolicyAction.Ask, app.AppName, app.ImagePath,
            $"AI app detected: {app.AppName} (PID {app.Pid}, by {app.DetectedBy}{more})", EventSeverity.Warning);
    };
    return broker;
});

// All hosted services are created before any starts, so the broker is listening before guards report.
builder.Services.AddHostedService<PipeServer>();
builder.Services.AddHostedService<ApprovalExpiry>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<GuardHost>());
builder.Services.AddHostedService(sp => sp.GetRequiredService<HelperSupervisor>());

var host = builder.Build();
var log = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Startup");
log.LogInformation("AI Firewall service {Version} starting from {Root}", ShieldBroker.Version, layout.Root);
foreach (var mitigation in mitigations.Where(m => !m.Applied))
    log.LogWarning("Couldn't apply the {Mitigation} mitigation", mitigation.Mitigation);
if (!layout.InstallProtected)
{
    log.LogWarning("Running from a folder ordinary users can change ({Problem}). The desktop app won't be trusted "
        + "and the secure prompt is off.", layout.InstallProblem);
}
host.Run();
return 0;

/// <summary>Blocks requests nobody answered in time, and everything pending at shutdown.</summary>
internal sealed class ApprovalExpiry(ApprovalQueue queue, ILogger<ApprovalExpiry> log) : CriticalService(log)
{
    protected override async Task RunAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                var expired = queue.ExpireOverdue();
                if (expired > 0)
                    log.LogInformation("Blocked {Count} unanswered request(s)", expired);
            }
        }
        finally
        {
            queue.BlockAll(DecisionSource.Shutdown);
        }
    }
}
