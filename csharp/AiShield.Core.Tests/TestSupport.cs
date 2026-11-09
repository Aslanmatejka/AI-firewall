using AiShield.Core.Approvals;
using AiShield.Core.Broker;
using AiShield.Core.Config;
using AiShield.Core.Detection;
using AiShield.Core.Guards;
using AiShield.Core.Ipc;
using AiShield.Core.Models;
using AiShield.Core.Policy;
using Microsoft.Extensions.Logging.Abstractions;

namespace AiShield.Core.Tests;

public sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "aishield-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Some tests lock folders down to SYSTEM. As their owner we can still take access back.
            ReclaimAccess(Path);
            try
            {
                Directory.Delete(Path, recursive: true);
            }
            catch (Exception again) when (again is IOException or UnauthorizedAccessException)
            {
                // Best effort.
            }
        }
    }

    private static void ReclaimAccess(string root)
    {
        var me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        var stack = new Stack<string>([root]);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            try
            {
                var security = new System.Security.AccessControl.DirectorySecurity();
                security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    me, System.Security.AccessControl.FileSystemRights.FullControl,
                    System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                    System.Security.AccessControl.PropagationFlags.None, System.Security.AccessControl.AccessControlType.Allow));
                new DirectoryInfo(dir).SetAccessControl(security);
                foreach (var child in Directory.EnumerateDirectories(dir))
                    stack.Push(child);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                // Not ours to reclaim.
            }
        }
    }
}

public sealed class ManualClock(DateTimeOffset start)
{
    public DateTimeOffset Now { get; set; } = start;

    public void Advance(TimeSpan by) => Now += by;
}

public static class TestDefaults
{
    public static ShieldDefaults Create(PolicyAction network = PolicyAction.Block, PolicyAction global = PolicyAction.Ask) => new()
    {
        GlobalPolicies = new Dictionary<string, PolicyAction>
        {
            [GlobalPolicyKeys.Global] = global,
            [GlobalPolicyKeys.Network] = network,
            [GlobalPolicyKeys.Clipboard] = PolicyAction.Allow,
            [GlobalPolicyKeys.Screenshot] = PolicyAction.Block,
            [GlobalPolicyKeys.Microphone] = PolicyAction.Ask,
            [GlobalPolicyKeys.Camera] = PolicyAction.Ask,
        },
        Signatures =
        [
            new AiSignature("Claude", ["claude", "anthropic"], []),
            new AiSignature("Cursor", ["cursor.exe"], []),
            new AiSignature("Ollama", ["ollama"], []),
            new AiSignature("Continue", ["continue"], []),
            new AiSignature("Claude Code", [], ["@anthropic-ai/claude-code"]),
            new AiSignature("Aider", ["aider.exe"], ["-m aider"]),
        ],
        AiDomains = ["openai.com"],
        ApprovalTimeout = TimeSpan.FromSeconds(120),
    };
}

public sealed class FakeConsent : IConsentPrompter
{
    public ConsentOutcome Answer { get; set; } = ConsentOutcome.Denied;
    public List<(int Session, ConsentText Text)> Asked { get; } = [];

    public Task<ConsentOutcome> AskAsync(int sessionId, ConsentText text, CancellationToken ct)
    {
        Asked.Add((sessionId, text));
        return Task.FromResult(Answer);
    }
}

public sealed class FakeProcesses : IAiProcessView
{
    public List<TrackedAiProcess> Apps { get; } = [];
    public IReadOnlyList<TrackedAiProcess> AiApps() => Apps;
    public TrackedAiProcess? Find(int pid) => Apps.FirstOrDefault(a => a.Pid == pid);
}

public sealed class FakeGuards : IGuardStatusView
{
    public IReadOnlyList<GuardStatus> Current() =>
        [new GuardStatus("Processes", GuardState.Active, "Watching", "Detects AI apps", DateTimeOffset.UnixEpoch)];
}

public sealed class FakeStopper : IProcessStopper
{
    public List<int> Stopped { get; } = [];
    public StopResult Stop(int pid)
    {
        Stopped.Add(pid);
        return new StopResult(true, "ai.exe", "");
    }
}

public sealed class FakeHelpers : IHelperControl
{
    public List<int> Suppressed { get; } = [];
    public void SuppressSession(int sessionId) => Suppressed.Add(sessionId);
}

/// <summary>A broker wired to a real store in a temp folder and fakes for everything Windows-specific.</summary>
public sealed class BrokerFixture : IDisposable
{
    private readonly TempDirectory _dir = new();

    public BrokerFixture()
    {
        Defaults = TestDefaults.Create();
        Clock = new ManualClock(new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero));
        Store = new PolicyStore(System.IO.Path.Combine(_dir.Path, "policy.db"), Defaults);
        Queue = new ApprovalQueue(TimeSpan.FromSeconds(120), () => Clock.Now);
        Broker = new ShieldBroker(new BrokerDependencies(
            Store, Defaults, Queue, Consent, Processes, new FakeGuards(), Stopper, Helpers, NullLogger.Instance));
    }

    public ShieldDefaults Defaults { get; }
    public ManualClock Clock { get; }
    public PolicyStore Store { get; }
    public ApprovalQueue Queue { get; }
    public FakeConsent Consent { get; } = new();
    public FakeProcesses Processes { get; } = new();
    public FakeStopper Stopper { get; } = new();
    public FakeHelpers Helpers { get; } = new();
    public ShieldBroker Broker { get; }

    public static PipeCaller Trusted { get; } = new(4242, 1, @"C:\Program Files\AiShield\dashboard\AiShield.Dashboard.exe", true);
    public static PipeCaller Untrusted { get; } = new(666, 1, @"C:\Users\me\AppData\Local\Temp\AiShield.Dashboard.exe", false);

    public Task<PipeResponse> Send(string op, object? args = null, PipeCaller? caller = null)
    {
        var json = args is null ? (System.Text.Json.JsonElement?)null : System.Text.Json.JsonSerializer.SerializeToElement(args, PipeProtocol.Json);
        return Broker.HandleAsync(caller ?? Trusted, new PipeRequest(1, op, json), TestContext.Current.CancellationToken);
    }

    public void Dispose()
    {
        Store.Dispose();
        _dir.Dispose();
    }
}
