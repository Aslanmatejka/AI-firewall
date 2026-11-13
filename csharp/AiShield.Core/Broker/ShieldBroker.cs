using System.Globalization;
using System.Reflection;
using System.Text.Json;
using AiShield.Core.Approvals;
using AiShield.Core.Config;
using AiShield.Core.Detection;
using AiShield.Core.Guards;
using AiShield.Core.Ipc;
using AiShield.Core.Models;
using AiShield.Core.Policy;
using Microsoft.Extensions.Logging;

namespace AiShield.Core.Broker;

public sealed record BrokerDependencies(
    PolicyStore Store,
    ShieldDefaults Defaults,
    ApprovalQueue Queue,
    IConsentPrompter Consent,
    IAiProcessView Processes,
    IGuardStatusView Guards,
    IProcessStopper Stopper,
    IHelperControl Helpers,
    ILogger Log);

/// <summary>
/// The service's single source of truth. A trusted desktop app may read state, tighten policy and deny
/// requests. Anything that weakens protection also needs the user to confirm on the secure prompt,
/// because software running as the user can drive or inject into the desktop app.
/// </summary>
public sealed class ShieldBroker
{
    public static readonly TimeSpan GrantDuration = TimeSpan.FromHours(24);
    public const string AllResources = "all";
    private const int MaxRecentEvents = 500;

    private readonly BrokerDependencies _deps;
    private readonly PolicyResolver _resolver;
    private readonly Lock _eventsGate = new();
    private readonly LinkedList<ShieldEvent> _recent = new();

    public ShieldBroker(BrokerDependencies deps)
    {
        _deps = deps;
        _resolver = new PolicyResolver(deps.Store);
        deps.Queue.Resolved += OnRequestResolved;
    }

    public static string Version { get; } =
        typeof(ShieldBroker).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? "0.0.0";

    public PolicyResolver Resolver => _resolver;

    public void Emit(ResourceType type, PolicyAction action, string app, string resource, string message,
        EventSeverity severity = EventSeverity.Info, string? decision = null)
    {
        var entry = new ShieldEvent(Ids.New(), DateTimeOffset.UtcNow, severity, type, action, app, resource, message, decision);
        lock (_eventsGate)
        {
            _recent.AddFirst(entry);
            while (_recent.Count > MaxRecentEvents)
                _recent.RemoveLast();
        }
        try
        {
            _deps.Store.Audit(entry);
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException)
        {
            _deps.Log.LogError(ex, "Couldn't write audit entry {Id}", entry.Id);
        }
    }

    /// <summary>Decides an access attempt now if policy allows, otherwise queues it for the user.</summary>
    public PolicyAction? RequestAccess(AccessRequestDraft draft, Action<ResolvedRequest> onResolved)
    {
        var policy = _resolver.Resolve(draft.AppName, draft.ResourceType, draft.Target);
        if (policy != PolicyAction.Ask)
            return policy;
        _deps.Queue.Submit(draft with { Policy = policy }, onResolved);
        return null;
    }

    public async Task<PipeResponse> HandleAsync(PipeCaller caller, PipeRequest request, CancellationToken ct)
    {
        if (request.Op == PipeOps.Hello)
            return PipeResponse.Success(request.Id, new HelloDto(Version, caller.Trusted, "service"));
        if (!caller.Trusted)
            return PipeResponse.Failure(request.Id, PipeErrors.UntrustedClient);

        var args = request.Args is { ValueKind: JsonValueKind.Object } a ? a : default;
        try
        {
            return request.Op switch
            {
                PipeOps.Status => PipeResponse.Success(request.Id, BuildStatus()),
                PipeOps.Config => PipeResponse.Success(request.Id, BuildConfig()),
                PipeOps.Events => PipeResponse.Success(request.Id, RecentEvents(ReadInt(args, "limit") ?? 50)),
                PipeOps.Audit => PipeResponse.Success(request.Id, _deps.Store.GetAudit(ReadInt(args, "limit") ?? 100)),
                PipeOps.AppPolicies => PipeResponse.Success(request.Id, BuildAppPolicies()),
                PipeOps.Deny => Deny(request.Id, ReadString(args, "id")),
                PipeOps.Review => await ReviewAsync(caller, request.Id, ReadString(args, "id"), ct).ConfigureAwait(false),
                PipeOps.SetGlobalPolicy => await SetGlobalAsync(caller, request.Id, args, ct).ConfigureAwait(false),
                PipeOps.SetAppPolicy => await SetAppPolicyAsync(caller, request.Id, args, ct).ConfigureAwait(false),
                PipeOps.RemoveAppPolicy => await RemoveAppPolicyAsync(caller, request.Id, args, ct).ConfigureAwait(false),
                PipeOps.LockdownOn => LockdownOn(request.Id),
                PipeOps.LockdownOff => await ChangeGlobalsAsync(caller, request.Id, LockdownOffPlan(), ct).ConfigureAwait(false),
                PipeOps.RestoreDefaults => await ChangeGlobalsAsync(caller, request.Id, RestoreDefaultsPlan(), ct).ConfigureAwait(false),
                PipeOps.RevokeGrants => RevokeGrants(request.Id, ReadString(args, "app_name")),
                PipeOps.Terminate => Terminate(caller, request.Id, ReadInt(args, "pid")),
                PipeOps.HelperExit => HelperExit(caller, request.Id),
#if AISHIELD_TEST_HOOKS
                PipeOps.TestSubmitRequest => TestSubmitRequest(request.Id, args),
#endif
                _ => PipeResponse.Failure(request.Id, PipeErrors.UnknownOp),
            };
        }
        catch (ArgumentException ex)
        {
            _deps.Log.LogWarning("Rejected {Op} from PID {Pid}: {Message}", request.Op, caller.ProcessId, ex.Message);
            return PipeResponse.Failure(request.Id, PipeErrors.InvalidArgs);
        }
    }

    public StatusDto BuildStatus()
    {
        var globals = _deps.Store.GetGlobals();
        var pending = _deps.Queue.Snapshot().Select(p => new AccessRequestDto(
            p.Id, Stamp(p.CreatedAt), p.Draft.AppName, p.Draft.AppPid, p.Draft.ResourceType.ToWire(),
            p.Draft.Target, p.Draft.Policy.ToWire(), p.Count)).ToList();
        var apps = _deps.Processes.AiApps().Select(p => new AiProcessDto(
            p.Pid, p.Name, p.ImagePath, p.AppName, p.Confidence, 0, p.DetectedBy)).ToList();
        return new StatusDto(
            Running: true,
            AiProcesses: apps,
            ActiveConnections: [],
            PendingRequests: pending,
            RecentEvents: RecentEvents(30),
            ProtectedFolders: [],
            Stats: new StatsDto(_deps.Store.GetStats(), null, 0),
            Guards: _deps.Guards.Current().Select(g => g.ToDto()).ToList(),
            Lockdown: globals.Lockdown,
            Backend: "service");
    }

    private ConfigDto BuildConfig()
    {
        var p = _deps.Store.GetGlobals().Policies;
        return new ConfigDto(
            p[GlobalPolicyKeys.Network].ToWire(), p[GlobalPolicyKeys.Clipboard].ToWire(),
            p[GlobalPolicyKeys.Screenshot].ToWire(), p[GlobalPolicyKeys.Microphone].ToWire(),
            p[GlobalPolicyKeys.Camera].ToWire(), p[GlobalPolicyKeys.Global].ToWire());
    }

    private List<EventDto> RecentEvents(int limit)
    {
        lock (_eventsGate)
        {
            return _recent.Take(Math.Clamp(limit, 1, MaxRecentEvents)).Select(e => new EventDto(
                e.Id, Stamp(e.Timestamp), e.Severity.ToWire(), e.ResourceType.ToWire(), e.Action.ToWire(),
                e.SourceApp, e.Resource, e.Message)).ToList();
        }
    }

    private List<AppPolicyDto> BuildAppPolicies()
    {
        var globals = _deps.Store.GetGlobals();
        return _deps.Store.GetAppNames().Select(app =>
        {
            var rows = _deps.Store.GetAppRows(app);
            string Effective(ResourceType type) => PolicyResolver.Configured(rows, globals, type).ToWire();
            return new AppPolicyDto(
                app, Effective(ResourceType.Process), Effective(ResourceType.File), Effective(ResourceType.Network),
                Effective(ResourceType.Clipboard), Effective(ResourceType.Microphone), Effective(ResourceType.Camera));
        }).ToList();
    }

    private PipeResponse Deny(int id, string? requestId)
    {
        if (string.IsNullOrEmpty(requestId))
            throw new ArgumentException("id is required");
        return _deps.Queue.Resolve(requestId, PolicyAction.Block, DecisionSource.User)
            ? PipeResponse.Success(id)
            : PipeResponse.Failure(id, PipeErrors.NotFound);
    }

    private async Task<PipeResponse> ReviewAsync(PipeCaller caller, int id, string? requestId, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(requestId))
            throw new ArgumentException("id is required");
        if (_deps.Queue.Find(requestId) is not { } pending)
            return PipeResponse.Failure(id, PipeErrors.NotFound);

        var draft = pending.Draft;
        var text = new ConsentText(
            "Allow access?",
            $"{DisplayText.Clean(draft.AppName, 60)} wants {ResourceLabel(draft.ResourceType)}",
            [
                $"Target: {DisplayText.Clean(draft.Target, 160)}",
                pending.Count > 1 ? $"Asked {pending.Count} times" : "Asked once",
                "Allowing lasts 24 hours. You can revoke it from AI Firewall.",
            ],
            RequestedBy(caller));
        var outcome = await _deps.Consent.AskAsync(caller.SessionId, text, ct).ConfigureAwait(false);
        if (outcome != ConsentOutcome.Approved)
            return PipeResponse.Failure(id, PipeErrors.NotApproved, outcome);

        return _deps.Queue.Resolve(requestId, PolicyAction.Allow, DecisionSource.User)
            ? PipeResponse.Success(id, consent: outcome)
            : PipeResponse.Failure(id, PipeErrors.NotFound, outcome);
    }

    private async Task<PipeResponse> SetGlobalAsync(PipeCaller caller, int id, JsonElement args, CancellationToken ct)
    {
        var key = ReadString(args, "key");
        if (!GlobalPolicyKeys.IsKnown(key) || !Wire.TryParsePolicy(ReadString(args, "value"), out var value))
            throw new ArgumentException("Unknown policy key or value");

        var before = _deps.Store.GetGlobals().Policies[key!];
        var plan = new ChangePlan(
            Weakens: PolicyChanges.Weakens(before, value),
            Text: new ConsentText(
                "Relax a protection?",
                $"Change {GlobalPolicyKeys.Label(key!)} for all AI apps from {before.ToWire()} to {value.ToWire()}",
                [],
                RequestedBy(caller)),
            Apply: () => _deps.Store.SetGlobal(key!, value),
            Describe: $"Set {GlobalPolicyKeys.Label(key!)} to {value.ToWire()}");
        return await ApplyAsync(caller, id, plan, ResourceType.Process, "Policy", ct).ConfigureAwait(false);
    }

    private async Task<PipeResponse> SetAppPolicyAsync(PipeCaller caller, int id, JsonElement args, CancellationToken ct)
    {
        var app = CleanAppName(ReadString(args, "app_name"));
        var resource = ReadString(args, "resource");
        var all = resource == AllResources;
        if (resource is null || (!all && !PolicyStore.AppResources.Contains(resource)) || !Wire.TryParsePolicy(ReadString(args, "policy"), out var value))
            throw new ArgumentException("Unknown resource or policy");

        var globals = _deps.Store.GetGlobals();
        var before = _deps.Store.GetAppRows(app);
        var after = new Dictionary<string, PolicyAction>(before, StringComparer.Ordinal);
        var changed = all ? PolicyStore.AppResources : [resource];
        foreach (var name in changed)
            after[name] = value;
        var label = all ? "everything" : resource == PolicyStore.DefaultResource ? "everything without its own rule" : resource;
        var plan = new ChangePlan(
            Weakens: PolicyChanges.AppRulesWeaken(before, after, globals),
            Text: new ConsentText(
                "Relax a protection?",
                $"Set {label} for {app} to {value.ToWire()}",
                [],
                RequestedBy(caller)),
            Apply: () =>
            {
                foreach (var name in changed)
                    _deps.Store.SetAppPolicy(app, name, value);
            },
            Describe: $"Set {label} for {app} to {value.ToWire()}");
        return await ApplyAsync(caller, id, plan, ResourceType.Process, app, ct).ConfigureAwait(false);
    }

    private async Task<PipeResponse> RemoveAppPolicyAsync(PipeCaller caller, int id, JsonElement args, CancellationToken ct)
    {
        var app = CleanAppName(ReadString(args, "app_name"));
        var before = _deps.Store.GetAppRows(app);
        if (before.Count == 0)
            return PipeResponse.Failure(id, PipeErrors.NotFound);

        var plan = new ChangePlan(
            Weakens: PolicyChanges.AppRulesWeaken(before, new Dictionary<string, PolicyAction>(), _deps.Store.GetGlobals()),
            Text: new ConsentText("Relax a protection?", $"Remove the saved rules for {app}", [], RequestedBy(caller)),
            Apply: () => _deps.Store.RemoveAppPolicy(app),
            Describe: $"Removed the saved rules for {app}");
        return await ApplyAsync(caller, id, plan, ResourceType.Process, app, ct).ConfigureAwait(false);
    }

    private PipeResponse LockdownOn(int id)
    {
        _deps.Store.SetLockdown(true);
        Emit(ResourceType.Process, PolicyAction.Block, "Policy", "lockdown",
            "Lockdown on: network, clipboard, screen, microphone and camera access are blocked for AI apps",
            EventSeverity.Warning, "block");
        return PipeResponse.Success(id, consent: ConsentOutcome.NotNeeded);
    }

    private ChangePlan LockdownOffPlan()
    {
        var before = _deps.Store.GetGlobals();
        return new ChangePlan(
            Weakens: PolicyChanges.GlobalsWeaken(before, before with { Lockdown = false }),
            Text: new ConsentText("Turn off lockdown?", "AI apps go back to your usual policies", [], ""),
            Apply: () => _deps.Store.SetLockdown(false),
            Describe: "Lockdown off");
    }

    private ChangePlan RestoreDefaultsPlan()
    {
        var before = _deps.Store.GetGlobals();
        var after = new GlobalSettings(_deps.Defaults.GlobalPolicies, Lockdown: false);
        var changes = GlobalPolicyKeys.All
            .Where(k => before.Policies[k] != after.Policies[k])
            .Select(k => $"{GlobalPolicyKeys.Label(k)}: {before.Policies[k].ToWire()} to {after.Policies[k].ToWire()}")
            .Concat(before.Lockdown ? ["Lockdown off"] : [])
            .ToList();
        return new ChangePlan(
            Weakens: PolicyChanges.GlobalsWeaken(before, after),
            Text: new ConsentText("Restore default policies?", "Put every policy back to its default", changes, ""),
            Apply: _deps.Store.RestoreDefaults,
            Describe: "Restored default policies");
    }

    private Task<PipeResponse> ChangeGlobalsAsync(PipeCaller caller, int id, ChangePlan plan, CancellationToken ct)
        => ApplyAsync(caller, id, plan with { Text = plan.Text with { RequestedBy = RequestedBy(caller) } }, ResourceType.Process, "Policy", ct);

    private PipeResponse RevokeGrants(int id, string? app)
    {
        var name = app is null ? null : CleanAppName(app);
        var removed = _deps.Store.RevokeGrants(name);
        Emit(ResourceType.Process, PolicyAction.Block, name ?? "All apps", "grants",
            $"Revoked {removed} saved decision(s)", EventSeverity.Info, "block");
        return PipeResponse.Success(id, new { removed }, ConsentOutcome.NotNeeded);
    }

    private PipeResponse Terminate(PipeCaller caller, int id, int? pid)
    {
        if (pid is not > 0)
            throw new ArgumentException("pid is required");
        // Only an AI app in the caller's own session. Anyone can start the desktop app, so it mustn't
        // become a way to stop programs in someone else's session.
        if (_deps.Processes.Find(pid.Value) is not { } target || target.SessionId != caller.SessionId)
            return PipeResponse.Failure(id, PipeErrors.NotFound);

        var result = _deps.Stopper.Stop(pid.Value);
        if (!result.Stopped)
            return PipeResponse.Failure(id, PipeErrors.Failed);
        Emit(ResourceType.Process, PolicyAction.Block, result.Name, pid.Value.ToString(CultureInfo.InvariantCulture),
            $"User stopped {result.Name} (PID {pid.Value})", EventSeverity.Warning, "block");
        return PipeResponse.Success(id);
    }

    private PipeResponse HelperExit(PipeCaller caller, int id)
    {
        _deps.Helpers.SuppressSession(caller.SessionId);
        return PipeResponse.Success(id);
    }

#if AISHIELD_TEST_HOOKS
    private PipeResponse TestSubmitRequest(int id, JsonElement args)
    {
        if (!Wire.TryParseResource(ReadString(args, "resource_type"), out var type))
            throw new ArgumentException("resource_type is required");
        var draft = new AccessRequestDraft(
            CleanAppName(ReadString(args, "app_name")), ReadInt(args, "pid") ?? 0, type,
            ReadString(args, "target") ?? "test", PolicyAction.Ask);
        var pending = _deps.Queue.Submit(draft);
        return PipeResponse.Success(id, new { id = pending.Id });
    }
#endif

    private sealed record ChangePlan(bool Weakens, ConsentText Text, Action Apply, string Describe);

    private async Task<PipeResponse> ApplyAsync(PipeCaller caller, int id, ChangePlan plan, ResourceType type, string app, CancellationToken ct)
    {
        var outcome = ConsentOutcome.NotNeeded;
        if (plan.Weakens)
        {
            outcome = await _deps.Consent.AskAsync(caller.SessionId, plan.Text, ct).ConfigureAwait(false);
            if (outcome != ConsentOutcome.Approved)
            {
                Emit(type, PolicyAction.Block, app, "policy", $"Not changed: {plan.Describe} wasn't confirmed ({outcome.ToWire()})");
                return PipeResponse.Failure(id, PipeErrors.NotApproved, outcome);
            }
        }

        plan.Apply();
        Emit(type, PolicyAction.Ask, app, "policy",
            plan.Weakens ? $"{plan.Describe}, confirmed on the secure prompt" : plan.Describe, EventSeverity.Info, "user");
        return PipeResponse.Success(id, consent: outcome);
    }

    private void OnRequestResolved(ResolvedRequest resolved)
    {
        var draft = resolved.Request.Draft;
        var allowed = resolved.Decision == PolicyAction.Allow;
        if (allowed && resolved.Source == DecisionSource.User)
            _deps.Store.Grant(draft.AppName, draft.ResourceType, draft.Target, PolicyAction.Allow, GrantDuration);

        var message = resolved.Source switch
        {
            DecisionSource.Timeout => $"No answer in time, so {ResourceLabel(draft.ResourceType)} was blocked",
            DecisionSource.Shutdown => "AI Firewall stopped before you answered, so the request was blocked",
            _ => allowed ? $"You allowed {ResourceLabel(draft.ResourceType)} for 24 hours" : $"You denied {ResourceLabel(draft.ResourceType)}",
        };
        Emit(draft.ResourceType, resolved.Decision, draft.AppName, draft.Target, message,
            allowed ? EventSeverity.Info : EventSeverity.Warning, resolved.Decision.ToWire());
    }

    private static string ResourceLabel(ResourceType type) => type switch
    {
        ResourceType.File => "file access",
        ResourceType.Network => "network access",
        ResourceType.Clipboard => "clipboard access",
        ResourceType.Screenshot => "screen capture",
        ResourceType.Microphone => "microphone access",
        ResourceType.Camera => "camera access",
        _ => "access",
    };

    private static string RequestedBy(PipeCaller caller)
        => $"Asked from the AI Firewall window (process {caller.ProcessId})";

    private static string CleanAppName(string? value)
    {
        var name = DisplayText.Clean(value, 64);
        return name.Length == 0 ? throw new ArgumentException("app_name is required") : name;
    }

    private static string Stamp(DateTimeOffset time) => time.ToString("O", CultureInfo.InvariantCulture);

    private static string? ReadString(JsonElement args, string name)
        => args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    private static int? ReadInt(JsonElement args, string name)
        => args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.TryGetInt32(out var n) ? n : null;
}
