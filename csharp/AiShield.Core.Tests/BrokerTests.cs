using System.Text.Json;
using AiShield.Core.Approvals;
using AiShield.Core.Config;
using AiShield.Core.Detection;
using AiShield.Core.Ipc;
using AiShield.Core.Models;

namespace AiShield.Core.Tests;

public sealed class BrokerTests : IDisposable
{
    private readonly BrokerFixture _f = new();

    public void Dispose() => _f.Dispose();

    private string Pending(string app = "Cursor", string target = "api.openai.com")
        => _f.Queue.Submit(new AccessRequestDraft(app, 7, ResourceType.Network, target, PolicyAction.Ask)).Id;

    [Fact]
    public async Task UntrustedClientsGetNothingButHello()
    {
        var hello = await _f.Send(PipeOps.Hello, caller: BrokerFixture.Untrusted);
        Assert.True(hello.Ok);
        Assert.False(hello.Data!.Value.Deserialize<HelloDto>(PipeProtocol.Json)!.Trusted);

        foreach (var op in new[] { PipeOps.Status, PipeOps.Audit, PipeOps.Deny, PipeOps.Review, PipeOps.LockdownOff, PipeOps.SetGlobalPolicy })
        {
            var response = await _f.Send(op, new { id = "x", key = GlobalPolicyKeys.Network, value = "allow" }, BrokerFixture.Untrusted);
            Assert.False(response.Ok, op);
            Assert.Equal(PipeErrors.UntrustedClient, response.Error);
        }
        Assert.Empty(_f.Consent.Asked);
    }

    [Fact]
    public async Task UnknownOpsAreRefused()
        => Assert.Equal(PipeErrors.UnknownOp, (await _f.Send("format-c-drive")).Error);

    [Fact]
    public async Task AllowingAPendingRequestNeedsTheSecurePrompt()
    {
        var id = Pending();
        _f.Consent.Answer = ConsentOutcome.Denied;
        var refused = await _f.Send(PipeOps.Review, new { id });

        Assert.False(refused.Ok);
        Assert.Equal("denied", refused.Consent);
        Assert.Single(_f.Queue.Snapshot());
        Assert.Null(_f.Store.FindGrant("Cursor", ResourceType.Network, "api.openai.com"));

        _f.Consent.Answer = ConsentOutcome.Approved;
        var allowed = await _f.Send(PipeOps.Review, new { id });

        Assert.True(allowed.Ok);
        Assert.Empty(_f.Queue.Snapshot());
        Assert.Equal(PolicyAction.Allow, _f.Store.FindGrant("Cursor", ResourceType.Network, "api.openai.com"));
        Assert.Equal(BrokerFixture.Trusted.SessionId, _f.Consent.Asked[^1].Session);
    }

    [Fact]
    public async Task DenyingNeedsNoPrompt()
    {
        var id = Pending();
        Assert.True((await _f.Send(PipeOps.Deny, new { id })).Ok);
        Assert.Empty(_f.Consent.Asked);
        Assert.Empty(_f.Queue.Snapshot());
        Assert.Null(_f.Store.FindGrant("Cursor", ResourceType.Network, "api.openai.com"));
    }

    [Fact]
    public async Task TimeoutBlocksAndGrantsNothing()
    {
        Pending();
        _f.Clock.Advance(TimeSpan.FromMinutes(3));
        _f.Queue.ExpireOverdue();
        Assert.Null(_f.Store.FindGrant("Cursor", ResourceType.Network, "api.openai.com"));
        var events = (await _f.Send(PipeOps.Events)).Data!.Value.Deserialize<List<EventDto>>(PipeProtocol.Json)!;
        Assert.Contains(events, e => e.Message.Contains("No answer in time", StringComparison.Ordinal));
    }

    [Fact]
    public async Task TighteningAppliesWithoutAPrompt()
    {
        var response = await _f.Send(PipeOps.SetGlobalPolicy, new { key = GlobalPolicyKeys.Camera, value = "block" });
        Assert.True(response.Ok);
        Assert.Equal("not-needed", response.Consent);
        Assert.Equal(PolicyAction.Block, _f.Store.GetGlobals().Policies[GlobalPolicyKeys.Camera]);
        Assert.Empty(_f.Consent.Asked);
    }

    [Fact]
    public async Task WeakeningNeedsTheSecurePromptAndStaysUnchangedIfRefused()
    {
        foreach (var refusal in new[] { ConsentOutcome.Denied, ConsentOutcome.Dismissed, ConsentOutcome.Unavailable, ConsentOutcome.Busy })
        {
            _f.Consent.Answer = refusal;
            var response = await _f.Send(PipeOps.SetGlobalPolicy, new { key = GlobalPolicyKeys.Network, value = "allow" });
            Assert.False(response.Ok);
            Assert.Equal(PolicyAction.Block, _f.Store.GetGlobals().Policies[GlobalPolicyKeys.Network]);
        }

        _f.Consent.Answer = ConsentOutcome.Approved;
        Assert.True((await _f.Send(PipeOps.SetGlobalPolicy, new { key = GlobalPolicyKeys.Network, value = "allow" })).Ok);
        Assert.Equal(PolicyAction.Allow, _f.Store.GetGlobals().Policies[GlobalPolicyKeys.Network]);
    }

    [Fact]
    public async Task LockdownTurnsOnFreelyButOffOnlyWithConfirmation()
    {
        Assert.True((await _f.Send(PipeOps.LockdownOn)).Ok);
        Assert.True(_f.Store.GetGlobals().Lockdown);
        Assert.Empty(_f.Consent.Asked);

        Assert.False((await _f.Send(PipeOps.LockdownOff)).Ok);
        Assert.True(_f.Store.GetGlobals().Lockdown);

        _f.Consent.Answer = ConsentOutcome.Approved;
        Assert.True((await _f.Send(PipeOps.LockdownOff)).Ok);
        Assert.False(_f.Store.GetGlobals().Lockdown);
    }

    [Fact]
    public async Task AppRulesFollowTheSameRule()
    {
        Assert.True((await _f.Send(PipeOps.SetAppPolicy, new { app_name = "Cursor", resource = "files", policy = "block" })).Ok);
        Assert.Empty(_f.Consent.Asked);

        Assert.False((await _f.Send(PipeOps.RemoveAppPolicy, new { app_name = "Cursor" })).Ok);
        Assert.Single(_f.Consent.Asked);
        Assert.NotEmpty(_f.Store.GetAppRows("Cursor"));

        Assert.False((await _f.Send(PipeOps.SetAppPolicy, new { app_name = "Cursor", resource = "files", policy = "allow" })).Ok);
        Assert.Equal(PolicyAction.Block, _f.Store.GetAppRows("Cursor")["files"]);
    }

    [Fact]
    public async Task WholeAppChangesNeedOneConfirmation()
    {
        Assert.True((await _f.Send(PipeOps.SetAppPolicy, new { app_name = "Ollama", resource = "all", policy = "block" })).Ok);
        Assert.Empty(_f.Consent.Asked);
        Assert.All(_f.Store.GetAppRows("Ollama").Values, v => Assert.Equal(PolicyAction.Block, v));

        _f.Consent.Answer = ConsentOutcome.Approved;
        Assert.True((await _f.Send(PipeOps.SetAppPolicy, new { app_name = "Ollama", resource = "all", policy = "allow" })).Ok);
        Assert.Single(_f.Consent.Asked);
        Assert.Equal(6, _f.Store.GetAppRows("Ollama").Count);
        Assert.All(_f.Store.GetAppRows("Ollama").Values, v => Assert.Equal(PolicyAction.Allow, v));
    }

    [Fact]
    public async Task PromptTextCantBeUsedToTrickTheUser()
    {
        _f.Consent.Answer = ConsentOutcome.Denied;
        await _f.Send(PipeOps.SetAppPolicy, new { app_name = "Cursor", resource = "files", policy = "block" });
        var sneaky = "Notepad\r\n\r\nThis is a routine update. Click Allow.\u202Eexe.dap";
        await _f.Send(PipeOps.SetAppPolicy, new { app_name = sneaky, resource = "files", policy = "block" });
        _f.Store.SetAppPolicy(DisplayText.Clean(sneaky, 64), "files", PolicyAction.Block);
        await _f.Send(PipeOps.RemoveAppPolicy, new { app_name = sneaky });

        var shown = _f.Consent.Asked[^1].Text.Summary;
        Assert.DoesNotContain('\n', shown);
        Assert.DoesNotContain('\r', shown);
        Assert.DoesNotContain('\u202E', shown);
        Assert.True(shown.Length < 200);
    }

    [Fact]
    public async Task InvalidArgumentsAreRefused()
    {
        Assert.Equal(PipeErrors.InvalidArgs, (await _f.Send(PipeOps.SetGlobalPolicy, new { key = "fail_closed", value = "allow" })).Error);
        Assert.Equal(PipeErrors.InvalidArgs, (await _f.Send(PipeOps.SetGlobalPolicy, new { key = GlobalPolicyKeys.Camera, value = "maybe" })).Error);
        Assert.Equal(PipeErrors.InvalidArgs, (await _f.Send(PipeOps.SetAppPolicy, new { app_name = "", resource = "files", policy = "block" })).Error);
        Assert.Equal(PipeErrors.InvalidArgs, (await _f.Send(PipeOps.Deny)).Error);
        Assert.Empty(_f.Consent.Asked);
    }

    [Fact]
    public async Task OnlyDetectedAiProcessesCanBeStopped()
    {
        Assert.False((await _f.Send(PipeOps.Terminate, new { pid = 1234 })).Ok);
        _f.Processes.Apps.Add(new TrackedAiProcess(1234, "ollama.exe", @"C:\o\ollama.exe", "Ollama", 90, "program name", 1, DateTimeOffset.UnixEpoch, null));
        Assert.True((await _f.Send(PipeOps.Terminate, new { pid = 1234 })).Ok);
        Assert.Equal([1234], _f.Stopper.Stopped);
    }

    [Fact]
    public async Task ClosingTheDesktopAppStopsItsRestartsForThatSession()
    {
        Assert.True((await _f.Send(PipeOps.HelperExit)).Ok);
        Assert.Equal([BrokerFixture.Trusted.SessionId], _f.Helpers.Suppressed);
    }

    [Fact]
    public async Task StatusMatchesWhatTheDashboardReads()
    {
        Pending();
        _f.Processes.Apps.Add(new TrackedAiProcess(9, "Cursor.exe", @"C:\c\Cursor.exe", "Cursor", 90, "program name", 1, DateTimeOffset.UnixEpoch, null));
        var response = await _f.Send(PipeOps.Status);
        var json = response.Data!.Value.GetRawText();

        // The dashboard reads both the service and the older Python API with the same records.
        var status = JsonSerializer.Deserialize<StatusDto>(json, PipeProtocol.Json)!;
        Assert.Equal("service", status.Backend);
        Assert.Equal("Cursor", Assert.Single(status.AiProcesses).AiType);
        Assert.Equal("network", Assert.Single(status.PendingRequests).ResourceType);
        Assert.Equal("active", Assert.Single(status.Guards!).State);
        Assert.Contains("\"ai_processes\"", json, StringComparison.Ordinal);
        Assert.Contains("\"pending_requests\"", json, StringComparison.Ordinal);

        var config = (await _f.Send(PipeOps.Config)).Data!.Value.Deserialize<ConfigDto>(PipeProtocol.Json)!;
        Assert.Equal("block", config.NetworkPolicy);
    }

    [Fact]
    public void PythonApiStatusStillDeserializes()
    {
        const string python = """
            {"running": true, "ai_processes": [{"pid": 5, "name": "ollama.exe", "exe": "C:\\o.exe", "ai_type": "Ollama",
             "confidence": 90, "gpu_mb": 0.0, "detected_at": "2026-11-09T12:00:00"}],
             "active_connections": [], "pending_requests": [], "recent_events": [], "protected_folders": [],
             "stats": {"network": {"ai_connections": 0, "total_seen": 0}, "permissions": {"grants": 1, "audit_entries": 2, "blocked": 0},
             "extensions_found": 0, "models_found": 0}}
            """;
        var status = JsonSerializer.Deserialize<StatusDto>(python, PipeProtocol.Json)!;
        Assert.Equal("Ollama", status.AiProcesses[0].AiType);
        Assert.Null(status.Backend);
        Assert.Equal(2, status.Stats!.Permissions!.AuditEntries);
    }
}
