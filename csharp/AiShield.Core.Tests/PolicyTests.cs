using AiShield.Core.Config;
using AiShield.Core.Models;
using AiShield.Core.Policy;

namespace AiShield.Core.Tests;

public sealed class PolicyTests : IDisposable
{
    private readonly TempDirectory _dir = new();
    private readonly ManualClock _clock = new(new DateTimeOffset(2026, 11, 9, 12, 0, 0, TimeSpan.Zero));
    private readonly PolicyStore _store;
    private readonly PolicyResolver _resolver;

    public PolicyTests()
    {
        _store = new PolicyStore(Path.Combine(_dir.Path, "policy.db"), TestDefaults.Create(), () => _clock.Now);
        _resolver = new PolicyResolver(_store);
    }

    public void Dispose()
    {
        _store.Dispose();
        _dir.Dispose();
    }

    // Ported from python/tests/test_resolver.py.
    [Fact]
    public void GlobalNetworkBlockApplies() => Assert.Equal(PolicyAction.Block, _resolver.Resolve("Cursor", ResourceType.Network, "api.openai.com"));

    [Fact]
    public void AppPolicyOverridesGlobal()
    {
        _store.SetAppPolicy("Cursor", "network", PolicyAction.Allow);
        Assert.Equal(PolicyAction.Allow, _resolver.Resolve("Cursor", ResourceType.Network, "api.openai.com"));
    }

    [Fact]
    public void AppDefaultRuleCoversResourcesWithoutTheirOwn()
    {
        _store.SetAppPolicy("Cursor", PolicyStore.DefaultResource, PolicyAction.Block);
        _store.SetAppPolicy("Cursor", "files", PolicyAction.Allow);
        Assert.Equal(PolicyAction.Block, _resolver.Resolve("Cursor", ResourceType.Clipboard, "x"));
        Assert.Equal(PolicyAction.Allow, _resolver.Resolve("Cursor", ResourceType.File, "x"));
    }

    [Fact]
    public void AppNamesIgnoreCase()
    {
        _store.SetAppPolicy("Cursor", "network", PolicyAction.Allow);
        Assert.Equal(PolicyAction.Allow, _resolver.Resolve("CURSOR", ResourceType.Network, "x"));
    }

    [Fact]
    public void GrantBeatsAppRules()
    {
        _store.SetAppPolicy("Cursor", "network", PolicyAction.Block);
        _store.Grant("Cursor", ResourceType.Network, "api.openai.com", PolicyAction.Allow, TimeSpan.FromHours(1));
        Assert.Equal(PolicyAction.Allow, _resolver.Resolve("Cursor", ResourceType.Network, "API.OPENAI.COM"));
        Assert.Equal(PolicyAction.Block, _resolver.Resolve("Cursor", ResourceType.Network, "other.example"));
    }

    [Fact]
    public void ExpiredGrantNoLongerApplies()
    {
        _store.Grant("Cursor", ResourceType.Network, "api.openai.com", PolicyAction.Allow, TimeSpan.FromHours(1));
        _clock.Advance(TimeSpan.FromHours(2));
        Assert.Equal(PolicyAction.Block, _resolver.Resolve("Cursor", ResourceType.Network, "api.openai.com"));
    }

    [Fact]
    public void LockdownBeatsGrantsAndAppRules()
    {
        _store.SetAppPolicy("Cursor", "network", PolicyAction.Allow);
        _store.Grant("Cursor", ResourceType.Clipboard, "x", PolicyAction.Allow, null);
        _store.SetLockdown(true);
        Assert.Equal(PolicyAction.Block, _resolver.Resolve("Cursor", ResourceType.Network, "x"));
        Assert.Equal(PolicyAction.Block, _resolver.Resolve("Cursor", ResourceType.Clipboard, "x"));
    }

    [Fact]
    public void FolderPolicyBeatsAppRulesButNotGrants()
    {
        _store.SetAppPolicy("Cursor", "files", PolicyAction.Allow);
        Assert.Equal(PolicyAction.Block, _resolver.Resolve("Cursor", ResourceType.File, @"C:\Secret\a.txt", PolicyAction.Block));
        _store.Grant("Cursor", ResourceType.File, @"C:\Secret\a.txt", PolicyAction.Allow, null);
        Assert.Equal(PolicyAction.Allow, _resolver.Resolve("Cursor", ResourceType.File, @"C:\Secret\a.txt", PolicyAction.Block));
    }

    [Fact]
    public void WildcardCharactersInTargetsStayLiteral()
    {
        _store.Grant("AI", ResourceType.File, @"C:\docs\100%_report.txt", PolicyAction.Allow, null);
        Assert.Equal(PolicyAction.Allow, _resolver.Resolve("AI", ResourceType.File, @"C:\docs\100%_report.txt"));
        Assert.Equal(PolicyAction.Ask, _resolver.Resolve("AI", ResourceType.File, @"C:\docs\100 percent secrets.txt"));
    }

    [Fact]
    public void RevokeRemovesGrants()
    {
        _store.Grant("Cursor", ResourceType.Network, "a", PolicyAction.Allow, null);
        _store.Grant("Ollama", ResourceType.Network, "a", PolicyAction.Allow, null);
        Assert.Equal(1, _store.RevokeGrants("cursor"));
        Assert.Null(_store.FindGrant("Cursor", ResourceType.Network, "a"));
        Assert.NotNull(_store.FindGrant("Ollama", ResourceType.Network, "a"));
    }

    [Fact]
    public void SettingsSurviveReopening()
    {
        _store.SetGlobal(GlobalPolicyKeys.Camera, PolicyAction.Block);
        _store.SetLockdown(true);
        using var reopened = new PolicyStore(Path.Combine(_dir.Path, "policy.db"), TestDefaults.Create());
        var globals = reopened.GetGlobals();
        Assert.Equal(PolicyAction.Block, globals.Policies[GlobalPolicyKeys.Camera]);
        Assert.True(globals.Lockdown);
    }

    [Fact]
    public void RestoreDefaultsResetsPoliciesAndLockdown()
    {
        _store.SetGlobal(GlobalPolicyKeys.Network, PolicyAction.Allow);
        _store.SetLockdown(true);
        _store.RestoreDefaults();
        var globals = _store.GetGlobals();
        Assert.Equal(PolicyAction.Block, globals.Policies[GlobalPolicyKeys.Network]);
        Assert.False(globals.Lockdown);
    }

    [Fact]
    public void UnknownKeysAndResourcesAreRefused()
    {
        Assert.Throws<ArgumentException>(() => _store.SetGlobal("fail_closed", PolicyAction.Allow));
        Assert.Throws<ArgumentException>(() => _store.SetAppPolicy("AI", "kernel", PolicyAction.Allow));
    }

    [Theory]
    [InlineData(PolicyAction.Block, PolicyAction.Ask, true)]
    [InlineData(PolicyAction.Block, PolicyAction.Allow, true)]
    [InlineData(PolicyAction.Ask, PolicyAction.Allow, true)]
    [InlineData(PolicyAction.Allow, PolicyAction.Block, false)]
    [InlineData(PolicyAction.Ask, PolicyAction.Ask, false)]
    public void WeakeningMeansLessStrict(PolicyAction before, PolicyAction after, bool weakens)
        => Assert.Equal(weakens, PolicyChanges.Weakens(before, after));

    [Fact]
    public void RemovingStrictAppRulesWeakens()
    {
        var globals = _store.GetGlobals();
        var strict = new Dictionary<string, PolicyAction> { ["files"] = PolicyAction.Block };
        var lax = new Dictionary<string, PolicyAction> { ["network"] = PolicyAction.Allow };
        Assert.True(PolicyChanges.AppRulesWeaken(strict, new Dictionary<string, PolicyAction>(), globals));
        Assert.False(PolicyChanges.AppRulesWeaken(lax, new Dictionary<string, PolicyAction>(), globals));
    }

    [Fact]
    public void ChangingTheDefaultRuleCountsEveryResourceItCovers()
    {
        var globals = _store.GetGlobals();
        var before = new Dictionary<string, PolicyAction> { [PolicyStore.DefaultResource] = PolicyAction.Block };
        var after = new Dictionary<string, PolicyAction> { [PolicyStore.DefaultResource] = PolicyAction.Ask };
        Assert.True(PolicyChanges.AppRulesWeaken(before, after, globals));
    }

    [Fact]
    public void LockdownOffWeakens()
    {
        var on = _store.GetGlobals() with { Lockdown = true };
        Assert.True(PolicyChanges.GlobalsWeaken(on, on with { Lockdown = false }));
        Assert.False(PolicyChanges.GlobalsWeaken(on with { Lockdown = false }, on));
    }

    [Fact]
    public void ShippedDefaultsLoad()
    {
        var defaults = ShieldDefaults.Load(Path.Combine(AppContext.BaseDirectory, "default.json"));
        Assert.Equal(PolicyAction.Block, defaults.GlobalPolicies[GlobalPolicyKeys.Screenshot]);
        Assert.Contains(defaults.Signatures, s => s.Name == "Claude Code" && s.CommandLinePatterns.Count > 0);
        Assert.Contains("api.anthropic.com", defaults.AiDomains);
        Assert.Equal(TimeSpan.FromSeconds(120), defaults.ApprovalTimeout);
    }

    [Fact]
    public void BadPolicyValuesInDefaultsFallBackToAsk()
    {
        var defaults = ShieldDefaults.Parse("""{ "network_policy": "maybe", "camera_policy": 3 }""");
        Assert.Equal(PolicyAction.Ask, defaults.GlobalPolicies[GlobalPolicyKeys.Network]);
        Assert.Equal(PolicyAction.Ask, defaults.GlobalPolicies[GlobalPolicyKeys.Camera]);
        Assert.Empty(defaults.Signatures);
    }
}
