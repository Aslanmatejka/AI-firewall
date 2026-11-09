using System.Collections.Frozen;
using AiShield.Core.Models;

namespace AiShield.Core.Policy;

/// <summary>Order: lockdown, then a saved decision, then the folder, the app's rules and the global policy.</summary>
public sealed class PolicyResolver(PolicyStore store)
{
    public static FrozenSet<ResourceType> LockdownCovers { get; } = new[]
    {
        ResourceType.Network, ResourceType.Clipboard, ResourceType.Screenshot, ResourceType.Microphone, ResourceType.Camera,
    }.ToFrozenSet();

    public PolicyAction Resolve(string appName, ResourceType type, string target, PolicyAction? folderPolicy = null)
    {
        var globals = store.GetGlobals();
        // Lockdown outranks saved decisions, so turning it on takes effect for everything at once.
        if (globals.Lockdown && LockdownCovers.Contains(type))
            return PolicyAction.Block;
        if (store.FindGrant(appName, type, target) is { } granted)
            return granted;
        if (folderPolicy is { } folder)
            return folder;
        return Configured(store.GetAppRows(appName), globals, type);
    }

    /// <summary>What the rules say for this app, ignoring lockdown and saved decisions.</summary>
    public static PolicyAction Configured(IReadOnlyDictionary<string, PolicyAction> appRows, GlobalSettings globals, ResourceType type)
    {
        if (appRows.TryGetValue(PolicyStore.AppResourceFor(type), out var own))
            return own;
        if (appRows.TryGetValue(PolicyStore.DefaultResource, out var fallback))
            return fallback;
        return globals.For(type);
    }
}

/// <summary>Whether a change makes protection weaker. Weakening changes need the user's confirmation.</summary>
public static class PolicyChanges
{
    public static bool Weakens(PolicyAction before, PolicyAction after) => after < before;

    public static bool AppRulesWeaken(
        IReadOnlyDictionary<string, PolicyAction> before,
        IReadOnlyDictionary<string, PolicyAction> after,
        GlobalSettings globals)
        => Enum.GetValues<ResourceType>().Any(type =>
            Weakens(PolicyResolver.Configured(before, globals, type), PolicyResolver.Configured(after, globals, type)));

    public static bool GlobalsWeaken(GlobalSettings before, GlobalSettings after)
        => (before.Lockdown && !after.Lockdown)
            || before.Policies.Any(pair => Weakens(pair.Value, after.Policies[pair.Key]));
}
