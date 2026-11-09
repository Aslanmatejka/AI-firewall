using System.Globalization;
using AiShield.Core.Config;
using AiShield.Core.Ipc;
using AiShield.Core.Models;
using Microsoft.Data.Sqlite;

namespace AiShield.Core.Policy;

public sealed record GlobalSettings(IReadOnlyDictionary<string, PolicyAction> Policies, bool Lockdown)
{
    public PolicyAction For(ResourceType type) => Policies[GlobalPolicyKeys.ForResource(type)];
}

/// <summary>Policy, grants and the audit log. Lives where only SYSTEM and administrators can write.</summary>
public sealed class PolicyStore : IDisposable
{
    public const string DefaultResource = "default";
    public static IReadOnlyList<string> AppResources { get; } = [DefaultResource, "files", "network", "clipboard", "microphone", "camera"];

    private const string LockdownKey = "lockdown";
    private const string Schema = """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS app_policies (
            app_name TEXT NOT NULL COLLATE NOCASE,
            resource TEXT NOT NULL,
            action TEXT NOT NULL,
            PRIMARY KEY (app_name, resource)
        );
        CREATE TABLE IF NOT EXISTS grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_name TEXT NOT NULL COLLATE NOCASE,
            resource_type TEXT NOT NULL,
            target TEXT NOT NULL COLLATE NOCASE,
            action TEXT NOT NULL,
            granted_at TEXT NOT NULL,
            expires_at TEXT,
            UNIQUE (app_name, resource_type, target)
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            app_name TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource TEXT NOT NULL,
            action TEXT NOT NULL,
            decision TEXT,
            message TEXT NOT NULL
        );
        """;

    private readonly SqliteConnection _db;
    private readonly Lock _gate = new();
    private readonly ShieldDefaults _defaults;
    private readonly Func<DateTimeOffset> _clock;

    public PolicyStore(string databasePath, ShieldDefaults defaults, Func<DateTimeOffset>? clock = null)
    {
        _defaults = defaults;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _db = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = false,
        }.ToString());
        _db.Open();
        Execute("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA secure_delete = ON;");
        Execute(Schema);
        foreach (var (key, value) in defaults.GlobalPolicies)
            Execute("INSERT OR IGNORE INTO settings (key, value) VALUES ($key, $value)", ("$key", key), ("$value", value.ToWire()));
        Execute("INSERT OR IGNORE INTO settings (key, value) VALUES ($key, '0')", ("$key", LockdownKey));
    }

    public static string AppResourceFor(ResourceType type) => type switch
    {
        ResourceType.File => "files",
        ResourceType.Network => "network",
        ResourceType.Clipboard => "clipboard",
        ResourceType.Microphone => "microphone",
        ResourceType.Camera => "camera",
        _ => DefaultResource,
    };

    public GlobalSettings GetGlobals()
    {
        var policies = new Dictionary<string, PolicyAction>(_defaults.GlobalPolicies, StringComparer.Ordinal);
        var lockdown = false;
        foreach (var (key, value) in Query("SELECT key, value FROM settings", static r => (r.GetString(0), r.GetString(1))))
        {
            if (key == LockdownKey)
                lockdown = value == "1";
            else if (GlobalPolicyKeys.IsKnown(key) && Wire.TryParsePolicy(value, out var action))
                policies[key] = action;
        }
        return new GlobalSettings(policies, lockdown);
    }

    public void SetGlobal(string key, PolicyAction value)
    {
        if (!GlobalPolicyKeys.IsKnown(key))
            throw new ArgumentException($"Unknown policy key: {key}", nameof(key));
        Execute("INSERT OR REPLACE INTO settings (key, value) VALUES ($key, $value)", ("$key", key), ("$value", value.ToWire()));
    }

    public void SetLockdown(bool on)
        => Execute("UPDATE settings SET value = $value WHERE key = $key", ("$key", LockdownKey), ("$value", on ? "1" : "0"));

    public void RestoreDefaults()
    {
        lock (_gate)
        {
            using var transaction = _db.BeginTransaction();
            foreach (var (key, value) in _defaults.GlobalPolicies)
                ExecuteLocked("UPDATE settings SET value = $value WHERE key = $key", ("$key", key), ("$value", value.ToWire()));
            ExecuteLocked("UPDATE settings SET value = '0' WHERE key = $key", ("$key", LockdownKey));
            transaction.Commit();
        }
    }

    public IReadOnlyDictionary<string, PolicyAction> GetAppRows(string appName)
    {
        var rows = new Dictionary<string, PolicyAction>(StringComparer.Ordinal);
        foreach (var (resource, action) in Query(
            "SELECT resource, action FROM app_policies WHERE app_name = $app",
            static r => (r.GetString(0), r.GetString(1)),
            ("$app", appName)))
        {
            if (Wire.TryParsePolicy(action, out var parsed))
                rows[resource] = parsed;
        }
        return rows;
    }

    public IReadOnlyList<string> GetAppNames()
        => Query("SELECT DISTINCT app_name FROM app_policies ORDER BY app_name", static r => r.GetString(0));

    public void SetAppPolicy(string appName, string resource, PolicyAction action)
    {
        if (!AppResources.Contains(resource))
            throw new ArgumentException($"Unknown resource: {resource}", nameof(resource));
        Execute(
            "INSERT OR REPLACE INTO app_policies (app_name, resource, action) VALUES ($app, $resource, $action)",
            ("$app", appName), ("$resource", resource), ("$action", action.ToWire()));
    }

    public bool RemoveAppPolicy(string appName)
        => Execute("DELETE FROM app_policies WHERE app_name = $app", ("$app", appName)) > 0;

    public PolicyAction? FindGrant(string appName, ResourceType type, string target)
    {
        var found = Query(
            "SELECT action FROM grants WHERE app_name = $app AND resource_type = $type AND target = $target "
            + "AND (expires_at IS NULL OR expires_at > $now) LIMIT 1",
            static r => r.GetString(0),
            ("$app", appName), ("$type", type.ToWire()), ("$target", target), ("$now", Stamp(_clock())));
        return found.Count > 0 && Wire.TryParsePolicy(found[0], out var action) ? action : null;
    }

    public void Grant(string appName, ResourceType type, string target, PolicyAction action, TimeSpan? duration)
    {
        var now = _clock();
        Execute(
            "INSERT OR REPLACE INTO grants (app_name, resource_type, target, action, granted_at, expires_at) "
            + "VALUES ($app, $type, $target, $action, $now, $expires)",
            ("$app", appName), ("$type", type.ToWire()), ("$target", target), ("$action", action.ToWire()),
            ("$now", Stamp(now)), ("$expires", duration is { } d ? Stamp(now + d) : null));
    }

    public int RevokeGrants(string? appName = null)
        => appName is null
            ? Execute("DELETE FROM grants")
            : Execute("DELETE FROM grants WHERE app_name = $app", ("$app", appName));

    public void Audit(ShieldEvent entry)
        => Execute(
            "INSERT INTO audit_log (timestamp, severity, app_name, resource_type, resource, action, decision, message) "
            + "VALUES ($ts, $severity, $app, $type, $resource, $action, $decision, $message)",
            ("$ts", Stamp(entry.Timestamp)), ("$severity", entry.Severity.ToWire()), ("$app", entry.SourceApp),
            ("$type", entry.ResourceType.ToWire()), ("$resource", entry.Resource), ("$action", entry.Action.ToWire()),
            ("$decision", entry.UserDecision), ("$message", entry.Message));

    public IReadOnlyList<AuditEntryDto> GetAudit(int limit)
        => Query(
            "SELECT id, timestamp, app_name, resource_type, resource, action, decision, message "
            + "FROM audit_log ORDER BY id DESC LIMIT $limit",
            static r => new AuditEntryDto(
                r.GetInt32(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4),
                r.GetString(5), r.IsDBNull(6) ? "" : r.GetString(6), r.GetString(7)),
            ("$limit", Math.Clamp(limit, 1, 5000)));

    public PermStatsDto GetStats()
    {
        var grants = Query("SELECT COUNT(*) FROM grants", static r => r.GetInt32(0))[0];
        var audits = Query("SELECT COUNT(*) FROM audit_log", static r => r.GetInt32(0))[0];
        var blocked = Query(
            "SELECT COUNT(*) FROM audit_log WHERE decision = 'block' OR action = 'block'", static r => r.GetInt32(0))[0];
        return new PermStatsDto(grants, audits, blocked);
    }

    public void Dispose() => _db.Dispose();

    private static string Stamp(DateTimeOffset time) => time.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private int Execute(string sql, params (string Name, object? Value)[] parameters)
    {
        lock (_gate)
            return ExecuteLocked(sql, parameters);
    }

    private int ExecuteLocked(string sql, params (string Name, object? Value)[] parameters)
    {
        using var command = Prepare(sql, parameters);
        return command.ExecuteNonQuery();
    }

    private List<T> Query<T>(string sql, Func<SqliteDataReader, T> read, params (string Name, object? Value)[] parameters)
    {
        lock (_gate)
        {
            using var command = Prepare(sql, parameters);
            using var reader = command.ExecuteReader();
            var results = new List<T>();
            while (reader.Read())
                results.Add(read(reader));
            return results;
        }
    }

    private SqliteCommand Prepare(string sql, (string Name, object? Value)[] parameters)
    {
        var command = _db.CreateCommand();
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
            command.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return command;
    }
}
