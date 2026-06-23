using AiShield.Core.Models;
using Microsoft.Data.Sqlite;

namespace AiShield.Core.Permissions;

public sealed class PermissionManager : IDisposable
{
    private readonly string _dbPath;
    private readonly object _lock = new();

    public PermissionManager(string? dataDir = null)
    {
        dataDir ??= Config.ConfigLoader.GetProgramDataPath();
        Directory.CreateDirectory(dataDir);
        _dbPath = Path.Combine(dataDir, "permissions.db");
        InitDb();
    }

    private void InitDb()
    {
        using var conn = Open();
        conn.Execute(@"
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                app_name TEXT,
                resource_type TEXT,
                resource TEXT,
                action TEXT,
                decision TEXT,
                message TEXT
            );
            CREATE TABLE IF NOT EXISTS app_policies (
                app_name TEXT PRIMARY KEY,
                default_action TEXT NOT NULL,
                microphone TEXT DEFAULT 'ask',
                camera TEXT DEFAULT 'ask',
                files TEXT DEFAULT 'ask',
                network TEXT DEFAULT 'ask',
                clipboard TEXT DEFAULT 'ask'
            );");
    }

    public void LogEvent(ShieldEvent evt)
    {
        lock (_lock)
        using (var conn = Open())
        {
            conn.Execute(
                "INSERT INTO audit_log (timestamp, app_name, resource_type, resource, action, decision, message) VALUES (@ts, @app, @type, @res, @act, @dec, @msg)",
                new
                {
                    ts = evt.Timestamp.ToString("O"),
                    app = evt.SourceApp,
                    type = evt.ResourceType.ToString().ToLower(),
                    res = evt.Resource,
                    act = evt.Action.ToString().ToLower(),
                    dec = evt.UserDecision,
                    msg = evt.Message,
                });
        }
    }

    public void LogDetection(string appName, int pid, string message)
    {
        LogEvent(new ShieldEvent(
            Guid.NewGuid().ToString()[..8], DateTime.Now, EventSeverity.Warning,
            ResourceType.Process, PolicyAction.Ask, appName, pid.ToString(), message));
    }

    public int GetAuditCount()
    {
        lock (_lock)
        using (var conn = Open())
            return conn.QueryScalar<int>("SELECT COUNT(*) FROM audit_log");
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        return conn;
    }

    public void Dispose() { }
}

internal static class SqliteExtensions
{
    public static void Execute(this SqliteConnection conn, string sql, object? param = null)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        if (param is not null)
        {
            foreach (var prop in param.GetType().GetProperties())
            {
                var p = cmd.CreateParameter();
                p.ParameterName = "@" + prop.Name;
                p.Value = prop.GetValue(param) ?? DBNull.Value;
                cmd.Parameters.Add(p);
            }
        }
        cmd.ExecuteNonQuery();
    }

    public static T QueryScalar<T>(this SqliteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        var result = cmd.ExecuteScalar();
        return (T)Convert.ChangeType(result ?? 0, typeof(T));
    }
}
