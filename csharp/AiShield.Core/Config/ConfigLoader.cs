using System.Text.Json;

namespace AiShield.Core.Config;

public sealed class ShieldConfig
{
    public string GlobalPolicy { get; set; } = "ask";
    public bool FailClosed { get; set; }
    public string NetworkPolicy { get; set; } = "ask";
    public string ClipboardPolicy { get; set; } = "ask";
    public string ScreenshotPolicy { get; set; } = "ask";
    public string MicrophonePolicy { get; set; } = "ask";
    public string CameraPolicy { get; set; } = "ask";
    public int DashboardPort { get; set; } = 9470;
    public string DashboardHost { get; set; } = "127.0.0.1";
    public List<string> AiDomains { get; set; } = [];
    public List<AiSignature> AiProcessSignatures { get; set; } = [];
}

public sealed class AiSignature
{
    public string Name { get; set; } = "";
    public string[] Patterns { get; set; } = [];
}

public static class ConfigLoader
{
    public static string GetProgramDataPath()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AiShield");
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static string ResolveConfigPath()
    {
        var programData = Path.Combine(GetProgramDataPath(), "config.json");
        if (File.Exists(programData)) return programData;

        var repo = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "config", "default.json"));
        if (File.Exists(repo)) return repo;

        return programData;
    }

    public static ShieldConfig Load()
    {
        var path = ResolveConfigPath();
        if (!File.Exists(path))
            return new ShieldConfig();

        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        return new ShieldConfig
        {
            GlobalPolicy = root.TryGetProperty("global_policy", out var gp) ? gp.GetString() ?? "ask" : "ask",
            FailClosed = root.TryGetProperty("fail_closed", out var fc) && fc.GetBoolean(),
            NetworkPolicy = root.TryGetProperty("network_policy", out var np) ? np.GetString() ?? "ask" : "ask",
            ClipboardPolicy = root.TryGetProperty("clipboard_policy", out var cp) ? cp.GetString() ?? "ask" : "ask",
            ScreenshotPolicy = root.TryGetProperty("screenshot_policy", out var sp) ? sp.GetString() ?? "ask" : "ask",
            MicrophonePolicy = root.TryGetProperty("microphone_policy", out var mp) ? mp.GetString() ?? "ask" : "ask",
            CameraPolicy = root.TryGetProperty("camera_policy", out var cap) ? cap.GetString() ?? "ask" : "ask",
            DashboardPort = root.TryGetProperty("dashboard_port", out var dp) ? dp.GetInt32() : 9470,
            DashboardHost = root.TryGetProperty("dashboard_host", out var dh) ? dh.GetString() ?? "127.0.0.1" : "127.0.0.1",
            AiDomains = root.TryGetProperty("ai_domains", out var ad)
                ? ad.EnumerateArray().Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList()
                : [],
            AiProcessSignatures = root.TryGetProperty("ai_process_signatures", out var sigs)
                ? sigs.EnumerateArray().Select(s => new AiSignature
                {
                    Name = s.GetProperty("name").GetString() ?? "",
                    Patterns = s.GetProperty("patterns").EnumerateArray().Select(p => p.GetString() ?? "").ToArray(),
                }).ToList()
                : [],
        };
    }

    public static void InstallDefaultConfig(string sourceJsonPath)
    {
        var dest = Path.Combine(GetProgramDataPath(), "config.json");
        if (!File.Exists(dest) && File.Exists(sourceJsonPath))
            File.Copy(sourceJsonPath, dest);
    }
}
