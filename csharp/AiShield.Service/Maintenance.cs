using System.Diagnostics;
using System.ServiceProcess;
using AiShield.Core.Config;
using AiShield.Core.Maintenance;
using AiShield.Core.Windows;
using Microsoft.Win32;

namespace AiShield.Service;

/// <summary>
/// Tasks the installer runs as SYSTEM through "AiShield.Service.exe --maintenance task". They print what
/// they did, and never touch anything they can't identify as AI Firewall's.
/// </summary>
internal static class Maintenance
{
    private const string ServiceKey = @"SYSTEM\CurrentControlSet\Services\AiShield";
    private const string EventSourceKey = @"SYSTEM\CurrentControlSet\Services\EventLog\Application\AiShield";
    private const string ProfileList = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    private static readonly string[] AppProcessNames = ["AiShield.Dashboard", "AiShield.Consent"];

    private static string Root => Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory))!;
    private static string ServiceExe => Path.Combine(Root, "service", "AiShield.Service.exe");
    private static string DataDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AiShield");

    public static int Run(string task)
    {
        try
        {
            switch (task)
            {
                case "stop-apps":
                    StopApps();
                    return 0;
                case "remove-legacy":
                    RemoveLegacyService();
                    RemoveLegacyBlocks();
                    return 0;
                case "remove-data":
                    RemoveLegacyBlocks();
                    RemoveData();
                    return 0;
                default:
                    Console.Error.WriteLine($"Unknown maintenance task: {task}");
                    return 2;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"{task} failed: {ex}");
            return 1;
        }
    }

    /// <summary>Closes the desktop app and any open prompt, so their files can be replaced or removed.</summary>
    private static void StopApps()
    {
        foreach (var name in AppProcessNames)
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                using (process)
                {
                    var image = NativeProcess.TryGetImagePath(process.Id);
                    if (image is null || !image.StartsWith(Root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                        continue;
                    try
                    {
                        process.Kill();
                        process.WaitForExit(TimeSpan.FromSeconds(5));
                        Console.WriteLine($"Closed {name} (PID {process.Id})");
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
                    {
                        Console.Error.WriteLine($"Couldn't close {name} (PID {process.Id}): {ex.Message}");
                    }
                }
            }
        }
    }

    /// <summary>
    /// Earlier versions registered a service with the same name that ran Python from wherever the
    /// repository was. It has to go before this version's service can be installed.
    /// </summary>
    private static void RemoveLegacyService()
    {
        using (var key = Registry.LocalMachine.OpenSubKey(ServiceKey))
        {
            if (key?.GetValue("ImagePath") is not string imagePath)
                return;
            if (string.Equals(imagePath.Trim().Trim('"'), ServiceExe, StringComparison.OrdinalIgnoreCase))
                return;
            Console.WriteLine($"Removing the old AiShield service ({imagePath})");
        }

        using (var service = new ServiceController("AiShield"))
        {
            try
            {
                if (service.Status != ServiceControllerStatus.Stopped)
                {
                    service.Stop();
                    service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.ServiceProcess.TimeoutException)
            {
                Console.Error.WriteLine($"Couldn't stop the old service: {ex.Message}");
            }
        }

        RunTool("sc.exe", "delete AiShield");
        for (var i = 0; i < 40 && Registry.LocalMachine.OpenSubKey(ServiceKey) is { } still; i++)
        {
            still.Dispose();
            Thread.Sleep(250);
        }
    }

    /// <summary>Firewall rules and hosts entries earlier versions added. This version uses neither.</summary>
    private static void RemoveLegacyBlocks()
    {
        RunTool(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe"),
            "-NoProfile -NonInteractive -Command \"Get-NetFirewallRule -DisplayName 'AiShield-Block-*','AiShield-WFP-*' "
            + "-ErrorAction SilentlyContinue | Remove-NetFirewallRule\"");

        var configPath = Path.Combine(Root, "config", "default.json");
        var domains = File.Exists(configPath) ? ShieldDefaults.Load(configPath).AiDomains : [];
        if (domains.Count == 0 || !File.Exists(HostsFile.Path))
            return;
        var original = File.ReadAllText(HostsFile.Path);
        var cleaned = HostsFile.RemoveLegacyEntries(original, domains, out var removed);
        if (removed > 0)
        {
            File.WriteAllText(HostsFile.Path, cleaned);
            Console.WriteLine($"Removed {removed} line(s) older versions added to the hosts file");
        }
    }

    /// <summary>A full uninstall removes policy, logs and anything left from a planted data folder.</summary>
    private static void RemoveData()
    {
        RunTool("logman.exe", "stop AiShield-ProcessGuard -ets");

        var parent = Path.GetDirectoryName(DataDirectory)!;
        foreach (var dir in Directory.EnumerateDirectories(parent, "AiShield*"))
        {
            var name = Path.GetFileName(dir);
            if (name == "AiShield" || name.StartsWith("AiShield.untrusted-", StringComparison.Ordinal))
                DeleteDirectory(dir);
        }

        Registry.LocalMachine.DeleteSubKeyTree(EventSourceKey, throwOnMissingSubKey: false);

        // The desktop app keeps a small error log in each user's profile.
        using var profiles = Registry.LocalMachine.OpenSubKey(ProfileList);
        foreach (var sid in profiles?.GetSubKeyNames() ?? [])
        {
            using var profile = profiles!.OpenSubKey(sid);
            if (profile?.GetValue("ProfileImagePath") is not string home)
                continue;
            var appFolder = Path.Combine(Environment.ExpandEnvironmentVariables(home), "AppData", "Local", "AiShield");
            if (!Directory.Exists(appFolder))
                continue;
            foreach (var log in Directory.EnumerateFiles(appFolder, "dashboard.log*"))
                File.Delete(log);
            if (!Directory.EnumerateFileSystemEntries(appFolder).Any())
                Directory.Delete(appFolder);
        }
    }

    private static void DeleteDirectory(string path)
    {
        var attributes = File.GetAttributes(path);
        // A planted link is removed itself, never followed.
        Directory.Delete(path, recursive: !attributes.HasFlag(FileAttributes.ReparsePoint));
        Console.WriteLine($"Removed {path}");
    }

    private static void RunTool(string tool, string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo(tool, arguments)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        });
        if (process is null)
            return;
        process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit(TimeSpan.FromSeconds(60));
    }
}
