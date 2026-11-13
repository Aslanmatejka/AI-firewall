using System.Diagnostics;
using System.ServiceProcess;
using AiShield.Core.Config;
using AiShield.Core.Maintenance;
using AiShield.Core.Security;
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
    private static readonly string[] AppProcessNames = ["AiShield.Dashboard", "AiShield.Consent"];

    private static string Root => Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory))!;
    private static string ServiceExe => Path.Combine(Root, "service", "AiShield.Service.exe");
    private static string DataDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AiShield");

    // Tools run by full path, so a same-named program elsewhere on the search path can't stand in for them.
    private static string System32 => Environment.GetFolderPath(Environment.SpecialFolder.System);

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

        RunTool(Path.Combine(System32, "sc.exe"), "delete AiShield");
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
            Path.Combine(System32, @"WindowsPowerShell\v1.0\powershell.exe"),
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

    /// <summary>
    /// A full uninstall removes the service's policy and logs. It never deletes anything an ordinary user
    /// can change: doing that as SYSTEM through a planted link is a classic way to take over a PC. So
    /// folders a user planted before install, which were moved aside, stay theirs, and so does the
    /// desktop app's small error log in each user's profile.
    /// </summary>
    private static void RemoveData()
    {
        RunTool(Path.Combine(System32, "logman.exe"), "stop AiShield-ProcessGuard -ets");

        if (Directory.Exists(DataDirectory))
        {
            // Only a folder nobody but SYSTEM and administrators could ever write into is safe to empty.
            if (SecureDataDirectory.IsLockedDown(DataDirectory, WellKnown.SystemAndAdministrators))
            {
                Directory.Delete(DataDirectory, recursive: true);
                Console.WriteLine($"Removed {DataDirectory}");
            }
            else
            {
                Console.Error.WriteLine($"Left {DataDirectory} alone: ordinary users can change it");
            }
        }

        Registry.LocalMachine.DeleteSubKeyTree(EventSourceKey, throwOnMissingSubKey: false);
        Registry.LocalMachine.DeleteSubKeyTree(Core.Ipc.PipeProtocol.RegistryKey, throwOnMissingSubKey: false);
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
