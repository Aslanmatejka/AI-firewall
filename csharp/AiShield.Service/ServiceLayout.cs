using System.Security.Principal;
using AiShield.Core.Security;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace AiShield.Service;

/// <summary>
/// Where everything lives. Installed, the layout is root\service, root\dashboard, root\consent and
/// root\config, under Program Files.
/// </summary>
internal sealed record ServiceLayout(
    bool IsService,
    string Root,
    string DashboardExe,
    string ConsentExe,
    string ConfigPath,
    string DataDirectory,
    IReadOnlyCollection<SecurityIdentifier> DataOwners,
    bool InstallProtected,
    string InstallProblem,
    IReadOnlyCollection<string> TrustedClientImages)
{
    public static ServiceLayout Resolve(string[] args)
    {
        var isService = WindowsServiceHelpers.IsWindowsService();
        var serviceDir = Path.TrimEndingDirectorySeparator(AppContext.BaseDirectory);
        var root = Path.GetDirectoryName(serviceDir) ?? serviceDir;

        // Run from a console, the service keeps its data wherever the developer says, as that developer.
        var dataDir = isService
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AiShield")
            : ReadArgument(args, "--data-dir") ?? Path.Combine(Path.GetTempPath(), "AiShield-dev");
        IReadOnlyCollection<SecurityIdentifier> owners = isService
            ? WellKnown.SystemAndAdministrators
            : [WindowsIdentity.GetCurrent().User!];

        var dashboard = Path.Combine(root, "dashboard", "AiShield.Dashboard.exe");
        List<string> trustedClients = [dashboard];
#if AISHIELD_TEST_HOOKS
        trustedClients.Add(Path.Combine(root, "dashboard", "AiShield.TamperProbe.exe"));
#endif

        var protectedInstall = InstallLocation.IsProtected(root, out var problem);
        return new ServiceLayout(
            isService, root, dashboard, Path.Combine(root, "consent", "AiShield.Consent.exe"),
            FindConfig(root, serviceDir), dataDir, owners, protectedInstall, problem,
            trustedClients.Select(Path.GetFullPath).ToList());
    }

    private static string FindConfig(string root, string serviceDir)
    {
        var installed = Path.Combine(root, "config", "default.json");
        if (File.Exists(installed))
            return installed;
        for (var dir = new DirectoryInfo(serviceDir); dir is not null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "config", "default.json");
            if (File.Exists(candidate))
                return candidate;
        }
        throw new FileNotFoundException("Couldn't find config\\default.json next to the service");
    }

    private static string? ReadArgument(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? Path.GetFullPath(args[index + 1]) : null;
    }
}
