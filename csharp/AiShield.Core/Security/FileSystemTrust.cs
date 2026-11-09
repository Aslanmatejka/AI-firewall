using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;

namespace AiShield.Core.Security;

public static class WellKnown
{
    public static SecurityIdentifier LocalSystem { get; } = new(WellKnownSidType.LocalSystemSid, null);
    public static SecurityIdentifier Administrators { get; } = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    public static SecurityIdentifier Interactive { get; } = new(WellKnownSidType.InteractiveSid, null);
    public static SecurityIdentifier AuthenticatedUsers { get; } = new(WellKnownSidType.AuthenticatedUserSid, null);
    public static SecurityIdentifier Network { get; } = new(WellKnownSidType.NetworkSid, null);
    public static SecurityIdentifier CreatorOwner { get; } = new(WellKnownSidType.CreatorOwnerSid, null);
    public static SecurityIdentifier TrustedInstaller { get; } = new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

    public static IReadOnlyList<SecurityIdentifier> SystemAndAdministrators { get; } = [LocalSystem, Administrators];
}

/// <summary>
/// Makes sure a data folder is a real folder that only trusted accounts can reach. Anything an ordinary
/// user put there first, whether a folder, a file or a link pointing elsewhere, is moved out of the way.
/// </summary>
public static class SecureDataDirectory
{
    public static void Ensure(string path, IReadOnlyCollection<SecurityIdentifier> trusted, Func<DateTimeOffset>? clock = null)
    {
        var now = clock ?? (() => DateTimeOffset.UtcNow);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            if (!Directory.Exists(path) && !File.Exists(path))
            {
                new DirectoryInfo(path).Create(BuildSecurity(trusted));
            }
            else
            {
                var attributes = File.GetAttributes(path);
                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    // A junction or link: remove the link itself, never what it points to.
                    if (attributes.HasFlag(FileAttributes.Directory))
                        Directory.Delete(path);
                    else
                        File.Delete(path);
                    continue;
                }
                if (!attributes.HasFlag(FileAttributes.Directory) || !IsOwnedByTrusted(path, trusted))
                {
                    MoveAside(path, attributes, now());
                    continue;
                }
                new DirectoryInfo(path).SetAccessControl(BuildSecurity(trusted));
            }

            if (IsLockedDown(path, trusted))
                return;
        }
        throw new UnauthorizedAccessException($"Couldn't secure {path}");
    }

    public static bool IsLockedDown(string path, IReadOnlyCollection<SecurityIdentifier> trusted)
    {
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint) || !IsOwnedByTrusted(path, trusted))
            return false;
        var rules = new DirectoryInfo(path).GetAccessControl()
            .GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        return rules.Cast<FileSystemAccessRule>().All(rule =>
            rule.AccessControlType == AccessControlType.Deny || trusted.Contains((SecurityIdentifier)rule.IdentityReference));
    }

    private static bool IsOwnedByTrusted(string path, IReadOnlyCollection<SecurityIdentifier> trusted)
        => new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner)
            .GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier owner && trusted.Contains(owner);

    private static DirectorySecurity BuildSecurity(IReadOnlyCollection<SecurityIdentifier> trusted)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in trusted)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }
        return security;
    }

    private static void MoveAside(string path, FileAttributes attributes, DateTimeOffset now)
    {
        var aside = $"{path}.untrusted-{now.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture)}";
        if (attributes.HasFlag(FileAttributes.Directory))
            Directory.Move(path, aside);
        else
            File.Move(path, aside);
    }
}

/// <summary>Checks that only administrators can change the program's own files.</summary>
public static class InstallLocation
{
    private const FileSystemRights WriteRights =
        FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes
        | FileSystemRights.WriteAttributes | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles
        | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    // Generic rights can appear unmapped in inheritable entries.
    private const int GenericAll = 0x10000000;
    private const int GenericWrite = 0x40000000;

    private static readonly SecurityIdentifier[] TrustedWriters =
        [WellKnown.LocalSystem, WellKnown.Administrators, WellKnown.TrustedInstaller];

    public static bool IsProtected(string root, out string problem)
    {
        if (!Directory.Exists(root))
        {
            problem = $"{root} doesn't exist";
            return false;
        }

        var items = new[] { root }
            .Concat(Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
            .SelectMany(dir => new[] { dir }.Concat(Directory.EnumerateFiles(dir)));
        foreach (var item in items)
        {
            if (Writable(item) is { } reason)
            {
                problem = $"{item}: {reason}";
                return false;
            }
        }
        problem = "";
        return true;
    }

    private static string? Writable(string path)
    {
        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.ReparsePoint))
            return "is a link";

        FileSystemSecurity security = attributes.HasFlag(FileAttributes.Directory)
            ? new DirectoryInfo(path).GetAccessControl()
            : new FileInfo(path).GetAccessControl();

        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !TrustedWriters.Contains(owner))
            return "has an untrusted owner";

        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType != AccessControlType.Allow)
                continue;
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (TrustedWriters.Contains(sid) || sid == WellKnown.CreatorOwner)
                continue;
            var rights = (int)rule.FileSystemRights;
            if ((rule.FileSystemRights & WriteRights) != 0 || (rights & (GenericAll | GenericWrite)) != 0)
                return $"{sid.Value} can change it";
        }
        return null;
    }
}
