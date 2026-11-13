using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using AiShield.Core.Ipc;
using AiShield.Core.Models;
using AiShield.Core.Security;
using AiShield.Core.Windows;

namespace AiShield.Core.Tests;

public sealed class PipeProtocolTests
{
    [Fact]
    public async Task MessagesRoundTrip()
    {
        using var stream = new MemoryStream();
        await PipeProtocol.WriteMessageAsync(stream, "{\"op\":\"status\"}"u8.ToArray(), TestContext.Current.CancellationToken);
        await PipeProtocol.WriteMessageAsync(stream, "{}"u8.ToArray(), TestContext.Current.CancellationToken);
        stream.Position = 0;

        Assert.Equal("{\"op\":\"status\"}"u8.ToArray(), await PipeProtocol.ReadMessageAsync(stream, TestContext.Current.CancellationToken));
        Assert.Equal("{}"u8.ToArray(), await PipeProtocol.ReadMessageAsync(stream, TestContext.Current.CancellationToken));
        Assert.Null(await PipeProtocol.ReadMessageAsync(stream, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OversizedAndTruncatedMessagesAreRejected()
    {
        using var huge = new MemoryStream([0xFF, 0xFF, 0xFF, 0x7F]);
        await Assert.ThrowsAsync<InvalidDataException>(() => PipeProtocol.ReadMessageAsync(huge, TestContext.Current.CancellationToken));

        using var negative = new MemoryStream([0xFF, 0xFF, 0xFF, 0xFF]);
        await Assert.ThrowsAsync<InvalidDataException>(() => PipeProtocol.ReadMessageAsync(negative, TestContext.Current.CancellationToken));

        using var truncated = new MemoryStream([10, 0, 0, 0, 1, 2]);
        await Assert.ThrowsAsync<EndOfStreamException>(() => PipeProtocol.ReadMessageAsync(truncated, TestContext.Current.CancellationToken));

        using var sink = new MemoryStream();
        await Assert.ThrowsAsync<InvalidDataException>(() =>
            PipeProtocol.WriteMessageAsync(sink, new byte[PipeProtocol.MaxMessageBytes + 1], TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ResponsesUseTheWireNames()
    {
        var json = System.Text.Json.JsonSerializer.Serialize(PipeResponse.Failure(3, PipeErrors.NotApproved, ConsentOutcome.Dismissed), PipeProtocol.Json);
        Assert.Contains("\"consent\":\"dismissed\"", json, StringComparison.Ordinal);
        Assert.Contains("\"error\":\"not-approved\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ClientGivesUpQuicklyWhenNoServiceIsRunning()
    {
        var client = new ShieldPipeClient { ConnectTimeout = TimeSpan.FromMilliseconds(200) };
        var watch = Stopwatch.StartNew();
        Assert.Null(await client.SendAsync(PipeOps.Hello, ct: TestContext.Current.CancellationToken));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5));
    }
}

public sealed class NativeProcessTests
{
    [Fact]
    public void ReadsThisProcess()
    {
        using var self = Process.GetCurrentProcess();
        Assert.Equal(Environment.ProcessPath, NativeProcess.TryGetImagePath(self.Id), StringComparer.OrdinalIgnoreCase);
        Assert.Contains(Path.GetFileNameWithoutExtension(Environment.ProcessPath!), NativeProcess.TryGetCommandLine(self.Id), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(self.SessionId, NativeProcess.GetSessionId(self.Id));
    }

    [Fact]
    public void SnapshotIncludesThisProcessAndItsParent()
    {
        var snapshot = NativeProcess.Snapshot();
        var self = Assert.Single(snapshot, e => e.Pid == Environment.ProcessId);
        Assert.True(self.ParentPid > 0);
        Assert.Contains(snapshot, e => e.Pid == 4 || e.ExeName.Equals("System", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void MissingProcessesReturnNothing()
    {
        Assert.Null(NativeProcess.TryGetImagePath(int.MaxValue - 1));
        Assert.Null(NativeProcess.TryGetCommandLine(int.MaxValue - 1));
    }

    [Fact]
    public void UnknownServiceHasNoProcess() => Assert.Null(ServiceQuery.GetProcessId("AiShield-does-not-exist"));
}

public sealed class FileSystemTrustTests
{
    private static readonly SecurityIdentifier Me = WindowsIdentity.GetCurrent().User!;

    // An elevated administrator's new folders are owned by the Administrators group rather than the user.
    private static readonly SecurityIdentifier[] TrustMe = [Me, WellKnown.Administrators];

    [Fact]
    public void CreatesALockedDownFolder()
    {
        using var dir = new TempDirectory();
        var data = Path.Combine(dir.Path, "AiShield");
        SecureDataDirectory.Ensure(data, TrustMe);

        Assert.True(SecureDataDirectory.IsLockedDown(data, TrustMe));
        var rules = new DirectoryInfo(data).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));
        Assert.All(rules.Cast<FileSystemAccessRule>(), r => Assert.Contains((SecurityIdentifier)r.IdentityReference, TrustMe));
    }

    [Fact]
    public void ReplacesAJunctionWithoutTouchingItsTarget()
    {
        using var dir = new TempDirectory();
        var target = Path.Combine(dir.Path, "victim");
        Directory.CreateDirectory(target);
        File.WriteAllText(Path.Combine(target, "keep.txt"), "important");
        var data = Path.Combine(dir.Path, "AiShield");
        Directory.CreateSymbolicLink(data, target).Refresh();
        if (!new DirectoryInfo(data).Attributes.HasFlag(FileAttributes.ReparsePoint))
            Assert.Skip("Couldn't create a link here");

        SecureDataDirectory.Ensure(data, TrustMe);

        Assert.False(new DirectoryInfo(data).Attributes.HasFlag(FileAttributes.ReparsePoint));
        Assert.Equal("important", File.ReadAllText(Path.Combine(target, "keep.txt")));
        Assert.False(SecureDataDirectory.IsLockedDown(target, TrustMe));
    }

    [Fact]
    public void MovesAsideAFolderSomeoneElseOwns()
    {
        using var dir = new TempDirectory();
        var data = Path.Combine(dir.Path, "AiShield");
        Directory.CreateDirectory(data);
        File.WriteAllText(Path.Combine(data, "policy.db"), "planted");

        // Pretend only SYSTEM is trusted, so the folder this test created counts as planted by someone else.
        Assert.ThrowsAny<Exception>(() => SecureDataDirectory.Ensure(data, [WellKnown.LocalSystem]));
        var aside = Assert.Single(Directory.GetDirectories(dir.Path, "AiShield.untrusted-*"));
        Assert.True(File.Exists(Path.Combine(aside, "policy.db")));
        Assert.Matches("untrusted-[0-9a-f]{32}$", aside);
    }

    [Fact]
    public void NeverAdoptsATrustedFolderOrdinaryUsersCouldWriteInto()
    {
        using var dir = new TempDirectory();
        var data = Path.Combine(dir.Path, "AiShield");
        Directory.CreateDirectory(data);
        File.WriteAllText(Path.Combine(data, "planted.txt"), "x");
        var loose = new DirectoryInfo(data).GetAccessControl();
        loose.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.Modify,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(data).SetAccessControl(loose);

        SecureDataDirectory.Ensure(data, TrustMe);

        Assert.True(SecureDataDirectory.IsLockedDown(data, TrustMe));
        Assert.False(File.Exists(Path.Combine(data, "planted.txt")));
        var aside = Assert.Single(Directory.GetDirectories(dir.Path, "AiShield.untrusted-*"));
        Assert.True(File.Exists(Path.Combine(aside, "planted.txt")));
    }

    [Fact]
    public void KeepsAFolderThatIsAlreadyLockedDown()
    {
        using var dir = new TempDirectory();
        var data = Path.Combine(dir.Path, "AiShield");
        SecureDataDirectory.Ensure(data, TrustMe);
        File.WriteAllText(Path.Combine(data, "policy.db"), "ours");
        SecureDataDirectory.Ensure(data, TrustMe);
        Assert.Equal("ours", File.ReadAllText(Path.Combine(data, "policy.db")));
        Assert.Empty(Directory.GetDirectories(dir.Path, "AiShield.untrusted-*"));
    }

    [Fact]
    public void AUserWritableFolderIsNotAProtectedInstall()
    {
        using var dir = new TempDirectory();
        File.WriteAllText(Path.Combine(dir.Path, "AiShield.Dashboard.exe"), "");
        Assert.False(InstallLocation.IsProtected(dir.Path, out var problem));
        Assert.NotEmpty(problem);
    }

    [Fact]
    public void SystemFoldersAreProtected()
    {
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        Assert.True(InstallLocation.IsProtected(Path.Combine(system32, "drivers", "etc"), out var problem), problem);
    }

    [Fact]
    public void DisplayTextRemovesTricks()
    {
        Assert.Equal("a  b", DisplayText.Clean("a\r\nb"));
        Assert.Equal("evil exe.txt", DisplayText.Clean("evil‮exe.txt"));
        Assert.Equal("abc…", DisplayText.Clean("abcdef", 3));
        Assert.Equal("", DisplayText.Clean(null));
    }
}

public sealed class AuditCsvTests
{
    [Fact]
    public void FormulaCellsAreNeutralizedAndQuoted()
    {
        var csv = AuditCsv.Write(
        [
            new AuditEntryDto(2, "t2", "=HYPERLINK(\"http://evil.example\")", "file", "+1,2", "ask", "", "@SUM(A1)"),
            new AuditEntryDto(1, "t1", "Cursor", "network", "api.openai.com", "block", "block", "plain"),
        ]);
        var lines = csv.Split('\n');
        Assert.Equal("timestamp,app_name,resource_type,resource,action,decision,message", lines[0]);
        Assert.Equal("t1,Cursor,network,api.openai.com,block,block,plain", lines[1]);
        Assert.Equal("t2,\"'=HYPERLINK(\"\"http://evil.example\"\")\",file,\"'+1,2\",ask,,'@SUM(A1)", lines[2]);
    }
}
