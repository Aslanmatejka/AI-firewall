using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace AiShield.TamperProbe;

/// <summary>Reruns the probe the way an AI app runs: as this user, without admin rights, at medium integrity.</summary>
internal static unsafe partial class BasicUser
{
    private const uint LuaToken = 0x4;
    private const uint DisableMaxPrivilege = 0x1;
    private const int TokenIntegrityLevel = 25;
    private const uint SeGroupIntegrity = 0x20;
    private const uint StartfUseStdHandles = 0x100;
    private const uint CreateNoWindow = 0x08000000;
    private const uint HandleFlagInherit = 0x1;
    private const uint Infinite = 0xFFFFFFFF;

    public static int Run(string[] childArgs)
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x0001 | 0x0002 | 0x0008 | 0x0080, out var self))
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "OpenProcessToken");
        using (self)
        {
            if (!CreateRestrictedToken(self, LuaToken | DisableMaxPrivilege, 0, null, 0, null, 0, null, out var limited))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "CreateRestrictedToken");
            using (limited)
            {
                SetMediumIntegrity(limited);
                return RunWithToken(limited, childArgs);
            }
        }
    }

    private static void SetMediumIntegrity(SafeAccessTokenHandle token)
    {
        var medium = new SecurityIdentifier("S-1-16-8192");
        var sid = new byte[medium.BinaryLength];
        medium.GetBinaryForm(sid, 0);
        fixed (byte* sidPtr = sid)
        {
            var label = new TokenMandatoryLabel { Sid = (nint)sidPtr, Attributes = SeGroupIntegrity };
            if (!SetTokenInformation(token, TokenIntegrityLevel, &label, (uint)(sizeof(TokenMandatoryLabel) + sid.Length)))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "SetTokenInformation(TokenIntegrityLevel)");
        }
    }

    private static int RunWithToken(SafeAccessTokenHandle token, string[] childArgs)
    {
        var inherit = new SecurityAttributes { Length = sizeof(SecurityAttributes), Inherit = 1 };
        if (!CreatePipe(out var read, out var write, &inherit, 0))
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "CreatePipe");
        SetHandleInformation(read, HandleFlagInherit, 0);

        var exe = Environment.ProcessPath!;
        var commandLine = ($"\"{exe}\" " + string.Join(' ', childArgs.Select(Quote)) + "\0").ToCharArray();
        var application = (exe + "\0").ToCharArray();
        ProcessInformation info;
        fixed (char* app = application)
        fixed (char* cmd = commandLine)
        {
            var startup = new StartupInfo
            {
                Size = sizeof(StartupInfo),
                Flags = StartfUseStdHandles,
                StdOutput = write,
                StdError = write,
            };
            var started = CreateProcessAsUserW(token, app, cmd, null, null, true, CreateNoWindow, null, null, &startup, &info);
            CloseHandle(write);
            if (!started)
            {
                CloseHandle(read);
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "CreateProcessAsUser");
            }
        }
        CloseHandle(info.Thread);

        using (var output = new FileStream(new SafeFileHandle(read, ownsHandle: true), FileAccess.Read))
        using (var reader = new StreamReader(output))
            Console.Write(reader.ReadToEnd());

        WaitForSingleObject(info.Process, Infinite);
        GetExitCodeProcess(info.Process, out var exitCode);
        CloseHandle(info.Process);
        return (int)exitCode;
    }

    private static string Quote(string arg)
        => arg.Length > 0 && !arg.Any(c => char.IsWhiteSpace(c) || c == '"') ? arg : "\"" + arg.Replace("\"", "\\\"", StringComparison.Ordinal) + "\"";

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenMandatoryLabel
    {
        public nint Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public nint Descriptor;
        public int Inherit;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public int Size;
        public nint Reserved;
        public nint Desktop;
        public nint Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute;
        public uint Flags;
        public short ShowWindow, Reserved2Size;
        public nint Reserved2, StdInput, StdOutput, StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint Process;
        public nint Thread;
        public int ProcessId;
        public int ThreadId;
    }

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint process, uint access, out SafeAccessTokenHandle token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateRestrictedToken(SafeAccessTokenHandle existing, uint flags, uint disableSidCount, void* sidsToDisable,
        uint deletePrivilegeCount, void* privilegesToDelete, uint restrictedSidCount, void* sidsToRestrict, out SafeAccessTokenHandle restricted);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetTokenInformation(SafeAccessTokenHandle token, int infoClass, void* info, uint length);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateProcessAsUserW(SafeAccessTokenHandle token, char* application, char* commandLine,
        void* processAttributes, void* threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags,
        void* environment, char* currentDirectory, StartupInfo* startup, ProcessInformation* info);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreatePipe(out nint read, out nint write, SecurityAttributes* attributes, uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetHandleInformation(nint handle, uint mask, uint flags);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(nint handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetExitCodeProcess(nint process, out uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
}

internal static unsafe partial class Native
{
    private const int TokenIntegrityLevel = 25;

    /// <summary>Throws access denied if Windows refuses those rights on the service.</summary>
    public static void OpenServiceWithRights(string name, uint rights)
    {
        var manager = OpenSCManagerW(null, null, 0x0001);
        if (manager == 0)
            throw new Win32Exception(Marshal.GetLastPInvokeError());
        try
        {
            var service = OpenServiceW(manager, name, rights);
            if (service == 0)
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            CloseServiceHandle(service);
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    public static void OpenProcessWithRights(int pid, uint rights)
    {
        var error = TryOpenProcess(pid, rights);
        if (error is not null)
            throw new Win32Exception(error.Value);
    }

    /// <summary>Returns null if the process opened with those rights, otherwise the Windows error.</summary>
    public static int? TryOpenProcess(int pid, uint rights)
    {
        var handle = OpenProcess(rights, false, (uint)pid);
        if (handle == 0)
            return Marshal.GetLastPInvokeError();
        CloseHandle(handle);
        return null;
    }

    /// <summary>Returns null if the desktop opened with those rights, otherwise the Windows error.</summary>
    public static int? TryOpenDesktop(string name, uint rights)
    {
        var desktop = OpenDesktopW(name, 0, false, rights);
        if (desktop == 0)
            return Marshal.GetLastPInvokeError();
        CloseDesktop(desktop);
        return null;
    }

    public static int IntegrityRid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        GetTokenInformation(identity.AccessToken, TokenIntegrityLevel, null, 0, out var needed);
        var buffer = new byte[needed];
        fixed (byte* raw = buffer)
        {
            if (!GetTokenInformation(identity.AccessToken, TokenIntegrityLevel, raw, needed, out _))
                return -1;
            var sid = new SecurityIdentifier(*(nint*)raw);
            var parts = sid.Value.Split('-');
            return int.Parse(parts[^1], System.Globalization.CultureInfo.InvariantCulture);
        }
    }

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenSCManagerW(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenServiceW(nint manager, string name, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(nint handle);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint pid);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    [LibraryImport("user32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenDesktopW(string name, uint flags, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseDesktop(nint desktop);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, void* info, uint length, out uint returnLength);
}
