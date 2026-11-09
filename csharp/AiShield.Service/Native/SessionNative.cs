using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AiShield.Service.Native;

/// <summary>A process this service started, which it can wait on even across sessions.</summary>
internal sealed partial class LaunchedProcess : IDisposable
{
    private const uint WaitObject0 = 0;
    private const uint StillActive = 259;

    private readonly SafeProcessHandle _handle;

    public LaunchedProcess(SafeProcessHandle handle, int id)
    {
        _handle = handle;
        Id = id;
    }

    public int Id { get; }

    public bool HasExited => WaitForSingleObject(_handle, 0) == WaitObject0;

    public int? ExitCode => GetExitCodeProcess(_handle, out var code) && code != StillActive ? (int)code : null;

    /// <summary>Returns the exit code, or null if the process is still running when the timeout ends.</summary>
    public async Task<int?> WaitForExitAsync(TimeSpan timeout, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow + timeout;
        while (!HasExited)
        {
            if (DateTimeOffset.UtcNow >= deadline)
                return null;
            await Task.Delay(TimeSpan.FromMilliseconds(250), ct).ConfigureAwait(false);
        }
        return ExitCode;
    }

    public void Kill(int exitCode = 1) => TerminateProcess(_handle, (uint)exitCode);

    public void Dispose() => _handle.Dispose();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateProcess(SafeProcessHandle process, uint exitCode);
}

/// <summary>Starts programs in a user's desktop session, which a service in session 0 can't do directly.</summary>
internal static unsafe partial class SessionNative
{
    private const int WtsActive = 0;
    private const int WtsUserName = 5;
    private const uint MaximumAllowed = 0x02000000;
    private const int SecurityIdentification = 1;
    private const int TokenPrimary = 1;
    private const int TokenSessionId = 12;
    private const uint DisableMaxPrivilege = 0x1;
    private const uint CreateUnicodeEnvironment = 0x00000400;
    private const uint SePrivilegeEnabled = 0x00000002;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const uint TokenDuplicate = 0x0002;
    private const uint TokenAssignPrimary = 0x0001;
    private const uint TokenAdjustDefault = 0x0080;
    private const uint TokenAdjustSessionId = 0x0100;

    /// <summary>Sessions where someone is signed in and at the keyboard or connected remotely.</summary>
    public static IReadOnlyList<int> ActiveUserSessions()
    {
        if (!WTSEnumerateSessionsW(0, 0, 1, out var buffer, out var count))
            return [];
        try
        {
            var sessions = new List<int>();
            for (var i = 0; i < count; i++)
            {
                var info = (WtsSessionInfo*)(buffer + i * sizeof(WtsSessionInfo));
                if (info->State == WtsActive && info->SessionId != 0 && !string.IsNullOrEmpty(UserName(info->SessionId)))
                    sessions.Add(info->SessionId);
            }
            return sessions;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    public static string? UserName(int sessionId)
    {
        if (!WTSQuerySessionInformationW(0, sessionId, WtsUserName, out var buffer, out _))
            return null;
        try
        {
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    /// <summary>Starts a program as the signed-in user of a session, with that user's environment.</summary>
    public static LaunchedProcess StartAsUser(int sessionId, string exe, string arguments)
    {
        if (!WTSQueryUserToken(sessionId, out var userToken))
            throw new Win32Exception(Marshal.GetLastPInvokeError(), $"WTSQueryUserToken({sessionId})");
        using (userToken)
        {
            if (!DuplicateTokenEx(userToken, MaximumAllowed, null, SecurityIdentification, TokenPrimary, out var primary))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "DuplicateTokenEx");
            using (primary)
            {
                if (!CreateEnvironmentBlock(out var environment, primary, false))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "CreateEnvironmentBlock");
                try
                {
                    return Create(primary, exe, arguments, environment);
                }
                finally
                {
                    DestroyEnvironmentBlock(environment);
                }
            }
        }
    }

    /// <summary>
    /// Starts a program as SYSTEM, stripped of privileges, on a user's desktop. Programs running as
    /// that user can't open it, inject into it or send it input.
    /// </summary>
    public static LaunchedProcess StartAsSystemInSession(int sessionId, string exe, string arguments)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenDuplicate | TokenQuery | TokenAssignPrimary | TokenAdjustDefault | TokenAdjustSessionId, out var self))
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "OpenProcessToken");
        using (self)
        {
            if (!CreateRestrictedToken(self, DisableMaxPrivilege, 0, null, 0, null, 0, null, out var restricted))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "CreateRestrictedToken");
            using (restricted)
            {
                var session = (uint)sessionId;
                if (!SetTokenInformation(restricted, TokenSessionId, &session, sizeof(uint)))
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "SetTokenInformation(TokenSessionId)");
                return Create(restricted, exe, arguments, 0);
            }
        }
    }

    /// <summary>LocalSystem holds these privileges but may not have them switched on.</summary>
    public static void EnablePrivileges(params string[] names)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            return;
        using (token)
        {
            foreach (var name in names)
            {
                if (!LookupPrivilegeValueW(null, name, out var luid))
                    continue;
                var privileges = new TokenPrivileges { Count = 1, Luid = luid, Attributes = SePrivilegeEnabled };
                AdjustTokenPrivileges(token, false, &privileges, 0, null, null);
            }
        }
    }

    private static LaunchedProcess Create(SafeAccessTokenHandle token, string exe, string arguments, nint environment)
    {
        var commandLine = $"\"{exe}\" {arguments}\0".ToCharArray();
        var application = (exe + "\0").ToCharArray();
        var desktop = "winsta0\\default\0".ToCharArray();
        var directory = ((Path.GetDirectoryName(exe) ?? "") + "\0").ToCharArray();
        fixed (char* cmd = commandLine)
        fixed (char* app = application)
        fixed (char* desk = desktop)
        fixed (char* cwd = directory)
        {
            var startup = new StartupInfo { Size = sizeof(StartupInfo), Desktop = (nint)desk };
            if (!CreateProcessAsUserW(token, app, cmd, null, null, false, CreateUnicodeEnvironment, (void*)environment, cwd, &startup, out var info))
                throw new Win32Exception(Marshal.GetLastPInvokeError(), $"CreateProcessAsUser({Path.GetFileName(exe)})");
            CloseHandle(info.Thread);
            return new LaunchedProcess(new SafeProcessHandle(info.Process, ownsHandle: true), info.ProcessId);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public nint WinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public int Size;
        public nint Reserved;
        public nint Desktop;
        public nint Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
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

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint Low;
        public int High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint Count;
        public Luid Luid;
        public uint Attributes;
    }

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSEnumerateSessionsW(nint server, int reserved, int version, out nint sessions, out int count);

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSQuerySessionInformationW(nint server, int sessionId, int infoClass, out nint buffer, out int bytes);

    [LibraryImport("wtsapi32.dll")]
    private static partial void WTSFreeMemory(nint memory);

    [LibraryImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSQueryUserToken(int sessionId, out SafeAccessTokenHandle token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DuplicateTokenEx(SafeAccessTokenHandle existing, uint access, void* attributes, int impersonationLevel, int tokenType, out SafeAccessTokenHandle duplicate);

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

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool LookupPrivilegeValueW(string? system, string name, out Luid luid);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AdjustTokenPrivileges(SafeAccessTokenHandle token, [MarshalAs(UnmanagedType.Bool)] bool disableAll,
        TokenPrivileges* newState, uint bufferLength, void* previousState, uint* returnLength);

    [LibraryImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateEnvironmentBlock(out nint environment, SafeAccessTokenHandle token, [MarshalAs(UnmanagedType.Bool)] bool inherit);

    [LibraryImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyEnvironmentBlock(nint environment);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateProcessAsUserW(SafeAccessTokenHandle token, char* application, char* commandLine,
        void* processAttributes, void* threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags,
        void* environment, char* currentDirectory, StartupInfo* startup, out ProcessInformation info);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
}
