using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace AiShield.Core.Windows;

/// <summary>Facts about other processes, as reported by Windows rather than by the process itself.</summary>
public static unsafe partial class NativeProcess
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const int ProcessCommandLineInformation = 60;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const uint Th32CsSnapProcess = 0x2;

    public sealed record SnapshotEntry(int Pid, int ParentPid, string ExeName);

    public static int? GetPipeServerProcessId(SafeHandle pipe)
        => GetNamedPipeServerProcessId(pipe, out var pid) ? (int)pid : null;

    public static int? GetPipeClientProcessId(SafeHandle pipe)
        => GetNamedPipeClientProcessId(pipe, out var pid) ? (int)pid : null;

    public static int? GetPipeClientSessionId(SafeHandle pipe)
        => GetNamedPipeClientSessionId(pipe, out var session) ? (int)session : null;

    public static int? GetSessionId(int pid)
        => ProcessIdToSessionId((uint)pid, out var session) ? (int)session : null;

    public static string? TryGetImagePath(int pid)
    {
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (process.IsInvalid)
            return null;

        var buffer = new char[1024];
        var size = (uint)buffer.Length;
        fixed (char* chars = buffer)
        {
            if (!QueryFullProcessImageNameW(process, 0, chars, ref size))
                return null;
        }
        return new string(buffer, 0, (int)size);
    }

    /// <summary>Reads another process's command line. Works for most processes when running as SYSTEM.</summary>
    public static string? TryGetCommandLine(int pid)
    {
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, (uint)pid);
        if (process.IsInvalid)
            return null;

        var length = 512u;
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var buffer = new byte[length];
            fixed (byte* raw = buffer)
            {
                var status = NtQueryInformationProcess(process, ProcessCommandLineInformation, raw, length, out var needed);
                if (status == StatusInfoLengthMismatch)
                {
                    length = Math.Max(needed, length * 2);
                    continue;
                }
                if (status != 0)
                    return null;

                var text = (UnicodeString*)raw;
                return text->Buffer == 0 ? "" : new string((char*)text->Buffer, 0, text->Length / 2);
            }
        }
        return null;
    }

    /// <summary>Every running process with its parent, from a single consistent snapshot.</summary>
    public static IReadOnlyList<SnapshotEntry> Snapshot()
    {
        var entries = new List<SnapshotEntry>();
        using var snapshot = CreateToolhelp32Snapshot(Th32CsSnapProcess, 0);
        if (snapshot.IsInvalid)
            return entries;

        var entry = new ProcessEntry32 { Size = (uint)sizeof(ProcessEntry32) };
        if (!Process32FirstW(snapshot, ref entry))
            return entries;
        do
        {
            var name = new string(entry.ExeFile);
            entries.Add(new SnapshotEntry((int)entry.ProcessId, (int)entry.ParentProcessId, name));
        }
        while (Process32NextW(snapshot, ref entry));
        return entries;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString
    {
        public ushort Length;
        public ushort MaximumLength;
        public nint Buffer;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ProcessEntry32
    {
        public uint Size;
        public uint Usage;
        public uint ProcessId;
        public nuint DefaultHeapId;
        public uint ModuleId;
        public uint Threads;
        public uint ParentProcessId;
        public int PriorityClassBase;
        public uint Flags;
        public fixed char ExeFile[260];
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafeHandle pipe, out uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafeHandle pipe, out uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientSessionId(SafeHandle pipe, out uint sessionId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ProcessIdToSessionId(uint processId, out uint sessionId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inheritHandle, uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryFullProcessImageNameW(SafeProcessHandle process, uint flags, char* buffer, ref uint size);

    [LibraryImport("ntdll.dll")]
    private static partial int NtQueryInformationProcess(SafeProcessHandle process, int infoClass, void* info, uint length, out uint returnLength);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeFileHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Process32FirstW(SafeFileHandle snapshot, ref ProcessEntry32 entry);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Process32NextW(SafeFileHandle snapshot, ref ProcessEntry32 entry);
}

/// <summary>Asks the Service Control Manager, which ordinary programs can't fool, about a service.</summary>
public static unsafe partial class ServiceQuery
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;
    private const uint ServiceRunning = 0x4;

    /// <summary>The service's process ID while it's running, otherwise null.</summary>
    public static int? GetProcessId(string serviceName)
    {
        var manager = OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == 0)
            return null;
        try
        {
            var service = OpenServiceW(manager, serviceName, ServiceQueryStatus);
            if (service == 0)
                return null;
            try
            {
                ServiceStatusProcess status;
                if (!QueryServiceStatusEx(service, ScStatusProcessInfo, &status, (uint)sizeof(ServiceStatusProcess), out _))
                    return null;
                return status.CurrentState == ServiceRunning && status.ProcessId != 0 ? (int)status.ProcessId : null;
            }
            finally
            {
                CloseServiceHandle(service);
            }
        }
        finally
        {
            CloseServiceHandle(manager);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenSCManagerW(string? machineName, string? databaseName, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenServiceW(nint manager, string serviceName, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryServiceStatusEx(nint service, int infoLevel, void* buffer, uint size, out uint needed);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(nint handle);
}
