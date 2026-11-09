using System.Runtime.InteropServices;
using System.Security.Cryptography;
using AiShield.Core.Ipc;

namespace AiShield.Consent;

/// <summary>Stage one: make a desktop only SYSTEM can open, show stage two on it, and always switch back.</summary>
internal static unsafe partial class PrivateDesktop
{
    private const uint DesktopSwitchDesktop = 0x0100;
    private const uint GenericAll = 0x10000000;
    private const uint WaitTimeout = 0x00000102;
    private const uint SddlRevision1 = 1;
    private static readonly uint PromptTimeoutMs = (uint)TimeSpan.FromSeconds(120).TotalMilliseconds;

    public static int Run(string requestArgument)
    {
        // Fails while the PC is locked or another secure prompt is showing. Never show the question then.
        var original = OpenInputDesktop(0, false, DesktopSwitchDesktop);
        if (original == 0)
            return ConsentExitCodes.DesktopUnavailable;
        try
        {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(A;;GA;;;SY)", SddlRevision1, out var descriptor, out _))
                return ConsentExitCodes.Error;
            try
            {
                var name = "AiShieldConsent-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
                var attributes = new SecurityAttributes { Length = sizeof(SecurityAttributes), Descriptor = descriptor };
                var desktop = CreateDesktopW(name, null, null, 0, GenericAll, &attributes);
                if (desktop == 0)
                    return ConsentExitCodes.DesktopUnavailable;
                try
                {
                    return ShowOn(desktop, name, requestArgument, original);
                }
                finally
                {
                    CloseDesktop(desktop);
                }
            }
            finally
            {
                LocalFree(descriptor);
            }
        }
        finally
        {
            CloseDesktop(original);
        }
    }

    private static int ShowOn(nint desktop, string name, string requestArgument, nint original)
    {
        var exe = Environment.ProcessPath ?? throw new InvalidOperationException("No process path");
        var commandLine = $"\"{exe}\" --stage2 --desktop {name} --request {requestArgument}\0".ToCharArray();
        var application = (exe + "\0").ToCharArray();
        var desktopName = $"WinSta0\\{name}\0".ToCharArray();

        ProcessInformation info;
        fixed (char* app = application)
        fixed (char* cmd = commandLine)
        fixed (char* desk = desktopName)
        {
            var startup = new StartupInfo { Size = sizeof(StartupInfo), Desktop = (nint)desk };
            if (!CreateProcessW(app, cmd, null, null, false, 0, null, null, &startup, &info))
                return ConsentExitCodes.Error;
        }
        CloseHandle(info.Thread);

        try
        {
            if (!SwitchDesktop(desktop))
            {
                TerminateProcess(info.Process, ConsentExitCodes.Dismissed);
                return ConsentExitCodes.DesktopUnavailable;
            }
            try
            {
                if (WaitForSingleObject(info.Process, PromptTimeoutMs) == WaitTimeout)
                {
                    TerminateProcess(info.Process, ConsentExitCodes.Dismissed);
                    WaitForSingleObject(info.Process, 5000);
                    return ConsentExitCodes.Dismissed;
                }
                return GetExitCodeProcess(info.Process, out var code) && code is ConsentExitCodes.Approved or ConsentExitCodes.Denied or ConsentExitCodes.Dismissed
                    ? (int)code
                    : ConsentExitCodes.Error;
            }
            finally
            {
                SwitchDesktop(original);
            }
        }
        finally
        {
            CloseHandle(info.Process);
        }
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

    [LibraryImport("user32.dll", SetLastError = true)]
    private static partial nint OpenInputDesktop(uint flags, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint access);

    [LibraryImport("user32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CreateDesktopW(string name, string? device, void* mode, uint flags, uint access, SecurityAttributes* attributes);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SwitchDesktop(nint desktop);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseDesktop(nint desktop);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateProcessW(char* application, char* commandLine, void* processAttributes, void* threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags, void* environment, char* currentDirectory,
        StartupInfo* startup, ProcessInformation* info);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(nint handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetExitCodeProcess(nint process, out uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateProcess(nint process, int exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out nint descriptor, out uint size);

    [LibraryImport("kernel32.dll")]
    private static partial nint LocalFree(nint memory);
}
