using System.Runtime.InteropServices;

namespace AiShield.Core.Windows;

/// <summary>
/// Windows exploit mitigations for AI Firewall's SYSTEM processes. Each one closes a route by which code
/// could get into, or be started by, a process that runs with full control of the PC. Arbitrary Code
/// Guard isn't used: .NET compiles code at run time, which it forbids.
/// </summary>
public static unsafe partial class ProcessHardening
{
    private const int ProcessExtensionPointDisablePolicy = 6;
    private const int ProcessFontDisablePolicy = 9;
    private const int ProcessImageLoadPolicy = 10;
    private const int ProcessChildProcessPolicy = 13;
    private const uint LoadLibrarySearchDefaultDirs = 0x00001000;

    public sealed record Result(string Mitigation, bool Applied);

    /// <summary>Applies the mitigations every AI Firewall SYSTEM process can live with.</summary>
    public static IReadOnlyList<Result> Apply(bool allowChildProcesses)
    {
        var results = new List<Result>
        {
            // DLL searches stop looking in the current folder and on PATH, either of which a user may control.
            new("safe DLL search", SetDefaultDllDirectories(LoadLibrarySearchDefaultDirs)),
            // No DLLs from network shares, or from files marked low integrity such as downloads.
            new("no remote or low-integrity DLLs", Set(ProcessImageLoadPolicy, 0b11)),
            // No AppInit DLLs, global window hooks, legacy IMEs or Winsock add-ins: old injection routes.
            new("no legacy extension DLLs", Set(ProcessExtensionPointDisablePolicy, 0b1)),
            // Only fonts installed in Windows, so a crafted font file can't reach the font parser.
            new("system fonts only", Set(ProcessFontDisablePolicy, 0b1)),
        };
        if (!allowChildProcesses)
            results.Add(new("no child processes", Set(ProcessChildProcessPolicy, 0b1)));
        return results;
    }

    private static bool Set(int policy, uint flags) => SetProcessMitigationPolicy(policy, &flags, sizeof(uint));

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetProcessMitigationPolicy(int policy, void* buffer, nuint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetDefaultDllDirectories(uint directoryFlags);
}
