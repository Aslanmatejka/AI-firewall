using System.Runtime.InteropServices;

namespace AiShield.Service.Native;

internal static unsafe partial class ServiceSelfConfig
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint ServiceConfigFailureActionsFlag = 4;

    /// <summary>Makes Windows apply the restart actions when the service exits with an error code.</summary>
    public static bool RestartOnErrorExit(string serviceName)
    {
        var manager = OpenSCManagerW(null, null, ScManagerConnect);
        if (manager == 0)
            return false;
        try
        {
            var service = OpenServiceW(manager, serviceName, ServiceChangeConfig);
            if (service == 0)
                return false;
            try
            {
                var onNonCrashFailures = 1;
                return ChangeServiceConfig2W(service, ServiceConfigFailureActionsFlag, &onNonCrashFailures);
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

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenSCManagerW(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint OpenServiceW(nint manager, string name, uint access);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ChangeServiceConfig2W(nint service, uint infoLevel, void* info);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(nint handle);
}
