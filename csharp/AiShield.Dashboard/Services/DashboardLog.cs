using System.IO;

namespace AiShield.Dashboard.Services;

internal static class DashboardLog
{
    private const long MaxBytes = 1024 * 1024;
    private static readonly object Gate = new();
    private static readonly string LogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AiShield", "dashboard.log");

    public static void Error(string context, Exception? error)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
                var file = new FileInfo(LogPath);
                if (file.Exists && file.Length > MaxBytes)
                    File.Move(LogPath, LogPath + ".1", overwrite: true);
                File.AppendAllText(LogPath, $"{DateTime.Now:O} {context}: {error}{Environment.NewLine}");
            }
        }
        catch (Exception logFailure) when (logFailure is IOException or UnauthorizedAccessException)
        {
            // A full or locked disk must not turn a logged error into a crash.
        }
    }
}
