#if AISHIELD_TEST_HOOKS
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using AiShield.Core.Ipc;

namespace AiShield.Consent;

/// <summary>
/// CiTesting builds only: lets CI answer the prompt, since nothing outside SYSTEM can click it.
/// The answer file lives in the service's data folder, which only SYSTEM and administrators can write.
/// Release builds don't contain this class, and CI checks that.
/// </summary>
internal static class TestHooks
{
    private static string Folder => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AiShield", "test");

    public static void Attach(ConsentWindow window, string desktopName)
    {
        Directory.CreateDirectory(Folder);
        File.WriteAllText(Path.Combine(Folder, "consent-shown.txt"),
            string.Create(CultureInfo.InvariantCulture, $"{desktopName}\n{Environment.ProcessId}\n{DateTimeOffset.UtcNow:O}\n"));

        // Nothing else can capture this desktop, so the prompt photographs itself for the CI report.
        var snapshot = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(800) };
        snapshot.Tick += (_, _) =>
        {
            snapshot.Stop();
            SaveImage(window, Path.Combine(Folder, "consent.png"));
        };
        snapshot.Start();

        var answerFile = Path.Combine(Folder, "consent-decision.txt");
        if (!File.Exists(answerFile))
            return;

        // Format: "allow", "deny" or "dismiss", then optionally how many seconds to keep the prompt up.
        var parts = File.ReadAllText(answerFile).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var result = parts.FirstOrDefault() switch
        {
            "allow" => ConsentExitCodes.Approved,
            "deny" => ConsentExitCodes.Denied,
            _ => ConsentExitCodes.Dismissed,
        };
        var delay = parts.Length > 1 && int.TryParse(parts[1], CultureInfo.InvariantCulture, out var seconds) ? seconds : 3;
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(Math.Max(delay, 3)) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            window.Finish(result);
        };
        timer.Start();
    }

    private static void SaveImage(Window window, string path)
    {
        if (window.Content is not FrameworkElement content || content.ActualWidth < 1)
            return;
        var bitmap = new RenderTargetBitmap((int)window.ActualWidth, (int)window.ActualHeight, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(window);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var file = File.Create(path);
        encoder.Save(file);
    }
}
#endif
