using System.Windows;
using AiShield.Dashboard.ViewModels;

namespace AiShield.Dashboard;

public partial class App : System.Windows.Application
{
    private TrayIcon? _tray;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode = ShutdownMode.OnMainWindowClose;
        MainWindow!.StateChanged += (_, _) =>
        {
            if (MainWindow.WindowState == WindowState.Minimized)
                MainWindow.Hide();
        };
        _tray = new TrayIcon((MainWindow)MainWindow);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        base.OnExit(e);
    }
}
