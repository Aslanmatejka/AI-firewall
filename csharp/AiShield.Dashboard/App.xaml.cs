using System.Windows;
using AiShield.Dashboard.Services;

namespace AiShield.Dashboard;

public partial class App : System.Windows.Application
{
    private TrayIcon? _tray;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += (_, args) =>
        {
            DashboardLog.Error("UI thread", args.Exception);
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            DashboardLog.Error("Background thread", args.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, args) =>
        {
            DashboardLog.Error("Background task", args.Exception);
            args.SetObserved();
        };

        ShutdownMode = ShutdownMode.OnMainWindowClose;
        var window = new MainWindow();
        MainWindow = window;
        window.StateChanged += (_, _) =>
        {
            if (window.WindowState == WindowState.Minimized)
                window.Hide();
        };
        _tray = new TrayIcon(window);
        window.Show();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        base.OnExit(e);
    }
}
