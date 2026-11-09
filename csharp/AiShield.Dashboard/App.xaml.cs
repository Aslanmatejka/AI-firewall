using System.Threading;
using System.Windows;
using AiShield.Core.Ipc;
using AiShield.Dashboard.Services;
using AiShield.Dashboard.ViewModels;

namespace AiShield.Dashboard;

/// <summary>
/// One copy per signed-in session. The service starts it with --background, which keeps it in the tray;
/// started by hand, it opens its window, or brings the running copy's window forward.
/// </summary>
public partial class App : System.Windows.Application
{
    private const string InstanceName = @"Local\AiShield.Dashboard.Instance";
    private const string ShowSignalName = @"Local\AiShield.Dashboard.Show";

    private Mutex? _instance;
    private EventWaitHandle? _showSignal;
    private RegisteredWaitHandle? _showRegistration;
    private TrayIcon? _tray;
    private MainWindow? _window;
    private bool _exiting;

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

        var background = e.Args.Contains("--background");
        _instance = new Mutex(initiallyOwned: true, InstanceName, out var firstInstance);
        if (!firstInstance)
        {
            if (!background && EventWaitHandle.TryOpenExisting(ShowSignalName, out var show))
            {
                using (show)
                    show.Set();
            }
            Shutdown(HelperExitCodes.AnotherInstanceRunning);
            return;
        }

        _showSignal = new EventWaitHandle(false, EventResetMode.AutoReset, ShowSignalName);
        _showRegistration = ThreadPool.RegisterWaitForSingleObject(
            _showSignal, (_, _) => Dispatcher.BeginInvoke(ShowWindow), null, Timeout.Infinite, executeOnlyOnce: false);

        // In the background, closing the window hides it; only the tray's Exit closes the app.
        ShutdownMode = background ? ShutdownMode.OnExplicitShutdown : ShutdownMode.OnMainWindowClose;
        var window = new MainWindow();
        _window = window;
        MainWindow = window;
        window.StateChanged += (_, _) =>
        {
            if (window.WindowState == WindowState.Minimized)
                window.Hide();
        };
        if (background)
        {
            window.Closing += (_, args) =>
            {
                if (_exiting)
                    return;
                args.Cancel = true;
                window.Hide();
            };
        }

        _tray = new TrayIcon(window, ExitAsync);
        if (window.DataContext is MainViewModel vm)
            vm.NewPendingRequest += request => _tray.Notify(request);

        if (!background)
            window.Show();
    }

    private void ShowWindow()
    {
        if (_window is null)
            return;
        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    private async Task ExitAsync()
    {
        _exiting = true;
        if (_window?.DataContext is MainViewModel vm)
        {
            try
            {
                await vm.NotifyExitingAsync();
            }
            catch (Exception ex)
            {
                DashboardLog.Error("Telling the service the app is closing", ex);
            }
        }
        Shutdown(0);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _tray?.Dispose();
        _showRegistration?.Unregister(null);
        _showSignal?.Dispose();
        _instance?.Dispose();
        base.OnExit(e);
    }
}
