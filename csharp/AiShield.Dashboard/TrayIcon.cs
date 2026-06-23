using System.Drawing;
using System.Windows;
using System.Windows.Forms;
using AiShield.Dashboard.ViewModels;
using Application = System.Windows.Application;

namespace AiShield.Dashboard;

public sealed class TrayIcon : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly MainWindow _window;

    public TrayIcon(MainWindow window)
    {
        _window = window;
        _icon = new NotifyIcon
        {
            Text = "AI Firewall",
            Visible = true,
        };

        try
        {
            _icon.Icon = SystemIcons.Shield;
        }
        catch
        {
            _icon.Icon = SystemIcons.Application;
        }

        var menu = new ContextMenuStrip();
        menu.Items.Add("Open Dashboard", null, (_, _) => ShowWindow());
        menu.Items.Add("Refresh", null, async (_, _) =>
        {
            if (_window.DataContext is MainViewModel vm)
                await vm.RefreshAsync();
        });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, (_, _) =>
        {
            _icon.Visible = false;
            Application.Current.Shutdown();
        });
        _icon.ContextMenuStrip = menu;
        _icon.DoubleClick += (_, _) => ShowWindow();
    }

    private void ShowWindow()
    {
        _window.Show();
        _window.WindowState = WindowState.Normal;
        _window.Activate();
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
    }
}
