using System.Drawing;
using System.Windows;
using System.Windows.Forms;
using AiShield.Core.Ipc;
using AiShield.Core.Models;
using AiShield.Dashboard.Services;
using AiShield.Dashboard.ViewModels;

namespace AiShield.Dashboard;

public sealed class TrayIcon : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly MainWindow _window;

    public TrayIcon(MainWindow window, Func<Task> exit)
    {
        _window = window;
        _icon = new NotifyIcon
        {
            Text = "AI Firewall",
            Icon = SystemIcons.Shield,
            Visible = true,
        };

        var menu = new ContextMenuStrip();
        menu.Items.Add("Open AI Firewall", null, (_, _) => ShowWindow());
        menu.Items.Add("Refresh", null, async (_, _) =>
        {
            try
            {
                if (_window.DataContext is MainViewModel vm)
                    await vm.RefreshAsync();
            }
            catch (Exception ex)
            {
                DashboardLog.Error("Tray refresh", ex);
            }
        });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Exit", null, async (_, _) =>
        {
            _icon.Visible = false;
            try
            {
                await exit();
            }
            catch (Exception ex)
            {
                DashboardLog.Error("Exit", ex);
            }
        });
        _icon.ContextMenuStrip = menu;
        _icon.DoubleClick += (_, _) => ShowWindow();
        _icon.BalloonTipClicked += (_, _) => ShowWindow();
    }

    /// <summary>Tells the user something is waiting for their decision.</summary>
    public void Notify(AccessRequestDto request)
    {
        var app = DisplayText.Clean(request.AppName, 40);
        var target = DisplayText.Clean(request.ResourcePath, 60);
        _icon.ShowBalloonTip(
            8000, "AI Firewall needs your decision",
            $"{app} wants {request.ResourceType} access ({target}). Click to review.",
            ToolTipIcon.Warning);
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
