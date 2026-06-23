using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using AiShield.Dashboard.Services;
using AiShield.Dashboard.ViewModels;
using WinForms = System.Windows.Forms;

namespace AiShield.Dashboard;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        DataContextChanged += (_, _) =>
        {
            if (DataContext is MainViewModel vm)
                vm.PropertyChanged += (_, args) =>
                {
                    if (args.PropertyName == nameof(MainViewModel.SelectedPage))
                        AnimatePageIn();
                };
        };
        Closed += (_, _) => (DataContext as MainViewModel)?.Dispose();
    }

    private void AnimatePageIn()
    {
        if (PageContent == null) return;
        var fade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut },
        };
        var slide = new ThicknessAnimation(
            new Thickness(0, 10, 0, 0), new Thickness(0), TimeSpan.FromMilliseconds(220))
        {
            EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut },
        };
        PageContent.BeginAnimation(OpacityProperty, fade);
        PageContent.BeginAnimation(MarginProperty, slide);
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is MainViewModel vm)
            await vm.RefreshAsync();
    }

    private void Module_Click(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement el && el.Tag is string tag
            && int.TryParse(tag, out var page) && DataContext is MainViewModel vm)
            vm.SelectedPage = page;
    }

    private async void FolderPolicy_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (sender is not System.Windows.Controls.ComboBox combo || combo.Tag is not string folderName) return;
        if (combo.SelectedItem is not System.Windows.Controls.ComboBoxItem item) return;
        var policy = item.Content?.ToString() ?? "ask";
        if (DataContext is MainViewModel vm)
            await vm.SetFolderPolicyAsync(folderName, policy);
    }

    private async void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new WinForms.FolderBrowserDialog
        {
            Description = "Select a folder to protect from AI access",
            UseDescriptionForTitle = true,
        };
        if (dialog.ShowDialog() != WinForms.DialogResult.OK) return;

        var path = dialog.SelectedPath;
        var name = System.IO.Path.GetFileName(path);
        if (string.IsNullOrEmpty(name)) name = "Custom";

        if (DataContext is MainViewModel vm)
            await vm.AddFolderAsync(name, path);
    }

    private void AppPolicyCombo_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.ComboBox combo || combo.DataContext is not AppPolicyDto dto) return;
        var resource = combo.Tag as string ?? "default";
        var current = resource switch
        {
            "default" => dto.DefaultAction,
            "files" => dto.Files,
            "network" => dto.Network,
            "clipboard" => dto.Clipboard,
            "microphone" => dto.Microphone,
            "camera" => dto.Camera,
            _ => "ask",
        };
        foreach (System.Windows.Controls.ComboBoxItem item in combo.Items)
        {
            if (item.Content?.ToString() == current)
            {
                combo.SelectedItem = item;
                break;
            }
        }
    }

    private async void AppPolicy_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (sender is not System.Windows.Controls.ComboBox combo || combo.DataContext is not AppPolicyDto dto) return;
        if (combo.SelectedItem is not System.Windows.Controls.ComboBoxItem item) return;
        if (e.AddedItems.Count == 0) return;
        var policy = item.Content?.ToString() ?? "ask";
        var resource = combo.Tag as string ?? "default";
        if (DataContext is MainViewModel vm)
            await vm.SetAppResourcePolicyAsync(dto.AppName, resource, policy);
    }
}
