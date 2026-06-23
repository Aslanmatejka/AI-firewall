using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Windows.Input;
using System.Windows.Threading;
using AiShield.Dashboard.Services;

namespace AiShield.Dashboard.ViewModels;

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly ShieldApiClient _api;
    private readonly DispatcherTimer _timer;
    private int _selectedPage;
    private bool _isConnected;
    private bool _isLoading = true;
    private bool _isRefreshing;
    private string _connectionStatus = "Connecting...";
    private string _lastUpdated = "—";
    private string _statusMessage = "";
    private string _networkPolicy = "ask";
    private string _clipboardPolicy = "ask";
    private string _screenshotPolicy = "ask";
    private string _microphonePolicy = "ask";
    private string _cameraPolicy = "ask";
    private int _aiCount, _netCount, _blockedCount, _folderCount, _pendingCount;
    private int _refreshRunning;
    private DateTime _lastFullRefresh = DateTime.MinValue;

    public MainViewModel()
    {
        _api = new ShieldApiClient();
        AiProcesses = new ObservableCollection<AiProcessDto>();
        NetworkConnections = new ObservableCollection<NetworkConnDto>();
        Events = new ObservableCollection<EventDto>();
        ProtectedFolders = new ObservableCollection<ProtectedFolderDto>();
        PendingRequests = new ObservableCollection<AccessRequestDto>();
        AuditLog = new ObservableCollection<AuditEntryDto>();
        Extensions = new ObservableCollection<ExtensionDto>();
        ModelFiles = new ObservableCollection<ModelFileDto>();
        AppPolicies = new ObservableCollection<AppPolicyDto>();
        PolicyOptions = new ObservableCollection<string> { "allow", "ask", "block" };

        NavigateCommand = new RelayCommand<int>(page => SelectedPage = page);
        RefreshCommand = new RelayCommand(_ => _ = RefreshAsync());
        ApproveCommand = new RelayCommand<string>(id => _ = RunAction(() => _api.ApproveRequestAsync(id!, true), "Access allowed"));
        DenyCommand = new RelayCommand<string>(id => _ = RunAction(() => _api.ApproveRequestAsync(id!, false), "Access denied"));

        TerminateProcessCommand = new RelayCommand<int>(pid => _ = RunAction(() => _api.TerminateProcessAsync(pid), $"Process {pid} terminated"));
        BlockAppCommand = new RelayCommand<string>(name => _ = RunAction(() => _api.BlockAppAsync(name!), $"Blocked {name}"));
        AllowAppCommand = new RelayCommand<string>(name => _ = RunAction(() => _api.AllowAppAsync(name!), $"Allowed {name}"));
        AskAppCommand = new RelayCommand<string>(name => _ = RunAction(() => _api.AskAppAsync(name!), $"Ask mode set for {name}"));
        BlockConnectionCommand = new RelayCommand<int>(pid => _ = RunAction(() => _api.BlockConnectionAsync(pid), "Connection blocked"));
        BlockDomainCommand = new RelayCommand<string>(d => _ = RunAction(() => _api.BlockDomainAsync(d!), $"Blocked {d}"));
        UnblockDomainCommand = new RelayCommand<string>(d => _ = RunAction(() => _api.UnblockDomainAsync(d!), $"Unblocked {d}"));
        BlockAllAiCommand = new RelayCommand(_ => _ = RunAction(() => _api.BlockAllAiAsync(), "All AI domains blocked"));
        ScanExtensionsCommand = new RelayCommand(_ => _ = RunAction(async () =>
        {
            var r = await _api.ScanExtensionsAsync();
            if (r.Ok) await LoadPageDataAsync();
            return r;
        }, "Extension scan complete"));
        BlockWebsitesCommand = new RelayCommand(_ => _ = RunAction(() => _api.BlockWebsitesAsync(), "AI websites blocked in hosts file"));
        ScanModelsCommand = new RelayCommand(_ => _ = RunAction(async () =>
        {
            var r = await _api.ScanModelsAsync();
            if (r.Ok) await LoadPageDataAsync();
            return r;
        }, "Model scan complete"));
        SetGlobalNetworkPolicyCommand = new RelayCommand<string>(p => _ = RunAction(() => _api.SetGlobalPolicyAsync("network_policy", p!), $"Network policy: {p}"));
        SetGlobalClipboardPolicyCommand = new RelayCommand<string>(p => _ = RunAction(() => _api.SetGlobalPolicyAsync("clipboard_policy", p!), $"Clipboard policy: {p}"));
        SetGlobalScreenshotPolicyCommand = new RelayCommand<string>(p => _ = RunAction(() => _api.SetGlobalPolicyAsync("screenshot_policy", p!), $"Screenshot policy: {p}"));
        SetGlobalMicrophonePolicyCommand = new RelayCommand<string>(p => _ = RunAction(() => _api.SetGlobalPolicyAsync("microphone_policy", p!), $"Microphone policy: {p}"));
        SetGlobalCameraPolicyCommand = new RelayCommand<string>(p => _ = RunAction(() => _api.SetGlobalPolicyAsync("camera_policy", p!), $"Camera policy: {p}"));
        LockdownCommand = new RelayCommand(_ => _ = RunAction(() => _api.LockdownAsync(), "Lockdown enabled"));
        RestoreDefaultsCommand = new RelayCommand(_ => _ = RunAction(() => _api.RestoreDefaultsAsync(), "Defaults restored"));
        TerminateAllAiCommand = new RelayCommand(_ => _ = RunAction(() => _api.TerminateAllAiAsync(), "All AI processes stopped"));
        RemoveFolderCommand = new RelayCommand<string>(name => _ = RunAction(() => _api.RemoveFolderAsync(name!), $"Removed {name}"));
        RemoveAppPolicyCommand = new RelayCommand<string>(name => _ = RunAction(() => _api.RemoveAppPolicyAsync(name!), $"Removed rules for {name}"));
        ExportAuditCommand = new RelayCommand(_ =>
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(_api.GetAuditExportUrl()) { UseShellExecute = true });
            StatusMessage = "Opening audit export…";
        });

        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(8) };
        _timer.Tick += async (_, _) =>
        {
            if (Interlocked.CompareExchange(ref _refreshRunning, 0, 0) != 0) return;
            var online = await _api.IsOnlineAsync();
            IsConnected = online;
            ConnectionStatus = online ? "Firewall Active" : "Service Offline";
            if (online && (DateTime.UtcNow - _lastFullRefresh).TotalSeconds >= 20)
                await RefreshAsync(silent: true);
        };
        _timer.Start();
        _ = RefreshAsync();
    }

    public ObservableCollection<string> PolicyOptions { get; }

    public ICommand NavigateCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand ApproveCommand { get; }
    public ICommand DenyCommand { get; }
    public ICommand TerminateProcessCommand { get; }
    public ICommand BlockAppCommand { get; }
    public ICommand AllowAppCommand { get; }
    public ICommand BlockConnectionCommand { get; }
    public ICommand BlockDomainCommand { get; }
    public ICommand UnblockDomainCommand { get; }
    public ICommand BlockAllAiCommand { get; }
    public ICommand ScanExtensionsCommand { get; }
    public ICommand BlockWebsitesCommand { get; }
    public ICommand ScanModelsCommand { get; }
    public ICommand SetGlobalNetworkPolicyCommand { get; }
    public ICommand SetGlobalClipboardPolicyCommand { get; }
    public ICommand SetGlobalScreenshotPolicyCommand { get; }
    public ICommand SetGlobalMicrophonePolicyCommand { get; }
    public ICommand SetGlobalCameraPolicyCommand { get; }
    public ICommand AskAppCommand { get; }
    public ICommand LockdownCommand { get; }
    public ICommand RestoreDefaultsCommand { get; }
    public ICommand TerminateAllAiCommand { get; }
    public ICommand RemoveFolderCommand { get; }
    public ICommand RemoveAppPolicyCommand { get; }
    public ICommand ExportAuditCommand { get; }

    public ObservableCollection<AiProcessDto> AiProcesses { get; }
    public ObservableCollection<NetworkConnDto> NetworkConnections { get; }
    public ObservableCollection<EventDto> Events { get; }
    public ObservableCollection<ProtectedFolderDto> ProtectedFolders { get; }
    public ObservableCollection<AccessRequestDto> PendingRequests { get; }
    public ObservableCollection<AuditEntryDto> AuditLog { get; }
    public ObservableCollection<ExtensionDto> Extensions { get; }
    public ObservableCollection<ModelFileDto> ModelFiles { get; }
    public ObservableCollection<AppPolicyDto> AppPolicies { get; }

    public string StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasStatusMessage)); }
    }

    public bool HasStatusMessage => !string.IsNullOrEmpty(StatusMessage);

    public string NetworkPolicy
    {
        get => _networkPolicy;
        set { _networkPolicy = value; OnPropertyChanged(); }
    }

    public string ClipboardPolicy
    {
        get => _clipboardPolicy;
        set { _clipboardPolicy = value; OnPropertyChanged(); }
    }

    public string ScreenshotPolicy
    {
        get => _screenshotPolicy;
        set { _screenshotPolicy = value; OnPropertyChanged(); }
    }

    public string MicrophonePolicy
    {
        get => _microphonePolicy;
        set { _microphonePolicy = value; OnPropertyChanged(); }
    }

    public string CameraPolicy
    {
        get => _cameraPolicy;
        set { _cameraPolicy = value; OnPropertyChanged(); }
    }

    public int SelectedPage
    {
        get => _selectedPage;
        set
        {
            if (_selectedPage == value) return;
            _selectedPage = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(PageTitle));
            OnPropertyChanged(nameof(PageSubtitle));
            _ = LoadPageDataAsync();
        }
    }

    public string PageTitle => SelectedPage switch
    {
        0 => "Welcome to AI Firewall",
        1 => "Dashboard",
        2 => "Documentation",
        3 => "AI Processes",
        4 => "Network Firewall",
        5 => "Protected Files",
        6 => "Activity Log",
        7 => "Settings",
        _ => "AI Firewall",
    };

    public string PageSubtitle => SelectedPage switch
    {
        0 => "Overview, live stats, and getting started",
        1 => "Click any stat card to drill down — quick actions below",
        2 => "Guides, policies, and how to use AI Firewall",
        3 => "Block, allow, or stop detected AI applications",
        4 => "Monitor and block connections to AI services",
        5 => "Set allow, ask, or block for each protected folder",
        6 => "Full audit trail of access decisions",
        7 => "Global policies and system-wide actions",
        _ => "",
    };

    public bool IsConnected { get => _isConnected; set { _isConnected = value; OnPropertyChanged(); OnPropertyChanged(nameof(ShieldHealthPercent)); } }
    public bool IsLoading { get => _isLoading; set { _isLoading = value; OnPropertyChanged(); } }
    public bool IsRefreshing { get => _isRefreshing; set { _isRefreshing = value; OnPropertyChanged(); } }
    public string ConnectionStatus { get => _connectionStatus; set { _connectionStatus = value; OnPropertyChanged(); } }
    public string LastUpdated { get => _lastUpdated; set { _lastUpdated = value; OnPropertyChanged(); } }
    public int AiCount { get => _aiCount; set { _aiCount = value; OnPropertyChanged(); OnPropertyChanged(nameof(ShieldHealthPercent)); } }
    public int NetCount { get => _netCount; set { _netCount = value; OnPropertyChanged(); } }
    public int BlockedCount { get => _blockedCount; set { _blockedCount = value; OnPropertyChanged(); } }
    public int FolderCount { get => _folderCount; set { _folderCount = value; OnPropertyChanged(); } }
    public int PendingCount { get => _pendingCount; set { _pendingCount = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasPending)); } }
    public bool HasPending => PendingCount > 0;
    public int ShieldHealthPercent => IsConnected ? Math.Clamp(100 - AiCount * 8 - NetCount * 5 - PendingCount * 15, 25, 100) : 0;

    public async Task SetFolderPolicyAsync(string folderName, string policy)
        => await RunAction(() => _api.SetFolderPolicyAsync(folderName, policy), $"{folderName}: {policy}");

    public async Task AddFolderAsync(string name, string path)
        => await RunAction(() => _api.AddFolderAsync(name, path), $"Added {name}");

    public async Task RemoveFolderAsync(string folderName)
        => await RunAction(() => _api.RemoveFolderAsync(folderName), $"Removed {folderName}");

    public async Task SetAppResourcePolicyAsync(string appName, string resource, string policy)
        => await RunAction(() => _api.SetAppResourcePolicyAsync(appName, resource, policy), $"{appName} {resource}: {policy}");

    public async Task RefreshAsync(bool silent = false)
    {
        if (Interlocked.CompareExchange(ref _refreshRunning, 1, 0) != 0) return;
        if (!silent) IsRefreshing = true;
        try
        {
            IsConnected = await _api.IsOnlineAsync();
            ConnectionStatus = IsConnected ? "Firewall Active" : "Service Offline";
            if (!IsConnected) { IsLoading = false; return; }

            var cfg = await _api.GetConfigAsync();
            if (cfg is not null)
            {
                NetworkPolicy = cfg.NetworkPolicy ?? "ask";
                ClipboardPolicy = cfg.ClipboardPolicy ?? "ask";
                ScreenshotPolicy = cfg.ScreenshotPolicy ?? "ask";
                MicrophonePolicy = cfg.MicrophonePolicy ?? "ask";
                CameraPolicy = cfg.CameraPolicy ?? "ask";
            }

            var status = await _api.GetStatusAsync();
            if (status is null) { IsLoading = false; return; }

            AiCount = status.AiProcesses.Count;
            NetCount = status.ActiveConnections.Count;
            BlockedCount = status.Stats?.Permissions?.Blocked ?? 0;
            FolderCount = status.ProtectedFolders.Count;
            PendingCount = status.PendingRequests.Count;

            ReplaceCollection(AiProcesses, status.AiProcesses);
            ReplaceCollection(NetworkConnections, status.ActiveConnections);
            ReplaceCollection(Events, status.RecentEvents);
            ReplaceCollection(ProtectedFolders, status.ProtectedFolders);
            ReplaceCollection(PendingRequests, status.PendingRequests);
            LastUpdated = DateTime.Now.ToString("HH:mm:ss");
            await LoadPageDataAsync();
            _lastFullRefresh = DateTime.UtcNow;
            IsLoading = false;
        }
        finally
        {
            IsRefreshing = false;
            Interlocked.Exchange(ref _refreshRunning, 0);
        }
    }

    private async Task LoadPageDataAsync()
    {
        if (!IsConnected) return;
        if (SelectedPage == 6) ReplaceCollection(AuditLog, await _api.GetAuditAsync());
        else if (SelectedPage == 7)
        {
            ReplaceCollection(Extensions, await _api.GetExtensionsAsync());
            ReplaceCollection(ModelFiles, await _api.GetModelsAsync());
            ReplaceCollection(AppPolicies, await _api.GetAppPoliciesAsync());
        }
    }

    private async Task RunAction(Func<Task<ActionResultDto>> action, string successHint)
    {
        StatusMessage = "Working...";
        var result = await action();
        StatusMessage = result.Ok
            ? (result.Message ?? successHint)
            : $"Failed: {result.Error ?? "Unknown error"}";
        await RefreshAsync(silent: true);
    }

    private static void ReplaceCollection<T>(ObservableCollection<T> target, IEnumerable<T> source)
    {
        target.Clear();
        foreach (var item in source) target.Add(item);
    }

    public void Dispose() { _timer.Stop(); _api.Dispose(); }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
