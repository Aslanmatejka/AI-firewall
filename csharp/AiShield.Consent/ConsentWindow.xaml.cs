using System.Globalization;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;
using AiShield.Core.Ipc;

namespace AiShield.Consent;

public partial class ConsentWindow : Window
{
    // A short delay before Allow works, so a click meant for something else can't land on it.
    private const int AllowDelaySeconds = 2;
    private const uint ExcludeFromCapture = 0x11;

    private readonly DispatcherTimer _countdown = new() { Interval = TimeSpan.FromSeconds(1) };
    private int _secondsLeft = AllowDelaySeconds;

    internal ConsentWindow(ConsentText text, string desktopName)
    {
        InitializeComponent();
        TitleText.Text = text.Title;
        SummaryText.Text = text.Summary;
        DetailsList.ItemsSource = text.Details;
        RequestedByText.Text = text.RequestedBy;
        UpdateAllowLabel();

        _countdown.Tick += (_, _) =>
        {
            _secondsLeft--;
            UpdateAllowLabel();
            if (_secondsLeft <= 0)
            {
                _countdown.Stop();
                AllowButton.IsEnabled = true;
            }
        };

        SourceInitialized += (_, _) => SetWindowDisplayAffinity(new WindowInteropHelper(this).Handle, ExcludeFromCapture);
        Loaded += (_, _) =>
        {
            Activate();
            DenyButton.Focus();
            _countdown.Start();
#if AISHIELD_TEST_HOOKS
            TestHooks.Attach(this, desktopName);
#endif
        };
        _ = desktopName;
    }

    /// <summary>Closing the prompt any way other than the two buttons counts as dismissed.</summary>
    internal int Result { get; private set; } = ConsentExitCodes.Dismissed;

    internal void Finish(int result)
    {
        Result = result;
        Close();
    }

    private void UpdateAllowLabel()
        => AllowButton.Content = _secondsLeft > 0
            ? string.Create(CultureInfo.CurrentCulture, $"Allow ({_secondsLeft})")
            : "Allow";

    private void Allow_Click(object sender, RoutedEventArgs e) => Finish(ConsentExitCodes.Approved);

    private void Deny_Click(object sender, RoutedEventArgs e) => Finish(ConsentExitCodes.Denied);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowDisplayAffinity(nint window, uint affinity);
}
