using System.Windows;

namespace AiShield.Dashboard.Dialogs;

public partial class ApprovalDialog : Window
{
    public bool Allowed { get; private set; }

    public ApprovalDialog(string appName, string resource)
    {
        InitializeComponent();
        AppText.Text = appName;
        ResourceText.Text = resource;
    }

    private void Allow_Click(object sender, RoutedEventArgs e)
    {
        Allowed = true;
        DialogResult = true;
        Close();
    }

    private void Deny_Click(object sender, RoutedEventArgs e)
    {
        Allowed = false;
        DialogResult = false;
        Close();
    }
}
