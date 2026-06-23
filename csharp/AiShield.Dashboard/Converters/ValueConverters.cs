using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace AiShield.Dashboard.Converters;

public class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is Visibility.Visible;
}

public class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : value;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is bool b ? !b : value;
}

public class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var app = System.Windows.Application.Current;
        return (value as string)?.ToLower() switch
        {
            "critical" => app.FindResource("DangerSubtleBrush") as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.DarkRed,
            "warning" => app.FindResource("WarningSubtleBrush") as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.DarkOrange,
            _ => app.FindResource("AccentSubtleBrush") as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.DarkBlue,
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public class PolicyToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var app = System.Windows.Application.Current;
        return (value as string)?.ToLower() switch
        {
            "block" => app.FindResource("DangerSubtleBrush") as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.DarkRed,
            "allow" => app.FindResource("SuccessSubtleBrush") as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.DarkGreen,
            _ => app.FindResource("WarningSubtleBrush") as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.DarkOrange,
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public class GpuDisplayConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is double d and > 0 ? $"{d:F0} MB" : "—";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public class TimeAgoConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not string s || !DateTime.TryParse(s, out var dt))
            return value?.ToString() ?? "";
        var diff = DateTime.Now - dt;
        if (diff.TotalSeconds < 60) return "Just now";
        if (diff.TotalMinutes < 60) return $"{(int)diff.TotalMinutes}m ago";
        if (diff.TotalHours < 24) return $"{(int)diff.TotalHours}h ago";
        return dt.ToString("MMM d, HH:mm");
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
