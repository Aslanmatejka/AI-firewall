using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace AiShield.Dashboard.Converters;

public class ConfidenceToWidthConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        if (values[0] is int confidence && values[1] is double totalWidth)
            return Math.Clamp(confidence / 100.0 * totalWidth, 0, totalWidth);
        return 0.0;
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public class ConfidenceToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var app = System.Windows.Application.Current;
        if (value is int c)
        {
            if (c >= 80) return app.FindResource("DangerBrush")!;
            if (c >= 50) return app.FindResource("WarningBrush")!;
            return app.FindResource("SuccessBrush")!;
        }
        return app.FindResource("AccentBrush")!;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public class HealthToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var app = System.Windows.Application.Current;
        if (value is int h)
        {
            if (h >= 75) return app.FindResource("SuccessBrush")!;
            if (h >= 50) return app.FindResource("WarningBrush")!;
            return app.FindResource("DangerBrush")!;
        }
        return app.FindResource("AccentBrush")!;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
