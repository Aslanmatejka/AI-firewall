using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace AiShield.Dashboard.Converters;

public class IntEqualsConverter : IMultiValueConverter
{
    public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
    {
        if (values.Length >= 2 && values[0] is int page && int.TryParse(values[1]?.ToString(), out var target))
            return page == target ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public class IntToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is int page && int.TryParse(parameter?.ToString(), out var target) && page == target;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => value is true && int.TryParse(parameter?.ToString(), out var target) ? target : System.Windows.Data.Binding.DoNothing;
}

public class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        => value is int c && c > 0 ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
