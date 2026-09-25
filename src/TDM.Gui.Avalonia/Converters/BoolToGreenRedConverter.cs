using Avalonia.Data.Converters;
using System;
using System.Globalization;

namespace TDM.Gui.Avalonia.Converters;

public class BoolToGreenRedConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is bool b)
        {
            return b ? "#35F2C0" : "#FF4D4F"; // Green for safe, Red for risk
        }
        return "#FF4D4F";
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}