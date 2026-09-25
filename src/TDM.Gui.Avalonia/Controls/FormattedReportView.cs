using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using TDM.Models;

namespace TDM.Gui.Avalonia.Controls;

public sealed class FormattedReportView : UserControl
{
    public static readonly StyledProperty<string?> ReportTextProperty =
        AvaloniaProperty.Register<FormattedReportView, string?>(nameof(ReportText));

    private readonly StackPanel _panel;

    public string? ReportText
    {
        get => GetValue(ReportTextProperty);
        set => SetValue(ReportTextProperty, value);
    }

    public FormattedReportView()
    {
        _panel = new StackPanel { Spacing = 6 };
        Content = new ScrollViewer
        {
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Content = _panel
        };

        PropertyChanged += OnAvaloniaPropertyChanged;
        Rebuild();
    }

    private void OnAvaloniaPropertyChanged(object? sender, AvaloniaPropertyChangedEventArgs e)
    {
        if (e.Property == ReportTextProperty)
            Rebuild();
    }

    private void Rebuild()
    {
        _panel.Children.Clear();
        var text = SanitizeVisibleText(ReportText);
        if (string.IsNullOrWhiteSpace(text))
        {
            _panel.Children.Add(new TextBlock
            {
                Text = "Sin datos para mostrar.",
                Foreground = new SolidColorBrush(Color.FromRgb(143, 163, 184)),
                TextWrapping = TextWrapping.Wrap
            });
            return;
        }

        var lines = text.Replace("\r\n", "\n").Split('\n');
        foreach (var raw in lines)
        {
            var line = raw.TrimEnd();
            if (string.IsNullOrWhiteSpace(line))
            {
                _panel.Children.Add(new Border { Height = 8, Background = Brushes.Transparent });
                continue;
            }

            if (TrySplitKeyValue(line, out var key, out var value))
            {
                var grid = new Grid
                {
                    ColumnDefinitions = new ColumnDefinitions("Auto,*"),
                    HorizontalAlignment = HorizontalAlignment.Stretch
                };

                var severityBrush = SeverityBrush(key, value);
                var lineBrush = severityBrush ?? new SolidColorBrush(Color.FromRgb(245, 250, 255));

                grid.Children.Add(new TextBlock
                {
                    Text = key + ":",
                    FontWeight = FontWeight.SemiBold,
                    Foreground = lineBrush,
                    TextWrapping = TextWrapping.Wrap,
                    VerticalAlignment = VerticalAlignment.Top
                });

                var valueBlock = new TextBlock
                {
                    Text = value,
                    Margin = new Thickness(8, 0, 0, 0),
                    Foreground = lineBrush,
                    TextWrapping = TextWrapping.Wrap,
                    VerticalAlignment = VerticalAlignment.Top
                };
                Grid.SetColumn(valueBlock, 1);
                grid.Children.Add(valueBlock);
                _panel.Children.Add(grid);
                continue;
            }

            _panel.Children.Add(new TextBlock
            {
                Text = line,
                Margin = line.StartsWith("•") ? new Thickness(18, 0, 0, 0) : default,
                FontWeight = line.EndsWith(':') ? FontWeight.SemiBold : FontWeight.Normal,
                Foreground = ExplicitSeverityBrush(line) ?? new SolidColorBrush(Color.FromRgb(245, 250, 255)),
                TextWrapping = TextWrapping.Wrap
            });
        }
    }


    private static string? SanitizeVisibleText(string? text)
        => string.IsNullOrWhiteSpace(text) ? text : TdmVisibleText.Sanitize(text);

    private static IBrush? SeverityBrush(string key, string value)
    {
        if (key.Equals("Crítico", StringComparison.OrdinalIgnoreCase) ||
            key.Equals("Critico", StringComparison.OrdinalIgnoreCase))
            return CriticalBrush();

        if (key.Equals("Error", StringComparison.OrdinalIgnoreCase))
            return ErrorBrush();

        if (key.Equals("Advertencia", StringComparison.OrdinalIgnoreCase))
            return WarningBrush();

        if (!key.Equals("Severidad", StringComparison.OrdinalIgnoreCase))
            return null;

        if (value.StartsWith("Crítico", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("Critico", StringComparison.OrdinalIgnoreCase))
            return CriticalBrush();

        if (value.StartsWith("Error", StringComparison.OrdinalIgnoreCase))
            return ErrorBrush();

        if (value.StartsWith("Advertencia", StringComparison.OrdinalIgnoreCase))
            return WarningBrush();

        return null;
    }

    private static IBrush? ExplicitSeverityBrush(string line)
    {
        var value = line.TrimStart();
        if (value.StartsWith("[CRÍTICO]", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("[CRITICO]", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("CRÍTICO:", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("CRITICO:", StringComparison.OrdinalIgnoreCase))
            return CriticalBrush();

        if (value.StartsWith("[ERROR]", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("ERROR:", StringComparison.OrdinalIgnoreCase))
            return ErrorBrush();

        if (value.StartsWith("[ADVERTENCIA]", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("ADVERTENCIA:", StringComparison.OrdinalIgnoreCase))
            return WarningBrush();

        return null;
    }

    private static IBrush CriticalBrush() => new SolidColorBrush(Color.FromRgb(255, 77, 79));
    private static IBrush ErrorBrush() => new SolidColorBrush(Color.FromRgb(255, 138, 61));
    private static IBrush WarningBrush() => new SolidColorBrush(Color.FromRgb(255, 209, 102));

    private static bool TrySplitKeyValue(string line, out string key, out string value)
    {
        var index = line.IndexOf(':');
        if (index <= 0)
        {
            key = string.Empty;
            value = string.Empty;
            return false;
        }

        key = line[..index].Trim();
        value = line[(index + 1)..].Trim();
        return !string.IsNullOrWhiteSpace(key);
    }
}
