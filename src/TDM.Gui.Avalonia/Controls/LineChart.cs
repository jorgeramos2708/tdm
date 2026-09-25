using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;

namespace TDM.Gui.Avalonia.Controls;

/// <summary>
/// Gráfica de líneas ligera y sin dependencias externas. Está diseñada para mantener
/// un coste bajo de render también en sesiones RDP o cuando Avalonia cae a software rendering.
/// Incluye inspección interactiva: al mover el puntero se selecciona la muestra más cercana,
/// se resaltan sus puntos y el cuadro de datos acompaña el movimiento sobre la serie.
/// </summary>
public sealed class LineChart : Control
{
    public static readonly StyledProperty<IReadOnlyList<double>?> SeriesAProperty =
        AvaloniaProperty.Register<LineChart, IReadOnlyList<double>?>(nameof(SeriesA));

    public static readonly StyledProperty<IReadOnlyList<double>?> SeriesBProperty =
        AvaloniaProperty.Register<LineChart, IReadOnlyList<double>?>(nameof(SeriesB));

    public static readonly StyledProperty<IReadOnlyList<string>?> PointLabelsProperty =
        AvaloniaProperty.Register<LineChart, IReadOnlyList<string>?>(nameof(PointLabels));

    public static readonly StyledProperty<IBrush?> SeriesABrushProperty =
        AvaloniaProperty.Register<LineChart, IBrush?>(nameof(SeriesABrush), Brushes.DeepSkyBlue);

    public static readonly StyledProperty<IBrush?> SeriesBBrushProperty =
        AvaloniaProperty.Register<LineChart, IBrush?>(nameof(SeriesBBrush), Brushes.MediumPurple);

    public static readonly StyledProperty<double> MaximumProperty =
        AvaloniaProperty.Register<LineChart, double>(nameof(Maximum), 100d);

    public static readonly StyledProperty<double?> WarningThresholdProperty =
        AvaloniaProperty.Register<LineChart, double?>(nameof(WarningThreshold));

    public static readonly StyledProperty<double?> CriticalThresholdProperty =
        AvaloniaProperty.Register<LineChart, double?>(nameof(CriticalThreshold));

    public static readonly StyledProperty<double?> SeriesAWarningThresholdProperty =
        AvaloniaProperty.Register<LineChart, double?>(nameof(SeriesAWarningThreshold));

    public static readonly StyledProperty<double?> SeriesACriticalThresholdProperty =
        AvaloniaProperty.Register<LineChart, double?>(nameof(SeriesACriticalThreshold));

    public static readonly StyledProperty<double?> SeriesBWarningThresholdProperty =
        AvaloniaProperty.Register<LineChart, double?>(nameof(SeriesBWarningThreshold));

    public static readonly StyledProperty<double?> SeriesBCriticalThresholdProperty =
        AvaloniaProperty.Register<LineChart, double?>(nameof(SeriesBCriticalThreshold));

    public static readonly StyledProperty<string> SeriesALabelProperty =
        AvaloniaProperty.Register<LineChart, string>(nameof(SeriesALabel), "Serie A");

    public static readonly StyledProperty<string> SeriesBLabelProperty =
        AvaloniaProperty.Register<LineChart, string>(nameof(SeriesBLabel), "Serie B");

    public static readonly StyledProperty<string> ValueFormatProperty =
        AvaloniaProperty.Register<LineChart, string>(nameof(ValueFormat), "0.##");

    public static readonly StyledProperty<string> ValueSuffixProperty =
        AvaloniaProperty.Register<LineChart, string>(nameof(ValueSuffix), string.Empty);

    public static readonly StyledProperty<string> SeriesAValueSuffixProperty =
        AvaloniaProperty.Register<LineChart, string>(nameof(SeriesAValueSuffix), string.Empty);

    public static readonly StyledProperty<string> SeriesBValueSuffixProperty =
        AvaloniaProperty.Register<LineChart, string>(nameof(SeriesBValueSuffix), string.Empty);

    public IReadOnlyList<double>? SeriesA { get => GetValue(SeriesAProperty); set => SetValue(SeriesAProperty, value); }
    public IReadOnlyList<double>? SeriesB { get => GetValue(SeriesBProperty); set => SetValue(SeriesBProperty, value); }
    public IReadOnlyList<string>? PointLabels { get => GetValue(PointLabelsProperty); set => SetValue(PointLabelsProperty, value); }
    public IBrush? SeriesABrush { get => GetValue(SeriesABrushProperty); set => SetValue(SeriesABrushProperty, value); }
    public IBrush? SeriesBBrush { get => GetValue(SeriesBBrushProperty); set => SetValue(SeriesBBrushProperty, value); }
    public double Maximum { get => GetValue(MaximumProperty); set => SetValue(MaximumProperty, value); }
    public double? WarningThreshold { get => GetValue(WarningThresholdProperty); set => SetValue(WarningThresholdProperty, value); }
    public double? CriticalThreshold { get => GetValue(CriticalThresholdProperty); set => SetValue(CriticalThresholdProperty, value); }
    public double? SeriesAWarningThreshold { get => GetValue(SeriesAWarningThresholdProperty); set => SetValue(SeriesAWarningThresholdProperty, value); }
    public double? SeriesACriticalThreshold { get => GetValue(SeriesACriticalThresholdProperty); set => SetValue(SeriesACriticalThresholdProperty, value); }
    public double? SeriesBWarningThreshold { get => GetValue(SeriesBWarningThresholdProperty); set => SetValue(SeriesBWarningThresholdProperty, value); }
    public double? SeriesBCriticalThreshold { get => GetValue(SeriesBCriticalThresholdProperty); set => SetValue(SeriesBCriticalThresholdProperty, value); }
    public string SeriesALabel { get => GetValue(SeriesALabelProperty); set => SetValue(SeriesALabelProperty, value); }
    public string SeriesBLabel { get => GetValue(SeriesBLabelProperty); set => SetValue(SeriesBLabelProperty, value); }
    public string ValueFormat { get => GetValue(ValueFormatProperty); set => SetValue(ValueFormatProperty, value); }
    public string ValueSuffix { get => GetValue(ValueSuffixProperty); set => SetValue(ValueSuffixProperty, value); }
    public string SeriesAValueSuffix { get => GetValue(SeriesAValueSuffixProperty); set => SetValue(SeriesAValueSuffixProperty, value); }
    public string SeriesBValueSuffix { get => GetValue(SeriesBValueSuffixProperty); set => SetValue(SeriesBValueSuffixProperty, value); }

    private int? _hoverIndex;
    private Point _pointerPosition;

    static LineChart()
    {
        AffectsRender<LineChart>(
            SeriesAProperty,
            SeriesBProperty,
            SeriesABrushProperty,
            SeriesBBrushProperty,
            MaximumProperty,
            WarningThresholdProperty,
            CriticalThresholdProperty,
            SeriesAWarningThresholdProperty,
            SeriesACriticalThresholdProperty,
            SeriesBWarningThresholdProperty,
            SeriesBCriticalThresholdProperty,
            PointLabelsProperty,
            SeriesALabelProperty,
            SeriesBLabelProperty,
            ValueFormatProperty,
            ValueSuffixProperty,
            SeriesAValueSuffixProperty,
            SeriesBValueSuffixProperty);
    }

    public LineChart()
    {
        PointerMoved += OnPointerMoved;
        PointerExited += OnPointerExited;
    }

    public override void Render(DrawingContext context)
    {
        base.Render(context);
        var width = Bounds.Width;
        var height = Bounds.Height;
        if (width <= 2 || height <= 2) return;

        var gridPen = new Pen(new SolidColorBrush(Color.FromArgb(72, 27, 49, 66)), 1);
        var bottomPad = 20d;
        var plotHeight = Math.Max(10d, height - bottomPad);

        DrawThresholdBands(context, width, plotHeight);

        for (var i = 1; i < 4; i++)
        {
            var y = plotHeight * i / 4d;
            context.DrawLine(gridPen, new Point(0, y), new Point(width, y));
        }

        DrawThreshold(context, WarningThreshold, new SolidColorBrush(Color.FromArgb(190, 255, 209, 102)), width, plotHeight, "Umbral advertencia");
        DrawThreshold(context, CriticalThreshold, new SolidColorBrush(Color.FromArgb(190, 255, 77, 79)), width, plotHeight, "Umbral crítico");
        DrawThreshold(context, SeriesAWarningThreshold, new SolidColorBrush(Color.FromArgb(190, 255, 209, 102)), width, plotHeight, $"{SeriesALabel} advertencia", EffectiveSuffix(SeriesAValueSuffix), alignRight: false);
        DrawThreshold(context, SeriesACriticalThreshold, new SolidColorBrush(Color.FromArgb(190, 255, 77, 79)), width, plotHeight, $"{SeriesALabel} crítico", EffectiveSuffix(SeriesAValueSuffix), alignRight: false);
        DrawThreshold(context, SeriesBWarningThreshold, new SolidColorBrush(Color.FromArgb(190, 255, 209, 102)), width, plotHeight, $"{SeriesBLabel} advertencia", EffectiveSuffix(SeriesBValueSuffix), alignRight: true);
        DrawThreshold(context, SeriesBCriticalThreshold, new SolidColorBrush(Color.FromArgb(190, 255, 77, 79)), width, plotHeight, $"{SeriesBLabel} crítico", EffectiveSuffix(SeriesBValueSuffix), alignRight: true);
        DrawSeries(context, SeriesA, new Pen(SeriesABrush ?? Brushes.DeepSkyBlue, 1.8), width, plotHeight);
        DrawSeries(context, SeriesB, new Pen(SeriesBBrush ?? Brushes.MediumPurple, 1.8), width, plotHeight);
        DrawHoverInspector(context, width, plotHeight);
    }

    private void DrawThresholdBands(DrawingContext context, double width, double plotHeight)
    {
        if (Maximum <= 0)
            return;

        if (WarningThreshold.HasValue)
        {
            var warningY = plotHeight - Math.Clamp(WarningThreshold.Value / Maximum, 0d, 1d) * plotHeight;
            context.FillRectangle(new SolidColorBrush(Color.FromArgb(9, 255, 209, 102)), new Rect(0, warningY, width, plotHeight - warningY));
        }

        if (CriticalThreshold.HasValue)
        {
            var criticalY = plotHeight - Math.Clamp(CriticalThreshold.Value / Maximum, 0d, 1d) * plotHeight;
            context.FillRectangle(new SolidColorBrush(Color.FromArgb(11, 255, 77, 79)), new Rect(0, 0, width, criticalY));
        }
    }

    private void OnPointerMoved(object? sender, PointerEventArgs e)
    {
        var maxCount = Math.Max(SeriesA?.Count ?? 0, SeriesB?.Count ?? 0);
        if (maxCount <= 0 || Bounds.Width <= 0)
        {
            _hoverIndex = null;
            InvalidateVisual();
            return;
        }

        _pointerPosition = e.GetPosition(this);
        _hoverIndex = (int)Math.Round(
            Math.Clamp(_pointerPosition.X / Bounds.Width, 0d, 1d) * Math.Max(0, maxCount - 1));
        InvalidateVisual();
    }

    private void OnPointerExited(object? sender, PointerEventArgs e)
    {
        _hoverIndex = null;
        InvalidateVisual();
    }

    private void DrawHoverInspector(DrawingContext context, double width, double plotHeight)
    {
        if (!_hoverIndex.HasValue || Maximum <= 0)
            return;

        var index = _hoverIndex.Value;
        var maxCount = Math.Max(SeriesA?.Count ?? 0, SeriesB?.Count ?? 0);
        if (maxCount <= 0 || index < 0 || index >= maxCount)
            return;

        var denominator = Math.Max(1, maxCount - 1);
        var x = width * index / denominator;
        var guideBrush = new SolidColorBrush(Color.FromArgb(150, 148, 163, 184));
        context.DrawLine(new Pen(guideBrush, 1, dashStyle: new DashStyle(new[] { 3d, 3d }, 0)), new Point(x, 0), new Point(x, plotHeight));

        var lines = new List<string>();
        if (PointLabels is not null && index < PointLabels.Count && !string.IsNullOrWhiteSpace(PointLabels[index]))
            lines.Add(PointLabels[index]);

        if (TryReadValue(SeriesA, index, out var valueA))
        {
            lines.Add($"{SeriesALabel}: {FormatValue(valueA, EffectiveSuffix(SeriesAValueSuffix))}");
            DrawHoverPoint(context, x, valueA, plotHeight, SeriesABrush ?? Brushes.DeepSkyBlue);
        }

        if (TryReadValue(SeriesB, index, out var valueB))
        {
            lines.Add($"{SeriesBLabel}: {FormatValue(valueB, EffectiveSuffix(SeriesBValueSuffix))}");
            DrawHoverPoint(context, x, valueB, plotHeight, SeriesBBrush ?? Brushes.MediumPurple);
        }

        if (lines.Count == 0)
            return;

        var text = string.Join(Environment.NewLine, lines);
        var foreground = new SolidColorBrush(Color.FromRgb(241, 245, 249));
        var formatted = new FormattedText(
            text,
            System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight,
            new Typeface(FontFamily.Default),
            11,
            foreground);

        var boxWidth = Math.Min(Math.Max(110d, formatted.Width + 18d), Math.Max(110d, width - 8d));
        var boxHeight = Math.Max(34d, formatted.Height + 12d);
        var boxX = _pointerPosition.X + 12d;
        if (boxX + boxWidth > width - 4d)
            boxX = _pointerPosition.X - boxWidth - 12d;
        boxX = Math.Clamp(boxX, 4d, Math.Max(4d, width - boxWidth - 4d));

        var boxY = _pointerPosition.Y - boxHeight - 10d;
        if (boxY < 4d)
            boxY = _pointerPosition.Y + 12d;
        boxY = Math.Clamp(boxY, 4d, Math.Max(4d, plotHeight - boxHeight - 4d));

        var rect = new Rect(boxX, boxY, boxWidth, boxHeight);
        context.FillRectangle(new SolidColorBrush(Color.FromArgb(232, 8, 17, 27)), rect);
        context.DrawRectangle(null, new Pen(new SolidColorBrush(Color.FromArgb(220, 51, 65, 85)), 1), rect);
        context.DrawText(formatted, new Point(rect.X + 9d, rect.Y + 6d));
    }

    private void DrawHoverPoint(DrawingContext context, double x, double value, double plotHeight, IBrush brush)
    {
        var normalized = Math.Clamp(value / Maximum, 0d, 1d);
        var y = plotHeight - normalized * plotHeight;
        context.DrawEllipse(brush, new Pen(new SolidColorBrush(Color.FromRgb(241, 245, 249)), 1), new Point(x, y), 4d, 4d);
    }

    private string EffectiveSuffix(string seriesSuffix)
        => string.IsNullOrWhiteSpace(seriesSuffix) ? ValueSuffix : seriesSuffix;

    private string FormatValue(double value, string suffix)
        => string.IsNullOrWhiteSpace(suffix)
            ? value.ToString(ValueFormat)
            : $"{value.ToString(ValueFormat)} {suffix}";

    private static bool TryReadValue(IReadOnlyList<double>? values, int index, out double value)
    {
        value = default;
        if (values is null || index < 0 || index >= values.Count)
            return false;

        value = values[index];
        return !double.IsNaN(value) && !double.IsInfinity(value);
    }

    private void DrawThreshold(
        DrawingContext context,
        double? value,
        IBrush brush,
        double width,
        double plotHeight,
        string labelPrefix,
        string? suffix = null,
        bool alignRight = true)
    {
        if (!value.HasValue || Maximum <= 0) return;
        var normalized = Math.Clamp(value.Value / Maximum, 0d, 1d);
        var y = plotHeight - normalized * plotHeight;
        context.DrawLine(new Pen(brush, 1, dashStyle: new DashStyle(new[] { 6d, 4d }, 0)), new Point(0, y), new Point(width, y));

        var label = $"{labelPrefix}: {FormatValue(value.Value, suffix ?? ValueSuffix)}";
        var formatted = new FormattedText(
            label,
            System.Globalization.CultureInfo.CurrentCulture,
            FlowDirection.LeftToRight,
            new Typeface(FontFamily.Default),
            11,
            brush);
        var rectWidth = Math.Min(formatted.Width + 10, Math.Max(80, width * 0.35));
        var rect = new Rect(alignRight ? width - rectWidth : 0, Math.Max(0, y - 16), rectWidth, 18);
        context.FillRectangle(new SolidColorBrush(Color.FromArgb(180, 8, 17, 27)), rect);
        context.DrawText(formatted, new Point(rect.X + 5, rect.Y + 1));
    }

    private void DrawSeries(DrawingContext context, IReadOnlyList<double>? values, Pen pen, double width, double plotHeight)
    {
        if (values is null || values.Count < 2 || Maximum <= 0) return;
        Point? previous = null;
        var denominator = Math.Max(1, values.Count - 1);
        for (var i = 0; i < values.Count; i++)
        {
            var value = values[i];
            if (double.IsNaN(value) || double.IsInfinity(value))
            {
                previous = null;
                continue;
            }

            var x = width * i / denominator;
            var normalized = Math.Clamp(value / Maximum, 0d, 1d);
            var point = new Point(x, plotHeight - normalized * plotHeight);
            if (previous.HasValue)
                context.DrawLine(pen, previous.Value, point);
            previous = point;
        }
    }
}
