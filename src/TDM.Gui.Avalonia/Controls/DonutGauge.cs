using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;

namespace TDM.Gui.Avalonia.Controls;

/// <summary>
/// Donut ligero dibujado por Avalonia. No depende de una librería de gráficas.
/// Usa puntos densos en el arco para conservar un render estable bajo RDP/software rendering.
/// </summary>
public sealed class DonutGauge : Control
{
    public static readonly StyledProperty<double> FractionProperty =
        AvaloniaProperty.Register<DonutGauge, double>(nameof(Fraction), 0d);

    public static readonly StyledProperty<IBrush?> AccentBrushProperty =
        AvaloniaProperty.Register<DonutGauge, IBrush?>(nameof(AccentBrush), Brushes.DeepSkyBlue);

    public static readonly StyledProperty<IBrush?> TrackBrushProperty =
        AvaloniaProperty.Register<DonutGauge, IBrush?>(nameof(TrackBrush), new SolidColorBrush(Color.FromRgb(31, 48, 66)));

    public static readonly StyledProperty<double> StrokeThicknessProperty =
        AvaloniaProperty.Register<DonutGauge, double>(nameof(StrokeThickness), 12d);

    public double Fraction
    {
        get => GetValue(FractionProperty);
        set => SetValue(FractionProperty, value);
    }

    public IBrush? AccentBrush
    {
        get => GetValue(AccentBrushProperty);
        set => SetValue(AccentBrushProperty, value);
    }

    public IBrush? TrackBrush
    {
        get => GetValue(TrackBrushProperty);
        set => SetValue(TrackBrushProperty, value);
    }

    public double StrokeThickness
    {
        get => GetValue(StrokeThicknessProperty);
        set => SetValue(StrokeThicknessProperty, value);
    }

    static DonutGauge()
    {
        AffectsRender<DonutGauge>(FractionProperty, AccentBrushProperty, TrackBrushProperty, StrokeThicknessProperty);
    }

    public override void Render(DrawingContext context)
    {
        base.Render(context);

        var diameter = Math.Min(Bounds.Width, Bounds.Height);
        if (diameter <= 0) return;

        var thickness = Math.Clamp(StrokeThickness, 2d, diameter / 3d);
        var radius = Math.Max(1d, diameter / 2d - thickness / 2d - 1d);
        var center = new Point(Bounds.Width / 2d, Bounds.Height / 2d);
        var track = TrackBrush ?? Brushes.DimGray;
        var accent = AccentBrush ?? Brushes.DeepSkyBlue;

        context.DrawEllipse(null, new Pen(track, thickness), center, radius, radius);

        var fraction = Math.Clamp(Fraction, 0d, 1d);
        if (fraction <= 0d) return;

        const int segments = 180;
        var visible = Math.Max(1, (int)Math.Round(segments * fraction));
        var dotRadius = Math.Max(1d, thickness / 2d);
        for (var i = 0; i < visible; i++)
        {
            var t = segments <= 1 ? 0d : i / (double)(segments - 1);
            var angle = (-90d + 360d * t) * Math.PI / 180d;
            var point = new Point(
                center.X + radius * Math.Cos(angle),
                center.Y + radius * Math.Sin(angle));
            context.DrawEllipse(accent, null, point, dotRadius, dotRadius);
        }
    }
}
