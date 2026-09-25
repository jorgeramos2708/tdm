using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using TDM.Models;
using TDM.Notifications;

namespace TDM.Gui.Avalonia.Views;

public partial class PortableNotificationWindow : Window
{
    internal const string VisualRevision = "FIX93_EXPLICIT_ALERTS_NO_RECOVERED";

    private readonly DispatcherTimer _autoClose;
    private Action? _activateTdm;

    public PortableNotificationWindow()
    {
        InitializeComponent();
        _autoClose = new DispatcherTimer { Interval = TimeSpan.FromSeconds(8) };
        _autoClose.Tick += (_, _) => Close();
        Opened += (_, _) => _autoClose.Start();
        Closed += (_, _) => _autoClose.Stop();
    }

    internal PortableNotificationWindow(IncidentNotification notification, Action activateTdm) : this()
    {
        _activateTdm = activateTdm;
        ApplyNotification(notification);
    }

    private void ApplyNotification(IncidentNotification notification)
    {
        var title = TdmVisibleText.Sanitize(notification.Title);
        var summary = TdmVisibleText.Sanitize(notification.Summary);
        TitleText.Text = notification.Transition switch
        {
            NotificationTransition.Escalated => $"↑ {title}",
            NotificationTransition.Recovered => $"⚠ {title}",
            _ => $"⚠ {title}"
        };
        SummaryText.Text = ShortSummary(summary);
        Card.BorderBrush = BrushFor(notification);
        _autoClose.Interval = IsCritical(notification.Severity)
            ? TimeSpan.FromSeconds(14)
            : TimeSpan.FromSeconds(8);
    }

    private static string ShortSummary(string? summary)
    {
        if (string.IsNullOrWhiteSpace(summary))
            return "Sin detalle adicional.";

        var normalized = summary
            .Replace(Environment.NewLine, " ")
            .Replace("\r", " ")
            .Replace("\n", " ")
            .Trim();
        var cut = normalized.IndexOfAny(['.', ';']);
        if (cut > 0) normalized = normalized[..cut].Trim();
        return normalized.Length > 130
            ? normalized[..127].TrimEnd() + "..."
            : normalized;
    }

    private static bool IsCritical(string? severity)
        => severity?.Trim().ToLowerInvariant() is "critico" or "crítico";

    private static IBrush BrushFor(IncidentNotification notification)
    {
        return notification.Severity.Trim().ToLowerInvariant() switch
        {
            "critico" or "crítico" => new SolidColorBrush(Color.FromRgb(255, 77, 79)),
            "error" => new SolidColorBrush(Color.FromRgb(255, 138, 61)),
            "advertencia" => new SolidColorBrush(Color.FromRgb(255, 209, 102)),
            _ => new SolidColorBrush(Color.FromRgb(57, 208, 255))
        };
    }

    private void Close_Click(object? sender, RoutedEventArgs e) => Close();

    private void OpenTdm_Click(object? sender, RoutedEventArgs e)
    {
        _activateTdm?.Invoke();
        Close();
    }
}
