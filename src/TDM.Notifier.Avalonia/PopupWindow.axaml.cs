using System.Diagnostics;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Threading;
using TDM.Models;
using TDM.Notifications;

namespace TDM.Notifier.Avalonia;

public partial class PopupWindow : Window
{
    // Embedded in the compiled assembly so startup/readiness can reject stale
    // notifier binaries that still contain the removed technical footer.
    internal const string VisualRevision = "FIX93_EXPLICIT_ALERTS_NO_RECOVERED";

    private readonly DispatcherTimer _autoClose;
    public IncidentNotification? Notification { get; private set; }

    // Public parameterless constructor required by Avalonia runtime XAML loader.
    public PopupWindow()
    {
        InitializeComponent();
        _autoClose = new DispatcherTimer { Interval = TimeSpan.FromSeconds(8) };
        _autoClose.Tick += (_, _) => Close();
        Opened += (_, _) => _autoClose.Start();
        Closed += (_, _) => _autoClose.Stop();
    }

    public PopupWindow(IncidentNotification notification) : this()
    {
        ApplyNotification(notification);
    }

    private void ApplyNotification(IncidentNotification notification)
    {
        Notification = notification;
        var title = SanitizeVisibleText(notification.Title);
        var summary = SanitizeVisibleText(notification.Summary);
        TitleText.Text = notification.Transition switch
        {
            NotificationTransition.Escalated => $"↑ {title}",
            NotificationTransition.Recovered => $"⚠ {title}",
            _ => $"⚠ {title}"
        };
        SummaryText.Text = ShortSummary(summary);
        Card.BorderBrush = BrushFor(notification);
        _autoClose.Interval = IsCritical(notification.Severity) ? TimeSpan.FromSeconds(14) : TimeSpan.FromSeconds(8);
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

        var cut = normalized.IndexOfAny(new[] { '.', ';' });
        if (cut > 0)
            normalized = normalized[..cut].Trim();

        if (normalized.Length > 130)
            normalized = normalized[..127].TrimEnd() + "...";

        return normalized;
    }

    private static string SanitizeVisibleText(string? text)
        => TdmVisibleText.Sanitize(text);

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
        try
        {
            var installRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "TDM");
            var launcher = Path.Combine(installRoot, "START-TDM-UI.cmd");
            if (File.Exists(launcher))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = Environment.GetEnvironmentVariable("COMSPEC") ?? "cmd.exe",
                    Arguments = $"/d /c \"\"{launcher}\"\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                });
                Close();
                return;
            }

            var candidates = new[]
            {
                Path.Combine(AppContext.BaseDirectory, "TDM.Application.exe"),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "App", "TDM.Application.exe")),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "TDM", "App", "TDM.Application.exe"),
                Path.Combine(AppContext.BaseDirectory, "TDM.Gui.exe"),
                Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "gui", "TDM.Gui.exe")),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "TDM", "gui-wpf", "TDM.Gui.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "TDM", "gui", "TDM.Gui.exe")
            };
            var exe = candidates.FirstOrDefault(File.Exists);
            if (exe is not null)
                Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true });
        }
        catch
        {
            // Notification UI must never crash because opening the main UI failed.
        }
        Close();
    }
}
