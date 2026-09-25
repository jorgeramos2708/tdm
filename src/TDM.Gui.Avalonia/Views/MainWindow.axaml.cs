using Avalonia;
using Avalonia.Controls;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using System.Diagnostics;
using TDM.Core;
using TDM.Gui.Avalonia.Services;
using TDM.Gui.Avalonia.ViewModels;
using TDM.Notifications;

namespace TDM.Gui.Avalonia.Views;

public partial class MainWindow : Window
{
    private readonly DispatcherTimer _refreshTimer;
    private PortableNotificationCoordinator? _portableNotificationCoordinator;
    private MainWindowViewModel? _portableNotificationViewModel;
    private bool _timerRefreshRunning;

    public MainWindow()
    {
        InitializeComponent();
        _refreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(IntegratedMonitoringService.RealtimeIntervalSeconds) };
        _refreshTimer.Tick += RefreshTimer_Tick;
        Opened += async (_, _) =>
        {
            ClampToWorkingArea();
            EmitReadyMarker();
            _refreshTimer.Start();
            if (DataContext is not MainWindowViewModel vm) return;

            vm.Diagnostics.SelectExportDirectoryAsync = SelectReportDirectoryAsync;
            vm.Diagnostics.RevealExportedFile = RevealExportedFile;

            if (PortableRuntime.IsEnabled && _portableNotificationViewModel is null)
            {
                _portableNotificationCoordinator = new PortableNotificationCoordinator(this);
                _portableNotificationViewModel = vm;
                vm.PortableNotificationsProduced += PortableNotificationsProduced;
            }

            await vm.InitializeAsync();
        };
        Closed += (_, _) =>
        {
            _refreshTimer.Stop();
            if (_portableNotificationViewModel is not null)
                _portableNotificationViewModel.PortableNotificationsProduced -= PortableNotificationsProduced;
            _portableNotificationCoordinator?.Dispose();
            if (DataContext is IDisposable disposable)
                disposable.Dispose();
        };
    }

    private void PortableNotificationsProduced(IReadOnlyList<IncidentNotification> notifications)
        => _portableNotificationCoordinator?.Show(notifications);

    private async void RefreshTimer_Tick(object? sender, EventArgs e)
    {
        if (_timerRefreshRunning || DataContext is not MainWindowViewModel vm) return;
        _timerRefreshRunning = true;
        try
        {
            await vm.RefreshAsync();
        }
        catch
        {
            // El ViewModel ya traduce fallos de lectura a StatusMessage. El timer no debe cerrar la GUI.
        }
        finally
        {
            _timerRefreshRunning = false;
        }
    }

    private async Task<string?> SelectReportDirectoryAsync(CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Seleccionar carpeta para guardar el reporte TDM",
            AllowMultiple = false
        });
        ct.ThrowIfCancellationRequested();
        return folders.Count == 0 ? null : folders[0].Path.LocalPath;
    }

    private static void RevealExportedFile(string path)
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return;
        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"/select,\"{path}\"",
            UseShellExecute = true
        });
    }

    /// <summary>
    /// Ajusta la ventana al área de trabajo del monitor (respeta la barra de tareas) para que
    /// nunca abra sobresaliendo de la pantalla en equipos de baja resolución. Best-effort.
    /// </summary>
    private void ClampToWorkingArea()
    {
        try
        {
            var screen = Screens.ScreenFromWindow(this) ?? Screens.Primary;
            if (screen is null) return;
            var area = screen.WorkingArea;
            if (area.Width <= 0 || area.Height <= 0) return;
            if (Width > area.Width) Width = area.Width;
            if (Height > area.Height) Height = area.Height;
            var x = Position.X;
            var y = Position.Y;
            if (x + (int)Width > area.X + area.Width) x = Math.Max(area.X, area.X + area.Width - (int)Width);
            if (y + (int)Height > area.Y + area.Height) y = Math.Max(area.Y, area.Y + area.Height - (int)Height);
            if (x < area.X) x = area.X;
            if (y < area.Y) y = area.Y;
            Position = new PixelPoint(x, y);
        }
        catch
        {
            // El ajuste es best-effort; nunca debe impedir abrir TDM.
        }
    }

    private static void EmitReadyMarker()
    {
        var path = Environment.GetEnvironmentVariable("TDM_AVALONIA_STARTUP_READY_FILE");
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            File.WriteAllText(path, $"READY|{DateTimeOffset.Now:O}|TDM.Application");
        }
        catch
        {
            // El marcador es exclusivo del gate de startup; nunca debe impedir abrir TDM.
        }
    }

}
