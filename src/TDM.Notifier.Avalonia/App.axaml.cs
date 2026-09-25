using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using TDM.Persistence;

namespace TDM.Notifier.Avalonia;

public partial class App : global::Avalonia.Application
{
    private Mutex? _singleInstanceMutex;
    private bool _ownsSingleInstanceMutex;
    private JournalReader? _reader;
    private PopupCoordinator? _coordinator;
    private DispatcherTimer? _timer;
    private bool _polling;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;

            // Readiness probe: valida inicialización real del lector sin competir con el
            // mutex de la instancia interactiva que puede estar ejecutándose.
            if (string.Equals(Environment.GetEnvironmentVariable("TDM_AVALONIA_NOTIFIER_READINESS_PROBE"), "1", StringComparison.Ordinal))
            {
                _reader = new JournalReader(TdmDataPaths.MachineRootPath, Path.Combine(TdmDataPaths.NotifierUserStatePath, "avalonia-readiness"));
                _ = RunReadinessProbeAsync(desktop);
                base.OnFrameworkInitializationCompleted();
                return;
            }

            _singleInstanceMutex = new Mutex(true, @"Local\TDM.Notifier.Avalonia", out var createdNew);
            _ownsSingleInstanceMutex = createdNew;
            if (!createdNew && !TryTakeOverNotifierFromAnotherDelivery())
            {
                desktop.Shutdown();
                base.OnFrameworkInitializationCompleted();
                return;
            }

            _coordinator = new PopupCoordinator();
            _reader = new JournalReader(TdmDataPaths.MachineRootPath, Path.Combine(TdmDataPaths.NotifierUserStatePath, "avalonia"));
            _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            _timer.Tick += PollAsync;
            _ = InitializeAndStartAsync();
            desktop.Exit += (_, _) => DisposeResources();
        }
        base.OnFrameworkInitializationCompleted();
    }

    private async Task InitializeAndStartAsync()
    {
        if (_reader is null || _timer is null) return;
        try
        {
            await _reader.InitializeAsync();
            _timer.Start();
            EmitReadinessMarker("READY", "TDM.Notifier");
        }
        catch (Exception ex)
        {
            EmitReadinessMarker("ERROR", $"{ex.GetType().Name}:{ex.Message}");
            // El journal autoritativo queda intacto; el siguiente inicio puede reintentar.
        }
    }

    private async Task RunReadinessProbeAsync(IClassicDesktopStyleApplicationLifetime desktop)
    {
        if (_reader is null)
        {
            EmitReadinessMarker("ERROR", "ReaderNotInitialized");
            desktop.Shutdown(2);
            return;
        }

        try
        {
            await _reader.InitializeAsync();
            EmitReadinessMarker("READY", "TDM.Notifier.Probe");
            // Mantener el proceso vivo brevemente; el gate lo cerrará tras observar READY.
        }
        catch (Exception ex)
        {
            EmitReadinessMarker("ERROR", $"{ex.GetType().Name}:{ex.Message}");
            desktop.Shutdown(2);
        }
    }

    private async void PollAsync(object? sender, EventArgs e)
    {
        if (_polling || _reader is null || _coordinator is null) return;
        _polling = true;
        try
        {
            var notifications = await _reader.ReadNewAsync();
            foreach (var notification in notifications) _coordinator.Show(notification);
        }
        catch
        {
            // Best-effort visual. TDM.Service y el journal siguen siendo la autoridad.
        }
        finally { _polling = false; }
    }

    private static void EmitReadinessMarker(string status, string detail)
    {
        var path = Environment.GetEnvironmentVariable("TDM_AVALONIA_NOTIFIER_READY_FILE");
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            var directory = Path.GetDirectoryName(path);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            var safeDetail = (detail ?? string.Empty).Replace("\r", " ").Replace("\n", " ");
            File.WriteAllText(path, $"{status}|{DateTimeOffset.Now:O}|{safeDetail}");
        }
        catch
        {
            // Sólo gate de readiness; el journal sigue siendo la autoridad.
        }
    }

    private bool TryTakeOverNotifierFromAnotherDelivery()
    {
        if (_singleInstanceMutex is null) return false;

        try
        {
            var currentPath = Path.GetFullPath(Environment.ProcessPath ?? string.Empty);
            var replaced = false;
            foreach (var processName in new[] { "TDM.Notifier", "TDM.Notifier.Avalonia" })
            {
                foreach (var process in Process.GetProcessesByName(processName))
                {
                    using (process)
                    {
                        if (process.Id == Environment.ProcessId) continue;
                        string? runningPath = null;
                        try { runningPath = process.MainModule?.FileName; } catch { }
                        if (string.IsNullOrWhiteSpace(runningPath) ||
                            Path.GetFullPath(runningPath).Equals(currentPath, StringComparison.OrdinalIgnoreCase))
                            continue;

                        process.Kill(entireProcessTree: true);
                        process.WaitForExit(2500);
                        replaced = true;
                    }
                }
            }

            if (!replaced) return false;
            try
            {
                _ownsSingleInstanceMutex = _singleInstanceMutex.WaitOne(TimeSpan.FromSeconds(3));
            }
            catch (AbandonedMutexException)
            {
                _ownsSingleInstanceMutex = true;
            }
            return _ownsSingleInstanceMutex;
        }
        catch
        {
            // Si no hay permisos para inspeccionar/terminar la entrega anterior,
            // se conserva la regla segura de una sola instancia.
            return false;
        }
    }

    private void DisposeResources()
    {
        _timer?.Stop();
        if (_ownsSingleInstanceMutex)
        {
            try { _singleInstanceMutex?.ReleaseMutex(); } catch { }
        }
        _singleInstanceMutex?.Dispose();
    }
}
