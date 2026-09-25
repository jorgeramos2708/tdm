using TDM.Core;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.Services;

public sealed record TelemetryReadResult(
    IReadOnlyList<ObservabilitySample> Samples,
    string RootPath,
    string DataSource,
    DateTimeOffset? LastTimestamp,
    string CoordinatorName,
    IReadOnlyList<FederationNodeStatus> FederationStatuses);

public sealed class TelemetryReadService
{
    public IReadOnlyList<string> PeriodOptions { get; } =
        [
            "Tiempo real",
            "15 minutos",
            "30 minutos",
            "1 hora",
            "2 horas",
            "4 horas",
            "8 horas",
            "12 horas",
            "1 día",
            "2 días",
            "3 días"
        ];

    public async Task<TelemetryReadResult> ReadAsync(string selectedPeriod, CancellationToken ct = default)
    {
        var (root, source) = await ResolveReadRootAsync(ct);
        var window = WindowForPeriod(selectedPeriod);
        IReadOnlyList<ObservabilitySample> samples = await new ObservabilityStore(root).ReadWindowAsync(window, ct);

        // Cuando TDM.Service está activo la GUI toma su historial desde %ProgramData%
        // y superpone las muestras locales de Avalonia a 5 s. Así el servicio conserva
        // el contexto operativo mientras la interfaz mantiene tiempo real verdadero.
        // Los diagnósticos manuales locales también se incorporan a la misma ventana.
        var localRoot = LocalStateStore.DefaultRootPath;
        if (!Path.GetFullPath(root).Equals(Path.GetFullPath(localRoot), StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var cutoff = DateTimeOffset.Now - window;
                var localOverlay = (await new ObservabilityStore(localRoot).ReadWindowAsync(window, ct))
                    .Where(s => (s.SampleKind.Equals("diagnostic-avalonia", StringComparison.OrdinalIgnoreCase)
                                 || s.SampleKind.Equals("avalonia-monitor", StringComparison.OrdinalIgnoreCase))
                                && s.Timestamp >= cutoff)
                    .ToList();

                if (localOverlay.Count > 0)
                {
                    samples = samples
                        .Concat(localOverlay)
                        .OrderBy(s => s.Timestamp)
                        .GroupBy(s => new { s.Timestamp, s.SampleKind })
                        .Select(g => g.Last())
                        .ToList();

                    if (localOverlay.Any(s => s.SampleKind.Equals("avalonia-monitor", StringComparison.OrdinalIgnoreCase)))
                        source += " + GUI 5 s";
                }
            }
            catch (UnauthorizedAccessException) { }
            catch (IOException) { }
        }

        string coordinator = Environment.MachineName;
        IReadOnlyList<FederationNodeStatus> federation = Array.Empty<FederationNodeStatus>();
        try
        {
            var settings = await new SupportMonitoringSettingsStore(root).LoadAsync(ct);
            if (settings.EnableMultiServer)
            {
                // La configuración de Federación sigue siendo por usuario/local, igual que en la GUI WPF.
                // Los nodos pueden apuntar a stores de máquina/UNC, pero el archivo nodes.json no requiere
                // permisos de modificación sobre %ProgramData%.
                var store = new FederationStore(LocalStateStore.DefaultRootPath);
                var config = await store.LoadConfigurationAsync(ct);
                coordinator = config.CoordinatorName;
                federation = await store.ReadStatusesAsync(config, settings.Thresholds, ct);
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        return new TelemetryReadResult(samples, root, source, samples.Count == 0 ? null : samples[^1].Timestamp, coordinator, federation);
    }

    private static async Task<(string Root, string Source)> ResolveReadRootAsync(CancellationToken ct)
    {
        if (PortableRuntime.IsEnabled)
            return (LocalStateStore.DefaultRootPath, "TDM Portable · Monitor local");

        var machineRoot = TdmDataPaths.MachineRootPath;
        try
        {
            var heartbeat = await new ServiceHeartbeatStore(machineRoot).ReadAsync(ct);
            if (ServiceHeartbeatStore.IsFresh(heartbeat) &&
                !string.Equals(heartbeat?.Status, "STOPPED", StringComparison.OrdinalIgnoreCase))
            {
                return (machineRoot, $"TDM.Service · {heartbeat?.Status} · {heartbeat?.Timestamp.ToLocalTime():HH:mm:ss}");
            }
        }
        catch (UnauthorizedAccessException) { }
        catch (IOException) { }

        return (LocalStateStore.DefaultRootPath, "Monitor GUI/local");
    }

    /// <summary>
    /// Convierte la opción visible de periodo en una ventana real de consulta.
    /// La persistencia conserva hasta tres días; "Tiempo real" mantiene una
    /// ventana corta de cinco minutos que se renueva visualmente cada cinco segundos.
    /// </summary>
    public static TimeSpan WindowForPeriod(string selectedPeriod)
        => selectedPeriod switch
        {
            "15 minutos" => TimeSpan.FromMinutes(15),
            "30 minutos" => TimeSpan.FromMinutes(30),
            "1 hora" => TimeSpan.FromHours(1),
            "2 horas" => TimeSpan.FromHours(2),
            "4 horas" => TimeSpan.FromHours(4),
            "8 horas" => TimeSpan.FromHours(8),
            "12 horas" => TimeSpan.FromHours(12),
            "1 día" => TimeSpan.FromDays(1),
            "2 días" => TimeSpan.FromDays(2),
            "3 días" => TimeSpan.FromDays(3),
            _ => TimeSpan.FromMinutes(5)
        };
}
