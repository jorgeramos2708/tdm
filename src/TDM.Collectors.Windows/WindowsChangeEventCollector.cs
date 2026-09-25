using System.Diagnostics.Eventing.Reader;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Captura cambios del sistema que pueden explicar por qué un servicio o producto comenzó
/// a fallar: instalación/cambio de servicios, reinicios, MSI y Windows Update. Sólo lectura.
/// Los cambios se conservan como antecedentes; no se declaran causa por sí solos.
/// RC17 también expone la cobertura de estas fuentes para que una lectura fallida no se
/// interprete como ausencia de cambios.
/// </summary>
public sealed class WindowsChangeEventCollector : IReadOnlyCollector
{
    public string Nombre => "Cambios recientes de Windows";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var coverage = new List<EvidenceItem>();
        var window = DiagnosticWindow.Resolve(context);
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);

        coverage.Add(new EvidenceItem("Ventana solicitada", $"{window.Start:O} → {window.End:O}"));
        coverage.Add(new EvidenceItem("System / servicios y reinicios", ReadSystemChanges(timeClause, ResolveLimit(160, context.Lookback), events, cancellationToken)));
        coverage.Add(new EvidenceItem("Application / MsiInstaller", ReadMsiChanges(timeClause, ResolveLimit(100, context.Lookback), events, cancellationToken)));
        coverage.Add(new EvidenceItem("Windows Update", ReadWindowsUpdateChanges(timeClause, ResolveLimit(120, context.Lookback), events, cancellationToken)));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Cobertura de cambios Windows",
            DiagnosticLayer.Windows,
            DiagnosticSeverity.Informativo,
            "WINDOWS_CHANGE_COVERAGE",
            "Cobertura de fuentes utilizadas para detectar cambios previos al incidente.",
            Evidencia: coverage));

        var unreadable = coverage
            .Where(x => x.Valor.StartsWith("Sin permisos", StringComparison.OrdinalIgnoreCase) ||
                        x.Valor.StartsWith("No legible", StringComparison.OrdinalIgnoreCase) ||
                        x.Valor.StartsWith("Parcial", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (unreadable.Count > 0)
        {
            findings.Add(new DiagnosticFinding(
                "WINDOWS-CHANGE-COVERAGE-INCOMPLETE",
                "Cambios recientes de Windows",
                DiagnosticSeverity.Advertencia,
                "No fue posible leer todas las fuentes de cambios previos de Windows.",
                "TDM conserva esta limitación de cobertura y no interpreta la ausencia de eventos en esas fuentes como ausencia de cambios.",
                unreadable,
                ConfidenceLevel.Confirmada,
                Capa: DiagnosticLayer.Windows));
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static string ReadSystemChanges(string timeClause, int max, List<DiagnosticEvent> output, CancellationToken ct)
    {
        var xpath = $"*[System[((EventID=7040 or EventID=7045 or EventID=6005 or EventID=6006 or EventID=6008 or EventID=41)) and {timeClause}]]";
        return Read("System", xpath, max, output, ct, record => record.Id switch
        {
            7040 => "SERVICE_CONFIGURATION_CHANGE",
            7045 => "SERVICE_INSTALLED",
            41 or 6005 or 6006 or 6008 => "SYSTEM_RESTART_CHANGE",
            _ => "SYSTEM_CHANGE_EVENT"
        });
    }

    private static string ReadMsiChanges(string timeClause, int max, List<DiagnosticEvent> output, CancellationToken ct)
    {
        var xpath = $"*[System[Provider[@Name='MsiInstaller'] and {timeClause}]]";
        return Read("Application", xpath, max, output, ct, _ => "SOFTWARE_INSTALL_CHANGE");
    }

    private static string ReadWindowsUpdateChanges(string timeClause, int max, List<DiagnosticEvent> output, CancellationToken ct)
    {
        var xpath = $"*[System[((EventID=19 or EventID=20 or EventID=31 or EventID=34 or EventID=43 or EventID=44)) and {timeClause}]]";
        return Read("Microsoft-Windows-WindowsUpdateClient/Operational", xpath, max, output, ct, _ => "WINDOWS_UPDATE_CHANGE");
    }

    private static string Read(
        string log,
        string xpath,
        int max,
        List<DiagnosticEvent> output,
        CancellationToken ct,
        Func<EventRecord, string> typeSelector)
    {
        try
        {
            var query = new EventLogQuery(log, PathType.LogName, xpath)
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };
            using var reader = new EventLogReader(query);
            var count = 0;
            for (EventRecord? record = reader.ReadEvent(); record is not null && count < max; record = reader.ReadEvent())
            {
                ct.ThrowIfCancellationRequested();
                using (record)
                {
                    string message;
                    try { message = record.FormatDescription() ?? "Sin descripción."; }
                    catch { message = "Descripción no disponible."; }
                    var provider = record.ProviderName ?? log;
                    var timestamp = record.TimeCreated is null ? (DateTimeOffset?)null : new DateTimeOffset(record.TimeCreated.Value);
                    var severity = record.Level switch
                    {
                        1 => DiagnosticSeverity.Critico,
                        2 => DiagnosticSeverity.Error,
                        3 => DiagnosticSeverity.Advertencia,
                        _ => DiagnosticSeverity.Informativo
                    };
                    var type = typeSelector(record);
                    var product = ProductFromText($"{provider} {message}");
                    output.Add(new DiagnosticEvent(
                        timestamp,
                        provider,
                        "Cambio del sistema",
                        DiagnosticLayer.Windows,
                        severity,
                        type,
                        message,
                        record.Id.ToString(),
                        Evidencia:
                        [
                            new("Canal", log),
                            new("EventId", record.Id.ToString()),
                            new("Provider", provider),
                            new("RecordId", record.RecordId?.ToString() ?? "N/D"),
                            new("Uso por TDM", "Antecedente temporal; no causal por sí solo")
                        ],
                        Producto: product));
                    count++;
                }
            }
            return count >= max
                ? $"Parcial; eventos observados>={count}; límite adaptativo={max} alcanzado"
                : $"Disponible; eventos observados={count}";
        }
        catch (EventLogNotFoundException) { return "Canal no disponible"; }
        catch (UnauthorizedAccessException) { return "Sin permisos de lectura"; }
        catch (EventLogException ex) { return $"No legible: {ex.Message}"; }
    }

    private static int ResolveLimit(int baseLimit, TimeSpan lookback)
    {
        var factor = lookback.TotalHours switch
        {
            <= 4 => 1,
            <= 12 => 2,
            <= 24 => 4,
            _ => 8
        };
        return Math.Min(2_500, Math.Max(baseLimit, baseLimit * factor));
    }

    private static TsplusProduct ProductFromText(string text)
    {
        if (text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.ServerMonitoring;
        if (text.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase) || text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.AdvancedSecurity;
        if (text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase) || text.Contains("Remote Support", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteSupport;
        if (text.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || text.Contains("2FA", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.TwoFactorAuthentication;
        if (text.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || text.Contains("Application Publishing", StringComparison.OrdinalIgnoreCase) || text.Contains("APSC", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteAccess;
        return TsplusProduct.Ninguno;
    }
}
