using TDM.Models;
using TDM.Persistence;

namespace TDM.Notifications;

/// <summary>
/// Genera títulos claros y consistentes para alertas visibles: solo nombran el recurso,
/// servicio o condición (p. ej. "CPU elevada", "Memoria libre en descenso").
/// Sin marca de producto ("TDM"), sin rol ("Alerta de"/"Incidencia de") —el icono del
/// aviso ya comunica la severidad— y sin etiquetas internas como "/ tendencia".
/// </summary>
public static class AlertTitleFormatter
{
    public static string ForIncident(ManagedIncident incident)
    {
        ArgumentNullException.ThrowIfNull(incident);
        var component = NormalizeLabel(incident.Component);
        if (string.IsNullOrWhiteSpace(component)) component = NormalizeLabel(incident.Kind);
        if (string.IsNullOrWhiteSpace(component)) component = "incidente operativo";
        return TdmVisibleText.Sanitize(component);
    }

    public static string ForFinding(DiagnosticFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var id = finding.Id?.Trim().ToUpperInvariant() ?? string.Empty;
        var detail = id switch
        {
            var x when x.StartsWith("RESOURCE-TREND-MEMORY-", StringComparison.Ordinal) => "memoria libre en descenso",
            var x when x.StartsWith("RESOURCE-TREND-CPU-", StringComparison.Ordinal) => "CPU elevada",
            var x when x.StartsWith("RESOURCE-TREND-PROCESS-RAM-", StringComparison.Ordinal) => $"uso de memoria en aumento ({NormalizeLabel(finding.Componente)})",
            var x when x.StartsWith("RESOURCE-TREND-PROCESS-HANDLES-", StringComparison.Ordinal) => $"handles en aumento ({NormalizeLabel(finding.Componente)})",
            var x when x.StartsWith("RESOURCE-TREND-PROCESS-THREADS-", StringComparison.Ordinal) => $"hilos en aumento ({NormalizeLabel(finding.Componente)})",
            var x when x.StartsWith("RDP-CERTIFICATE-", StringComparison.Ordinal) => "certificado RDP",
            _ => NormalizeLabel(finding.Componente)
        };
        if (string.IsNullOrWhiteSpace(detail)) detail = "condición preventiva";
        return TdmVisibleText.Sanitize(detail);
    }

    private static string NormalizeLabel(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        var normalized = value.Trim()
            .Replace(" / tendencia", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Replace("/ tendencia", string.Empty, StringComparison.OrdinalIgnoreCase)
            .Trim(' ', '/', '-', '·');
        return normalized;
    }
}
