using TDM.Models;

namespace TDM.Core;

/// <summary>
/// Combina el diagnóstico completo inicial con muestras incrementales del monitor.
/// Mantiene una ventana móvil acotada, reemplaza estados actuales y deduplica
/// evidencia histórica sin volver a consultar las últimas cuatro horas completas.
/// </summary>
public static class ContinuousDiagnosticMerger
{
    public static DiagnosticReport Merge(
        DiagnosticReport baseline,
        DiagnosticReport incremental,
        TimeSpan maxWindow)
    {
        var end = ResolveEnd(incremental);
        var boundedWindow = maxWindow <= TimeSpan.Zero ? TimeSpan.FromHours(4) : maxWindow;
        var start = end - boundedWindow;

        var events = baseline.Eventos
            .Where(e => KeepEvent(e, start, end))
            .ToList();

        foreach (var incoming in incremental.Eventos)
        {
            if (IsCurrentStateEvent(incoming))
                events.RemoveAll(existing => IsSameCurrentState(existing, incoming));
            events.Add(incoming);
        }

        events = events
            .Where(e => KeepEvent(e, start, end))
            .GroupBy(EventIdentity, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Last())
            .OrderBy(e => e.Timestamp ?? end)
            .TakeLast(12_000)
            .ToList();

        // Hallazgos fechados salen de la ventana móvil. Los hallazgos que representan
        // estado actual se reemplazan por la muestra nueva; si la condición se recuperó,
        // desaparecen en lugar de quedar pegados al diagnóstico continuo.
        var findings = baseline.Hallazgos
            .Where(f => DiagnosticTimeWindow.IsFindingInside(f, start, end))
            .Where(f => !IsCurrentStateFinding(f))
            .Concat(incremental.Hallazgos)
            .GroupBy(FindingIdentity, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Last())
            .OrderByDescending(f => f.Severidad)
            .Take(4_000)
            .ToList();

        return baseline with
        {
            Sistema = incremental.Sistema,
            Hallazgos = findings,
            Eventos = events,
            Fin = end,
            PeriodoAnalizadoInicio = start,
            PeriodoAnalizadoFin = end,
            PeriodoEvidenciaInicio = start,
            PeriodoEvidenciaFin = end,
            EvidenciaDisponibleLookback = boundedWindow,
            Lookback = boundedWindow,
            LookbackSolicitado = boundedWindow,
            CausasRaiz = [],
            PatronesFalla = [],
            PrecisionDiagnostica = null,
            ImpactoFuncional = null,
            PlanAccion = null,
            CoberturaDiagnostica = null,
            ResolucionesGuiadas = []
        };
    }

    public static bool IsCurrentStateEvent(DiagnosticEvent e) => DiagnosticEventCatalog.IsMergeCurrentState(e.Tipo);

    private static bool KeepEvent(DiagnosticEvent e, DateTimeOffset start, DateTimeOffset end)
        => IsCurrentStateEvent(e)
           || !e.Timestamp.HasValue
           || (e.Timestamp.Value >= start && e.Timestamp.Value <= end);

    private static bool IsSameCurrentState(DiagnosticEvent a, DiagnosticEvent b)
    {
        if (!a.Tipo.Equals(b.Tipo, StringComparison.OrdinalIgnoreCase)) return false;
        if (!a.Componente.Equals(b.Componente, StringComparison.OrdinalIgnoreCase)) return false;
        if (a.Producto != b.Producto) return false;
        return CurrentStateSubIdentity(a).Equals(CurrentStateSubIdentity(b), StringComparison.OrdinalIgnoreCase);
    }

    private static string CurrentStateSubIdentity(DiagnosticEvent e)
    {
        var identityKeys = new[] { "Servicio", "Producto", "Puerto", "Archivo", "Módulo", "Nombre" };
        var parts = (e.Evidencia ?? [])
            .Where(x => identityKeys.Any(key => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase)))
            .Select(x => $"{x.Clave}={x.Valor}");
        return string.Join("|", parts);
    }

    private static bool IsCurrentStateFinding(DiagnosticFinding f)
        => f.Id.StartsWith("SVC-", StringComparison.OrdinalIgnoreCase)
           || f.Id.StartsWith("MONITOR-RDP-", StringComparison.OrdinalIgnoreCase)
           || f.Id.StartsWith("RESOURCE-TREND-", StringComparison.OrdinalIgnoreCase);

    private static string FindingIdentity(DiagnosticFinding f)
        => $"{f.Id}|{f.Componente}|{f.Capa}";

    private static string EventIdentity(DiagnosticEvent e)
    {
        var nativeId = EvidenceValue(e, "RecordId")
                       ?? EvidenceValue(e, "EventRecordId")
                       ?? EvidenceValue(e, "ReportId");
        if (!string.IsNullOrWhiteSpace(nativeId))
            return $"native|{e.Fuente}|{e.Tipo}|{nativeId}";

        if (IsCurrentStateEvent(e))
            return $"state|{e.Tipo}|{e.Componente}|{e.Producto}|{CurrentStateSubIdentity(e)}";

        var timestamp = e.Timestamp?.ToUniversalTime().Ticks.ToString() ?? "sin-fecha";
        return $"event|{timestamp}|{e.Fuente}|{e.Tipo}|{e.Codigo}|{e.Componente}|{e.Archivo}|{e.Linea}|{e.Mensaje}";
    }

    private static string? EvidenceValue(DiagnosticEvent e, string key)
        => EvidenceReader.Value(e, key);

    private static DateTimeOffset ResolveEnd(DiagnosticReport report)
    {
        if (report.PeriodoAnalizadoFin != default) return report.PeriodoAnalizadoFin;
        if (report.Fin != default) return report.Fin;
        return DateTimeOffset.Now;
    }
}
