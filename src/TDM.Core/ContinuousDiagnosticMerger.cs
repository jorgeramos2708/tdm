using TDM.Models;

namespace TDM.Core;

/// <summary>
/// Combina el diagnóstico completo inicial con muestras incrementales del monitor.
/// Mantiene una ventana móvil acotada, reemplaza estados actuales y deduplica
/// evidencia histórica sin volver a consultar las últimas cuatro horas completas.
/// </summary>
public static class ContinuousDiagnosticMerger
{
    public static bool ShouldContinue(DiagnosticReport? baseline, TimeSpan lookback, DateTimeOffset now)
        => baseline is not null
           && baseline.PeriodoAnalizadoInicio != default
           && baseline.PeriodoAnalizadoInicio <= now - lookback;

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

        // Sólo se arrastran hallazgos de las fuentes sustituidas por collectors
        // incrementales (Event Log y logs TSplus): no se regeneran cada ciclo.
        // Los hallazgos de estado actual se recalculan en la muestra nueva y no
        // deben sobrevivir si la condición ya se recuperó.
        var findings = baseline.Hallazgos
            .Where(f => DiagnosticTimeWindow.IsFindingInside(f, start, end))
            .Where(IsContinuousFinding)
            .Concat(incremental.Hallazgos)
            .GroupBy(FindingIdentity, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Last())
            .OrderByDescending(f => f.Severidad)
            .Take(4_000)
            .ToList();

        // Si la ventana continua es mayor que la solicitada, el reporte consolidado cubre
        // más de lo pedido: declararlo en los campos de auto-ampliación en vez de
        // enmascarar el lookback solicitado con el máximo de la ventana.
        var requestedWindow = incremental.LookbackSolicitado > TimeSpan.Zero ? incremental.LookbackSolicitado : boundedWindow;
        var windowExpanded = boundedWindow > requestedWindow;

        return incremental with
        {
            Hallazgos = findings,
            Eventos = events,
            Fin = end,
            PeriodoAnalizadoInicio = start,
            PeriodoAnalizadoFin = end,
            PeriodoEvidenciaInicio = start,
            PeriodoEvidenciaFin = end,
            EvidenciaDisponibleLookback = boundedWindow,
            Lookback = boundedWindow,
            LookbackSolicitado = requestedWindow,
            VentanaAutoAmpliada = windowExpanded,
            MotivoAmpliacion = windowExpanded
                ? $"La ventana de monitoreo continuo se amplió de {requestedWindow.TotalMinutes:g} a {boundedWindow.TotalMinutes:g} min para cubrir la ventana máxima configurada."
                : null,
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
    {
        if (IsCurrentStateEvent(e)) return true;
        if (e.Timestamp.HasValue) return e.Timestamp.Value >= start && e.Timestamp.Value <= end;
        // C#12: una línea de log sin timestamp entraba a la ventana sin cotejo y
        // sobrevivía a cualquier fusión (|| !Timestamp.HasValue la conservaba para
        // siempre). Ahora caduca cuando su hora de ingesta queda antes de la ventana;
        // una ingesta posterior al cierre se conserva porque es evidencia reciente,
        // no residual. Sin IngestedAt no hay cómo ubicarla y se arrastra (legacy).
        return e.IngestedAt is null || e.IngestedAt >= start;
    }

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

    private static bool IsContinuousFinding(DiagnosticFinding f)
        => (f.Id.StartsWith("EVT-", StringComparison.OrdinalIgnoreCase)
            && !f.Id.EndsWith("-ACCESS", StringComparison.OrdinalIgnoreCase)
            && !f.Id.EndsWith("-READ", StringComparison.OrdinalIgnoreCase))
           || f.Id.StartsWith("LIVE-EVT-", StringComparison.OrdinalIgnoreCase)
           || f.Id.StartsWith("TSLOG-", StringComparison.OrdinalIgnoreCase)
           || f.Id.StartsWith("LIVE-TSLOG-", StringComparison.OrdinalIgnoreCase);

    private static string FindingIdentity(DiagnosticFinding f)
        => $"{f.Id}|{f.Componente}|{f.Capa}";

    private static string EventIdentity(DiagnosticEvent e)
    {
        var resolved = DiagnosticEventIdentity.Resolve(e);
        if (resolved is not null) return resolved;

        if (IsCurrentStateEvent(e))
            return $"state|{e.Tipo}|{e.Componente}|{e.Producto}|{CurrentStateSubIdentity(e)}";

        var timestamp = e.Timestamp?.ToUniversalTime().Ticks.ToString() ?? "sin-fecha";
        return $"event|{timestamp}|{e.Fuente}|{e.Tipo}|{e.Codigo}|{e.Componente}|{e.Archivo}|{e.Mensaje}";
    }

    private static DateTimeOffset ResolveEnd(DiagnosticReport report)
    {
        var end = DiagnosticReportWindow.EffectivePeriodEnd(report);
        return end != default ? end : DateTimeOffset.Now;
    }
}
