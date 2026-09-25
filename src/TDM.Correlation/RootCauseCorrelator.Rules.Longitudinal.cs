using TDM.Models;

namespace TDM.Correlation;

public static partial class RootCauseCorrelator
{
    private static void AddLongitudinalHistoryCandidates(DiagnosticReport report, List<CandidateDraft> drafts)
    {
        var transitions = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo is "TDM_FORENSIC_STATE_TRANSITION" or "TDM_INTEGRITY_STATE_TRANSITION" or "TDM_MONITOR_STATE_TRANSITION")
            .OrderBy(e => e.Timestamp)
            .ToList();
        var failures = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Severidad != DiagnosticSeverity.Informativo)
            .Where(e => !e.Fuente.StartsWith("TDM", StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.Timestamp)
            .ToList();

        foreach (var transition in transitions)
        {
            var stateType = EvidenceValue(transition, "Tipo") ?? string.Empty;
            if (!IsCausalLongitudinalType(stateType)) continue;
            if (transition.Timestamp is not DateTimeOffset changedAt) continue;

            // Un servicio que cambia de Running a otro estado es causalmente interesante;
            // un arranque de servicio se conserva como contexto, no como causa automática.
            if (stateType.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase))
            {
                var previous = EvidenceValue(transition, "Estado anterior") ?? string.Empty;
                var current = EvidenceValue(transition, "Estado actual") ?? string.Empty;
                if (!previous.Contains("Running", StringComparison.OrdinalIgnoreCase)
                    || current.Contains("Running", StringComparison.OrdinalIgnoreCase))
                    continue;
            }

            var next = failures
                .Where(e => e.Timestamp!.Value >= changedAt)
                .Select(e => (Event: e, Delta: e.Timestamp!.Value - changedAt))
                .Where(x => x.Delta <= TimeSpan.FromMinutes(15))
                .OrderBy(x => x.Delta)
                .FirstOrDefault();
            if (next.Event is null) continue;

            var sameContext = SameLongitudinalContext(transition, next.Event);
            var strongTime = next.Delta <= TimeSpan.FromMinutes(5);
            var confidence = sameContext && strongTime ? ConfidenceLevel.Alta : ConfidenceLevel.Media;
            var score = stateType.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase) ? 92
                : transition.Tipo.Equals("TDM_INTEGRITY_STATE_TRANSITION", StringComparison.OrdinalIgnoreCase) ? 94
                : 90;
            if (sameContext) score += 3;
            if (strongTime) score += 2;

            var category = stateType.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase)
                ? "cambio de servicio"
                : stateType.Contains("LIBRARY", StringComparison.OrdinalIgnoreCase) || stateType.Contains("FILE", StringComparison.OrdinalIgnoreCase)
                    ? "cambio de archivo/librería"
                    : "cambio de configuración";
            var product = transition.Producto != TsplusProduct.Ninguno ? transition.Producto : next.Event.Producto;
            var layer = transition.Capa == DiagnosticLayer.Desconocida ? next.Event.Capa : transition.Capa;

            drafts.Add(new CandidateDraft(
                $"ROOT-HISTORICAL-{unchecked((uint)HashCode.Combine(transition.Componente, changedAt, stateType)):X8}",
                transition.Componente,
                layer,
                Math.Clamp(score, 0, 99),
                confidence,
                $"Un {category} observado por TDM precedió una falla relacionada.",
                $"TDM registró el cambio a las {changedAt:O} y una señal de falla apareció {FormatDelta(next.Delta)} después. Esta secuencia aumenta la plausibilidad causal, pero una correlación temporal por sí sola no se clasifica como causa confirmada.",
                CompactEvidence(
                    new EvidenceItem("Tipo de estado", stateType),
                    new EvidenceItem("Cambio observado", transition.Mensaje),
                    new EvidenceItem("Estado anterior", EvidenceValue(transition, "Estado anterior") ?? "N/D"),
                    new EvidenceItem("Estado actual", EvidenceValue(transition, "Estado actual") ?? "N/D"),
                    new EvidenceItem("Hora del cambio", changedAt.ToString("O")),
                    new EvidenceItem("Falla posterior", $"{next.Event.Componente}: {next.Event.Mensaje}"),
                    new EvidenceItem("Diferencia temporal", FormatDelta(next.Delta)),
                    new EvidenceItem("Coincidencia de componente", sameContext ? "Sí" : "No concluyente"),
                    new EvidenceItem("Regla de confianza", "Nunca Confirmada sólo por proximidad temporal")),
                null,
                next.Event.Timestamp,
                layer == DiagnosticLayer.Tsplus ? "TSPLUS" : "WINDOWS",
                product));
        }
        var fileModifications = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Tipo is "TSPLUS_FILE_MODIFICATION_EVIDENCE" or "WINDOWS_FILE_MODIFICATION_EVIDENCE")
            .OrderBy(e => e.Timestamp)
            .ToList();
        foreach (var modification in fileModifications)
        {
            if (modification.Timestamp is not DateTimeOffset changedAt) continue;
            var next = failures
                .Where(e => e.Timestamp!.Value >= changedAt)
                .Select(e => (Event: e, Delta: e.Timestamp!.Value - changedAt))
                .Where(x => x.Delta <= TimeSpan.FromMinutes(15))
                .OrderBy(x => x.Delta)
                .FirstOrDefault();
            if (next.Event is null) continue;

            var sameContext = SameLongitudinalContext(modification, next.Event);
            var confidence = sameContext && next.Delta <= TimeSpan.FromMinutes(5) ? ConfidenceLevel.Media : ConfidenceLevel.Baja;
            var score = sameContext ? 78 : 68;
            var file = modification.Archivo ?? EvidenceValue(modification, "Archivo") ?? modification.Componente;
            drafts.Add(new CandidateDraft(
                $"ROOT-FILE-MTIME-{unchecked((uint)HashCode.Combine(file, changedAt)):X8}",
                modification.Componente,
                modification.Capa,
                score,
                confidence,
                "Un archivo relevante fue modificado antes de una falla observada.",
                $"El LastWriteTime del archivo actual cae dentro de la ventana y precede la falla por {FormatDelta(next.Delta)}. Este dato es retrospectivo, pero no demuestra qué contenido tenía la versión previa; por eso TDM limita la confianza.",
                CompactEvidence(
                    new EvidenceItem("Archivo", file),
                    new EvidenceItem("Hora de modificación", changedAt.ToString("O")),
                    new EvidenceItem("Falla posterior", $"{next.Event.Componente}: {next.Event.Mensaje}"),
                    new EvidenceItem("Diferencia temporal", FormatDelta(next.Delta)),
                    new EvidenceItem("Coincidencia de contexto", sameContext ? "Sí" : "No concluyente"),
                    new EvidenceItem("Limitación", "No existe snapshot de contenido anterior; LastWriteTime no equivale a causa confirmada")),
                null,
                next.Event.Timestamp,
                modification.Capa == DiagnosticLayer.Tsplus ? "TSPLUS" : "WINDOWS",
                modification.Producto));
        }
    }

    private static bool IsCausalLongitudinalType(string type)
        => type.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("WINDOWS_LONGITUDINAL_CONFIG_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("WINDOWS_LONGITUDINAL_LIBRARY_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("TSPLUS_LONGITUDINAL_CONFIG_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("TSPLUS_LONGITUDINAL_LIBRARY_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("TSPLUS_CONFIG_ARTIFACT_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("TSPLUS_MODULE_CRITICAL_FILE_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("TSPLUS_APPCONTROL_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("TSPLUS_WEB_SETTINGS_JS_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("WINDOWS_RDP_POLICY_STATE", StringComparison.OrdinalIgnoreCase)
           || type.Equals("WINDOWS_TSPLUS_WINLOGON_INTEGRATION", StringComparison.OrdinalIgnoreCase);

    private static bool SameLongitudinalContext(DiagnosticEvent transition, DiagnosticEvent failure)
    {
        if (transition.Componente.Equals(failure.Componente, StringComparison.OrdinalIgnoreCase)) return true;

        var previous = EvidenceValue(transition, "Estado anterior") ?? string.Empty;
        var current = EvidenceValue(transition, "Estado actual") ?? string.Empty;
        var file = transition.Archivo ?? EvidenceValue(transition, "Archivo") ?? string.Empty;
        var failureText = $"{failure.Componente} {failure.Mensaje} {failure.Archivo}";

        // Sólo se usan identificadores de alta señal. No se comparan palabras genéricas del
        // estado serializado (por ejemplo "Estado" o "Disponible"), porque eso elevaría la
        // confianza de causas no relacionadas.
        var identifiers = new List<string> { transition.Componente };
        if (!string.IsNullOrWhiteSpace(file))
        {
            identifiers.Add(file);
            identifiers.Add(Path.GetFileName(file));
        }
        foreach (var serialized in new[] { previous, current })
        foreach (var key in new[] { "Servicio", "Archivo", "Ruta", "Componente", "Nombre", "Producto" })
        {
            var value = ExtractPersistedField(serialized, key);
            if (!string.IsNullOrWhiteSpace(value)) identifiers.Add(value);
        }

        if (identifiers.Where(x => x.Length >= 5).Any(x => failureText.Contains(x, StringComparison.OrdinalIgnoreCase)))
            return true;

        var stop = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "estado", "actual", "anterior", "disponible", "completa", "parcial", "windows",
            "tsplus", "servicio", "archivo", "componente", "producto", "running", "stopped",
            "configuracion", "configuration", "filesystem", "remote", "access"
        };
        var tokens = identifiers
            .SelectMany(x => x.Split(new[] { ' ', '/', '\\', '|', '=', ':', ';', '.', '_', '-' }, StringSplitOptions.RemoveEmptyEntries))
            .Select(x => x.Trim())
            .Where(x => x.Length >= 5 && !stop.Contains(x))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(32);
        return tokens.Any(token => failureText.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    private static string? ExtractPersistedField(string value, string key)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var marker = key + "=";
        var index = value.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0) return null;
        var start = index + marker.Length;
        var end = value.IndexOf(" | ", start, StringComparison.Ordinal);
        var result = (end < 0 ? value[start..] : value[start..end]).Trim();
        return result.Length == 0 ? null : result;
    }

    private static string FormatDelta(TimeSpan delta)
        => delta.TotalMinutes >= 1 ? $"{delta.TotalMinutes:0.##} min" : $"{Math.Max(0, delta.TotalSeconds):0} s";
}
