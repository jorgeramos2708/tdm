using TDM.Models;

namespace TDM.Correlation;

public static partial class RootCauseCorrelator
{
    private static void AddConfigurationAndIntegrityCandidates(DiagnosticReport report, List<CandidateDraft> drafts, IReadOnlyList<DiagnosticEvent> tsplusErrors)
    {
        // RC18.3.1: configuración interna de publicación/web de TSplus.
        // Una anomalía estática sólo se eleva con fuerza cuando además existe un síntoma operativo compatible
        // dentro de la ventana temporal; así evitamos convertir configuraciones antiguas/no usadas en causas falsas.
        var appConfigIssues = report.Hallazgos
            .Where(f => f.Id.StartsWith("TSPLUS-PUBLISHED-APP-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-APPCONTROL-", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(f => f.Severidad)
            .ToList();
        var publishingErrors = tsplusErrors
            .Where(e => e.Tipo is "APPLICATION_PUBLISHING" or "FILE_NOT_FOUND" or "ACCESS_DENIED" or "SESSION" or "OPERATION_FAILED")
            .OrderBy(e => e.Timestamp)
            .ToList();
        if (appConfigIssues.Count > 0)
        {
            var evaluatedIssues = appConfigIssues.Take(50).Select(issue =>
            {
                var correlationNeedles = issue.Evidencia
                    .Where(ev => ev.Clave.Contains("Aplicación", StringComparison.OrdinalIgnoreCase) ||
                                 ev.Clave.Contains("Ruta", StringComparison.OrdinalIgnoreCase) ||
                                 ev.Clave.Contains("Asignación", StringComparison.OrdinalIgnoreCase) ||
                                 ev.Clave.Contains("Usuario", StringComparison.OrdinalIgnoreCase) ||
                                 ev.Clave.Contains("Grupo", StringComparison.OrdinalIgnoreCase))
                    .SelectMany(ev => new[] { ev.Valor, Path.GetFileName(ev.Valor) })
                    .Where(v => !string.IsNullOrWhiteSpace(v) && v.Length >= 4 && !v.Equals("N/D", StringComparison.OrdinalIgnoreCase))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();
                var related = publishingErrors
                    .Where(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
                    .LastOrDefault(e =>
                    e.Mensaje.Contains(issue.Componente, StringComparison.OrdinalIgnoreCase) ||
                    correlationNeedles.Any(needle => e.Mensaje.Contains(needle, StringComparison.OrdinalIgnoreCase)));
                return (issue, related);
            }).ToList();

            // Si existe una anomalía que sí coincide con el error operativo, se prioriza sobre otra
            // anomalía estática de mayor severidad pero no relacionada con el incidente actual.
            var selectedIssues = evaluatedIssues.Any(x => x.related is not null)
                ? evaluatedIssues.Where(x => x.related is not null).OrderByDescending(x => x.related!.Timestamp).Take(3).ToList()
                : evaluatedIssues.Take(1).ToList();

            var issueIndex = 0;
            foreach (var item in selectedIssues)
            {
                issueIndex++;
                var issue = item.issue;
                var related = item.related;
                var score = related is null ? 78 : 94;
                drafts.Add(new CandidateDraft(
                    issueIndex == 1 ? "ROOT-TSPLUS-APPLICATION-CONFIG" : $"ROOT-TSPLUS-APPLICATION-CONFIG-{issueIndex}",
                    $"Application Control / {issue.Componente}",
                    DiagnosticLayer.Tsplus,
                    score,
                    related is null ? ConfidenceLevel.Media : ConfidenceLevel.Alta,
                    related is null
                        ? "TDM detectó una anomalía vigente en la configuración de una aplicación publicada por TSplus."
                        : "TDM correlacionó una anomalía de Application Control con un error operativo compatible en la misma vista.",
                    related is null
                        ? "Existe una inconsistencia observable en AppControl.ini (por ejemplo ruta de ejecutable/startup inexistente o sección ambigua). Sin un intento de apertura correlacionado no se afirma que explique el incidente actual, pero debe validarse antes de reparar Windows."
                        : "La configuración publicada contiene una inconsistencia y, dentro de la ventana, TSplus registró un error de sesión/publicación compatible con la misma aplicación, ruta, asignación o usuario. La combinación orienta la corrección a Application Control y a la aplicación asignada, no a componentes generales de Windows.",
                    Merge(issue.Evidencia,
                        new EvidenceItem("Error TSplus correlacionado", related?.Tipo ?? "No"),
                        related?.Timestamp is DateTimeOffset ts ? new EvidenceItem("Hora error", ts.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")) : null,
                        related is null ? null : new EvidenceItem("Fuente error", related.Fuente)),
                    null,
                    related?.Timestamp,
                    "TSPLUS",
                    TsplusProduct.RemoteAccess));
            }
        }

        var webConfigIssues = report.Hallazgos
            .Where(f => f.Id.StartsWith("TSPLUS-WEB-CONFIG-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-WEB-RUNTIME-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-WEB-PORT-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-WEB-JVM-CRASH-", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(f => f.Severidad)
            .ToList();
        var webErrors = tsplusErrors.Where(e => e.Tipo is "WEB" or "PORT_BIND" or "CERTIFICATE_OR_TLS" or "TSPLUS_HTML5_JVM_CRASH").OrderBy(e => e.Timestamp).ToList();
        if (webConfigIssues.Count > 0)
        {
            var issue = webConfigIssues[0];
            var related = webErrors.LastOrDefault(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)));
            drafts.Add(new CandidateDraft(
                "ROOT-TSPLUS-WEB-CONFIG",
                "TSplus Web Portal / Web Server",
                DiagnosticLayer.Tsplus,
                related is null ? 76 : 91,
                related is null ? ConfidenceLevel.Media : ConfidenceLevel.Alta,
                related is null ? "TDM detectó una anomalía vigente en configuración web TSplus." : "TDM correlacionó configuración web anómala con evidencia de error Web/HTML5.",
                related is null
                    ? "La configuración web no pudo validarse completamente. Sin un error HTML5/Web cercano se conserva como hipótesis, no como causa primaria."
                    : "Una anomalía de configuración del portal/servidor web coincide con errores Web/HTML5 dentro del periodo analizado. Esta capa debe investigarse antes de RDP genérico si el síntoma ocurre únicamente por navegador/HTML5.",
                Merge(issue.Evidencia, new EvidenceItem("Error web correlacionado", related?.Tipo ?? "No")),
                null,
                related?.Timestamp,
                "TSPLUS",
                TsplusProduct.RemoteAccess));
        }

        // Mission Assurance: artefactos de configuración del árbol TSplus (.ini/.js/.bin/JSON/XML y afines).
        // Una anomalía estructural puede convertirse en candidato fuerte cuando existe una señal operativa
        // compatible. Una simple modificación temporal sólo se conserva como candidato medio: correlación
        // temporal no equivale a causalidad por sí sola.
        var artifactIssues = report.Hallazgos
            .Where(f => f.Id.StartsWith("TSPLUS-CONFIG-ZERO-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-CONFIG-INI-STRUCTURE-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-CONFIG-JSON-STRUCTURE-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-CONFIG-XML-STRUCTURE-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-CONFIG-JS-STRUCTURE-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-CONFIG-KV-STRUCTURE-", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(f => f.Severidad)
            .Take(8)
            .ToList();

        var artifactIndex = 0;
        foreach (var issue in artifactIssues)
        {
            var file = issue.Evidencia.FirstOrDefault(e => e.Clave.Equals("Archivo", StringComparison.OrdinalIgnoreCase))?.Valor;
            var fileName = string.IsNullOrWhiteSpace(file) ? null : Path.GetFileName(file);
            var related = tsplusErrors
                .Where(e => e.Timestamp.HasValue && IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
                .Where(e => e.Componente.Contains(issue.Componente, StringComparison.OrdinalIgnoreCase) ||
                            (!string.IsNullOrWhiteSpace(fileName) && $"{e.Mensaje} {e.Archivo} {e.Componente}".Contains(fileName, StringComparison.OrdinalIgnoreCase)))
                .OrderByDescending(e => e.Timestamp)
                .FirstOrDefault();
            artifactIndex++;
            drafts.Add(new CandidateDraft(
                artifactIndex == 1 ? "ROOT-TSPLUS-CONFIG-ARTIFACT" : $"ROOT-TSPLUS-CONFIG-ARTIFACT-{artifactIndex}",
                string.IsNullOrWhiteSpace(fileName) ? issue.Componente : $"{issue.Componente} / {fileName}",
                DiagnosticLayer.Tsplus,
                related is null ? 79 : 93,
                related is null ? ConfidenceLevel.Media : ConfidenceLevel.Alta,
                related is null
                    ? "TDM detectó una anomalía verificable en un artefacto de configuración TSplus."
                    : "TDM correlacionó una anomalía de configuración TSplus con una señal operativa compatible en el periodo analizado.",
                related is null
                    ? "La estructura, legibilidad o integridad física del archivo es anómala. Sin una señal funcional compatible se mantiene como candidato y no como originador confirmado."
                    : "El artefacto presenta una anomalía verificable y una señal TSplus compatible aparece en la misma ventana. Esta combinación sustenta investigar primero el componente y archivo indicados.",
                Merge(issue.Evidencia,
                    new EvidenceItem("Señal operativa correlacionada", related?.Tipo ?? "No"),
                    related?.Timestamp is DateTimeOffset ats ? new EvidenceItem("Hora señal", ats.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")) : null),
                null,
                related?.Timestamp,
                "TSPLUS",
                ProductFromText(issue.Componente)));
        }

        var changedArtifacts = report.Eventos
            .Where(e => e.Tipo == "TSPLUS_CONFIG_ARTIFACT_STATE" && e.Timestamp.HasValue)
            .Where(e => EvidenceValue(e, "Modificado en ventana")?.Equals("Sí", StringComparison.OrdinalIgnoreCase) == true)
            .Where(e => EvidenceValue(e, "Conocido por TDM")?.Equals("Sí", StringComparison.OrdinalIgnoreCase) == true)
            .OrderByDescending(e => e.Timestamp)
            .Take(12)
            .ToList();
        foreach (var changed in changedArtifacts)
        {
            var file = EvidenceValue(changed, "Archivo") ?? changed.Archivo ?? changed.Componente;
            var fileName = Path.GetFileName(file);
            var related = tsplusErrors
                .Where(e => e.Timestamp.HasValue && e.Timestamp >= changed.Timestamp && e.Timestamp <= changed.Timestamp + TimeSpan.FromMinutes(15))
                .Where(e => e.Componente.Contains(changed.Componente, StringComparison.OrdinalIgnoreCase) ||
                            (!string.IsNullOrWhiteSpace(fileName) && $"{e.Mensaje} {e.Archivo}".Contains(fileName, StringComparison.OrdinalIgnoreCase)))
                .OrderBy(e => e.Timestamp)
                .FirstOrDefault();
            if (related is null) continue;

            drafts.Add(new CandidateDraft(
                $"ROOT-TSPLUS-CONFIG-CHANGE-{SafeArtifactId(fileName)}",
                $"{changed.Componente} / {fileName}",
                DiagnosticLayer.Tsplus,
                84,
                ConfidenceLevel.Media,
                "Un artefacto de configuración TSplus conocido cambió antes de una señal operativa compatible.",
                "La secuencia temporal es relevante pero no demuestra por sí sola que el cambio haya causado la falla. TDM la conserva como candidato principal sólo cuando componente/archivo y señal son compatibles.",
                Merge(changed.Evidencia ?? [],
                    new EvidenceItem("Señal posterior", related.Tipo),
                    new EvidenceItem("Hora cambio", changed.Timestamp!.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                    new EvidenceItem("Hora señal", related.Timestamp!.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss"))),
                null,
                related.Timestamp,
                "TSPLUS",
                changed.Producto));
        }

        // Integridad física de componentes TSplus. Un binario vacío es una anomalía confirmada,
        // pero sólo se eleva como causa del incidente si existe evidencia operativa que mencione
        // el mismo archivo/componente. Los cambios recientes de archivos se conservan únicamente como contexto.
        var integrityIssues = report.Hallazgos
            .Where(f => f.Id.StartsWith("TSPLUS-INTEGRITY-", StringComparison.OrdinalIgnoreCase) ||
                        f.Id.StartsWith("TSPLUS-ZERO-BINARY-", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(f => f.Severidad)
            .ToList();
        if (integrityIssues.Count > 0)
        {
            var issue = integrityIssues[0];
            var file = issue.Evidencia.FirstOrDefault(e => e.Clave.Equals("Archivo", StringComparison.OrdinalIgnoreCase))?.Valor;
            var fileName = string.IsNullOrWhiteSpace(file) ? null : Path.GetFileName(file);
            var related = report.Eventos
                .Where(e => e.Timestamp.HasValue && e.Severidad != DiagnosticSeverity.Informativo)
                .Where(e => IsNearAnalysisEnd(report, e, TimeSpan.FromMinutes(15)))
                .Where(e => !e.Fuente.Equals("TDM", StringComparison.OrdinalIgnoreCase))
                .Where(e => !string.IsNullOrWhiteSpace(fileName) &&
                            ($"{e.Mensaje} {e.Archivo} {e.Componente}").Contains(fileName!, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(e => e.Timestamp)
                .FirstOrDefault();

            drafts.Add(new CandidateDraft(
                "ROOT-TSPLUS-INTEGRITY",
                string.IsNullOrWhiteSpace(fileName) ? "Integridad de archivos TSplus" : $"Integridad TSplus / {fileName}",
                DiagnosticLayer.Tsplus,
                related is null ? 82 : 94,
                related is null ? ConfidenceLevel.Media : ConfidenceLevel.Alta,
                related is null
                    ? "TDM confirmó una inconsistencia física en un archivo de instalación TSplus."
                    : "TDM correlacionó una inconsistencia física de archivo TSplus con un error operativo que referencia el mismo componente.",
                related is null
                    ? "El archivo observado es físicamente anómalo, pero todavía no existe evidencia suficiente para afirmar que intervino en el incidente actual. Debe validarse antes de reinstalar o reparar componentes generales de Windows."
                    : "La misma ruta/componente aparece en una inconsistencia física y en evidencia operativa del periodo visible. La investigación debe comenzar por la integridad/instalación de ese componente TSplus.",
                Merge(issue.Evidencia,
                    new EvidenceItem("Error operativo correlacionado", related?.Tipo ?? "No"),
                    related?.Timestamp is DateTimeOffset its ? new EvidenceItem("Hora del error", its.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")) : null),
                null,
                related?.Timestamp,
                "TSPLUS",
                ProductFromText(issue.Componente)));
        }

    }
    private static string SafeArtifactId(string? value)
    {
        var cleaned = new string((value ?? string.Empty)
            .Where(char.IsLetterOrDigit)
            .Select(char.ToUpperInvariant)
            .Take(24)
            .ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "CONFIG" : cleaned;
    }

}
