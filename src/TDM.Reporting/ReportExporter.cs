using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TDM.Models;

namespace TDM.Reporting;

public sealed record ReportExportResult(string JsonPath, string HtmlPath);

public static class ReportExporter
{
public static async Task<ReportExportResult> ExportAsync(
        DiagnosticReport report,
        string directory,
        CancellationToken ct = default,
        DiagnosticReport? previousReport = null)
    {
        Directory.CreateDirectory(directory);
        // Exportaci�n segura por defecto: contenido y nombre de archivo usan la misma
        // pseudonimizaci�n para no filtrar hostname/identidades fuera de TDM.
        var safeReport = SupportBundleSanitizer.Sanitize(report);
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
        var safeHost = SanitizeFileName(safeReport.Sistema.Equipo);
        var baseName = $"TDM-{safeHost}-{stamp}-{Guid.NewGuid().ToString("N")[..6]}";
        var jsonPath = Path.Combine(directory, baseName + ".json");
        var htmlPath = Path.Combine(directory, baseName + ".html");

        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        var json = JsonSerializer.Serialize(safeReport, options);
        // S9: valida que el JSON serializado est� bien formado antes de escribirlo; un truncado
        // parcial ya no puede exportarse como �xito operativo.
        try { using var _ = JsonDocument.Parse(json); }
        catch (JsonException ex) { throw new IOException("La serializaci�n del reporte produjo JSON inv�lido.", ex); }
        await File.WriteAllTextAsync(jsonPath, json, new UTF8Encoding(false), ct);
        var html = BuildHtml(safeReport, sanitized: true);
        // P0-diff: tarjeta d�a-a-d�a. Se calcula sobre versiones sanitizadas (la anterior se
        // sanitiza igual que la actual) y se inyecta antes del cierre del body. Sin reporte
        // anterior o sin cambios, el HTML es byte-id�ntico al de antes. El diff jam�s tumba la exportaci�n.
        if (previousReport is not null)
        {
            try
            {
                var diff = ReportDiffer.Compute(SupportBundleSanitizer.Sanitize(previousReport), safeReport);
                if (diff is { Changes.Count: > 0 })
                    html = html.Replace("</body>", ReportDiffer.ToHtmlCard(diff) + "</body>", StringComparison.Ordinal);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                _ = ex;
            }
        }
        await File.WriteAllTextAsync(htmlPath, html, new UTF8Encoding(false), ct);

        // P23: un reporte vac�o/corrupto nunca debe exportarse como �xito operativo.
        var jsonBytes = new FileInfo(jsonPath).Length;
        var htmlBytes = new FileInfo(htmlPath).Length;
        if (jsonBytes <= 0 || htmlBytes <= 0)
            throw new IOException($"La exportaci�n gener� archivos vac�os: json={jsonBytes} bytes, html={htmlBytes} bytes.");

        // Mission Assurance: la acci�n Generar reporte produce exclusivamente dos archivos operativos:
        // HTML para lectura humana y JSON para evidencia estructurada. No se crea ZIP ni archivos auxiliares.
        return new ReportExportResult(jsonPath, htmlPath);
    }

    private static string BuildHtml(DiagnosticReport report, bool sanitized = false)
    {
        static string H(string? value) => WebUtility.HtmlEncode(value ?? "");

        static bool IsDiagnosticHeading(string line)
        {
            var text = line.Trim();
            if (text.Length < 3 || text.Length > 96 || text.StartsWith("[", StringComparison.Ordinal)) return false;
            if (text.EndsWith(":", StringComparison.Ordinal)) text = text[..^1].TrimEnd();
            else if (text.Contains(':')) return false;
            var letters = text.Where(char.IsLetter).ToArray();
            return letters.Length >= 2 && letters.All(char.IsUpper);
        }

        static bool TryDiagnosticLabel(string line, out int labelLength)
        {
            labelLength = 0;
            if (string.IsNullOrWhiteSpace(line)) return false;
            var first = 0;
            while (first < line.Length && char.IsWhiteSpace(line[first])) first++;
            if (first >= line.Length) return false;
            var semantic = line[first..];
            if (semantic.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                semantic.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
                semantic.StartsWith("file://", StringComparison.OrdinalIgnoreCase)) return false;
            if (char.IsDigit(line[first]) && line.AsSpan(first).IndexOf('/') is >= 0 and < 12) return false;
            var colon = line.IndexOf(':', first);
            if (colon <= first) return false;
            if (colon == first + 1 && char.IsLetter(line[first]) && colon + 1 < line.Length &&
                (line[colon + 1] == '\\' || line[colon + 1] == '/')) return false;
            var candidate = line[first..colon].Trim();
            if (candidate.Length is < 1 or > 88 || candidate.Contains('\\') || candidate.Contains('|')) return false;
            if (!candidate.Any(char.IsLetter)) return false;
            labelLength = colon + 1;
            return true;
        }

        static string RenderDiagnosticText(string text)
        {
            var html = new StringBuilder();
            foreach (var rawLine in (text ?? string.Empty).Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n').Split('\n'))
            {
                if (string.IsNullOrWhiteSpace(rawLine))
                {
                    html.Append("<div class='diag-gap'></div>");
                    continue;
                }
                if (IsDiagnosticHeading(rawLine))
                {
                    html.Append($"<div class='diag-heading'>{H(rawLine.ToUpperInvariant())}</div>");
                    continue;
                }

                const string separator = " | ";
                var parts = rawLine.Split(separator, StringSplitOptions.None);
                var hasLabel = parts.Any(part => TryDiagnosticLabel(part, out _));
                html.Append("<div class='diag-line'>");
                if (!hasLabel) html.Append(H(rawLine));
                else
                {
                    for (var i = 0; i < parts.Length; i++)
                    {
                        var part = parts[i];
                        if (TryDiagnosticLabel(part, out var length))
                        {
                            html.Append($"<strong>{H(part[..length])}</strong>");
                            if (length < part.Length) html.Append(H(part[length..]));
                        }
                        else html.Append(H(part));
                        if (i < parts.Length - 1) html.Append(" <span class='diag-sep'>|</span> ");
                    }
                }
                html.Append("</div>");
            }
            return html.ToString();
        }
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang='es-MX'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>");
        sb.Append("<title>TDM - Reporte de diagnóstico</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:22px auto;padding:0 20px;max-width:1180px;color:#e6edf5;background:#070b11;line-height:1.42}h1{margin:0;color:#f4f8fb;font-size:28px}h2{font-size:18px;margin:0 0 12px;color:#39d0ff;text-transform:uppercase;letter-spacing:.02em}h3{color:#39d0ff;text-transform:uppercase;letter-spacing:.02em}.report-sub{color:#8fa3b8;margin:4px 0 18px}.muted{color:#8fa3b8}.card{background:#0d141e;border:1px solid #243247;border-radius:12px;padding:12px;margin:8px 0;box-shadow:0 8px 28px rgba(0,0,0,.18)}.quick-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.quick-card{background:#101b27;border:1px solid #243247;border-radius:10px;padding:12px;min-height:70px}.quick-label{color:#39d0ff;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.02em}.quick-value{font-size:17px;font-weight:700;margin-top:5px}.state-ok{color:#67e8a5}.state-warn{color:#ffd166}.state-error{color:#ff8a3d}.state-muted{color:#8fa3b8}.support-main{border-left:4px solid #39d0ff}.support-title{font-size:21px;font-weight:700;margin:4px 0}.support-meta{display:flex;gap:16px;flex-wrap:wrap;color:#e6edf5;font-size:12px}.support-meta strong{color:#fff}.support-evidence{margin-top:9px;color:#b7c8d8;font-size:12px}.impact-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.impact-item{background:#101b27;border:1px solid #243247;border-radius:8px;padding:10px}.step{display:grid;grid-template-columns:32px 1fr;gap:8px;align-items:start;padding:8px 0;border-bottom:1px solid #1d2a3a}.step-num{width:24px;height:24px;border-radius:50%;background:#173a4a;color:#67d9ff;display:flex;align-items:center;justify-content:center;font-weight:700}.compact-timeline{display:grid;gap:6px}.compact-event{display:grid;grid-template-columns:105px 26px 1fr;gap:8px;align-items:start;padding:8px 0;border-bottom:1px solid #1d2a3a}.compact-time{color:#8fa3b8;font-size:12px}.technical-bundle{margin:16px 0;border:1px solid #31516a;border-radius:12px;background:#0a111a}.technical-bundle>summary{cursor:pointer;padding:15px 17px;font-weight:700;color:#67d9ff;list-style:none}.technical-bundle>summary::-webkit-details-marker{display:none}.technical-bundle>summary:before{content:'＋ ';color:#39d0ff}.technical-bundle[open]>summary:before{content:'− '}.technical-bundle>.card{margin:12px}.card details>summary{cursor:pointer;color:#67d9ff}.card table{font-size:13px}table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid #1d2a3a;text-align:left;padding:8px;vertical-align:top}th{color:#fff;font-weight:700}.critical{font-weight:700;color:#ff4d4f}.error{font-weight:700;color:#ff8a3d}.info{color:#ffffff}.mono{font-family:Consolas,monospace;white-space:pre-wrap;color:#dbe8f2}.diag-text{font-family:Consolas,monospace;color:#fff}.diag-line{white-space:pre-wrap;min-height:1.35em}.diag-line strong{font-weight:700;color:#fff}.diag-heading{color:#39d0ff;font-weight:700;text-transform:uppercase;letter-spacing:.02em;margin:12px 0 5px}.diag-gap{height:.7em}.diag-sep{color:#8fa3b8}.badge{display:inline-block;border:1px solid #31516a;border-radius:999px;padding:2px 8px;margin-right:6px;color:#67d9ff}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.metric,.flow-node,.dep{background:#101b27;border:1px solid #243247;border-radius:10px;padding:12px}.metric .label{color:#8fa3b8;font-size:12px}.metric .value{font-weight:700;font-size:18px;margin-top:7px}.flow{display:flex;align-items:stretch;gap:7px;overflow-x:auto;padding-bottom:4px}.flow-node{min-width:185px;flex:1}.flow-node .kind{color:#8fa3b8;font-size:11px}.flow-arrow{display:flex;align-items:center;color:#39d0ff;font-size:22px}.deps{display:flex;gap:7px;overflow-x:auto}.dep{min-width:180px}.ok{border-color:#236b52}.accent{border-color:#39d0ff}.warn{border-color:#ffd166}.error{border-color:#ff8a3d}.critical{border-color:#ff4d4f}.timeline-v{display:grid;gap:7px}.timeline-event{background:#101b27;border-left:3px solid #39d0ff;border-radius:6px;padding:10px}.timeline-event.info{border-left-color:#ffffff}.timeline-event.warn{border-left-color:#ffd166}.timeline-event.error{border-left-color:#ff8a3d}.timeline-event.critical{border-left-color:#ff4d4f}a{color:#67d9ff}@media(max-width:800px){.quick-grid,.impact-grid,.grid{grid-template-columns:1fr}.metrics{grid-template-columns:1fr 1fr}.flow{flex-direction:column}.flow-arrow{transform:rotate(90deg);justify-content:center}.compact-event{grid-template-columns:85px 22px 1fr}}@media print{body{background:#fff;color:#111}.card,.quick-card,.impact-item,.technical-bundle{background:#fff;border-color:#ccc;box-shadow:none}h1,h2,h3,.mono{color:#111}.muted,.report-sub,.quick-label,.support-meta,.compact-time{color:#555}th{color:#111}.technical-bundle{display:block}.technical-bundle>summary{color:#111}.technical-bundle:not([open])>:not(summary){display:none!important}}</style></head><body>");
        sb.Append("<h1>TSplus Diagnostic Monitor (TDM)</h1>");
        var quickPeriodStart = report.PeriodoAnalizadoInicio == default ? report.Inicio - report.Lookback : report.PeriodoAnalizadoInicio;
        var quickPeriodEnd = report.PeriodoAnalizadoFin == default ? report.Inicio : report.PeriodoAnalizadoFin;
        sb.Append($"<p class='report-sub'>Reporte de soporte · {H(report.Sistema.Equipo)} · {quickPeriodStart.ToLocalTime():dd/MM/yyyy HH:mm}–{quickPeriodEnd.ToLocalTime():HH:mm}</p>");
        if (sanitized) sb.Append("<div class='card warn'><strong>PAQUETE SANITIZADO</strong><span class='muted'> · Revise antes de compartir.</span></div>");

        var quickCause = report.CausaRaizPrincipal;
        var quickResponsibility = CausalResponsibilityFormatter.Resolve(quickCause);
        var quickImpact = report.ImpactoFuncional;
        var quickState = ExecutiveState(report, quickCause);
        var quickCoverage = report.CoberturaDiagnostica is null ? "N/D" : $"{report.CoberturaDiagnostica.Score}/100";
        var criticalCoverageComplete = report.CoberturaDiagnostica is not null && !report.CoberturaDiagnostica.Fuentes.Any(x => x.Critica && x.Estado is not "Disponible" and not "No aplica");
        var quickQuality = report.PrecisionDiagnostica is null ? "N/D" : $"{report.PrecisionDiagnostica.Score}/100";
        var quickConfidence = quickCause?.Confianza.ToString() ?? "Insuficiente";
        var quickImpactState = quickImpact is null ? "No evaluado" : CompactImpactState(quickImpact.EstadoGeneral);
        sb.Append("<div class='quick-grid'>");
        QuickCard("ESTADO", quickState, ExecutiveStateCss(quickState));
        var directImpact = quickImpact?.Impactos.FirstOrDefault(i => i.Estado is FunctionalImpactState.Interrumpido or FunctionalImpactState.Degradado);
        QuickCard("ORIGEN", quickCause is null ? (directImpact is null ? "No confirmado" : "Impacto confirmado · causa no demostrada") : $"{quickResponsibility.EtiquetaOrigen}: {quickResponsibility.OriginadorEspecifico} / {quickResponsibility.OrigenGeneral}", quickCause is null ? "state-muted" : "");
        QuickCard("CONFIANZA", quickConfidence, quickCause is null ? "state-muted" : "");
        QuickCard("IMPACTO", quickImpactState, ExecutiveStateCss(quickImpactState));
        sb.Append("</div>");

        sb.Append("<div class='card support-main'><div class='quick-label'>DIAGNÓSTICO PRINCIPAL</div>");
        var quickReading = quickCause is null
            ? directImpact is null ? (report.Hallazgos.Count == 0 ? "Sin causa identificada" : "Falla detectada") : $"{directImpact.Funcion}: impacto confirmado"
            : quickCause.Componente;
        var quickExplanation = quickCause is null
            ? directImpact is null
                ? (report.Hallazgos.Count == 0
                    ? (criticalCoverageComplete
                        ? "No se identificó una falla con las fuentes críticas evaluadas en esta vista."
                        : "No se identificó una falla con la evidencia disponible. La cobertura crítica es incompleta y no permite descartar las fuentes NO EVALUADAS.")
                    : "Se detectaron hallazgos, pero la evidencia actual no forma una cadena causal suficiente.")
                : $"{CompactForReport(directImpact.Resumen, 180)} La causa del fallo subyacente no está demostrada."
            : $"{quickResponsibility.EtiquetaOrigen}. {CompactForReport(quickCause.Resumen, 150)}";
        sb.Append($"<div class='support-title'>{H(quickReading)}</div>");
        sb.Append($"<div>{H(quickExplanation)}</div>");
        sb.Append("<div class='support-meta'>");
        sb.Append($"<span>Calidad: <strong>{H(quickQuality)}</strong></span>");
        sb.Append($"<span>Cobertura: <strong>{H(quickCoverage)}</strong></span>");
        sb.Append($"<span>Modo: <strong>{H(report.DiagnosticoContinuo ? "Continuo" : "Puntual")}</strong></span>");
        sb.Append("</div>");
        if (quickCause?.Evidencia.Count > 0)
        {
            var evidence = quickCause.Evidencia
                .Where(x => !string.IsNullOrWhiteSpace(x.Valor) && !x.Valor.Equals("N/D", StringComparison.OrdinalIgnoreCase))
                .Take(3)
                .Select(x => $"{x.Clave}: {CompactForReport(x.Valor, 58)}");
            var evidenceText = string.Join(" / ", evidence);
            if (!string.IsNullOrWhiteSpace(evidenceText)) sb.Append($"<div class='support-evidence'><strong>Evidencia:</strong> {H(evidenceText)}</div>");
        }
        sb.Append("</div>");

        if (quickImpact?.Impactos.Count > 0)
        {
            var affected = quickImpact.Impactos
                .Where(i => i.Estado is FunctionalImpactState.Degradado or FunctionalImpactState.Interrumpido)
                .Take(4)
                .ToList();
            sb.Append("<div class='card'><h2>Impacto</h2>");
            if (affected.Count == 0)
            {
                sb.Append("<p class='state-ok'><strong>Sin impacto funcional confirmado en la vista actual.</strong></p>");
            }
            else
            {
                sb.Append("<div class='impact-grid'>");
                foreach (var item in affected)
                {
                    var stateText = CompactImpactState(item.Estado);
                    sb.Append($"<div class='impact-item'><div class='quick-label'>{H(item.Funcion)}</div><div class='quick-value {ExecutiveStateCss(stateText)}'>{H(stateText)}</div><div class='muted'>{H(CompactForReport(item.Modulo, 54))}</div></div>");
                }
                sb.Append("</div>");
            }
            sb.Append("</div>");
        }

        sb.Append("<div class='grid'>");
        sb.Append("<div class='card'><h2>Qué revisar</h2>");
        var quickSteps = report.PlanAccion?.DondeEmpezar.Take(2).ToList() ?? [];
        if (quickSteps.Count == 0) sb.Append("<p class='muted'>Reproducir el síntoma si es seguro y recopilar evidencia adicional.</p>");
        else for (var i = 0; i < quickSteps.Count; i++) sb.Append($"<div class='step'><div class='step-num'>{i + 1}</div><div>{H(CompactForReport(quickSteps[i].Accion, 145))}</div></div>");
        sb.Append("</div>");
        sb.Append("<div class='card'><h2>Últimas señales relevantes</h2><div class='compact-timeline'>");
        var quickEvents = BuildCompactReportEventGroups(report).TakeLast(4).ToList();
        if (quickEvents.Count == 0) sb.Append("<p class='muted'>Sin actividad relevante fechada en la vista.</p>");
        foreach (var group in quickEvents)
        {
            var time = group.Count > 1 && group.First != group.Last ? $"{group.First.ToLocalTime():HH:mm:ss}–{group.Last.ToLocalTime():HH:mm:ss}" : group.Last.ToLocalTime().ToString("HH:mm:ss");
            var count = group.Count > 1 ? $" ×{group.Count}" : string.Empty;
            var icon = group.Severity >= DiagnosticSeverity.Error ? "✕" : group.Severity == DiagnosticSeverity.Advertencia ? "⚠" : "✓";
            var css = group.Severity >= DiagnosticSeverity.Error ? "state-error" : group.Severity == DiagnosticSeverity.Advertencia ? "state-warn" : "state-ok";
            sb.Append($"<div class='compact-event'><div class='compact-time'>{H(time)}</div><div class='{css}'>{icon}</div><div><strong>{H(group.Component)}{H(count)}</strong><div class='muted'>{H(CompactForReport(group.Detail, 90))}</div></div></div>");
        }
        sb.Append("</div></div></div>");

        sb.Append("<details class='technical-bundle'><summary>Detalle técnico completo</summary>");
        sb.Append("<div class='card'><h2>Resumen técnico</h2><table>");
        Row("Equipo", report.Sistema.Equipo); Row("Sistema", $"{report.Sistema.SistemaOperativo} {report.Sistema.Version} (build {report.Sistema.Build}, {report.Sistema.Arquitectura})");
        Row("TSplus Remote Access", report.Sistema.TsplusDetectado ? "Detectado" : "No detectado");
        if (report.Sistema.TsplusDetectado) { Row("Versión TSplus", report.Sistema.TsplusVersion ?? "N/D"); Row("Ruta TSplus", report.Sistema.TsplusRuta ?? "N/D"); }
        var periodoInicio = report.PeriodoAnalizadoInicio == default ? report.Inicio - report.Lookback : report.PeriodoAnalizadoInicio;
        var periodoFin = report.PeriodoAnalizadoFin == default ? report.Inicio : report.PeriodoAnalizadoFin;
        var evidenceLookback = report.EvidenciaDisponibleLookback <= TimeSpan.Zero ? report.Lookback : report.EvidenciaDisponibleLookback;
        var evidenceStart = report.PeriodoEvidenciaInicio == default ? periodoInicio : report.PeriodoEvidenciaInicio;
        var evidenceEnd = report.PeriodoEvidenciaFin == default ? periodoFin : report.PeriodoEvidenciaFin;
        Row("Evidencia disponible", $"{FormatLookback(evidenceLookback)} · {evidenceStart.ToLocalTime():dd/MM/yyyy HH:mm:ss} - {evidenceEnd.ToLocalTime():dd/MM/yyyy HH:mm:ss}");
        Row("Vista actual", FormatLookback(report.Lookback));
        Row("Modo de vista", "Filtro en memoria; cambiar el periodo no relee el servidor");
        Row("Modo de diagnóstico", report.DiagnosticoContinuo ? "Continuo · evidencia incremental compartida con Observabilidad" : "Puntual");
        if (report.DiagnosticoContinuo)
        {
            Row("Actualización continua", $"cada {report.IntervaloContinuoSegundos} s · muestras={report.MuestrasContinuas}");
            Row("Última actualización continua", report.UltimaActualizacionContinua?.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") ?? "Pendiente");
        }
        Row("Periodo visible", $"{periodoInicio.ToLocalTime():dd/MM/yyyy HH:mm:ss} - {periodoFin.ToLocalTime():dd/MM/yyyy HH:mm:ss}");
        Row("Ejecución TDM", $"{report.Inicio.ToLocalTime():dd/MM/yyyy HH:mm:ss} - {report.Fin.ToLocalTime():dd/MM/yyyy HH:mm:ss}");
        Row("Hallazgos", report.Hallazgos.Count.ToString()); Row("Observaciones normalizadas", report.Eventos.Count.ToString()); Row("Incidentes agrupados", report.Incidentes.Count.ToString()); Row("Candidatos a causa raíz", report.CausasRaiz.Count.ToString()); Row("Patrones detectados", report.PatronesFalla.Count.ToString());
        var localHistory = report.Eventos.LastOrDefault(e => e.Tipo == "TDM_LOCAL_HISTORY_STATUS");
        if (localHistory?.Evidencia is { Count: > 0 })
        {
            Row("Historial local TDM", "Activo · JSON/JSONL sin motor de base de datos");
            Row("Ruta de historial", localHistory.Evidencia.FirstOrDefault(x => x.Clave == "Almacén")?.Valor ?? "N/D");
            Row("Transiciones nuevas", localHistory.Evidencia.FirstOrDefault(x => x.Clave == "Transiciones detectadas")?.Valor ?? "0");
            Row("Baseline sano", localHistory.Evidencia.FirstOrDefault(x => x.Clave == "Baseline sano")?.Valor ?? "No configurado");
        }
        if (report.RendimientoDiagnostico is { } performance)
        {
            Row("Rendimiento TDM", $"{performance.DuracionTotalMs / 1000d:F1} s · collectors={performance.CollectorsEjecutados} · timeout={performance.CollectorsConTimeout} · errores={performance.CollectorsConError}");
            Row("Collector más lento", $"{performance.CollectorMasLento} · {performance.CollectorMasLentoMs:F0} ms");
        }
        if (report.CoberturaDiagnostica is { } summaryCoverage)
            Row("Cobertura diagnóstica", $"{summaryCoverage.Score}/100 · {summaryCoverage.Nivel} · limitaciones={summaryCoverage.Limitaciones.Count}");
        if (report.PrecisionDiagnostica is { } precision)
        {
            Row("Calidad de evidencia", $"{precision.Score}/100 · {precision.Nivel} (no es probabilidad)");
            Row("Cobertura crítica", precision.CoberturaCompleta ? "Completa" : $"Incompleta · {precision.FuentesBloqueadas} fuente(s) bloqueada(s)");
            Row("Señales causales / contexto", $"{precision.SenalesCausales} / {precision.EventosContexto}");
            Row("Conflicto de origen", precision.OrigenEnConflicto ? "Sí" : "No");
        }
        sb.Append("</table></div>");

        var visualCause = report.CausaRaizPrincipal;
        var visualHistoricalEvents = report.Eventos.Count(e => !IsCurrentStateEventForReport(e));
        var visualState = InvestigationStateForReport(visualCause);
        sb.Append("<div class='card'><h2>Vista gráfica del incidente</h2><div class='metrics'>");
        Metric("Estado de investigación", visualState);
        var visualResponsibility = CausalResponsibilityFormatter.Resolve(visualCause);
        Metric("Origen técnico", visualCause is null ? "Sin candidato" : $"{visualResponsibility.EtiquetaOrigen} · {visualResponsibility.OriginadorEspecifico} · {visualResponsibility.OrigenGeneral}");
        Metric("Ventana / eventos", $"{FormatLookback(report.Lookback)} · {visualHistoricalEvents} eventos");
        Metric("Patrones", $"{report.PatronesFalla.Count(p => p.Incidentes > 1)} recurrente(s)");
        sb.Append("</div>");

        if (visualCause is not null)
        {
            string Evidence(string key) => visualCause.Evidencia.FirstOrDefault(e => e.Clave.Contains(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
            var action = report.PlanAccion?.DondeEmpezar.FirstOrDefault()?.Accion
                         ?? (string.IsNullOrWhiteSpace(visualCause.SolucionSugerida) ? "Recopilar evidencia adicional" : FirstSentenceForReport(visualCause.SolucionSugerida));
            var responsibility = CausalResponsibilityFormatter.Resolve(visualCause);
            var mechanism = Evidence("Tipo de excepción") == "N/D" ? visualCause.Resumen : Evidence("Tipo de excepción");
            var technicalOrigin = Evidence("Componente interno observado");
            if (technicalOrigin == "N/D") technicalOrigin = Evidence("Componente semántico");
            sb.Append("<h3>Cadena causal</h3><div class='flow'>");
            FlowNode($"{responsibility.EtiquetaOrigen} · {responsibility.OrigenGeneral}", responsibility.OriginadorEspecifico, "accent"); Arrow();
            FlowNode("MECANISMO / EVIDENCIA", mechanism, "warn"); Arrow();
            FlowNode("AFECTADO", $"{responsibility.ComponenteAfectado} · TSplus: {responsibility.RolTsplus}", ""); Arrow();
            if (report.ImpactoFuncional is { } visualImpact && visualImpact.Impactos.Count > 0)
            {
                var strongestImpact = visualImpact.Impactos.OrderByDescending(i => i.Estado switch
                {
                    FunctionalImpactState.Interrumpido => 4,
                    FunctionalImpactState.Degradado => 3,
                    FunctionalImpactState.Indeterminado => 2,
                    _ => 1
                }).First();
                FlowNode("IMPACTO", $"{strongestImpact.Funcion}: {strongestImpact.Estado}", strongestImpact.Estado == FunctionalImpactState.Interrumpido ? "critical" : strongestImpact.Estado == FunctionalImpactState.Degradado ? "error" : ""); Arrow();
            }
            FlowNode("ESTADO", $"{visualState} · Windows: {responsibility.RolWindows} · origen técnico: {(technicalOrigin == "N/D" ? visualCause.Componente : technicalOrigin)}", ""); Arrow();
            FlowNode("SIGUIENTE PASO", action, "ok");
            sb.Append("</div>");
        }
        else
        {
            sb.Append("<p class='muted'>No existe un candidato causal suficiente en la vista temporal actual.</p>");
        }

        var visualTimeline = report.Eventos
            .Where(e => !IsCurrentStateEventForReport(e) && e.Timestamp.HasValue)
            .Where(e => e.Severidad != DiagnosticSeverity.Informativo || IsLikelyCausalForReport(e))
            .OrderByDescending(e => e.Timestamp)
            .Take(7)
            .OrderBy(e => e.Timestamp)
            .ToList();
        sb.Append("<h3>Secuencia causal seleccionada</h3><div class='timeline-v'>");
        if (visualTimeline.Count == 0) sb.Append("<div class='muted'>Sin eventos causales/operativos fechados en esta vista.</div>");
        foreach (var e in visualTimeline)
        {
            var cls = e.Severidad switch
            {
                DiagnosticSeverity.Critico => "critical",
                DiagnosticSeverity.Error => "error",
                DiagnosticSeverity.Advertencia => "warn",
                _ => "info"
            };
            sb.Append($"<div class='timeline-event {cls}'><strong>{e.Timestamp!.Value.ToLocalTime():HH:mm:ss} · {H(e.Componente)}</strong><br><span class='muted'>{H(e.Tipo)} · {H(e.Capa.ToString())}</span><br>{H(FirstLineForReport(e.Mensaje, e.Tipo))}</div>");
        }
        sb.Append("</div>");

        var visualDependencyHealth = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_DEPENDENCY_HEALTH");
        if (visualDependencyHealth?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Mapa de dependencias</h3><div class='deps'>");
            foreach (var item in visualDependencyHealth.Evidencia.Take(14))
            {
                var cls = DependencyClassForReport(item.Valor);
                sb.Append($"<div class='dep {cls}'><strong>{H(item.Clave)}</strong><br><span class='muted'>{H(CompactForReport(item.Valor, 95))}</span></div>");
            }
            sb.Append("</div>");
        }
        sb.Append("</div>");

        if (report.ImpactoFuncional is { } impactAssessment)
        {
            sb.Append("<div class='card'><h2>Impacto funcional</h2><p><strong>" + H(impactAssessment.EstadoGeneral.ToString()) + "</strong> · " + H(impactAssessment.Resumen) + "</p>");
            if (impactAssessment.Impactos.Count > 0)
            {
                sb.Append("<table><tr><th>Función</th><th>Módulo</th><th>Estado</th><th>Confianza</th><th>Lectura</th></tr>");
                foreach (var item in impactAssessment.Impactos)
                    sb.Append($"<tr><td>{H(item.Funcion)}</td><td>{H(item.Modulo)}</td><td>{H(item.Estado.ToString())}</td><td>{H(item.Confianza.ToString())}</td><td>{H(item.Resumen)}</td></tr>");
                sb.Append("</table>");
            }
            sb.Append("<p class='muted'>TDM separa impacto observado de causa raíz: una falla de un componente complementario no implica por sí sola indisponibilidad global de Remote Access.</p></div>");
        }

        if (report.PlanAccion is { } safePlan)
        {
            sb.Append("<div class='card'><h2>Plan de actuación seguro</h2><p>" + H(safePlan.Resumen) + "</p><div class='grid'>");
            sb.Append("<div><h3>Dónde empezar</h3><ol>");
            foreach (var step in safePlan.DondeEmpezar) sb.Append($"<li><strong>{H(step.Accion)}</strong><br><span class='muted'>{H(step.Motivo)}</span></li>");
            sb.Append("</ol></div><div><h3>Qué no tocar primero</h3><ul>");
            foreach (var step in safePlan.NoTocarPrimero) sb.Append($"<li><strong>{H(step.Accion)}</strong><br><span class='muted'>{H(step.Motivo)}</span></li>");
            sb.Append("</ul></div></div><h3>Verificaciones</h3><ul>");
            foreach (var step in safePlan.Verificaciones) sb.Append($"<li>{H(step.Accion)} <span class='muted'>— {H(step.Motivo)}</span></li>");
            sb.Append("</ul><p class='muted'>TDM no ejecuta reparaciones automáticamente. Estas acciones están priorizadas para preservar evidencia y reducir cambios innecesarios.</p></div>");
        }

        if (report.PrecisionDiagnostica is { } quality)
        {
            sb.Append("<div class='card'><h2>Calidad diagnóstica</h2><p><strong>" + H($"{quality.Score}/100 · {quality.Nivel}") + "</strong> <span class='muted'>(mide cobertura/coherencia de evidencia; no probabilidad de acierto)</span></p><p>" + H(quality.Resumen) + "</p><table>");
            foreach (var item in quality.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table></div>");
        }

        if (report.CoberturaDiagnostica is { } coverageReport)
        {
            sb.Append("<div class='card'><h2>Cobertura y autodiagnóstico</h2><p><strong>" + H($"{coverageReport.Score}/100 · {coverageReport.Nivel}") + "</strong> · " + H(coverageReport.Resumen) + "</p><table><tr><th>Fuente</th><th>Estado</th><th>Crítica</th><th>Detalle</th></tr>");
            foreach (var source in coverageReport.Fuentes)
                sb.Append($"<tr><td>{H(source.Fuente)}</td><td>{H(source.Estado)}</td><td>{(source.Critica ? "Sí" : "No")}</td><td>{H(source.Detalle)}</td></tr>");
            sb.Append("</table>");
            if (coverageReport.Limitaciones.Count > 0)
            {
                sb.Append("<h3>Limitaciones explícitas</h3><ul>");
                foreach (var limitation in coverageReport.Limitaciones) sb.Append($"<li>{H(limitation)}</li>");
                sb.Append("</ul>");
            }
            sb.Append("<p class='muted'>Una fuente no disponible no se interpreta como componente sano; las hipótesis que dependan de esa fuente permanecen no descartadas.</p></div>");
        }

        if (report.RendimientoDiagnostico is { } perfReport)
        {
            sb.Append("<div class='card'><h2>Rendimiento y hardening</h2><table>");
            Row("Duración", $"{perfReport.DuracionTotalMs / 1000d:F1} s");
            Row("Collectors", perfReport.CollectorsEjecutados.ToString());
            Row("Timeouts", perfReport.CollectorsConTimeout.ToString());
            Row("Errores controlados", perfReport.CollectorsConError.ToString());
            Row("Collector más lento", $"{perfReport.CollectorMasLento} · {perfReport.CollectorMasLentoMs:F0} ms");
            Row("Eventos brutos / normalizados", $"{perfReport.EventosEntrada} / {perfReport.EventosNormalizados}");
            Row("Memoria antes / después", $"{perfReport.MemoriaAntesBytes / 1024d / 1024d:F1} MB / {perfReport.MemoriaDespuesBytes / 1024d / 1024d:F1} MB");
            sb.Append("</table><p class='muted'>Cada collector tiene un límite de 45 s; un timeout reduce cobertura pero no congela indefinidamente el diagnóstico. El motor limita volúmenes extremos preservando primero señales relevantes.</p></div>");
        }

        sb.Append("<div class='card'><h2>Productos TSplus</h2><table><tr><th>Producto</th><th>Instalación</th><th>Operación observada</th><th>Salud</th><th>Relación con Remote Access</th></tr>");
        var hasCanonicalRemoteAccess = report.Eventos.Any(e => e.Tipo == "TSPLUS_PRODUCT_STATE" && e.Producto == TsplusProduct.RemoteAccess);
        foreach (var p in report.Eventos.Where(e => e.Tipo == "TSPLUS_PRODUCT_STATE")
                     .Where(e => !(hasCanonicalRemoteAccess && e.Producto == TsplusProduct.Ninguno && e.Componente.Contains("Remote Access", StringComparison.OrdinalIgnoreCase)))
                     .GroupBy(e => e.Producto)
                     .Select(g => g.OrderByDescending(e => (e.Evidencia?.FirstOrDefault(x => x.Clave == "Instalación")?.Valor ?? "N/D") != "N/D").ThenByDescending(e => e.Timestamp).First())
                     .OrderBy(e => e.Producto))
        {
            string V(string key) => p.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
            sb.Append($"<tr><td>{H(p.Componente)}</td><td>{H(V("Instalación"))}</td><td>{H(V("Operación observada"))}</td><td>{H(V("Salud"))}</td><td>{H(V("Relación con Remote Access"))}</td></tr>");
        }
        sb.Append("</table></div>");

        sb.Append("<div class='card'><h2>Resolución guiada por producto</h2>");
        if (report.ResolucionesGuiadas.Count == 0)
        {
            sb.Append("<p class='muted'>No se generó troubleshooting guiado para esta vista.</p>");
        }
        else
        {
            sb.Append("<table><tr><th>Producto</th><th>Componente</th><th>Estado</th><th>Confianza</th><th>Interpretación</th></tr>");
            foreach (var item in report.ResolucionesGuiadas)
                sb.Append($"<tr><td>{H(item.Producto.ToString())}</td><td>{H(item.Componente)}</td><td>{H(item.Estado.ToString())}</td><td>{H(item.Confianza.ToString())}</td><td>{H(item.CausaProbable)}</td></tr>");
            sb.Append("</table>");

            foreach (var item in report.ResolucionesGuiadas.Where(r => r.Estado is GuidedResolutionState.Error or GuidedResolutionState.Advertencia).Take(12))
            {
                sb.Append($"<h3>{H(item.Producto.ToString())} · {H(item.Componente)} · {H(item.Estado.ToString())}</h3>");
                sb.Append($"<p><strong>Causa probable:</strong> {H(item.CausaProbable)}<br><strong>Impacto:</strong> {H(item.Impacto)}</p>");
                sb.Append("<div class='grid'><div><strong>Cómo corregir / revisar</strong><ol>");
                foreach (var step in item.ComoCorregir) sb.Append($"<li>{H(step)}</li>");
                sb.Append("</ol></div><div><strong>Cómo validar</strong><ol>");
                foreach (var step in item.ComoValidar) sb.Append($"<li>{H(step)}</li>");
                sb.Append("</ol></div></div>");
                if (item.NoHacerPrimero.Count > 0)
                {
                    sb.Append("<strong>Qué no hacer primero</strong><ul>");
                    foreach (var step in item.NoHacerPrimero) sb.Append($"<li>{H(step)}</li>");
                    sb.Append("</ul>");
                }
                sb.Append($"<p class='muted'>Cobertura: {H(item.Cobertura)} · Fuente oficial: <a href='{H(item.UrlOficial)}'>{H(item.FuenteOficial)}</a></p>");
            }
        }
        sb.Append("<p class='muted'>El asistente sólo interpreta evidencia ya recopilada. TDM no ejecuta reparaciones, no reinicia servicios, no cambia políticas y no lee secretos 2FA.</p></div>");

        var moduleHealth = report.Eventos
            .Where(e => e.Tipo == "TSPLUS_MODULE_HEALTH_STATE")
            .GroupBy(e => e.Componente, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Last())
            .OrderByDescending(e => e.Severidad)
            .ThenBy(e => e.Componente)
            .ToList();
        sb.Append("<div class='card'><h2>Salud funcional por módulo</h2>");
        if (moduleHealth.Count == 0) sb.Append("<p class='muted'>No disponible.</p>");
        else
        {
            sb.Append("<table><tr><th>Módulo</th><th>Estado</th><th>Cobertura</th><th>Impacto</th><th>Problemas principales</th></tr>");
            foreach (var m in moduleHealth)
            {
                string V(string key) => m.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                sb.Append($"<tr><td>{H(m.Componente)}</td><td>{H(V("Estado funcional"))}</td><td>{H(V("Cobertura"))}</td><td>{H(V("Impacto funcional"))}</td><td>{H(V("Problemas principales"))}</td></tr>");
            }
            sb.Append("</table>");
        }
        sb.Append("</div>");

        var crashLoops = report.Eventos.Where(e => e.Tipo == "TSPLUS_CRASH_LOOP_PATTERN").OrderByDescending(e => e.Timestamp).ToList();
        if (crashLoops.Count > 0)
        {
            sb.Append("<div class='card'><h2>Recurrencia / crash-loop</h2><table><tr><th>Componente</th><th>Severidad</th><th>Eventos visibles</th><th>Contador reportado</th><th>Última detección</th></tr>");
            foreach (var loop in crashLoops)
            {
                string V(string key) => loop.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                sb.Append($"<tr><td>{H(loop.Componente)}</td><td>{H(loop.Severidad.ToString())}</td><td>{H(V("Eventos visibles equivalentes"))}</td><td>{H(V("Contador SCM/reportado"))}</td><td>{H(V("Última detección visible"))}</td></tr>");
            }
            sb.Append("</table><p class='muted'>La recurrencia confirma inestabilidad; no identifica por sí sola la causa primaria.</p></div>");
        }

        var resourceTrend = report.Eventos.LastOrDefault(e => e.Tipo == "TDM_RESOURCE_TREND");
        if (resourceTrend is not null)
        {
            sb.Append("<div class='card'><h2>Tendencia preventiva de recursos</h2>");
            sb.Append($"<p><strong>{H(resourceTrend.Severidad.ToString())}</strong> — {H(resourceTrend.Mensaje)}</p><table>");
            foreach (var item in resourceTrend.Evidencia ?? []) Row(item.Clave, item.Valor);
            sb.Append("</table><p class='muted'>Estas tendencias se construyen con telemetría local de TDM y no son causa primaria automática.</p></div>");
        }

        sb.Append("<div class='card'><h2>Usuarios, perfiles y sesiones</h2>");
        var userInventory = report.Eventos.LastOrDefault(e => e.Tipo == "USER_SESSION_INVENTORY");
        if (userInventory is null) sb.Append("<p>No disponible.</p>");
        else
        {
            sb.Append("<table>");
            foreach (var item in userInventory.Evidencia ?? []) Row(item.Clave, item.Valor);
            sb.Append("</table>");
            var accounts = report.Eventos.Where(e => e.Tipo == "USER_ACCOUNT_STATE").Take(100).ToList();
            if (accounts.Count > 0)
            {
                sb.Append("<h3>Cuentas locales</h3><table><tr><th>Usuario</th><th>Estado</th><th>Cuenta expira</th><th>Grupos locales</th><th>Perfil</th></tr>");
                foreach (var account in accounts)
                {
                    string A(string key) => account.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                    var state = A("Habilitada") == "Sí" ? (A("Bloqueada") == "Sí" ? "Bloqueada" : "Habilitada") : "Deshabilitada";
                    sb.Append($"<tr><td>{H(A("Usuario"))}</td><td>{H(state)}</td><td>{H(A("Cuenta expira"))}</td><td>{H(A("Grupos locales"))}</td><td>{H(A("Perfil registrado"))}</td></tr>");
                }
                sb.Append("</table>");
            }
            var sessions = report.Eventos.Where(e => e.Tipo == "USER_SESSION_STATE")
                .Where(e => (e.Evidencia?.FirstOrDefault(x => x.Clave == "Usuario")?.Valor ?? "N/D") != "N/D")
                .Take(60).ToList();
            if (sessions.Count > 0)
            {
                sb.Append("<h3>Sesiones observadas</h3><table><tr><th>Usuario</th><th>SessionId</th><th>Estado</th><th>Protocolo</th><th>Cliente</th><th>Perfil</th></tr>");
                foreach (var session in sessions)
                {
                    string V(string key) => session.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                    sb.Append($"<tr><td>{H(V("Dominio"))}\\{H(V("Usuario"))}</td><td>{H(V("SessionId"))}</td><td>{H(V("Estado"))}</td><td>{H(V("Protocolo"))}</td><td>{H(V("Cliente"))}</td><td>{H(V("Perfil"))}</td></tr>");
                }
                sb.Append("</table>");
            }
            var authEvents = report.Eventos
                .Where(e => e.Timestamp.HasValue && e.Tipo is "USER_LOGON_FAILURE" or "USER_NLA_PASSWORD_FAILURE" or "WINDOWS_CREDENTIAL_VALIDATION_FAILURE" or "ACCOUNT_LOCKOUT" or "KERBEROS_PREAUTH_FAILURE")
                .OrderByDescending(e => e.Timestamp)
                .Take(80)
                .ToList();
            if (authEvents.Count > 0)
            {
                sb.Append("<h3>Autenticación e identidad</h3><table><tr><th>Hora</th><th>Usuario</th><th>Evento</th><th>Origen</th><th>Detalle</th></tr>");
                foreach (var auth in authEvents)
                {
                    string V(string key) => auth.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                    var source = V("Equipo originador") != "N/D" ? V("Equipo originador") : V("IP origen") != "N/D" ? V("IP origen") : V("Estación");
                    sb.Append($"<tr><td>{auth.Timestamp!.Value.ToLocalTime():dd/MM/yyyy HH:mm:ss}</td><td>{H(V("Dominio") != "N/D" ? V("Dominio") + "\\" + V("Usuario") : V("Usuario"))}</td><td>{H(auth.Tipo)}</td><td>{H(source)}</td><td>{H(auth.Mensaje)}</td></tr>");
                }
                sb.Append("</table><p class='muted'>Los eventos de autenticación sólo se elevan a causa raíz cuando existe correlación temporal y de identidad con el síntoma RDP/TSplus; un evento aislado no se considera originador.</p>");
            }
            var profileIssues = report.Hallazgos.Where(f => f.Id.StartsWith("USER-PROFILE-", StringComparison.OrdinalIgnoreCase)).ToList();
            if (profileIssues.Count > 0)
            {
                sb.Append("<h3>Anomalías de perfil</h3><table><tr><th>Severidad</th><th>Componente</th><th>Hallazgo</th></tr>");
                foreach (var f in profileIssues.Take(50)) sb.Append($"<tr><td>{H(f.Severidad.ToString())}</td><td>{H(f.Componente)}</td><td>{H(f.Resumen)}</td></tr>");
                sb.Append("</table>");
            }
        }
        sb.Append("<p class='muted'>TDM no recopila contraseñas, hashes ni tokens. La identidad se utiliza para correlacionar cuenta, perfil y sesión.</p></div>");

        sb.Append("<div class='card'><h2>Configuración interna TSplus</h2>");
        var appControlState = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_APPCONTROL_STATE");
        if (appControlState?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Application Control</h3><table>");
            foreach (var item in appControlState.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var publishedApps = report.Eventos.Where(e => e.Tipo == "TSPLUS_PUBLISHED_APPLICATION").ToList();
        if (publishedApps.Count > 0)
        {
            sb.Append("<h3>Aplicaciones publicadas</h3><table><tr><th>Aplicación</th><th>Ruta</th><th>Startup</th><th>Usuarios</th><th>Grupos</th></tr>");
            foreach (var app in publishedApps.Take(100))
            {
                string V(string key) => app.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                sb.Append($"<tr><td>{H(V("Aplicación"))}</td><td>{H(V("Ruta"))}</td><td>{H(V("Startup"))}</td><td>{H(V("Usuarios asignados"))}</td><td>{H(V("Grupos asignados"))}</td></tr>");
            }
            sb.Append("</table>");
        }
        var appSecurity = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_APPCONTROL_SECURITY_STATE");
        if (appSecurity?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Opciones de sesión/publicación</h3><table>");
            foreach (var item in appSecurity.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var applicationFileSet = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_APPLICATION_FILESET_STATE");
        if (applicationFileSet?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Configuración principal de aplicaciones — diagnóstico dirigido</h3><table>");
            foreach (var item in applicationFileSet.Evidencia.Where(x => x.Clave != "Manifest funcional")) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var sessionFileSet = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_SESSION_FILESET_STATE");
        if (sessionFileSet?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Fuentes principales de sesión — diagnóstico dirigido</h3><table>");
            foreach (var item in sessionFileSet.Evidencia.Where(x => x.Clave != "Manifest funcional")) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var webStack = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_WEB_STACK_STATE");
        if (webStack?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Servidor web / portal</h3><table>");
            foreach (var item in webStack.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var webFileSet = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_WEB_FILESET_STATE");
        if (webFileSet?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Archivos principales Web/HTML5 — diagnóstico dirigido</h3><table>");
            foreach (var item in webFileSet.Evidencia.Where(x => x.Clave != "Manifest funcional")) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var webRuntime = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_WEB_RUNTIME_STATE");
        if (webRuntime?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Runtime HTML5</h3><table>");
            foreach (var item in webRuntime.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var webSettings = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_WEB_SETTINGS_STATE");
        if (webSettings?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>settings.bin</h3><table>");
            foreach (var item in webSettings.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var releaseFamily = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_RELEASE_FAMILY");
        if (releaseFamily?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Versión / familia LTS</h3><table>");
            foreach (var item in releaseFamily.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var farmState = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_FARM_CONFIGURATION_STATE");
        if (farmState?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Granja / Load Balancing / Reverse Proxy</h3><table>");
            foreach (var item in farmState.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var fullTree = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_FULL_TREE_AUDIT");
        if (fullTree?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Árbol completo de la raíz TSplus</h3><table>");
            foreach (var item in fullTree.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var configArtifactCoverage = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_CONFIG_ARTIFACT_COVERAGE");
        if (configArtifactCoverage?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Cobertura de artefactos de configuración (.ini/.js/.bin y afines)</h3><table>");
            foreach (var item in configArtifactCoverage.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        var configArtifacts = report.Eventos.Where(e => e.Tipo == "TSPLUS_CONFIG_ARTIFACT_STATE")
            .OrderByDescending(e => e.Severidad)
            .ThenByDescending(e => e.Timestamp)
            .Take(120)
            .ToList();
        if (configArtifacts.Count > 0)
        {
            sb.Append("<h3>Artefactos de configuración examinados</h3><table><tr><th>Componente</th><th>Archivo</th><th>Tipo</th><th>Parser</th><th>Estructura</th><th>Modificado en ventana</th><th>Estado</th></tr>");
            foreach (var artifact in configArtifacts)
            {
                string V(string key) => artifact.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                var state = artifact.Severidad == DiagnosticSeverity.Informativo ? "Sin anomalía observada" : "Revisar";
                sb.Append($"<tr><td>{H(artifact.Componente)}</td><td>{H(V("Archivo"))}</td><td>{H(V("Extensión"))}</td><td>{H(V("Parser"))}</td><td>{H(V("Estructura"))}</td><td>{H(V("Modificado en ventana"))}</td><td>{H(state)}</td></tr>");
            }
            sb.Append("</table>");
            if (report.Eventos.Count(e => e.Tipo == "TSPLUS_CONFIG_ARTIFACT_STATE") > configArtifacts.Count)
                sb.Append($"<p class='muted'>Mostrando {configArtifacts.Count} de {report.Eventos.Count(e => e.Tipo == "TSPLUS_CONFIG_ARTIFACT_STATE")} artefactos destacados. El JSON conserva la colección completa.</p>");
        }
        var fileInventories = report.Eventos.Where(e => e.Tipo == "TSPLUS_INTERNAL_FILE_INVENTORY").ToList();
        if (fileInventories.Count > 0)
        {
            sb.Append("<h3>Inventario de archivos TSplus</h3><table><tr><th>Producto</th><th>Raíz</th><th>Relevantes</th><th>Binarios 0 bytes</th><th>Cambios en ventana</th><th>Truncado</th></tr>");
            foreach (var inventory in fileInventories)
            {
                string V(string key) => inventory.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                sb.Append($"<tr><td>{H(V("Producto"))}</td><td>{H(V("Raíz"))}</td><td>{H(V("Archivos relevantes"))}</td><td>{H(V("Binarios 0 bytes"))}</td><td>{H(V("Cambios de código/configuración en ventana"))}</td><td>{H(V("Inventario truncado"))}</td></tr>");
            }
            sb.Append("</table>");
        }
        var configIssues = report.Hallazgos.Where(f =>
            f.Id.StartsWith("TSPLUS-APPCONTROL-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-PUBLISHED-APP-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-WEB-CONFIG-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-WEB-RUNTIME-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-WEB-PORT-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-WEB-JVM-CRASH-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-INTEGRITY-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-FARM-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-UPDATE-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-ZERO-BINARY-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-FULL-TREE-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-CONFIG-", StringComparison.OrdinalIgnoreCase)).ToList();
        if (configIssues.Count > 0)
        {
            sb.Append("<h3>Anomalías internas</h3><table><tr><th>Severidad</th><th>Componente</th><th>Hallazgo</th><th>Acción sugerida</th></tr>");
            foreach (var f in configIssues.Take(60)) sb.Append($"<tr><td>{H(f.Severidad.ToString())}</td><td>{H(f.Componente)}</td><td>{H(f.Resumen)}</td><td>{H(f.SolucionSugerida)}</td></tr>");
            sb.Append("</table>");
        }
        else
        {
            var configCoverageState = configArtifactCoverage?.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Cobertura", StringComparison.OrdinalIgnoreCase))?.Valor;
            if (string.IsNullOrWhiteSpace(configCoverageState) || !configCoverageState.Equals("Disponible", StringComparison.OrdinalIgnoreCase))
                sb.Append("<p>No se detectaron anomalías en las fuentes de configuración que pudieron evaluarse. La cobertura de configuración es parcial o no evaluada, por lo que no se descartan los artefactos que TDM no pudo leer.</p>");
            else
                sb.Append("<p>No se detectaron anomalías en las comprobaciones internas implementadas y la cobertura declarada de artefactos de configuración fue disponible.</p>");
        }
        sb.Append("<p class='muted'>Los archivos sensibles de credenciales sólo se auditan por metadatos; TDM no lee ni exporta sus valores.</p></div>");

        sb.Append("<div class='card'><h2>Patrones recurrentes</h2>");
        if (!report.PatronesFalla.Any(p => p.Incidentes > 1)) sb.Append("<p>No se detectaron patrones recurrentes en la vista temporal actual.</p>");
        else
        {
            sb.Append("<table><tr><th>Producto</th><th>Componente</th><th>Excepción</th><th>Incidentes</th><th>Primera</th><th>Última</th><th>Estado</th></tr>");
            foreach (var p in report.PatronesFalla.Where(p => p.Incidentes > 1).Take(20))
                sb.Append($"<tr><td>{H(p.Producto.ToString())}</td><td>{H(p.ComponenteSemantico)}</td><td>{H(p.TipoExcepcion)}</td><td>{p.Incidentes}</td><td>{p.PrimeraDeteccion.ToLocalTime():dd/MM/yyyy HH:mm:ss}</td><td>{p.UltimaDeteccion.ToLocalTime():dd/MM/yyyy HH:mm:ss}</td><td>{H(p.EstadoInvestigacion)}</td></tr>");
            sb.Append("</table><p class='muted'>La recurrencia aumenta prioridad operativa, pero no confirma por sí sola la causa primaria.</p>");
        }
        sb.Append("</div>");

        sb.Append("<div class='card'><h2>Diagnóstico extendido</h2><div class='diag-text'>");
        sb.Append(RenderDiagnosticText(DiagnosticNarrativeBuilder.Build(report)));
        sb.Append("</div></div>");

        var forensicCoverage = report.Eventos.LastOrDefault(e => e.Tipo == "WINDOWS_FORENSIC_COVERAGE");
        var changeCoverage = report.Eventos.LastOrDefault(e => e.Tipo == "WINDOWS_CHANGE_COVERAGE");
        var forensicArtifacts = report.Eventos.LastOrDefault(e => e.Tipo == "FORENSIC_ARTIFACT_SUMMARY");
        sb.Append("<div class='card'><h2>Diagnóstico forense</h2>");
        if (forensicCoverage?.Evidencia is { Count: > 0 })
        {
            sb.Append("<table><tr><th>Fuente</th><th>Estado</th></tr>");
            foreach (var item in forensicCoverage.Evidencia) sb.Append($"<tr><td>{H(item.Clave)}</td><td>{H(item.Valor)}</td></tr>");
            sb.Append("</table>");
        }
        else sb.Append("<p>No disponible.</p>");
        if (changeCoverage?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Cobertura de cambios previos</h3><table><tr><th>Fuente</th><th>Estado</th></tr>");
            foreach (var item in changeCoverage.Evidencia) sb.Append($"<tr><td>{H(item.Clave)}</td><td>{H(item.Valor)}</td></tr>");
            sb.Append("</table>");
        }
        if (forensicArtifacts?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Evidencia forense ya existente</h3><table>");
            foreach (var item in forensicArtifacts.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        sb.Append("</div>");

        sb.Append("<div class='card'><h2>Incidentes agrupados</h2>");
        if (report.Incidentes.Count == 0) sb.Append("<p>No hay grupos de incidentes funcionales en la ventana analizada.</p>");
        else
        {
            sb.Append("<table><tr><th>Incidente</th><th>Dominio</th><th>Estado</th><th>Severidad</th><th>Ventana</th><th>Señales</th><th>Interpretación</th></tr>");
            foreach (var incident in report.Incidentes.Take(20))
                sb.Append($"<tr><td>{H(incident.Id)}</td><td>{H(incident.Dominio)}</td><td>{H(incident.Estado)}</td><td>{H(incident.SeveridadMaxima.ToString())}</td><td>{H($"{incident.Inicio:dd/MM/yyyy HH:mm:ss} - {incident.Fin:dd/MM/yyyy HH:mm:ss}")}</td><td>{incident.Senales}</td><td>{H(incident.Resumen)}</td></tr>");
            sb.Append("</table><p class='muted'>La agrupación separa dominios funcionales; proximidad temporal no equivale a causa raíz.</p>");
        }
        sb.Append("</div>");

        var dependencyHealth = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_DEPENDENCY_HEALTH");
        var scmDependencyCoverage = report.Eventos.LastOrDefault(e => e.Tipo == "SERVICE_DEPENDENCY_COVERAGE");
        var scmDependencies = report.Eventos.Where(e => e.Tipo == "SERVICE_DEPENDENCY_STATE").ToList();
        var scmDependents = report.Eventos.Where(e => e.Tipo == "SERVICE_DEPENDENT_STATE").ToList();
        sb.Append("<div class='card'><h2>Salud y dependencias</h2>");
        if (dependencyHealth is null && scmDependencyCoverage is null && scmDependencies.Count == 0)
            sb.Append("<p>No evaluado: no se obtuvo evidencia suficiente de dependencias.</p>");
        if (dependencyHealth is not null)
        {
            sb.Append("<h3>Dependencias funcionales TSplus</h3><table><tr><th>Dependencia</th><th>Estado observado</th></tr>");
            foreach (var item in dependencyHealth.Evidencia ?? []) sb.Append($"<tr><td>{H(item.Clave)}</td><td>{H(item.Valor)}</td></tr>");
            sb.Append("</table>");
        }
        if (scmDependencyCoverage?.Evidencia is { Count: > 0 })
        {
            sb.Append("<h3>Cobertura del grafo real de servicios Windows/TSplus</h3><table>");
            foreach (var item in scmDependencyCoverage.Evidencia) Row(item.Clave, item.Valor);
            sb.Append("</table>");
        }
        if (scmDependencies.Count > 0 || scmDependents.Count > 0)
        {
            sb.Append("<h3>Relaciones reales del Service Control Manager</h3><table><tr><th>Servicio</th><th>Relación</th><th>Servicio relacionado</th><th>Estado</th></tr>");
            foreach (var dep in scmDependencies.Where(IsRelevantDependencyRow).Take(120))
            {
                string V(string key) => dep.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                sb.Append($"<tr><td>{H(V("Servicio"))}</td><td>depende de</td><td>{H(V("Dependencia"))}</td><td>{H(V("Estado dependencia") != "N/D" ? V("Estado dependencia") : V("Estado"))}</td></tr>");
            }
            foreach (var dep in scmDependents.Where(IsRelevantDependencyRow).Take(60))
            {
                string V(string key) => dep.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                sb.Append($"<tr><td>{H(V("Dependiente"))}</td><td>depende de</td><td>{H(V("Servicio"))}</td><td>{H(V("Estado dependiente"))}</td></tr>");
            }
            sb.Append("</table>");
            if (scmDependencies.Count > 160 || scmDependents.Count > 80)
                sb.Append($"<p class='muted'>La tabla muestra hasta 160 dependencias y 80 dependientes. El JSON conserva todas las relaciones recopiladas ({scmDependencies.Count + scmDependents.Count}).</p>");
        }
        sb.Append("</div>");

        var resources = report.Eventos.LastOrDefault(e => e.Tipo == "SYSTEM_RESOURCE_STATE");
        if (resources is not null)
        {
            sb.Append("<div class='card'><h2>Recursos del sistema</h2><table>");
            foreach (var ev in resources.Evidencia ?? []) Row(ev.Clave, ev.Valor);
            sb.Append("</table><p class='muted'>Snapshot preventivo actual. La presión de recursos no se declara causa histórica sin evidencia temporal adicional.</p></div>");
        }

        var printing = report.Eventos.LastOrDefault(e => e.Tipo == "PRINTING_STATE");
        if (printing is not null)
        {
            sb.Append("<div class='card'><h2>Diagnóstico de impresión</h2><table>");
            foreach (var ev in printing.Evidencia ?? []) Row(ev.Clave, ev.Valor);
            sb.Append("</table><p class='muted'>Universal/Virtual Printer se correlacionan con Spooler y PrintService. TDM no reinicia la cola de impresión.</p></div>");
        }

        var windowsCauses = report.CausasRaiz.Where(c => OwnerForReport(c.OrigenClasificado) == "WINDOWS").OrderByDescending(c => c.Puntaje).ToList();
        var tsplusCauses = report.CausasRaiz.Where(c => OwnerForReport(c.OrigenClasificado) == "TSPLUS").OrderByDescending(c => c.Puntaje).ToList();
        var externalCauses = report.CausasRaiz.Where(c => OwnerForReport(c.OrigenClasificado) == "EXTERNO").OrderByDescending(c => c.Puntaje).ToList();
        var windowsIssues = report.Hallazgos.Where(f => FindingOwnerForReport(f) == "WINDOWS" && f.Severidad != DiagnosticSeverity.Informativo).ToList();
        var tsplusIssues = report.Hallazgos.Where(f => FindingOwnerForReport(f) == "TSPLUS" && f.Severidad != DiagnosticSeverity.Informativo).ToList();
        var externalIssues = report.Hallazgos.Where(f => FindingOwnerForReport(f) == "EXTERNO" && f.Severidad != DiagnosticSeverity.Informativo).ToList();
        sb.Append("<div class='card'><h2>Comparación de orígenes</h2><div class='grid'>");
        sb.Append("<div class='card'><h3>WINDOWS</h3>");
        sb.Append($"<p><strong>Candidatos causales:</strong> {windowsCauses.Count} · <strong>Hallazgos:</strong> {windowsIssues.Count}</p>");
        if (windowsCauses.Count > 0) sb.Append($"<p><strong>Mejor candidato:</strong> {H(windowsCauses[0].Componente)} · {H(InvestigationStateForReport(windowsCauses[0]))} · ranking {windowsCauses[0].Puntaje}/100</p>");
        else sb.Append("<p class='muted'>Sin candidato causal Windows sustentado.</p>");
        sb.Append("</div>");
        sb.Append("<div class='card'><h3>TSPLUS</h3>");
        sb.Append($"<p><strong>Candidatos causales:</strong> {tsplusCauses.Count} · <strong>Hallazgos:</strong> {tsplusIssues.Count}</p>");
        if (tsplusCauses.Count > 0) sb.Append($"<p><strong>Mejor candidato:</strong> {H(tsplusCauses[0].Componente)} · {H(InvestigationStateForReport(tsplusCauses[0]))} · ranking {tsplusCauses[0].Puntaje}/100</p>");
        else sb.Append("<p class='muted'>Sin candidato causal TSplus sustentado.</p>");
        sb.Append("</div>");
        sb.Append("<div class='card'><h3>EXTERNO</h3>");
        sb.Append($"<p><strong>Candidatos causales:</strong> {externalCauses.Count} · <strong>Hallazgos:</strong> {externalIssues.Count}</p>");
        if (externalCauses.Count > 0) sb.Append($"<p><strong>Mejor candidato:</strong> {H(externalCauses[0].Componente)} · {H(InvestigationStateForReport(externalCauses[0]))} · ranking {externalCauses[0].Puntaje}/100</p>");
        else sb.Append("<p class='muted'>Sin candidato causal externo sustentado.</p>");
        sb.Append("</div></div><p class='muted'>Esta comparación resume candidatos; los hallazgos completos se muestran una sola vez en la sección Hallazgos. Un observador Windows que registra la caída de un proceso TSplus no se considera automáticamente originador. La presencia de un antivirus/EDR/driver tampoco implica causalidad.</p></div>");

        sb.Append("<div class='card'><h2>Análisis de causa raíz</h2>");
        if (!report.Sistema.TsplusDetectado) sb.Append("<p>TSplus Remote Access no está detectado. TDM no emite una causa raíz de TSplus en este equipo.</p>");
        else if (report.CausasRaiz.Count == 0)
        {
            var coverageNote = criticalCoverageComplete
                ? "Las fuentes críticas disponibles no forman una cadena causal suficiente."
                : "La cobertura crítica es incompleta; las fuentes NO EVALUADAS no pueden descartarse como origen.";
            sb.Append($"<p>Evidencia insuficiente para identificar una causa raíz en la ventana analizada. {H(coverageNote)}</p>");
        }
        else
        {
            var mostRecent = report.CausasRaiz.Where(c => c.HoraIncidente.HasValue).OrderByDescending(c => c.HoraIncidente).FirstOrDefault();
            var best = report.CausaRaizPrincipal;
            if (mostRecent is not null) sb.Append($"<p><strong>Incidente más reciente:</strong> {mostRecent.HoraIncidente!.Value.ToLocalTime():dd/MM/yyyy HH:mm:ss} · {H(mostRecent.Componente)} · origen {H(mostRecent.OrigenClasificado)}</p>");
            if (best is not null)
            {
                var bestResponsibility = CausalResponsibilityFormatter.Resolve(best);
                sb.Append($"<p><strong>{H(bestResponsibility.EtiquetaOrigen)}:</strong> {H(bestResponsibility.OriginadorEspecifico)} · {H(best.Confianza.ToString())} · origen {H(best.OrigenClasificado)} <span class='muted'>(ranking interno {best.Puntaje}/100)</span></p>");
            }
            foreach (var c in report.CausasRaiz.Take(8))
            {
                var causeAnchor = "cau-" + c.Posicion;
                sb.Append($"<h3 id='{causeAnchor}' class='anchor-target'><a class='anchor-link' href='#{causeAnchor}'>#{c.Posicion} \u2020 {H(c.Componente)}</a></h3><p><span class='badge'>{H(c.Confianza.ToString())}</span><span class='badge muted'>ranking {c.Puntaje}/100</span><span class='badge'>{H(c.Capa.ToString())}</span><span class='badge'>{H(c.Producto.ToString())}</span><span class='badge'>Origen {H(c.OrigenClasificado)}</span></p>");
            if (c.HoraIncidente.HasValue) sb.Append($"<p><strong>Hora incidente:</strong> {c.HoraIncidente.Value.ToLocalTime():dd/MM/yyyy HH:mm:ss}</p>");
            sb.Append($"<p>{H(c.Resumen)}</p><p><strong>Por qué:</strong> {H(c.Explicacion)}</p><ul>");
            foreach (var e in c.Evidencia.Take(24)) sb.Append($"<li><strong>{H(e.Clave)}:</strong> {H(e.Valor)}</li>");
            sb.Append("</ul>");
            if (!string.IsNullOrWhiteSpace(c.SolucionSugerida)) sb.Append($"<p><strong>Solución sugerida (no se ejecuta):</strong> {H(c.SolucionSugerida)}</p>");
            if (!string.IsNullOrWhiteSpace(c.FuenteOficial)) sb.Append($"<p><strong>Fuente oficial:</strong> {H(c.FuenteOficial)}</p>");
            if (!string.IsNullOrWhiteSpace(c.UrlOficial)) sb.Append($"<p><a href='{H(c.UrlOficial)}'>{H(c.UrlOficial)}</a></p>");
            }
        }
        
        // Hallazgos relacionados por causa
        var causeRelatedFindings = report.CausasRaiz
            .Where(c => c.Posicion <= 8)
            .Select(c => new { 
                Cause = c, 
                Findings = report.Hallazgos
                    .Where(f => f.Componente == c.Componente || (f.Evidencia?.Any(e => e.Clave.Contains("Causa") && e.Valor.Contains(c.Componente, StringComparison.OrdinalIgnoreCase)) == true))
                    .Take(10)
                    .ToList() 
            })
            .Where(x => x.Findings.Count > 0)
            .ToList();
            
        if (causeRelatedFindings.Count > 0)
        {
            sb.Append("<div class='card'><h2>Hallazgos relacionados en este reporte</h2>");
            foreach (var crf in causeRelatedFindings)
            {
                var causeAnchor = "cau-" + crf.Cause.Posicion;
                sb.Append($"<h3><a class='anchor-link' href='#{causeAnchor}'>#{crf.Cause.Posicion} · {H(crf.Cause.Componente)}</a></h3>");
                sb.Append("<table><tr><th>Severidad</th><th>Componente</th><th>Resumen</th><th>Confianza</th></tr>");
                foreach (var f in crf.Findings)
                {
                    sb.Append($"<tr><td>{H(f.Severidad.ToString())}</td><td>{H(f.Componente)}</td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>");
                }
                sb.Append("</table>");
            }
            sb.Append("</div>");
        }

        sb.Append("</div>");

sb.Append("<div class='card'><h2>Hallazgos</h2>");
        if (report.Hallazgos.Count > 200) sb.Append($"<p class='muted'>Mostrando 200 de {report.Hallazgos.Count} hallazgos. El JSON conserva la colección completa del reporte.</p>");
        sb.Append("<table><tr><th>Severidad</th><th>Fuente de evidencia</th><th>Capa diagnóstica</th><th>Componente</th><th>Resumen</th><th>Confianza</th></tr>");
        foreach (var (f, fi) in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200).Select((x, i) => (x, i + 1)))
            sb.Append($"<tr id='fnd-{fi}' class='anchor-target'><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td><a class='anchor-link' href='#fnd-{fi}'>{H(f.Componente)}</a></td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>");
        sb.Append("</table>");
        if (report.Hallazgos.Count > 200) sb.Append($"<p class='muted'>Truncado: {report.Hallazgos.Count - 200} hallazgos no mostrados en HTML (completos en JSON).</p>");
        sb.Append("</div>");

        sb.Append("<div class='card'><h2>Línea de tiempo</h2><div class='mono'>");
        var timelineEventCount = report.Eventos.Count(x => x.Severidad != DiagnosticSeverity.Informativo && x.Timestamp.HasValue);
        if (timelineEventCount > 300) sb.Append($"<p class='muted'>Mostrando 300 de {timelineEventCount} eventos fechados no informativos. El JSON conserva la colección completa del reporte.</p>");
        foreach (var e in report.Eventos.Where(x => x.Severidad != DiagnosticSeverity.Informativo && x.Timestamp.HasValue).OrderBy(x => x.Timestamp).Take(300))
            sb.Append(H($"{e.Timestamp!.Value.ToLocalTime():dd/MM/yyyy HH:mm:ss} [Fuente: {EvidenceSourceForEventReport(e)}] [Capa: {e.Capa}] [{e.Componente}] {e.Tipo}\n  {e.Mensaje}\n\n"));
        sb.Append("</div></div>");
        if (timelineEventCount > 300) sb.Append($"<p class='muted'>Truncado: {timelineEventCount - 300} eventos no mostrados en HTML (completos en JSON).</p>");

        sb.Append("<div class='card'><h2>Evidencia recopilada</h2><details><summary>Mostrar observaciones normalizadas (" + report.Eventos.Count + ")</summary><div class='mono'>");
        if (report.Eventos.Count > 1000) sb.Append($"<p class='muted'>Mostrando 1,000 de {report.Eventos.Count} observaciones normalizadas. El JSON conserva la colección completa del reporte.</p>");
        foreach (var e in report.Eventos.OrderBy(x => x.Timestamp ?? DateTimeOffset.MaxValue).Take(1000))
            sb.Append(H($"{(e.Timestamp.HasValue ? e.Timestamp.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") : "Sin fecha")} [{e.Severidad}] [Fuente: {EvidenceSourceForEventReport(e)}] [Capa: {e.Capa}] [{e.Producto}] [{e.Componente}] {e.Tipo}\n  {e.Mensaje}\n\n"));
        sb.Append("</div></details></div>");
        if (report.Eventos.Count > 1000) sb.Append($"<p class='muted'>Truncado: {report.Eventos.Count - 1000} observaciones no mostradas en HTML (completas en JSON).</p>");
        sb.Append("</details></body></html>");
        return sb.ToString();

        void QuickCard(string label, string value, string css) => sb.Append($"<div class='quick-card'><div class='quick-label'>{H(label)}</div><div class='quick-value {H(css)}'>{H(value)}</div></div>");
        void Row(string key, string value) => sb.Append($"<tr><th>{H(key)}</th><td>{H(value)}</td></tr>");
        void Metric(string label, string value) => sb.Append($"<div class='metric'><div class='label'>{H(label)}</div><div class='value'>{H(value)}</div></div>");
        void FlowNode(string kind, string value, string css) => sb.Append($"<div class='flow-node {css}'><div class='kind'>{H(kind)}</div><div><strong>{H(value)}</strong></div></div>");
        void Arrow() => sb.Append("<div class='flow-arrow'>&rarr;</div>");
    }

    private sealed record CompactReportEventGroup(
        DateTimeOffset First,
        DateTimeOffset Last,
        int Count,
        string Component,
        string Detail,
        DiagnosticSeverity Severity);

    private static string ExecutiveState(DiagnosticReport report, RootCauseCandidate? cause)
    {
        var criticalCoverageIncomplete = report.CoberturaDiagnostica?.Fuentes.Any(
            x => x.Critica && x.Estado is not "Disponible" and not "No aplica") == true;

        if (report.ImpactoFuncional is { } impact)
        {
            return impact.EstadoGeneral switch
            {
                FunctionalImpactState.Interrumpido => "ERROR",
                FunctionalImpactState.Degradado => "ADVERTENCIA",
                FunctionalImpactState.SinImpactoObservado => criticalCoverageIncomplete ? "NO EVALUADO" : "SALUDABLE",
                _ => cause is null ? "NO EVALUADO" : InvestigationStateForReport(cause)
            };
        }

        if (cause is not null) return InvestigationStateForReport(cause);
        if (report.Hallazgos.Any(x => x.Severidad >= DiagnosticSeverity.Error)) return "ADVERTENCIA";
        return criticalCoverageIncomplete ? "NO EVALUADO" : "SALUDABLE";
    }

    private static string ExecutiveStateCss(string? state)
    {
        var text = state ?? string.Empty;
        if (text.Contains("ERROR", StringComparison.OrdinalIgnoreCase) || text.Contains("INTERRUMP", StringComparison.OrdinalIgnoreCase) || text.Contains("FALLA", StringComparison.OrdinalIgnoreCase)) return "state-error";
        if (text.Contains("ADVERT", StringComparison.OrdinalIgnoreCase) || text.Contains("DEGRAD", StringComparison.OrdinalIgnoreCase) || text.Contains("PROBABLE", StringComparison.OrdinalIgnoreCase)) return "state-warn";
        if (text.Contains("SALUD", StringComparison.OrdinalIgnoreCase) || text.Contains("SIN IMPACTO", StringComparison.OrdinalIgnoreCase) || text.Contains("CONFIRMADA", StringComparison.OrdinalIgnoreCase)) return "state-ok";
        return "state-muted";
    }

    private static string CompactImpactState(FunctionalImpactState state) => state switch
    {
        FunctionalImpactState.SinImpactoObservado => "SALUDABLE",
        FunctionalImpactState.Degradado => "ADVERTENCIA",
        FunctionalImpactState.Interrumpido => "ERROR",
        _ => "NO EVALUADO"
    };

    private static IReadOnlyList<CompactReportEventGroup> BuildCompactReportEventGroups(DiagnosticReport report)
    {
        return report.Eventos
            .Where(e => e.Timestamp.HasValue && !IsCurrentStateEventForReport(e))
            .Where(e => e.Severidad != DiagnosticSeverity.Informativo || e.Tipo is "RDP_AUTHENTICATION_STAGE" or "RDP_SESSION_LOGON_STAGE" or "RDP_SHELL_START_STAGE")
            .GroupBy(e => $"{e.Componente}|{e.Tipo}|{ReportEventFingerprint(e.Mensaje)}", StringComparer.OrdinalIgnoreCase)
            .Select(g => new CompactReportEventGroup(
                g.Min(x => x.Timestamp!.Value),
                g.Max(x => x.Timestamp!.Value),
                g.Count(),
                g.OrderByDescending(x => x.Timestamp).First().Componente,
                FirstLineForReport(g.OrderByDescending(x => x.Timestamp).First().Mensaje, g.OrderByDescending(x => x.Timestamp).First().Tipo),
                g.OrderByDescending(x => x.Severidad).First().Severidad))
            .OrderBy(x => x.Last)
            .ToList();
    }

    private static string ReportEventFingerprint(string? message)
    {
        if (string.IsNullOrWhiteSpace(message)) return string.Empty;
        var line = message.Replace("\r", string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? message;
        line = Regex.Replace(line, @"\d{1,4}[-/:.]\d{1,4}[-/:.]\d{1,4}", "#");
        line = Regex.Replace(line, @"\b\d+\b", "#");
        return Regex.Replace(line, @"\s+", " ").Trim();
    }

    private static string OwnerForReport(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "INDETERMINADO";
        if (value.Contains("TSPLUS", StringComparison.OrdinalIgnoreCase)) return "TSPLUS";
        if (value.Contains("WINDOWS", StringComparison.OrdinalIgnoreCase)) return "WINDOWS";
        if (value.Contains("EXTER", StringComparison.OrdinalIgnoreCase) || value.Contains("DEPENDENCIA EXTERNA", StringComparison.OrdinalIgnoreCase)) return "EXTERNO";
        return "INDETERMINADO";
    }

    private static string FindingOwnerForReport(DiagnosticFinding f)
    {
        if (f.Id.StartsWith("THIRD-PARTY-", StringComparison.OrdinalIgnoreCase)) return "EXTERNO";
        if (f.Id.StartsWith("TSPLUS-", StringComparison.OrdinalIgnoreCase) || f.Capa == DiagnosticLayer.Tsplus) return "TSPLUS";
        if (f.Id.StartsWith("WINDOWS-", StringComparison.OrdinalIgnoreCase) || f.Capa is DiagnosticLayer.Windows or DiagnosticLayer.Rdp or DiagnosticLayer.Red) return "WINDOWS";
        if (f.Capa == DiagnosticLayer.Seguridad)
        {
            var text = $"{f.Id} {f.Componente} {f.Resumen}";
            if (text.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase)) return "TSPLUS";
            if (text.Contains("third-party", StringComparison.OrdinalIgnoreCase) || text.Contains("tercero", StringComparison.OrdinalIgnoreCase) || text.Contains("extern", StringComparison.OrdinalIgnoreCase)) return "EXTERNO";
            return "WINDOWS";
        }
        return "INDETERMINADO";
    }

    private static string EvidenceSourceForFindingReport(DiagnosticFinding finding)
    {
        if (finding.Id.StartsWith("TSPLUS-CRASH-LOOP-", StringComparison.OrdinalIgnoreCase))
            return "TDM";

        return FindingOwnerForReport(finding) switch
        {
            "TSPLUS" => "TSplus",
            "WINDOWS" => "Windows",
            "EXTERNO" => "Externo",
            _ => finding.Capa == DiagnosticLayer.Desconocida ? "No determinada" : finding.Capa.ToString()
        };
    }

    private static string EvidenceSourceForEventReport(DiagnosticEvent diagnosticEvent)
    {
        if (diagnosticEvent.Fuente.Equals("TDM", StringComparison.OrdinalIgnoreCase)) return "TDM";
        if (diagnosticEvent.Tipo.StartsWith("THIRD_PARTY_", StringComparison.OrdinalIgnoreCase)) return "Externo";
        if (diagnosticEvent.Capa == DiagnosticLayer.Tsplus) return "TSplus";
        if (diagnosticEvent.Capa is DiagnosticLayer.Windows or DiagnosticLayer.Rdp or DiagnosticLayer.Red) return "Windows";
        if (diagnosticEvent.Capa == DiagnosticLayer.Seguridad)
        {
            var text = $"{diagnosticEvent.Fuente} {diagnosticEvent.Componente} {diagnosticEvent.Tipo} {diagnosticEvent.Archivo}";
            if (text.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || diagnosticEvent.Producto == TsplusProduct.AdvancedSecurity) return "TSplus";
            if (text.Contains("third-party", StringComparison.OrdinalIgnoreCase) || text.Contains("tercero", StringComparison.OrdinalIgnoreCase) || text.Contains("extern", StringComparison.OrdinalIgnoreCase)) return "Externo";
            return "Windows";
        }
        return diagnosticEvent.Capa == DiagnosticLayer.Desconocida ? "No determinada" : diagnosticEvent.Capa.ToString();
    }

    private static string InvestigationStateForReport(RootCauseCandidate? candidate)
    {
        if (candidate is null) return "INDETERMINADA";
        var explicitState = candidate.Evidencia.FirstOrDefault(e =>
            e.Clave.Contains("Estado del origen", StringComparison.OrdinalIgnoreCase) ||
            e.Clave.Contains("Estado de investigación", StringComparison.OrdinalIgnoreCase))?.Valor;
        if (!string.IsNullOrWhiteSpace(explicitState)) return explicitState;
        return InvestigationGuidanceBuilder.State(candidate);
    }

    private static bool IsCurrentStateEventForReport(DiagnosticEvent e) => DiagnosticEventCatalog.IsReportCurrentState(e.Tipo);

    private static bool IsLikelyCausalForReport(DiagnosticEvent e) => e.Tipo is
        "APPLICATION_CRASH" or "DOTNET_UNHANDLED_EXCEPTION" or "WER_REPORT" or "WINDOWS_EVENT" or
        "SIDEBYSIDE_DEPENDENCY_FAILURE" or "DEPENDENCY_NOT_FOUND" or "DEPENDENCY_LOAD_FAILURE" or
        "DLL_NOT_FOUND" or "INVALID_IMAGE_FORMAT" or "USER_LOGON_FAILURE" or "USER_PROFILE_SERVICE_EVENT" or
        "TSPLUS_HTML5_JVM_CRASH" or "RDP_AUTHENTICATION_STAGE" or "RDP_SESSION_LOGON_STAGE" or "RDP_SHELL_START_STAGE" or
        "TSPLUS_CRASH_LOOP_PATTERN";

    private static string FirstLineForReport(string? message, string fallback)
    {
        if (string.IsNullOrWhiteSpace(message)) return fallback;
        var first = message.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n')
            .Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return string.IsNullOrWhiteSpace(first) ? fallback : first.Trim();
    }

    private static string FirstSentenceForReport(string value)
    {
        var normalized = (value ?? string.Empty).Replace("\r", " ").Replace("\n", " ").Trim();
        if (normalized.Length == 0) return "Recopilar evidencia adicional";
        var index = normalized.IndexOf('.');
        return index > 0 ? normalized[..(index + 1)] : normalized;
    }

    private static bool IsRelevantDependencyRow(DiagnosticEvent e)
    {
        if (e.Producto == TsplusProduct.RemoteAccess) return true;
        string V(string key) => e.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? string.Empty;
        var text = $"{V("Servicio")} {V("Dependencia")} {V("Dependiente")} {e.Componente}";
        string[] markers = ["TSplus", "TermService", "Spooler", "RpcSs", "ProfSvc", "SessionEnv", "UmRdpService", "Netlogon", "W32Time", "Dnscache", "APSC", "HTML5", "WebPortal", "Remote Desktop"];
        return markers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
    }

    private static string DependencyClassForReport(string value)
    {
        var v = value ?? string.Empty;
        if (new[] { "Stopped", "Detenido", "No operativo", "Falla", "Failed", "Error", "No encontrado", "No disponible", "Missing", "Crítico", "Critico", "Critical", "Fatal" }.Any(x => v.Contains(x, StringComparison.OrdinalIgnoreCase))) return "critical";
        if (new[] { "Unknown", "Desconoc", "Indeterminado", "Parcial", "Advertencia", "Ninguno identificado" }.Any(x => v.Contains(x, StringComparison.OrdinalIgnoreCase))) return "warn";
        return "ok";
    }

    private static string CompactForReport(string value, int max)
        => string.IsNullOrEmpty(value) || value.Length <= max ? value : value[..Math.Max(0, max - 3)] + "...";

    private static string FormatLookback(TimeSpan value)
    {
        if (value.TotalHours >= 1) return value.TotalHours == 1 ? "1 h" : $"{value.TotalHours:0} h";
        if (value.TotalMinutes >= 1) return value.TotalMinutes == 1 ? "1 min" : $"{value.TotalMinutes:0} min";
        return $"{value.TotalSeconds:0} s";
    }

    private static string SanitizeFileName(string value)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) value = value.Replace(c, '_');
        return string.IsNullOrWhiteSpace(value) ? "equipo" : value;
    }
}




