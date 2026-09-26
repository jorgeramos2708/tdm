using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// RC18.11: autodiagnóstico de cobertura. Distingue "sin falla" de "fuente no leída".
/// </summary>
public static class DiagnosticCoverageAnalyzer
{
    public static DiagnosticCoverageAssessment Analyze(DiagnosticReport report)
    {
        var sources = new List<CoverageSourceAssessment>();
        var limitations = new List<string>();

        AddWindowsForensic(report, sources, limitations);
        AddWindowsCompatibilityProbeCoverage(report, sources, limitations);
        AddSecurityLog(report, sources, limitations);
        AddPresence(report, sources, "RDP / estado y listener", "RDP_STATE", true,
            "Estado RDP y listener local disponibles.", "No se obtuvo el snapshot RDP; la salud de Remote Access queda parcialmente cubierta.", limitations);
        AddPresence(report, sources, "Recursos/WMI del sistema", "SYSTEM_RESOURCE_STATE", false,
            "Snapshot de recursos del sistema disponible.", "No se obtuvo snapshot de recursos; tendencias/condiciones de memoria/CPU quedan limitadas.", limitations);
        AddTsplusLogs(report, sources, limitations);
        AddServiceDependencyCoverage(report, sources, limitations);
        if (report.Sistema.TsplusDetectado)
        {
            AddPresence(report, sources, "Árbol completo TSplus", "TSPLUS_FULL_TREE_AUDIT", true,
                "Árbol de instalación TSplus auditado recursivamente.", "No se ejecutó la auditoría profunda del árbol TSplus.", limitations);
            AddPresence(report, sources, "Configuraciones TSplus (.ini/.js/.bin y afines)", "TSPLUS_CONFIG_ARTIFACT_COVERAGE", true,
                "Artefactos de configuración TSplus inventariados y evaluados con parsers conservadores.", "No se obtuvo cobertura de artefactos de configuración TSplus.", limitations);
            AddPresence(report, sources, "Integridad de archivos TSplus", "TSPLUS_FILE_INTEGRITY_COVERAGE", true,
                "Integridad física de archivos TSplus candidatos evaluada.", "No se obtuvo cobertura de integridad de archivos TSplus.", limitations);
        }
        AddAdvancedSecurity(report, sources, limitations);
        AddPresence(report, sources, "Configuración Web/HTML5", "TSPLUS_WEB_SETTINGS_JS_STATE", false,
            "settings.js/configuración Web principal evaluada.", "No se observó la fuente principal Web; puede no aplicar si el módulo no está instalado/configurado.", limitations);
        AddPresence(report, sources, "Aplicaciones publicadas", "TSPLUS_APPCONTROL_STATE", false,
            "AppControl.ini/publicación evaluados.", "No se obtuvo estado AppControl; puede no aplicar en servidores sin aplicaciones publicadas.", limitations);
        AddPresence(report, sources, "Impresión TSplus/Windows", "PRINTING_STATE", false,
            "Spooler/impresión y componentes TSplus evaluados.", "No se obtuvo snapshot de impresión.", limitations);
        AddForensicArtifacts(report, sources, limitations);
        AddLocalHistory(report, sources, limitations);
        AddLongitudinalHistoryCoverage(report, sources, limitations);
        AddThirdParty(report, sources);
        AddFarmCoverage(report, sources, limitations);
        AddPerformanceCoverage(report, sources, limitations);
        if (report.DiagnosticoContinuo)
        {
            AddPresence(report, sources, "Event Viewer incremental", "WINDOWS_INCREMENTAL_COVERAGE", true,
                "Canales incrementales Windows monitorizados.", "No se obtuvo estado de cobertura incremental de Event Viewer.", limitations);
            if (report.Sistema.TsplusDetectado)
                AddPresence(report, sources, "Logs TSplus incrementales", "TSPLUS_INCREMENTAL_LOG_COVERAGE", true,
                    "Fuentes incrementales TSplus monitorizadas.", "No se obtuvo estado de cobertura incremental de logs TSplus.", limitations);
        }

        var scored = sources.Where(s => !s.Estado.Equals("No aplica", StringComparison.OrdinalIgnoreCase)).ToList();
        double totalWeight = 0;
        double obtained = 0;
        foreach (var source in scored)
        {
            var weight = source.Critica ? 2d : 1d;
            totalWeight += weight;
            obtained += weight * StatusValue(source.Estado);
        }

        var score = totalWeight <= 0 ? 0 : (int)Math.Round(obtained * 100d / totalWeight);
        score = Math.Clamp(score, 0, 100);
        var level = score switch
        {
            >= 90 => "ALTA",
            >= 75 => "MEDIA-ALTA",
            >= 60 => "MEDIA",
            >= 40 => "BAJA",
            _ => "INSUFICIENTE"
        };

        var criticalUnavailable = sources.Count(s => s.Critica && (s.Estado is "No disponible" or "Bloqueada" or "Timeout"));
        var partial = sources.Count(s => s.Estado is "Parcial" or "No consultado");
        var summary = criticalUnavailable > 0
            ? $"Cobertura incompleta: {criticalUnavailable} fuente(s) crítica(s) no disponible(s). Las hipótesis dependientes de ellas no se consideran descartadas."
            : partial > 0
                ? $"Cobertura útil con {partial} fuente(s) parcial(es/no consultadas); las conclusiones deben respetar esas limitaciones."
                : "Las fuentes críticas definidas para el diagnóstico local fueron consultadas sin bloqueos detectados.";

        return new DiagnosticCoverageAssessment(score, level, sources, limitations.Distinct(StringComparer.OrdinalIgnoreCase).ToList(), summary);
    }

    private static void AddServiceDependencyCoverage(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        AddPresence(report, sources, "Dependencias reales de servicios SCM", "SERVICE_DEPENDENCY_COVERAGE", true,
            "Grafo real ServicesDependedOn/DependentServices evaluado para Windows/RDP/TSplus.",
            "No se obtuvo el grafo real de dependencias del Service Control Manager.", limitations);
    }

    public static int CriticalUnavailableCount(DiagnosticReport report)
    {
        var assessment = report.CoberturaDiagnostica ?? Analyze(report);
        return assessment.Fuentes.Count(s => s.Critica && s.Estado is not "Disponible" and not "No aplica");
    }

    /// <summary>
    /// Fuentes críticas realmente bloqueadas: sin ellas no hay evidencia utilizable.
    /// Una fuente "Parcial" o "No consultado" sigue aportando lectura parcial y no debe
    /// castigar el puntaje de precisión como si la fuente no existiera.
    /// </summary>
    public static int CriticalHardBlockedCount(DiagnosticReport report)
    {
        var assessment = report.CoberturaDiagnostica ?? Analyze(report);
        return assessment.Fuentes.Count(s => s.Critica && s.Estado is "No disponible" or "Bloqueada" or "Timeout");
    }

    private static void AddWindowsForensic(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var coverage = report.Eventos.LastOrDefault(e => e.Tipo == "WINDOWS_FORENSIC_COVERAGE");
        if (coverage?.Evidencia is not { Count: > 0 })
        {
            sources.Add(new("Windows Event Log forense", "No disponible", "No se obtuvo el mapa de cobertura de canales Windows.", true));
            limitations.Add("No se pudo determinar la cobertura de Event Log forense Windows.");
            return;
        }

        var channelEvidence = coverage.Evidencia.Where(x =>
            !x.Clave.Equals("Descubrimiento dinámico de canales", StringComparison.OrdinalIgnoreCase)
            && !x.Clave.Equals("Ventana solicitada", StringComparison.OrdinalIgnoreCase)
            && !x.Clave.Equals("Duración solicitada", StringComparison.OrdinalIgnoreCase)).ToList();
        var discovery = coverage.Evidencia.FirstOrDefault(x => x.Clave.Equals("Descubrimiento dinámico de canales", StringComparison.OrdinalIgnoreCase));
        var blocked = channelEvidence.Where(x => IsBlocked(x.Valor)).ToList();
        var unavailable = channelEvidence.Where(x => x.Valor.StartsWith("Canal no disponible", StringComparison.OrdinalIgnoreCase)).ToList();
        var available = channelEvidence.Count - blocked.Count - unavailable.Count;
        var discoveryUnavailable = discovery is not null && (discovery.Valor.Contains("No evaluado", StringComparison.OrdinalIgnoreCase) || IsBlocked(discovery.Valor));
        var status = blocked.Count > 0 ? "Bloqueada" : unavailable.Count > 0 || discoveryUnavailable ? "Parcial" : "Disponible";
        sources.Add(new("Windows Event Log forense", status,
            $"Canales disponibles={available}; no disponibles={unavailable.Count}; bloqueados/no legibles={blocked.Count}.", true));
        if (blocked.Count > 0) limitations.Add("Uno o más canales Windows no pudieron leerse por permisos/error; una ausencia de evento en ellos no descarta la hipótesis.");
        if (discoveryUnavailable) limitations.Add("No se pudo inventariar dinámicamente canales adicionales de Event Viewer relacionados con TSplus/RDP/AppLocker/Code Integrity.");
    }


    private static void AddWindowsCompatibilityProbeCoverage(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var gaps = report.Hallazgos
            .Where(f => f.Id.StartsWith("WINDOWS-PROBE-", StringComparison.OrdinalIgnoreCase))
            .ToList();
        if (gaps.Count == 0) return;
        sources.Add(new("Compatibilidad Windows / Registro", "Parcial",
            $"{gaps.Count} comprobación(es) de compatibilidad no pudieron leerse por completo; no se interpretaron como estado sano.", true));
        limitations.Add("Una o más comprobaciones Windows quedaron NO EVALUADAS por acceso/error de lectura; las hipótesis dependientes de esas fuentes siguen abiertas.");
    }

    private static void AddSecurityLog(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var auth = report.Eventos.LastOrDefault(e => e.Tipo == "USER_AUTH_AUDIT_COVERAGE");
        var raw = auth?.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Security log", StringComparison.OrdinalIgnoreCase))?.Valor;
        if (auth is null || string.IsNullOrWhiteSpace(raw))
        {
            sources.Add(new("Security Log / autenticación", "No disponible", "No se obtuvo estado de auditoría de autenticación.", true));
            limitations.Add("Sin Security Log legible no puede confirmarse/descartarse completamente NLA/4625, bloqueos 4740, Kerberos 4771, validación 4776 ni estados de contraseña.");
            return;
        }
        var status = IsBlocked(raw) ? "Bloqueada" : raw.Contains("Disponible", StringComparison.OrdinalIgnoreCase) ? "Disponible" : raw.Contains("No disponible", StringComparison.OrdinalIgnoreCase) ? "No disponible" : "Parcial";
        sources.Add(new("Security Log / autenticación", status, raw, true));
        if (status != "Disponible") limitations.Add("Cobertura de autenticación/NLA/Kerberos limitada: " + raw);
    }

    private static void AddTsplusLogs(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var e = report.Eventos.LastOrDefault(x => x.Tipo == "TSPLUS_INCREMENTAL_LOG_COVERAGE")
                 ?? report.Eventos.LastOrDefault(x => x.Tipo == "TSPLUS_LOG_COVERAGE");
        if (e is null)
        {
            sources.Add(new("Logs TSplus Remote Access", "No disponible", "No se generó el estado de cobertura de logs Remote Access.", true));
            limitations.Add("Sin cobertura de logs TSplus, la causa interna puede requerir Event Log/stack u otra fuente independiente.");
            return;
        }
        static int IntEvidence(DiagnosticEvent ev, string key)
            => int.TryParse(ev.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor, out var value) ? value : 0;
        int available;
        int total;
        if (e.Tipo.Equals("TSPLUS_INCREMENTAL_LOG_COVERAGE", StringComparison.OrdinalIgnoreCase))
        {
            var candidates = IntEvidence(e, "Fuentes candidatas");
            available = Math.Max(0, candidates - IntEvidence(e, "Fuentes no evaluadas"));
            total = candidates;
        }
        else
        {
            available = IntEvidence(e, "Fuentes Remote Access disponibles");
            total = IntEvidence(e, "Fuentes Remote Access conocidas/detectadas");
        }
        var declared = e.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Cobertura", StringComparison.OrdinalIgnoreCase))?.Valor ?? "Parcial";
        var readFailures = report.Eventos.Count(x => x.Tipo is "LOG_ACCESS_DENIED" or "LOG_READ_ERROR" or "TSPLUS_INCREMENTAL_SOURCE_UNAVAILABLE");
        var discoveryPartial = declared.Contains("Parcial", StringComparison.OrdinalIgnoreCase) || declared.Contains("No evalu", StringComparison.OrdinalIgnoreCase);
        var status = total == 0 ? "Parcial" : readFailures > 0 || discoveryPartial ? "Parcial" : available == total ? "Disponible" : available > 0 ? "Parcial" : "No disponible";
        sources.Add(new("Logs TSplus Remote Access", status, $"Fuentes conocidas/detectadas disponibles={available}/{total}; errores de lectura/pérdida={readFailures}; descubrimiento={declared}. La ausencia de logs opcionales no se interpreta como falla.", true));
        if (status != "Disponible") limitations.Add("Parte de los logs Remote Access no está disponible/habilitada o perdió acceso; TDM conserva la limitación sin declarar el módulo sano por ausencia de log.");
    }

    private static void AddAdvancedSecurity(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var product = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE");
        if (product is null)
        {
            sources.Add(new("Advanced Security", "No aplica", "No se detectó runtime/estado de Advanced Security en esta ejecución.", false));
            return;
        }
        var modules = report.Eventos.Where(e => e.Tipo == "TSPLUS_ADVSEC_MODULE_STATE").ToList();
        var partial = modules.Count(e => (e.Evidencia?.Any(x => x.Valor.Contains("parcial", StringComparison.OrdinalIgnoreCase)) ?? false));
        var status = partial > 0 ? "Parcial" : "Disponible";
        sources.Add(new("Advanced Security", status, $"Módulos evaluados={modules.Count}; cobertura parcial={partial}. Los logs por función pueden estar deshabilitados.", false));
        if (partial > 0) limitations.Add("Advanced Security contiene funciones cuya habilitación/estado no puede inferirse de una fuente local estable; ausencia de log no equivale a falla.");
    }

    private static void AddForensicArtifacts(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var f = report.Eventos.LastOrDefault(e => e.Tipo == "FORENSIC_ARTIFACT_SUMMARY");
        if (f is null)
        {
            sources.Add(new("WER/dumps/artefactos existentes", "Parcial", "No se obtuvo resumen de artefactos forenses existentes.", false));
            limitations.Add("No se pudo resumir la evidencia WER/dump existente; esto no significa que no existan artefactos.");
            return;
        }
        sources.Add(new("WER/dumps/artefactos existentes", "Disponible", "La búsqueda forense de artefactos existentes se completó en modo de solo lectura.", false));
    }

    private static void AddLocalHistory(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var e = report.Eventos.LastOrDefault(x => x.Tipo == "TDM_LOCAL_HISTORY_STATUS");
        if (e is null)
        {
            sources.Add(new("Historial local TDM", "Parcial", "No se integró estado de historial local en esta vista.", false));
            return;
        }
        sources.Add(new("Historial local TDM", "Disponible", "Snapshots/transiciones locales disponibles sin motor de base de datos.", false));
    }

    private static void AddLongitudinalHistoryCoverage(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var e = report.Eventos.LastOrDefault(x => x.Tipo == "TDM_FORENSIC_HISTORY_COVERAGE");
        if (e is null)
        {
            sources.Add(new("Historial longitudinal de cambios", "Parcial", "No se pudo verificar la continuidad de servicios/configuración/integridad en esta vista.", true));
            limitations.Add("Sin un mapa de continuidad longitudinal, TDM no puede afirmar que conoce cómo eran configuraciones o archivos antes de la captura actual.");
            return;
        }

        var global = EvidenceReader.Value(e, "Cobertura global") ?? "Parcial";
        var services = EvidenceReader.Value(e, "Servicios") ?? "No disponible";
        var config = EvidenceReader.Value(e, "Configuración Windows/TSplus") ?? "No disponible";
        var integrity = EvidenceReader.Value(e, "Archivos/librerías críticas") ?? "No disponible";
        var status = global.Equals("Completa", StringComparison.OrdinalIgnoreCase) ? "Disponible"
            : global.Equals("No disponible", StringComparison.OrdinalIgnoreCase) ? "No disponible"
            : "Parcial";

        sources.Add(new("Historial TDM / servicios", StatusFromDescription(services), services, true));
        sources.Add(new("Historial TDM / configuración Windows y TSplus", StatusFromDescription(config), config, true));
        sources.Add(new("Historial TDM / archivos y librerías críticas", StatusFromDescription(integrity), integrity, false));
        if (status != "Disponible")
            limitations.Add("La ventana retrospectiva contiene historial longitudinal incompleto. TDM conserva el hueco y no reconstruye valores pasados que nunca observó.");
    }

    private static string StatusFromDescription(string value)
    {
        if (value.StartsWith("Completa", StringComparison.OrdinalIgnoreCase)) return "Disponible";
        if (value.StartsWith("No disponible", StringComparison.OrdinalIgnoreCase)) return "No disponible";
        return "Parcial";
    }

    private static void AddThirdParty(DiagnosticReport report, List<CoverageSourceAssessment> sources)
    {
        var e = report.Eventos.LastOrDefault(x => x.Tipo == "THIRD_PARTY_RUNTIME_INVENTORY");
        sources.Add(e is null
            ? new("Terceros / EDR / módulos externos", "Parcial", "No se obtuvo inventario contextual de terceros en esta vista.", false)
            : new("Terceros / EDR / módulos externos", "Disponible", "Inventario contextual disponible; presencia no implica causalidad.", false));
    }

    private static void AddFarmCoverage(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var farm = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_FARM_CONFIGURATION_STATE");
        if (farm is null)
        {
            sources.Add(new("Farm/Gateway remoto", "No aplica", "No se detectó evidencia local suficiente de granja en esta ejecución.", false));
            return;
        }
        var evidence = farm.Evidencia?.FirstOrDefault(x => x.Clave.Contains("Evidencia de granja", StringComparison.OrdinalIgnoreCase))?.Valor ?? "Sí";
        var topologyCoverage = farm.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Cobertura de topología", StringComparison.OrdinalIgnoreCase))?.Valor;
        if (evidence.Equals("Sí", StringComparison.OrdinalIgnoreCase))
        {
            sources.Add(new("Farm/Gateway remoto", "No consultado", "Topología/configuración local evaluada; nodos remotos no se sondean activamente en diagnóstico normal.", false));
            limitations.Add("La salud real de Application Servers remotos no fue consultada; TDM sólo conoce evidencia local de la granja.");
        }
        else if (evidence.Contains("determin", StringComparison.OrdinalIgnoreCase) || topologyCoverage?.Equals("Parcial", StringComparison.OrdinalIgnoreCase) == true)
        {
            sources.Add(new("Farm/Gateway remoto", "Parcial", "La topología local no pudo determinarse por completo; no se asume servidor independiente.", false));
            limitations.Add("Una fuente local de topología Farm/Gateway no pudo leerse; la ausencia de granja no está demostrada.");
        }
        else sources.Add(new("Farm/Gateway remoto", "No aplica", "Sin granja activa inferida desde evidencia local evaluable.", false));
    }

    private static void AddPerformanceCoverage(DiagnosticReport report, List<CoverageSourceAssessment> sources, List<string> limitations)
    {
        var perf = report.RendimientoDiagnostico;
        if (perf is null) return;
        if (perf.PresupuestoAgotado)
        {
            sources.Add(new("Collectors TDM", "Timeout", $"Se agotó el presupuesto global; {perf.CollectorsOmitidosPorPresupuesto} fuente(s) quedaron sin ejecutar.", true));
            limitations.Add("El diagnóstico alcanzó su presupuesto global; las fuentes omitidas se consideran NO EVALUADAS y no sanas.");
        }
        else if (perf.CollectorsConTimeout > 0)
        {
            sources.Add(new("Collectors TDM", "Timeout", $"{perf.CollectorsConTimeout} collector(es) excedieron su tiempo máximo.", true));
            limitations.Add("Uno o más collectors fueron cancelados por timeout; sus capas quedan con cobertura parcial.");
        }
        else if (perf.CollectorsConError > 0)
        {
            sources.Add(new("Collectors TDM", "Parcial", $"{perf.CollectorsConError} collector(es) finalizaron con error controlado.", true));
            limitations.Add("Uno o más collectors fallaron de forma controlada; revisar hallazgos COLLECTOR-*.");
        }
        else sources.Add(new("Collectors TDM", "Disponible", $"{perf.CollectorsEjecutados} collectors completaron sin timeout/error controlado.", true));
    }

    private static void AddPresence(DiagnosticReport report, List<CoverageSourceAssessment> sources, string name, string type, bool critical, string ok, string missing, List<string> limitations)
    {
        var observed = report.Eventos.LastOrDefault(e => e.Tipo == type);
        if (observed is not null)
        {
            var declaredCoverage = EvidenceReader.Value(observed, "Cobertura");
            var partial = !string.IsNullOrWhiteSpace(declaredCoverage) &&
                          (declaredCoverage.Contains("Parcial", StringComparison.OrdinalIgnoreCase) ||
                           declaredCoverage.Contains("No evalu", StringComparison.OrdinalIgnoreCase));
            if (partial)
            {
                var detail = $"{ok} Cobertura declarada por la fuente: {declaredCoverage}.";
                sources.Add(new(name, "Parcial", detail, critical));
                limitations.Add($"{name}: la fuente declaró cobertura parcial; la ausencia de un hallazgo no descarta la hipótesis.");
            }
            else sources.Add(new(name, "Disponible", ok, critical));
        }
        else
        {
            sources.Add(new(name, critical ? "No disponible" : "Parcial", missing, critical));
            if (critical) limitations.Add(missing);
        }
    }

    private static bool IsBlocked(string value) =>
        value.StartsWith("Sin permisos", StringComparison.OrdinalIgnoreCase) ||
        value.StartsWith("No legible", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("acceso denegado", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("bloquead", StringComparison.OrdinalIgnoreCase);

    private static double StatusValue(string status) => status switch
    {
        "Disponible" => 1d,
        "No aplica" => 1d,
        "Parcial" => .6d,
        "No consultado" => .55d,
        "Timeout" => .2d,
        "Bloqueada" => 0d,
        "No disponible" => 0d,
        _ => .5d
    };
}
