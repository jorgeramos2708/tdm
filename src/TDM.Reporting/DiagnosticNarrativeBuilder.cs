using System.Text;
using TDM.Models;

namespace TDM.Reporting;

/// <summary>
/// Construye una explicación extendida del diagnóstico a partir de evidencia ya recolectada.
/// No agrega hechos externos ni convierte correlación en causalidad.
/// </summary>
public static class DiagnosticNarrativeBuilder
{
    public static string Build(DiagnosticReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Equipo: {report.Sistema.Equipo}");
        sb.AppendLine($"Sistema: {report.Sistema.SistemaOperativo} {report.Sistema.Version} (build {report.Sistema.Build}, {report.Sistema.Arquitectura})");
        sb.AppendLine($"Remote Access: {(report.Sistema.TsplusDetectado ? $"Detectado ({report.Sistema.TsplusVersion ?? "versión N/D"})" : "No detectado")}");
        var periodoInicio = report.PeriodoAnalizadoInicio == default ? report.Inicio - report.Lookback : report.PeriodoAnalizadoInicio;
        var periodoFin = report.PeriodoAnalizadoFin == default ? report.Inicio : report.PeriodoAnalizadoFin;
        var evidenceLookback = report.EvidenciaDisponibleLookback <= TimeSpan.Zero ? report.Lookback : report.EvidenciaDisponibleLookback;
        var evidenceStart = report.PeriodoEvidenciaInicio == default ? periodoInicio : report.PeriodoEvidenciaInicio;
        var evidenceEnd = report.PeriodoEvidenciaFin == default ? periodoFin : report.PeriodoEvidenciaFin;
        sb.AppendLine($"Evidencia disponible: últimas {FormatLookback(evidenceLookback)} ({evidenceStart:dd/MM/yyyy HH:mm:ss} - {evidenceEnd:dd/MM/yyyy HH:mm:ss})");
        sb.AppendLine($"Vista actual: últimos {FormatLookback(report.Lookback)}");
        sb.AppendLine($"Periodo visible: {periodoInicio:dd/MM/yyyy HH:mm:ss} - {periodoFin:dd/MM/yyyy HH:mm:ss}");
        sb.AppendLine("Modo de vista: FILTRO EN MEMORIA — cambiar el periodo no vuelve a consultar Windows ni TSplus.");
        sb.AppendLine($"Ejecución TDM: {report.Inicio:dd/MM/yyyy HH:mm:ss} - {report.Fin:dd/MM/yyyy HH:mm:ss} (duración {(report.Fin - report.Inicio).TotalSeconds:F1} s)");
        sb.AppendLine($"Hallazgos: {report.Hallazgos.Count} | Observaciones: {report.Eventos.Count} | Incidentes agrupados: {report.Incidentes.Count} | Candidatos: {report.CausasRaiz.Count} | Patrones: {report.PatronesFalla.Count}");
        if (report.RendimientoDiagnostico is { } perf)
            sb.AppendLine($"Rendimiento TDM: {perf.DuracionTotalMs / 1000d:F1} s | collectors={perf.CollectorsEjecutados} | timeouts={perf.CollectorsConTimeout} | errores controlados={perf.CollectorsConError} | más lento={perf.CollectorMasLento} ({perf.CollectorMasLentoMs:F0} ms)");
        if (report.CoberturaDiagnostica is { } coverage)
        {
            sb.AppendLine($"Cobertura diagnóstica explícita: {coverage.Score}/100 · {coverage.Nivel} · limitaciones={coverage.Limitaciones.Count}");
            sb.AppendLine($"Lectura de cobertura: {coverage.Resumen}");
        }
        if (report.PrecisionDiagnostica is { } precision)
        {
            sb.AppendLine($"Calidad de evidencia: {precision.Score}/100 · {precision.Nivel} (no es probabilidad de acierto)");
            sb.AppendLine($"Cobertura crítica completa: {(precision.CoberturaCompleta ? "Sí" : "No")} | Señales causales: {precision.SenalesCausales} | Contexto/telemetría: {precision.EventosContexto} | Conflicto de origen: {(precision.OrigenEnConflicto ? "Sí" : "No")}");
            sb.AppendLine($"Lectura de calidad: {precision.Resumen}");
        }

        var bestSupported = report.CausaRaizPrincipal;
        var mostRecent = report.CausasRaiz.Where(c => c.HoraIncidente.HasValue).OrderByDescending(c => c.HoraIncidente).FirstOrDefault();
        if (mostRecent is not null)
            sb.AppendLine($"Incidente más reciente: {mostRecent.HoraIncidente!.Value.ToLocalTime():dd/MM/yyyy HH:mm:ss} | {ProductName(mostRecent.Producto)} | {mostRecent.Componente} | origen={mostRecent.OrigenClasificado}");
        if (bestSupported is not null)
            sb.AppendLine($"Incidente/candidato mejor sustentado: {(bestSupported.HoraIncidente.HasValue ? bestSupported.HoraIncidente.Value.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss") : "sin hora de incidente")} | {bestSupported.Componente} | {bestSupported.Confianza} | ranking interno {bestSupported.Puntaje}/100");
        if (mostRecent is not null && bestSupported is not null && !ReferenceEquals(mostRecent, bestSupported) && mostRecent.Id == "ROOT-PROCESS-CRASH")
            sb.AppendLine("Nota: el incidente más reciente y el candidato mejor sustentado son distintos; TDM los mantiene separados para evitar que evidencia histórica oculte el problema actual.");
        sb.AppendLine();

        if (report.Incidentes.Count > 0)
        {
            sb.AppendLine("INCIDENTES AGRUPADOS");
            sb.AppendLine("-------------------");
            foreach (var incident in report.Incidentes.Take(12))
                sb.AppendLine($"  - {incident.Id} | {incident.Dominio} | {incident.Estado} | señales={incident.Senales} | {incident.Resumen}");
            sb.AppendLine();
        }

        if (report.PrecisionDiagnostica is { } quality)
        {
            sb.AppendLine("0. CALIDAD Y COBERTURA DE EVIDENCIA");
            sb.AppendLine("---------------------------------");
            foreach (var item in quality.Evidencia) sb.AppendLine($"  - {item.Clave}: {item.Valor}");
            sb.AppendLine("  Interpretación: este puntaje mide cobertura/coherencia de la evidencia disponible; no representa una probabilidad estadística de que la causa raíz sea correcta.");
            sb.AppendLine();
        }

        if (report.CoberturaDiagnostica is { } detailedCoverage)
        {
            sb.AppendLine("0B. AUTODIAGNÓSTICO DE COBERTURA");
            sb.AppendLine("--------------------------------");
            foreach (var source in detailedCoverage.Fuentes)
                sb.AppendLine($"  - {source.Fuente}: {source.Estado} · {source.Detalle}");
            if (detailedCoverage.Limitaciones.Count > 0)
            {
                sb.AppendLine("  Limitaciones:");
                foreach (var limitation in detailedCoverage.Limitaciones) sb.AppendLine($"    - {limitation}");
            }
            sb.AppendLine();
        }

        sb.AppendLine("1. CONCLUSIÓN PRINCIPAL");
        sb.AppendLine("-----------------------");
        if (!report.Sistema.TsplusDetectado)
        {
            sb.AppendLine("Remote Access no está detectado; TDM puede describir anomalías de Windows/productos complementarios, pero no atribuye una causa a Remote Access.");
        }
        else if (bestSupported is null)
        {
            if (report.CausasRaiz.Count == 0)
                sb.AppendLine("TDM no dispone de evidencia suficiente para declarar una causa raíz en la ventana analizada.");
            else
                sb.AppendLine("TDM detectó candidatos causales, pero ninguno tiene suficiente separación de evidencia para declararlo causa raíz principal. Se mantienen como hipótesis competitivas.");
        }
        else
        {
            var c = bestSupported;
            sb.AppendLine($"Candidato principal: {c.Componente}");
            sb.AppendLine($"Producto: {ProductName(c.Producto)}");
            sb.AppendLine($"Capa: {c.Capa}");
            var responsibility = CausalResponsibilityFormatter.Resolve(c);
            sb.AppendLine($"Origen general: {responsibility.OrigenGeneral}");
            sb.AppendLine($"{responsibility.EtiquetaOrigen}: {responsibility.OriginadorEspecifico}");
            sb.AppendLine($"Rol de TSplus: {responsibility.RolTsplus}");
            sb.AppendLine($"Rol de Windows: {responsibility.RolWindows}");
            sb.AppendLine($"Componente TSplus afectado: {responsibility.ComponenteAfectado}");
            if (c.HoraIncidente.HasValue) sb.AppendLine($"Hora del incidente: {c.HoraIncidente.Value.ToLocalTime():dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine($"Estado de investigación: {InvestigationGuidanceBuilder.State(c)}");
            sb.AppendLine($"Ranking interno: {c.Puntaje}/100 | Confianza técnica: {c.Confianza}");
            sb.AppendLine($"DÓNDE EMPEZAR A CORREGIR: {StartHere(c)}");
            sb.AppendLine($"QUÉ NO MODIFICAR PRIMERO: {DoNotModify(c)}");
            sb.AppendLine($"Conclusión observada: {c.Resumen}");
            if (c.Id == "ROOT-PROCESS-CRASH")
            {
                string EV(string key) => c.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
                var exceptionType = EV("Tipo de excepción");
                var scm = EV("Service Control Manager 7031 cercano");
                sb.AppendLine("Mecanismo de falla: TDM sólo confirma los eslabones realmente observados.");
                sb.AppendLine($"  [OBSERVADO] Proceso: {c.Componente}");
                if (!string.Equals(exceptionType, "N/D", StringComparison.OrdinalIgnoreCase)) sb.AppendLine($"  [OBSERVADO] Excepción .NET: {exceptionType}");
                var internalComponent = EV("Componente interno observado");
                if (!string.Equals(internalComponent, "N/D", StringComparison.OrdinalIgnoreCase)) sb.AppendLine($"  [OBSERVADO] Componente interno: {internalComponent}");
                if (!string.Equals(scm, "N/D", StringComparison.OrdinalIgnoreCase)) sb.AppendLine($"  [CONTEXTO] Service Control Manager: {scm}");
            }
        }
        sb.AppendLine();

        sb.AppendLine("1A. IMPACTO FUNCIONAL");
        sb.AppendLine("---------------------");
        if (report.ImpactoFuncional is not { } impact || impact.Impactos.Count == 0)
        {
            sb.AppendLine("Impacto no determinado con la cobertura actual.");
        }
        else
        {
            sb.AppendLine($"Estado general: {impact.EstadoGeneral}");
            sb.AppendLine($"Lectura: {impact.Resumen}");
            foreach (var item in impact.Impactos)
            {
                sb.AppendLine($"  - {item.Funcion} [{item.Modulo}]: {item.Estado} · confianza {item.Confianza}");
                sb.AppendLine($"    {item.Resumen}");
            }
        }
        sb.AppendLine();

        sb.AppendLine("1A.1 PLAN DE ACTUACIÓN SEGURO");
        sb.AppendLine("-----------------------------");
        if (report.PlanAccion is not { } plan)
        {
            sb.AppendLine("Plan no disponible.");
        }
        else
        {
            sb.AppendLine(plan.Resumen);
            sb.AppendLine("DÓNDE EMPEZAR:");
            foreach (var step in plan.DondeEmpezar) sb.AppendLine($"  {step.Orden}. {step.Accion} — {step.Motivo}");
            sb.AppendLine("QUÉ NO TOCAR PRIMERO:");
            foreach (var step in plan.NoTocarPrimero) sb.AppendLine($"  - {step.Accion} — {step.Motivo}");
            sb.AppendLine("VERIFICACIONES:");
            foreach (var step in plan.Verificaciones) sb.AppendLine($"  - {step.Accion} — {step.Motivo}");
        }
        sb.AppendLine();

        var crashIncidents = report.CausasRaiz
            .Where(c => c.Id == "ROOT-PROCESS-CRASH" && c.HoraIncidente.HasValue)
            .OrderByDescending(c => c.HoraIncidente)
            .Take(8)
            .ToList();
        if (crashIncidents.Count > 0)
        {
            sb.AppendLine("1B. INCIDENTES DETECTADOS / AGRUPACIÓN TEMPORAL");
            sb.AppendLine("--------------------------------------------");
            foreach (var incident in crashIncidents)
            {
                var origin = incident.Evidencia.FirstOrDefault(e => e.Clave.Equals("Origen técnico más bajo sustentado", StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
                var semantic = incident.Evidencia.FirstOrDefault(e => e.Clave.Equals("Componente semántico", StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
                var recurrence = incident.Evidencia.FirstOrDefault(e => e.Clave.Equals("Recurrencia observada", StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
                var labels = new List<string>();
                if (ReferenceEquals(incident, mostRecent)) labels.Add("MÁS RECIENTE");
                if (ReferenceEquals(incident, bestSupported)) labels.Add("MEJOR SUSTENTADO");
                var tag = labels.Count == 0 ? "" : $" [{string.Join(" / ", labels)}]";
                sb.AppendLine($"  - {incident.HoraIncidente!.Value.ToLocalTime():dd/MM/yyyy HH:mm:ss}{tag} | {ProductName(incident.Producto)} | {incident.Componente}");
                sb.AppendLine($"    Origen={incident.OrigenClasificado}; componente funcional={semantic}; estado={InvestigationGuidanceBuilder.State(incident)}; recurrencia={recurrence}.");
                sb.AppendLine($"    Origen técnico sustentado: {origin}");
            }
            sb.AppendLine("Los incidentes se agrupan por aplicación y proximidad temporal. TDM no fusiona productos distintos salvo que exista una dependencia o antecedente común demostrable.");
            sb.AppendLine();
        }

        if (report.PatronesFalla.Count > 0)
        {
            sb.AppendLine("1C. PATRONES DE FALLA EN LA VENTANA");
            sb.AppendLine("-----------------------------------");
            foreach (var pattern in report.PatronesFalla.Take(12))
            {
                var recurrence = pattern.Incidentes > 1 ? "RECURRENTE" : "AISLADO";
                sb.AppendLine($"  - {recurrence} | {ProductName(pattern.Producto)} | {pattern.ComponenteSemantico}");
                sb.AppendLine($"    Incidentes={pattern.Incidentes}; excepción={pattern.TipoExcepcion}; origen={pattern.OrigenClasificado}; estado={pattern.EstadoInvestigacion}.");
                sb.AppendLine($"    Primera={pattern.PrimeraDeteccion.ToLocalTime():dd/MM/yyyy HH:mm:ss}; última={pattern.UltimaDeteccion.ToLocalTime():dd/MM/yyyy HH:mm:ss}; intervalo promedio={(pattern.IntervaloPromedio.HasValue ? FormatLookback(pattern.IntervaloPromedio.Value) : "No aplica")}.");
            }
            sb.AppendLine("La recurrencia de un patrón aumenta su prioridad operativa, pero no convierte por sí sola el mecanismo observado en causa primaria confirmada.");
            sb.AppendLine();
        }

        sb.AppendLine("1D. DEPENDENCIA COMÚN ENTRE PRODUCTOS");
        sb.AppendLine("------------------------------------");
        AppendSharedDependencyAssessment(sb, report);
        sb.AppendLine();

        sb.AppendLine("2. CADENA CAUSAL / TEMPORAL OBSERVADA");
        sb.AppendLine("------------------------------------");
        AppendCausalChain(sb, report);
        sb.AppendLine();

        sb.AppendLine("3. DEPENDENCIAS Y ESTADO ACTUAL");
        sb.AppendLine("--------------------------------");
        var health = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_DEPENDENCY_HEALTH");
        if (health?.Evidencia is { Count: > 0 })
            foreach (var e in health.Evidencia) sb.AppendLine($"  - {e.Clave}: {e.Valor}");
        else sb.AppendLine("No se obtuvo un snapshot consolidado de dependencias.");
        var resources = report.Eventos.LastOrDefault(e => e.Tipo == "SYSTEM_RESOURCE_STATE");
        if (resources?.Evidencia is { Count: > 0 })
        {
            sb.AppendLine("  Recursos actuales:");
            foreach (var e in resources.Evidencia) sb.AppendLine($"    - {e.Clave}: {e.Valor}");
        }
        sb.AppendLine();

        sb.AppendLine("4. PRODUCTOS TSPLUS OBSERVADOS");
        sb.AppendLine("------------------------------");
        var products = report.Eventos.Where(e => e.Tipo == "TSPLUS_PRODUCT_STATE").OrderBy(e => e.Producto).ToList();
        if (products.Count == 0) sb.AppendLine("No se obtuvo inventario de productos.");
        foreach (var p in products)
        {
            string V(string key) => p.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
            sb.AppendLine($"  - {p.Componente}: instalación={V("Instalación")}; operación={V("Operación observada")}; salud={V("Salud")}; relación RA={V("Relación con Remote Access")}");
        }
        sb.AppendLine();

        sb.AppendLine("4B. USUARIOS, PERFILES Y SESIONES");
        sb.AppendLine("---------------------------------");
        var userInventory = report.Eventos.LastOrDefault(e => e.Tipo == "USER_SESSION_INVENTORY");
        if (userInventory?.Evidencia is { Count: > 0 })
        {
            foreach (var e in userInventory.Evidencia) sb.AppendLine($"  - {e.Clave}: {e.Valor}");
            var accounts = report.Eventos.Where(e => e.Tipo == "USER_ACCOUNT_STATE").Take(60).ToList();
            if (accounts.Count > 0)
            {
                sb.AppendLine("  Cuentas locales:");
                foreach (var account in accounts)
                {
                    string A(string key) => account.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                    sb.AppendLine($"    - {A("Usuario")}: habilitada={A("Habilitada")}; bloqueada={A("Bloqueada")}; contraseña expirada={A("Contraseña expirada")}; cuenta expira={A("Cuenta expira")}; grupos={A("Grupos locales")}; perfil={A("Perfil registrado")}");
                }
            }
            sb.AppendLine("  Sesiones observadas:");
            foreach (var session in report.Eventos.Where(e => e.Tipo == "USER_SESSION_STATE").Where(e => (e.Evidencia?.FirstOrDefault(x => x.Clave == "Usuario")?.Valor ?? "N/D") != "N/D").Take(30))
            {
                string V(string key) => session.Evidencia?.FirstOrDefault(x => x.Clave == key)?.Valor ?? "N/D";
                sb.AppendLine($"    - {V("Dominio")}\\{V("Usuario")}: SessionId={V("SessionId")}; estado={V("Estado")}; protocolo={V("Protocolo")}; cliente={V("Cliente")}; perfil={V("Perfil")}");
            }
        }
        else sb.AppendLine("No se obtuvo inventario de usuarios/sesiones.");
        var userProblems = report.Hallazgos.Where(f => f.Id.StartsWith("USER-PROFILE-", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var f in userProblems.Take(30)) sb.AppendLine($"  - [{f.Severidad}] {f.Resumen}");
        sb.AppendLine();

        sb.AppendLine("4C. CONFIGURACIÓN INTERNA TSPLUS");
        sb.AppendLine("--------------------------------");
        var appControl = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_APPCONTROL_STATE");
        if (appControl?.Evidencia is { Count: > 0 })
            foreach (var e in appControl.Evidencia) sb.AppendLine($"  - {e.Clave}: {e.Valor}");
        else sb.AppendLine("  - AppControl.ini: no auditado/no disponible.");
        sb.AppendLine($"  - Aplicaciones publicadas inventariadas: {report.Eventos.Count(e => e.Tipo == "TSPLUS_PUBLISHED_APPLICATION")}");
        var appSecurity = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_APPCONTROL_SECURITY_STATE");
        if (appSecurity?.Evidencia is { Count: > 0 })
            foreach (var e in appSecurity.Evidencia.Where(x => x.Clave != "Archivo")) sb.AppendLine($"  - AppControl/Security {e.Clave}: {e.Valor}");
        var webStack = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_WEB_STACK_STATE");
        if (webStack?.Evidencia is { Count: > 0 })
            foreach (var e in webStack.Evidencia) sb.AppendLine($"  - {e.Clave}: {e.Valor}");
        var webRuntime = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_WEB_RUNTIME_STATE");
        if (webRuntime?.Evidencia is { Count: > 0 })
            foreach (var e in webRuntime.Evidencia) sb.AppendLine($"  - Web/HTML5 {e.Clave}: {e.Valor}");

        var fileInventories = report.Eventos.Where(e => e.Tipo == "TSPLUS_INTERNAL_FILE_INVENTORY").ToList();
        if (fileInventories.Count > 0)
        {
            sb.AppendLine("  - Inventario de archivos TSplus (metadatos, solo lectura):");
            foreach (var inv in fileInventories.Take(12))
            {
                string V(string key) => inv.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
                sb.AppendLine($"    · {V("Producto")}: raíz={V("Raíz")}; relevantes={V("Archivos relevantes")}; binarios 0 bytes={V("Binarios 0 bytes")}; cambios en ventana={V("Cambios de código/configuración en ventana")}; truncado={V("Inventario truncado")}");
            }
        }

        var configProblems = report.Hallazgos.Where(f =>
            f.Id.StartsWith("TSPLUS-APPCONTROL-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-PUBLISHED-APP-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-WEB-CONFIG-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-WEB-RUNTIME-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-WEB-PORT-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-WEB-JVM-CRASH-", StringComparison.OrdinalIgnoreCase) ||
            f.Id.StartsWith("TSPLUS-INTEGRITY-", StringComparison.OrdinalIgnoreCase)).ToList();
        if (configProblems.Count == 0) sb.AppendLine("  - Anomalías internas detectadas: 0 en las comprobaciones implementadas.");
        else foreach (var f in configProblems.Take(40)) sb.AppendLine($"  - [{f.Severidad}] {f.Componente}: {f.Resumen}");
        sb.AppendLine("  - Archivos sensibles: TDM conserva sólo metadatos y no exporta credenciales.");
        sb.AppendLine();

        sb.AppendLine("5. HIPÓTESIS REVISADAS / DESCARTADAS");
        sb.AppendLine("-----------------------------------");
        AppendHypotheses(sb, report);
        sb.AppendLine();

        sb.AppendLine("6. IMPRESIÓN TSPLUS / WINDOWS");
        sb.AppendLine("------------------------------");
        var printing = report.Eventos.LastOrDefault(e => e.Tipo == "PRINTING_STATE");
        if (printing?.Evidencia is { Count: > 0 })
        {
            foreach (var e in printing.Evidencia) sb.AppendLine($"  - {e.Clave}: {e.Valor}");
            var printEvents = report.Eventos.Count(e => e.Tipo.StartsWith("PRINT_EVENT_", StringComparison.OrdinalIgnoreCase));
            sb.AppendLine($"  - Eventos PrintService relevantes en la ventana: {printEvents}");
        }
        else sb.AppendLine("No se obtuvo snapshot de impresión.");
        sb.AppendLine();

        sb.AppendLine("7. ESTADO DE INVESTIGACIÓN Y SIGUIENTE ACCIÓN");
        sb.AppendLine("----------------------------------------------");
        InvestigationGuidanceBuilder.Append(sb, report, bestSupported);
        sb.AppendLine();
        sb.AppendLine("ACCIONES GENERALES (NO SE EJECUTAN):");
        if (bestSupported is null)
        {
            sb.AppendLine("  1) Conserva el reporte y revisa el impacto funcional confirmado antes de investigar causas.");
            sb.AppendLine("  2) Revisa las hipótesis competitivas y las fuentes bloqueadas; una hipótesis no se eleva a causa sólo por proximidad temporal.");
            sb.AppendLine("  3) No reinstales TSplus ni reinicies servicios de forma indiscriminada sin evidencia que justifique el cambio.");
        }
        else
        {
            var c = bestSupported;
            sb.AppendLine($"  1) Comienza por el origen clasificado como {c.OrigenClasificado}; atiende primero la capa causal más baja demostrada y no presentes el mecanismo de caída como causa primaria.");
            if (!string.IsNullOrWhiteSpace(c.SolucionSugerida)) sb.AppendLine($"  2) {c.SolucionSugerida}");
            else sb.AppendLine("  2) Revisa manualmente el componente y los eventos inmediatamente anteriores al síntoma.");
            sb.AppendLine("  3) Después de corregir la causa, vuelve a ejecutar TDM y compara el nuevo baseline/timeline.");
            sb.AppendLine("  4) Si el fallo persiste y la evidencia termina en un crash de aplicación sin causa demostrable, recopila el material que solicite soporte/fabricante; TDM no habilita dumps automáticamente.");
            if (!string.IsNullOrWhiteSpace(c.FuenteOficial)) sb.AppendLine($"  Fuente: {c.FuenteOficial} — {c.UrlOficial}");
        }
        sb.AppendLine();

        sb.AppendLine("8. LIMITACIONES Y EVIDENCIA INSUFICIENTE");
        sb.AppendLine("----------------------------------------");
        var undated = report.Eventos.Count(e => !e.Timestamp.HasValue && e.Severidad != DiagnosticSeverity.Informativo);
        sb.AppendLine($"  - Evidencia relevante sin timestamp: {undated} observación(es). No participa en correlación temporal.");
        var baseline = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_INSTALLATION_BASELINE");
        var logCoverage = baseline?.Evidencia?.FirstOrDefault(e => e.Clave.Contains("Fuentes de log", StringComparison.OrdinalIgnoreCase))?.Valor;
        if (!string.IsNullOrWhiteSpace(logCoverage)) sb.AppendLine($"  - Cobertura de logs Remote Access: {logCoverage}.");
        if (report.Hallazgos.Any(f => f.Id == "FORENSIC-COVERAGE-INCOMPLETE"))
            sb.AppendLine("  - Cobertura forense incompleta: al menos una fuente no pudo leerse por permisos/error. TDM no la interpreta como sana ni descartada.");
        sb.AppendLine("  - Un módulo Windows listado como 'faulting module' identifica el punto de manifestación, no necesariamente la causa técnica.");
        sb.AppendLine("  - TDM no evalúa licencias, no activa productos y no usa el estado de licencia para decidir una causa raíz.");
        sb.AppendLine("  - TDM es de solo lectura sobre Windows/TSplus: no reinicia servicios ni modifica Registro, firewall, archivos de producto, impresoras o configuración TSplus. El historial de RC18.4 se guarda únicamente en archivos propios de TDM.");
        return sb.ToString();
    }

    private static void AppendCausalChain(StringBuilder sb, DiagnosticReport report)
    {
        var primary = report.CausaRaizPrincipal;
        if (primary is null) { sb.AppendLine("No hay una cadena causal suficientemente sustentada."); return; }

        if (primary.Id == "ROOT-PROCESS-CRASH")
        {
            string EV(string key) => primary.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
            var app = EV("Aplicación");
            if (string.Equals(app, "N/D", StringComparison.OrdinalIgnoreCase)) app = primary.Componente;
            var related = report.Eventos
                .Where(e => e.Timestamp.HasValue && (e.Mensaje.Contains(app, StringComparison.OrdinalIgnoreCase) || e.Componente.Contains(Path.GetFileNameWithoutExtension(app), StringComparison.OrdinalIgnoreCase)))
                .Where(e => (e.Tipo is "DOTNET_UNHANDLED_EXCEPTION" or "APPLICATION_CRASH" or "WER_REPORT") || e.Codigo == "7031")
                .OrderBy(e => e.Timestamp).Take(16).ToList();
            if (related.Count == 0) { sb.AppendLine("Se detectó el crash, pero no se reconstruyeron eventos auxiliares suficientes."); return; }

            sb.AppendLine($"  [INFERIDO] Origen técnico más bajo: {EV("Origen técnico más bajo sustentado")} ({EV("Estado del origen")})");
            var antecedentWindows = EV("Antecedente Windows más cercano");
            if (!string.Equals(antecedentWindows, "N/D", StringComparison.OrdinalIgnoreCase)) sb.AppendLine($"  [ANTECEDENTE] Windows: {antecedentWindows}");
            var antecedentTsplus = EV("Antecedente TSplus más cercano");
            if (!string.Equals(antecedentTsplus, "N/D", StringComparison.OrdinalIgnoreCase)) sb.AppendLine($"  [ANTECEDENTE] TSplus: {antecedentTsplus}");
            foreach (var e in related)
            {
                var status = e.Tipo == "DOTNET_UNHANDLED_EXCEPTION" || e.Tipo == "APPLICATION_CRASH" || e.Codigo == "7031" ? "OBSERVADO" : "CORRELACIONADO";
                sb.AppendLine($"  [{status}] {e.Timestamp!.Value.ToLocalTime():dd/MM/yyyy HH:mm:ss.fff} → {e.Tipo} / {e.Fuente}: {TrimOneLine(e.Mensaje, 180)}");
            }
            return;
        }

        if (primary.Id == "ROOT-PRINT-SPOOLER")
        {
            sb.AppendLine("  Componente de impresión TSplus → Windows Printing → Print Spooler → PrintService/RPC.");
            sb.AppendLine("  Spooler indisponible es una dependencia previa al procesamiento de trabajos; debe corregirse antes de reinstalar el componente TSplus.");
            return;
        }
        if (primary.Id.StartsWith("ROOT-RDP", StringComparison.OrdinalIgnoreCase))
        {
            sb.AppendLine("  Remote Access → RDP/Listener → TermService → pila de sesiones de Windows.");
            sb.AppendLine("  La anomalía RDP/TermService se encuentra por debajo de TSplus y debe investigarse primero.");
            return;
        }
        if (primary.Id == "ROOT-TSPLUS-APS")
        {
            sb.AppendLine("  Remote Access → Application Publishing Service/APSC → publicación/control de sesiones.");
            return;
        }
        if (primary.Id == "ROOT-DEPENDENCY-LOAD")
        {
            sb.AppendLine("  Proceso TSplus → carga de dependencia/DLL/assembly → subsistema de Windows → fallo de carga → crash o funcionalidad no disponible.");
            return;
        }
        if (primary.Id.StartsWith("ROOT-SECURITY", StringComparison.OrdinalIgnoreCase))
        {
            sb.AppendLine("  Producto de seguridad → acción sobre archivo/proceso TSplus → archivo/proceso afectado → error TSplus posterior.");
            return;
        }
        sb.AppendLine("La evidencia apunta al candidato principal, pero no existe una cadena causal completa para representarla como confirmada.");
    }

    private static void AppendHypotheses(StringBuilder sb, DiagnosticReport report)
    {
        bool Has(string id) => report.Hallazgos.Any(f => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        var rdpState = report.Eventos.LastOrDefault(e => e.Tipo == "RDP_STATE");
        var printState = report.Eventos.LastOrDefault(e => e.Tipo == "PRINTING_STATE");
        var defenderTsplus = report.Eventos.Any(e => (e.Tipo is "DEFENDER_THREAT_DETECTED" or "DEFENDER_ACTION_TAKEN") &&
            ($"{e.Mensaje} {e.Archivo}").Contains("TSplus", StringComparison.OrdinalIgnoreCase));
        var depLoad = report.Eventos.Any(e => e.Tipo is "SIDEBYSIDE_DEPENDENCY_FAILURE" or "DEPENDENCY_NOT_FOUND" or "DEPENDENCY_LOAD_FAILURE" or "DLL_NOT_FOUND" or "INVALID_IMAGE_FORMAT");

        sb.AppendLine(Has("RDP-TERMSERVICE-NOT-RUNNING") || Has("RDP-LISTENER-NOT-LISTENING")
            ? "  - RDP/TermService: existe anomalía; permanece como hipótesis activa."
            : "  - RDP/TermService: sin falla estructural demostrada por las comprobaciones actuales.");
        sb.AppendLine(Has("PRINT-SPOOLER-DOWN")
            ? "  - Impresión/Spooler: existe anomalía; puede explicar síntomas de Universal/Virtual Printer."
            : "  - Impresión/Spooler: no se detectó Spooler caído en el snapshot actual.");
        sb.AppendLine(defenderTsplus
            ? "  - Defender/EDR: existe evidencia relacionada con TSplus y requiere correlación."
            : "  - Defender/EDR: no se detectó una acción explícita sobre TSplus dentro de la evidencia recopilada.");
        sb.AppendLine(depLoad
            ? "  - Dependencias/DLL: existen eventos de carga y deben correlacionarse con el producto afectado."
            : "  - Dependencias/DLL: no se detectó una falla explícita de carga relacionada con TSplus en la ventana.");

        var primary = report.CausaRaizPrincipal;
        if (primary?.Id == "ROOT-PROCESS-CRASH")
        {
            string EV(string key) => primary.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
            var semantic = EV("Componente semántico");
            var directed = EV("Dependencias dirigidas - estado actual");
            if (!string.Equals(semantic, "N/D", StringComparison.OrdinalIgnoreCase))
                sb.AppendLine($"  - Análisis dirigido: {semantic}. Estado actual observado: {directed}.");
            if (primary.OrigenClasificado == "TSPLUS" && EV("Antecedentes Windows fuertes") == "0")
            {
                var causalWindow = EV("Ventana causal efectiva");
                sb.AppendLine($"  - Windows subyacente: no se encontró antecedente fuerte en la ventana causal evaluada ({causalWindow}); esto orienta al producto, pero no demuestra la causa primaria interna.");
            }
        }

        var unrelated = report.CausasRaiz.Where(c => c.Producto is TsplusProduct.ServerMonitoring or TsplusProduct.AdvancedSecurity or TsplusProduct.RemoteSupport).ToList();
        if (unrelated.Count > 0) sb.AppendLine("  - Productos complementarios: se detectaron anomalías independientes; no se atribuye impacto a Remote Access sin evidencia directa.");
    }

    private static string FormatLookback(TimeSpan value)
    {
        if (value <= TimeSpan.Zero) return "N/D";
        if (value.TotalDays >= 1) return $"{value.TotalDays:F1} días";
        if (value.TotalHours >= 1) return value.TotalHours == 1 ? "1 h" : $"{value.TotalHours:F0} h";
        if (value.TotalMinutes >= 1) return value.TotalMinutes == 1 ? "1 min" : $"{value.TotalMinutes:F0} min";
        return $"{value.TotalSeconds:F0} s";
    }

    private static string StartHere(RootCauseCandidate c)
    {
        string EV(string key) => c.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
        var semantic = EV("Componente semántico");
        return c.OrigenClasificado switch
        {
            "WINDOWS" => $"Windows / {c.Componente}. Valida primero la dependencia o evento antecedente señalado antes de tocar TSplus.",
            "TSPLUS" => $"{ProductName(c.Producto)} / {(semantic == "N/D" ? c.Componente : semantic)}. La evidencia actual no justifica reparar Windows primero.",
            "DEPENDENCIA EXTERNA" => $"Dependencia externa / {c.Componente}. Confirma disponibilidad, integridad y versión antes de reinstalar TSplus.",
            _ => "No aplicar cambios todavía. Obtén evidencia que discrimine Windows frente a TSplus antes de elegir una reparación."
        };
    }

    private static string DoNotModify(RootCauseCandidate c) => c.OrigenClasificado switch
    {
        "WINDOWS" => "No reinstales ni reconfigures TSplus mientras la falla Windows subyacente siga demostrada.",
        "TSPLUS" => "No repares RDP, RPC, Spooler, WMI ni componentes generales de Windows sin evidencia causal previa que los implique.",
        "DEPENDENCIA EXTERNA" => "No cambies indiscriminadamente Windows o la configuración de TSplus antes de validar la dependencia específica.",
        _ => "No modifiques Windows ni TSplus basándote únicamente en una hipótesis indeterminada."
    };

    private static void AppendSharedDependencyAssessment(StringBuilder sb, DiagnosticReport report)
    {
        var incidents = report.CausasRaiz
            .Where(c => c.Id == "ROOT-PROCESS-CRASH" && c.HoraIncidente.HasValue && c.Producto != TsplusProduct.Ninguno)
            .OrderBy(c => c.HoraIncidente)
            .ToList();
        if (incidents.Select(c => c.Producto).Distinct().Count() < 2)
        {
            sb.AppendLine("  No hay suficientes incidentes de productos distintos para buscar una dependencia común.");
            return;
        }

        static bool StrongWindows(DiagnosticEvent e) =>
            e.Timestamp.HasValue &&
            (e.Capa is DiagnosticLayer.Windows or DiagnosticLayer.Rdp or DiagnosticLayer.Red or DiagnosticLayer.Seguridad) &&
            (e.Severidad == DiagnosticSeverity.Critico ||
             e.Tipo is "SIDEBYSIDE_DEPENDENCY_FAILURE" or "DEPENDENCY_NOT_FOUND" or "DEPENDENCY_LOAD_FAILURE" or "DLL_NOT_FOUND" or "INVALID_IMAGE_FORMAT" or "DEFENDER_ACTION_TAKEN" ||
             e.Codigo is "7000" or "7001" or "7009" or "7011" or "7023" or "7024" or "55" or "129" or "153");

        var signals = report.Eventos.Where(StrongWindows).ToList();
        var commonWindow = report.Lookback > TimeSpan.Zero && report.Lookback < TimeSpan.FromMinutes(5)
            ? report.Lookback
            : TimeSpan.FromMinutes(5);
        var common = new List<(DiagnosticEvent Event, int Products)>();
        foreach (var ev in signals)
        {
            var products = incidents
                .Where(i => i.HoraIncidente!.Value >= ev.Timestamp!.Value && i.HoraIncidente.Value - ev.Timestamp.Value <= commonWindow)
                .Select(i => i.Producto)
                .Distinct()
                .Count();
            if (products >= 2) common.Add((ev, products));
        }

        if (common.Count == 0)
        {
            sb.AppendLine($"  No se encontró un antecedente Windows fuerte común dentro de {FormatLookback(commonWindow)} previos a incidentes de productos TSplus distintos.");
            sb.AppendLine("  Los incidentes permanecen separados; TDM no asume una causa común por simple proximidad temporal.");
            return;
        }

        sb.AppendLine("  POSIBLE DEPENDENCIA COMÚN: existe evidencia Windows previa compartida por varios productos; requiere validación causal antes de atribuirle todos los incidentes.");
        foreach (var item in common.OrderByDescending(x => x.Event.Timestamp).Take(5))
            sb.AppendLine($"  - {item.Event.Timestamp!.Value.ToLocalTime():dd/MM/yyyy HH:mm:ss} | {item.Event.Fuente} | {item.Event.Codigo ?? item.Event.Tipo} | productos posteriores={item.Products} | {TrimOneLine(item.Event.Mensaje, 160)}");
    }

    private static string ProductName(TsplusProduct p) => p switch
    {
        TsplusProduct.RemoteAccess => "TSplus Remote Access",
        TsplusProduct.TwoFactorAuthentication => "TSplus 2FA",
        TsplusProduct.AdvancedSecurity => "TSplus Advanced Security",
        TsplusProduct.ServerMonitoring => "TSplus Server Monitoring",
        TsplusProduct.RemoteSupport => "TSplus Remote Support",
        _ => "No determinado"
    };

    private static string TrimOneLine(string value, int max)
    {
        var one = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return one;
    }
}
