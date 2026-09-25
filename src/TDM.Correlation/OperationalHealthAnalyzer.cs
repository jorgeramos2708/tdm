using System.Text.RegularExpressions;
using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// Post-procesador conservador del diagnóstico normal. Convierte evidencia ya recopilada
/// en salud funcional por módulo y patrones de recurrencia. No realiza I/O ni acciones
/// adicionales sobre Windows/TSplus.
/// </summary>
public static partial class OperationalHealthAnalyzer
{
    public static DiagnosticReport Enrich(DiagnosticReport report)
    {
        var findings = report.Hallazgos.ToList();
        var events = report.Eventos.ToList();

        DeriveCrashLoops(report, findings, events);
        DeriveModuleHealth(report with { Hallazgos = findings, Eventos = events }, findings, events);

        return report with { Hallazgos = findings, Eventos = events };
    }

    private static void DeriveCrashLoops(
        DiagnosticReport report,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> output)
    {
        var candidates = report.Eventos
            .Where(e => e.Timestamp.HasValue)
            .Where(e => e.Tipo is "SERVICE_TERMINATION" or "APPLICATION_CRASH" or "DOTNET_UNHANDLED_EXCEPTION" or "TSPLUS_HTML5_JVM_CRASH")
            .Where(e => IsTsplusRelated(e, report.Sistema))
            .ToList();

        foreach (var group in candidates.GroupBy(FailureSignature, StringComparer.OrdinalIgnoreCase))
        {
            var ordered = group.OrderBy(e => e.Timestamp).ToList();
            if (ordered.Count == 0) continue;

            var reportedCount = ordered.Select(e => ParseReportedRecurrence(e.Mensaje)).DefaultIfEmpty(0).Max();
            var visibleCount = ordered.Count;
            if (visibleCount < 3 && reportedCount < 3) continue;

            var first = ordered[0].Timestamp!.Value;
            var last = ordered[^1].Timestamp!.Value;
            TimeSpan? avg = null;
            if (visibleCount > 1)
            {
                long ticks = 0;
                for (var i = 1; i < ordered.Count; i++) ticks += (ordered[i].Timestamp!.Value - ordered[i - 1].Timestamp!.Value).Ticks;
                avg = TimeSpan.FromTicks(ticks / (visibleCount - 1));
            }

            var exemplar = ordered[^1];
            var product = ResolveProduct(exemplar);
            var severity = ordered.Any(e => e.Severidad == DiagnosticSeverity.Critico)
                ? DiagnosticSeverity.Critico
                : DiagnosticSeverity.Error;
            var component = NormalizeFailureComponent(exemplar);
            var effective = Math.Max(visibleCount, reportedCount);
            var id = $"TSPLUS-CRASH-LOOP-{Sanitize(product.ToString())}-{StableHash(group.Key):X8}";
            if (findings.Any(f => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase))) continue;

            var detail = reportedCount > visibleCount
                ? $"En la ventana visible se observaron {visibleCount} evento(s), y Service Control Manager/reportes asociados indican un contador acumulado de {reportedCount}. El contador acumulado no se interpreta como {reportedCount} incidentes dentro de la ventana; se usa únicamente como señal de inestabilidad recurrente."
                : $"Se observaron {visibleCount} fallas equivalentes del mismo componente dentro de la ventana analizada.";

            var evidence = new List<EvidenceItem>
            {
                new("Producto", ProductName(product)),
                new("Componente", component),
                new("Tipo", exemplar.Tipo),
                new("Eventos visibles equivalentes", visibleCount.ToString()),
                new("Contador SCM/reportado", reportedCount > 0 ? reportedCount.ToString() : "No disponible"),
                new("Primera detección visible", first.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                new("Última detección visible", last.ToLocalTime().ToString("dd/MM/yyyy HH:mm:ss")),
                new("Intervalo promedio visible", avg.HasValue ? FormatInterval(avg.Value) : "No aplica"),
                new("Interpretación causal", "La recurrencia confirma inestabilidad; no identifica por sí sola la causa primaria")
            };

            findings.Add(new DiagnosticFinding(
                id,
                component,
                severity,
                effective >= 10 ? "Se detectó un patrón severamente recurrente de caída/reinicio." : "Se detectó un patrón recurrente de caída/reinicio.",
                detail,
                evidence,
                ConfidenceLevel.Alta,
                "Microsoft Service Control Manager / Windows Error Reporting + evidencia TSplus",
                null,
                "Priorice la causa del primer crash/excepción del patrón y sus dependencias. No reinicie ni reinstale componentes de forma automática desde TDM.",
                exemplar.Capa));

            output.Add(new DiagnosticEvent(
                last,
                "TDM",
                component,
                exemplar.Capa,
                severity,
                "TSPLUS_CRASH_LOOP_PATTERN",
                effective >= 10
                    ? $"Patrón recurrente de alta frecuencia detectado para {component}."
                    : $"Patrón recurrente detectado para {component}.",
                Evidencia: evidence,
                Producto: product));
        }
    }

    private static void DeriveModuleHealth(
        DiagnosticReport report,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> output)
    {
        var definitions = new[]
        {
            new ModuleDefinition("RDP / Remote Access Core", TsplusProduct.RemoteAccess, DiagnosticLayer.Rdp,
                ["RDP", "TermService", "Remote Desktop", "Winlogon", "logonsession", "NLA", "CredSSP", "contraseña", "credenciales"],
                "Creación y mantenimiento de sesiones remotas", "RDP_STATE", "TSPLUS_REMOTEACCESS_MODULE_STATE"),
            new ModuleDefinition("Web / HTML5 / Web Portal", TsplusProduct.RemoteAccess, DiagnosticLayer.Tsplus,
                ["Web", "HTML5", "httpwebs", "settings.js", "Web Portal"],
                "Acceso web, HTML5 y portal", "TSPLUS_WEB_FILESET_STATE", "TSPLUS_WEB_RUNTIME_STATE"),
            new ModuleDefinition("Aplicaciones publicadas", TsplusProduct.RemoteAccess, DiagnosticLayer.Tsplus,
                ["AppControl", "Publicación", "Application Publishing", "Published Application", "TSPLUS_PUBLISHED"],
                "Publicación, asignación y lanzamiento de aplicaciones", "TSPLUS_APPLICATION_FILESET_STATE", "TSPLUS_APPCONTROL_STATE"),
            new ModuleDefinition("Sesiones / perfiles / logon", TsplusProduct.RemoteAccess, DiagnosticLayer.Tsplus,
                ["Sesion", "Sesión", "Perfil", "logon", "wsession", "APSC", "NLA", "CredSSP", "contraseña", "credenciales", "Active Directory"],
                "Inicio, continuidad y perfil de sesiones", "TSPLUS_SESSION_FILESET_STATE", "USER_SESSION_INVENTORY"),
            new ModuleDefinition("Farm / Gateway / Load Balancing / Reverse Proxy", TsplusProduct.RemoteAccess, DiagnosticLayer.Tsplus,
                ["Farm", "Gateway", "Load Balanc", "Reverse Proxy", "balance.bin"],
                "Enrutamiento y distribución de conexiones de la granja", "TSPLUS_FARM_CONFIGURATION_STATE", "TSPLUS_WEB_BALANCE_STATE"),
            new ModuleDefinition("Universal Printer", TsplusProduct.RemoteAccess, DiagnosticLayer.Tsplus,
                ["Universal Printer", "novaPDF"],
                "Impresión universal desde sesiones TSplus", "TSPLUS_UNIVERSAL_PRINTER_STATE", "PRINTING_STATE"),
            new ModuleDefinition("Virtual Printer", TsplusProduct.RemoteAccess, DiagnosticLayer.Tsplus,
                ["Virtual Printer", "Virtual Devices"],
                "Impresión virtual redirigida por sesión", "TSPLUS_VIRTUAL_PRINTER_STATE", "PRINTING_STATE"),
            new ModuleDefinition("Two-Factor Authentication (2FA)", TsplusProduct.TwoFactorAuthentication, DiagnosticLayer.Tsplus,
                ["Two-Factor", "TwoFactor", "2FA"],
                "Segundo factor de autenticación de Remote Access", "TSPLUS_REMOTEACCESS_MODULE_STATE", "TSPLUS_PRODUCT_STATE"),
            new ModuleDefinition("Advanced Security", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security", "TSplus-Security", "Security Service"],
                "Protecciones de Advanced Security", "TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE", "TSPLUS_ADVSEC_MODULE_SUMMARY"),
            new ModuleDefinition("Advanced Security / Firewall", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Firewall"], "Filtrado y bloqueo de conexiones", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Geographic Protection", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Geographic Protection"], "Control geográfico de conexiones entrantes", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Bruteforce Protection", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Bruteforce Protection"], "Bloqueo de intentos de autenticación repetidos", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Hacker IP Protection", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Hacker IP Protection"], "Bloqueo de IPs conocidas como maliciosas", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Restrict Working Hours", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Restrict Working Hours"], "Restricción de acceso por horario", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Secure Sessions", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Secure Sessions"], "Restricciones de entorno y sesión segura", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Trusted Devices", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Trusted Devices"], "Control de dispositivos autorizados", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Permissions", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Permissions"], "Restricciones de permisos y recursos", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Ransomware Protection", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Ransomware Protection"], "Protección y respuesta frente a ransomware", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Alerts", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Alerts"], "Notificación de eventos de seguridad", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Reports", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Reports"], "Informes de actividad y protección", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Events", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Events"], "Registro y consulta de eventos del producto", "TSPLUS_ADVSEC_MODULE_STATE"),
            new ModuleDefinition("Advanced Security / Application", TsplusProduct.AdvancedSecurity, DiagnosticLayer.Seguridad,
                ["Advanced Security / Application", "Advanced Security / Application / interfaz"], "Interfaz administrativa del producto", "TSPLUS_ADVSEC_MODULE_STATE")
        };

        foreach (var module in definitions)
        {
            var productState = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_PRODUCT_STATE" && e.Producto == module.Product);
            var installValue = productState?.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Instalación", StringComparison.OrdinalIgnoreCase))?.Valor;
            var explicitlyNotInstalled = !string.IsNullOrWhiteSpace(installValue)
                && (installValue.StartsWith("No ", StringComparison.OrdinalIgnoreCase) || installValue.Contains("no instalado", StringComparison.OrdinalIgnoreCase));
            if (explicitlyNotInstalled && module.Product is (TsplusProduct.AdvancedSecurity or TsplusProduct.TwoFactorAuthentication))
            {
                output.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", module.Name, module.Layer, DiagnosticSeverity.Informativo,
                    "TSPLUS_MODULE_HEALTH_STATE", $"{module.Name}: NO APLICA porque el producto no está instalado/detectado.",
                    Evidencia: [new("Módulo", module.Name), new("Estado funcional", "NO APLICA / PRODUCTO NO INSTALADO"), new("Cobertura", "No aplica"), new("Impacto funcional", module.Impact), new("Problemas principales", "Ninguno; producto no instalado")],
                    Producto: module.Product));
                continue;
            }

            var relatedFindings = findings
                .Where(f => FindingProductMatches(module, f))
                .Where(f => Matches(module, f.Componente, f.Id, f.Resumen))
                .ToList();
            if (module.Name is "Universal Printer" or "Virtual Printer")
                relatedFindings.AddRange(findings.Where(f => f.Id == "PRINT-SPOOLER-DOWN" && !relatedFindings.Contains(f)));
            if (module.Name.StartsWith("Sesiones", StringComparison.OrdinalIgnoreCase))
                relatedFindings.AddRange(findings.Where(f => f.Id == "RDP-TERMSERVICE-NOT-RUNNING" && !relatedFindings.Contains(f)));
            var relatedEvents = report.Eventos
                .Where(e => ProductMatches(module, e))
                .Where(e => Matches(module, e.Componente, e.Fuente, e.Tipo, e.Mensaje))
                .ToList();
            var sourceStates = report.Eventos
                .Where(e => ProductMatches(module, e))
                .Where(e => module.SourceTypes.Contains(e.Tipo, StringComparer.OrdinalIgnoreCase))
                .Where(e => Matches(module, e.Componente, e.Fuente, e.Tipo, e.Mensaje))
                .ToList();

            var worstFinding = relatedFindings.OrderByDescending(f => f.Severidad).FirstOrDefault();
            var worstEventSeverity = relatedEvents.Where(e => e.Tipo != "TSPLUS_MODULE_HEALTH_STATE")
                .Select(e => EffectiveModuleSeverity(module, e))
                .DefaultIfEmpty(DiagnosticSeverity.Informativo)
                .OrderByDescending(x => x)
                .First();
            var worst = MaxSeverity(worstFinding?.Severidad ?? DiagnosticSeverity.Informativo, worstEventSeverity);

            var coverage = Coverage(module, sourceStates, relatedEvents);
            var partialCoverage = IsPartialCoverage(module, sourceStates, coverage);
            var health = worst switch
            {
                DiagnosticSeverity.Critico => "CRÍTICO",
                DiagnosticSeverity.Error => "ERROR",
                DiagnosticSeverity.Advertencia => "ATENCIÓN",
                _ when sourceStates.Count == 0 && relatedEvents.Count == 0 => "NO EVALUADO / NO DETECTADO",
                _ when module.Name.StartsWith("Farm", StringComparison.OrdinalIgnoreCase) => "SIN FALLA OBSERVADA/COBERTURA LOCAL",
                _ when partialCoverage => "SIN FALLA OBSERVADA/COBERTURA PARCIAL",
                _ => "SALUDABLE/SIN FALLA OBSERVADA"
            };
            var severity = health.StartsWith("NO EVALUADO", StringComparison.OrdinalIgnoreCase)
                ? DiagnosticSeverity.Informativo
                : worst;

            var problems = relatedFindings.Where(f => f.Severidad != DiagnosticSeverity.Informativo)
                .OrderByDescending(f => f.Severidad)
                .Select(f => $"[{f.Severidad}] {f.Resumen}")
                .Concat(relatedEvents
                    .Where(e => e.Tipo != "TSPLUS_MODULE_HEALTH_STATE" && EffectiveModuleSeverity(module, e) != DiagnosticSeverity.Informativo)
                    .OrderByDescending(e => EffectiveModuleSeverity(module, e))
                    .Select(e => $"[{EffectiveModuleSeverity(module, e)}] {e.Tipo}: {e.Mensaje}"))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(5)
                .ToList();
            var loops = relatedEvents.Where(e => e.Tipo == "TSPLUS_CRASH_LOOP_PATTERN").ToList();

            output.Add(new DiagnosticEvent(
                DateTimeOffset.Now,
                "TDM",
                module.Name,
                module.Layer,
                severity,
                "TSPLUS_MODULE_HEALTH_STATE",
                health.StartsWith("SALUDABLE", StringComparison.OrdinalIgnoreCase) || health.StartsWith("SIN FALLA", StringComparison.OrdinalIgnoreCase)
                    ? $"No se observó una falla funcional sustentada en {module.Name}; revise el alcance de cobertura indicado."
                    : health.StartsWith("NO EVALUADO", StringComparison.OrdinalIgnoreCase)
                        ? $"TDM no obtuvo evidencia suficiente para evaluar completamente {module.Name}."
                        : $"El módulo {module.Name} presenta estado {health} según la evidencia disponible.",
                Evidencia:
                [
                    new("Módulo", module.Name),
                    new("Estado funcional", health),
                    new("Cobertura", coverage),
                    new("Impacto funcional", module.Impact),
                    new("Hallazgos relacionados", relatedFindings.Count.ToString()),
                    new("Eventos/señales relacionados", relatedEvents.Count.ToString()),
                    new("Patrones recurrentes", loops.Count.ToString()),
                    new("Problemas principales", problems.Count == 0 ? "Ninguno sustentado" : string.Join(" | ", problems)),
                    new("Regla", "Configuración + runtime/dependencia + evidencia temporal + impacto; un cambio aislado no equivale a causa raíz")
                ],
                Producto: module.Product));
        }
    }

    private static bool IsPartialCoverage(ModuleDefinition module, IReadOnlyList<DiagnosticEvent> sourceStates, string coverage)
    {
        var values = sourceStates.SelectMany(e => e.Evidencia ?? []).Select(x => x.Valor).ToList();
        if (module.Product == TsplusProduct.AdvancedSecurity && module.Name != "Advanced Security")
        {
            return values.Any(v => v.Contains("parcial", StringComparison.OrdinalIgnoreCase)
                || v.Contains("no observado", StringComparison.OrdinalIgnoreCase)
                || v.Contains("puede estar deshabilitado", StringComparison.OrdinalIgnoreCase));
        }
        return coverage.Contains("Parcial", StringComparison.OrdinalIgnoreCase)
            || values.Any(v => v.Contains("parcial", StringComparison.OrdinalIgnoreCase));
    }

    private static string Coverage(ModuleDefinition module, IReadOnlyList<DiagnosticEvent> sourceStates, IReadOnlyList<DiagnosticEvent> related)
    {
        if (module.Product == TsplusProduct.AdvancedSecurity)
        {
            if (module.Name == "Advanced Security")
                return sourceStates.Count > 0
                    ? "Servicio principal + logs oficiales disponibles + eventos Windows/TSplus"
                    : related.Count > 0 ? "Parcial por evidencia indirecta" : "No detectado / no evaluado";

            if (sourceStates.Count == 0) return related.Count > 0 ? "Parcial por evidencia indirecta" : "No evaluado";
            var declared = sourceStates.SelectMany(e => e.Evidencia ?? [])
                .FirstOrDefault(x => x.Clave.Equals("Cobertura TDM", StringComparison.OrdinalIgnoreCase))?.Valor;
            return string.IsNullOrWhiteSpace(declared)
                ? "Estado de función parcial; servicio/log/eventos según disponibilidad"
                : declared;
        }
        if (module.Name.StartsWith("Farm", StringComparison.OrdinalIgnoreCase))
            return sourceStates.Count > 0 ? "Configuración y logs locales; nodos remotos no sondeados" : "Sin evidencia local suficiente";
        var declaredCoverage = sourceStates.SelectMany(e => e.Evidencia ?? [])
            .FirstOrDefault(x => x.Clave.Equals("Cobertura TDM", StringComparison.OrdinalIgnoreCase))?.Valor;
        if (!string.IsNullOrWhiteSpace(declaredCoverage))
            return $"{declaredCoverage}; runtime/eventos según disponibilidad";
        return sourceStates.Count > 0 ? "Diagnóstico normal dirigido por perfil + runtime/eventos" : related.Count > 0 ? "Parcial por evidencia indirecta" : "Sin evidencia suficiente";
    }

    private static bool ProductMatches(ModuleDefinition module, DiagnosticEvent e)
    {
        if (e.Producto is not TsplusProduct.Ninguno and not TsplusProduct.Desconocido)
            return e.Producto == module.Product;

        var text = $"{e.Componente} {e.Fuente} {e.Tipo} {e.Mensaje} {e.Archivo} " +
                   string.Join(" ", (e.Evidencia ?? []).Select(x => $"{x.Clave}={x.Valor}"));
        var inferred = InferProduct(text);
        if (inferred is not TsplusProduct.Ninguno and not TsplusProduct.Desconocido)
            return inferred == module.Product;

        // Los productos complementarios deben tener identidad explícita o inferible.
        // Un evento genérico/Unknown no puede contaminar Advanced Security o 2FA sólo por compartir palabras comunes.
        if (module.Product is TsplusProduct.AdvancedSecurity or TsplusProduct.TwoFactorAuthentication or TsplusProduct.ServerMonitoring or TsplusProduct.RemoteSupport)
            return false;

        return true;
    }

    private static bool FindingProductMatches(ModuleDefinition module, DiagnosticFinding finding)
    {
        var text = $"{finding.Componente} {finding.Id} {finding.Resumen} {finding.Detalle} " +
                   string.Join(" ", finding.Evidencia.Select(x => $"{x.Clave}={x.Valor}"));
        var inferred = InferProduct(text);
        if (inferred is not TsplusProduct.Ninguno and not TsplusProduct.Desconocido)
            return inferred == module.Product;

        if (module.Product is TsplusProduct.AdvancedSecurity or TsplusProduct.TwoFactorAuthentication or TsplusProduct.ServerMonitoring or TsplusProduct.RemoteSupport)
            return false;

        return true;
    }

    private static TsplusProduct InferProduct(string text)
    {
        if (text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase) || text.Contains("Server Monitoring", StringComparison.OrdinalIgnoreCase))
            return TsplusProduct.ServerMonitoring;
        if (text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase) || text.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase))
            return TsplusProduct.AdvancedSecurity;
        if (text.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || text.Contains("Two-Factor", StringComparison.OrdinalIgnoreCase) || text.Contains("2FA", StringComparison.OrdinalIgnoreCase))
            return TsplusProduct.TwoFactorAuthentication;
        if (text.Contains("Remote Support", StringComparison.OrdinalIgnoreCase) || text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase))
            return TsplusProduct.RemoteSupport;
        return TsplusProduct.Desconocido;
    }

    private static bool Matches(ModuleDefinition module, params string?[] values)
    {
        foreach (var value in values.Where(v => !string.IsNullOrWhiteSpace(v)))
            if (module.Tokens.Any(t => value!.Contains(t, StringComparison.OrdinalIgnoreCase))) return true;
        return false;
    }

    private static bool IsTsplusRelated(DiagnosticEvent e, SystemSnapshot snapshot)
    {
        if (e.Producto is not TsplusProduct.Ninguno and not TsplusProduct.Desconocido) return true;
        if (e.Capa == DiagnosticLayer.Tsplus) return true;
        var text = $"{e.Componente} {e.Mensaje} {e.Archivo}";
        if (text.Contains("TSplus", StringComparison.OrdinalIgnoreCase)) return true;
        return !string.IsNullOrWhiteSpace(snapshot.TsplusRuta) && text.Contains(snapshot.TsplusRuta, StringComparison.OrdinalIgnoreCase);
    }

    private static string FailureSignature(DiagnosticEvent e)
        => $"{ResolveProduct(e)}|{NormalizeFailureComponent(e)}|{e.Tipo}";

    private static string NormalizeFailureComponent(DiagnosticEvent e)
    {
        var app = e.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Aplicación", StringComparison.OrdinalIgnoreCase))?.Valor;
        var service = e.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Servicio", StringComparison.OrdinalIgnoreCase))?.Valor;
        if (!string.IsNullOrWhiteSpace(app)) return app;
        if (!string.IsNullOrWhiteSpace(service)) return service;

        if (e.Tipo == "SERVICE_TERMINATION")
        {
            var fromMessage = ExtractTerminatedServiceName(e.Mensaje);
            if (!string.IsNullOrWhiteSpace(fromMessage)) return fromMessage;
        }

        return string.IsNullOrWhiteSpace(e.Componente) ? "TSplus / componente no determinado" : e.Componente;
    }

    private static string? ExtractTerminatedServiceName(string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return null;

        const string esStart = "El servicio ";
        const string esEnd = " terminó inesperadamente";
        var start = message.IndexOf(esStart, StringComparison.OrdinalIgnoreCase);
        if (start >= 0)
        {
            start += esStart.Length;
            var end = message.IndexOf(esEnd, start, StringComparison.OrdinalIgnoreCase);
            if (end > start) return message[start..end].Trim();
        }

        const string enStart = "The ";
        const string enEnd = " service terminated unexpectedly";
        start = message.IndexOf(enStart, StringComparison.OrdinalIgnoreCase);
        if (start >= 0)
        {
            start += enStart.Length;
            var end = message.IndexOf(enEnd, start, StringComparison.OrdinalIgnoreCase);
            if (end > start) return message[start..end].Trim();
        }

        return null;
    }

    private static TsplusProduct ResolveProduct(DiagnosticEvent e)
    {
        if (e.Producto is not TsplusProduct.Ninguno and not TsplusProduct.Desconocido) return e.Producto;
        var text = $"{e.Componente} {e.Mensaje} {e.Archivo}";
        if (text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase) || text.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.AdvancedSecurity;
        if (text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase) || text.Contains("Server Monitoring", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.ServerMonitoring;
        return TsplusProduct.RemoteAccess;
    }

    private static int ParseReportedRecurrence(string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return 0;
        var match = RecurrenceRegex().Match(message);
        if (!match.Success) return 0;
        return int.TryParse(match.Groups["count"].Value, out var value) ? value : 0;
    }

    private static DiagnosticSeverity EffectiveModuleSeverity(ModuleDefinition module, DiagnosticEvent e)
    {
        if (module.Name.StartsWith("RDP / Remote Access Core", StringComparison.OrdinalIgnoreCase))
        {
            var text = $"{e.Tipo} {e.Mensaje} {e.Codigo}";
            var knownDisconnectTransition = text.Contains("0x800708CA", StringComparison.OrdinalIgnoreCase)
                || text.Contains("0x80070040", StringComparison.OrdinalIgnoreCase)
                || text.Contains("0x8007139F", StringComparison.OrdinalIgnoreCase)
                || (text.Contains("Event_Disconnect", StringComparison.OrdinalIgnoreCase) && text.Contains("transition", StringComparison.OrdinalIgnoreCase));
            if (knownDisconnectTransition && e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico)
                return DiagnosticSeverity.Advertencia;
        }
        return e.Severidad;
    }

    private static DiagnosticSeverity MaxSeverity(DiagnosticSeverity a, DiagnosticSeverity b) => (int)a >= (int)b ? a : b;

    private static string FormatInterval(TimeSpan value)
        => value.TotalHours >= 1 ? $"{value.TotalHours:0.#} h" : value.TotalMinutes >= 1 ? $"{value.TotalMinutes:0.#} min" : $"{value.TotalSeconds:0.#} s";

    private static string ProductName(TsplusProduct product) => product switch
    {
        TsplusProduct.RemoteAccess => "TSplus Remote Access",
        TsplusProduct.AdvancedSecurity => "TSplus Advanced Security",
        TsplusProduct.ServerMonitoring => "TSplus Server Monitoring",
        TsplusProduct.TwoFactorAuthentication => "TSplus 2FA",
        _ => "TSplus"
    };

    private static string Sanitize(string value)
        => new(value.Where(char.IsLetterOrDigit).Take(28).ToArray());

    private static uint StableHash(string value)
    {
        const uint offset = 2166136261;
        const uint prime = 16777619;
        var hash = offset;
        foreach (var ch in value) { hash ^= char.ToUpperInvariant(ch); hash *= prime; }
        return hash;
    }

    private sealed class ModuleDefinition
    {
        public ModuleDefinition(string name, TsplusProduct product, DiagnosticLayer layer, string[] tokens, string impact, params string[] sourceTypes)
        {
            Name = name; Product = product; Layer = layer; Tokens = tokens; Impact = impact; SourceTypes = sourceTypes;
        }
        public string Name { get; }
        public TsplusProduct Product { get; }
        public DiagnosticLayer Layer { get; }
        public string[] Tokens { get; }
        public string Impact { get; }
        public string[] SourceTypes { get; }
    }

    [GeneratedRegex(@"(?:repetid[oa]\s+|repeated\s+|has\s+done\s+this\s+)(?<count>\d+)\s*(?:veces|times?|time\(s\))?", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RecurrenceRegex();
}
