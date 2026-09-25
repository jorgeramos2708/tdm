using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// RC18.8: traduce evidencia causal y salud modular a impacto operativo observable.
/// No afirma indisponibilidad global si TDM sólo observó una falla local o parcial.
/// </summary>
public static class FunctionalImpactAnalyzer
{
    public static FunctionalImpactAssessment Analyze(DiagnosticReport report)
    {
        var items = new List<FunctionalImpactItem>();
        var cause = report.CausaRaizPrincipal;

        // Primero refleja módulos que ya tienen una salud funcional explícita.
        foreach (var state in report.Eventos
            .Where(e => e.Tipo == "TSPLUS_MODULE_HEALTH_STATE")
            .GroupBy(e => e.Componente, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Last()))
        {
            var status = Evidence(state, "Estado funcional") ?? state.Severidad.ToString();
            var impact = ToImpactState(state.Severidad, status);
            if (impact == FunctionalImpactState.SinImpactoObservado) continue;

            items.Add(new FunctionalImpactItem(
                FunctionForModule(state.Componente),
                state.Componente,
                impact,
                SummaryForModule(state.Componente, impact, status),
                state.Severidad is DiagnosticSeverity.Critico or DiagnosticSeverity.Error ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                [
                    new EvidenceItem("Estado funcional", status),
                    new EvidenceItem("Cobertura", Evidence(state, "Cobertura") ?? "N/D"),
                    new EvidenceItem("Problemas principales", Evidence(state, "Problemas principales") ?? "N/D")
                ]));
        }

        AddDirectServiceStateImpact(report, items);

        if (cause is not null)
            AddCauseDrivenImpact(report, cause, items);

        // Evita duplicados por función/módulo, conservando el impacto más fuerte.
        var normalized = items
            .GroupBy(i => $"{i.Funcion}|{i.Modulo}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(i => ImpactRank(i.Estado)).ThenByDescending(i => ConfidenceRank(i.Confianza)).First())
            .OrderByDescending(i => ImpactRank(i.Estado))
            .ThenBy(i => i.Funcion)
            .ToList();

        // Si el incidente está limitado a un producto complementario, deja explícito que Remote Access
        // no aparece afectado por causalidad demostrada.
        if (cause is not null && cause.Producto is TsplusProduct.ServerMonitoring or TsplusProduct.RemoteSupport or TsplusProduct.AdvancedSecurity)
        {
            var remoteAccessFailure = normalized.Any(i =>
                i.Modulo.Contains("Remote Access", StringComparison.OrdinalIgnoreCase) &&
                i.Estado is FunctionalImpactState.Interrumpido or FunctionalImpactState.Degradado);
            if (!remoteAccessFailure)
            {
                normalized.Add(new FunctionalImpactItem(
                    "Acceso remoto de usuarios",
                    "TSplus Remote Access",
                    FunctionalImpactState.SinImpactoObservado,
                    "No se observó propagación causal del incidente hacia Remote Access en la ventana analizada.",
                    ConfidenceLevel.Media,
                    [new EvidenceItem("Origen observado", cause.Producto.ToString())]));
            }
        }

        var overall = normalized.Count == 0
            ? FunctionalImpactState.Indeterminado
            : normalized.MaxBy(i => ImpactRank(i.Estado))!.Estado;

        var summary = overall switch
        {
            FunctionalImpactState.Interrumpido => "Existe al menos una función con indisponibilidad o interrupción sustentada por la evidencia disponible.",
            FunctionalImpactState.Degradado => "Se detectó degradación funcional sin evidencia suficiente de indisponibilidad total.",
            FunctionalImpactState.SinImpactoObservado => "No se observó impacto funcional atribuible al incidente principal en las funciones evaluadas.",
            _ => "El impacto funcional no puede determinarse con la cobertura disponible."
        };

        return new FunctionalImpactAssessment(overall, summary, normalized);
    }

    private static void AddCauseDrivenImpact(DiagnosticReport report, RootCauseCandidate cause, List<FunctionalImpactItem> items)
    {
        var text = $"{cause.Componente} {cause.Resumen} {cause.Explicacion} " +
                   string.Join(" ", cause.Evidencia.Select(e => $"{e.Clave}={e.Valor}"));

        void Add(string function, string module, FunctionalImpactState state, string summary, params EvidenceItem[] evidence)
        {
            items.Add(new FunctionalImpactItem(function, module, state, summary, cause.Confianza, evidence));
        }

        if (cause.Producto == TsplusProduct.ServerMonitoring || text.Contains("Server Monitoring", StringComparison.OrdinalIgnoreCase))
        {
            Add("Monitoreo y reportes TSplus", "TSplus Server Monitoring",
                cause.Confianza is ConfidenceLevel.Confirmada or ConfidenceLevel.Alta or ConfidenceLevel.Media ? FunctionalImpactState.Degradado : FunctionalImpactState.Indeterminado,
                "El incidente afecta Server Monitoring; no implica por sí solo una caída de Remote Access.",
                new EvidenceItem("Candidato", cause.Componente),
                new EvidenceItem("Origen", cause.OrigenClasificado));
            return;
        }

        if (cause.Producto == TsplusProduct.AdvancedSecurity || text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase))
        {
            Add("Protecciones de Advanced Security", "TSplus Advanced Security",
                cause.Confianza is ConfidenceLevel.Confirmada or ConfidenceLevel.Alta ? FunctionalImpactState.Degradado : FunctionalImpactState.Indeterminado,
                "La protección de seguridad puede quedar degradada; TDM no asume pérdida de acceso remoto mientras no exista evidencia de propagación.",
                new EvidenceItem("Candidato", cause.Componente));
            return;
        }

        if (cause.Producto == TsplusProduct.RemoteSupport || text.Contains("Remote Support", StringComparison.OrdinalIgnoreCase))
        {
            Add("Soporte remoto", "TSplus Remote Support", FunctionalImpactState.Degradado,
                "El incidente se limita al componente de Remote Support observado.", new EvidenceItem("Candidato", cause.Componente));
            return;
        }

        if (text.Contains("NLA", StringComparison.OrdinalIgnoreCase) || text.Contains("CredSSP", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("contraseña", StringComparison.OrdinalIgnoreCase) || text.Contains("password", StringComparison.OrdinalIgnoreCase))
        {
            Add("Nuevos inicios de sesión", "Remote Access / autenticación",
                FunctionalImpactState.Interrumpido,
                "Usuarios afectados por el estado de credenciales/NLA pueden no completar el inicio de sesión; las sesiones ya establecidas no se consideran afectadas sin evidencia adicional.",
                new EvidenceItem("Originador", cause.OrigenClasificado));
        }

        if (text.Contains("shell", StringComparison.OrdinalIgnoreCase) || text.Contains("pantalla negra", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("Winlogon", StringComparison.OrdinalIgnoreCase) || text.Contains("User Profile", StringComparison.OrdinalIgnoreCase))
        {
            Add("Inicio de escritorio/shell", "Sesiones / perfiles / logon",
                FunctionalImpactState.Interrumpido,
                "La autenticación puede completarse pero la sesión no llega a presentar correctamente el shell/escritorio.",
                new EvidenceItem("Candidato", cause.Componente));
        }

        if (text.Contains("Web", StringComparison.OrdinalIgnoreCase) || text.Contains("HTML5", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("443", StringComparison.OrdinalIgnoreCase) || text.Contains("80", StringComparison.OrdinalIgnoreCase))
        {
            Add("Acceso Web / HTML5", "Web / HTML5 / Web Portal",
                cause.Confianza is ConfidenceLevel.Confirmada or ConfidenceLevel.Alta ? FunctionalImpactState.Interrumpido : FunctionalImpactState.Degradado,
                "El acceso por Web/HTML5 puede quedar afectado; el acceso RDP nativo se evalúa por separado.",
                new EvidenceItem("Candidato", cause.Componente));
        }

        if (text.Contains("AppControl", StringComparison.OrdinalIgnoreCase) || text.Contains("RemoteApp", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("startup.config", StringComparison.OrdinalIgnoreCase) || text.Contains("aplicación publicada", StringComparison.OrdinalIgnoreCase))
        {
            Add("Aplicaciones publicadas / RemoteApp", "Publicación de aplicaciones",
                cause.Confianza is ConfidenceLevel.Confirmada or ConfidenceLevel.Alta ? FunctionalImpactState.Interrumpido : FunctionalImpactState.Degradado,
                "La apertura de una o más aplicaciones publicadas puede fallar; no se asume caída completa de las sesiones.",
                new EvidenceItem("Candidato", cause.Componente));
        }

        if (text.Contains("TermService", StringComparison.OrdinalIgnoreCase) || text.Contains("RDP", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("listener", StringComparison.OrdinalIgnoreCase))
        {
            // R8: preferir el RDP_STATE dentro de la ventana analizada; un snapshot viejo
            // (p. ej. arrastrado por fusión continua) no debe describir el impacto actual.
            // Sin ventana o sin muestra reciente se conserva el último (comportamiento anterior).
            var rdpStates = report.Eventos.Where(e => e.Tipo == "RDP_STATE").ToList();
            var rdpState = (report.PeriodoAnalizadoInicio != default
                    ? rdpStates.Where(e => e.Timestamp >= report.PeriodoAnalizadoInicio).ToList()
                    : rdpStates) is { Count: > 0 } recent
                ? recent.LastOrDefault()
                : rdpStates.LastOrDefault();
            var listener = rdpState is null ? "N/D" : Evidence(rdpState, "Listener") ?? Evidence(rdpState, "RDP Listener") ?? "N/D";
            // Sonda funcional: si el puerto RDP acepta TCP local, la pila de red entrega;
            // la indisponibilidad queda acotada al servicio/sesión, no a la red.
            var tcpRdp = NetworkPortTcp(report, "RDP configurado");
            Add("Nuevas conexiones remotas", "RDP / Remote Access Core",
                cause.Confianza is ConfidenceLevel.Confirmada or ConfidenceLevel.Alta ? FunctionalImpactState.Interrumpido : FunctionalImpactState.Degradado,
                "La capacidad de aceptar nuevas conexiones RDP/Remote Access puede estar afectada.",
                new EvidenceItem("Listener observado", listener),
                new EvidenceItem("Sonda TCP local (RDP)", tcpRdp ?? "N/D"));
        }

        if (text.Contains("Spooler", StringComparison.OrdinalIgnoreCase) || text.Contains("Printer", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("novaPDF", StringComparison.OrdinalIgnoreCase))
        {
            Add("Impresión remota", "Universal / Virtual Printer",
                FunctionalImpactState.Degradado,
                "Las sesiones pueden continuar operativas mientras la impresión Universal/Virtual permanece degradada.",
                new EvidenceItem("Candidato", cause.Componente));
        }

        if (text.Contains("Farm", StringComparison.OrdinalIgnoreCase) || text.Contains("Gateway", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("Load Balancing", StringComparison.OrdinalIgnoreCase) || text.Contains("Reverse Proxy", StringComparison.OrdinalIgnoreCase))
        {
            Add("Distribución de conexiones en granja", "Farm / Gateway / Load Balancing / Reverse Proxy",
                FunctionalImpactState.Degradado,
                "La distribución de conexiones o el acceso a uno o más nodos puede degradarse; TDM no declara toda la granja caída sin sondeo remoto.",
                new EvidenceItem("Cobertura", "Local; nodos remotos no sondeados en diagnóstico normal"));
        }
    }

    private static FunctionalImpactState ToImpactState(DiagnosticSeverity severity, string status)
    {
        // El estado funcional explícito manda sobre la severidad del evento contenedor.
        // Cobertura parcial/local/no evaluada describe incertidumbre, no degradación.
        if (status.Contains("NO APLICA", StringComparison.OrdinalIgnoreCase)) return FunctionalImpactState.SinImpactoObservado;
        if (status.Contains("NO EVALUADO", StringComparison.OrdinalIgnoreCase)
            || status.Contains("NO DETECTADO", StringComparison.OrdinalIgnoreCase)
            || status.Contains("COBERTURA PARCIAL", StringComparison.OrdinalIgnoreCase)
            || status.Contains("COBERTURA LOCAL", StringComparison.OrdinalIgnoreCase)
            || status.Equals("N/D", StringComparison.OrdinalIgnoreCase))
            return FunctionalImpactState.Indeterminado;

        if ((status.Contains("SALUDABLE", StringComparison.OrdinalIgnoreCase) || status.Contains("SIN FALLA OBSERVADA", StringComparison.OrdinalIgnoreCase))
            && !status.Contains("ERROR", StringComparison.OrdinalIgnoreCase) && !status.Contains("CRÍT", StringComparison.OrdinalIgnoreCase))
            return FunctionalImpactState.SinImpactoObservado;

        if (status.Contains("CRÍT", StringComparison.OrdinalIgnoreCase) || severity == DiagnosticSeverity.Critico) return FunctionalImpactState.Interrumpido;
        if (status.Contains("ERROR", StringComparison.OrdinalIgnoreCase) || status.Contains("FALLA", StringComparison.OrdinalIgnoreCase) || severity == DiagnosticSeverity.Error) return FunctionalImpactState.Degradado;
        if (status.Contains("ATEN", StringComparison.OrdinalIgnoreCase) || severity == DiagnosticSeverity.Advertencia) return FunctionalImpactState.Degradado;
        return FunctionalImpactState.SinImpactoObservado;
    }

    private static string FunctionForModule(string module)
    {
        if (module.Contains("Web", StringComparison.OrdinalIgnoreCase)) return "Acceso Web / HTML5";
        if (module.Contains("Sesiones", StringComparison.OrdinalIgnoreCase) || module.Contains("logon", StringComparison.OrdinalIgnoreCase)) return "Inicio y continuidad de sesiones";
        if (module.Contains("Printer", StringComparison.OrdinalIgnoreCase) || module.Contains("Impres", StringComparison.OrdinalIgnoreCase)) return "Impresión remota";
        if (module.Contains("Farm", StringComparison.OrdinalIgnoreCase) || module.Contains("Gateway", StringComparison.OrdinalIgnoreCase)) return "Acceso/distribución de granja";
        if (module.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase)) return "Protecciones de seguridad";
        if (module.Contains("RDP", StringComparison.OrdinalIgnoreCase)) return "Conectividad remota";
        return module;
    }

    private static string SummaryForModule(string module, FunctionalImpactState state, string status) =>
        state switch
        {
            FunctionalImpactState.Interrumpido => $"{module}: existe evidencia de interrupción funcional ({status}).",
            FunctionalImpactState.Degradado => $"{module}: existe evidencia de degradación ({status}).",
            FunctionalImpactState.Indeterminado => $"{module}: impacto no determinado por cobertura limitada/local ({status}).",
            _ => $"{module}: sin impacto funcional observado."
        };

    private static string? Evidence(DiagnosticEvent e, string key) =>
        e.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor;

    /// <summary>
    /// Lee el resultado de la sonda TCP funcional ("tcp=...") del evento NETWORK_STATE para
    /// el puerto indicado por etiqueta (p. ej. "RDP configurado", "Web "). Devuelve null si no
    /// hay sonda (puerto sin listener, sin cobertura o collector antiguo).
    /// </summary>
    private static string? NetworkPortTcp(DiagnosticReport report, string labelPrefix)
    {
        var net = report.Eventos.LastOrDefault(e => e.Tipo == "NETWORK_STATE");
        if (net?.Evidencia is null) return null;
        foreach (var item in net.Evidencia.Where(x => (x.Clave ?? string.Empty).StartsWith(labelPrefix, StringComparison.OrdinalIgnoreCase)))
        {
            var value = item.Valor ?? string.Empty;
            var marker = value.IndexOf("tcp=", StringComparison.OrdinalIgnoreCase);
            if (marker >= 0) return value[(marker + 4)..].Trim();
        }
        return null;
    }

    /// <summary>
    /// Sonda TCP de cualquier puerto web sondeado (HTTP/HTTPS configurado o predeterminado).
    /// Devuelve el primer resultado disponible; null si no hay sonda.
    /// </summary>
    private static string? NetworkWebTcp(DiagnosticReport report)
        => NetworkPortTcp(report, "Web ");

    /// <summary>
    /// Alcance potencial (blast radius básico): sesiones observadas en el inventario más
    /// reciente ("N activas / M desconectadas") o null sin inventario. Solo lectura de
    /// evidencia ya capturada; no distingue qué sesiones usan el servicio afectado.
    /// </summary>
    private static string? SessionBlastRadius(DiagnosticReport report)
    {
        var inventory = report.Eventos.LastOrDefault(e => e.Tipo == "USER_SESSION_INVENTORY");
        if (inventory?.Evidencia is null) return null;
        string? Get(string key) => inventory.Evidencia
            .FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor;
        var active = Get("Sesiones activas");
        var disconnected = Get("Sesiones desconectadas");
        if (string.IsNullOrWhiteSpace(active) && string.IsNullOrWhiteSpace(disconnected)) return null;
        return $"{active ?? "?"} activas / {disconnected ?? "?"} desconectadas";
    }

    private static readonly string[] TransientServiceStates =
        ["StartPending", "StopPending", "PausePending", "ContinuePending"];

    private static void AddDirectServiceStateImpact(DiagnosticReport report, List<FunctionalImpactItem> items)
    {
        foreach (var state in report.Eventos
            .Where(e => e.Tipo.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase))
            .Where(e => e.Producto == TsplusProduct.RemoteAccess)
            .Where(e => e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico)
            // P16: los estados *Pending son transitorios del SCM, no interrupciones demostradas.
            .Where(e => !TransientServiceStates.Contains(Evidence(e, "Estado") ?? string.Empty, StringComparer.OrdinalIgnoreCase))
            .Where(e => !string.Equals(Evidence(e, "Estado"), "Running", StringComparison.OrdinalIgnoreCase))
            // P1-03: Filtrar servicios Manual/Trigger detenidos que no son fallas operativas.
            // Usamos "Estado presentación" (si disponible) o "Inicio" para determinar si el servicio
            // debería estar corriendo. Un servicio Manual/Trigger detenido no es una falla operativa.
            .Where(e =>
            {
                var presentation = Evidence(e, "Estado presentación") ?? string.Empty;
                var startMode = Evidence(e, "Inicio") ?? string.Empty;
                var isManualOrTrigger = startMode.Equals("Manual", StringComparison.OrdinalIgnoreCase)
                                     || startMode.Equals("Trigger", StringComparison.OrdinalIgnoreCase);
                var isNotRequired = presentation.Contains("No requerido", StringComparison.OrdinalIgnoreCase)
                                 || presentation.Contains("No required", StringComparison.OrdinalIgnoreCase);
                return !(isManualOrTrigger && isNotRequired);
            })
            .GroupBy(e => Evidence(e, "Servicio") ?? e.Componente, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(e => e.Severidad).ThenByDescending(e => e.Timestamp).First()))
        {
            var service = Evidence(state, "Servicio") ?? state.Componente;
            var display = Evidence(state, "Nombre visible") ?? service;
            var isWeb = display.Contains("Web Portal", StringComparison.OrdinalIgnoreCase)
                        || service.Contains("WebPortal", StringComparison.OrdinalIgnoreCase)
                        || display.Contains("HTML5", StringComparison.OrdinalIgnoreCase)
                        || service.Contains("HTML5", StringComparison.OrdinalIgnoreCase);
            var function = isWeb ? "Acceso Web / HTML5" : $"Servicio TSplus: {display}";
            var module = isWeb ? "Web / HTML5 / Web Portal" : display;
            // Sonda funcional: si el servicio web está detenido pero su puerto sigue aceptando
            // TCP local, algo lo sigue sirviendo (proxy, puerta, instancia residual): el impacto
            // directo NO está demostrado y se degrada en vez de interrumpir.
            var webTcp = isWeb ? NetworkWebTcp(report) : null;
            var webTcpOk = webTcp is not null && webTcp.StartsWith("OK", StringComparison.OrdinalIgnoreCase);
            // Blast radius: sesiones observadas que potencialmente usan el servicio afectado.
            var blastRadius = SessionBlastRadius(report);
            items.Add(new FunctionalImpactItem(
                function, module, webTcpOk ? FunctionalImpactState.Degradado : FunctionalImpactState.Interrumpido,
                isWeb
                    ? webTcpOk
                        ? "El servicio Web Portal de TSplus está detenido, pero su puerto sigue aceptando conexiones TCP locales (posible proxy o puerta frontal): impacto directo no demostrado. Esto no demuestra por sí solo la causa del paro."
                        : "El servicio Web Portal de TSplus está detenido; el impacto Web/HTML5 está demostrado. Esto no demuestra por sí solo la causa del paro."
                    : $"El servicio TSplus {display} no está operativo; su impacto funcional directo queda demostrado por el estado del servicio.",
                ConfidenceLevel.Alta,
                [
                    new EvidenceItem("Estado operativo", Evidence(state, "Estado") ?? "N/D"),
                    new EvidenceItem("Servicio", service),
                    new EvidenceItem("Sonda TCP local (Web)", webTcp ?? "N/D"),
                    new EvidenceItem("Alcance potencial (sesiones observadas)", blastRadius ?? "N/D (sin inventario en ventana)"),
                    new EvidenceItem("Causa del paro demostrada", "No")
                ]));
        }
    }

    private static int ImpactRank(FunctionalImpactState state) => state switch
    {
        FunctionalImpactState.Interrumpido => 4,
        FunctionalImpactState.Degradado => 3,
        FunctionalImpactState.Indeterminado => 2,
        _ => 1
    };

    private static int ConfidenceRank(ConfidenceLevel level) => level switch
    {
        ConfidenceLevel.Confirmada => 5,
        ConfidenceLevel.Alta => 4,
        ConfidenceLevel.Media => 3,
        ConfidenceLevel.Baja => 2,
        _ => 1
    };
}
