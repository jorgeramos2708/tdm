using System.Collections.Generic;
using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// Agrupa señales que pertenecen al mismo incidente funcional sin convertir proximidad temporal
/// en causalidad. Permite que Web/HTML5, AD/NLA, WMI/observabilidad y otros dominios coexistan.
/// </summary>
public static class IncidentClusterAnalyzer
{
    private static readonly TimeSpan ClusterGap = TimeSpan.FromMinutes(5);

    // P1-01: Normalizador de claves de evidencia para que IdentityKey agrupe correctamente
    // aunque distintos collectors usen nombres distintos para el mismo concepto.
    private static readonly IReadOnlyDictionary<string, string> EvidenceKeyNormalizer =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            // Usuario
            ["Usuario"] = "User",
            ["User"] = "User",
            ["TargetUserName"] = "User",
            ["TargetUser"] = "User",
            ["AccountName"] = "User",
            ["LogonAccount"] = "User",
            
            // Equipo/Host
            ["Equipo"] = "Host",
            ["Host"] = "Host",
            ["Estación"] = "Host",
            ["Estacion"] = "Host",
            ["Servidor"] = "Host",
            ["Computer"] = "Host",
            ["Workstation"] = "Host",
            ["SourceWorkstation"] = "Host",
            ["CallerComputerName"] = "Host",
            
            // Dominio
            ["Dominio"] = "Domain",
            ["Domain"] = "Domain",
            ["TargetDomainName"] = "Domain",
            
            // Servicio
            ["Servicio"] = "Service",
            ["Service"] = "Service",
            ["ServiceName"] = "Service",
            
            // Aplicación
            ["Aplicación"] = "Application",
            ["Aplicacion"] = "Application",
            ["Application"] = "Application",
            ["AppName"] = "Application",
            ["FaultingApplicationName"] = "Application",
            
            // Módulo/Excepción
            ["Módulo con error"] = "FaultingModule",
            ["Modulo con error"] = "FaultingModule",
            ["FaultingModuleName"] = "FaultingModule",
            ["ModuleName"] = "FaultingModule",
            ["Tipo de excepción .NET"] = "ExceptionType",
            ["Tipo de excepción"] = "ExceptionType",
            ["ExceptionType"] = "ExceptionType",
            
            // IP/Red
            ["IP origen"] = "SourceIp",
            ["IpAddress"] = "SourceIp",
            ["Ip"] = "SourceIp",
            
            // Logon
            ["LogonType"] = "LogonType",
            ["Status"] = "Status",
            ["SubStatus"] = "SubStatus",
            
            // Código de error
            ["Código de error"] = "ErrorCode",
            ["ErrorCode"] = "ErrorCode",
            ["Status"] = "Status",
            ["FailureCode"] = "FailureCode",
            
            // PreAuth
            ["Tipo preautenticación"] = "PreAuthType",
            ["PreAuthType"] = "PreAuthType",
        };

    public static IReadOnlyList<DiagnosticIncidentCluster> Analyze(DiagnosticReport report)
    {
        var signals = report.Eventos
            .Where(e => e.Timestamp.HasValue)
            .Where(IsIncidentSignal)
            .OrderBy(e => e.Timestamp)
            .ToList();

        var groups = new List<List<DiagnosticEvent>>();
        foreach (var signal in signals)
        {
            // Agrupación por identidad + tiempo: mismo dominio y hueco ≤5 min ya no basta si
            // ambas señales traen identidad conocida y distinta (servicio/usuario/host distintos
            // = incidentes distintos aunque coincidan en ventana). Sin identidad en alguna se
            // conserva la regla temporal para no fragmentar evidencia parcial.
            if (groups.Count == 0 || signal.Timestamp!.Value - groups[^1][^1].Timestamp!.Value > ClusterGap ||
                !SameDomain(groups[^1][^1], signal) || DistinctIdentity(groups[^1][^1], signal))
                groups.Add([signal]);
            else
                groups[^1].Add(signal);
        }

        return groups.Select((g, index) => BuildCluster(g, index + 1)).ToList();
    }

    private static DiagnosticIncidentCluster BuildCluster(IReadOnlyList<DiagnosticEvent> events, int index)
    {
        var domain = Domain(events[0]);
        var severity = events.Max(e => e.Severidad);
        var operational = events.Count(IsOperationalImpact);
        var state = domain == "OBSERVABILIDAD"
            ? "OBSERVABILIDAD"
            : operational > 0 ? "INCIDENTE_OPERATIVO" : "EVIDENCIA_CORRELACIONABLE";
        var componentNames = events.Select(e => e.Componente).Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(8).ToList();
        var evidence = new List<EvidenceItem>
        {
            new("Dominio", domain),
            new("Señales", events.Count.ToString()),
            new("Incidentes operativos", operational.ToString()),
            new("Ventana del incidente", $"{events[0].Timestamp!.Value:dd/MM/yyyy HH:mm:ss} - {events[^1].Timestamp!.Value:dd/MM/yyyy HH:mm:ss}"),
            new("Causa común demostrada", "No"),
            new("Regla de agrupación", $"mismo dominio + hueco <= {ClusterGap.TotalMinutes:0} min + identidad compatible"),
            new("Identidad del grupo", IdentityKey(events[0]) ?? "No determinada (regla temporal)"),
        };
        if (domain == "OBSERVABILIDAD")
            evidence.Add(new EvidenceItem("Rol", "Problema de observabilidad; no se atribuye automáticamente a TSplus"));

        var summary = domain switch
        {
            "WEB_HTML5" => "Incidente funcional del acceso Web/HTML5; la causa del fallo se evalúa por separado.",
            "AD_AUTENTICACION" => "Incidente de identidad/dominio que puede afectar autenticación y establecimiento de sesiones.",
            "RDP_SESIONES" => "Incidente relacionado con RDP, autenticación o continuidad de sesiones.",
            "OBSERVABILIDAD" => "Señales de observabilidad/WMI; afectan la capacidad de diagnóstico y no demuestran por sí solas una falla TSplus.",
            _ => "Grupo de señales relacionadas temporal y funcionalmente; no implica una causa común demostrada."
        };
        var id = $"INC-GRP-{index:000}";
        return new DiagnosticIncidentCluster(id, domain, state, severity,
            events[0].Timestamp!.Value, events[^1].Timestamp!.Value, events.Count, operational,
            summary, componentNames, evidence);
    }

    private static bool IsIncidentSignal(DiagnosticEvent e)
    {
        if (e.Tipo is "TDM_STATE_TRANSITION" or "TDM_MONITOR_STATE_TRANSITION" or "LOG_ACCESS_DENIED" or "LOG_READ_ERROR") return false;
        if (e.Tipo == "WMI_EVENT_INCREMENTAL" || e.Tipo == "DCOM_EVENT_INCREMENTAL") return true;
        if (e.Tipo.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase))
            return e.Severidad >= DiagnosticSeverity.Advertencia;
        return e.Severidad >= DiagnosticSeverity.Error || e.Tipo is
            "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE" or "WINDOWS_AD_TERMSRV_SPN_FAILURE" or "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE" or
            "RDP_AUTHENTICATION_STAGE" or "RDP_SESSION_LOGON_STAGE" or "RDP_SHELL_START_STAGE" or "RDP_SHELL_START_GAP" or "RDP_SHELL_START_DELAY";
    }

    private static bool IsOperationalImpact(DiagnosticEvent e)
        => e.Tipo == "SERVICE_STATE" && e.Producto == TsplusProduct.RemoteAccess &&
           !string.Equals(Value(e, "Estado"), "Running", StringComparison.OrdinalIgnoreCase)
           || e.Tipo is "RDP_AUTHENTICATION_STAGE" or "RDP_SESSION_LOGON_STAGE" or "RDP_SHELL_START_STAGE" or "RDP_SHELL_START_GAP" or "RDP_SHELL_START_DELAY"
           || e.Tipo is "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE" or "WINDOWS_AD_TERMSRV_SPN_FAILURE" or "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE";

    private static string Domain(DiagnosticEvent e)
    {
        if (e.Tipo.StartsWith("WMI_", StringComparison.OrdinalIgnoreCase) || e.Tipo.StartsWith("DCOM_", StringComparison.OrdinalIgnoreCase)) return "OBSERVABILIDAD";
        var text = $"{e.Componente} {e.Mensaje} {e.Tipo}";
        if (text.Contains("Web Portal", StringComparison.OrdinalIgnoreCase) || text.Contains("HTML5", StringComparison.OrdinalIgnoreCase) || text.Contains("WebServer", StringComparison.OrdinalIgnoreCase)) return "WEB_HTML5";
        if (e.Tipo.StartsWith("WINDOWS_AD_", StringComparison.OrdinalIgnoreCase) || text.Contains("Active Directory", StringComparison.OrdinalIgnoreCase) || text.Contains("Netlogon", StringComparison.OrdinalIgnoreCase)) return "AD_AUTENTICACION";
        if (e.Capa == DiagnosticLayer.Rdp || text.Contains("RDP", StringComparison.OrdinalIgnoreCase) || text.Contains("TermService", StringComparison.OrdinalIgnoreCase)) return "RDP_SESIONES";
        if (e.Producto == TsplusProduct.RemoteAccess) return "TSPLUS_REMOTE_ACCESS";
        return e.Capa.ToString().ToUpperInvariant();
    }

    private static bool SameDomain(DiagnosticEvent a, DiagnosticEvent b) => Domain(a).Equals(Domain(b), StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Identidad operativa de una señal: usuario/host/servicio/aplicación/módulo/excepción
    /// conocidos. Null si no hay nada identificable (se conserva la regla temporal).
    /// P1-01: usa EvidenceKeyNormalizer para unificar claves entre collectors.
    /// </summary>
    private static string? IdentityKey(DiagnosticEvent e)
    {
        string? Value(string key)
        {
            var lookup = EvidenceKeyNormalizer.TryGetValue(key, out var nk) ? nk : key;
            return e.Evidencia?.FirstOrDefault(x =>
            {
                var stored = EvidenceKeyNormalizer.TryGetValue(x.Clave, out var sk) ? sk : x.Clave;
                return stored.Equals(lookup, StringComparison.OrdinalIgnoreCase);
            })?.Valor;
        }
        var parts = new[]
        {
            Value("User"),
            Value("Host"),
            Value("Service"),
            Value("Application"),
            Value("FaultingModule"),
            Value("ExceptionType") ?? e.Codigo
        }
        .Where(x => !string.IsNullOrWhiteSpace(x) && !x.Equals("N/D", StringComparison.OrdinalIgnoreCase))
        .Select(x => x!.Trim().ToUpperInvariant())
        .ToList();
        return parts.Count == 0 ? null : string.Join("|", parts);
    }

    /// <summary>
    /// Dos señales tienen identidad distinta y conocida: aunque compartan dominio y ventana,
    /// pertenecen a incidentes distintos. La comparación es por intersección de tokens para no
    /// fragmentar cuando una señal trae evidencia parcial (p. ej. servicio sí, usuario no).
    /// </summary>
    private static bool DistinctIdentity(DiagnosticEvent a, DiagnosticEvent b)
    {
        var ka = IdentityKey(a);
        var kb = IdentityKey(b);
        if (ka is null || kb is null) return false;
        if (ka.Equals(kb, StringComparison.Ordinal)) return false;
        var tokensB = new HashSet<string>(kb.Split('|'), StringComparer.Ordinal);
        return !ka.Split('|').Any(tokensB.Contains);
    }

    private static string? Value(DiagnosticEvent e, string key) => e.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor;
}
