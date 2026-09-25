namespace TDM.Models;

/// <summary>
/// Contrato central de tipos de evento persistidos por TDM. Los valores string se conservan
/// para compatibilidad con JSON/JSONL y reportes existentes; el código nuevo debe usar estas
/// constantes o el catálogo en lugar de duplicar listas de literales.
/// </summary>
public static class DiagnosticEventTypes
{
    public const string ServiceState = "SERVICE_STATE";
    public const string RdpState = "RDP_STATE";
    public const string NetworkState = "NETWORK_STATE";
    public const string SystemResourceState = "SYSTEM_RESOURCE_STATE";
    public const string PrintingState = "PRINTING_STATE";
    public const string UserSessionState = "USER_SESSION_STATE";
    public const string UserSessionInventory = "USER_SESSION_INVENTORY";
    public const string TsplusProductState = "TSPLUS_PRODUCT_STATE";
    public const string TsplusDependencyHealth = "TSPLUS_DEPENDENCY_HEALTH";
    public const string TsplusInstallationBaseline = "TSPLUS_INSTALLATION_BASELINE";
    public const string TsplusModuleHealthState = "TSPLUS_MODULE_HEALTH_STATE";
    public const string WindowsRebootPendingState = "WINDOWS_REBOOT_PENDING_STATE";
    public const string WindowsRdpPolicyState = "WINDOWS_RDP_POLICY_STATE";
    public const string WindowsTsplusWinlogonIntegration = "WINDOWS_TSPLUS_WINLOGON_INTEGRATION";
    public const string WindowsRdsRoleCompatibility = "WINDOWS_RDS_ROLE_COMPATIBILITY";
    public const string WindowsForensicCoverage = "WINDOWS_FORENSIC_COVERAGE";
    public const string WindowsChangeCoverage = "WINDOWS_CHANGE_COVERAGE";
}

public static class DiagnosticEventCatalog
{
    private static readonly HashSet<string> MergeCurrentState = new(StringComparer.OrdinalIgnoreCase)
    {
        "SERVICE_STATE", "RDP_STATE", "NETWORK_STATE", "SYSTEM_RESOURCE_STATE", "PRINTING_STATE",
        "TSPLUS_DEPENDENCY_HEALTH", "TSPLUS_PRODUCT_STATE", "TSPLUS_INSTALLATION_BASELINE",
        "TSPLUS_MODULE_CRITICAL_FILE_STATE", "TSPLUS_REMOTEACCESS_MODULE_STATE", "TSPLUS_REMOTEACCESS_MODULE_SUMMARY",
        "TSPLUS_UNIVERSAL_PRINTER_STATE", "TSPLUS_VIRTUAL_PRINTER_STATE", "TSPLUS_2FA_HEALTH_STATE",
        "TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE", "TSPLUS_ADVSEC_MODULE_STATE", "TSPLUS_ADVSEC_MODULE_SUMMARY",
        "TSPLUS_MODULE_HEALTH_STATE", "USER_SESSION_INVENTORY",
        "SERVICE_DEPENDENCY_COVERAGE", "WINDOWS_INCREMENTAL_COVERAGE", "TSPLUS_INCREMENTAL_LOG_COVERAGE"
    };

    private static readonly HashSet<string> Snapshot = new(StringComparer.OrdinalIgnoreCase)
    {
        "SERVICE_STATE", "RDP_STATE", "NETWORK_STATE", "SYSTEM_RESOURCE_STATE", "PRINTING_STATE",
        "TSPLUS_DEPENDENCY_HEALTH", "TSPLUS_PRODUCT_STATE", "TSPLUS_INSTALLATION_BASELINE",
        "WINDOWS_FORENSIC_COVERAGE", "WINDOWS_CHANGE_COVERAGE", "FORENSIC_ARTIFACT_SUMMARY",
        "TSPLUS_INTERNAL_CONFIG_AUDIT", "TSPLUS_INTERNAL_FILE_INVENTORY", "TSPLUS_FILE_INVENTORY_BLOCKED",
        "TSPLUS_APPCONTROL_STATE", "TSPLUS_APPCONTROL_SECURITY_STATE", "TSPLUS_PUBLISHED_APPLICATION",
        "TSPLUS_WEB_JSON_VALID", "TSPLUS_WEB_SETTINGS_JS_STATE", "TSPLUS_WEB_SETTINGS_STATE", "TSPLUS_WEB_BALANCE_STATE",
        "TSPLUS_WEB_RUNTIME_STATE", "TSPLUS_WEB_STACK_STATE", "TSPLUS_SENSITIVE_CONFIG_PRESENT",
        "USER_ACCOUNT_STATE", "USER_PROFILE_STATE", "USER_SESSION_STATE", "USER_SESSION_INVENTORY",
        "USER_AUTH_AUDIT_COVERAGE", "WINDOWS_NLA_PASSWORD_COMPAT_STATE", "RDP_SESSION_PIPELINE_STATE",
        "THIRD_PARTY_RUNTIME_INVENTORY", "REMOTEAPP_NONASCII_IDENTITY_CONTEXT", "REMOTEAPP_NONASCII_LOG_CONTEXT",
        "TSPLUS_REMOTEAPP_NONASCII_CONFIG_CONTEXT", "TSPLUS_REMOTEAPP_ENCODING_COVERAGE", "TSPLUS_STARTUP_CONFIG_ENCODING_STATE",
        "WINDOWS_REBOOT_PENDING_STATE", "WINDOWS_RDP_POLICY_STATE", "WINDOWS_TSPLUS_WINLOGON_INTEGRATION", "WINDOWS_RDS_ROLE_COMPATIBILITY",
        "TSPLUS_VERSION_PROFILE_STATE", "TSPLUS_RELEASE_FAMILY", "TSPLUS_FARM_CONFIGURATION_STATE", "TSPLUS_KNOWN_COMPONENT_STATE",
        "TSPLUS_FULL_TREE_AUDIT", "TSPLUS_TEMP_ARTIFACT_STATE", "TSPLUS_WEB_FILESET_STATE", "TSPLUS_APPLICATION_FILESET_STATE",
        "TSPLUS_SESSION_FILESET_STATE", "TSPLUS_MODULE_CRITICAL_FILE_STATE", "TSPLUS_MODULE_RECURSIVE_COVERAGE",
        "TSPLUS_REMOTEACCESS_MODULE_STATE", "TSPLUS_REMOTEACCESS_MODULE_SUMMARY", "TSPLUS_UNIVERSAL_PRINTER_STATE",
        "TSPLUS_VIRTUAL_PRINTER_STATE", "TSPLUS_2FA_HEALTH_STATE", "TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE",
        "TSPLUS_ADVSEC_MODULE_STATE", "TSPLUS_ADVSEC_MODULE_SUMMARY", "TSPLUS_MODULE_HEALTH_STATE",
        "SERVICE_DEPENDENCY_COVERAGE", "TSPLUS_CONFIG_ARTIFACT_COVERAGE", "TSPLUS_FILE_INTEGRITY_COVERAGE", "WINDOWS_INCREMENTAL_COVERAGE", "TSPLUS_INCREMENTAL_LOG_COVERAGE"
    };

    private static readonly HashSet<string> ReportCurrentState = new(StringComparer.OrdinalIgnoreCase)
    {
        "FORENSIC_ARTIFACT_SUMMARY", "NETWORK_STATE", "PRINTING_STATE", "RDP_SESSION_PIPELINE_STATE", "RDP_STATE",
        "REMOTEAPP_NONASCII_IDENTITY_CONTEXT", "REMOTEAPP_NONASCII_LOG_CONTEXT", "SERVICE_STATE", "SYSTEM_RESOURCE_STATE", "TDM_BASELINE_DIFFERENCE",
        "TDM_LOCAL_HISTORY_STATUS", "TDM_PERSISTENT_BASELINE_STATUS", "TDM_RESOURCE_TREND", "THIRD_PARTY_RUNTIME_INVENTORY", "TSPLUS_APPCONTROL_SECURITY_STATE",
        "TSPLUS_APPCONTROL_STATE", "TSPLUS_APPLICATION_FILESET_STATE", "TSPLUS_BASELINE_UNAVAILABLE", "TSPLUS_DEPENDENCY_HEALTH", "TSPLUS_FARM_CONFIGURATION_STATE",
        "TSPLUS_FILE_INVENTORY_BLOCKED", "TSPLUS_FILE_NOT_PRESENT", "TSPLUS_FILE_PRESENT", "TSPLUS_FULL_TREE_AUDIT", "TSPLUS_CONFIG_ARTIFACT_COVERAGE", "TSPLUS_CONFIG_ARTIFACT_STATE", "TSPLUS_FILE_INTEGRITY_COVERAGE", "TSPLUS_INSTALLATION_BASELINE",
        "TSPLUS_INTERNAL_CONFIG_AUDIT", "TSPLUS_INTERNAL_FILE_INVENTORY", "TSPLUS_KNOWN_COMPONENT_STATE", "TSPLUS_LOG_COVERAGE", "TSPLUS_MODULE_CRITICAL_FILE_STATE",
        "TSPLUS_MODULE_HEALTH_STATE", "TSPLUS_MODULE_RECURSIVE_COVERAGE", "TSPLUS_NOT_DETECTED", "TSPLUS_PRODUCT_STATE", "TSPLUS_PUBLISHED_APPLICATION",
        "TSPLUS_RELEASE_FAMILY", "TSPLUS_REMOTEAPP_ENCODING_COVERAGE", "TSPLUS_REMOTEAPP_NONASCII_CONFIG_CONTEXT", "TSPLUS_SECURITY_LOGS_PRESENT", "TSPLUS_SENSITIVE_CONFIG_PRESENT",
        "TSPLUS_SESSION_FILESET_STATE", "TSPLUS_STARTUP_CONFIG_ENCODING_STATE", "TSPLUS_TEMP_ARTIFACT_STATE", "TSPLUS_VERSION_PROFILE_STATE", "TSPLUS_WEB_BALANCE_STATE",
        "TSPLUS_WEB_FILESET_STATE", "TSPLUS_WEB_JSON_VALID", "TSPLUS_WEB_RUNTIME_STATE", "TSPLUS_WEB_SETTINGS_JS_STATE", "TSPLUS_WEB_SETTINGS_STATE",
        "TSPLUS_WEB_STACK_STATE", "USER_ACCOUNT_STATE", "USER_AUTH_AUDIT_COVERAGE", "USER_PROFILE_STATE", "USER_SESSION_INVENTORY",
        "USER_SESSION_STATE", "WINDOWS_CHANGE_COVERAGE", "WINDOWS_FORENSIC_COVERAGE", "WINDOWS_INCREMENTAL_COVERAGE", "SERVICE_DEPENDENCY_COVERAGE", "WINDOWS_NLA_PASSWORD_COMPAT_STATE", "WINDOWS_RDP_POLICY_STATE",
        "WINDOWS_RDS_ROLE_COMPATIBILITY", "WINDOWS_REBOOT_PENDING_STATE", "WINDOWS_TSPLUS_WINLOGON_INTEGRATION"
    };

    private static readonly HashSet<string> PrecisionCurrentState = new(StringComparer.OrdinalIgnoreCase)
    {
        "SYSTEM_RESOURCE_STATE", "RDP_STATE", "NETWORK_STATE", "PRINTING_STATE", "SERVICE_STATE", "TSPLUS_INVENTORY",
        "TSPLUS_INSTALLATION_BASELINE", "TSPLUS_DEPENDENCY_HEALTH", "TSPLUS_PRODUCT_STATE", "WINDOWS_FORENSIC_COVERAGE",
        "WINDOWS_CHANGE_COVERAGE", "FORENSIC_ARTIFACT_SUMMARY", "TSPLUS_INTERNAL_CONFIG_AUDIT", "TSPLUS_INTERNAL_FILE_INVENTORY",
        "TSPLUS_FILE_INVENTORY_BLOCKED", "TSPLUS_APPCONTROL_STATE", "TSPLUS_APPCONTROL_SECURITY_STATE", "TSPLUS_PUBLISHED_APPLICATION",
        "TSPLUS_WEB_JSON_VALID", "TSPLUS_WEB_SETTINGS_STATE", "TSPLUS_WEB_BALANCE_STATE", "TSPLUS_WEB_RUNTIME_STATE", "TSPLUS_WEB_STACK_STATE",
        "TSPLUS_SENSITIVE_CONFIG_PRESENT", "USER_ACCOUNT_STATE", "USER_PROFILE_STATE", "USER_SESSION_STATE", "USER_SESSION_INVENTORY",
        "USER_AUTH_AUDIT_COVERAGE", "WINDOWS_NLA_PASSWORD_COMPAT_STATE", "RDP_SESSION_PIPELINE_STATE", "THIRD_PARTY_RUNTIME_INVENTORY",
        "REMOTEAPP_NONASCII_IDENTITY_CONTEXT", "REMOTEAPP_NONASCII_LOG_CONTEXT", "TSPLUS_REMOTEAPP_NONASCII_CONFIG_CONTEXT",
        "TSPLUS_REMOTEAPP_ENCODING_COVERAGE", "TSPLUS_STARTUP_CONFIG_ENCODING_STATE", "WINDOWS_REBOOT_PENDING_STATE",
        "WINDOWS_RDP_POLICY_STATE", "WINDOWS_TSPLUS_WINLOGON_INTEGRATION", "WINDOWS_RDS_ROLE_COMPATIBILITY", "TSPLUS_RELEASE_FAMILY",
        "TSPLUS_FARM_CONFIGURATION_STATE", "TSPLUS_KNOWN_COMPONENT_STATE", "TSPLUS_FULL_TREE_AUDIT", "TSPLUS_CONFIG_ARTIFACT_COVERAGE", "TSPLUS_FILE_INTEGRITY_COVERAGE", "TSPLUS_TEMP_ARTIFACT_STATE",
        "TSPLUS_MODULE_HEALTH_STATE", "SERVICE_DEPENDENCY_COVERAGE", "WINDOWS_INCREMENTAL_COVERAGE", "TSPLUS_INCREMENTAL_LOG_COVERAGE"
    };

    private static readonly HashSet<string> IncidentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "SERVICE_TERMINATION", "SERVICE_START_FAILURE", "SERVICE_STATE", "APPLICATION_CRASH", "WER_REPORT", "DOTNET_UNHANDLED_EXCEPTION",
        "USER_LOGON_FAILURE", "USER_NLA_PASSWORD_FAILURE", "WINDOWS_CREDENTIAL_VALIDATION_FAILURE", "ACCOUNT_LOCKOUT", "KERBEROS_PREAUTH_FAILURE", "RDP_EVENT_INCREMENTAL", "WINDOWS_EVENT_INCREMENTAL",
        "TIMEOUT", "CERTIFICATE_OR_TLS", "APPLICATION_PUBLISHING", "WEB", "SESSION", "PORT_BIND", "OPERATION_FAILED", "CONNECTION_CLIENT",
        "CODE_INTEGRITY_EVENT", "APPLOCKER_EVENT", "DEFENDER_EVENT_INCREMENTAL", "FIREWALL_EVENT_INCREMENTAL",
        "PRINT_EVENT_INCREMENTAL", "WMI_EVENT_INCREMENTAL", "NETWORK_EVENT_INCREMENTAL", "CAPI2_EVENT_INCREMENTAL",
        "RESOURCE_EXHAUSTION", "STORAGE_FAILURE", "SIDEBYSIDE_DEPENDENCY_FAILURE", "DEPENDENCY_LOAD_FAILURE", "DEPENDENCY_NOT_FOUND", "DLL_NOT_FOUND", "INVALID_IMAGE_FORMAT",
        "ACCESS_DENIED", "FILE_NOT_FOUND", "LICENSE", "JAVA", "PRINTING", "DATABASE", "EXCEPTION", "LOG_ERROR", "LOG_CRITICAL",
        "PRINT_SPOOLER_STATE"
    };

    private static readonly HashSet<string> IdentityIncidentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "ACCOUNT_LOCKOUT", "USER_LOGON_FAILURE", "USER_NLA_PASSWORD_FAILURE",
        "KERBEROS_PREAUTH_FAILURE", "WINDOWS_CREDENTIAL_VALIDATION_FAILURE"
    };

    private static readonly HashSet<string> NonFunctionalIncidentSignals = new(StringComparer.OrdinalIgnoreCase)
    {
        "TDM_STATE_TRANSITION", "TDM_MONITOR_STATE_TRANSITION",
        "LOG_ACCESS_DENIED", "LOG_READ_ERROR", "TSPLUS_INCREMENTAL_SOURCE_UNAVAILABLE", "WINDOWS_EVENT_SOURCE_UNAVAILABLE",
        "WMI_EVENT_INCREMENTAL", "DCOM_EVENT_INCREMENTAL"
    };

    private static readonly HashSet<string> MissionScopedWindowsIncidents = new(StringComparer.OrdinalIgnoreCase)
    {
        "APPLICATION_CRASH", "WER_REPORT", "DOTNET_UNHANDLED_EXCEPTION",
        "CODE_INTEGRITY_EVENT", "APPLOCKER_EVENT", "DEFENDER_EVENT_INCREMENTAL", "FIREWALL_EVENT_INCREMENTAL",
        "PRINT_EVENT_INCREMENTAL", "WMI_EVENT_INCREMENTAL", "NETWORK_EVENT_INCREMENTAL", "CAPI2_EVENT_INCREMENTAL"
    };

    private static readonly HashSet<string> MissionScopedServiceIncidents = new(StringComparer.OrdinalIgnoreCase)
    {
        "SERVICE_TERMINATION", "SERVICE_START_FAILURE"
    };

    private static readonly string[] MissionServiceMarkers =
    [
        "tsplus", "termservice", "remote desktop services", "remote desktop", "rdp",
        "apsc", "application publishing", "html5", "gateway",
        "rpcss", "remote procedure call", "dcomlaunch",
        "eventlog", "windows event log", "winmgmt", "windows management instrumentation",
        "spooler", "print spooler"
    ];

    private static readonly string[] MissionMarkers =
    [
        "tsplus", "remote access", "remote desktop", "remotedesktop", "termservice", "rdp", "tdm.", "tdm ",
        "apsc", "wsession", "logonsession", "alternateshell", "html5", "webportal", "gateway", "application publishing"
    ];

    /// <summary>
    /// Contrato de severidad para incidentes operativos: únicamente ERROR y CRÍTICO.
    /// Advertencias e informativos pueden conservarse como evidencia diagnóstica, pero nunca
    /// deben incrementar contadores, donuts, barras, timelines o ledger de incidentes.
    /// </summary>
    public static bool IsIncidentSeverity(DiagnosticSeverity severity)
        => severity is DiagnosticSeverity.Error or DiagnosticSeverity.Critico;

    public static bool IsIncidentSeverity(string? severity)
        => !string.IsNullOrWhiteSpace(severity)
           && (severity.Equals(nameof(DiagnosticSeverity.Error), StringComparison.OrdinalIgnoreCase)
               || severity.Equals(nameof(DiagnosticSeverity.Critico), StringComparison.OrdinalIgnoreCase)
               || severity.Equals("Crítico", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Determina si una señal representa una incidencia funcional relevante para la misión de TDM.
    /// Cobertura perdida, cambios del propio monitor, advertencias y eventos Windows ajenos se conservan
    /// como evidencia, pero no se presentan ni contabilizan como incidentes operativos.
    /// </summary>
    public static bool IsFunctionalIncident(DiagnosticEvent e)
    {
        // EventTime real es obligatorio para una incidencia funcional. IngestedAt sólo
        // representa cuándo TDM adquirió la evidencia y nunca sustituye al tiempo causal.
        if (e.Timestamp is null || !IsIncidentSeverity(e.Severidad)) return false;
        if (!IsIncidentType(e.Tipo) || NonFunctionalIncidentSignals.Contains(e.Tipo)) return false;

        // Un SERVICE_STATE crítico/error de un servicio TSplus/RDP requerido es una señal
        // operacional directa. Sigue siendo estado actual, pero debe alimentar el monitor/ledger
        // para que una caída sea detectable sin esperar un Event Log posterior.
        if (e.Tipo.Equals("SERVICE_STATE", StringComparison.OrdinalIgnoreCase))
        {
            var state = EvidenceReader.Value(e, "Estado");
            var required = EvidenceReader.Value(e, "Requerida ahora");
            var provider = EvidenceReader.Value(e, "Proveedor");
            var role = EvidenceReader.Value(e, "Rol");
            var isStopped = state is not null && !state.Equals("Running", StringComparison.OrdinalIgnoreCase);
            var inMission = e.Producto != TsplusProduct.Ninguno
                || provider?.Contains("TSplus", StringComparison.OrdinalIgnoreCase) == true
                || role?.Contains("Remote Access", StringComparison.OrdinalIgnoreCase) == true
                || role?.Contains("núcleo", StringComparison.OrdinalIgnoreCase) == true;
            return isStopped && inMission &&
                   (e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico) &&
                   (!required?.Equals("No", StringComparison.OrdinalIgnoreCase) ?? true);
        }

        // P08: un Spooler detenido solo es incidente funcional cuando el propio collector
        // confirmó impresión TSplus observada (evidencia "Impresión TSplus observada = Sí").
        // Sin ella es Advertencia/contexto; el crash (7031/7034) sigue su propia vía.
        if (e.Tipo.Equals("PRINT_SPOOLER_STATE", StringComparison.OrdinalIgnoreCase))
        {
            var state = EvidenceReader.Value(e, "Estado");
            var printing = EvidenceReader.Value(e, "Impresión TSplus observada");
            return e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico
                && state is not null && !state.Equals("Running", StringComparison.OrdinalIgnoreCase)
                && printing?.Equals("Sí", StringComparison.OrdinalIgnoreCase) == true;
        }

        if (IdentityIncidentTypes.Contains(e.Tipo)
            && !string.Equals(EvidenceReader.Value(e, "Correlación funcional"), "Confirmada", StringComparison.OrdinalIgnoreCase))
            return false;

        if (e.Tipo.Equals("WINDOWS_EVENT_INCREMENTAL", StringComparison.OrdinalIgnoreCase))
        {
            var id = EvidenceReader.Int32(e, "EventId");
            return id is 41 or 51 or 55; // apagado inesperado / E/S / NTFS: impacto sistémico real.
        }

        if (MissionScopedServiceIncidents.Contains(e.Tipo))
        {
            if (e.Producto != TsplusProduct.Ninguno || e.Capa == DiagnosticLayer.Rdp) return true;
            var text = $"{e.Fuente} {e.Componente} {e.Mensaje}";
            return MissionServiceMarkers.Any(marker => text.Contains(marker, StringComparison.OrdinalIgnoreCase));
        }

        if (MissionScopedWindowsIncidents.Contains(e.Tipo))
        {
            if (e.Producto != TsplusProduct.Ninguno || e.Capa == DiagnosticLayer.Rdp) return true;
            var text = $"{e.Fuente} {e.Componente} {e.Mensaje} {e.Archivo}";
            return MissionMarkers.Any(marker => text.Contains(marker, StringComparison.OrdinalIgnoreCase));
        }

        return true;
    }

    public static bool IsMergeCurrentState(string? type) => type is not null && MergeCurrentState.Contains(type);
    public static bool IsSnapshot(string? type) => type is not null && Snapshot.Contains(type);
    public static bool IsReportCurrentState(string? type) => type is not null && ReportCurrentState.Contains(type);
    public static bool IsPrecisionCurrentState(string? type) => type is not null && PrecisionCurrentState.Contains(type);
    public static bool IsIncidentType(string? type) => type is not null && IncidentTypes.Contains(type);
}

public static class EvidenceReader
{
    public static string? Value(DiagnosticEvent e, params string[] keys)
        => e.Evidencia?.FirstOrDefault(item => keys.Any(key => item.Clave.Equals(key, StringComparison.OrdinalIgnoreCase)))?.Valor;

    public static bool Is(DiagnosticEvent e, string key, string expected)
        => string.Equals(Value(e, key), expected, StringComparison.OrdinalIgnoreCase);

    public static int? Int32(DiagnosticEvent e, string key)
        => int.TryParse(Value(e, key), out var value) ? value : null;

    public static double? Double(DiagnosticEvent e, string key)
        => double.TryParse(Value(e, key), System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var value) ? value : null;
}
