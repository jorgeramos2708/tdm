using TDM.Models;

namespace TDM.Persistence;

/// <summary>
/// Autoridad única para decidir qué registros persistidos pueden tratarse como incidentes operativos.
/// Protege la UI, federación y ledger incluso al leer historial creado por versiones anteriores.
/// </summary>
public static class ObservabilityIncidentPolicy
{
    private static readonly HashSet<string> NonFunctionalKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        // Q9: todos los tipos de transición del journal (incluidos forensic/integrity) son
        // explícitamente no-incidentes, aunque alguna vez cambien de severidad.
        "TDM_STATE_TRANSITION", "TDM_MONITOR_STATE_TRANSITION",
        "TDM_FORENSIC_STATE_TRANSITION", "TDM_INTEGRITY_STATE_TRANSITION",
        "LOG_ACCESS_DENIED", "LOG_READ_ERROR", "TSPLUS_INCREMENTAL_SOURCE_UNAVAILABLE", "WINDOWS_EVENT_SOURCE_UNAVAILABLE",
        "WMI_EVENT_INCREMENTAL", "DCOM_EVENT_INCREMENTAL"
    };

    private static readonly HashSet<string> MissionScopedServiceKinds = new(StringComparer.OrdinalIgnoreCase)
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

    private static readonly HashSet<string> MissionScopedKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        "APPLICATION_CRASH", "WER_REPORT", "DOTNET_UNHANDLED_EXCEPTION",
        "CODE_INTEGRITY_EVENT", "APPLOCKER_EVENT", "DEFENDER_EVENT_INCREMENTAL", "FIREWALL_EVENT_INCREMENTAL",
        "PRINT_EVENT_INCREMENTAL", "WMI_EVENT_INCREMENTAL", "NETWORK_EVENT_INCREMENTAL", "CAPI2_EVENT_INCREMENTAL"
    };

    private static readonly HashSet<string> IdentityKinds = new(StringComparer.OrdinalIgnoreCase)
    {
        "ACCOUNT_LOCKOUT", "USER_LOGON_FAILURE", "USER_NLA_PASSWORD_FAILURE",
        "KERBEROS_PREAUTH_FAILURE", "WINDOWS_CREDENTIAL_VALIDATION_FAILURE"
    };

    private static readonly string[] MissionMarkers =
    [
        "tsplus", "remote access", "remote desktop", "remotedesktop", "termservice", "rdp", "tdm.", "tdm ",
        "apsc", "wsession", "logonsession", "alternateshell", "html5", "webportal", "gateway", "application publishing"
    ];

    public static bool IsSevere(ObservabilityIncident incident)
        => DiagnosticEventCatalog.IsIncidentSeverity(incident.Severity);

    public static bool IsOperationalIncident(ObservabilityIncident incident)
        => IsOperationalIncident(incident.Kind, incident.Component, incident.Severity, incident.Summary,
            incident.EvidenceSource, incident.EvidenceFile, incident.Product, incident.Classification);

    public static bool IsOperationalIncident(
        string? kind,
        string? component,
        string? severity,
        string? summary,
        string? evidenceSource = null,
        string? evidenceFile = null,
        string? product = null,
        string? classification = null)
    {
        if (!DiagnosticEventCatalog.IsIncidentSeverity(severity)) return false;

        var normalizedKind = kind?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedKind) || !DiagnosticEventCatalog.IsIncidentType(normalizedKind) || NonFunctionalKinds.Contains(normalizedKind)) return false;

        // Eventos de identidad son extremadamente ruidosos en servidores multiuso. Sólo se aceptan
        // desde snapshots RC18.20.12+ que preserven la marca explícita de correlación funcional.
        if (IdentityKinds.Contains(normalizedKind)
            && !string.Equals(classification, "IdentityCorrelated", StringComparison.OrdinalIgnoreCase))
            return false;

        // Versiones anteriores podían marcar como funcional cualquier 7031/7034. Revalidamos
        // el servicio antes de confiar en la clasificación persistida para evitar contaminar historial.
        if (MissionScopedServiceKinds.Contains(normalizedKind))
        {
            if (!string.IsNullOrWhiteSpace(product)
                && !product.Equals(nameof(TsplusProduct.Ninguno), StringComparison.OrdinalIgnoreCase))
                return true;
            var serviceText = $"{component} {summary} {evidenceSource}";
            return MissionServiceMarkers.Any(marker => serviceText.Contains(marker, StringComparison.OrdinalIgnoreCase));
        }

        // En agregados históricos no existe EventId confiable (EvidenceId puede ser RecordId), por lo que
        // un WINDOWS_EVENT_INCREMENTAL genérico no puede elevarse de forma segura a incidente aunque una
        // versión anterior lo haya persistido con Classification=Funcional.
        if (normalizedKind.Equals("WINDOWS_EVENT_INCREMENTAL", StringComparison.OrdinalIgnoreCase)) return false;

        // Igual que con servicios, la clasificación persistida no es autoridad suficiente para señales
        // Windows muy ruidosas. Revalidamos el alcance de misión antes de aceptar un incidente legado.
        if (MissionScopedKinds.Contains(normalizedKind))
        {
            if (!string.IsNullOrWhiteSpace(product)
                && !product.Equals(nameof(TsplusProduct.Ninguno), StringComparison.OrdinalIgnoreCase))
                return true;

            var text = $"{component} {summary} {evidenceSource} {evidenceFile}";
            return MissionMarkers.Any(marker => text.Contains(marker, StringComparison.OrdinalIgnoreCase));
        }

        // Para el resto de tipos del catálogo, ERROR/CRÍTICO + tipo incidental conocido es suficiente.
        // Classification se conserva como metadata, pero nunca puede saltarse las reglas anteriores.
        return true;
    }

    public static string IdentityKey(ObservabilityIncident incident)
    {
        var timestamp = incident.Timestamp.ToUniversalTime().Ticks;
        var evidenceId = incident.EvidenceId?.Trim();
        if (!string.IsNullOrWhiteSpace(evidenceId) && !evidenceId.Equals("N/D", StringComparison.OrdinalIgnoreCase))
            return $"native|{incident.Kind}|{incident.EvidenceSource}|{evidenceId}";
        return $"event|{timestamp}|{incident.Kind}|{incident.Component}|{incident.Summary}";
    }

    public static IReadOnlyList<ObservabilityIncident> Normalize(IEnumerable<ObservabilityIncident>? incidents)
        => (incidents ?? [])
            .Where(IsOperationalIncident)
            .GroupBy(IdentityKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => Sanitize(g.Last()))
            .OrderBy(x => x.Timestamp)
            .ToList();

    private static ObservabilityIncident Sanitize(ObservabilityIncident incident)
        => incident with
        {
            Component = TdmVisibleText.Sanitize(incident.Component),
            Summary = TdmVisibleText.Sanitize(incident.Summary),
            EvidenceSource = string.IsNullOrWhiteSpace(incident.EvidenceSource) ? incident.EvidenceSource : TdmVisibleText.Sanitize(incident.EvidenceSource),
            EvidenceId = string.IsNullOrWhiteSpace(incident.EvidenceId) ? incident.EvidenceId : TdmVisibleText.Sanitize(incident.EvidenceId),
            EvidenceFile = string.IsNullOrWhiteSpace(incident.EvidenceFile) ? incident.EvidenceFile : TdmVisibleText.Sanitize(incident.EvidenceFile)
        };
}
