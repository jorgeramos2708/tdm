using System.Security.Cryptography;
using System.Text;
using TDM.Models;

namespace TDM.Persistence;

public static class StateSnapshotBuilder
{
    // Sólo se persisten estados actuales útiles para diagnóstico longitudinal.
    // Se excluyen mensajes históricos/eventos crudos para no duplicar EventLog ni logs TSplus.
    private static readonly HashSet<string> PersistentTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "SERVICE_STATE", "RDP_STATE", "NETWORK_STATE", "SYSTEM_RESOURCE_STATE", "PRINTING_STATE",
        "TSPLUS_DEPENDENCY_HEALTH", "TSPLUS_PRODUCT_STATE", "TSPLUS_INSTALLATION_BASELINE",
        "TSPLUS_APPCONTROL_STATE", "TSPLUS_APPCONTROL_SECURITY_STATE", "TSPLUS_WEB_SETTINGS_JS_STATE", "TSPLUS_WEB_SETTINGS_STATE",
        "TSPLUS_WEB_BALANCE_STATE", "TSPLUS_WEB_RUNTIME_STATE", "TSPLUS_WEB_STACK_STATE",
        "TSPLUS_FARM_CONFIGURATION_STATE", "TSPLUS_KNOWN_COMPONENT_STATE", "TSPLUS_VERSION_PROFILE_STATE", "TSPLUS_RELEASE_FAMILY",
        "TSPLUS_WEB_FILESET_STATE", "TSPLUS_APPLICATION_FILESET_STATE", "TSPLUS_SESSION_FILESET_STATE", "TSPLUS_MODULE_CRITICAL_FILE_STATE",
        "WINDOWS_REBOOT_PENDING_STATE", "WINDOWS_RDP_POLICY_STATE", "WINDOWS_TSPLUS_WINLOGON_INTEGRATION",
        "WINDOWS_RDS_ROLE_COMPATIBILITY", "USER_SESSION_INVENTORY",
        "TSPLUS_REMOTEACCESS_MODULE_STATE", "TSPLUS_REMOTEACCESS_MODULE_SUMMARY",
        "TSPLUS_UNIVERSAL_PRINTER_STATE", "TSPLUS_VIRTUAL_PRINTER_STATE",
        "TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE", "TSPLUS_ADVSEC_MODULE_STATE", "TSPLUS_ADVSEC_MODULE_SUMMARY",
        "TSPLUS_MODULE_HEALTH_STATE",
        "TSPLUS_CONFIG_ARTIFACT_STATE", "SERVICE_DEPENDENCY_STATE", "SERVICE_DEPENDENT_STATE",
        "WINDOWS_LONGITUDINAL_CONFIG_STATE", "WINDOWS_LONGITUDINAL_LIBRARY_STATE",
        "TSPLUS_LONGITUDINAL_CONFIG_STATE", "TSPLUS_LONGITUDINAL_LIBRARY_STATE"
    };

    // Métricas y conteos fluctúan de forma natural; se guardan, pero no producen transiciones.
    private static readonly HashSet<string> NoTransitionTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "SYSTEM_RESOURCE_STATE", "USER_SESSION_INVENTORY",
        // Estados de cobertura/inventario: se conservan en historial, pero no representan una transición operativa.
        // Las transiciones operativas se siguen mediante estados directos de servicio/runtime/configuración; la salud derivada se recalcula.
        "TSPLUS_ADVSEC_MODULE_STATE", "TSPLUS_ADVSEC_MODULE_SUMMARY",
        "TSPLUS_REMOTEACCESS_MODULE_STATE", "TSPLUS_REMOTEACCESS_MODULE_SUMMARY",
        // Salud derivada mezcla evidencia de ventana; se recalcula en cada diagnóstico pero no representa por sí sola una transición física.
        "TSPLUS_MODULE_HEALTH_STATE"
    };

    // Un baseline sano debe representar configuración/estado relativamente estable, no CPU/RAM/sesiones actuales.
    private static readonly HashSet<string> BaselineTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "SERVICE_STATE", "RDP_STATE", "NETWORK_STATE", "PRINTING_STATE",
        "TSPLUS_DEPENDENCY_HEALTH", "TSPLUS_PRODUCT_STATE", "TSPLUS_INSTALLATION_BASELINE",
        "TSPLUS_APPCONTROL_STATE", "TSPLUS_APPCONTROL_SECURITY_STATE", "TSPLUS_WEB_SETTINGS_JS_STATE", "TSPLUS_WEB_SETTINGS_STATE",
        "TSPLUS_WEB_BALANCE_STATE", "TSPLUS_WEB_RUNTIME_STATE", "TSPLUS_WEB_STACK_STATE",
        "TSPLUS_FARM_CONFIGURATION_STATE", "TSPLUS_KNOWN_COMPONENT_STATE", "TSPLUS_VERSION_PROFILE_STATE", "TSPLUS_RELEASE_FAMILY",
        "TSPLUS_WEB_FILESET_STATE", "TSPLUS_APPLICATION_FILESET_STATE", "TSPLUS_SESSION_FILESET_STATE", "TSPLUS_MODULE_CRITICAL_FILE_STATE",
        "WINDOWS_REBOOT_PENDING_STATE", "WINDOWS_RDP_POLICY_STATE", "WINDOWS_TSPLUS_WINLOGON_INTEGRATION",
        "WINDOWS_RDS_ROLE_COMPATIBILITY",
        // Los estados de cobertura modular no forman parte del baseline: pueden variar por logging disponible.
        "TSPLUS_UNIVERSAL_PRINTER_STATE", "TSPLUS_VIRTUAL_PRINTER_STATE",
        "TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE",
        "TSPLUS_CONFIG_ARTIFACT_STATE", "SERVICE_DEPENDENCY_STATE", "SERVICE_DEPENDENT_STATE",
        "WINDOWS_LONGITUDINAL_CONFIG_STATE", "WINDOWS_LONGITUDINAL_LIBRARY_STATE",
        "TSPLUS_LONGITUDINAL_CONFIG_STATE", "TSPLUS_LONGITUDINAL_LIBRARY_STATE"
    };

    private static readonly string[] SensitiveKeyTokens =
    [
        "password", "contraseña", "passwd", "secret", "secreto", "token", "credential", "credencial",
        "private key", "clave privada", "api key", "apikey", "client secret"
    ];

    public static PersistentStateSnapshot Build(DiagnosticReport report, string toolVersion)
    {
        var observations = report.Eventos
            .Where(e => PersistentTypes.Contains(e.Tipo))
            .Select(ToObservation)
            .Where(o => o is not null)
            .Cast<PersistentObservation>()
            .GroupBy(o => o.Key, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Last())
            .OrderBy(o => o.Type, StringComparer.OrdinalIgnoreCase)
            .ThenBy(o => o.Component, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new PersistentStateSnapshot(
            2,
            toolVersion,
            DateTimeOffset.Now,
            report.Sistema.Equipo,
            report.Sistema.SistemaOperativo,
            report.Sistema.Version,
            report.Sistema.Build,
            report.Sistema.Arquitectura,
            report.Sistema.TsplusDetectado,
            report.Sistema.TsplusVersion,
            observations);
    }

    private static PersistentObservation? ToObservation(DiagnosticEvent e)
    {
        if (IsLongitudinalStateType(e.Tipo))
        {
            var coverage = e.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Cobertura", StringComparison.OrdinalIgnoreCase))?.Valor;
            if (!string.IsNullOrWhiteSpace(coverage)
                && !coverage.StartsWith("Disponible", StringComparison.OrdinalIgnoreCase)
                && !coverage.StartsWith("Completa", StringComparison.OrdinalIgnoreCase))
                return null;
        }
        var evidence = (e.Evidencia ?? [])
            .Where(x => !IsSensitiveKey(x.Clave) && !IsVolatileEvidence(e.Tipo, x.Clave))
            .Select(x => new KeyValuePair<string, string>(Normalize(x.Clave), Normalize(x.Valor)))
            .Where(x => !string.IsNullOrWhiteSpace(x.Key))
            .OrderBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var value = evidence.Count > 0
            ? string.Join(" | ", evidence.Select(x => $"{x.Key}={x.Value}"))
            : Normalize(e.Mensaje);
        if (value.Length > 8192) value = value[..8192] + "…";

        var identity = string.Join("|", new[]
        {
            e.Tipo,
            e.Producto.ToString(),
            e.Componente,
            e.Archivo ?? string.Empty,
            EvidenceIdentity(evidence)
        });
        var key = $"{e.Tipo}:{ShortHash(identity)}";

        return new PersistentObservation(
            key,
            e.Tipo,
            Normalize(e.Componente),
            e.Capa.ToString(),
            e.Producto.ToString(),
            e.Severidad.ToString(),
            value,
            !NoTransitionTypes.Contains(e.Tipo),
            BaselineTypes.Contains(e.Tipo));
    }

    private static string EvidenceIdentity(IReadOnlyList<KeyValuePair<string, string>> evidence)
    {
        var identityKeys = new[] { "Servicio", "Producto", "Puerto", "Archivo", "Ruta", "Aplicación", "Componente", "Nombre" };
        return string.Join("|", evidence
            .Where(x => identityKeys.Any(k => x.Key.Equals(k, StringComparison.OrdinalIgnoreCase)))
            .Select(x => $"{x.Key}={x.Value}"));
    }


    private static bool IsVolatileEvidence(string type, string key)
    {
        if (type.Equals("RDP_STATE", StringComparison.OrdinalIgnoreCase) &&
            key.Equals("Sesiones WTS", StringComparison.OrdinalIgnoreCase)) return true;
        if (type.Equals("TSPLUS_ADVSEC_MODULE_STATE", StringComparison.OrdinalIgnoreCase) &&
            (key.Equals("Artefactos coincidentes", StringComparison.OrdinalIgnoreCase) || key.Equals("Logs coincidentes", StringComparison.OrdinalIgnoreCase))) return true;
        if (type.Equals("TSPLUS_ADVSEC_PRODUCT_RUNTIME_STATE", StringComparison.OrdinalIgnoreCase) &&
            (key.Equals("Archivos inventariados por nombre", StringComparison.OrdinalIgnoreCase)
             || key.Equals("Logs observados", StringComparison.OrdinalIgnoreCase))) return true;
        if (type.Equals("TSPLUS_MODULE_HEALTH_STATE", StringComparison.OrdinalIgnoreCase) &&
            !key.Equals("Módulo", StringComparison.OrdinalIgnoreCase) &&
            !key.Equals("Estado funcional", StringComparison.OrdinalIgnoreCase)) return true;
        if (type.Equals("TSPLUS_FARM_CONFIGURATION_STATE", StringComparison.OrdinalIgnoreCase) &&
            (key.Equals("balance.bin", StringComparison.OrdinalIgnoreCase)
             || key.Equals("GatewayPortalLoadBalancing.ini", StringComparison.OrdinalIgnoreCase)
             || key.Equals("svcenterprise.log", StringComparison.OrdinalIgnoreCase))) return true;
        if (type.Equals("TSPLUS_VIRTUAL_PRINTER_STATE", StringComparison.OrdinalIgnoreCase) &&
            key.Equals("Impresoras Virtual/Virtual Devices", StringComparison.OrdinalIgnoreCase)) return true;
        if (type is "TSPLUS_WEB_FILESET_STATE" or "TSPLUS_APPLICATION_FILESET_STATE" or "TSPLUS_SESSION_FILESET_STATE")
        {
            if (key.Equals("Archivos dinámicos/logs", StringComparison.OrdinalIgnoreCase) ||
                key.Equals("Cambios recientes", StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static bool IsLongitudinalStateType(string type)
        => type is "WINDOWS_LONGITUDINAL_CONFIG_STATE" or "WINDOWS_LONGITUDINAL_LIBRARY_STATE"
            or "TSPLUS_LONGITUDINAL_CONFIG_STATE" or "TSPLUS_LONGITUDINAL_LIBRARY_STATE";

    private static bool IsSensitiveKey(string key)
        => SensitiveKeyTokens.Any(t => key.Contains(t, StringComparison.OrdinalIgnoreCase));

    private static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        return value.Replace("\r\n", " ", StringComparison.Ordinal)
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Trim();
    }

    private static string ShortHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return Convert.ToHexString(bytes.AsSpan(0, 8)).ToLowerInvariant();
    }
}
