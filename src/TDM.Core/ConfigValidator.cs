using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using TDM.Models;
using TDM.Persistence;

#pragma warning disable CA1416 // EventLog is Windows-only

namespace TDM.Core;

/// <summary>
/// Validación estricta de configuración al arranque (fail-fast).
/// Lanza excepción si hay JSON corrupto, umbrales fuera de rango, rutas inaccesibles, etc.
/// </summary>
public static class ConfigValidator
{
    public sealed record ValidationResult(
        bool IsValid,
        IReadOnlyList<string> Errors,
        IReadOnlyList<string> Warnings);

    /// <summary>
    /// Valida toda la configuración al arranque. Lanza ConfigValidationException si hay errores críticos.
    /// </summary>
    public static void ValidateOrThrow(string? rootPath = null, bool portable = false)
    {
        var result = Validate(rootPath, portable);
        if (!result.IsValid)
        {
            var msg = "CONFIGURACIÓN INVÁLIDA (fail-fast):\n" + string.Join("\n", result.Errors);
            throw new ConfigValidationException(msg, result.Errors);
        }
        // Warnings solo se loguean
        foreach (var w in result.Warnings)
            System.Diagnostics.Debug.WriteLine($"[CONFIG WARN] {w}");
    }

    /// <summary>
    /// Valida sin lanzar; retorna resultado para logging/health check.
    /// </summary>
    public static ValidationResult Validate(string? rootPath = null, bool portable = false)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        var root = rootPath ?? (portable || PortableRuntime.IsEnabled
            ? LocalStateStore.DefaultRootPath
            : TdmDataPaths.MachineRootPath);

        // 1. Directorio raíz accesible (lectura/escritura)
        try
        {
            if (!Directory.Exists(root))
                Directory.CreateDirectory(root);

            var testFile = Path.Combine(root, $".write_test_{Guid.NewGuid():N}.tmp");
            File.WriteAllText(testFile, "ok");
            File.Delete(testFile);
        }
        catch (Exception ex)
        {
            errors.Add($"Directorio raíz inaccesible ({root}): {ex.Message}");
        }

        // 2. Settings JSON válido + umbrales en rango
        try
        {
            var settingsStore = new SupportMonitoringSettingsStore(root);
            var settings = settingsStore.LoadAsync().GetAwaiter().GetResult();
            var thresholdErrors = SupportThresholdsValidator.Validate(settings.Thresholds);
            errors.AddRange(thresholdErrors.Select(e => $"Umbrales: {e}"));

            // Verificar que las rutas de store existen
            foreach (var sub in new[] { "history", "baseline", "cursors", "settings", "transitions" })
            {
                var p = Path.Combine(root, sub);
                if (!Directory.Exists(p))
                    warnings.Add($"Subdirectorio '{sub}' no existe (se creará al primer uso): {p}");
            }
        }
        catch (Exception ex)
        {
            errors.Add($"Settings store corrupto o inaccesible: {ex.Message}");
        }

        // 3. Email settings JSON válido
        try
        {
            var notificationRoot = portable ? LocalStateStore.DefaultRootPath : TdmDataPaths.MachineRootPath;
            var emailStore = new EmailNotificationSettingsStore(notificationRoot);
            var emailSettings = emailStore.LoadAsync().GetAwaiter().GetResult();
            var emailErrors = EmailNotificationSettingsValidator.Validate(emailSettings);
            errors.AddRange(emailErrors.Select(e => $"Email: {e}"));
        }
        catch (Exception ex)
        {
            errors.Add($"Email settings corrupto: {ex.Message}");
        }

        // 4. Federation JSON válido
        try
        {
            var fedStore = new FederationStore(LocalStateStore.DefaultRootPath);
            var fed = fedStore.LoadConfigurationAsync().GetAwaiter().GetResult();
            if (fed.Nodes.Count == 0)
                warnings.Add("Federación: 0 nodos configurados");
            foreach (var n in fed.Nodes)
            {
                if (!Directory.Exists(n.ObservabilityRoot))
                    warnings.Add($"Nodo '{n.DisplayName}': ruta observabilidad no existe: {n.ObservabilityRoot}");
            }
        }
        catch (Exception ex)
        {
            errors.Add($"Federation config corrupto: {ex.Message}");
        }

        // 5. TSplus install path (validación opcional, se hace en collectors)
        // Se omite aquí para evitar dependencia circular; TsplusLogCollector valida su propia ruta

        // 6. Permisos EventLog (solo aviso)
        try
        {
            using var log = new System.Diagnostics.EventLog("System");
            _ = log.Entries.Count; // fuerza acceso
        }
        catch (Exception ex)
        {
            warnings.Add($"EventLog 'System' no accesible (requiere admin): {ex.Message}");
        }

        // 7. netstat disponible
        var netstat = Path.Combine(Environment.SystemDirectory, "netstat.exe");
        if (!File.Exists(netstat))
            warnings.Add($"netstat.exe no encontrado en {Environment.SystemDirectory}");

        return new ValidationResult(errors.Count == 0, errors, warnings);
    }
}

public sealed class ConfigValidationException : Exception
{
    public IReadOnlyList<string> Errors { get; }
    public ConfigValidationException(string message, IReadOnlyList<string> errors) : base(message)
    {
        Errors = errors;
    }
}