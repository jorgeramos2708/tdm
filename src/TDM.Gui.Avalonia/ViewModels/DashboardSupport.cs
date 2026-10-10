using Avalonia.Media;
using TDM.Models;
using TDM.Notifications;
using TDM.Persistence;

namespace TDM.Gui.Avalonia.ViewModels;

internal static class DashboardPalette
{
    public static IBrush Good { get; } = new SolidColorBrush(Color.FromRgb(103, 232, 165));
    public static IBrush Warn { get; } = new SolidColorBrush(Color.FromRgb(255, 209, 102));
    public static IBrush Error { get; } = new SolidColorBrush(Color.FromRgb(255, 138, 61));
    public static IBrush Danger { get; } = new SolidColorBrush(Color.FromRgb(255, 77, 79));
    public static IBrush Muted { get; } = new SolidColorBrush(Color.FromRgb(143, 163, 184));
    public static IBrush Cyan { get; } = new SolidColorBrush(Color.FromRgb(57, 208, 255));
    public static IBrush Info { get; } = new SolidColorBrush(Color.FromRgb(245, 250, 255));
    public static IBrush Violet { get; } = new SolidColorBrush(Color.FromRgb(167, 139, 250));
}

internal static class DashboardRules
{
    public static IReadOnlyList<ObservabilityIncident> UniqueOperationalIncidents(IReadOnlyList<ObservabilitySample> samples)
        => samples
            .SelectMany(s => s.Incidents ?? [])
            .Where(ObservabilityIncidentPolicy.IsOperationalIncident)
            .GroupBy(ObservabilityIncidentPolicy.IdentityKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.Last())
            .GroupBy(DisplayIncidentKey, StringComparer.OrdinalIgnoreCase)
            .Select(g => g
                .OrderByDescending(x => NotificationSignalPolicy.EvidencePreference($"incident|LOCAL|{x.Component}|{x.Kind}"))
                .ThenByDescending(x => x.Timestamp)
                .First())
            .OrderByDescending(x => x.Timestamp)
            .ToList();

    public static int DroppedIncidents(IReadOnlyList<ObservabilitySample> samples)
        => samples.Sum(s => Math.Max(0, s.IncidentsDropped));

    // §1/P8: el catálogo ligero (monitor de 5 s) no incluye dependencias ni salud, así que
    // los paneles sirven el último ciclo completo que sí las evaluó. Cuando esos datos tienen
    // más de 2 min de antigüedad deben declararlo en vez de presentarlos como actuales.
    public static string StaleDataAge(DateTimeOffset latestTimestamp, ObservabilitySample? dataSample)
    {
        if (dataSample is null) return string.Empty;
        var age = latestTimestamp - dataSample.Timestamp;
        if (age < TimeSpan.FromMinutes(2)) return string.Empty;
        return FormatAge(age);
    }

    public static string FormatAge(TimeSpan age)
        => age.TotalMinutes >= 1 ? $"{(int)age.TotalMinutes} min" : $"{Math.Max(0, (int)age.TotalSeconds)} s";

    private static string DisplayIncidentKey(ObservabilityIncident incident)
    {
        var rawKey = $"incident|LOCAL|{incident.Component}|{incident.Kind}";
        var canonical = NotificationSignalPolicy.CanonicalKey(rawKey);
        if (canonical.EndsWith("|PROCESS_CRASH", StringComparison.OrdinalIgnoreCase))
        {
            // Windows suele registrar 1026, 1000 y 1001 para el mismo cierre. Una ventana
            // corta conserva crashes realmente separados y evita tres/cuatro filas iguales.
            var tenSecondWindow = incident.Timestamp.ToUniversalTime().ToUnixTimeSeconds() / 10;
            return $"{canonical}|{tenSecondWindow}";
        }

        return ObservabilityIncidentPolicy.IdentityKey(incident);
    }

    public static IReadOnlyDictionary<string, string> TargetServiceStates(IReadOnlyDictionary<string, string>? states)
    {
        if (states is null || states.Count == 0)
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        return states
            .Where(x => !IsInternalTdmService(x.Key))
            .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);
    }

    public static (IReadOnlyDictionary<string, string> Services, IReadOnlyDictionary<string, string> Dependencies)
        TsplusOperationalStates(
            IReadOnlyDictionary<string, string>? serviceStates,
            IReadOnlyDictionary<string, string>? dependencyStates)
    {
        var services = TargetServiceStates(serviceStates);
        var dependencies = dependencyStates ?? new Dictionary<string, string>();
        var relevant = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var name in services.Keys.Where(IsTsplusRootService)) relevant.Add(name);
        foreach (var name in dependencies.Keys)
            if (TryParseDependencyRelation(name, out var source, out _) && IsTsplusRootService(source))
                relevant.Add(source);

        // Conservar únicamente el subgrafo SCM alcanzable desde servicios TSplus o
        // desde el núcleo RDP que TSplus utiliza. Una dependencia transitiva real sí
        // afecta a TSplus; un servicio del catálogo general sin esa relación no se muestra.
        var changed = true;
        while (changed)
        {
            changed = false;
            foreach (var name in dependencies.Keys)
            {
                if (!TryParseDependencyRelation(name, out var source, out var dependency) || !relevant.Contains(source)) continue;
                if (relevant.Add(dependency)) changed = true;
            }
        }

        var filteredServices = services
            .Where(x => relevant.Contains(x.Key))
            .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);
        var filteredDependencies = dependencies
            .Where(x => TryParseDependencyRelation(x.Key, out var source, out _)
                ? relevant.Contains(source)
                : IsTsplusVirtualDependency(x.Key))
            .ToDictionary(x => x.Key, x => x.Value, StringComparer.OrdinalIgnoreCase);

        return (filteredServices, filteredDependencies);
    }

    public static bool IsInternalTdmService(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        var normalized = new string(name.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        return normalized is "tdmservice" or "tsplusdiagnosticmonitor" or "tsplusdiagnosticmonitorservice";
    }

    public static int OperationalStateLevel(string? state)
    {
        var value = state ?? string.Empty;
        if (string.IsNullOrWhiteSpace(value)) return 0;

        // Estados deliberadamente neutrales: no deben inflar la dona de fallas ni
        // generar acciones preventivas sólo por no estar Running.
        if (ContainsAny(value, "Complementario", "No requerido", "Bajo demanda")) return 1;

        // F35 (M-06): escala renumerada para separar lo que no se midió de lo que está
        // degradado. 0 vacío · 1 sano/neutro · 2 brecha de cobertura (no hay medición) ·
        // 3 degradación o revisión (hay señal) · 4 falla explícita. Antes "No evaluado"
        // y "Advertencia" compartían bucket y ensuciaban la semántica del scoring.
        if (ContainsAny(value, "No evaluado", "Unknown", "N/D", "Parcial", "No localizado")) return 2;

        // Una dependencia condicional detenida merece contexto/revisión, pero no
        // equivale a una dependencia requerida caída: nunca alcanza el nivel 4.
        if (ContainsAny(value, "Condicional"))
        {
            if (ContainsAny(value, "Running", "Operativo", "Saludable", "OK", "Deshabilitado")) return 1;
            return 3;
        }

        // Sólo una falla explícita de un elemento requerido/operativo cuenta como caída.
        if (ContainsAny(value, "Stopped", "Failed", "Error", "Crítico", "Critico", "No operativo", "Listening=No", "Gateway=No", "Activos=0")) return 4;

        if (ContainsAny(value, "Running", "En ejecución", "Operativo", "Saludable", "Listening=Sí", "Gateway=Sí", "OK")) return 1;

        // Advertencia, degradación o texto no reconocido: requiere revisión sin
        // declarar caída (el desconocido conserva incertidumbre en vez de asumir salud).
        return 3;
    }

    public static bool IsRunningState(string? state)
    {
        var value = state ?? string.Empty;
        var stoppedMarkers = new[]
        {
            "Stopped", "Failed", "Error", "No operativo", "No activa", "No evaluado", "Unknown",
            "Paused", "Pending", "Listening=No", "Gateway=No", "Activos=0", "Bajo demanda", "Deshabilitado"
        };
        if (stoppedMarkers.Any(term => value.Contains(term, StringComparison.OrdinalIgnoreCase))) return false;

        var runningMarkers = new[]
        {
            "Running", "En ejecución", "Operativo", "Saludable", "Listening=Sí", "Gateway=Sí", "OK"
        };
        return runningMarkers.Any(term => value.Contains(term, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsSessionIncident(ObservabilityIncident incident)
        => incident.Kind.ToUpperInvariant() is "SESSION" or "USER_LOGON_FAILURE" or "USER_NLA_PASSWORD_FAILURE" or
            "WINDOWS_CREDENTIAL_VALIDATION_FAILURE" or "ACCOUNT_LOCKOUT" or "KERBEROS_PREAUTH_FAILURE" or "RDP_EVENT_INCREMENTAL";

    public static bool HasSessionData(ObservabilitySample sample)
        => !string.IsNullOrWhiteSpace(sample.SessionCoverage)
           && !sample.SessionCoverage.Equals("No evaluado", StringComparison.OrdinalIgnoreCase);

    public static ObservabilitySample? LastSessionSample(IReadOnlyList<ObservabilitySample> samples)
        => samples.LastOrDefault(x => HasSessionData(x) || x.LogonFailures > 0 || x.NlaFailures > 0);

    public static string ShortPath(string path)
        => path.Length <= 62 ? path : $"…{path[^61..]}";

    /// <summary>
    /// Limita únicamente los puntos enviados al control gráfico. El conjunto completo
    /// sigue disponible para cálculos, incidentes y estadísticas del periodo seleccionado.
    /// </summary>
    public static IReadOnlyList<ObservabilitySample> ChartSamples(IReadOnlyList<ObservabilitySample> samples, int maxPoints = 1200)
    {
        if (samples.Count <= maxPoints || maxPoints < 2) return samples;

        var result = new List<ObservabilitySample>(maxPoints);
        var denominator = maxPoints - 1d;
        var sourceLast = samples.Count - 1d;
        var previousIndex = -1;
        for (var i = 0; i < maxPoints; i++)
        {
            var index = (int)Math.Round(i * sourceLast / denominator);
            if (index == previousIndex) continue;
            result.Add(samples[index]);
            previousIndex = index;
        }

        if (!ReferenceEquals(result[^1], samples[^1]) && result[^1].Timestamp != samples[^1].Timestamp)
            result.Add(samples[^1]);
        return result;
    }

    /// <summary>
    /// Serie continua para las gráficas: los huecos de una métrica (muestras sin CPU,
    /// primer ciclo con baseline de GetSystemTimes, etc.) se completan con el último
    /// valor conocido para que la línea no se vea "mordida" por NaN intercalados.
    /// Si no existe ningún valor, se devuelve todo NaN y la gráfica queda vacía.
    /// </summary>
    public static IReadOnlyList<double> ContinuousSeries(
        IReadOnlyList<ObservabilitySample> samples,
        Func<ObservabilitySample, double?> selector)
    {
        var values = new double[samples.Count];
        var last = double.NaN;
        for (var i = 0; i < samples.Count; i++)
        {
            var value = selector(samples[i]);
            if (value.HasValue && !double.IsNaN(value.Value)) last = value.Value;
            values[i] = last;
        }

        return values;
    }

    public static IBrush StateBrush(string state)
        => OperationalStateLevel(state) switch
        {
            >= 4 => DashboardPalette.Error,
            3 => DashboardPalette.Warn,
            1 => DashboardPalette.Good,
            // 0 vacío y 2 brecha de cobertura: gris en vez de naranja (M-06), para que
            // "No evaluado" no se pinte como degradación.
            _ => DashboardPalette.Muted
        };

    public static int HealthRank(string value)
    {
        if (value.Contains("CRÍT", StringComparison.OrdinalIgnoreCase)) return 4;
        if (value.Contains("ERROR", StringComparison.OrdinalIgnoreCase)) return 3;
        if (value.Contains("ATEN", StringComparison.OrdinalIgnoreCase) || value.Contains("ADVERT", StringComparison.OrdinalIgnoreCase)) return 2;
        if (value.Contains("SALUDABLE", StringComparison.OrdinalIgnoreCase) || value.Contains("SIN FALLA", StringComparison.OrdinalIgnoreCase)) return 1;
        if (value.Contains("FALLA", StringComparison.OrdinalIgnoreCase)) return 3;
        return 0;
    }

    public static (string Label, IBrush Brush) HealthState(string value)
    {
        if (value.Contains("NO EVALUADO", StringComparison.OrdinalIgnoreCase)) return ("NO EVALUADO", DashboardPalette.Muted);
        if (value.Contains("CRÍT", StringComparison.OrdinalIgnoreCase)) return ("CRÍTICO", DashboardPalette.Danger);
        if (value.Contains("ERROR", StringComparison.OrdinalIgnoreCase)) return ("ERROR", DashboardPalette.Error);
        if (value.Contains("ATEN", StringComparison.OrdinalIgnoreCase) || value.Contains("ADVERT", StringComparison.OrdinalIgnoreCase)) return ("ATENCIÓN", DashboardPalette.Warn);
        if (value.Contains("COBERTURA PARCIAL", StringComparison.OrdinalIgnoreCase)) return ("SIN FALLA · PARCIAL", DashboardPalette.Info);
        if (value.Contains("COBERTURA LOCAL", StringComparison.OrdinalIgnoreCase)) return ("SIN FALLA · LOCAL", DashboardPalette.Info);
        if (value.Contains("SALUDABLE", StringComparison.OrdinalIgnoreCase) || value.Contains("SIN FALLA", StringComparison.OrdinalIgnoreCase)) return ("SALUDABLE", DashboardPalette.Good);
        if (value.Contains("FALLA", StringComparison.OrdinalIgnoreCase)) return ("ERROR", DashboardPalette.Error);
        return ("NO EVALUADO", DashboardPalette.Muted);
    }

    public static (string Label, string Detail, IBrush Brush) OverallModuleHealth(IReadOnlyDictionary<string, string> modules)
    {
        if (modules.Count == 0) return ("NO EVALUADO", "sin salud modular", DashboardPalette.Muted);
        var worst = modules.OrderByDescending(x => HealthRank(x.Value)).First();
        var state = HealthState(worst.Value);
        return (state.Label, CompactModuleName(worst.Key), state.Brush);
    }

    public static (string Label, string Detail, IBrush Brush) ModuleStateFor(IReadOnlyDictionary<string, string> modules, string module)
    {
        var matches = modules.Where(x => ModuleMatches(module, x.Key)).ToList();
        if (matches.Count == 0) return ("NO EVALUADO", "sin evidencia", DashboardPalette.Muted);
        var worst = matches.OrderByDescending(x => HealthRank(x.Value)).First();
        var state = HealthState(worst.Value);
        return (state.Label, NormalizeHealthDetail(worst.Value), state.Brush);
    }

    public static string CompactModuleName(string value)
        => value switch
        {
            "RDP / Remote Access Core" => "Remote Access/RDP",
            "Web / HTML5 / Web Portal" => "Web/HTML5",
            "Sesiones / perfiles / logon" => "Sesiones/logon",
            "Farm / Gateway / Load Balancing / Reverse Proxy" => "Farm/Gateway",
            "Two-Factor Authentication (2FA)" => "2FA",
            "RDP / Listener" => "RDP/Listener",
            _ => CompactSlashes(value.Length <= 34 ? NormalizeDisplayName(value) : NormalizeDisplayName(value[..31] + "..."))
        };

    public static string NormalizeHealthDetail(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "sin evidencia";
        if (value.Contains("NO EVALUADO", StringComparison.OrdinalIgnoreCase)) return "SIN EVIDENCIA";
        if (value.Contains("CRÍT", StringComparison.OrdinalIgnoreCase) || value.Contains("CRIT", StringComparison.OrdinalIgnoreCase)) return "FALLA CRÍTICA OBSERVADA";
        if (value.Contains("ERROR", StringComparison.OrdinalIgnoreCase)) return "ERROR/FALLA OBSERVADA";
        if (value.Contains("ATEN", StringComparison.OrdinalIgnoreCase) || value.Contains("ADVERT", StringComparison.OrdinalIgnoreCase)) return "REQUIERE ATENCIÓN";
        if (value.Contains("COBERTURA PARCIAL", StringComparison.OrdinalIgnoreCase)) return "SIN FALLA OBSERVADA/COBERTURA PARCIAL";
        if (value.Contains("COBERTURA LOCAL", StringComparison.OrdinalIgnoreCase)) return "SIN FALLA OBSERVADA/COBERTURA LOCAL";
        if (value.Contains("SALUDABLE", StringComparison.OrdinalIgnoreCase) || value.Contains("SIN FALLA", StringComparison.OrdinalIgnoreCase)) return "SALUDABLE/SIN FALLA OBSERVADA";
        if (value.Contains("FALLA", StringComparison.OrdinalIgnoreCase)) return "ERROR/FALLA OBSERVADA";
        return CompactSlashes(value);
    }

    public static string LocalizeOperationalText(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "N/D";
        return CompactSlashes(value
            .Replace("Stopped", "Detenido", StringComparison.OrdinalIgnoreCase)
            .Replace("Running", "En ejecución", StringComparison.OrdinalIgnoreCase)
            .Replace("Failed", "Fallido", StringComparison.OrdinalIgnoreCase)
            .Replace("Unknown", "Desconocido", StringComparison.OrdinalIgnoreCase)
            .Replace("Paused", "Pausado", StringComparison.OrdinalIgnoreCase)
            .Replace("Pending", "Pendiente", StringComparison.OrdinalIgnoreCase));
    }

    public static string LocalizedPreventiveModuleName(string value)
        => CompactModuleName(value) switch
        {
            "Remote Access/RDP" => "Acceso remoto/RDP",
            "Sesiones/logon" => "Sesiones/inicio de sesión",
            "Farm/Gateway" => "Granja/Puerta de enlace",
            "RDP/Listener" => "RDP/Servicio de escucha",
            _ => CompactModuleName(value)
        };

    public static string NormalizeDisplayName(string value)
        => value switch
        {
            "RDP / Listener" => "RDP/Listener",
            "Red / Gateway" => "Red/Gateway",
            "Sesiones / logon TSplus" => "Sesiones/logon TSplus",
            _ => CompactSlashes(value)
        };

    public static string CompactSlashes(string value)
        => value.Replace(" / ", "/", StringComparison.Ordinal)
            .Replace("/ ", "/", StringComparison.Ordinal)
            .Replace(" /", "/", StringComparison.Ordinal);

    public static IBrush OriginBrush(string? origin)
        => origin?.ToUpperInvariant() switch
        {
            "TSPLUS" => DashboardPalette.Cyan,
            "WINDOWS" => DashboardPalette.Info,
            "EXTERNO" => DashboardPalette.Warn,
            _ => DashboardPalette.Muted
        };

    public static string SanitizeVisibleText(string? text)
        => TdmVisibleText.Sanitize(text);

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024d:0.0} KB";
        return $"{bytes / 1024d / 1024d:0.00} MB";
    }

    public static IBrush MetricBrush(double? value, double warn, double critical)
    {
        if (!value.HasValue) return DashboardPalette.Muted;
        if (value.Value >= critical) return DashboardPalette.Error;
        if (value.Value >= warn) return DashboardPalette.Warn;
        return DashboardPalette.Good;
    }

    public static IBrush ReverseMetricBrush(double? value, double warn, double critical)
    {
        if (!value.HasValue) return DashboardPalette.Muted;
        if (value.Value <= critical) return DashboardPalette.Error;
        if (value.Value <= warn) return DashboardPalette.Warn;
        return DashboardPalette.Good;
    }

    private static bool ModuleMatches(string requested, string actual)
    {
        if (actual.Equals(requested, StringComparison.OrdinalIgnoreCase)) return true;
        if (requested.Equals("Advanced Security", StringComparison.OrdinalIgnoreCase))
            return actual.StartsWith("Advanced Security", StringComparison.OrdinalIgnoreCase);
        return actual.Contains(requested, StringComparison.OrdinalIgnoreCase) || requested.Contains(actual, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsAny(string value, params string[] terms)
        => terms.Any(term => value.Contains(term, StringComparison.OrdinalIgnoreCase));

    private static bool IsTsplusRootService(string name)
    {
        string[] rdpRoots = ["TermService", "UmRdpService", "SessionEnv", "TermServLicensing", "Tssdis", "RDMS", "TSGateway"];
        if (rdpRoots.Any(x => name.Equals(x, StringComparison.OrdinalIgnoreCase))) return true;

        string[] tsplusMarkers =
        [
            "TSplus", "RemoteAccess", "Remote Access", "RemoteSupport", "Remote Support", "ServerMonitoring", "Server Monitoring",
            "Advanced Security", "TSplus-Security", "Application Publishing", "APSC", "WebPortal", "HTML5",
            "TwoFactor", "Two Factor", "2FA", "UniversalPrinter", "Universal Printer", "VirtualPrinter", "Virtual Printer",
            "Farm/Gateway", "Farm / Gateway"
        ];
        return tsplusMarkers.Any(x => name.Contains(x, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsTsplusVirtualDependency(string name)
        => name.Equals("RDP/Listener", StringComparison.OrdinalIgnoreCase)
           || name.Equals("RDP / Listener", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Red/Gateway", StringComparison.OrdinalIgnoreCase)
           || name.Equals("Red / Gateway", StringComparison.OrdinalIgnoreCase)
           || IsTsplusRootService(name);

    private static bool TryParseDependencyRelation(string name, out string source, out string dependency)
    {
        var separator = name.IndexOf('→');
        if (separator <= 0 || separator >= name.Length - 1)
        {
            source = dependency = string.Empty;
            return false;
        }

        source = name[..separator].Trim();
        dependency = name[(separator + 1)..].Trim();
        return source.Length > 0 && dependency.Length > 0;
    }
}

public sealed record StateRow(string Name, string Origin, string Status, IBrush Accent, IBrush OriginAccent);
public sealed record MetricRow(string Name, string Value, string Detail, IBrush Accent);
public sealed record IncidentRow(string Time, string Severity, string Kind, string Component, string Summary, IBrush Accent);
public sealed record ModuleRow(string Name, string Status, string Detail, IBrush Accent);
public sealed record SignalRow(string Name, string Detail, IBrush Accent);
public sealed record CausalRow(string Name, string Origin, string Count, IBrush Accent);
public sealed record FederationRow(string Server, string Group, string Role, string Connectivity, string Health, string Cpu, string Memory, string Sessions, string Incidents, string Detail, IBrush Accent);
