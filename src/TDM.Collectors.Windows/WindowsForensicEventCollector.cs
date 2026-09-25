using System.Diagnostics.Eventing.Reader;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Auditoría forense ampliada de registros Windows relevantes para TSplus.
/// Sólo lectura. Los canales inexistentes o deshabilitados se reportan como cobertura, no como falla.
/// </summary>
public sealed class WindowsForensicEventCollector : IReadOnlyCollector
{
    public string Nombre => "Auditoría forense de Windows";

    private sealed record ChannelSpec(string Log, DiagnosticLayer Layer, string Area, int Max = 180);

    private static readonly ChannelSpec[] Channels =
    [
        new("System", DiagnosticLayer.Windows, "Sistema", 350),
        new("Application", DiagnosticLayer.Windows, "Aplicación", 350),
        new("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", DiagnosticLayer.Rdp, "RDP/LocalSessionManager"),
        new("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", DiagnosticLayer.Rdp, "RDP/RemoteConnectionManager"),
        new("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational", DiagnosticLayer.Rdp, "RDP/CoreTS"),
        new("Microsoft-Windows-PrintService/Admin", DiagnosticLayer.Windows, "Impresión"),
        new("Microsoft-Windows-WMI-Activity/Operational", DiagnosticLayer.Windows, "WMI"),
        new("Microsoft-Windows-Windows Defender/Operational", DiagnosticLayer.Seguridad, "Defender"),
        new("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", DiagnosticLayer.Seguridad, "Firewall de Windows"),
        new("Microsoft-Windows-WindowsUpdateClient/Operational", DiagnosticLayer.Windows, "Windows Update"),
        new("Microsoft-Windows-Resource-Exhaustion-Detector/Operational", DiagnosticLayer.Windows, "Agotamiento de recursos"),
        new("Microsoft-Windows-DiskDiagnostic/Operational", DiagnosticLayer.Windows, "Diagnóstico de disco"),
        new("Microsoft-Windows-GroupPolicy/Operational", DiagnosticLayer.Windows, "Directiva de grupo"),
        new("Microsoft-Windows-DNS-Client/Operational", DiagnosticLayer.Red, "DNS"),
        new("Microsoft-Windows-NetworkProfile/Operational", DiagnosticLayer.Red, "Red"),
        new("Microsoft-Windows-CAPI2/Operational", DiagnosticLayer.Seguridad, "Certificados/CAPI2"),
        new("Microsoft-Windows-CodeIntegrity/Operational", DiagnosticLayer.Seguridad, "Integridad de código"),
        new("Microsoft-Windows-AppLocker/EXE and DLL", DiagnosticLayer.Seguridad, "AppLocker EXE/DLL"),
        new("Microsoft-Windows-AppLocker/MSI and Script", DiagnosticLayer.Seguridad, "AppLocker MSI/Script"),
        new("Microsoft-Windows-Diagnostics-Performance/Operational", DiagnosticLayer.Windows, "Rendimiento de Windows")
    ];

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var coverage = new List<EvidenceItem>();
        var window = DiagnosticWindow.Resolve(context);
        var windowStart = window.Start;
        var windowEnd = window.End;
        coverage.Add(new EvidenceItem("Ventana solicitada", $"{windowStart:O} → {windowEnd:O}"));
        coverage.Add(new EvidenceItem("Duración solicitada", $"{context.Lookback.TotalHours:0.##} h"));
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);
        var xpath = $"*[System[(Level=1 or Level=2 or Level=3) and {timeClause}]]";
        var channelDiscovery = DiscoverAdditionalChannels();
        coverage.Add(new EvidenceItem("Descubrimiento dinámico de canales",
            channelDiscovery.Available
                ? channelDiscovery.Truncated
                    ? $"Parcial; adicionales considerados={channelDiscovery.Channels.Count}; límite=24 alcanzado"
                    : $"Disponible; adicionales={channelDiscovery.Channels.Count}; límite=24 no alcanzado"
                : "No evaluado: " + channelDiscovery.Error));
        var channels = Channels.Concat(channelDiscovery.Channels)
            .GroupBy(x => x.Log, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        foreach (var spec in channels)
        {
            try
            {
                var query = new EventLogQuery(spec.Log, PathType.LogName, xpath) { ReverseDirection = true, TolerateQueryErrors = false };
                using var reader = new EventLogReader(query);
                var count = 0;
                var limit = ResolveLimit(spec.Max, context.Lookback);
                var limitReached = false;
                for (EventRecord? record = reader.ReadEvent(); record is not null; record = reader.ReadEvent())
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using (record)
                    {
                        var provider = record.ProviderName ?? spec.Area;
                        if (!Relevant(spec, provider, record.Id)) continue;
                        string message;
                        try { message = record.FormatDescription() ?? "Sin descripción."; }
                        catch { message = "Descripción no disponible."; }
                        var ts = record.TimeCreated is null ? (DateTimeOffset?)null : new DateTimeOffset(record.TimeCreated.Value);
                        var severity = record.Level switch
                        {
                            1 => DiagnosticSeverity.Critico,
                            2 => DiagnosticSeverity.Error,
                            3 => DiagnosticSeverity.Advertencia,
                            _ => DiagnosticSeverity.Informativo
                        };
                        var product = ProductFromText($"{provider} {message}");
                        // Application/System pueden contener directamente el crash de un proceso TSplus.
                        // En canales especializados (Firewall, WMI, RDP, red, etc.) conservamos la capa Windows original
                        // y usamos Producto sólo como relación, para no convertir una dependencia del SO en evento TSplus.
                        var applicationCrashProvider = provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase) ||
                                                       provider.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase) ||
                                                       provider.Contains("Windows Error Reporting", StringComparison.OrdinalIgnoreCase) ||
                                                       provider.Contains("Application Hang", StringComparison.OrdinalIgnoreCase);
                        var eventType = ClassifyType(spec, provider, record.Id, message);
                        // V2: capa única Seguridad para TLS en los tres emisores (Rdp, forense, base);
                        // sin esto el mismo registro diverge por capa aunque el dedup lo colapse.
                        var layer = eventType == "TLS_SCHANNEL_EVENT"
                            ? DiagnosticLayer.Seguridad
                            : spec.Log == "Application" && applicationCrashProvider &&
                                    product != TsplusProduct.Ninguno && product != TsplusProduct.Desconocido
                            ? DiagnosticLayer.Tsplus
                            : spec.Layer;
                        // V2: para Schannel, usar Fuente="Schannel" para dedup consistente
                        var fuente = eventType == "TLS_SCHANNEL_EVENT" ? "Schannel" : provider;
                        events.Add(new DiagnosticEvent(ts, fuente, spec.Area, layer, severity, eventType, message,
                            record.Id.ToString(), Evidencia:
                            [
                                new EvidenceItem("Canal", spec.Log),
                                new EvidenceItem("Área", spec.Area),
                                new EvidenceItem("EventId", record.Id.ToString()),
                                new EvidenceItem("Provider", provider),
                                new EvidenceItem("RecordId", record.RecordId?.ToString() ?? "N/D")
                            ], Producto: product));
                        count++;
                        if (count >= limit)
                        {
                            limitReached = true;
                            break;
                        }
                    }
                }
                coverage.Add(new EvidenceItem(spec.Area, limitReached
                    ? $"Parcial; eventos relevantes>={count}; límite adaptativo={limit} alcanzado"
                    : $"Disponible; eventos relevantes={count}"));
            }
            catch (EventLogNotFoundException) { coverage.Add(new EvidenceItem(spec.Area, "Canal no disponible")); }
            catch (UnauthorizedAccessException) { coverage.Add(new EvidenceItem(spec.Area, "Sin permisos de lectura")); }
            catch (EventLogException ex) { coverage.Add(new EvidenceItem(spec.Area, $"No legible: {ex.Message}")); }
        }

        var unreadable = coverage
            .Where(x => x.Valor.StartsWith("Sin permisos", StringComparison.OrdinalIgnoreCase) || x.Valor.StartsWith("No legible", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var limited = coverage.Where(x => x.Valor.StartsWith("Parcial;", StringComparison.OrdinalIgnoreCase)).ToList();
        var coveragePartial = unreadable.Count > 0 || limited.Count > 0 || !channelDiscovery.Available || channelDiscovery.Truncated;
        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Cobertura forense Windows", DiagnosticLayer.Windows,
            coveragePartial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "WINDOWS_FORENSIC_COVERAGE",
            coveragePartial
                ? "Cobertura de Event Viewer parcial: existen canales no legibles/NO EVALUADOS o se alcanzó un límite de seguridad de lectura/descubrimiento."
                : "Cobertura de registros Windows consultados por TDM.",
            Evidencia: coverage));
        if (unreadable.Count > 0 || limited.Count > 0 || !channelDiscovery.Available || channelDiscovery.Truncated)
        {
            findings.Add(new DiagnosticFinding(
                "FORENSIC-COVERAGE-INCOMPLETE",
                "Cobertura forense de Windows",
                DiagnosticSeverity.Advertencia,
                "La cobertura forense está incompleta por permisos, errores de lectura o límites de seguridad alcanzados.",
                "TDM no interpreta una fuente que no pudo leer como evidencia de que esa capa esté sana. Las hipótesis que dependan de esos canales deben conservarse como no descartadas.",
                [.. unreadable, .. limited, .. (!channelDiscovery.Available ? [new EvidenceItem("Descubrimiento dinámico", "No evaluado: " + channelDiscovery.Error)] : Array.Empty<EvidenceItem>()), .. (channelDiscovery.Truncated ? [new EvidenceItem("Descubrimiento dinámico", "Parcial: límite de 24 canales adicionales alcanzado")] : Array.Empty<EvidenceItem>())],
                ConfidenceLevel.Confirmada,
                Capa: DiagnosticLayer.Windows));
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static int ResolveLimit(int baseLimit, TimeSpan lookback)
    {
        var factor = lookback.TotalHours switch
        {
            <= 4 => 1,
            <= 12 => 2,
            <= 24 => 4,
            _ => 8
        };
        return Math.Min(3_000, Math.Max(baseLimit, baseLimit * factor));
    }

    private sealed record ChannelDiscoveryResult(IReadOnlyList<ChannelSpec> Channels, bool Available, bool Truncated, string? Error);

    private static ChannelDiscoveryResult DiscoverAdditionalChannels()
    {
        try
        {
            var known = new HashSet<string>(Channels.Select(x => x.Log), StringComparer.OrdinalIgnoreCase);
            var discoveredNames = EventLogSession.GlobalSession.GetLogNames()
                .Where(name => !known.Contains(name))
                .Where(IsMissionRelevantChannel)
                .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
                .Take(25)
                .ToList();
            var truncated = discoveredNames.Count > 24;
            var dynamic = discoveredNames
                .Take(24)
                .Select(name => new ChannelSpec(name, LayerForDynamicChannel(name), $"Canal descubierto · {ShortChannelName(name)}", 120))
                .ToList();
            return new ChannelDiscoveryResult(dynamic, true, truncated, null);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or InvalidOperationException)
        {
            return new ChannelDiscoveryResult([], false, false, ex.Message);
        }
    }

    private static bool IsMissionRelevantChannel(string name)
        => name.Contains("TSplus", StringComparison.OrdinalIgnoreCase)
           || name.Contains("TerminalServices", StringComparison.OrdinalIgnoreCase)
           || name.Contains("RemoteDesktopServices", StringComparison.OrdinalIgnoreCase)
           || name.Contains("AppLocker", StringComparison.OrdinalIgnoreCase)
           || name.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase);

    private static DiagnosticLayer LayerForDynamicChannel(string name)
        => name.Contains("TerminalServices", StringComparison.OrdinalIgnoreCase) || name.Contains("RemoteDesktopServices", StringComparison.OrdinalIgnoreCase)
            ? DiagnosticLayer.Rdp
            : name.Contains("AppLocker", StringComparison.OrdinalIgnoreCase) || name.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase)
                ? DiagnosticLayer.Seguridad
                : name.Contains("TSplus", StringComparison.OrdinalIgnoreCase)
                    ? DiagnosticLayer.Tsplus
                    : DiagnosticLayer.Windows;

    private static string ShortChannelName(string name)
        => name.Length <= 72 ? name : "…" + name[^71..];

    private static string ClassifyType(ChannelSpec spec, string provider, int id, string message)
    {
        if (provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase))
        {
            if (id is 7031 or 7034) return "SERVICE_TERMINATION";
            if (id is 7000 or 7001 or 7009 or 7011 or 7023 or 7024) return "SERVICE_START_FAILURE";
        }
        if (provider.Contains("Resource-Exhaustion", StringComparison.OrdinalIgnoreCase) || id == 2004) return "RESOURCE_EXHAUSTION";
        if (provider.Contains("Disk", StringComparison.OrdinalIgnoreCase) || provider.Contains("Ntfs", StringComparison.OrdinalIgnoreCase) ||
            provider.Contains("stor", StringComparison.OrdinalIgnoreCase) || provider.Contains("volmgr", StringComparison.OrdinalIgnoreCase))
            return "STORAGE_FAILURE";
        if (provider.Contains("Schannel", StringComparison.OrdinalIgnoreCase)) return "TLS_SCHANNEL_EVENT";
        if (provider.Contains("WindowsUpdateClient", StringComparison.OrdinalIgnoreCase)) return "WINDOWS_UPDATE_EVENT";
        if (provider.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase) || spec.Area == "Integridad de código") return "CODE_INTEGRITY_EVENT";
        if (provider.Contains("AppLocker", StringComparison.OrdinalIgnoreCase) || spec.Area.StartsWith("AppLocker", StringComparison.OrdinalIgnoreCase)) return "APPLOCKER_EVENT";
        if (provider.Contains("Diagnostics-Performance", StringComparison.OrdinalIgnoreCase) || spec.Area == "Rendimiento de Windows") return "WINDOWS_PERFORMANCE_EVENT";
        if (provider.Contains("DistributedCOM", StringComparison.OrdinalIgnoreCase)) return "DCOM_EVENT";
        if (provider.Contains("WMI", StringComparison.OrdinalIgnoreCase) || spec.Area == "WMI") return "WMI_EVENT";
        if (provider.Contains("PrintService", StringComparison.OrdinalIgnoreCase) || spec.Area == "Impresión") return "PRINT_FORENSIC_EVENT";
        if (spec.Layer == DiagnosticLayer.Rdp) return "RDP_FORENSIC_EVENT";
        if (spec.Layer == DiagnosticLayer.Red) return "NETWORK_FORENSIC_EVENT";
        if (spec.Layer == DiagnosticLayer.Seguridad) return "SECURITY_FORENSIC_EVENT";
        return "WINDOWS_FORENSIC_EVENT";
    }

    private static bool Relevant(ChannelSpec spec, string provider, int id)
    {
        if (spec.Log is not "System" and not "Application") return true;
        string[] providers = [
            "Service Control Manager", ".NET Runtime", "Application Error", "Windows Error Reporting", "Schannel",
            "Disk", "Ntfs", "stor", "volmgr", "Kernel-Power", "Tcpip", "DNS", "WMI", "DistributedCOM",
            "SideBySide", "User Profile Service", "GroupPolicy", "TerminalServices", "RemoteDesktop", "PrintService",
            "WindowsUpdateClient", "Resource-Exhaustion", "Application Hang"
        ];
        return providers.Any(p => provider.Contains(p, StringComparison.OrdinalIgnoreCase)) ||
               id is 41 or 51 or 55 or 1000 or 1001 or 1026 or 2004 or 7000 or 7001 or 7009 or 7011 or 7023 or 7024 or 7031 or 7034;
    }

    private static TsplusProduct ProductFromText(string text)
    {
        if (text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.ServerMonitoring;
        if (text.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase) || text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.AdvancedSecurity;
        if (text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase) || text.Contains("Remote Support", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteSupport;
        if (text.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || text.Contains("2FA", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.TwoFactorAuthentication;
        if (text.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || text.Contains("Application Publishing", StringComparison.OrdinalIgnoreCase) || text.Contains("APSC", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteAccess;
        return TsplusProduct.Ninguno;
    }
}
