using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Lee eventos de crash de Application Error, Windows Error Reporting y .NET Runtime.
/// SOLO LECTURA: no habilita dumps, no modifica WER y no cambia el Registro.
/// </summary>
public sealed class CrashEventCollector : IReadOnlyCollector
{
    public string Nombre => "Crashes de procesos / WER";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var window = DiagnosticWindow.Resolve(context);
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);
        var xpath = $"*[System[(EventID=1000 or EventID=1001 or EventID=1026) and {timeClause}]]";
        var max = ResolveLimit(context.Lookback);
        var observed = 0;
        var readable = true;
        // S7: count solo avanza con proveedores de crash; sin cota de examinados, miles de
        // 1000/1001/1026 ajenos se iteran hasta el timeout del motor. scanLimit lo acota.
        var scanned = 0;
        var scanLimit = Math.Max(max * 20, 5_000);
        var scanTruncated = false;

        try
        {
            var query = new EventLogQuery("Application", PathType.LogName, xpath) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            var count = 0;

            for (EventRecord? record = reader.ReadEvent(); record is not null && count < max; record = reader.ReadEvent())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (++scanned > scanLimit) { scanTruncated = true; break; }
                using (record)
                {
                    var provider = record.ProviderName ?? "Desconocido";
                    if (!IsCrashProvider(provider, record.Id)) continue;

                    var data = ParseEventData(record);
                    var message = SafeDescription(record);
                    var timestamp = record.TimeCreated is null ? (DateTimeOffset?)null : new DateTimeOffset(record.TimeCreated.Value);
                    var parsed = ParseCrash(provider, record.Id, data, message);
                    var product = ClassifyProduct(parsed, context.Sistema);
                    var touchesTsplus = product != TsplusProduct.Ninguno;
                    var layer = touchesTsplus ? DiagnosticLayer.Tsplus : DiagnosticLayer.Windows;
                    // WER 1001 es muy ruidoso (LiveKernelEvent, instaladores, apps ajenas).
                    // Si no toca TSplus explícitamente, se conserva como evidencia informativa
                    // y queda fuera del timeline de advertencias/errores/críticos.
                    var severity = record.Id == 1001 && !touchesTsplus
                        ? DiagnosticSeverity.Informativo
                        : record.Level == 1
                            ? DiagnosticSeverity.Critico
                            : DiagnosticSeverity.Error;

                    var applicationName = SanitizeUiName(parsed.ApplicationName);
                    var applicationLabel = string.IsNullOrWhiteSpace(applicationName) ? provider : applicationName;

                    var evidence = new List<EvidenceItem>
                    {
                        new("Log", "Application"),
                        new("EventId", record.Id.ToString()),
                        new("Provider", provider),
                        new("RecordId", record.RecordId?.ToString() ?? "N/D"),
                        new("Fecha", record.TimeCreated?.ToString("O") ?? "N/D")
                    };
                    Add(evidence, "Aplicación", applicationLabel);
                    Add(evidence, "Ruta de aplicación", parsed.ApplicationPath);
                    Add(evidence, "Módulo con error", parsed.FaultingModuleName);
                    Add(evidence, "Ruta del módulo", parsed.FaultingModulePath);
                    Add(evidence, "Código de excepción", parsed.ExceptionCode);
                    Add(evidence, "Tipo de excepción .NET", parsed.DotNetExceptionType);
                    Add(evidence, "Stack trace disponible", parsed.StackFrames.Count > 0 ? "Sí" : "No");
                    Add(evidence, "Primer frame no framework", parsed.FirstNonFrameworkFrame);
                    Add(evidence, "Componente interno observado", parsed.InternalComponent);
                    if (parsed.StackFrames.Count > 0)
                        Add(evidence, "Stack .NET resumido", string.Join(" | ", parsed.StackFrames.Take(8)));
                    Add(evidence, "Report ID", parsed.ReportId);
                    evidence.Add(new EvidenceItem("Relacionado explícitamente con TSplus", touchesTsplus ? "Sí" : "No"));

                    var type = record.Id switch
                    {
                        1000 => "APPLICATION_CRASH",
                        1001 => "WER_REPORT",
                        1026 => "DOTNET_UNHANDLED_EXCEPTION",
                        _ => "PROCESS_CRASH_EVIDENCE"
                    };

                    events.Add(new DiagnosticEvent(
                        timestamp,
                        provider,
                        applicationLabel,
                        layer,
                        severity,
                        type,
                        message,
                        parsed.ExceptionCode ?? record.Id.ToString(),
                        parsed.ApplicationPath,
                        Evidencia: evidence,
                        Producto: product));

                    // Un crash ajeno a TSplus se conserva como evidencia, pero no genera un hallazgo de TSplus.
                    if (touchesTsplus)
                    {
                        findings.Add(new DiagnosticFinding(
                            $"CRASH-{record.RecordId}",
                            applicationName ?? "Proceso TSplus",
                            severity,
                            record.Id == 1026
                                ? "Se detectó una excepción .NET no controlada relacionada explícitamente con TSplus."
                                : "Se detectó un crash de proceso relacionado explícitamente con TSplus.",
                            BuildFindingDetail(parsed, message),
                            evidence,
                            ConfidenceLevel.Alta,
                            Capa: DiagnosticLayer.Tsplus));
                    }

                    count++;
                }
            }
            observed = count;
        }
        catch (EventLogNotFoundException) { readable = false; }
        catch (UnauthorizedAccessException ex)
        {
            readable = false;
            findings.Add(new DiagnosticFinding(
                "CRASH-EVENTLOG-ACCESS",
                "Application Event Log",
                DiagnosticSeverity.Advertencia,
                "No fue posible leer evidencia de Application Error / WER.",
                ex.Message,
                [new EvidenceItem("Log", "Application")],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Windows));
        }
        catch (EventLogException ex)
        {
            readable = false;
            findings.Add(new DiagnosticFinding(
                "CRASH-EVENTLOG-READ",
                "Application Event Log",
                DiagnosticSeverity.Advertencia,
                "La fuente Application/WER no pudo leerse por completo.",
                ex.Message,
                [new EvidenceItem("Log", "Application"), new EvidenceItem("Cobertura", "No disponible")],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Windows));
        }

        var limited = observed >= max || scanTruncated;
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Cobertura de crashes / WER", DiagnosticLayer.Windows,
            !readable || limited ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "CRASH_EVENT_COVERAGE",
            !readable ? "La fuente Application/WER no estuvo disponible por completo."
                : limited ? "La lectura de crashes alcanzó el límite adaptativo y la cobertura se considera parcial."
                : "La lectura de crashes/WER completó la ventana solicitada dentro del límite de seguridad.",
            Evidencia:
            [
                new EvidenceItem("Ventana solicitada", $"{window.Start:O} → {window.End:O}"),
                new EvidenceItem("Eventos observados", observed.ToString()),
                new EvidenceItem("Registros examinados", scanned.ToString()),
                new EvidenceItem("Límite adaptativo", max.ToString()),
                new EvidenceItem("Cobertura", !readable ? "No disponible" : limited ? "Parcial" : "Disponible")
            ]));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static int ResolveLimit(TimeSpan lookback)
        => lookback.TotalHours switch
        {
            <= 4 => 300,
            <= 12 => 600,
            <= 24 => 1_200,
            _ => 2_400
        };

    private static bool IsCrashProvider(string provider, int id) =>
        (id == 1000 && provider.Contains("Application Error", StringComparison.OrdinalIgnoreCase)) ||
        (id == 1001 && provider.Contains("Windows Error Reporting", StringComparison.OrdinalIgnoreCase)) ||
        (id == 1026 && provider.Contains(".NET Runtime", StringComparison.OrdinalIgnoreCase));

    private static string SafeDescription(EventRecord record)
    {
        try { return record.FormatDescription() ?? "Descripción no disponible."; }
        catch { return "Descripción no disponible; los campos estructurados del evento se conservaron cuando fue posible."; }
    }

    private static Dictionary<string, string> ParseEventData(EventRecord record)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var doc = XDocument.Parse(record.ToXml());
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            var data = doc.Descendants(ns + "EventData").Elements(ns + "Data").ToList();
            for (var i = 0; i < data.Count; i++)
            {
                var name = data[i].Attribute("Name")?.Value;
                var value = data[i].Value;
                if (!string.IsNullOrWhiteSpace(name)) result[name] = value;
                result[$"param{i + 1}"] = value;
            }
        }
        catch { }
        return result;
    }

    private static CrashData ParseCrash(string provider, int eventId, IReadOnlyDictionary<string, string> data, string message)
    {
        string? Get(params string[] keys)
        {
            foreach (var key in keys)
                if (data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value)) return value.Trim();
            return null;
        }

        if (eventId == 1000)
        {
            return new CrashData(
                Get("AppName", "FaultingApplicationName", "param1"),
                Get("AppPath", "FaultingApplicationPath", "param11"),
                Get("ModuleName", "FaultingModuleName", "param4"),
                Get("ModulePath", "FaultingModulePath", "param12"),
                Get("ExceptionCode", "param7"),
                null,
                Get("ReportId", "param13"),
                [], null, null);
        }

        if (eventId == 1001)
        {
            return new CrashData(
                Get("AppName", "ApplicationName", "param1"),
                Get("AppPath", "ApplicationPath"),
                Get("FaultingModuleName", "ModuleName"),
                Get("FaultingModulePath", "ModulePath"),
                Get("ExceptionCode"),
                null,
                Get("ReportId", "ReportIdValue"),
                [], null, null);
        }

        // .NET Runtime 1026 no siempre expone EventData con nombres estables; usamos mensaje como evidencia primaria.
        var app = ExtractAfter(message, "Application:") ?? ExtractAfter(message, "Aplicación:");
        var exception = ExtractExceptionType(message);
        var frames = ExtractStackFrames(message);
        var firstNonFramework = frames.FirstOrDefault(IsNonFrameworkFrame);
        var internalComponent = ExtractInternalComponent(firstNonFramework);
        return new CrashData(app, null, null, null, null, exception, null, frames, firstNonFramework, internalComponent);
    }

    private static TsplusProduct ClassifyProduct(CrashData crash, SystemSnapshot system)
    {
        var joined = string.Join(" ", new[]
        {
            crash.ApplicationName, crash.ApplicationPath, crash.FaultingModuleName,
            crash.FaultingModulePath, crash.DotNetExceptionType
        }.Where(x => !string.IsNullOrWhiteSpace(x)));

        if (joined.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase) ||
            joined.Contains("TSplus-ServerMonitoring", StringComparison.OrdinalIgnoreCase))
            return TsplusProduct.ServerMonitoring;
        if (joined.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase) ||
            joined.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase))
            return TsplusProduct.AdvancedSecurity;
        if (joined.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase) ||
            joined.Contains("Remote Support", StringComparison.OrdinalIgnoreCase))
            return TsplusProduct.RemoteSupport;
        if (joined.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || joined.Contains("2FA", StringComparison.OrdinalIgnoreCase))
            return TsplusProduct.TwoFactorAuthentication;
        if (!string.IsNullOrWhiteSpace(system.TsplusRuta) && joined.Contains(system.TsplusRuta, StringComparison.OrdinalIgnoreCase))
            return TsplusProduct.RemoteAccess;
        string[] markers = ["tsplus", "wsession", "logonsession", "alternateshell", "svcr.exe", "adminTool", "gateway", "html5"];
        return markers.Any(x => joined.Contains(x, StringComparison.OrdinalIgnoreCase)) ? TsplusProduct.RemoteAccess : TsplusProduct.Ninguno;
    }

    private static string BuildFindingDetail(CrashData crash, string fallback)
    {
        var parts = new List<string>();
        var applicationName = SanitizeUiName(crash.ApplicationName);
        if (!string.IsNullOrWhiteSpace(applicationName)) parts.Add($"Aplicación: {applicationName}");
        if (!string.IsNullOrWhiteSpace(crash.FaultingModuleName)) parts.Add($"Módulo con error: {crash.FaultingModuleName}");
        if (!string.IsNullOrWhiteSpace(crash.ExceptionCode)) parts.Add($"Código de excepción: {crash.ExceptionCode}");
        if (!string.IsNullOrWhiteSpace(crash.DotNetExceptionType)) parts.Add($"Excepción .NET: {crash.DotNetExceptionType}");
        if (!string.IsNullOrWhiteSpace(crash.InternalComponent)) parts.Add($"Componente interno observado: {crash.InternalComponent}");
        return parts.Count > 0 ? string.Join("; ", parts) : fallback;
    }

    private static string SanitizeUiName(string? value)
        => TdmVisibleText.Sanitize(value);

    private static IReadOnlyList<string> ExtractStackFrames(string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return [];
        var frames = new List<string>();
        foreach (var raw in message.Replace("\r", string.Empty).Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith("at ", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("en ", StringComparison.OrdinalIgnoreCase) ||
                line.Contains(".MoveNext()", StringComparison.OrdinalIgnoreCase))
            {
                frames.Add(line);
                if (frames.Count >= 16) break;
            }
        }
        return frames;
    }

    private static bool IsNonFrameworkFrame(string frame)
    {
        string[] framework = [
            "System.", "Microsoft.", "mscorlib", "Windows.", "PresentationFramework",
            "PresentationCore", "Newtonsoft.", "Serilog.", "NLog."
        ];
        var normalized = frame.TrimStart();
        if (normalized.StartsWith("at ", StringComparison.OrdinalIgnoreCase)) normalized = normalized[3..].TrimStart();
        else if (normalized.StartsWith("en ", StringComparison.OrdinalIgnoreCase)) normalized = normalized[3..].TrimStart();
        return !framework.Any(x => normalized.StartsWith(x, StringComparison.OrdinalIgnoreCase));
    }

    private static string? ExtractInternalComponent(string? frame)
    {
        if (string.IsNullOrWhiteSpace(frame)) return null;
        var value = frame.Trim();
        if (value.StartsWith("at ", StringComparison.OrdinalIgnoreCase)) value = value[3..].TrimStart();
        else if (value.StartsWith("en ", StringComparison.OrdinalIgnoreCase)) value = value[3..].TrimStart();
        var paren = value.IndexOf('(');
        if (paren > 0) value = value[..paren];
        return value;
    }

    private static string? ExtractAfter(string text, string marker)
    {
        var index = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (index < 0) return null;
        var rest = text[(index + marker.Length)..].TrimStart();
        var end = rest.IndexOfAny(['\r', '\n']);
        return (end >= 0 ? rest[..end] : rest).Trim();
    }

    private static string? ExtractExceptionType(string text)
    {
        string[] markers = ["Exception Info:", "Información de la excepción:", "Exception information:"];
        foreach (var marker in markers)
        {
            var index = text.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (index < 0) continue;
            var rest = text[(index + marker.Length)..].TrimStart();
            var end = rest.IndexOfAny(['\r', '\n']);
            var line = (end >= 0 ? rest[..end] : rest).Trim();
            if (line.Length > 0) return line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
        }
        return null;
    }

    private static void Add(List<EvidenceItem> evidence, string key, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) evidence.Add(new EvidenceItem(key, value));
    }

    private sealed record CrashData(
        string? ApplicationName,
        string? ApplicationPath,
        string? FaultingModuleName,
        string? FaultingModulePath,
        string? ExceptionCode,
        string? DotNetExceptionType,
        string? ReportId,
        IReadOnlyList<string> StackFrames,
        string? FirstNonFrameworkFrame,
        string? InternalComponent);
}
