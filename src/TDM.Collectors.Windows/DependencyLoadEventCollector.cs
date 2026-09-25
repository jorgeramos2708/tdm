using System.Diagnostics.Eventing.Reader;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Recolecta evidencia de dependencias/librerías que Windows no pudo cargar.
/// SOLO LECTURA: únicamente consulta el registro Application.
/// </summary>
public sealed class DependencyLoadEventCollector : IReadOnlyCollector
{
    public string Nombre => "Dependencias / DLL / SideBySide";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var timeClause = DiagnosticWindow.EventLogTimeClause(context);
        var xpath = $"*[System[{timeClause}]]";
        var inspectLimit = context.Lookback.TotalHours switch
        {
            <= 4 => 1_200,
            <= 12 => 2_400,
            <= 24 => 4_800,
            _ => 9_600
        };

        try
        {
            var query = new EventLogQuery("Application", PathType.LogName, xpath) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            var inspected = 0;

            for (EventRecord? record = reader.ReadEvent(); record is not null && inspected < inspectLimit; record = reader.ReadEvent())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using (record)
                {
                    inspected++;
                    var provider = record.ProviderName ?? "Desconocido";
                    var message = SafeDescription(record);
                    var signal = Classify(provider, record.Id, message);
                    if (signal is null) continue;

                    var touchesTsplus = TouchesTsplus(message, context.Sistema);
                    var layer = touchesTsplus ? DiagnosticLayer.Tsplus : DiagnosticLayer.Windows;
                    var severity = touchesTsplus ? DiagnosticSeverity.Error : DiagnosticSeverity.Informativo;
                    var timestamp = record.TimeCreated is null ? (DateTimeOffset?)null : new DateTimeOffset(record.TimeCreated.Value);
                    var dependency = ExtractDependency(message);

                    var evidence = new List<EvidenceItem>
                    {
                        new("Log", "Application"),
                        new("Provider", provider),
                        new("Event ID", record.Id.ToString()),
                        new("Relacionado explícitamente con TSplus", touchesTsplus ? "Sí" : "No")
                    };
                    if (!string.IsNullOrWhiteSpace(dependency)) evidence.Add(new("Dependencia detectada", dependency));
                    var dependencyOrigin = ClassifyDependencyOrigin(dependency, message, context.Sistema);
                    evidence.Add(new EvidenceItem("Clasificación de dependencia", dependencyOrigin));
                    evidence.Add(new EvidenceItem("Originador específico", SpecificDependencyName(dependency, dependencyOrigin)));
                    // X3: producto del ecosistema para el emparejamiento con crashes (U2). Sin
                    // producto seguiría Ninguno y el wildcard emparejaría con crash de otro producto.
                    // Solo productos complementarios explícitos salen de Ninguno/RemoteAccess, así que
                    // el pool tsplusErrors (RemoteAccess|Ninguno) conserva todos estos eventos.
                    var dependencyProduct = ClassifyDependencyProduct(message, touchesTsplus);

                    events.Add(new DiagnosticEvent(
                        timestamp,
                        provider,
                        dependency ?? provider,
                        layer,
                        severity,
                        signal,
                        message,
                        record.Id.ToString(),
                        Evidencia: evidence,
                        Producto: dependencyProduct));

                    if (touchesTsplus)
                    {
                        findings.Add(new DiagnosticFinding(
                            $"DEPENDENCY-{record.RecordId}",
                            dependency ?? provider,
                            DiagnosticSeverity.Error,
                            "Windows registró una falla de carga de dependencia relacionada explícitamente con TSplus.",
                            message,
                            evidence,
                            ConfidenceLevel.Alta,
                            Capa: DiagnosticLayer.Tsplus));
                    }
                }
            }
        }
        catch (EventLogNotFoundException) { }
        catch (UnauthorizedAccessException ex)
        {
            findings.Add(new DiagnosticFinding(
                "DEPENDENCY-EVENTLOG-ACCESS",
                "Application Event Log",
                DiagnosticSeverity.Advertencia,
                "No fue posible consultar eventos de carga de dependencias.",
                ex.Message,
                [new EvidenceItem("Log", "Application")],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Windows));
        }
        catch (EventLogException ex)
        {
            // Y1: lectura interrumpida a mitad de canal; lo ya leído se conserva y la
            // cobertura queda parcial en vez de perderse como COLLECTOR-ERROR.
            findings.Add(new DiagnosticFinding(
                "DEPENDENCY-EVENTLOG-READ",
                "Application Event Log",
                DiagnosticSeverity.Advertencia,
                "La lectura de eventos de carga de dependencias quedó parcial.",
                ex.Message,
                [new EvidenceItem("Log", "Application"), new EvidenceItem("Cobertura", "Parcial")],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Windows));
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static string? Classify(string provider, int eventId, string message)
    {
        if (provider.Contains("SideBySide", StringComparison.OrdinalIgnoreCase) && eventId is 33 or 35 or 59)
            return "SIDEBYSIDE_DEPENDENCY_FAILURE";

        if (ContainsAny(message,
            "FileNotFoundException",
            "Could not load file or assembly",
            "Could not load file",
            "The specified module could not be found",
            "El módulo especificado no se encuentra",
            "No se puede cargar el archivo o ensamblado",
            "no se pudo encontrar el archivo o ensamblado"))
            return "DEPENDENCY_NOT_FOUND";

        if (ContainsAny(message, "FileLoadException", "COR_E_FILELOAD", "0x80131621"))
            return "DEPENDENCY_LOAD_FAILURE";

        if (ContainsAny(message, "0xc0000135", "STATUS_DLL_NOT_FOUND"))
            return "DLL_NOT_FOUND";

        if (ContainsAny(message, "0xc000007b", "STATUS_INVALID_IMAGE_FORMAT"))
            return "INVALID_IMAGE_FORMAT";

        return null;
    }

    private static bool TouchesTsplus(string message, SystemSnapshot system)
    {
        if (!string.IsNullOrWhiteSpace(system.TsplusRuta) && message.Contains(system.TsplusRuta, StringComparison.OrdinalIgnoreCase))
            return true;

        string[] markers =
        [
            "tsplus", "\\wsession", "logonsession.exe", "alternateshell.exe",
            "removelastfolders.exe", "svcr.exe", "admintool", "application publishing"
        ];
        return markers.Any(x => message.Contains(x, StringComparison.OrdinalIgnoreCase));
    }

    private static string? ExtractDependency(string message)
    {
        string[] markers = ["Dependent Assembly ", "Could not load file or assembly '", "No se puede cargar el archivo o ensamblado '"];
        foreach (var marker in markers)
        {
            var i = message.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (i < 0) continue;
            var rest = message[(i + marker.Length)..];
            var end = rest.IndexOfAny(['\r','\n','\'','\"',',']);
            var value = (end > 0 ? rest[..end] : rest).Trim();
            if (!string.IsNullOrWhiteSpace(value)) return value;
        }
        return null;
    }


    private static TsplusProduct ClassifyDependencyProduct(string message, bool touchesTsplus)
    {
        if (!touchesTsplus) return TsplusProduct.Ninguno;
        if (message.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.ServerMonitoring;
        if (message.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase) || message.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.AdvancedSecurity;
        if (message.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase) || message.Contains("Remote Support", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteSupport;
        if (message.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || message.Contains("2FA", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.TwoFactorAuthentication;
        return TsplusProduct.RemoteAccess;
    }

    private static string ClassifyDependencyOrigin(string? dependency, string message, SystemSnapshot system)
    {
        var text = $"{dependency} {message}";
        if (!string.IsNullOrWhiteSpace(system.TsplusRuta) && text.Contains(system.TsplusRuta, StringComparison.OrdinalIgnoreCase)) return "TSPLUS";
        if (ContainsAny(text, "TSplus", "ServerMonitoring", "RemoteSupport", "logonsession", "APSC")) return "TSPLUS";
        if (ContainsAny(text, "Microsoft.", "System.", "Windows.", "mscorlib", "KERNELBASE.dll", "ntdll.dll", "kernel32.dll")) return "WINDOWS";
        // Un nombre de ensamblado/DLL desconocido no basta para atribuirlo a un tercero:
        // puede ser una dependencia empaquetada por TSplus o por la propia aplicación.
        // Sólo los collectors que resuelven ruta/metadata/proveedor elevan EXTERNO.
        return "INDETERMINADO";
    }

    private static string SpecificDependencyName(string? dependency, string origin)
    {
        if (string.IsNullOrWhiteSpace(dependency)) return origin switch
        {
            "WINDOWS" => "Windows / dependencia del sistema",
            "TSPLUS" => "TSplus / dependencia interna",
            "EXTERNO" => "Dependencia externa no identificada",
            _ => "Dependencia no identificada"
        };
        var value = dependency.Trim();
        try
        {
            var file = Path.GetFileName(value);
            if (!string.IsNullOrWhiteSpace(file)) value = file;
        }
        catch { }
        return origin switch
        {
            "WINDOWS" => $"Windows / {value}",
            "TSPLUS" => $"TSplus / {value}",
            "EXTERNO" => $"Dependencia externa: {value}",
            _ => value
        };
    }

    private static bool ContainsAny(string value, params string[] terms) =>
        terms.Any(t => value.Contains(t, StringComparison.OrdinalIgnoreCase));

    private static string SafeDescription(EventRecord record)
    {
        try { return record.FormatDescription() ?? "Descripción no disponible."; }
        catch { return "Descripción no disponible."; }
    }

}
