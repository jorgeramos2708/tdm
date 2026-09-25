using System.Text;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

public sealed class TsplusLogCollector : IReadOnlyCollector
{
    public string Nombre => "Logs TSplus";
    private const int DefaultmaxFilesPerDirectory = 400;
    private const int DefaultmaxBytesPerFile = 64 * 1024 * 1024;
    private const long DefaultmaxTotalBytes = 256L * 1024 * 1024;
    private const int DefaultmaxEvents = 5000;

    public async Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var opts = context.Options ?? new DiagnosticOptions();
        var maxFilesPerDirectory = opts.MaxFilesPerDirectory ?? DefaultmaxFilesPerDirectory;
        var maxBytesPerFile = opts.MaxBytesPerFile ?? DefaultmaxBytesPerFile;
        var maxTotalBytes = opts.MaxTotalBytes ?? DefaultmaxTotalBytes;
        var maxEvents = opts.MaxEvents ?? DefaultmaxEvents;
    var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var directoryEnumerationErrors = 0;
        var directoryEnumerationTruncations = 0;
        var eventLimitReached = false;
        var byteLimitReached = false;
        var truncatedLogFiles = 0;
        var skippedOlderFiles = 0;
        long logBytesRead = 0;
        var windowEnd = context.HoraIncidente ?? DateTimeOffset.Now;
        var windowStart = windowEnd - context.Lookback;
        var discovery = TsplusLogDiscovery.DiscoverDetailed(context.Sistema.TsplusRuta);
        var sources = discovery.Sources;

        var remoteAccessSources = sources.Where(s => s.Producto == TsplusProduct.RemoteAccess).ToList();
        var availableRemoteAccess = remoteAccessSources.Count(s => s.Existe);
        var knownRemoteAccess = remoteAccessSources.Count;
        var coverage = knownRemoteAccess == 0 ? 0 : (int)Math.Round(availableRemoteAccess * 100d / knownRemoteAccess);

        var discoveryPartial = discovery.DiscoveryErrors > 0 || discovery.DiscoveryTruncated || discovery.UserProfilesTruncated;
        var coverageEvidence = new List<EvidenceItem>
        {
            new("Cobertura", discoveryPartial ? "Parcial" : "Disponible"),
            new("Fuentes Remote Access conocidas/detectadas", knownRemoteAccess.ToString()),
            new("Fuentes Remote Access disponibles", availableRemoteAccess.ToString()),
            new("Directorios dinámicos visitados", discovery.DynamicDirectoriesVisited.ToString()),
            new("Directorios de logs descubiertos", discovery.DynamicDirectoriesAdded.ToString()),
            new("Errores de descubrimiento", discovery.DiscoveryErrors.ToString()),
            new("Descubrimiento truncado", discovery.DiscoveryTruncated ? "Sí" : "No"),
            new("Perfiles de usuario truncados", discovery.UserProfilesTruncated ? "Sí; límite 200" : "No"),
            new("Ventana solicitada", $"{windowStart:O} → {windowEnd:O}"),
            new("Máximo por archivo", $"{maxBytesPerFile / 1024 / 1024} MiB"),
            new("Presupuesto total de lectura", $"{maxTotalBytes / 1024 / 1024} MiB")
        };
        coverageEvidence.AddRange(remoteAccessSources.Select(s => new EvidenceItem($"Fuente · {s.Componente}", s.Existe ? s.Ruta : "No disponible / no habilitado")));
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Cobertura de logs TSplus Remote Access",
            DiagnosticLayer.Tsplus,
            discoveryPartial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "TSPLUS_LOG_COVERAGE",
            $"Fuentes opcionales de diagnóstico Remote Access disponibles: {availableRemoteAccess}/{knownRemoteAccess} ({coverage}%). La ausencia de logs no se interpreta como falla porque TSplus puede tenerlos deshabilitados. El descubrimiento dinámico queda {(discoveryPartial ? "PARCIAL" : "DISPONIBLE")}.",
            Evidencia: coverageEvidence));

        var securitySource = sources.FirstOrDefault(s => s.Producto == TsplusProduct.AdvancedSecurity);
        if (securitySource is { Existe: true })
        {
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "TDM", "TSplus Advanced Security", DiagnosticLayer.Seguridad,
                DiagnosticSeverity.Informativo, "TSPLUS_SECURITY_LOGS_PRESENT",
                "Se detectaron logs de TSplus Advanced Security. Esto no implica que TSplus Remote Access esté instalado.",
                Archivo: securitySource.Ruta));
        }

        if (!context.Sistema.TsplusDetectado && !sources.Any(s => s.Existe))
            return new CollectorResult(findings, events);

        var processedFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var source in sources.Where(s => s.Existe))
        {
            cancellationToken.ThrowIfCancellationRequested();
            IEnumerable<string> files;
            if (source.EsDirectorio)
            {
                var enumeration = EnumerateLogFilesDetailed(source.Ruta, windowStart.UtcDateTime, maxFilesPerDirectory);
                files = enumeration.Files;
                directoryEnumerationErrors += enumeration.Errors;
                skippedOlderFiles += enumeration.SkippedOlder;
                if (enumeration.Truncated)
                {
                    directoryEnumerationTruncations++;
                    coverageEvidence.Add(new EvidenceItem($"Lectura · {source.Componente}", $"Parcial: directorios={enumeration.DirectoriesVisited}; archivos examinados={enumeration.FilesExamined}; límite de seguridad alcanzado"));
                }
                else if (enumeration.Errors > 0)
                {
                    coverageEvidence.Add(new EvidenceItem($"Lectura · {source.Componente}", $"Parcial: errores de enumeración={enumeration.Errors}"));
                }
            }
            else files = [source.Ruta];

            var layer = source.Capa;
            var sourceName = source.Producto == TsplusProduct.AdvancedSecurity ? "TSplus Security Log" : "TSplus Log";

            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string canonical;
                try { canonical = Path.GetFullPath(file); }
                catch { canonical = file; }
                if (!processedFiles.Add(canonical)) continue;
                if (SafeLastWriteTimeUtc(file) < windowStart.UtcDateTime)
                {
                    skippedOlderFiles++;
                    continue;
                }
                var remainingBytes = maxTotalBytes - logBytesRead;
                if (remainingBytes <= 0)
                {
                    byteLimitReached = true;
                    break;
                }
                var component = source.Producto == TsplusProduct.AdvancedSecurity
                    ? ResolveAdvancedSecurityComponent(file, source.Componente)
                    : source.Componente;
                var readBudget = (int)Math.Min(maxBytesPerFile, remainingBytes);
                var parsed = await ReadAndParseAsync(component, file, context, layer, sourceName, source.Producto, readBudget, maxEvents, cancellationToken);
                events.AddRange(parsed.Events);
                logBytesRead += parsed.BytesRead;
                if (parsed.Truncated) truncatedLogFiles++;
                if (events.Count >= maxEvents) { eventLimitReached = true; break; }
            }

            if (events.Count >= maxEvents) { eventLimitReached = true; break; }
            if (byteLimitReached) break;
        }

        var logReadFailures = events.Count(e => e.Tipo is "LOG_ACCESS_DENIED" or "LOG_READ_ERROR");
        var runtimeCoveragePartial = discoveryPartial || directoryEnumerationErrors > 0 || directoryEnumerationTruncations > 0
            || eventLimitReached || byteLimitReached || truncatedLogFiles > 0 || logReadFailures > 0;
        coverageEvidence[0] = new EvidenceItem("Cobertura", runtimeCoveragePartial ? "Parcial" : "Disponible");
        coverageEvidence.Add(new EvidenceItem("Errores al enumerar directorios de logs", directoryEnumerationErrors.ToString()));
        coverageEvidence.Add(new EvidenceItem("Directorios con lectura truncada", directoryEnumerationTruncations.ToString()));
        coverageEvidence.Add(new EvidenceItem("Errores de lectura de archivos", logReadFailures.ToString()));
        coverageEvidence.Add(new EvidenceItem("Eventos truncados por límite", eventLimitReached ? $"Sí; límite={maxEvents}" : "No"));
        coverageEvidence.Add(new EvidenceItem("Archivos fuera de ventana omitidos", skippedOlderFiles.ToString()));
        coverageEvidence.Add(new EvidenceItem("Archivos leídos parcialmente", truncatedLogFiles.ToString()));
        coverageEvidence.Add(new EvidenceItem("Bytes leídos", logBytesRead.ToString()));
        coverageEvidence.Add(new EvidenceItem("Presupuesto de bytes agotado", byteLimitReached ? "Sí" : "No"));
        events[0] = new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Cobertura de logs TSplus Remote Access",
            DiagnosticLayer.Tsplus,
            runtimeCoveragePartial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "TSPLUS_LOG_COVERAGE",
            $"Fuentes opcionales de diagnóstico Remote Access disponibles: {availableRemoteAccess}/{knownRemoteAccess} ({coverage}%). La ausencia de logs no se interpreta como falla. Cobertura efectiva: {(runtimeCoveragePartial ? "PARCIAL" : "DISPONIBLE")}.",
            Evidencia: coverageEvidence);

        // Solo eventos con fecha demostrable pueden convertirse en hallazgos de una ventana temporal.
        // Los eventos sin timestamp se conservan como evidencia no correlacionada, pero no como causa del incidente.
        foreach (var group in events
            .Where(e => (e.Fuente == "TSplus Log" || e.Fuente == "TSplus Security Log")
                     && e.Severidad != DiagnosticSeverity.Informativo
                     && e.Timestamp.HasValue)
            .GroupBy(e => new { e.Componente, e.Tipo, e.Severidad, e.Capa }))
        {
            var sample = group.OrderByDescending(e => e.Timestamp).First();
            findings.Add(new DiagnosticFinding(
                $"TSLOG-{SanitizeId(group.Key.Componente)}-{group.Key.Tipo}",
                group.Key.Componente,
                group.Key.Severidad,
                $"Se detectaron {group.Count()} eventos '{group.Key.Tipo}' dentro de la ventana temporal analizada.",
                sample.Mensaje,
                [
                    new EvidenceItem("Tipo", group.Key.Tipo),
                    new EvidenceItem("Cantidad", group.Count().ToString()),
                    new EvidenceItem("Último registro", sample.Timestamp?.ToString("O") ?? "N/D"),
                    new EvidenceItem("Timestamp del log", "Disponible; usado para correlación temporal"),
                    new EvidenceItem("Archivo", sample.Archivo ?? "N/D")
                ],
                group.Count() >= 3 ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                Capa: group.Key.Capa));
        }

        var undated = events.Count(e => (e.Fuente == "TSplus Log" || e.Fuente == "TSplus Security Log")
                                     && e.Severidad != DiagnosticSeverity.Informativo
                                     && !e.Timestamp.HasValue);
        if (undated > 0)
        {
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "TDM", "Correlación temporal", DiagnosticLayer.Desconocida,
                DiagnosticSeverity.Informativo, "UNDATED_LOG_EVIDENCE",
                $"Se encontraron {undated} líneas potencialmente relevantes sin timestamp reconocible. Se conservaron con hora de ingestión y se marcan explícitamente como tiempo del evento no determinado."));
        }

        return new CollectorResult(findings, events.Take(maxEvents).ToList());
    }

    private sealed record LogEnumerationResult(IReadOnlyList<string> Files, int DirectoriesVisited, int FilesExamined, int Errors, int SkippedOlder, bool Truncated);
    private sealed record LogReadResult(IReadOnlyList<DiagnosticEvent> Events, long BytesRead, bool Truncated);

    private static LogEnumerationResult EnumerateLogFilesDetailed(string directory, DateTime windowStartUtc, int maxFilesPerDirectory)
    {
        // Lectura recursiva acotada. Si el límite se alcanza, la cobertura se declara Parcial;
        // TDM nunca presenta la ausencia de eventos fuera del límite como evidencia de salud.
        const int maxDepth = 3;
        const int maxDirectories = 256;
        const int maxFilesExamined = 5000;
        var candidates = new List<string>();
        var pending = new Queue<(string Path, int Depth)>();
        pending.Enqueue((directory, 0));
        var dirs = 0;
        var files = 0;
        var errors = 0;
        var skippedOlder = 0;
        var truncated = false;

        while (pending.Count > 0 && dirs < maxDirectories && files < maxFilesExamined)
        {
            var current = pending.Dequeue();
            dirs++;
            try
            {
                foreach (var file in Directory.EnumerateFiles(current.Path, "*", SearchOption.TopDirectoryOnly))
                {
                    files++;
                    if (IsLikelyLogFile(file))
                    {
                        if (SafeLastWriteTimeUtc(file) >= windowStartUtc) candidates.Add(file);
                        else skippedOlder++;
                    }
                    if (files >= maxFilesExamined) { truncated = true; break; }
                }

                if (current.Depth >= maxDepth) continue;
                foreach (var child in Directory.EnumerateDirectories(current.Path, "*", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0) continue;
                    }
                    catch { errors++; continue; }
                    pending.Enqueue((child, current.Depth + 1));
                    if (pending.Count + dirs >= maxDirectories) { truncated = true; break; }
                }
            }
            catch { errors++; }
        }

        if (pending.Count > 0 || dirs >= maxDirectories || files >= maxFilesExamined) truncated = true;
        var distinct = candidates
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(SafeLastWriteTimeUtc)
            .ToList();
        if (distinct.Count > maxFilesPerDirectory) truncated = true;
        return new LogEnumerationResult(distinct.Take(maxFilesPerDirectory).ToArray(), dirs, files, errors, skippedOlder, truncated);
    }

    private static DateTime SafeLastWriteTimeUtc(string path)
    {
        try { return File.GetLastWriteTimeUtc(path); }
        catch { return DateTime.MinValue; }
    }

    private static bool IsLikelyLogFile(string path)
    {
        var ext = Path.GetExtension(path);
        return string.IsNullOrEmpty(ext)
            || ext.Equals(".log", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".txt", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".trace", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<LogReadResult> ReadAndParseAsync(
        string component,
        string path,
        DiagnosticContext context,
        DiagnosticLayer layer,
        string sourceName,
        TsplusProduct product,
        int maxBytes,
        int maxEvents,
        CancellationToken ct)
    {
        var result = new List<DiagnosticEvent>();
        long bytesRead = 0;
        var wasTruncated = false;
        try
        {
            await using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 4096,
                FileOptions.Asynchronous | FileOptions.SequentialScan);

            var truncated = stream.Length > maxBytes;
            wasTruncated = truncated;
            var bytesToRead = Math.Min(stream.Length, maxBytes);
            bytesRead = bytesToRead;
            if (truncated) stream.Seek(-maxBytes, SeekOrigin.End);

            using var reader = new StreamReader(stream, new UTF8Encoding(false, false), true, 4096, leaveOpen: false);
            if (truncated)
            {
                // El seek puede caer a mitad de una línea; ese fragmento no es evidencia íntegra.
                _ = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                result.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", component, layer, DiagnosticSeverity.Advertencia,
                    "TSPLUS_LOG_FILE_TRUNCATED",
                    $"El archivo excede el presupuesto de {maxBytes / 1024 / 1024} MiB para esta lectura; se analizó únicamente el tail y se descartó el primer fragmento parcial.",
                    Archivo: path,
                    Evidencia: [new EvidenceItem("Cobertura", "Parcial"), new EvidenceItem("Tail bytes", maxBytes.ToString())],
                    Producto: product));
            }
            int lineNumber = 0;
            DiagnosticEvent? current = null;
            while (!reader.EndOfStream && result.Count < maxEvents)
            {
                ct.ThrowIfCancellationRequested();
                var line = await reader.ReadLineAsync(ct);
                lineNumber++;
                if (line is null) continue;
                var parsed = TsplusLogParser.ParseLine(component, path, line, lineNumber, context, layer, sourceName, product);
                if (parsed is not null)
                {
                    if (current is not null) result.Add(current);
                    if (truncated)
                    {
                        var evidence = (parsed.Evidencia ?? []).Concat([new EvidenceItem("Línea", $"relativa al tail: {lineNumber}")]).ToList();
                        parsed = parsed with { Evidencia = evidence };
                    }
                    current = parsed;
                    if (product == TsplusProduct.RemoteAccess &&
                        (parsed.Tipo is "CONNECTION_CLIENT" or "APPLICATION_PUBLISHING" or "OPERATION_FAILED" or "SESSION") &&
                        HasNonAscii(line) && result.Count < maxEvents - 1)
                    {
                        result.Add(new DiagnosticEvent(
                            parsed.Timestamp,
                            sourceName,
                            "RemoteApp / contexto Unicode",
                            layer,
                            DiagnosticSeverity.Informativo,
                            "REMOTEAPP_NONASCII_LOG_CONTEXT",
                            "Un evento operativo de Remote Access contiene caracteres no ASCII. Se conserva como contexto de compatibilidad de codificación; no constituye una falla por sí solo.",
                            Archivo: path,
                            Linea: lineNumber,
                            Evidencia:
                            [
                                new EvidenceItem("Evento asociado", parsed.Tipo),
                                new EvidenceItem("Componente asociado", parsed.Componente),
                                new EvidenceItem("Caracteres no ASCII", "Sí"),
                                new EvidenceItem("Nota", "TDM no atribuye causalidad Unicode sin evidencia adicional de startup.config/Connection Client")
                            ],
                            Producto: TsplusProduct.RemoteAccess));
                    }
                    continue;
                }

                if (current is not null && TsplusLogParser.IsContinuationLine(line))
                    current = current with { Mensaje = current.Mensaje + Environment.NewLine + line.TrimEnd() };
            }
            if (current is not null && result.Count < maxEvents) result.Add(current);
        }
        catch (UnauthorizedAccessException ex)
        {
            result.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "TDM", component, layer,
                DiagnosticSeverity.Advertencia, "LOG_ACCESS_DENIED",
                "No fue posible leer el log por permisos insuficientes.",
                Archivo: path,
                Evidencia: [new EvidenceItem("Error", ex.Message)],
                Producto: product));
        }
        catch (IOException ex)
        {
            result.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "TDM", component, layer,
                DiagnosticSeverity.Advertencia, "LOG_READ_ERROR",
                "No fue posible completar la lectura del log.",
                Archivo: path,
                Evidencia: [new EvidenceItem("Error", ex.Message)],
                Producto: product));
        }

        return new LogReadResult(result, bytesRead, wasTruncated);
    }


    private static string ResolveAdvancedSecurityComponent(string filePath, string fallback)
    {
        var name = Path.GetFileName(filePath);
        if (ContainsAny(name, "ransom", "quarantine", "snapshot")) return "Advanced Security / Ransomware Protection";
        if (ContainsAny(name, "brute", "defender")) return "Advanced Security / Bruteforce Protection";
        if (ContainsAny(name, "geographic", "geography", "homeland", "geo")) return "Advanced Security / Geographic Protection";
        if (ContainsAny(name, "firewall")) return "Advanced Security / Firewall";
        if (ContainsAny(name, "working", "hours")) return "Advanced Security / Restrict Working Hours";
        if (ContainsAny(name, "endpoint", "trusted")) return "Advanced Security / Trusted Devices / Endpoint Protection";
        if (ContainsAny(name, "permission")) return "Advanced Security / Permissions";
        if (ContainsAny(name, "secure", "session")) return "Advanced Security / Secure Sessions";
        if (ContainsAny(name, "hacker", "blacklist", "blocked")) return "Advanced Security / Hacker IP Protection";
        if (ContainsAny(name, "alert")) return "Advanced Security / Alerts";
        if (ContainsAny(name, "report")) return "Advanced Security / Reports";
        if (ContainsAny(name, "service")) return "Advanced Security / Service";
        if (ContainsAny(name, "application", "app")) return "Advanced Security / Application";
        return fallback;
    }

    private static bool ContainsAny(string value, params string[] tokens)
        => tokens.Any(t => value.Contains(t, StringComparison.OrdinalIgnoreCase));

    private static bool HasNonAscii(string? value) =>
        !string.IsNullOrEmpty(value) && value.Any(ch => ch > 127);

    private static string SanitizeId(string value) =>
        new(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(24).ToArray());
}
