using System.Text;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
    /// Lector incremental de logs TSplus. El cursor avanza únicamente por bytes realmente consumidos.
    /// Si una ráfaga excede los presupuestos, el remanente queda como backlog para muestras posteriores.
    /// </summary>
    public sealed class IncrementalTsplusLogCollector : IReadOnlyCollector
    {
        public string Nombre => "Logs TSplus incrementales";

        private const int DefaultMaxFiles = 240;
        private const int DefaultMaxEvents = 300;
        private const long DefaultMaxNewBytesPerFile = 256 * 1024;
        private const long DefaultMaxNewBytesPerCycle = 1024 * 1024;
        private const int DefaultMaxPartialChars = 512 * 1024;

    private readonly object _sync = new();
    private readonly Dictionary<string, long> _offsets = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _partialLines = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long> _creationTicks = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Queue<DiagnosticEvent>> _pendingEvents = new(StringComparer.OrdinalIgnoreCase);
    private IReadOnlyList<TsplusLogSource> _sources = [];
    private string? _cursorPersistenceWarning;
    private TsplusLogDiscoveryResult? _discovery;
    private DateTimeOffset _lastDiscovery = DateTimeOffset.MinValue;
    private bool _primed;
    private bool _forceReplayAfterCursorLoss;

    // Configurable limits (loaded per-cycle from context.Options)
    private int _maxFiles = DefaultMaxFiles;
    private int _maxEvents = DefaultMaxEvents;
    private long _maxNewBytesPerFile = DefaultMaxNewBytesPerFile;
    private long _maxNewBytesPerCycle = DefaultMaxNewBytesPerCycle;

    private sealed record FileCursorState(long Offset, long CreationUtcTicks, string PartialLine, string FileHash);
    private sealed record TsplusCursorState(Dictionary<string, FileCursorState> Files, DateTimeOffset SavedAt);

    public void Prime(string? installPath)
    {
        lock (_sync)
        {
            _offsets.Clear();
            _partialLines.Clear();
            _creationTicks.Clear();
            _pendingEvents.Clear();
            _discovery = TsplusLogDiscovery.DiscoverDetailed(installPath);
            _sources = _discovery.Sources;
            _lastDiscovery = DateTimeOffset.Now;

            var loaded = CollectorCursorStore.TryLoad<TsplusCursorState>("tsplus-log-cursors", out var state, out var error)
                         && state?.Files is not null;
            _forceReplayAfterCursorLoss = !loaded && !string.IsNullOrWhiteSpace(error);
            _cursorPersistenceWarning = error;
            // V3: mismo orden global por recencia que en CollectAsync (ver comentario allí).
            foreach (var candidate in EnumerateCandidates(_sources).Candidates
                .OrderByDescending(c => SafeLastWriteTimeUtc(c.Path)).Take(DefaultMaxFiles))
            {
                try
                {
                    var info = new FileInfo(candidate.Path);
                    var creation = info.CreationTimeUtc.Ticks;
                    // P2-03: Compute file hash for robust cursor tracking (file+size+hash)
                    var fileHash = ComputeFileHash(candidate.Path);
                    if (loaded && state!.Files.TryGetValue(candidate.Path, out var saved)
                               && saved.CreationUtcTicks == creation
                               && saved.FileHash == fileHash
                               && saved.Offset >= 0 && saved.Offset <= info.Length)
                    {
                        _offsets[candidate.Path] = saved.Offset;
                        _creationTicks[candidate.Path] = creation;
                        if (!string.IsNullOrEmpty(saved.PartialLine)) _partialLines[candidate.Path] = saved.PartialLine;
                    }
                    else
                    {
                        // Primer arranque evita inundar con historial; tras existir un estado durable,
                        // un archivo nuevo se procesa desde el inicio para no perder lo ocurrido offline.
                        _offsets[candidate.Path] = loaded || _forceReplayAfterCursorLoss ? 0 : info.Length;
                        _creationTicks[candidate.Path] = creation;
                    }
                }
                catch { }
            }
            if (_forceReplayAfterCursorLoss)
                _cursorPersistenceWarning = string.IsNullOrWhiteSpace(error)
                    ? "Cursor no disponible; se conserva replay acotado para archivos TSplus."
                    : "Cursor no recuperable; se conserva replay acotado para archivos TSplus: " + error;
            _primed = true;
        }
    }

    public async Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var opts = context.Options ?? new DiagnosticOptions();
        _maxFiles = opts.MaxFilesPerDirectoryIncremental ?? DefaultMaxFiles;
        _maxEvents = opts.MaxEventsIncremental ?? DefaultMaxEvents;
        _maxNewBytesPerFile = opts.MaxBytesPerFileIncremental ?? DefaultMaxNewBytesPerFile;
        _maxNewBytesPerCycle = opts.MaxTotalBytesIncremental ?? DefaultMaxNewBytesPerCycle;

        if (!_primed) Prime(context.Sistema.TsplusRuta);
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var candidateEnumeration = EnumerateCandidates(GetSources(context.Sistema.TsplusRuta));
        // V3: el Take(240) seguía orden de discovery (estáticas→dinámicas→perfiles) y amputaba
        // fuentes tardías aunque fueran más nuevas. Orden global por recencia antes de cortar.
        var candidates = candidateEnumeration.Candidates
            .OrderByDescending(c => SafeLastWriteTimeUtc(c.Path))
            .Take(_maxFiles).ToList();
        var candidatesObserved = 0;
        var backlogFiles = 0;
        var bytesReadThisCycle = 0L;
        var partialTruncatedChars = 0L;
        var readLosses = 0;

        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            candidatesObserved++;

            DrainPending(candidate.Path, events);
            if (events.Count >= _maxEvents)
            {
                backlogFiles += PendingCount(candidate.Path) > 0 ? 1 : 0;
                continue;
            }

            if (PendingCount(candidate.Path) > 0)
            {
                backlogFiles++;
                continue;
            }

            long previous;
            lock (_sync)
            {
                if (!_offsets.TryGetValue(candidate.Path, out previous))
                {
                    previous = 0;
                    _offsets[candidate.Path] = 0;
                }
            }

            long length;
            long creationTicks;
            try
            {
                var info = new FileInfo(candidate.Path);
                length = info.Length;
                creationTicks = info.CreationTimeUtc.Ticks;
            }
            catch (UnauthorizedAccessException ex)
            {
                events.Add(SourceUnavailable(candidate, "Sin permisos de lectura", ex.Message));
                readLosses++;
                continue;
            }
            catch (IOException ex)
            {
                events.Add(SourceUnavailable(candidate, "Error de lectura", ex.Message));
                readLosses++;
                continue;
            }

            var knownCreation = CreationTicks(candidate.Path);
            if ((knownCreation != 0 && knownCreation != creationTicks) || length < previous)
            {
                previous = 0;
                lock (_sync)
                {
                    _offsets[candidate.Path] = 0;
                    _creationTicks[candidate.Path] = creationTicks;
                    _partialLines.Remove(candidate.Path);
                    _pendingEvents.Remove(candidate.Path);
                }
            }
            else if (knownCreation == 0)
            {
                lock (_sync) _creationTicks[candidate.Path] = creationTicks;
            }
            if (length == previous) continue;

            var cycleRemaining = _maxNewBytesPerCycle - bytesReadThisCycle;
            if (cycleRemaining <= 0)
            {
                backlogFiles++;
                continue;
            }

            var requested = Math.Min(Math.Min(_maxNewBytesPerFile, cycleRemaining), length - previous);
            var priorPartial = GetPartial(candidate.Path);
            var readResult = await ReadChunkAsync(candidate, previous, requested, priorPartial, context, cancellationToken).ConfigureAwait(false);
            bytesReadThisCycle += readResult.BytesConsumed;
            partialTruncatedChars += readResult.PartialTruncatedChars;

            if (readResult.ReadFailure is not null)
            {
                events.Add(readResult.ReadFailure);
                readLosses++;
                continue;
            }

            lock (_sync)
            {
                _offsets[candidate.Path] = previous + readResult.BytesConsumed;
                if (string.IsNullOrEmpty(readResult.PartialLine)) _partialLines.Remove(candidate.Path);
                else _partialLines[candidate.Path] = readResult.PartialLine;
                if (readResult.Events.Count > 0)
                {
                    if (!_pendingEvents.TryGetValue(candidate.Path, out var queue))
                        _pendingEvents[candidate.Path] = queue = new Queue<DiagnosticEvent>();
                    foreach (var evt in readResult.Events) queue.Enqueue(evt);
                }
            }

            DrainPending(candidate.Path, events);
            var newOffset = PreviousOffset(candidate.Path);
            if (newOffset < length || PendingCount(candidate.Path) > 0) backlogFiles++;
        }

        if (!PersistCursorState(out var persistError))
        {
            _cursorPersistenceWarning = persistError ?? "No fue posible persistir el cursor incremental TSplus.";
            events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Persistencia de logs TSplus", DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Advertencia, "TSPLUS_INCREMENTAL_CURSOR_NOT_PERSISTED",
                "Los logs se leyeron, pero TDM no pudo persistir el cursor durable; la continuidad después de reiniciar no está garantizada.",
                Evidencia: [new EvidenceItem("Cobertura", "Parcial"), new EvidenceItem("Detalle", _cursorPersistenceWarning)],
                Producto: TsplusProduct.RemoteAccess));
            readLosses++;
        }
        else
        {
            _forceReplayAfterCursorLoss = false;
        }

        foreach (var group in events
                     .Where(e => e.Severidad is DiagnosticSeverity.Advertencia or DiagnosticSeverity.Error or DiagnosticSeverity.Critico)
                     .Where(e => e.Timestamp.HasValue)
                     .GroupBy(e => new { e.Componente, e.Tipo, e.Severidad, e.Capa }))
        {
            var latest = group.OrderByDescending(x => x.Timestamp).First();
            findings.Add(new DiagnosticFinding(
                $"LIVE-TSLOG-{SanitizeId(group.Key.Componente)}-{group.Key.Tipo}",
                group.Key.Componente,
                group.Key.Severidad,
                $"Nueva evidencia TSplus durante el diagnóstico continuo: {group.Key.Tipo}",
                latest.Mensaje,
                [
                    new EvidenceItem("Cantidad nueva", group.Count().ToString()),
                    new EvidenceItem("Último registro", latest.Timestamp?.ToString("O") ?? "N/D"),
                    new EvidenceItem("Archivo", latest.Archivo ?? "N/D"),
                    new EvidenceItem("Modo captura", "Incremental por cursor de bytes; backlog persistente")
                ],
                group.Count() >= 3 ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                Capa: group.Key.Capa));
        }

        var discovery = GetDiscoverySnapshot();
        var discoveryPartial = discovery is not null && (discovery.DiscoveryErrors > 0 || discovery.DiscoveryTruncated || discovery.UserProfilesTruncated);
        var candidatesTruncated = candidateEnumeration.Candidates.Count > _maxFiles;
        var coverageLosses = readLosses + candidateEnumeration.Failures;
        var partialCoverage = coverageLosses > 0 || discoveryPartial || candidatesTruncated || candidateEnumeration.TruncatedDirectories > 0 || backlogFiles > 0;

        var coverageEvent = new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Cobertura incremental TSplus", DiagnosticLayer.Tsplus,
            partialCoverage ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "TSPLUS_INCREMENTAL_LOG_COVERAGE",
            partialCoverage
                ? "La cobertura incremental TSplus es parcial o tiene backlog; ningún byte omitido se da por procesado."
                : "Cobertura incremental de logs TSplus actualizada sin backlog.",
            Evidencia:
            [
                new EvidenceItem("Cobertura", partialCoverage ? "Parcial" : "Disponible"),
                new EvidenceItem("Fuentes candidatas", candidatesObserved.ToString()),
                new EvidenceItem("Fuentes no evaluadas", coverageLosses.ToString()),
                new EvidenceItem("Fuentes con backlog", backlogFiles.ToString()),
                new EvidenceItem("Bytes leídos en ciclo", bytesReadThisCycle.ToString()),
                new EvidenceItem("Caracteres parciales descartados por límite", partialTruncatedChars.ToString()),
                new EvidenceItem("Directorios truncados", candidateEnumeration.TruncatedDirectories.ToString()),
                new EvidenceItem("Límite de archivos alcanzado", candidatesTruncated ? $"Sí; máximo {_maxFiles}" : "No"),
                new EvidenceItem("Descubrimiento dinámico", discoveryPartial ? "Parcial" : "Disponible"),
                new EvidenceItem("Regla", "El cursor avanza sólo por bytes consumidos; el remanente se procesa en ciclos posteriores")
            ], Producto: TsplusProduct.RemoteAccess);

        var outputEvents = events.Where(e => e.Tipo != "TSPLUS_INCREMENTAL_LOG_COVERAGE").Take(Math.Max(0, _maxEvents - 1)).ToList();
        outputEvents.Add(coverageEvent);
        return new CollectorResult(findings, outputEvents);
    }

    private void DrainPending(string path, List<DiagnosticEvent> output)
    {
        lock (_sync)
        {
            if (!_pendingEvents.TryGetValue(path, out var queue)) return;
            while (queue.Count > 0 && output.Count < _maxEvents - 1)
                output.Add(queue.Dequeue());
            if (queue.Count == 0) _pendingEvents.Remove(path);
        }
    }

    private int PendingCount(string path)
    {
        lock (_sync) return _pendingEvents.TryGetValue(path, out var queue) ? queue.Count : 0;
    }

    private long PreviousOffset(string path)
    {
        lock (_sync) return _offsets.TryGetValue(path, out var value) ? value : 0;
    }

    private string GetPartial(string path)
    {
        lock (_sync) return _partialLines.TryGetValue(path, out var value) ? value : string.Empty;
    }

    private long CreationTicks(string path)
    {
        lock (_sync) return _creationTicks.TryGetValue(path, out var value) ? value : 0;
    }

    private bool PersistCursorState(out string? error)
    {
        Dictionary<string, FileCursorState> files;
        lock (_sync)
        {
            files = _offsets.ToDictionary(
                pair => pair.Key,
                pair => new FileCursorState(
                    pair.Value,
                    _creationTicks.TryGetValue(pair.Key, out var creation) ? creation : 0,
                    _partialLines.TryGetValue(pair.Key, out var partial) ? partial : string.Empty,
                    ComputeFileHash(pair.Key)),
                StringComparer.OrdinalIgnoreCase);
        }
        return CollectorCursorStore.TrySave("tsplus-log-cursors", new TsplusCursorState(files, DateTimeOffset.Now), out error);
    }

    private static (string Text, int BytesUsed) DecodeSafePrefix(Encoding encoding, byte[] buffer, int count)
    {
        if (count <= 0) return (string.Empty, 0);
        Encoding strict = encoding.CodePage switch
        {
            65001 => new UTF8Encoding(false, true),
            1200 => new UnicodeEncoding(false, false, true),
            1201 => new UnicodeEncoding(true, false, true),
            _ => encoding
        };

        var maxTrim = encoding.CodePage == 65001 ? Math.Min(3, count) : encoding.CodePage is 1200 or 1201 ? Math.Min(2, count) : 0;
        for (var trim = 0; trim <= maxTrim; trim++)
        {
            var usable = count - trim;
            if (usable <= 0) break;
            if (encoding.CodePage is 1200 or 1201 && usable % 2 != 0) continue;
            try { return (strict.GetString(buffer, 0, usable), usable); }
            catch (DecoderFallbackException) { }
        }
        // Si hay bytes inválidos en el interior (p. ej. log ANSI sin BOM), no bloquear el
        // cursor indefinidamente: conservar la evidencia con sustitución de caracteres.
        return (encoding.GetString(buffer, 0, count), count);
    }

    private static DiagnosticEvent SourceUnavailable(LogCandidate candidate, string state, string detail) =>
        new(DateTimeOffset.Now, "TDM", candidate.Component, candidate.Layer, DiagnosticSeverity.Advertencia,
            "TSPLUS_INCREMENTAL_SOURCE_UNAVAILABLE",
            "Una fuente incremental de TSplus quedó NO EVALUADA durante esta muestra.",
            Archivo: candidate.Path,
            Evidencia:
            [
                new EvidenceItem("Cobertura", "No evaluado"),
                new EvidenceItem("Estado", state),
                new EvidenceItem("Detalle", detail)
            ], Producto: candidate.Product);

    private static async Task<IncrementalReadResult> ReadChunkAsync(
        LogCandidate candidate,
        long start,
        long requestedBytes,
        string priorPartial,
        DiagnosticContext context,
        CancellationToken ct)
    {
        try
        {
            if (requestedBytes <= 0) return new IncrementalReadResult([], priorPartial, 0, null);
            var encoding = await DetectEncodingAsync(candidate.Path, ct).ConfigureAwait(false);
            await using var stream = new FileStream(candidate.Path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            stream.Seek(start, SeekOrigin.Begin);
            var buffer = new byte[(int)Math.Min(requestedBytes, int.MaxValue)];
            var read = 0;
            while (read < buffer.Length)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct).ConfigureAwait(false);
                if (n == 0) break;
                read += n;
            }
            if (read == 0) return new IncrementalReadResult([], priorPartial, 0, null);

            var decoded = DecodeSafePrefix(encoding, buffer, read);
            var bytesUsed = decoded.BytesUsed;
            if (bytesUsed <= 0) return new IncrementalReadResult([], priorPartial, 0, null);

            var appended = decoded.Text;
            if (start == 0) appended = appended.TrimStart('\uFEFF');
            var combined = priorPartial + appended;
            var lastBreak = combined.LastIndexOf('\n');
            if (lastBreak < 0)
            {
                // S9: si la línea parcial supera el tope, se miden los caracteres descartados en vez
                // de perderlos en silencio. El cursor avanza por bytes: no hay pérdida de posición,
                // solo de contenido de líneas gigantes (p. ej. blobs JSON de una línea).
                var dropped = Math.Max(0, combined.Length - DefaultMaxPartialChars);
                var pending = combined.Length <= DefaultMaxPartialChars ? combined : combined[^DefaultMaxPartialChars..];
                return new IncrementalReadResult([], pending, bytesUsed, null, dropped);
            }

            var complete = combined[..(lastBreak + 1)];
            var remainder = combined[(lastBreak + 1)..].TrimStart('\r');
            long remainderDropped = 0;
            if (remainder.Length > DefaultMaxPartialChars)
            {
                remainderDropped = remainder.Length - DefaultMaxPartialChars;
                remainder = remainder[^DefaultMaxPartialChars..];
            }

            var result = new List<DiagnosticEvent>();
            DiagnosticEvent? current = null;
            var lineNumber = 0;
            using var lines = new StringReader(complete);
            string? line;
            while ((line = lines.ReadLine()) is not null)
            {
                ct.ThrowIfCancellationRequested();
                lineNumber++;
                if (line.Length == 0) continue;
                var parsed = TsplusLogParser.ParseLine(candidate.Component, candidate.Path, line, lineNumber,
                    context, candidate.Layer, candidate.SourceName, candidate.Product);
                if (parsed is not null)
                {
                    if (current is not null) result.Add(current);
                    var evidence = (parsed.Evidencia ?? []).Concat([
                        new EvidenceItem("Offset inicial del bloque", start.ToString()),
                        new EvidenceItem("Línea", $"relativa al bloque: {lineNumber}")
                    ]).ToList();
                    current = parsed with { Evidencia = evidence };
                    continue;
                }

                if (current is not null && TsplusLogParser.IsContinuationLine(line))
                    current = current with { Mensaje = current.Mensaje + Environment.NewLine + line.TrimEnd() };
            }
            if (current is not null) result.Add(current);

            return new IncrementalReadResult(result, remainder, bytesUsed, null, remainderDropped);
        }
        catch (UnauthorizedAccessException ex)
        {
            return new IncrementalReadResult([], priorPartial, 0, SourceUnavailable(candidate, "Sin permisos de lectura", ex.Message));
        }
        catch (IOException ex)
        {
            return new IncrementalReadResult([], priorPartial, 0, SourceUnavailable(candidate, "Error de lectura", ex.Message));
        }
    }

    private static async Task<Encoding> DetectEncodingAsync(string path, CancellationToken ct)
    {
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var bom = new byte[4];
            var n = await stream.ReadAsync(bom.AsMemory(0, 4), ct).ConfigureAwait(false);
            if (n >= 2 && bom[0] == 0xFF && bom[1] == 0xFE) return Encoding.Unicode;
            if (n >= 2 && bom[0] == 0xFE && bom[1] == 0xFF) return Encoding.BigEndianUnicode;
            if (n >= 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF) return new UTF8Encoding(false, false);
            if (n >= 4 && bom[1] == 0 && bom[3] == 0) return Encoding.Unicode;
            if (n >= 4 && bom[0] == 0 && bom[2] == 0) return Encoding.BigEndianUnicode;
        }
        catch { }
        return new UTF8Encoding(false, false);
    }

    private IReadOnlyList<TsplusLogSource> GetSources(string? installPath)
    {
        lock (_sync)
        {
            if (DateTimeOffset.Now - _lastDiscovery >= TimeSpan.FromMinutes(15))
            {
                _discovery = TsplusLogDiscovery.DiscoverDetailed(installPath);
                _sources = _discovery.Sources;
                _lastDiscovery = DateTimeOffset.Now;
            }
            return _sources;
        }
    }

    private TsplusLogDiscoveryResult? GetDiscoverySnapshot()
    {
        lock (_sync) return _discovery;
    }

    private sealed record CandidateEnumerationResult(List<LogCandidate> Candidates, int Failures, int TruncatedDirectories);

    // S4: el incremental era TopDirectoryOnly mientras la base es recursiva (depth3): los
    // subdirectorios quedaban ciegos en continuo. Recursión acotada (profundidad ≤3, 64 dirs,
    // 800 archivos examinados, 80 archivos por dir) con tope global compartido para depth3
    // cuando el presupuesto de candidatos (MaxFiles=240) lo permite.
    private const int IncrementalMaxDepth = 3;
    private const int IncrementalMaxDirectories = 64;
    private const int IncrementalMaxFilesExamined = 800;
    private const int IncrementalMaxFilesPerDirectory = 80;

    private static CandidateEnumerationResult EnumerateCandidates(IEnumerable<TsplusLogSource> sources)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var candidates = new List<LogCandidate>();
        var failures = 0;
        var truncatedDirectories = 0;
        var state = new RecursiveEnumerationState();
        foreach (var source in sources.Where(x => x.Existe))
        {
            if (!source.EsDirectorio)
            {
                if (IsLikelyLogFile(source.Ruta) && seen.Add(source.Ruta))
                    candidates.Add(ToCandidate(source, source.Ruta));
                continue;
            }

            try
            {
                EnumerateDirectoryRecursive(source, source.Ruta, 0, seen, candidates, state, ref truncatedDirectories);
            }
            catch { failures++; }
        }
        if (state.Truncated) truncatedDirectories++;
        return new CandidateEnumerationResult(candidates, failures, truncatedDirectories);
    }

    private sealed class RecursiveEnumerationState
    {
        public int DirectoriesVisited;
        public int FilesExamined;
        public bool Truncated;
    }

    private static void EnumerateDirectoryRecursive(
        TsplusLogSource source,
        string directory,
        int depth,
        HashSet<string> seen,
        List<LogCandidate> candidates,
        RecursiveEnumerationState state,
        ref int truncatedDirectories)
    {
        if (depth > IncrementalMaxDepth || state.DirectoriesVisited >= IncrementalMaxDirectories
            || state.FilesExamined >= IncrementalMaxFilesExamined)
        {
            state.Truncated = true;
            return;
        }
        state.DirectoriesVisited++;
        string[] files;
        try
        {
            files = Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly)
                .Where(IsLikelyLogFile)
                .OrderByDescending(SafeLastWriteTimeUtc)
                .Take(IncrementalMaxFilesPerDirectory + 1)
                .ToArray();
        }
        catch
        {
            return;
        }
        if (files.Length > IncrementalMaxFilesPerDirectory) truncatedDirectories++;
        foreach (var file in files.Take(IncrementalMaxFilesPerDirectory))
        {
            state.FilesExamined++;
            if (state.FilesExamined > IncrementalMaxFilesExamined) { state.Truncated = true; return; }
            if (seen.Add(file)) candidates.Add(ToCandidate(source, file));
        }
        if (depth >= IncrementalMaxDepth) return;
        string[] children;
        try { children = Directory.EnumerateDirectories(directory, "*", SearchOption.TopDirectoryOnly).ToArray(); }
        catch { return; }
        foreach (var child in children)
        {
            try
            {
                if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0) continue;
            }
            catch { continue; }
            EnumerateDirectoryRecursive(source, child, depth + 1, seen, candidates, state, ref truncatedDirectories);
            if (state.Truncated) return;
        }
    }

    private static LogCandidate ToCandidate(TsplusLogSource source, string path)
        => new(source.Componente, path, source.Capa,
            source.Producto == TsplusProduct.AdvancedSecurity ? "TSplus Security Log" : "TSplus Log",
            source.Producto);

    private static bool IsLikelyLogFile(string path)
    {
        var ext = Path.GetExtension(path);
        return string.IsNullOrEmpty(ext)
               || ext.Equals(".log", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".txt", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".trace", StringComparison.OrdinalIgnoreCase);
    }

    private static DateTime SafeLastWriteTimeUtc(string path)
    {
        try { return File.GetLastWriteTimeUtc(path); }
        catch { return DateTime.MinValue; }
    }

    /// <summary>
    /// P2-03: Computes SHA256 hash of file for robust cursor tracking (file+size+hash).
    /// Used to detect file rotation/truncation beyond offset/creation time.
    /// </summary>
    private static string ComputeFileHash(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return string.Empty;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
            using var sha = System.Security.Cryptography.SHA256.Create();
            var hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch { return string.Empty; }
    }

    private static string SanitizeId(string value)
        => new(value.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(24).ToArray());

    private sealed record IncrementalReadResult(IReadOnlyList<DiagnosticEvent> Events, string PartialLine, long BytesConsumed, DiagnosticEvent? ReadFailure, long PartialTruncatedChars = 0);
    private sealed record LogCandidate(string Component, string Path, DiagnosticLayer Layer, string SourceName, TsplusProduct Product);
}
