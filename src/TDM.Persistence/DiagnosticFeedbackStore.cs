using System.Text;
using System.Text.Json;
using TDM.Models;

namespace TDM.Persistence;

/// <summary>
/// Veredicto del técnico sobre una causa propuesta por TDM.
/// </summary>
public enum FeedbackVerdict
{
    Desconocido = 0,
    Confirmada = 1,
    Descartada = 2,
    NoAplica = 3
}

/// <summary>
/// Registro inmutable de feedback: qué candidato validó o descartó el técnico y por qué.
/// Base del aprendizaje futuro (ponderar patrones por historial verificado). No altera
/// diagnósticos pasados; solo alimenta futuras calibraciones.
/// </summary>
public sealed record DiagnosticFeedback(
    string Id,
    DateTimeOffset Timestamp,
    string CandidateId,
    string Componente,
    int Puntaje,
    string Confianza,
    FeedbackVerdict Verdicto,
    string? Nota = null,
    string? Tecnico = null);

/// <summary>
/// Persiste el feedback del técnico en JSONL durable (append-only) bajo state/feedback.
/// Solo lectura/escritura de su propio archivo; jamás modifica configuración del sistema.
/// Sin feedback registrado, cualquier consumidor debe comportarse como si no existiera.
/// </summary>
public sealed class DiagnosticFeedbackStore
{
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };
    public string Path { get; }

    public DiagnosticFeedbackStore(string? rootPath = null)
    {
        var root = string.IsNullOrWhiteSpace(rootPath) ? LocalStateStore.DefaultRootPath : rootPath;
        Path = System.IO.Path.Combine(root, "state", "diagnostic-feedback.jsonl");
    }

    public async Task<DiagnosticFeedback> RecordAsync(
        string candidateId,
        string componente,
        int puntaje,
        string confianza,
        FeedbackVerdict veredicto,
        string? nota = null,
        string? tecnico = null,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(candidateId);
        ArgumentException.ThrowIfNullOrWhiteSpace(componente);
        var feedback = new DiagnosticFeedback(
            "FBK-" + Guid.NewGuid().ToString("N")[..12].ToUpperInvariant(),
            DateTimeOffset.Now,
            candidateId.Trim(),
            TdmVisibleText.Sanitize(componente),
            Math.Clamp(puntaje, 0, 100),
            string.IsNullOrWhiteSpace(confianza) ? "N/D" : confianza.Trim(),
            veredicto,
            string.IsNullOrWhiteSpace(nota) ? null : nota.Trim(),
            string.IsNullOrWhiteSpace(tecnico) ? null : tecnico.Trim());
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var line = JsonSerializer.Serialize(feedback, _json) + Environment.NewLine;
        var bytes = Encoding.UTF8.GetBytes(line);
        await using var stream = new FileStream(Path, FileMode.Append, FileAccess.Write, FileShare.Read,
            16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
        return feedback;
    }

    public async Task<IReadOnlyList<DiagnosticFeedback>> ReadAsync(
        DateTimeOffset? from = null,
        DateTimeOffset? to = null,
        CancellationToken ct = default)
    {
        var output = new List<DiagnosticFeedback>();
        if (!File.Exists(Path)) return output;
        try
        {
            using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete,
                64 * 1024, FileOptions.SequentialScan);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            while (await reader.ReadLineAsync(ct).ConfigureAwait(false) is { } line)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                DiagnosticFeedback? item;
                try { item = JsonSerializer.Deserialize<DiagnosticFeedback>(line, _json); }
                catch (JsonException) { continue; }
                if (item is null) continue;
                if (from.HasValue && item.Timestamp < from.Value) continue;
                if (to.HasValue && item.Timestamp > to.Value) continue;
                output.Add(item);
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return output.OrderBy(x => x.Timestamp).ToList();
    }

    /// <summary>
    /// Tasa de acierto por ID de candidato (confirmadas / (confirmadas + descartadas)).
    /// Base futura para ponderar patrones por historial verificado. Null sin datos.
    /// </summary>
    public static IReadOnlyDictionary<string, (int Confirmadas, int Descartadas, double Tasa)> HitRateByCandidate(
        IEnumerable<DiagnosticFeedback> feedback)
    {
        var groups = feedback
            .Where(f => f.Verdicto is FeedbackVerdict.Confirmada or FeedbackVerdict.Descartada)
            .GroupBy(f => f.CandidateId, StringComparer.OrdinalIgnoreCase);
        var result = new Dictionary<string, (int, int, double)>(StringComparer.OrdinalIgnoreCase);
        foreach (var group in groups)
        {
            var confirmadas = group.Count(f => f.Verdicto == FeedbackVerdict.Confirmada);
            var descartadas = group.Count(f => f.Verdicto == FeedbackVerdict.Descartada);
            var total = confirmadas + descartadas;
            result[group.Key] = (confirmadas, descartadas, total == 0 ? 0d : (double)confirmadas / total);
        }
        return result;
    }
}
