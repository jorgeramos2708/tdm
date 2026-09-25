using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Esquema versionado para logs estructurados TSplus (JSONL).
/// Versión 1.0: campos base + contexto operacional.
/// </summary>
public static class TsplusLogSchema
{
    public const string SchemaVersion = "1.0";
    public const string SchemaId = "tsplus.log.schema.v1";

    /// <summary>
    /// Entrada de log estructurada TSplus v1.
    /// </summary>
    public sealed record StructuredLogEntry(
        // Requeridos (sin valores por defecto)
        [property: JsonPropertyName("@timestamp")] DateTimeOffset Timestamp,
        [property: JsonPropertyName("host")] string Host,
        [property: JsonPropertyName("pid")] int ProcessId,
        [property: JsonPropertyName("thread")] int ThreadId,
        [property: JsonPropertyName("level")] string Level,
        [property: JsonPropertyName("component")] string Component,
        [property: JsonPropertyName("category")] string Category,
        [property: JsonPropertyName("message")] string Message,
        
        // Metadatos de esquema (opcional)
        [property: JsonPropertyName("@schema")] string Schema = SchemaId,
        [property: JsonPropertyName("@version")] string Version = SchemaVersion,
        
        // Contexto operacional (opcional)
        [property: JsonPropertyName("session_id")] string? SessionId = null,
        [property: JsonPropertyName("user")] string? User = null,
        [property: JsonPropertyName("domain")] string? Domain = null,
        [property: JsonPropertyName("client_ip")] string? ClientIp = null,
        [property: JsonPropertyName("application")] string? Application = null,
        
        // Métricas numéricas (opcional)
        [property: JsonPropertyName("duration_ms")] long? DurationMs = null,
        [property: JsonPropertyName("bytes_sent")] long? BytesSent = null,
        [property: JsonPropertyName("bytes_received")] long? BytesReceived = null,
        
        // Excepción/Stack trace (opcional)
        [property: JsonPropertyName("exception_type")] string? ExceptionType = null,
        [property: JsonPropertyName("exception_message")] string? ExceptionMessage = null,
        [property: JsonPropertyName("stack_trace")] string? StackTrace = null,
        
        // Tags para búsqueda/filtro
        [property: JsonPropertyName("tags")] IReadOnlyList<string>? Tags = null
    );

    /// <summary>
    /// Opciones de serialización JSONL.
    /// </summary>
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };
}

/// <summary>
/// Escritor JSONL para logs estructurados TSplus.
/// Rotación diaria, compresión opcional, buffer asíncrono.
/// </summary>
public sealed class TsplusStructuredLogWriter : IDisposable
{
    private readonly string _logDirectory;
    private readonly string _hostName;
    private readonly int _processId;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? _currentFile;
    private DateTime _currentDate = DateTime.MinValue;
    private FileStream? _currentStream;
    private StreamWriter? _currentWriter;
    private long _currentFileSize;
    private readonly Timer _flushTimer;

    public TsplusStructuredLogWriter(string logDirectory, string? hostName = null)
    {
        _logDirectory = logDirectory;
        _hostName = hostName ?? Environment.MachineName;
        _processId = Environment.ProcessId;
        Directory.CreateDirectory(_logDirectory);

        _flushTimer = new Timer(FlushAsync, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5));
    }

    public async ValueTask WriteAsync(TsplusLogSchema.StructuredLogEntry entry, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            EnsureFileForDate(entry.Timestamp);
            var json = JsonSerializer.Serialize(entry, TsplusLogSchema.JsonOptions);
            await _currentWriter!.WriteLineAsync(json);
            _currentFileSize += System.Text.Encoding.UTF8.GetByteCount(json) + 1;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Escribe múltiples entradas en lote.
    /// </summary>
    public async Task WriteBatchAsync(IEnumerable<TsplusLogSchema.StructuredLogEntry> entries, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct);
        try
        {
            foreach (var entry in entries)
            {
                ct.ThrowIfCancellationRequested();
                EnsureFileForDate(entry.Timestamp);
                var json = JsonSerializer.Serialize(entry, TsplusLogSchema.JsonOptions);
                await _currentWriter!.WriteLineAsync(json);
                _currentFileSize += System.Text.Encoding.UTF8.GetByteCount(json) + 1;
            }
            await _currentWriter!.FlushAsync(ct);
        }
        finally
        {
            _gate.Release();
        }
    }

    private void EnsureFileForDate(DateTimeOffset timestamp)
    {
        var date = timestamp.Date;
        var fileName = $"tsplus-structured-{date:yyyyMMdd}.jsonl";
        var filePath = Path.Combine(_logDirectory, fileName);

        if (_currentFile == filePath && _currentWriter != null) return;

        // Cerrar archivo anterior
        if (_currentWriter != null)
        {
            _currentWriter.Flush();
            _currentWriter.Dispose();
            _currentStream?.Dispose();
        }

        // Crear nuevo archivo
        _currentFile = filePath;
        _currentDate = date;
        _currentStream = new FileStream(_currentFile, FileMode.Append, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        _currentWriter = new StreamWriter(_currentStream, new System.Text.UTF8Encoding(false), 64 * 1024, leaveOpen: false) { AutoFlush = false };
        _currentFileSize = new FileInfo(_currentFile).Length;
    }

    private async void FlushAsync(object? state)
    {
        try
        {
            await _gate.WaitAsync(TimeSpan.FromSeconds(1));
            try
            {
                if (_currentWriter != null)
                    await _currentWriter.FlushAsync();
            }
            finally
            {
                _gate.Release();
            }
        }
        catch { }
    }

    public void Dispose()
    {
        _flushTimer.Dispose();
        _gate.Wait();
        try
        {
            _currentWriter?.Flush();
            _currentWriter?.Dispose();
            _currentStream?.Dispose();
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }
}

/// <summary>
/// Factoría para crear entradas estructuradas a partir de líneas de log crudo TSplus.
/// </summary>
public static class TsplusStructuredLogFactory
{
    private static readonly JsonSerializerOptions _jsonOptions = TsplusLogSchema.JsonOptions;

    /// <summary>
    /// Convierte una línea de log crudo TSplus a entrada estructurada.
    /// </summary>
    public static TsplusLogSchema.StructuredLogEntry? TryCreate(string rawLine, string host, int pid, DateTimeOffset timestamp)
    {
        if (string.IsNullOrWhiteSpace(rawLine)) return null;

        // Parsing básico - en producción usar parser específico por formato
        var level = ExtractLevel(rawLine);
        var component = ExtractComponent(rawLine);
        var category = ExtractCategory(rawLine);
        var message = ExtractMessage(rawLine);
        var tags = ExtractTags(rawLine);

        return new TsplusLogSchema.StructuredLogEntry(
            Timestamp: timestamp,
            Host: host,
            ProcessId: Environment.ProcessId,
            ThreadId: Environment.CurrentManagedThreadId,
            Level: level,
            Component: component,
            Category: category,
            Message: message,
            Tags: tags
        );
    }

    private static string ExtractLevel(string line)
    {
        var upper = line.ToUpperInvariant();
        if (upper.Contains("ERROR") || upper.Contains("EXCEPTION") || upper.Contains("FAIL")) return "ERROR";
        if (upper.Contains("WARN")) return "WARN";
        if (upper.Contains("CRITICAL") || upper.Contains("FATAL")) return "CRITICAL";
        if (upper.Contains("DEBUG")) return "DEBUG";
        return "INFO";
    }

    private static string ExtractComponent(string line)
    {
        // Heurística simple - en producción usar parser específico
        if (line.Contains("RemoteAccess", StringComparison.OrdinalIgnoreCase)) return "RemoteAccess";
        if (line.Contains("HTML5", StringComparison.OrdinalIgnoreCase)) return "HTML5";
        if (line.Contains("Gateway", StringComparison.OrdinalIgnoreCase)) return "Gateway";
        if (line.Contains("License", StringComparison.OrdinalIgnoreCase)) return "License";
        if (line.Contains("Auth", StringComparison.OrdinalIgnoreCase)) return "Auth";
        if (line.Contains("Session", StringComparison.OrdinalIgnoreCase)) return "Session";
        if (line.Contains("Print", StringComparison.OrdinalIgnoreCase)) return "Print";
        return "TSplus";
    }

    private static string ExtractCategory(string line)
    {
        var upper = line.ToUpperInvariant();
        if (upper.Contains("CONNECT") || upper.Contains("LOGON")) return "CONNECTION";
        if (upper.Contains("AUTH") || upper.Contains("LOGON")) return "AUTH";
        if (upper.Contains("SESSION")) return "SESSION";
        if (upper.Contains("PRINT")) return "PRINT";
        if (upper.Contains("LICENSE")) return "LICENSE";
        if (upper.Contains("START") || upper.Contains("STOP")) return "LIFECYCLE";
        return "GENERAL";
    }

    private static string ExtractMessage(string line)
    {
        // Extraer mensaje después del timestamp/level/component si existe
        var idx = line.IndexOf(']');
        if (idx >= 0 && idx < line.Length - 1)
            return line[(idx + 1)..].TrimStart(' ', ':');
        return line;
    }

    private static IReadOnlyList<string> ExtractTags(string line)
    {
        var tags = new List<string>();
        var upper = line.ToUpperInvariant();
        if (upper.Contains("ERROR")) tags.Add("error");
        if (upper.Contains("WARN")) tags.Add("warning");
        if (upper.Contains("CONNECT")) tags.Add("connection");
        if (upper.Contains("SESSION")) tags.Add("session");
        return tags;
    }
}