using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Reactive.Subjects;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TDM.Core;

namespace TDM.Gui.Avalonia.Services;

/// <summary>
/// Servicio centralizado de logging con buffer circular, persistencia a archivo y suscripción en tiempo real.
/// </summary>
public sealed class LogService : IDisposable
{
    private const int MaxBufferSize = 10000;
    private const int MaxFileSizeBytes = 10 * 1024 * 1024; // 10 MB por archivo
    private const int MaxFiles = 30; // Retención 30 días

    private readonly ConcurrentQueue<LogEntry> _buffer = new();
    private readonly Subject<LogEntry> _subject = new();
    private readonly string _logDirectory;
    private readonly SemaphoreSlim _fileGate = new(1, 1);
    private readonly Timer _cleanupTimer;
    private readonly object _bufferLock = new();
    private int _currentCount;
    private string? _currentLogFile;
    private DateTime _currentLogDate = DateTime.MinValue;
    private long _currentFileSize;
    private bool _disposed;

    public LogService()
    {
        var root = TDM.Persistence.TdmDataPaths.ResolveWritableDefault();
        _logDirectory = Path.Combine(root, "logs");
        Directory.CreateDirectory(_logDirectory);

        // Timer de limpieza diaria
        _cleanupTimer = new Timer(CleanupOldFiles, null, TimeSpan.FromHours(1), TimeSpan.FromHours(24));

        // Rotar archivo inicial
        RotateLogFile();
    }

    /// <summary>
    /// Observable para suscripción en tiempo real.
    /// </summary>
    public IObservable<LogEntry> Entries => _subject;

    /// <summary>
    /// Escribe una entrada al log.
    /// </summary>
    public void Write(LogEntry entry)
    {
        if (_disposed) return;

        // Añadir al buffer circular
        lock (_bufferLock)
        {
            _buffer.Enqueue(entry);
            _currentCount++;
            if (_currentCount > MaxBufferSize)
            {
                _buffer.TryDequeue(out _);
                _currentCount--;
            }
        }

        // Notificar suscriptores
        _subject.OnNext(entry);

        // Persistir a archivo
        _ = PersistAsync(entry);
    }

    /// <summary>
    /// Escribe un log con parámetros simplificados.
    /// </summary>
    public void Write(LogLevel level, string source, string? component, string message, Exception? exception = null)
    {
        var entry = LogEntry.Create(level, source, component, message, exception);
        Write(entry);
    }

    /// <summary>
    /// Obtiene snapshot actual del buffer (para carga inicial).
    /// </summary>
    public IReadOnlyList<LogEntry> GetSnapshot()
    {
        lock (_bufferLock)
        {
            return _buffer.ToArray();
        }
    }

/// <summary>
    /// Persiste la entrada a archivo rotativo diario.
    /// </summary>
    private async Task PersistAsync(LogEntry entry)
    {
        await _fileGate.WaitAsync();
        try
        {
            RotateLogFile();

            var line = FormatLogLine(entry);
            var bytes = Encoding.UTF8.GetBytes(line + Environment.NewLine);

            await using var stream = new FileStream(_currentLogFile!, FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.Asynchronous);
            await stream.WriteAsync(bytes);
            _currentFileSize += bytes.Length;
        }
        catch
        {
            // Best-effort: no dejar que falle el logging rompa la app
        }
        finally
        {
            _fileGate.Release();
        }
    }

    private void RotateLogFile()
    {
        var today = DateTime.UtcNow.Date;
        if (_currentLogFile != null && _currentLogDate == today && _currentFileSize < MaxFileSizeBytes)
            return;

        var fileName = $"tdm-gui-{today:yyyyMMdd}.log";
        _currentLogFile = Path.Combine(_logDirectory, fileName);
        _currentLogDate = today;
        _currentFileSize = File.Exists(_currentLogFile) ? new FileInfo(_currentLogFile).Length : 0;
    }

    private string FormatLogLine(LogEntry entry)
    {
        var sb = new StringBuilder();
        sb.Append(entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff"));
        sb.Append(' ');
        sb.Append('[').Append(entry.LevelText).Append(']');
        sb.Append(' ');
        sb.Append('[').Append(entry.SourceSystemText).Append(']');
        sb.Append(' ');
        sb.Append(entry.Source);
        if (!string.IsNullOrWhiteSpace(entry.Component))
        {
            sb.Append('/').Append(entry.Component);
        }
        sb.Append(": ");
        sb.Append(entry.Message);

        if (entry.Exception != null)
        {
            sb.Append(Environment.NewLine).Append("  Exception: ").Append(entry.Exception);
        }

        return sb.ToString();
    }

    private void CleanupOldFiles(object? state)
    {
        try
        {
            var files = Directory.GetFiles(_logDirectory, "tdm-gui-*.log")
                .Select(f => new FileInfo(f))
                .OrderByDescending(f => f.CreationTimeUtc)
                .ToList();

            if (files.Count > MaxFiles)
            {
                foreach (var file in files.Skip(MaxFiles))
                {
                    try { file.Delete(); } catch { }
                }
            }

            // Comprimir archivos antiguos (>7 días) si son grandes
            var cutoff = DateTime.UtcNow.AddDays(-7);
            foreach (var file in files.Where(f => f.CreationTimeUtc < cutoff && f.Length > 1024 * 1024))
            {
                // Opcional: comprimir a .gz
            }
        }
        catch { }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cleanupTimer?.Dispose();
        _subject.OnCompleted();
        _subject.Dispose();
        _fileGate.Dispose();
    }
}