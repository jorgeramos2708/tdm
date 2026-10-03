using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Reactive.Subjects;
using System.Text;
using System.Threading;
using System.Threading.Channels;
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
    // MEDIUM F25: cota de entradas pendientes de persistir; con una ráfaga de miles de
    // registros, el productor nunca acumula más de esto en memoria (DropOldest descarta
    // las más antiguas sin bloquear — MS core/extensions/channels).
    private const int MaxPendingPersists = 1000;

    private readonly ConcurrentQueue<LogEntry> _buffer = new();
    private readonly Subject<LogEntry> _subject = new();
    private readonly string _logDirectory;
    private readonly Timer _cleanupTimer;
    private readonly object _bufferLock = new();
    private readonly Channel<LogEntry> _pending = Channel.CreateBounded<LogEntry>(
        new BoundedChannelOptions(MaxPendingPersists)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropOldest
        });
    private readonly Task _persistTask;
    private int _currentCount;
    private string? _currentLogFile;
    private DateTime _currentLogDate = DateTime.MinValue;
    private long _currentFileSize;
    private bool _disposed;

    public LogService(string? rootPath = null)
    {
        var root = string.IsNullOrWhiteSpace(rootPath)
            ? TDM.Persistence.TdmDataPaths.ResolveWritableDefault()
            : rootPath;
        _logDirectory = Path.Combine(root, "logs");
        Directory.CreateDirectory(_logDirectory);

        // Timer de limpieza diaria
        _cleanupTimer = new Timer(CleanupOldFiles, null, TimeSpan.FromHours(1), TimeSpan.FromHours(24));

        // Rotar archivo inicial
        RotateLogFile();

        // MEDIUM F25: UN consumidor serializa la E/S en lugar de una tarea por entrada.
        _persistTask = Task.Run(PersistLoopAsync);
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
        // MEDIUM F25: el flag de dispose se revisa DENTRO del lock (check-then-act) y la
        // persistencia se encola en el canal acotado: TryWrite nunca bloquea ni lanza y,
        // con DropOldest, el productor no puede acumular tareas sin límite.
        lock (_bufferLock)
        {
            if (_disposed) return;

            // Añadir al buffer circular
            _buffer.Enqueue(entry);
            _currentCount++;
            if (_currentCount > MaxBufferSize)
            {
                _buffer.TryDequeue(out _);
                _currentCount--;
            }

            _pending.Writer.TryWrite(entry);
        }

        // Notificar suscriptores fuera del lock (no se invoca código ajeno con el lock tomado);
        // el sujeto ya no se dispone, así que un OnNext concurrente con OnCompleted es inocuo.
        _subject.OnNext(entry);
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
    /// Consumidor único del canal de persistencia: drena las entradas encoladas y las
    /// escribe al archivo rotativo. Un fallo de E/S de una entrada no interrumpe el bucle.
    /// </summary>
    private async Task PersistLoopAsync()
    {
        await foreach (var entry in _pending.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            try { AppendEntry(entry); }
            catch
            {
                // Best-effort: no dejar que falle el logging rompa la app
            }
        }
    }

    private void AppendEntry(LogEntry entry)
    {
        RotateLogFile();

        var line = FormatLogLine(entry);
        var bytes = Encoding.UTF8.GetBytes(line + Environment.NewLine);

        using var stream = new FileStream(_currentLogFile!, FileMode.Append, FileAccess.Write, FileShare.Read, 4096);
        stream.Write(bytes, 0, bytes.Length);
        _currentFileSize += bytes.Length;
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
        // MEDIUM F25: dispose a prueba de carreras — el flag se marca y OnCompleted se emite
        // bajo el MISMO lock que serializa el check de Write; el sujeto ya no se dispone
        // (OnNext tardío inocuo) y el canal se completa para que el consumidor drene y pare
        // sin que ningún productor encuentre un recurso dispuesto.
        lock (_bufferLock)
        {
            if (_disposed) return;
            _disposed = true;
            _subject.OnCompleted();
        }
        _pending.Writer.TryComplete();
        try { _persistTask.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cleanupTimer?.Dispose();
    }
}