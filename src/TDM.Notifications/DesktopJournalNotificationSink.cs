using System.Text;
using System.Text.Json;
using TDM.Persistence;

namespace TDM.Notifications;

/// <summary>
/// Sink local de RC18.21. El servicio escribe un journal protegido en ProgramData y
/// TDM.Notifier lo consume en modo sólo lectura desde la sesión interactiva.
/// </summary>
public sealed class DesktopJournalNotificationSink : INotificationSink
{
    private const long RotateAfterBytes = 4L * 1024 * 1024;
    private readonly JsonSerializerOptions _json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly SemaphoreSlim _gate = new(1, 1);
    public string Path { get; }
    public string PreviousPath => Path + ".1";

    public DesktopJournalNotificationSink(string? rootPath = null)
    {
        var root = string.IsNullOrWhiteSpace(rootPath) ? TdmDataPaths.MachineRootPath : System.IO.Path.GetFullPath(rootPath);
        Path = System.IO.Path.Combine(root, "notifications", "desktop-journal.jsonl");
    }

    public async Task SendAsync(IncidentNotification notification, CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
            await RotateIfNeededAsync(ct).ConfigureAwait(false);
            var payload = JsonSerializer.Serialize(notification, _json) + "\n";
            var bytes = Encoding.UTF8.GetBytes(payload);
            await using var stream = new FileStream(Path, FileMode.Append, FileAccess.Write, FileShare.Read,
                16 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
            await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
            stream.Flush(true);
        }
        finally { _gate.Release(); }
    }

    private async Task RotateIfNeededAsync(CancellationToken ct)
    {
        try
        {
            if (!File.Exists(Path) || new FileInfo(Path).Length < RotateAfterBytes) return;
            if (File.Exists(PreviousPath)) File.Delete(PreviousPath);
            File.Move(Path, PreviousPath);
            await Task.CompletedTask.ConfigureAwait(false);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        ct.ThrowIfCancellationRequested();
    }
}
