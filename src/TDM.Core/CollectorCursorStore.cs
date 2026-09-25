using System.Text.Json;

namespace TDM.Core;

/// <summary>
/// Persistencia atómica y de solo estado para cursores incrementales. Si no puede
/// persistirse, el collector debe degradar cobertura; nunca se asume continuidad.
/// </summary>
public static class CollectorCursorStore
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public static bool TryLoad<T>(string key, out T? value, out string? error) where T : class
    {
        value = null;
        error = null;
        try
        {
            var path = StatePath(key);
            if (!File.Exists(path)) { error = null; return false; }
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            value = JsonSerializer.Deserialize<T>(stream, Json);
            if (value is null) { error = "El cursor existe pero está vacío o no contiene un estado válido."; return false; }
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or System.Security.SecurityException)
        {
            error = ex.Message;
            return false;
        }
    }

    public static bool TrySave<T>(string key, T value, out string? error) where T : class
    {
        error = null;
        var path = StatePath(key);
        var dir = Path.GetDirectoryName(path)!;
        var tmp = path + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            Directory.CreateDirectory(dir);
            using (var stream = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                       16 * 1024, FileOptions.WriteThrough))
            {
                JsonSerializer.Serialize(stream, value, Json);
                stream.Flush(true);
            }
            File.Move(tmp, path, true);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
        }
    }

    private static string StatePath(string key)
    {
        var overrideRoot = Environment.GetEnvironmentVariable("TDM_STATE_ROOT");
        var root = !string.IsNullOrWhiteSpace(overrideRoot)
            ? Path.GetFullPath(overrideRoot)
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "TDM", "collector-state");
        var safe = new string(key.Where(ch => char.IsLetterOrDigit(ch) || ch is '-' or '_').ToArray());
        if (string.IsNullOrWhiteSpace(safe)) safe = "cursor";
        return Path.Combine(root, safe + ".json");
    }
}
