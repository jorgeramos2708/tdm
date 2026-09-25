using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Diff semántico de configuración por CLAVES, nunca por valores: los ficheros y el
/// registro pueden contener secretos y TDM no los expone ni en evidencia. Dice QUÉ
/// ajuste cambió (sección/clave agregada o eliminada), no su contenido.
/// Puro y pineado por tests (la enumeración del registro vive en el collector).
/// </summary>
public static class TsplusConfigSemanticDiff
{
    public const string GlobalSection = "(global)";

    /// <summary>Sección -> claves en orden de aparición.</summary>
    public static Dictionary<string, List<string>> ParseIniKeys(string content)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var current = GlobalSection;
        foreach (var raw in (content ?? "").Split('\n'))
        {
            var line = raw.Trim().TrimEnd('\r');
            if (line.Length == 0 || line[0] is ';' or '#') continue;
            if (line.Length >= 3 && line[0] == '[' && line.EndsWith("]", StringComparison.Ordinal))
            {
                var name = line[1..^1].Trim();
                current = string.IsNullOrWhiteSpace(name) ? GlobalSection : name;
                if (!result.ContainsKey(current)) result[current] = [];
                continue;
            }
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            if (key.Length == 0) continue;
            if (!result.TryGetValue(current, out var keys)) result[current] = keys = [];
            if (!keys.Contains(key, StringComparer.OrdinalIgnoreCase)) keys.Add(key);
        }
        return result;
    }

    public sealed record KeyChange(string Path, string Section, string Change, string Key);

    /// <summary>
    /// Change: "+seccion" | "-seccion" | "+clave" | "-clave". Orden determinista
    /// por ruta, sección y cambio para reportes estables.
    /// </summary>
    public static IReadOnlyList<KeyChange> DiffIni(
        IReadOnlyDictionary<string, Dictionary<string, List<string>>> previous,
        IReadOnlyDictionary<string, Dictionary<string, List<string>>> current)
    {
        var changes = new List<KeyChange>();
        var paths = previous.Keys.Concat(current.Keys)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase);
        foreach (var path in paths)
        {
            previous.TryGetValue(path, out var prev);
            current.TryGetValue(path, out var cur);
            prev ??= new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            cur ??= new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var section in cur.Keys.Except(prev.Keys, StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
                changes.Add(new KeyChange(path, section, "+seccion", ""));
            foreach (var section in prev.Keys.Except(cur.Keys, StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
                changes.Add(new KeyChange(path, section, "-seccion", ""));
            foreach (var section in cur.Keys.Intersect(prev.Keys, StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
            {
                foreach (var key in cur[section].Except(prev[section], StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
                    changes.Add(new KeyChange(path, section, "+clave", key));
                foreach (var key in prev[section].Except(cur[section], StringComparer.OrdinalIgnoreCase).OrderBy(x => x))
                    changes.Add(new KeyChange(path, section, "-clave", key));
            }
        }
        return changes;
    }

    /// <summary>Resumen compacto agrupado por archivo para la evidencia del hallazgo.</summary>
    public static string Summarize(IReadOnlyList<KeyChange> changes, int cap = 6)
    {
        if (changes.Count == 0) return "Sin cambios de claves.";
        var parts = new List<string>();
        foreach (var group in changes.GroupBy(c => c.Path).Take(cap))
        {
            var name = group.Key;
            try { var file = Path.GetFileName(group.Key); if (!string.IsNullOrWhiteSpace(file)) name = file; }
            catch { }
            var items = group.Take(cap).Select(c => c.Change switch
            {
                "+seccion" => "[+" + c.Section + "]",
                "-seccion" => "[-" + c.Section + "]",
                _ => "[" + c.Section + ": " + c.Change + c.Key + "]"
            });
            parts.Add(name + ": " + string.Join(" ", items));
        }
        return string.Join(" | ", parts);
    }

    /// <summary>
    /// Huella estable de un valor de registro a partir de su tipo y contenido, sin
    /// exponer el contenido. Binarios grandes se resumen por longitud.
    /// </summary>
    public static string FingerprintValue(string kind, object? data)
    {
        string rep = data switch
        {
            null => "null",
            byte[] bytes => "bytes:" + bytes.Length + ":" + Convert.ToHexString(SHA256.HashData(bytes.Length > 65536 ? bytes.AsSpan(0, 65536).ToArray() : bytes)),
            string[] strings => "multi:" + strings.Length + ":" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\0", strings.Take(100))))),
            string s => s.Length > 4096 ? "texto-largo:" + s.Length + ":" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))) : s,
            _ => data.ToString() ?? "null"
        };
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(kind + "|" + rep))).ToLowerInvariant();
    }

    /// <summary>Conveniencia para enumerar con RegistryValueKind real.</summary>
    public static string FingerprintRegistryValue(RegistryValueKind kind, object? data)
        => FingerprintValue(kind.ToString(), data);
}
