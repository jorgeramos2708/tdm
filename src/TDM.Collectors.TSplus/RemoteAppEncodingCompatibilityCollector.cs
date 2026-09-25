using System.Text;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Diagnóstico dirigido de compatibilidad de cadenas Unicode en RemoteApp.
/// No recorre todo el árbol TSplus: inspecciona AppControl.ini y archivos temporales
/// startup.config bajo C:\wsession cuando existen.
/// </summary>
public sealed class RemoteAppEncodingCompatibilityCollector : IReadOnlyCollector
{
    public string Nombre => "RemoteApp / compatibilidad de codificación";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        if (!context.Sistema.TsplusDetectado || string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
            return Task.FromResult(CollectorResult.Empty);

        var root = context.Sistema.TsplusRuta!;
        var appControl = Path.Combine(root, "UserDesktop", "files", "AppControl.ini");
        AuditAppControl(appControl, events);

        var sessionRoot = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "wsession");
        var startupFiles = FindNamedFilesBounded(sessionRoot, "startup.config", maxDepth: 4, maxFiles: 40, cancellationToken);
        var risky = 0;
        foreach (var file in startupFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = InspectEncoding(file);
            if (result is null) continue;
            if (result.Value.NonAscii && (!result.Value.ValidUtf8 || result.Value.MojibakeRisk)) risky++;

            events.Add(new DiagnosticEvent(
                File.GetLastWriteTime(file),
                "TSplus RemoteApp",
                "startup.config",
                DiagnosticLayer.Tsplus,
                result.Value.NonAscii && (!result.Value.ValidUtf8 || result.Value.MojibakeRisk) ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
                result.Value.NonAscii && (!result.Value.ValidUtf8 || result.Value.MojibakeRisk) ? "TSPLUS_STARTUP_CONFIG_ENCODING_RISK" : "TSPLUS_STARTUP_CONFIG_ENCODING_STATE",
                result.Value.NonAscii && !result.Value.ValidUtf8
                    ? "startup.config contiene bytes no ASCII y no forma una secuencia UTF-8 válida; es compatible con una cadena ANSI/codificación local que puede romper un flujo RemoteApp si el consumidor espera UTF-8."
                    : result.Value.MojibakeRisk
                        ? "startup.config es UTF-8 válido, pero contiene patrones compatibles con mojibake/doble codificación (por ejemplo, Ã/Â/�). Se conserva como riesgo de compatibilidad."
                        : "startup.config inspeccionado para compatibilidad de codificación.",
                Archivo: file,
                Evidencia:
                [
                    new EvidenceItem("Archivo", file),
                    new EvidenceItem("Tamaño", result.Value.Length.ToString()),
                    new EvidenceItem("Contiene caracteres/bytes no ASCII", result.Value.NonAscii ? "Sí" : "No"),
                    new EvidenceItem("UTF-8 válido", result.Value.ValidUtf8 ? "Sí" : "No"),
                    new EvidenceItem("Codificación probable", result.Value.EncodingHint),
                    new EvidenceItem("BOM", result.Value.Bom),
                    new EvidenceItem("Mojibake/doble codificación probable", result.Value.MojibakeRisk ? "Sí" : "No"),
                    new EvidenceItem("Caracter de reemplazo Unicode", result.Value.ReplacementCharacter ? "Sí" : "No"),
                    new EvidenceItem("Originador específico", "TSplus RemoteApp / cadena de inicio")
                ],
                Producto: TsplusProduct.RemoteAccess));
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "RemoteApp / codificación",
            DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo,
            "TSPLUS_REMOTEAPP_ENCODING_COVERAGE",
            "Cobertura dirigida de compatibilidad Unicode/RemoteApp completada sin auditoría recursiva profunda.",
            Evidencia:
            [
                new EvidenceItem("AppControl.ini", FileSystemProbe.Display(FileSystemProbe.File(appControl), appControl, "No localizado")),
                new EvidenceItem("startup.config observados", startupFiles.Count.ToString()),
                new EvidenceItem("startup.config con riesgo de codificación", risky.ToString()),
                new EvidenceItem("Cobertura cliente .connect", "No disponible desde el servidor; requiere evidencia del equipo cliente"),
                new EvidenceItem("Alcance", "AppControl.ini + C:\\wsession\\**\\startup.config (búsqueda acotada por nombre)")
            ],
            Producto: TsplusProduct.RemoteAccess));

        if (risky > 0)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-REMOTEAPP-ENCODING-RISK",
                "TSplus RemoteApp / startup.config",
                DiagnosticSeverity.Advertencia,
                $"Se detectaron {risky} archivo(s) startup.config con riesgo de codificación (UTF-8 inválido o patrones de mojibake).",
                "La diferencia ANSI/UTF-8 o una doble codificación puede alterar cadenas transmitidas a un cliente RemoteApp. TDM sólo eleva este riesgo a causa probable cuando existe además un fallo de Connection Client/Application Publishing temporalmente compatible y contexto Unicode; no atribuye el problema únicamente por encontrar una letra acentuada.",
                [
                    new EvidenceItem("Archivos afectados", risky.ToString()),
                    new EvidenceItem("Root de sesión", sessionRoot),
                    new EvidenceItem("Rol de TSplus", "Posible originador si existe falla RemoteApp correlacionada"),
                    new EvidenceItem("Cliente .connect", "No inspeccionado desde el servidor")
                ],
                ConfidenceLevel.Media,
                "Microsoft Support — RemoteApp y caracteres acentuados (referencia de compatibilidad RDP)",
                "https://support.microsoft.com/en-US/servicing/Management-Tools/forefront/uag/hotfix/fix-you-cannot-start-a-remoteapp-application-when-its-name-contains-accented-characters",
                "Correlacione el usuario/nombre afectado, startup.config y eventos/logs de Connection Client. No renombre usuarios ni modifique archivos de producción únicamente por este indicador.",
                DiagnosticLayer.Tsplus));
        }

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void AuditAppControl(string path, List<DiagnosticEvent> events)
    {
        if (!FileSystemProbe.File(path).IsAvailable) return;
        try
        {
            var matches = new List<string>();
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#')) continue;
                var idx = line.IndexOf('=');
                if (idx <= 0) continue;
                var key = line[..idx].Trim();
                var value = line[(idx + 1)..].Trim();
                if (key.Equals("appname", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("users", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("groups", StringComparison.OrdinalIgnoreCase) ||
                    key.Equals("startup", StringComparison.OrdinalIgnoreCase))
                {
                    if (HasNonAscii(value)) matches.Add($"{key}={value}");
                }
            }
            if (matches.Count == 0) return;
            events.Add(new DiagnosticEvent(
                File.GetLastWriteTime(path),
                "TSplus AppControl",
                "RemoteApp / cadenas Unicode",
                DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Informativo,
                "TSPLUS_REMOTEAPP_NONASCII_CONFIG_CONTEXT",
                "AppControl.ini contiene nombres o asignaciones con caracteres no ASCII. Es contexto de compatibilidad, no una falla por sí solo.",
                Archivo: path,
                Evidencia:
                [
                    new EvidenceItem("Coincidencias", matches.Count.ToString()),
                    new EvidenceItem("Ejemplos", string.Join(" | ", matches.Take(8))),
                    new EvidenceItem("Caracteres no ASCII", "Sí")
                ],
                Producto: TsplusProduct.RemoteAccess));
        }
        catch { }
    }

    private static List<string> FindNamedFilesBounded(string root, string fileName, int maxDepth, int maxFiles, CancellationToken ct)
    {
        var result = new List<string>();
        if (!FileSystemProbe.Directory(root).IsAvailable) return result;
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((root, 0));
        var visited = 0;
        while (queue.Count > 0 && result.Count < maxFiles && visited < 500)
        {
            ct.ThrowIfCancellationRequested();
            var (dir, depth) = queue.Dequeue();
            visited++;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir, fileName, SearchOption.TopDirectoryOnly))
                {
                    result.Add(file);
                    if (result.Count >= maxFiles) break;
                }
                if (depth >= maxDepth) continue;
                foreach (var child in Directory.EnumerateDirectories(dir))
                {
                    try
                    {
                        var attr = File.GetAttributes(child);
                        if ((attr & FileAttributes.ReparsePoint) != 0) continue;
                        queue.Enqueue((child, depth + 1));
                    }
                    catch { }
                }
            }
            catch { }
        }
        return result;
    }

    private static (bool NonAscii, bool ValidUtf8, bool ReplacementCharacter, bool MojibakeRisk, string EncodingHint, string Bom, long Length)? InspectEncoding(string file)
    {
        try
        {
            var info = new FileInfo(file);
            if (!info.Exists || info.Length > 1024 * 1024) return null;
            var bytes = File.ReadAllBytes(file);
            var nonAscii = bytes.Any(b => b >= 0x80);
            var bom = bytes.Length >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF ? "UTF-8 BOM"
                : bytes.Length >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE ? "UTF-16 LE"
                : bytes.Length >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF ? "UTF-16 BE"
                : "Sin BOM";
            var validUtf8 = true;
            string decoded;
            try { decoded = new UTF8Encoding(false, true).GetString(bytes); }
            catch (DecoderFallbackException)
            {
                validUtf8 = false;
                decoded = Encoding.UTF8.GetString(bytes);
            }
            var replacement = decoded.Contains('\uFFFD');
            var mojibake = decoded.Contains("Ã", StringComparison.Ordinal) ||
                           decoded.Contains("Â", StringComparison.Ordinal) ||
                           decoded.Contains("â€", StringComparison.Ordinal) ||
                           replacement;
            var hint = bom.StartsWith("UTF-16", StringComparison.OrdinalIgnoreCase) ? bom
                : validUtf8 ? (bom == "UTF-8 BOM" ? "UTF-8 con BOM" : "UTF-8 válido / sin BOM")
                : nonAscii ? "No UTF-8; compatible con ANSI/codificación local" : "ASCII";
            return (nonAscii, validUtf8, replacement, mojibake, hint, bom, info.Length);
        }
        catch { return null; }
    }

    private static bool HasNonAscii(string? value) =>
        !string.IsNullOrEmpty(value) && value.Any(ch => ch > 127);
}
