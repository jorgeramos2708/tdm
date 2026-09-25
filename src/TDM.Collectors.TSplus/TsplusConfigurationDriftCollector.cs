using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Estado de línea base de configuración TSplus para detección de deriva.
/// P1-05: público para uso por ConfigurationHistoryStore.
/// </summary>
public sealed record ConfigBaselineState(
    Dictionary<string, string> Hashes,
    DateTimeOffset SavedAt,
    Dictionary<string, Dictionary<string, List<string>>>? IniStructure = null,
    Dictionary<string, string>? Registry = null);

/// <summary>
/// Deriva de configuración TSplus: snapshot versionado (SHA-256) de los archivos críticos de
/// configuración y comparación contra la ejecución anterior. Responde "qué cambió" sin
/// interpretar el contenido. Solo lectura de archivos + cursor durable propio; jamás escribe
/// configuración. Sin línea base previa la crea y lo declara (primera ejecución no es drift).
/// P1-05: Soporte multi-generación para diff histórico via ConfigurationHistoryStore.
/// </summary>
public sealed class TsplusConfigurationDriftCollector : IReadOnlyCollector
{
    public string Nombre => "Deriva de configuración TSplus";

    private const string BaselineKey = "tsplus-config-baseline";
    private const long MaxHashBytes = 1024 * 1024;

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        try
        {
            var install = context.Sistema.TsplusRuta;
            if (!context.Sistema.TsplusDetectado || string.IsNullOrWhiteSpace(install))
                return Task.FromResult(new CollectorResult(findings, events));

            var candidates = new List<string>
            {
                Path.Combine(install, "UserDesktop", "files", "AppControl.ini"),
                Path.Combine(install, "UserDesktop", "AppControl.ini"),
                Path.Combine(install, "Clients", "webserver", "runwebserver.bat"),
                Path.Combine(install, "Clients", "www", "software", "html5", "settings.js")
            };

            var current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var currentIni = new Dictionary<string, Dictionary<string, List<string>>>(StringComparer.OrdinalIgnoreCase);
            var evidence = new List<EvidenceItem>();
            foreach (var path in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Lectura única por archivo: del mismo buffer salen el hash y la
                // estructura de claves (una segunda lectura podría ver otro instante).
                if (!TryReadFile(path, out var bytes, out var note))
                {
                    evidence.Add(new EvidenceItem(ShortName(path), note));
                    continue;
                }
                var hash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                current[path] = hash;
                evidence.Add(new EvidenceItem(ShortName(path), $"SHA-256 {hash[..12]}…"));
                if (IsIniArtifact(path))
                    currentIni[path] = TsplusConfigSemanticDiff.ParseIniKeys(Encoding.Latin1.GetString(bytes));
            }

            var registry = SnapshotRegistry(out var registryNote);

            if (!CollectorCursorStore.TryLoad<ConfigBaselineState>("tsplus-config-baseline", out var baseline, out _) || baseline?.Hashes is null)
            {
                var baselineInit = new ConfigBaselineState(current, DateTimeOffset.Now, currentIni, registry);
                ConfigurationHistoryStore.Instance.SaveAsync(baselineInit, cancellationToken);
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now, "TDM", "Línea base de configuración TSplus", DiagnosticLayer.Tsplus,
                    DiagnosticSeverity.Informativo, "TSPLUS_CONFIG_BASELINE_INITIALIZED",
                    "Se guardó la línea base inicial de configuración; la próxima ejecución comparará contra ella. No indica cambio alguno.",
                    Evidencia: evidence, Producto: TsplusProduct.RemoteAccess));
                return Task.FromResult(new CollectorResult(findings, events));
            }

            var added = current.Keys.Except(baseline.Hashes.Keys, StringComparer.OrdinalIgnoreCase).Take(8).ToList();
            var removed = baseline.Hashes.Keys.Except(current.Keys, StringComparer.OrdinalIgnoreCase).Take(8).ToList();
            var changed = current
                .Where(kv => baseline.Hashes.TryGetValue(kv.Key, out var previous) && !previous.Equals(kv.Value, StringComparison.OrdinalIgnoreCase))
                .Select(kv => kv.Key).Take(8).ToList();

            // P1-semántico: QUÉ ajuste cambió (claves agregadas/eliminadas, nunca valores).
            // Solo si la línea base previa ya trae estructura; una base antigua la
            // inicializa sin comparar para no declarar drift espurio.
            var semanticChanges = baseline.IniStructure is null
                ? new List<TsplusConfigSemanticDiff.KeyChange>()
                : TsplusConfigSemanticDiff.DiffIni(baseline.IniStructure, currentIni).ToList();
            var regAdded = new List<string>();
            var regRemoved = new List<string>();
            var regChanged = new List<string>();
            if (baseline.Registry is not null)
            {
                regAdded = registry.Keys.Except(baseline.Registry.Keys, StringComparer.OrdinalIgnoreCase).Take(8).ToList();
                regRemoved = baseline.Registry.Keys.Except(registry.Keys, StringComparer.OrdinalIgnoreCase).Take(8).ToList();
                regChanged = registry
                    .Where(kv => baseline.Registry.TryGetValue(kv.Key, out var prev) && !prev.Equals(kv.Value, StringComparison.OrdinalIgnoreCase))
                    .Select(kv => kv.Key).Take(8).ToList();
            }

            if (added.Count + removed.Count + changed.Count > 0)
            {
                var driftEvidence = new List<EvidenceItem>(evidence)
                {
                    new("Archivos agregados", added.Count == 0 ? "Ninguno" : string.Join(" | ", added.Select(ShortName))),
                    new("Archivos eliminados", removed.Count == 0 ? "Ninguno" : string.Join(" | ", removed.Select(ShortName))),
                    new("Archivos modificados", changed.Count == 0 ? "Ninguno" : string.Join(" | ", changed.Select(ShortName))),
                    new("Cambios semánticos (claves)", semanticChanges.Count == 0 ? "Ninguno" : TsplusConfigSemanticDiff.Summarize(semanticChanges)),
                    new("Horas de cambio (UTC)", ChangeTimesEvidence(added, changed)),
                    new("Registro TSplus", registryNote + (baseline.Registry is null ? "; línea base inicializada" : ""))
                };
                findings.Add(new DiagnosticFinding(
                    "TSPLUS-CONFIG-DRIFT",
                    "Configuración TSplus",
                    DiagnosticSeverity.Advertencia,
                    $"Se detectaron cambios en archivos de configuración respecto a la muestra anterior ({added.Count + removed.Count + changed.Count}).",
                    "Un cambio de configuración no es una falla por sí solo, pero es el primer sospechoso cuando el síntoma coincide en tiempo. Valide si hubo actualización, edición manual o cambio autorizado antes de atribuir el incidente a otra capa.",
                    driftEvidence,
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Tsplus));
            }
            else
            {
                events.Add(new DiagnosticEvent(
                    DateTimeOffset.Now, "TDM", "Deriva de configuración TSplus", DiagnosticLayer.Tsplus,
                    DiagnosticSeverity.Informativo, "TSPLUS_CONFIG_STABLE",
                    "Los archivos críticos de configuración coinciden con la muestra anterior.",
                    Evidencia: evidence, Producto: TsplusProduct.RemoteAccess));
            }

            if (baseline.Registry is not null && regAdded.Count + regRemoved.Count + regChanged.Count > 0)
            {
                findings.Add(new DiagnosticFinding(
                    "TSPLUS-CONFIG-DRIFT-REGISTRY",
                    "Configuración TSplus (registro)",
                    DiagnosticSeverity.Advertencia,
                    $"Se detectaron cambios en valores del registro de TSplus ({regAdded.Count + regRemoved.Count + regChanged.Count}).",
                    "El registro conserva buena parte de la configuración efectiva de TSplus. Solo se comparan rutas y huellas, nunca contenidos. Valide si hubo actualización o edición (AdminTool/regedit) antes de atribuir el incidente a otra capa.",
                    [new EvidenceItem("Valores agregados", regAdded.Count == 0 ? "Ninguno" : string.Join(" | ", regAdded)),
                     new EvidenceItem("Valores eliminados", regRemoved.Count == 0 ? "Ninguno" : string.Join(" | ", regRemoved)),
                     new EvidenceItem("Valores modificados", regChanged.Count == 0 ? "Ninguno" : string.Join(" | ", regChanged)),
                     new EvidenceItem("Nota", registryNote)],
                    ConfidenceLevel.Media,
                    Capa: DiagnosticLayer.Tsplus));
            }

            var baselineFinal = new ConfigBaselineState(current, DateTimeOffset.Now, currentIni, registry);
            // P1-05: Save to history store for multi-generation diff
            ConfigurationHistoryStore.Instance.SaveAsync(baselineFinal, cancellationToken);
            return Task.FromResult(new CollectorResult(findings, events));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-CONFIG-DRIFT-COVERAGE",
                "Deriva de configuración TSplus",
                DiagnosticSeverity.Advertencia,
                "No fue posible evaluar la deriva de configuración en esta muestra.",
                ex.Message,
                [new EvidenceItem("Cobertura", "No evaluado")],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
            return Task.FromResult(new CollectorResult(findings, events));
        }
    }

    private static bool TryReadFile(string path, out byte[] bytes, out string note)
    {
        bytes = [];
        note = "No presente / no legible";
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return false;
            if (info.Length > MaxHashBytes)
            {
                note = $"Omitido por tamaño ({info.Length} bytes > {MaxHashBytes})";
                return false;
            }
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
            using var memory = new MemoryStream((int)Math.Min(info.Length, MaxHashBytes) + 1);
            stream.CopyTo(memory);
            bytes = memory.ToArray();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            note = "No legible: " + ex.Message;
            return false;
        }
    }

    private static bool IsIniArtifact(string path)
    {
        try { return Path.GetFileName(path).Equals("AppControl.ini", StringComparison.OrdinalIgnoreCase); }
        catch { return false; }
    }

    /// <summary>
    /// Horas a las que cambió cada archivo (modificación; creación para agregados) en
    /// formato "archivo|ISO; ..." para la regla de proximidad del correlador.
    /// </summary>
    private static string ChangeTimesEvidence(IReadOnlyList<string> added, IReadOnlyList<string> changed)
    {
        var parts = new List<string>();
        foreach (var path in changed)
        {
            try { parts.Add($"{ShortName(path)}|{File.GetLastWriteTimeUtc(path):O}"); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        foreach (var path in added)
        {
            try { parts.Add($"{ShortName(path)}|{new FileInfo(path).CreationTimeUtc:O}"); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return parts.Count == 0 ? "Ninguna determinable" : string.Join("; ", parts);
    }

    /// <summary>
    /// Snapshot de estructura del registro TSplus (rutas + huellas, nunca contenidos).
    /// Acotado en profundidad, valores y subclaves. Nunca lanza: ante falta de acceso
    /// devuelve vacío con nota NO EVALUADO.
    /// </summary>
    private static Dictionary<string, string> SnapshotRegistry(out string note)
    {
        var snapshot = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var examined = 0;
        const int maxValues = 500;
        try
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var root = baseKey.OpenSubKey("SOFTWARE\\TSplus", writable: false);
                if (root is null) continue;
                CollectRegistryValues(root, view + "\\SOFTWARE\\TSplus", snapshot, ref examined, maxValues, depth: 0);
                if (examined >= maxValues) break;
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            note = "No legible: " + ex.Message;
            return snapshot;
        }
        note = examined == 0 ? "No evaluado" : $"Examinados {examined} valores (tope {maxValues})";
        return snapshot;
    }

    private static void CollectRegistryValues(RegistryKey key, string path, Dictionary<string, string> snapshot, ref int examined, int maxValues, int depth)
    {
        if (depth > 4 || examined >= maxValues) return;
        try
        {
            foreach (var name in key.GetValueNames())
            {
                if (examined >= maxValues) break;
                var value = key.GetValue(name);
                snapshot[path + "\\" + name] = TsplusConfigSemanticDiff.FingerprintRegistryValue(key.GetValueKind(name), value);
                examined++;
            }
            foreach (var sub in key.GetSubKeyNames())
            {
                if (examined >= maxValues) break;
                try
                {
                    using var child = key.OpenSubKey(sub, writable: false);
                    if (child is not null) CollectRegistryValues(child, path + "\\" + sub, snapshot, ref examined, maxValues, depth + 1);
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException) { }
    }

    private static string ShortName(string path)
    {
        try
        {
            var file = Path.GetFileName(path);
            if (!string.IsNullOrWhiteSpace(file)) return file;
        }
        catch { }
        return path;
    }
}