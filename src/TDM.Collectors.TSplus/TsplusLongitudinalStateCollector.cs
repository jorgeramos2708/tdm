using System.Diagnostics;
using System.Security.Cryptography;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Registra cambios de metadatos de configuración y binarios/librerías TSplus relevantes.
/// No almacena contenido de configuraciones ni credenciales. El inventario está acotado
/// para poder ejecutarse periódicamente sin convertir TDM en una carga para el servidor.
/// </summary>
public sealed class TsplusLongitudinalStateCollector : IReadOnlyCollector
{
    private const int MaxDirectories = 256;
    private const int MaxFilesExamined = 6_000;
    private const int MaxRuntimeFiles = 120;
    private const long MaxHashBytes = 64L * 1024 * 1024;
    private readonly bool _calculateHashes;

    private static readonly string[] RuntimeTokens =
    [
        "wsession", "logon", "svcr", "html5", "httpwebs", "gateway", "apsc", "application",
        "printer", "remoteapp", "seamless", "twofactor", "security", "servermonitoring", "remotesupport"
    ];

    public TsplusLongitudinalStateCollector(bool calculateHashes = false) => _calculateHashes = calculateHashes;

    public string Nombre => _calculateHashes
        ? "Historial TSplus / integridad crítica"
        : "Historial TSplus / configuración crítica";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var roots = DiscoverRoots(context.Sistema).Distinct(StringComparer.OrdinalIgnoreCase).Where(path => FileSystemProbe.Directory(path).IsAvailable).ToList();
        var now = DateTimeOffset.Now;
        var examined = 0;
        var directories = 0;
        var accessErrors = 0;
        var configFound = 0;
        var runtimeFound = 0;
        var bounded = false;

        foreach (var root in roots)
        {
            foreach (var file in EnumerateFilesSafe(root, cancellationToken, ref examined, ref directories, ref accessErrors, ref bounded))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var name = Path.GetFileName(file);
                var descriptor = TsplusConfigurationArtifactCatalog.Find(name);
                if (descriptor is not null)
                {
                    configFound++;
                    var state = ReadFileState(file, _calculateHashes && !descriptor.Sensitive);
                    events.Add(new DiagnosticEvent(
                        now,
                        "TSplus Filesystem",
                        descriptor.Component,
                        DiagnosticLayer.Tsplus,
                        DiagnosticSeverity.Informativo,
                        "TSPLUS_LONGITUDINAL_CONFIG_STATE",
                        $"Estado longitudinal de configuración TSplus: {name}.",
                        Archivo: file,
                        Evidencia:
                        [
                            new EvidenceItem("Archivo", file),
                            new EvidenceItem("Nombre", name),
                            new EvidenceItem("Producto", descriptor.Product.ToString()),
                            new EvidenceItem("Componente", descriptor.Component),
                            new EvidenceItem("Presente", state.Exists ? "Sí" : "No"),
                            new EvidenceItem("Tamaño", state.Length.ToString()),
                            new EvidenceItem("Última modificación UTC", state.LastWriteUtc),
                            new EvidenceItem("SHA-256", descriptor.Sensitive ? "No calculado (artefacto sensible)" : state.Hash),
                            new EvidenceItem("Cobertura", state.Available ? "Disponible" : state.Detail)
                        ],
                        Producto: descriptor.Product));
                    AddModificationEvidence(events, file, state, descriptor.Component, descriptor.Product, context, now);
                    continue;
                }

                if (runtimeFound >= MaxRuntimeFiles || !IsCriticalRuntimeFile(file)) continue;
                runtimeFound++;
                var product = TsplusConfigurationArtifactCatalog.ClassifyProduct(file);
                var component = TsplusConfigurationArtifactCatalog.ClassifyComponent(file);
                var stateRuntime = ReadFileState(file, _calculateHashes);
                events.Add(new DiagnosticEvent(
                    now,
                    "TSplus Filesystem",
                    component,
                    DiagnosticLayer.Tsplus,
                    DiagnosticSeverity.Informativo,
                    "TSPLUS_LONGITUDINAL_LIBRARY_STATE",
                    $"Estado longitudinal de binario/librería TSplus: {name}.",
                    Archivo: file,
                    Evidencia:
                    [
                        new EvidenceItem("Archivo", file),
                        new EvidenceItem("Nombre", name),
                        new EvidenceItem("Producto", product.ToString()),
                        new EvidenceItem("Componente", component),
                        new EvidenceItem("Presente", stateRuntime.Exists ? "Sí" : "No"),
                        new EvidenceItem("Tamaño", stateRuntime.Length.ToString()),
                        new EvidenceItem("Última modificación UTC", stateRuntime.LastWriteUtc),
                        new EvidenceItem("Versión", stateRuntime.Version),
                        new EvidenceItem("SHA-256", stateRuntime.Hash),
                        new EvidenceItem("Cobertura", stateRuntime.Available ? "Disponible" : stateRuntime.Detail)
                    ],
                    Producto: product));
                AddModificationEvidence(events, file, stateRuntime, component, product, context, now);
            }
        }

        var coverage = roots.Count == 0
            ? (context.Sistema.TsplusDetectado ? "Parcial" : "No aplica")
            : accessErrors == 0 && !bounded ? "Completa" : "Parcial";

        events.Add(new DiagnosticEvent(
            now,
            "TDM",
            "Historial TSplus crítico",
            DiagnosticLayer.Tsplus,
            coverage is "Completa" or "No aplica" ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
            "TSPLUS_LONGITUDINAL_COVERAGE",
            $"Cobertura del inventario longitudinal TSplus: {coverage}.",
            Evidencia:
            [
                new EvidenceItem("Cobertura", coverage),
                new EvidenceItem("Raíces TSplus", roots.Count.ToString()),
                new EvidenceItem("Directorios examinados", directories.ToString()),
                new EvidenceItem("Archivos examinados", examined.ToString()),
                new EvidenceItem("Configuraciones conocidas", configFound.ToString()),
                new EvidenceItem("Binarios/librerías críticos", runtimeFound.ToString()),
                new EvidenceItem("Errores de acceso", accessErrors.ToString()),
                new EvidenceItem("Límite de inventario alcanzado", bounded ? "Sí" : "No"),
                new EvidenceItem("Hashes", _calculateHashes ? "Sí; salvo artefactos sensibles y archivos >64 MiB" : "No; muestra de estado"),
                new EvidenceItem("Privacidad", "No se persiste contenido de archivos de configuración")
            ],
            Producto: TsplusProduct.RemoteAccess));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void AddModificationEvidence(
        List<DiagnosticEvent> events,
        string file,
        FileState state,
        string component,
        TsplusProduct product,
        DiagnosticContext context,
        DateTimeOffset now)
    {
        if (!state.Available || !state.Exists || !DateTimeOffset.TryParse(state.LastWriteUtc, out var modifiedAt)) return;
        var windowEnd = context.HoraIncidente ?? now;
        var windowStart = windowEnd - context.Lookback;
        if (modifiedAt < windowStart || modifiedAt > windowEnd) return;
        events.Add(new DiagnosticEvent(
            modifiedAt,
            "TSplus Filesystem",
            component,
            DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo,
            "TSPLUS_FILE_MODIFICATION_EVIDENCE",
            "El metadato actual del archivo TSplus indica una modificación dentro de la ventana analizada.",
            Archivo: file,
            Evidencia:
            [
                new EvidenceItem("Archivo", file),
                new EvidenceItem("Última modificación UTC", modifiedAt.ToString("O")),
                new EvidenceItem("Versión actual", state.Version),
                new EvidenceItem("Limitación", "LastWriteTime es evidencia retrospectiva del archivo actual; no demuestra qué contenido existía antes de la modificación")
            ],
            Producto: product));
    }

    private static IEnumerable<string> DiscoverRoots(SystemSnapshot system)
    {
        if (!string.IsNullOrWhiteSpace(system.TsplusRuta)) yield return system.TsplusRuta!;
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        foreach (var baseDir in new[] { pf86, pf }.Where(x => !string.IsNullOrWhiteSpace(x)))
        foreach (var name in new[] { "TSplus", "TSplus-Security", "TSplus Advanced Security", "TSplus-ServerMonitoring", "TSplus Remote Support", "TSplus-RemoteSupport" })
        {
            var path = Path.Combine(baseDir, name);
            if (FileSystemProbe.Directory(path).IsAvailable) yield return path;
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(
        string root,
        CancellationToken ct,
        ref int filesExamined,
        ref int directoriesExamined,
        ref int accessErrors,
        ref bool bounded)
    {
        var output = new List<string>();
        var queue = new Queue<(string Path, int Depth)>();
        queue.Enqueue((root, 0));

        while (queue.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            if (directoriesExamined >= MaxDirectories || filesExamined >= MaxFilesExamined)
            {
                bounded = true;
                break;
            }

            var (dir, depth) = queue.Dequeue();
            directoriesExamined++;
            try
            {
                foreach (var file in Directory.EnumerateFiles(dir))
                {
                    filesExamined++;
                    if (filesExamined > MaxFilesExamined)
                    {
                        bounded = true;
                        break;
                    }
                    output.Add(file);
                }
                if (bounded) break;

                if (depth >= 4) continue;
                foreach (var child in Directory.EnumerateDirectories(dir))
                    queue.Enqueue((child, depth + 1));
            }
            catch (UnauthorizedAccessException) { accessErrors++; }
            catch (IOException) { accessErrors++; }
        }

        return output;
    }

    private static bool IsCriticalRuntimeFile(string path)
    {
        var extension = Path.GetExtension(path);
        if (!extension.Equals(".dll", StringComparison.OrdinalIgnoreCase)
            && !extension.Equals(".exe", StringComparison.OrdinalIgnoreCase)
            && !extension.Equals(".jar", StringComparison.OrdinalIgnoreCase))
            return false;
        return RuntimeTokens.Any(token => path.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    private static FileState ReadFileState(string path, bool hash)
    {
        try
        {
            var file = new FileInfo(path);
            if (!file.Exists) return new(true, false, 0, "N/D", "N/D", "N/D", "Disponible");
            var version = "N/D";
            try { version = FileVersionInfo.GetVersionInfo(path).FileVersion ?? "N/D"; } catch { }
            var sha = "No calculado";
            if (hash)
            {
                if (file.Length <= MaxHashBytes)
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    sha = Convert.ToHexString(SHA256.HashData(stream));
                }
                else sha = "Omitido (>64 MiB)";
            }
            return new(true, true, file.Length, file.LastWriteTimeUtc.ToString("O"), version, sha, "Disponible");
        }
        catch (UnauthorizedAccessException ex) { return new(false, FileSystemProbe.File(path).IsAvailable, 0, "N/D", "N/D", "N/D", "Acceso denegado: " + ex.Message); }
        catch (IOException ex) { return new(false, FileSystemProbe.File(path).IsAvailable, 0, "N/D", "N/D", "N/D", "Error de E/S: " + ex.Message); }
        catch (Exception ex) { return new(false, FileSystemProbe.File(path).IsAvailable, 0, "N/D", "N/D", "N/D", "Error de lectura: " + ex.Message); }
    }

    private sealed record FileState(bool Available, bool Exists, long Length, string LastWriteUtc, string Version, string Hash, string Detail);
}
