using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Security;

public sealed class TsplusFileIntegrityCollector : IReadOnlyCollector
{
    public string Nombre => "Integridad de archivos TSplus";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken)
    {
        var events = new List<DiagnosticEvent>();
        if (!context.Sistema.TsplusDetectado)
            return Task.FromResult(CollectorResult.Empty);

        var candidates = BuildCandidates(context.Sistema).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var metadataFailures = 0;
        foreach (var path in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var exists = FileSystemProbe.File(path).IsAvailable;
            var evidence = new List<EvidenceItem>
            {
                new("Archivo", path),
                new("Existe", exists ? "Sí" : "No")
            };

            if (exists)
            {
                try
                {
                    var info = new FileInfo(path);
                    var version = FileVersionInfo.GetVersionInfo(path);
                    evidence.Add(new("Tamaño", info.Length.ToString()));
                    evidence.Add(new("Última modificación", info.LastWriteTimeUtc.ToString("O")));
                    evidence.Add(new("Versión", version.FileVersion ?? "N/D"));
                    evidence.Add(new("Producto", version.ProductName ?? "N/D"));
                    evidence.Add(new("Firma", GetSignatureSubject(path)));
                }
                catch (Exception ex)
                {
                    metadataFailures++;
                    evidence.Add(new("Metadatos", "No disponibles: " + ex.Message));
                }
            }

            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now,
                "File System",
                "TSplus File Integrity",
                DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Informativo,
                exists ? "TSPLUS_FILE_PRESENT" : "TSPLUS_FILE_NOT_PRESENT",
                exists ? "Archivo TSplus observado en modo de solo lectura." : "Archivo candidato TSplus no está presente. Por sí solo esto no se considera falla; se requiere evidencia adicional.",
                Archivo: path,
                Evidencia: evidence));
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Integridad de archivos TSplus", DiagnosticLayer.Tsplus,
            metadataFailures > 0 ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "TSPLUS_FILE_INTEGRITY_COVERAGE",
            "Cobertura de integridad física de binarios/ejecutables TSplus candidatos.",
            Evidencia:
            [
                new EvidenceItem("Cobertura", metadataFailures > 0 ? "Parcial" : "Disponible"),
                new EvidenceItem("Archivos candidatos", candidates.Count.ToString()),
                new EvidenceItem("Metadatos no disponibles", metadataFailures.ToString()),
                new EvidenceItem("Interpretación", "La ausencia de un archivo candidato no se declara causa sin correlación adicional")
            ], Producto: TsplusProduct.RemoteAccess));

        return Task.FromResult(new CollectorResult([], events));
    }

    private static IEnumerable<string> BuildCandidates(SystemSnapshot system)
    {
        if (!string.IsNullOrWhiteSpace(system.TsplusRuta) && FileSystemProbe.Directory(system.TsplusRuta).IsAvailable)
        {
            foreach (var file in SafeEnumerateExecutables(system.TsplusRuta, 2)) yield return file;
        }

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        foreach (var name in new[] { "alternateshell.exe", "logonsession.exe", "removelastfolders.exe", "svcr.exe", "uninst.exe" })
            yield return Path.Combine(programData, name);

        foreach (var path in new[] { @"C:\wsession\logonsession.exe", @"C:\wsession\svcr.exe" })
            yield return path;
    }

    private static IEnumerable<string> SafeEnumerateExecutables(string root, int maxDepth)
    {
        var queue = new Queue<(string dir, int depth)>();
        queue.Enqueue((root, 0));
        var count = 0;

        while (queue.Count > 0 && count < 250)
        {
            var (dir, depth) = queue.Dequeue();
            string[] files;
            try { files = Directory.GetFiles(dir, "*.exe", SearchOption.TopDirectoryOnly); }
            catch { files = []; }

            foreach (var file in files)
            {
                yield return file;
                if (++count >= 250) yield break;
            }

            if (depth >= maxDepth) continue;
            string[] dirs;
            try { dirs = Directory.GetDirectories(dir); }
            catch { dirs = []; }
            foreach (var child in dirs) queue.Enqueue((child, depth + 1));
        }
    }

    private static string GetSignatureSubject(string path)
    {
        try
        {
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            return string.IsNullOrWhiteSpace(cert.Subject) ? "Firma presente" : cert.Subject;
        }
        catch { return "No determinada"; }
    }
}
