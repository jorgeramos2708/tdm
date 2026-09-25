using System.Text;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Descubre evidencia forense ya existente sin modificar WER, LocalDumps ni la configuración del servidor.
/// </summary>
public sealed class ForensicArtifactCollector : IReadOnlyCollector
{
    public string Nombre => "Artefactos forenses existentes";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var events = new List<DiagnosticEvent>();
        var findings = new List<DiagnosticFinding>();
        var window = DiagnosticWindow.Resolve(context);
        var since = window.Start.LocalDateTime;
        var until = window.End.LocalDateTime;
        var roots = ExistingRoots();
        var examined = 0; var wer = 0; var dumps = 0; var logs = 0; var tsplus = 0;

        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (var file in EnumerateSafe(root, 2500))
            {
                cancellationToken.ThrowIfCancellationRequested();
                examined++;
                FileInfo fi;
                try { fi = new FileInfo(file); if (!fi.Exists || fi.LastWriteTime < since || fi.LastWriteTime > until) continue; }
                catch { continue; }
                var ext = fi.Extension.ToLowerInvariant();
                var isWer = ext == ".wer";
                var isDump = ext is ".dmp" or ".mdmp";
                var isLog = ext is ".log" or ".txt";
                if (!isWer && !isDump && !isLog) continue;
                var product = ProductFromPath(file);
                if (product != TsplusProduct.Ninguno) tsplus++;
                if (isWer) wer++; else if (isDump) dumps++; else logs++;

                var evidence = new List<EvidenceItem>
                {
                    new("Archivo", file), new("Última modificación", fi.LastWriteTime.ToString("O")),
                    new("Tamaño", fi.Length.ToString()), new("Producto inferido", product.ToString())
                };
                string message = isDump ? "Dump existente encontrado; TDM no lo modifica ni lo genera." :
                    isWer ? "Reporte WER existente encontrado." : "Log/texto forense reciente encontrado.";

                if ((isWer || isLog) && fi.Length <= 2_000_000)
                {
                    foreach (var item in ExtractTextEvidence(file).Take(8)) evidence.Add(item);
                }
                events.Add(new DiagnosticEvent(new DateTimeOffset(fi.LastWriteTime), "TDM", "Evidencia forense existente",
                    product == TsplusProduct.Ninguno ? DiagnosticLayer.Windows : DiagnosticLayer.Tsplus,
                    DiagnosticSeverity.Informativo, isDump ? "FORENSIC_DUMP_FOUND" : isWer ? "FORENSIC_WER_FOUND" : "FORENSIC_LOG_FOUND",
                    message, Archivo: file, Evidencia: evidence, Producto: product));
            }
        }

        events.Add(new DiagnosticEvent(DateTimeOffset.Now, "TDM", "Evidencia forense existente", DiagnosticLayer.Windows,
            DiagnosticSeverity.Informativo, "FORENSIC_ARTIFACT_SUMMARY", "Inventario de evidencia ya presente en el servidor.", Evidencia:
            [new("Raíces inspeccionadas", roots.Count.ToString()), new("Archivos examinados", examined.ToString()),
             new("WER recientes", wer.ToString()), new("Dumps recientes", dumps.ToString()), new("Logs/textos recientes", logs.ToString()),
             new("Artefactos relacionados con TSplus", tsplus.ToString()),
             new("Modo", "Solo lectura; no habilita LocalDumps/WER ni crea capturas") ]));
        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static List<string> ExistingRoots()
    {
        string pd = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        string la = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var candidates = new[]
        {
            Path.Combine(pd, "Microsoft", "Windows", "WER", "ReportArchive"),
            Path.Combine(pd, "Microsoft", "Windows", "WER", "ReportQueue"),
            Path.Combine(la, "CrashDumps"),
            Path.Combine(pf86, "TSplus"), Path.Combine(pf86, "TSplus-Security"),
            Path.Combine(pf86, "TSplus-ServerMonitoring"), Path.Combine(pf86, "TSplus-RemoteSupport"), @"C:\wsession"
        };
        return candidates.Where(Directory.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static IEnumerable<string> EnumerateSafe(string root, int max)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        var count = 0;

        while (stack.Count > 0 && count < max)
        {
            var dir = stack.Pop();

            string[] files;
            try
            {
                files = Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                files = [];
            }

            foreach (var file in files)
            {
                yield return file;
                count++;
                if (count >= max) yield break;
            }

            string[] directories;
            try
            {
                directories = Directory.GetDirectories(dir, "*", SearchOption.TopDirectoryOnly);
            }
            catch
            {
                directories = [];
            }

            foreach (var child in directories.Take(200))
                stack.Push(child);
        }
    }

    private static IEnumerable<EvidenceItem> ExtractTextEvidence(string file)
    {
        string[] keys = ["AppName=", "AppPath=", "Fault Module", "Exception", "ExceptionCode=", "ReportIdentifier=", "Sig[", "stack", "error", "exception"];
        string[] lines;
        try
        {
            lines = File.ReadLines(file, Encoding.UTF8).Take(500).ToArray();
        }
        catch
        {
            lines = [];
        }

        foreach (var line in lines.Where(l => keys.Any(k => l.Contains(k, StringComparison.OrdinalIgnoreCase))).Take(8))
            yield return new EvidenceItem("Señal de archivo", Sanitize(line));
    }

    private static string Sanitize(string s)
    {
        if (s.Length > 300) s = s[..300];
        // Evita exponer claves de activación si algún log las contuviera.
        if (s.Contains("activation key", StringComparison.OrdinalIgnoreCase) || s.Contains("license key", StringComparison.OrdinalIgnoreCase)) return "[dato de licencia omitido]";
        return s;
    }

    private static TsplusProduct ProductFromPath(string path)
    {
        if (path.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.ServerMonitoring;
        if (path.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.AdvancedSecurity;
        if (path.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteSupport;
        if (path.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.TwoFactorAuthentication;
        if (path.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || path.Contains("wsession", StringComparison.OrdinalIgnoreCase)) return TsplusProduct.RemoteAccess;
        return TsplusProduct.Ninguno;
    }
}
