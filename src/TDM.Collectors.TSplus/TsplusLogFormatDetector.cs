using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Detector de formato desconocido por archivo: si un volumen relevante de un SOLO
/// archivo no produce eventos, el formato de ese archivo (p. ej. nueva versión TSplus)
/// puede requerir un perfil de parseo nuevo. El umbral global del collector mezcla
/// todos los archivos y no señala al responsable. Puro y pineado por tests.
/// </summary>
public static class TsplusLogFormatDetector
{
    public const int MinLines = 200;
    public const double MinUnparsedRatio = 0.8;
    public const int MaxFiles = 5;

    public static IReadOnlyList<DiagnosticFinding> Evaluate(IReadOnlyDictionary<string, (long Total, long Unparsed)> perFile)
    {
        var findings = new List<DiagnosticFinding>();
        foreach (var kv in perFile.OrderByDescending(x => x.Value.Unparsed).Take(MaxFiles))
        {
            if (kv.Value.Total < MinLines) continue;
            var ratio = (double)kv.Value.Unparsed / kv.Value.Total;
            if (ratio < MinUnparsedRatio) continue;
            findings.Add(new DiagnosticFinding(
                "TSPLUS-LOG-UNKNOWN-FORMAT",
                "Logs TSplus",
                DiagnosticSeverity.Advertencia,
                $"El archivo {ShortName(kv.Key)} aporta {kv.Value.Unparsed}/{kv.Value.Total} líneas sin evento ({ratio:P0}).",
                "Un solo archivo con volumen relevante y cobertura casi nula sugiere formato no reconocido por el parser actual (p. ej. nueva versión TSplus), no solo líneas sanas. Los síntomas de ese componente quedan parcialmente ciegos.",
                [new EvidenceItem("Archivo", kv.Key),
                 new EvidenceItem("Líneas leídas", kv.Value.Total.ToString()),
                 new EvidenceItem("Líneas sin evento", kv.Value.Unparsed.ToString()),
                 new EvidenceItem("Proporción", ratio.ToString("P1"))],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
        }
        return findings;
    }

    private static string ShortName(string path)
    {
        try { var file = Path.GetFileName(path); if (!string.IsNullOrWhiteSpace(file)) return file; }
        catch { }
        return path;
    }
}
