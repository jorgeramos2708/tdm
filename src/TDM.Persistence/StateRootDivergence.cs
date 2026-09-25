using TDM.Models;

namespace TDM.Persistence;

/// <summary>
/// Detecta divergencia servicio↔GUI: con el servicio vivo (heartbeat fresco) pero un
/// run en otra raíz, los historiales (transiciones, feedback, cursores) se bifurcan
/// en silencio. Puro y pineado por tests; el llamador aporta el heartbeat ya leído.
/// </summary>
public static class StateRootDivergence
{
    public static DiagnosticFinding? Evaluate(bool serviceActive, string? runRoot, string? machineRoot)
    {
        if (!serviceActive) return null;
        if (string.IsNullOrWhiteSpace(runRoot) || string.IsNullOrWhiteSpace(machineRoot)) return null;
        string run;
        string machine;
        try
        {
            run = Path.GetFullPath(runRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            machine = Path.GetFullPath(machineRoot).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch { return null; }
        if (run.Equals(machine, StringComparison.OrdinalIgnoreCase)) return null;
        return new DiagnosticFinding(
            "TDM-ROOT-DIVERGENCE",
            "Raíz de estado",
            DiagnosticSeverity.Advertencia,
            "Este diagnóstico usa una raíz de estado distinta a la del servicio activo.",
            "Con el servicio vivo en la raíz de máquina y este run en otra raíz, transiciones, feedback verificado y cursores se calculan contra historiales diferentes. Para una sola fuente de verdad, ejecute con el servicio detenido o configure la misma raíz.",
            [new EvidenceItem("Raíz del run", run),
             new EvidenceItem("Raíz del servicio", machine)],
            ConfidenceLevel.Alta,
            Capa: DiagnosticLayer.Desconocida);
    }
}
