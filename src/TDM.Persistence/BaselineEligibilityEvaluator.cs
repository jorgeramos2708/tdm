using TDM.Models;

namespace TDM.Persistence;

public sealed record BaselineEligibilityAssessment(
    bool Eligible,
    string Reason,
    int SeriousFindings,
    int UnhealthyModules,
    int CrashLoops,
    int StableObservations,
    IReadOnlyList<string> MissingRequiredTypes);

/// <summary>
/// Aplica una única política de seguridad para fijar un baseline sano, tanto desde GUI como CLI.
/// El baseline sólo puede crearse con evidencia suficiente y sin señales activas de falla grave.
/// </summary>
public static class BaselineEligibilityEvaluator
{
    private static readonly string[] RequiredCurrentStateTypes =
    [
        "RDP_STATE",
        "TSPLUS_DEPENDENCY_HEALTH",
        "TSPLUS_PRODUCT_STATE"
    ];

    public static BaselineEligibilityAssessment Evaluate(DiagnosticReport? report, PersistentStateSnapshot? state)
    {
        if (report is null || state is null)
            return new(false, "Ejecuta un diagnóstico completo antes de establecer el baseline.", 0, 0, 0, 0, []);

        if (!report.Sistema.TsplusDetectado)
            return new(false, "Baseline no disponible: TSplus Remote Access no fue detectado.", 0, 0, 0, 0, []);

        var serious = report.Hallazgos.Count(f => f.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico);
        var unhealthyModules = report.Eventos.Count(e =>
            e.Tipo.Equals("TSPLUS_MODULE_HEALTH_STATE", StringComparison.OrdinalIgnoreCase) &&
            e.Severidad is DiagnosticSeverity.Error or DiagnosticSeverity.Critico);
        var crashLoops = report.Eventos.Count(e => e.Tipo.Equals("TSPLUS_CRASH_LOOP_PATTERN", StringComparison.OrdinalIgnoreCase));
        var stable = state.Observations.Count(o => o.BaselineEligible);
        var missing = RequiredCurrentStateTypes
            .Where(type => !report.Eventos.Any(e => e.Tipo.Equals(type, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        if (serious > 0 || unhealthyModules > 0 || crashLoops > 0)
        {
            return new(false,
                $"Baseline bloqueado: Error/Crítico={serious}, módulos no saludables={unhealthyModules}, crash-loop={crashLoops}. Investigue antes de fijar este estado como sano.",
                serious, unhealthyModules, crashLoops, stable, missing);
        }

        if (missing.Length > 0)
        {
            return new(false,
                "Baseline bloqueado por cobertura insuficiente. Falta: " + string.Join(", ", missing),
                serious, unhealthyModules, crashLoops, stable, missing);
        }

        if (stable < 3)
        {
            return new(false,
                $"Baseline bloqueado: sólo hay {stable} observaciones estables elegibles.",
                serious, unhealthyModules, crashLoops, stable, missing);
        }

        return new(true,
            $"Elegible para baseline sano · {stable} observaciones estables · confirme que el servidor opera normalmente.",
            serious, unhealthyModules, crashLoops, stable, missing);
    }
}
