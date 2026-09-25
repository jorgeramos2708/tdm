using TDM.Models;

namespace TDM.Reporting;

public sealed record CausalResponsibility(
    string OrigenGeneral,
    string OriginadorEspecifico,
    string RolTsplus,
    string RolWindows,
    string ComponenteAfectado,
    string EtiquetaOrigen = "CANDIDATO");

public static class CausalResponsibilityFormatter
{
    public static CausalResponsibility Resolve(RootCauseCandidate? candidate)
    {
        if (candidate is null)
            return new("INDETERMINADO", "No determinado", "No determinado", "No determinado", "No determinado", "SIN ORIGEN CONFIRMADO");

        var general = string.IsNullOrWhiteSpace(candidate.OrigenClasificado) ? "INDETERMINADO" : candidate.OrigenClasificado.ToUpperInvariant();
        var specific = Evidence(candidate, "Originador específico");
        if (string.IsNullOrWhiteSpace(specific) || specific.Equals("N/D", StringComparison.OrdinalIgnoreCase) ||
            general == "TSPLUS" && IsCommonWindowsFaultModule(specific))
            specific = InferSpecific(candidate, general);

        var affected = ProductName(candidate.Producto);
        if (candidate.Producto is TsplusProduct.Ninguno or TsplusProduct.Desconocido)
            affected = candidate.Componente;

        var ranking = Evidence(candidate, "Estado de ranking");
        var label = candidate.RolCausal.Equals("IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO", StringComparison.OrdinalIgnoreCase)
            ? "IMPACTO DIRECTO · CAUSA NO DEMOSTRADA"
            : ranking?.Contains("EMPATE_TECNICO", StringComparison.OrdinalIgnoreCase) == true
                ? "HIPÓTESIS COMPETITIVAS"
                : candidate.Confianza switch
                {
                    ConfidenceLevel.Confirmada => "ORIGINADOR CONFIRMADO",
                    ConfidenceLevel.Alta => "ORIGEN MÁS SUSTENTADO",
                    ConfidenceLevel.Media => "CANDIDATO PRINCIPAL",
                    _ => "HIPÓTESIS"
                };

        return general switch
        {
            "TSPLUS" => new(general, specific, label, "Sin falla causal demostrada", affected, label),
            "WINDOWS" => new(general, specific, "VÍCTIMA / AFECTADO", label, affected, label),
            "DEPENDENCIA EXTERNA" or "EXTERNO" => new("EXTERNO", specific, "VÍCTIMA / AFECTADO", "No demostrado como origen", affected, label),
            _ => new("INDETERMINADO", specific, "POSIBLE ORIGEN / AFECTADO", "POSIBLE ORIGEN / NO DETERMINADO", affected, "HIPÓTESIS")
        };
    }

    private static string InferSpecific(RootCauseCandidate c, string general)
    {
        var text = $"{c.Componente} {c.Resumen} {c.Explicacion} " + string.Join(" ", c.Evidencia.Select(e => $"{e.Clave}={e.Valor}"));

        if (general == "TSPLUS")
        {
            foreach (var key in new[] { "Componente semántico", "Componente interno observado", "Primer frame no framework", "Origen técnico más bajo sustentado" })
            {
                var value = Evidence(c, key);
                if (!string.IsNullOrWhiteSpace(value) && !value.Equals("N/D", StringComparison.OrdinalIgnoreCase) && !IsCommonWindowsFaultModule(value))
                    return value;
            }
            return c.Componente;
        }
        string[] products =
        [
            "Microsoft Defender", "CrowdStrike", "SentinelOne", "Sophos", "ESET", "Trend Micro",
            "McAfee", "Bitdefender", "Carbon Black", "Fortinet", "Palo Alto", "Zscaler", "Symantec"
        ];
        foreach (var product in products)
            if (text.Contains(product, StringComparison.OrdinalIgnoreCase)) return product;

        foreach (var key in new[] { "Dependencia detectada", "Dependencia", "Módulo con error", "Módulo", "Archivo" })
        {
            var value = Evidence(c, key);
            if (string.IsNullOrWhiteSpace(value) || value.Equals("N/D", StringComparison.OrdinalIgnoreCase) || value.Equals("unknown", StringComparison.OrdinalIgnoreCase)) continue;
            try
            {
                var file = Path.GetFileName(value);
                if (!string.IsNullOrWhiteSpace(file) && file.Contains('.')) return file;
            }
            catch { }
        }

        return c.Componente;
    }

    private static bool IsCommonWindowsFaultModule(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        string[] common = ["KERNELBASE.dll", "ntdll.dll", "kernel32.dll", "ucrtbase.dll", "msvcrt.dll"];
        var file = value;
        try { file = Path.GetFileName(value); } catch { }
        return common.Contains(file, StringComparer.OrdinalIgnoreCase);
    }

    private static string Evidence(RootCauseCandidate c, string key) =>
        c.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";

    private static string ProductName(TsplusProduct product) => product switch
    {
        TsplusProduct.RemoteAccess => "TSplus Remote Access",
        TsplusProduct.TwoFactorAuthentication => "TSplus 2FA",
        TsplusProduct.AdvancedSecurity => "TSplus Advanced Security",
        TsplusProduct.ServerMonitoring => "TSplus Server Monitoring",
        TsplusProduct.RemoteSupport => "TSplus Remote Support",
        _ => "TSplus"
    };
}
