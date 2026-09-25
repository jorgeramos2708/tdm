using System.Text;
using TDM.Models;

namespace TDM.Reporting;

public static class InvestigationGuidanceBuilder
{
    public static string State(RootCauseCandidate? c)
    {
        if (c is null) return "INDETERMINADA";
        if (c.Confianza == ConfidenceLevel.Alta)
        {
            string EV(string key) => c.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
            var coverageIncomplete = EV("Cobertura crítica legible").Equals("No", StringComparison.OrdinalIgnoreCase);
            var noIndependent = EV("Evidencia primaria independiente").Equals("No", StringComparison.OrdinalIgnoreCase);
            if (coverageIncomplete || noIndependent) return "SUSTENTADA CON LIMITACIONES";
        }
        return c.Confianza switch
        {
            ConfidenceLevel.Confirmada => "CONFIRMADA",
            ConfidenceLevel.Alta => "ALTAMENTE SUSTENTADA",
            ConfidenceLevel.Media => "PROBABLE",
            _ => "INDETERMINADA"
        };
    }

    public static void Append(StringBuilder sb, DiagnosticReport report, RootCauseCandidate? c)
    {
        var state = State(c);
        sb.AppendLine($"ESTADO DE INVESTIGACIÓN: {state}");
        sb.AppendLine();
        AppendActionScope(sb, c);
        sb.AppendLine();
        switch (state)
        {
            case "CONFIRMADA":
                sb.AppendLine("QUÉ HACER AHORA:");
                sb.AppendLine("  La evidencia disponible permite actuar sobre la causa identificada sin perseguir componentes no relacionados.");
                if (!string.IsNullOrWhiteSpace(c?.SolucionSugerida)) sb.AppendLine($"  - {c.SolucionSugerida}");
                else sb.AppendLine("  - Corrige primero el componente causal indicado y evita reinstalaciones/cambios fuera de esa cadena.");
                sb.AppendLine("  - Después de la corrección, ejecuta TDM nuevamente y valida que desaparezcan el evento causal y sus síntomas posteriores.");
                break;
            case "ALTAMENTE SUSTENTADA":
            case "SUSTENTADA CON LIMITACIONES":
                sb.AppendLine("QUÉ FALTA PARA CONFIRMAR:");
                sb.AppendLine("  La evidencia converge en este candidato, pero falta una prueba causal independiente.");
                AppendAutomaticEvidenceSearch(sb, report, c);
                AppendOriginDirectedGuidance(sb, report, c);
                AppendMissingEvidence(sb, report, c);
                sb.AppendLine("  TDM debe volver a correlacionar esa evidencia antes de recomendar una reparación definitiva.");
                break;
            case "PROBABLE":
                sb.AppendLine("ARGUMENTOS Y SIGUIENTE PASO:");
                sb.AppendLine("  Existen indicios relevantes, pero todavía hay explicaciones alternativas.");
                if (c is not null) sb.AppendLine($"  - A favor: {c.Explicacion}");
                if (c is not null) sb.AppendLine($"  - Origen actualmente clasificado: {c.OrigenClasificado}.");
                sb.AppendLine("  - No modifiques todavía TSplus ni Windows basándote sólo en esta hipótesis.");
                AppendOriginDirectedGuidance(sb, report, c);
                AppendMissingEvidence(sb, report, c);
                break;
            default:
                sb.AppendLine("CÓMO CONTINUAR:");
                sb.AppendLine("  TDM no encontró evidencia suficiente para señalar responsable.");
                sb.AppendLine("  - Si el incidente queda cerca del inicio del periodo, selecciona un periodo mayor en el menú «Periodo de investigación».");
                sb.AppendLine("  - Reproduce el síntoma si es seguro y vuelve a ejecutar el diagnóstico con el periodo mínimo que incluya el incidente y sus antecedentes.");
                sb.AppendLine("  - Revisa la sección Diagnóstico forense: un canal no disponible puede contener la evidencia faltante.");
                sb.AppendLine("  - Si el límite de evidencia es un crash de proceso, un dump/stack solicitado por soporte puede ser necesario para confirmar la causa primaria.");
                break;
        }
    }

    private static void AppendActionScope(StringBuilder sb, RootCauseCandidate? c)
    {
        sb.AppendLine("DÓNDE EMPEZAR / QUÉ NO TOCAR:");
        if (c is null)
        {
            sb.AppendLine("  - Inicio: no aplicar correcciones todavía; primero identifica un candidato causal dentro del periodo seleccionado.");
            sb.AppendLine("  - No tocar: Windows ni TSplus de forma indiscriminada sin evidencia que justifique el cambio.");
            return;
        }

        string EV(string key) => c.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
        var semantic = EV("Componente semántico");
        switch (c.OrigenClasificado)
        {
            case "WINDOWS":
                sb.AppendLine($"  - Inicio: Windows / {c.Componente}. Valida y corrige primero la dependencia subyacente demostrada.");
                sb.AppendLine("  - No tocar primero: no reinstales ni reconfigures TSplus mientras la falla Windows siga vigente.");
                break;
            case "TSPLUS":
                sb.AppendLine($"  - Inicio: {ProductName(c.Producto)} / {(semantic == "N/D" ? c.Componente : semantic)}.");
                sb.AppendLine("  - No tocar primero: RDP, RPC, Spooler, WMI u otros componentes generales de Windows sin un antecedente causal que los implique.");
                break;
            case "DEPENDENCIA EXTERNA":
                sb.AppendLine($"  - Inicio: dependencia externa señalada ({c.Componente}); confirma archivo/assembly/driver, versión e integridad.");
                sb.AppendLine("  - No tocar primero: no repares Windows ni reinstales TSplus de forma general antes de validar esa dependencia.");
                break;
            default:
                sb.AppendLine("  - Inicio: obtén evidencia discriminante antes de elegir Windows o TSplus como frente de corrección.");
                sb.AppendLine("  - No tocar: no apliques cambios correctivos a ninguno de los dos lados mientras el origen siga indeterminado.");
                break;
        }
    }

    private static string ProductName(TsplusProduct p) => p switch
    {
        TsplusProduct.RemoteAccess => "TSplus Remote Access",
        TsplusProduct.TwoFactorAuthentication => "TSplus 2FA",
        TsplusProduct.AdvancedSecurity => "TSplus Advanced Security",
        TsplusProduct.ServerMonitoring => "TSplus Server Monitoring",
        TsplusProduct.RemoteSupport => "TSplus Remote Support",
        _ => "TSplus"
    };

    private static void AppendAutomaticEvidenceSearch(StringBuilder sb, DiagnosticReport report, RootCauseCandidate? c)
    {
        var artifacts = report.Eventos.Where(e => e.Tipo is "FORENSIC_WER_FOUND" or "FORENSIC_DUMP_FOUND" or "FORENSIC_LOG_FOUND").ToList();
        var related = c is null ? [] : artifacts.Where(e =>
            e.Componente.Contains(c.Componente, StringComparison.OrdinalIgnoreCase) ||
            e.Mensaje.Contains(c.Componente, StringComparison.OrdinalIgnoreCase) ||
            (e.Evidencia?.Any(x => x.Valor.Contains(c.Componente, StringComparison.OrdinalIgnoreCase)) ?? false) ||
            (c.Producto != TsplusProduct.Ninguno && e.Producto == c.Producto)).ToList();
        sb.AppendLine("  BÚSQUEDA AUTOMÁTICA DE EVIDENCIA YA EXISTENTE:");
        sb.AppendLine($"    - WER encontrados: {related.Count(e => e.Tipo == "FORENSIC_WER_FOUND")}");
        sb.AppendLine($"    - Dumps encontrados: {related.Count(e => e.Tipo == "FORENSIC_DUMP_FOUND")}");
        sb.AppendLine($"    - Logs/textos recientes: {related.Count(e => e.Tipo == "FORENSIC_LOG_FOUND")}");
        if (related.Count == 0) sb.AppendLine("    - No se encontró artefacto local adicional que permita elevar la hipótesis a CONFIRMADA.");
    }

    private static void AppendOriginDirectedGuidance(StringBuilder sb, DiagnosticReport report, RootCauseCandidate? c)
    {
        if (c is null) return;
        string EV(string key) => c.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
        var semantic = EV("Componente semántico");
        var origin = c.OrigenClasificado;

        sb.AppendLine("  ORIENTACIÓN DE INVESTIGACIÓN:");
        if (origin == "TSPLUS")
        {
            sb.AppendLine("    - Comienza en el producto/componente TSplus señalado; TDM no encontró una falla Windows fuerte previa que justifique reparar el SO primero.");
            if (semantic.Contains("Advanced Security / Firewall", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine("    - TDM ya contrasta BFE, MpsSvc, NSI, RPC y eventos de Firewall/Windows alrededor del incidente.");
                sb.AppendLine("    - Si esas dependencias permanecen sanas y no aparece antecedente causal, la evidencia faltante debe provenir del propio Advanced Security (log causal, stack más profundo o dump solicitado durante reproducción).");
            }
            else if (semantic.Contains("Server Monitoring / Report Export", StringComparison.OrdinalIgnoreCase))
            {
                sb.AppendLine("    - TDM ya contrasta EventLog, WMI/RPC y eventos de disco/NTFS/recursos alrededor de Report Export.");
                sb.AppendLine("    - Si no existe fallo previo de esas dependencias, la siguiente evidencia debe explicar el estado interno de ReportExportMonitor/StopMonitoring antes de la ObjectDisposedException.");
            }
        }
        else if (origin == "WINDOWS")
        {
            sb.AppendLine("    - Comienza por Windows/dependencia subyacente y valida el evento antecedente indicado antes de modificar TSplus.");
            var antecedent = EV("Antecedente Windows más cercano");
            if (!string.Equals(antecedent, "N/D", StringComparison.OrdinalIgnoreCase)) sb.AppendLine($"    - Antecedente a validar: {antecedent}");
        }
        else if (origin == "DEPENDENCIA EXTERNA")
        {
            sb.AppendLine("    - Valida primero la DLL/ensamblado/driver o dependencia externa que Windows no pudo cargar; no reinstales TSplus hasta confirmar integridad, versión y disponibilidad de esa dependencia.");
        }
        else
        {
            sb.AppendLine("    - El origen sigue en conflicto/indeterminado. TDM debe obtener una evidencia anterior que discrimine Windows frente al producto TSplus antes de recomendar cambios.");
        }
    }

    private static void AppendMissingEvidence(StringBuilder sb, DiagnosticReport report, RootCauseCandidate? c)
    {
        if (c?.Id == "ROOT-PROCESS-CRASH")
        {
            string EV(string key) => c.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";
            var scm = EV("Service Control Manager 7031 cercano");
            var stack = EV("Stack .NET disponible");
            var internalComponent = EV("Componente interno observado");
            var origin = EV("Origen técnico más bajo sustentado");
            var originState = EV("Estado del origen");
            var independent = EV("Evidencia primaria independiente");

            sb.AppendLine($"  - Origen técnico más bajo actualmente: {origin} [{originState}].");
            if (!string.Equals(internalComponent, "N/D", StringComparison.OrdinalIgnoreCase))
                sb.AppendLine($"  - La pila .NET alcanza el componente interno: {internalComponent}.");
            if (!string.Equals(scm, "Sí", StringComparison.OrdinalIgnoreCase))
                sb.AppendLine("  - No existe SCM 7031 correlacionado; esto limita la confirmación del ciclo de servicio, pero no invalida el crash ya observado.");
            if (!string.Equals(independent, "Sí", StringComparison.OrdinalIgnoreCase))
            {
                if (string.Equals(stack, "Sí", StringComparison.OrdinalIgnoreCase))
                    sb.AppendLine("  - Para confirmar la CAUSA PRIMARIA falta una evidencia anterior que explique por qué el estado interno produjo la excepción (log causal, dependencia fallida o dump/stack más profundo).");
                else
                    sb.AppendLine("  - Para confirmar la CAUSA PRIMARIA falta stack/dump o una segunda fuente causal anterior al crash.");
            }
            else
            {
                sb.AppendLine("  - Existe una fuente causal independiente; TDM debe verificar que preceda al crash y que afecte al mismo componente antes de elevar la causa primaria a CONFIRMADA.");
            }
            sb.AppendLine("  - TDM ya buscó evidencia forense existente; no es necesario repetir manualmente búsquedas que aparecen cubiertas en el reporte.");
            return;
        }
        if (c?.Capa == DiagnosticLayer.Rdp)
        {
            sb.AppendLine("  - Correlaciona LocalSessionManager, RemoteConnectionManager y RdpCoreTS con TermService/listener y el primer síntoma TSplus.");
            return;
        }
        if (c?.Id == "ROOT-PRINT-SPOOLER")
        {
            sb.AppendLine("  - Correlaciona PrintService con la caída de Spooler, driver/puerto implicado y el primer fallo de Universal/Virtual Printer.");
            return;
        }
        sb.AppendLine("  - Busca un evento anterior en Windows/TSplus que explique el primer síntoma y una segunda fuente independiente que lo corrobore.");
    }
}
