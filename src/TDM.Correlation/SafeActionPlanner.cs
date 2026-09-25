using TDM.Models;

namespace TDM.Correlation;

/// <summary>
/// RC18.9: genera orientación segura y reversible. No ejecuta reparaciones ni cambios.
/// </summary>
public static class SafeActionPlanner
{
    public static SafeActionPlan Build(DiagnosticReport report)
    {
        var cause = report.CausaRaizPrincipal;
        var start = new List<SafeActionItem>();
        var dont = new List<SafeActionItem>();
        var verify = new List<SafeActionItem>();

        if (cause is null)
        {
            start.Add(new(1, "Conservar el estado actual y recopilar una reproducción del síntoma dentro de la ventana de TDM.",
                "No existe evidencia suficiente para escoger un originador sin riesgo de cambiar el sistema equivocado.", "DONDE_EMPEZAR"));
            verify.Add(new(1, "Revisar Cobertura diagnóstica y fuentes no disponibles.",
                "Una fuente no leída puede contener la evidencia que falta para discriminar el origen.", "VERIFICAR"));
            // Desempate: si hay hipótesis competitivas empatadas, indicar la prueba concreta
            // que las discrimina en vez de dejar solo el mensaje genérico de indeterminación.
            var tiebreak = TiebreakGuidance(report);
            if (tiebreak is not null) verify.Add(new(2, tiebreak, "Con dos hipótesis empatadas, una sola comprobación dirigida suele cerrar el diagnóstico.", "VERIFICAR"));
            dont.Add(new(1, "No reinstalar TSplus ni modificar servicios Windows por descarte.",
                "No existe una causa sustentada que justifique cambios destructivos.", "NO_TOCAR"));
            return new SafeActionPlan("Origen indeterminado: priorizar evidencia antes de cambios.", start, dont, verify);
        }

        var origin = NormalizeOrigin(cause.OrigenClasificado);
        var text = $"{cause.Componente} {cause.Resumen} {cause.Explicacion} " + string.Join(" ", cause.Evidencia.Select(e => $"{e.Clave}={e.Valor}"));
        var specific = Evidence(cause, "Originador específico");
        var semantic = Evidence(cause, "Componente semántico");
        if (specific == "N/D") specific = semantic == "N/D" ? cause.Componente : semantic;

        if (origin == "WINDOWS")
        {
            if (ContainsAny(text, "NLA", "CredSSP", "contraseña", "password", "0xC0000224", "0xC0000071"))
            {
                start.Add(new(1, "Validar el estado de contraseña de la cuenta afectada y la política de cambio obligatorio/expiración.",
                    "La evidencia sitúa el rechazo en autenticación Windows/NLA antes de que TSplus complete la sesión.", "DONDE_EMPEZAR"));
                start.Add(new(2, "Comprobar NLA/CredSSP y conectividad efectiva con el controlador de dominio desde el servidor.",
                    "NLA requiere resolver la autenticación antes de crear la sesión interactiva.", "DONDE_EMPEZAR"));
                verify.Add(new(1, "Correlacionar Event 4625 Status/SubStatus con el usuario y la hora del síntoma.",
                    "Confirma que el rechazo observado corresponde a contraseña expirada/cambio obligatorio y no a otra credencial.", "VERIFICAR"));
                dont.Add(new(1, "No reinstalar ni modificar Remote Access como primera acción.",
                    "TSplus aparece como víctima de una preautenticación Windows fallida.", "NO_TOCAR"));
            }
            else if (ContainsAny(text, "User Profile", "Winlogon", "shell", "pantalla negra", "TERMSRV", "Netlogon", "Active Directory", "dominio"))
            {
                start.Add(new(1, "Revisar User Profile Service, Winlogon/Userinit, Netlogon/AD y el primer evento Windows anterior al síntoma.",
                    "La evidencia coloca la anomalía en la canalización de inicio de sesión Windows.", "DONDE_EMPEZAR"));
                verify.Add(new(1, "Confirmar si el logon se completa y en qué punto deja de iniciarse el shell/perfil.",
                    "Distingue una falla de autenticación de una falla post-logon/pantalla negra.", "VERIFICAR"));
                dont.Add(new(1, "No modificar AppControl.ini ni publicación de aplicaciones sin evidencia de que el fallo llegue a esa capa.",
                    "El origen actual está por debajo de TSplus.", "NO_TOCAR"));
            }
            else if (ContainsAny(text, "TermService", "Remote Desktop Services", "listener", "RDP"))
            {
                start.Add(new(1, "Validar TermService, listener RDP, políticas RDS y el evento Windows antecedente.",
                    "Remote Access depende de la disponibilidad de RDP/Remote Desktop Services.", "DONDE_EMPEZAR"));
                verify.Add(new(1, "Comprobar que el listener y TermService permanezcan estables después del evento.",
                    "Evita declarar resuelto un reinicio transitorio.", "VERIFICAR"));
                dont.Add(new(1, "No cambiar archivos de configuración TSplus hasta confirmar que la dependencia Windows está sana.",
                    "La evidencia actual responsabiliza Windows.", "NO_TOCAR"));
            }
            else
            {
                start.Add(new(1, $"Comenzar por la dependencia Windows identificada: {specific}.",
                    "TDM encontró un antecedente Windows mejor sustentado que una falla interna TSplus.", "DONDE_EMPEZAR"));
                verify.Add(new(1, "Confirmar que el evento antecedente precede al primer síntoma TSplus y afecta la misma función.",
                    "La proximidad temporal por sí sola no basta para causalidad.", "VERIFICAR"));
                dont.Add(new(1, "No reparar TSplus antes de validar la dependencia Windows señalada.",
                    "Evita introducir cambios en la víctima del incidente.", "NO_TOCAR"));
            }
        }
        else if (origin == "TSPLUS")
        {
            if (ContainsAny(text, "Server Monitoring", "Report Export", "StopMonitoring", "ObjectDisposedException"))
            {
                start.Add(new(1, "Revisar Server Monitoring / Report Export / StopMonitoring y el estado interno previo a la excepción.",
                    "La pila alcanza código del producto y no existe una falla Windows fuerte anterior que explique el estado.", "DONDE_EMPEZAR"));
                verify.Add(new(1, "Correlacionar el stack .NET, logs Server Monitoring y recurrencia de los mismos episodios.",
                    "Permite diferenciar un defecto recurrente del producto de un evento aislado.", "VERIFICAR"));
                dont.Add(new(1, "No reiniciar o reconfigurar RDP, RPC, WMI, Spooler o EventLog como primera medida.",
                    "Esas dependencias no están implicadas causalmente en la evidencia actual.", "NO_TOCAR"));
            }
            else if (ContainsAny(text, "RemoteApp", "startup.config", "encoding", "UTF-8", "AppControl"))
            {
                start.Add(new(1, "Revisar la cadena RemoteApp: AppControl.ini → startup.config → cliente/conexión, preservando los archivos originales.",
                    "Existe evidencia compatible con configuración/codificación dentro del flujo de publicación TSplus.", "DONDE_EMPEZAR"));
                verify.Add(new(1, "Comparar el contenido/codificación del caso afectado con un usuario/aplicación sin caracteres especiales.",
                    "Una comparación controlada discrimina una incompatibilidad de codificación sin alterar producción.", "VERIFICAR"));
                dont.Add(new(1, "No renombrar usuarios o aplicaciones como corrección definitiva sin confirmar el punto exacto de ruptura.",
                    "El nombre con acento es contexto; la causalidad requiere evidencia de codificación/lectura.", "NO_TOCAR"));
            }
            else if (ContainsAny(text, "Web", "HTML5", "settings.js", "httpwebs.jar"))
            {
                start.Add(new(1, "Revisar settings.js, runtime Web/HTML5, listener HTTP/HTTPS y el primer log/error del módulo.",
                    "La evidencia señala el subsistema Web de Remote Access.", "DONDE_EMPEZAR"));
                verify.Add(new(1, "Confirmar que configuración, proceso propietario y listener correspondan entre sí después del fallo.",
                    "Evita atribuir a configuración un problema de runtime o viceversa.", "VERIFICAR"));
                dont.Add(new(1, "No modificar TermService/RDP si el acceso RDP nativo permanece sano.",
                    "Web/HTML5 y RDP nativo son rutas funcionales diferentes.", "NO_TOCAR"));
            }
            else if (ContainsAny(text, "Printer", "Spooler", "novaPDF"))
            {
                start.Add(new(1, "Revisar la cadena de impresión TSplus/driver identificada junto con PrintService.",
                    "La falla está acotada al subsistema de impresión observado.", "DONDE_EMPEZAR"));
                dont.Add(new(1, "No alterar sesiones/RDP si sólo está degradada la impresión.",
                    "La evidencia no demuestra impacto sobre la conectividad de la sesión.", "NO_TOCAR"));
            }
            else
            {
                start.Add(new(1, $"Comenzar por el componente TSplus identificado: {specific}.",
                    "TDM sitúa el origen técnico dentro del producto y no encontró un antecedente Windows más fuerte.", "DONDE_EMPEZAR"));
                verify.Add(new(1, "Confirmar la misma cadena en logs/eventos recurrentes antes de aplicar cambios permanentes.",
                    "La recurrencia y una segunda fuente elevan la confianza.", "VERIFICAR"));
                dont.Add(new(1, "No modificar servicios Windows generales por descarte.",
                    "No están sustentados como originadores.", "NO_TOCAR"));
            }
        }
        else if (origin == "EXTERNO")
        {
            start.Add(new(1, $"Revisar el tercero identificado: {specific} y su evento/módulo correlacionado con el proceso TSplus.",
                "TDM encontró evidencia explícita de un componente externo en la cadena causal.", "DONDE_EMPEZAR"));
            verify.Add(new(1, "Confirmar propietario, versión, firma/ruta del módulo y timestamp frente al incidente.",
                "Evita culpar un producto instalado que sólo estaba presente sin intervenir.", "VERIFICAR"));
            verify.Add(new(2, "Consultar logs del producto tercero antes de solicitar una exclusión o cambio de política.",
                "Las exclusiones deben basarse en evidencia y aprobación, no en prueba y error.", "VERIFICAR"));
            dont.Add(new(1, "No deshabilitar ni desinstalar antivirus/EDR/firewall automáticamente.",
                "Puede reducir la postura de seguridad y no constituye una prueba causal controlada.", "NO_TOCAR"));
            dont.Add(new(2, "No reinstalar TSplus mientras la evidencia siga apuntando al tercero.",
                "Reinstalar la víctima puede ocultar temporalmente el síntoma sin eliminar la causa.", "NO_TOCAR"));
        }
        else
        {
            start.Add(new(1, "Obtener la evidencia discriminante indicada por TDM antes de hacer cambios.",
                "El origen sigue indeterminado o en conflicto.", "DONDE_EMPEZAR"));
            verify.Add(new(1, "Buscar una fuente independiente que preceda al primer síntoma y afecte el mismo componente.",
                "Es la condición necesaria para separar correlación temporal de causa primaria.", "VERIFICAR"));
            dont.Add(new(1, "No aplicar reparaciones por descarte ni múltiples cambios simultáneos.",
                "Dificultan probar qué acción resolvió o empeoró el incidente.", "NO_TOCAR"));
        }

        // Siempre agrega controles operativos básicos y seguros.
        verify.Add(new(verify.Count + 1, "Conservar/exportar el reporte TDM antes de cualquier cambio.",
            "Permite comparar estado antes/después y mantener trazabilidad del incidente.", "VERIFICAR"));
        verify.Add(new(verify.Count + 1, "Aplicar una sola modificación a la vez y volver a ejecutar TDM.",
            "Reduce ambigüedad y facilita confirmar causalidad.", "VERIFICAR"));

        return new SafeActionPlan(
            $"Plan de actuación no destructivo para origen {origin}; TDM no ejecuta estas acciones automáticamente.",
            start, dont, verify);
    }

    private static bool ContainsAny(string text, params string[] values) => values.Any(v => text.Contains(v, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Guía de desempate: cuando hay ≥2 hipótesis causales con margen &lt;5 puntos, indica la
    /// comprobación concreta que las discrimina. Solo lectura de candidatos ya calculados.
    /// </summary>
    private static string? TiebreakGuidance(DiagnosticReport report)
    {
        var causal = (report.CausasRaiz ?? [])
            .Where(c => !c.RolCausal.Equals("IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO", StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(c => c.Puntaje)
            .Take(2)
            .ToList();
        if (causal.Count < 2 || causal[0].Puntaje - causal[1].Puntaje >= 5) return null;
        var hint = DiscriminatingCheck(causal[0]);
        return $"Desempatar entre '{causal[0].Componente}' ({causal[0].Puntaje} pts) y '{causal[1].Componente}' ({causal[1].Puntaje} pts): {hint}";
    }

    private static string DiscriminatingCheck(RootCauseCandidate candidate)
    {
        var id = candidate.Id ?? string.Empty;
        if (id.StartsWith("ROOT-RDP-TERMSERVICE", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("ROOT-RDP-LISTENER", StringComparison.OrdinalIgnoreCase))
            return "confirme TermService en SCM y el listener TCP en el puerto RDP; el que falle descarta al otro.";
        if (id.StartsWith("ROOT-TLS-SCHANNEL", StringComparison.OrdinalIgnoreCase))
            return "valide el thumbprint del certificado RDP y un handshake afectado concreto con hora coincidente.";
        if (id.StartsWith("ROOT-WINDOWS-AD-RDP-DEPENDENCY", StringComparison.OrdinalIgnoreCase))
            return "correlacione mismo usuario y hora en Netlogon/Event 4625; sin coincidencia, la vía AD pierde fuerza.";
        if (id.StartsWith("ROOT-WINDOWS-RDP-SHELL-PIPELINE", StringComparison.OrdinalIgnoreCase))
            return "confirme si el shell llega a iniciar (pantalla negra) y si el perfil carga; sin brecha de shell, descarte esta vía.";
        if (id.StartsWith("ROOT-PROCESS-CRASH", StringComparison.OrdinalIgnoreCase))
            return "compare módulo/excepción entre ráfagas (huella distinta = incidentes distintos).";
        if (id.StartsWith("ROOT-SCM-SERVICE-FAILURE", StringComparison.OrdinalIgnoreCase)
            || id.StartsWith("ROOT-SERVICE-DEPENDENCY-", StringComparison.OrdinalIgnoreCase))
            return "revise el código SCM del servicio y sus dependencias declaradas; sin fallo SCM no hay cadena.";
        if (id.StartsWith("ROOT-DEPENDENCY-LOAD", StringComparison.OrdinalIgnoreCase))
            return "confirme que la DLL/dependencia falta también fuera del crash (misma ruta, mismo producto).";
        return "busque una segunda fuente independiente (evento, dependencia o síntoma) para cada hipótesis; la que no la tenga pierde.";
    }

    private static string Evidence(RootCauseCandidate c, string key) =>
        c.Evidencia.FirstOrDefault(e => e.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? "N/D";

    private static string NormalizeOrigin(string origin) => origin.ToUpperInvariant() switch
    {
        "DEPENDENCIA EXTERNA" => "EXTERNO",
        "EXTERNO" => "EXTERNO",
        "WINDOWS" => "WINDOWS",
        "TSPLUS" => "TSPLUS",
        _ => "INDETERMINADO"
    };
}
