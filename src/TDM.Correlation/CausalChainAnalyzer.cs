using TDM.Models;

namespace TDM.Correlation;

internal sealed record ProcessCrashAssessment(
    string OriginAssessment,
    string OriginState,
    string OriginCategory,
    string OriginReason,
    string? InternalComponent,
    string? SemanticComponent,
    string? FirstStackFrame,
    int StrongWindowsAntecedents,
    int ProductAntecedents,
    int RelatedArtifacts,
    string? ClosestWindowsAntecedent,
    string? ClosestProductAntecedent,
    bool IndependentPrimaryEvidence,
    IReadOnlyList<EvidenceItem> Evidence);

/// <summary>
/// Analiza qué ocurrió ANTES del crash para separar mecanismo, origen técnico y causa primaria.
/// RC15 añade análisis dirigido por el componente interno observado.
/// Sólo lectura: trabaja exclusivamente con evidencia ya recolectada.
/// </summary>
internal static class CausalChainAnalyzer
{
    public static ProcessCrashAssessment AnalyzeProcessCrash(
        DiagnosticReport report,
        DiagnosticEvent appCrash,
        DiagnosticEvent? dotnetClose,
        DiagnosticEvent? scmClose,
        string appName,
        TsplusProduct product)
    {
        if (appCrash.Timestamp is not DateTimeOffset incident)
            return Empty();

        var firstFrame = EvidenceValue(dotnetClose, "Primer frame no framework");
        var internalComponent = EvidenceValue(dotnetClose, "Componente interno observado");
        var stackAvailable = string.Equals(EvidenceValue(dotnetClose, "Stack trace disponible"), "Sí", StringComparison.OrdinalIgnoreCase);
        var internalFrame = IsLikelyProductInternalFrame(firstFrame, product, appName);
        var semanticComponent = SemanticComponent(product, internalComponent ?? firstFrame);

        var antecedentWindow = report.Lookback > TimeSpan.Zero && report.Lookback < TimeSpan.FromMinutes(15)
            ? report.Lookback
            : TimeSpan.FromMinutes(15);
        var windowStart = incident - antecedentWindow;
        var prior = report.Eventos
            .Where(e => e.Timestamp.HasValue && e.Timestamp.Value >= windowStart && e.Timestamp.Value < incident)
            .Where(e => !IsSameCrashEvidence(e, appName, incident))
            .OrderBy(e => e.Timestamp)
            .ToList();

        var strongWindows = prior
            .Where(e => IsStrongWindowsAntecedent(e, product, appName, semanticComponent))
            .OrderByDescending(e => e.Timestamp)
            .ToList();

        var targetedWindows = prior
            .Where(e => IsTargetedWindowsAntecedent(e, product, semanticComponent))
            .OrderByDescending(e => e.Timestamp)
            .ToList();

        var systemChanges = prior
            .Where(e => e.Tipo is "SERVICE_CONFIGURATION_CHANGE" or "SERVICE_INSTALLED" or "SYSTEM_RESTART_CHANGE" or "SOFTWARE_INSTALL_CHANGE" or "WINDOWS_UPDATE_CHANGE")
            .OrderByDescending(e => e.Timestamp)
            .ToList();

        var productPrior = prior
            .Where(e => product != TsplusProduct.Ninguno && e.Producto == product)
            .Where(e => e.Severidad != DiagnosticSeverity.Informativo || e.Tipo == "FORENSIC_LOG_FOUND")
            .Where(e => e.Tipo is not "APPLICATION_CRASH" and not "DOTNET_UNHANDLED_EXCEPTION" and not "WER_REPORT")
            .OrderByDescending(e => e.Timestamp)
            .ToList();

        var artifacts = report.Eventos
            .Where(e => e.Timestamp.HasValue && (e.Tipo is "FORENSIC_WER_FOUND" or "FORENSIC_DUMP_FOUND" or "FORENSIC_LOG_FOUND"))
            .Where(e => (e.Timestamp!.Value - incident).Duration() <= antecedentWindow)
            .Where(e => ArtifactTouchesCandidate(e, appName, product))
            .OrderByDescending(e => e.Timestamp)
            .ToList();

        var closestWindows = strongWindows.FirstOrDefault();
        var closestProduct = productPrior.FirstOrDefault();
        var explicitDependencyCause = strongWindows.Any(IsExplicitDependencyFailure);
        // R4: un marcador textual ("corrupt", "missing", ...) en un evento previo del mismo producto
        // no basta por sí solo: exige corroboración (frame interno, antecedente Windows dirigido o
        // artefacto forense) para contar como evidencia primaria independiente.
        var explicitProductCause = productPrior.Any(IsExplicitProductCause)
            && (internalFrame || targetedWindows.Count > 0 || artifacts.Count > 0);
        var dependencySnapshot = DirectedDependencySnapshot(report, product, semanticComponent);

        string origin;
        string originState;
        string originCategory;
        string reason;

        DiagnosticEvent? explicitDependency = null;
        if (explicitDependencyCause)
        {
            var dep = strongWindows.First(IsExplicitDependencyFailure);
            explicitDependency = dep;
            originCategory = DependencyOriginCategory(dep);
            origin = SpecificDependencyOriginator(dep, windowsFallback: originCategory == "WINDOWS");
            originState = originCategory == "INDETERMINADO" ? "PROBABLE" : "ALTAMENTE SUSTENTADO";
            reason = originCategory == "INDETERMINADO"
                ? "Existe una falla explícita de dependencia anterior al crash, pero la evidencia disponible no permite atribuir con seguridad la propiedad técnica de esa dependencia a Windows, TSplus o un tercero. TDM conserva el nombre concreto sin inventar responsable."
                : "Existe una falla explícita de una dependencia anterior al crash y dentro de la ventana causal. TDM conserva el proveedor/módulo concreto cuando puede identificarlo; debe demostrarse que esa dependencia alimentó directamente el proceso antes de declarar la causa primaria como confirmada.";
        }
        else if (explicitProductCause && strongWindows.Count == 0)
        {
            originCategory = "TSPLUS";
            origin = ProductName(product) + " / evidencia interna previa";
            originState = "ALTAMENTE SUSTENTADO";
            reason = "Existe un error interno explícito del mismo producto anterior al crash y no se observó una falla Windows fuerte previa. TDM orienta la investigación al producto; la causa primaria sólo se confirma si el mensaje previo identifica de forma inequívoca la condición que provoca el fallo.";
        }
        else if (internalFrame && strongWindows.Count == 0)
        {
            originCategory = "TSPLUS";
            origin = ProductName(product) + " / código interno del producto";
            originState = "ALTAMENTE SUSTENTADO";
            reason = "La pila .NET entra en código del producto y no se observó una falla Windows subyacente fuerte inmediatamente anterior. Esto orienta el inicio de la corrección al producto/componente interno, sin convertir todavía el estado que produjo la excepción en causa primaria confirmada.";
        }
        else if (strongWindows.Count > 0)
        {
            originCategory = "INDETERMINADO";
            origin = "Indeterminado entre Windows/dependencia y " + ProductName(product);
            originState = "PROBABLE / EN CONFLICTO";
            reason = "Existen eventos Windows antecedentes y un crash del producto, pero la evidencia actual no demuestra cuál inició la cadena causal.";
        }
        else if (stackAvailable)
        {
            originCategory = "INDETERMINADO";
            origin = ProductName(product);
            originState = "PROBABLE";
            reason = "Existe stack .NET del proceso, pero no contiene todavía un frame interno suficientemente identificable ni una dependencia Windows causal previa.";
        }
        else
        {
            originCategory = "INDETERMINADO";
            origin = "No determinado";
            originState = "INDETERMINADO";
            reason = "La evidencia confirma el crash, pero no contiene un antecedente causal fuerte ni stack suficiente para ubicar el origen por debajo del proceso.";
        }

        var independentPrimaryEvidence = explicitDependencyCause || explicitProductCause;

        var evidence = new List<EvidenceItem>
        {
            new("Clasificación de origen", originCategory),
            new("Origen técnico más bajo sustentado", origin),
            new("Estado del origen", originState),
            new("Fundamento del origen", reason),
            new("Stack .NET disponible", stackAvailable ? "Sí" : "No"),
            new("Frame interno del producto", internalFrame ? "Sí" : "No"),
            new("Componente interno observado", internalComponent ?? "N/D"),
            new("Componente semántico", semanticComponent ?? "N/D"),
            new("Ventana causal efectiva", FormatWindow(antecedentWindow)),
            new("Antecedentes Windows fuertes", strongWindows.Count.ToString()),
            new("Antecedentes Windows dirigidos", targetedWindows.Count.ToString()),
            new("Antecedentes del mismo producto", productPrior.Count.ToString()),
            new("Cambios del sistema previos", systemChanges.Count.ToString()),
            new("Artefactos forenses correlacionados", artifacts.Count.ToString()),
            new("Dependencias dirigidas - estado actual", dependencySnapshot),
            new("Evidencia primaria independiente", independentPrimaryEvidence ? "Sí" : "No")
        };
        if (explicitDependency is not null)
            evidence.Add(new("Originador específico", SpecificDependencyOriginator(explicitDependency, originCategory == "WINDOWS")));
        else if (originCategory == "TSPLUS")
        {
            var productOriginator = semanticComponent ?? internalComponent ?? firstFrame;
            if (!string.IsNullOrWhiteSpace(productOriginator))
                evidence.Add(new("Originador específico", productOriginator));
        }
        if (!string.IsNullOrWhiteSpace(firstFrame)) evidence.Add(new("Primer frame no framework", firstFrame));
        if (closestWindows is not null) evidence.Add(new("Antecedente Windows más cercano", Describe(closestWindows, incident)));
        if (targetedWindows.Count > 0) evidence.Add(new("Antecedente dirigido más cercano", Describe(targetedWindows[0], incident)));
        if (closestProduct is not null) evidence.Add(new("Antecedente TSplus más cercano", Describe(closestProduct, incident)));
        if (systemChanges.Count > 0) evidence.Add(new("Cambio del sistema más cercano", Describe(systemChanges[0], incident)));
        if (artifacts.Count > 0) evidence.Add(new("Artefacto forense más cercano", Describe(artifacts[0], incident)));

        return new ProcessCrashAssessment(
            origin,
            originState,
            originCategory,
            reason,
            internalComponent,
            semanticComponent,
            firstFrame,
            strongWindows.Count,
            productPrior.Count,
            artifacts.Count,
            closestWindows is null ? null : Describe(closestWindows, incident),
            closestProduct is null ? null : Describe(closestProduct, incident),
            independentPrimaryEvidence,
            evidence);
    }

    private static bool IsSameCrashEvidence(DiagnosticEvent e, string appName, DateTimeOffset incident)
    {
        if (e.Timestamp is not DateTimeOffset ts || (ts - incident).Duration() > TimeSpan.FromSeconds(10)) return false;
        if (e.Tipo is not "APPLICATION_CRASH" and not "DOTNET_UNHANDLED_EXCEPTION" and not "WER_REPORT") return false;
        return Mentions(e, appName);
    }

    private static bool IsStrongWindowsAntecedent(DiagnosticEvent e, TsplusProduct product, string appName, string? semanticComponent)
    {
        if (e.Capa == DiagnosticLayer.Tsplus || e.Severidad == DiagnosticSeverity.Informativo) return false;

        // Una dependencia Windows sólo es antecedente fuerte cuando identifica el proceso/producto
        // investigado. Que Remote Access sea el producto principal no convierte cualquier DLL/SideBySide
        // cercano en causa del crash.
        if (e.Tipo is "SIDEBYSIDE_DEPENDENCY_FAILURE" or "DEPENDENCY_NOT_FOUND" or "DEPENDENCY_LOAD_FAILURE" or "DLL_NOT_FOUND" or "INVALID_IMAGE_FORMAT")
            return Mentions(e, appName) || (e.Producto == product && product != TsplusProduct.Ninguno);

        // Defender/EDR requiere identidad técnica compartida (proceso, ruta, archivo o producto).
        // Una señal genérica del antivirus sólo se conserva como contexto.
        if (e.Tipo is "DEFENDER_ACTION_TAKEN" or "DEFENDER_THREAT_DETECTED" or "THIRD_PARTY_SECURITY_INTERFERENCE_SIGNAL")
            return MentionsProduct(e, product, appName) || SharesProcessOrPathIdentity(e, appName);

        // Fallos AD/RDP pueden explicar un síntoma de sesión, pero no un crash arbitrario del proceso.
        // Para elevarlos aquí deben mencionar explícitamente el proceso/producto o el componente dirigido.
        if (product == TsplusProduct.RemoteAccess &&
            (e.Tipo == "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE" || e.Tipo == "WINDOWS_AD_TERMSRV_SPN_FAILURE" ||
             e.Tipo == "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE" || e.Tipo == "RDP_SHELL_START_GAP" || e.Tipo == "RDP_SHELL_START_DELAY"))
            return Mentions(e, appName) || IsTargetedWindowsAntecedent(e, product, semanticComponent);

        if (e.Tipo is "SERVICE_CONFIGURATION_CHANGE" or "SERVICE_INSTALLED")
            return MentionsProduct(e, product, appName);

        if (e.Codigo is "7000" or "7001" or "7009" or "7011" or "7023" or "7024" or "7031" or "7034")
            return MentionsProduct(e, product, appName) || IsTargetedWindowsAntecedent(e, product, semanticComponent);

        if (e.Fuente.Contains("SideBySide", StringComparison.OrdinalIgnoreCase))
            return MentionsProduct(e, product, appName);

        // Schannel no es causa de un crash TSplus por proximidad temporal. Debe compartir endpoint,
        // certificado, proceso/ruta o identidad explícita del producto investigado.
        if (e.Fuente.Contains("Schannel", StringComparison.OrdinalIgnoreCase) || e.Capa == DiagnosticLayer.Rdp)
            return Mentions(e, appName) || HasExplicitTsplusIdentity(e, product);

        // Disk/NTFS/volmgr/Resource-Exhaustion sólo es fuerte si toca el proceso/ruta/producto
        // investigado. Un volumen diferente permanece como contexto.
        if (e.Fuente.Contains("Disk", StringComparison.OrdinalIgnoreCase) ||
            e.Fuente.Contains("Ntfs", StringComparison.OrdinalIgnoreCase) ||
            e.Fuente.Contains("volmgr", StringComparison.OrdinalIgnoreCase) ||
            e.Fuente.Contains("Resource-Exhaustion", StringComparison.OrdinalIgnoreCase))
            return SharesProcessOrPathIdentity(e, appName) || HasExplicitTsplusIdentity(e, product) || IsTargetedWindowsAntecedent(e, product, semanticComponent);

        return IsTargetedWindowsAntecedent(e, product, semanticComponent);
    }

    private static bool SharesProcessOrPathIdentity(DiagnosticEvent e, string appName)
    {
        if (Mentions(e, appName)) return true;
        var stem = Path.GetFileNameWithoutExtension(appName);
        var values = new[]
        {
            e.Archivo,
            EvidenceValue(e, "Proceso"), EvidenceValue(e, "Process"), EvidenceValue(e, "Image"),
            EvidenceValue(e, "Archivo"), EvidenceValue(e, "Ruta"), EvidenceValue(e, "Path"),
            EvidenceValue(e, "Aplicación"), EvidenceValue(e, "Application")
        };
        return values.Where(v => !string.IsNullOrWhiteSpace(v)).Any(v =>
            v!.Contains(appName, StringComparison.OrdinalIgnoreCase) ||
            (!string.IsNullOrWhiteSpace(stem) && v.Contains(stem, StringComparison.OrdinalIgnoreCase)));
    }

    private static bool HasExplicitTsplusIdentity(DiagnosticEvent e, TsplusProduct product)
    {
        if (product == TsplusProduct.Ninguno) return false;
        if (e.Producto == product) return true;
        var text = string.Join(" ", new[]
        {
            e.Componente, e.Mensaje, e.Archivo,
            EvidenceValue(e, "Proceso"), EvidenceValue(e, "Aplicación"), EvidenceValue(e, "Producto"),
            EvidenceValue(e, "Endpoint"), EvidenceValue(e, "Host"), EvidenceValue(e, "Puerto"),
            EvidenceValue(e, "Certificado"), EvidenceValue(e, "Thumbprint")
        }.Where(x => !string.IsNullOrWhiteSpace(x)));
        return product switch
        {
            TsplusProduct.RemoteAccess => text.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || text.Contains("APSC", StringComparison.OrdinalIgnoreCase) || text.Contains("wsession", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.AdvancedSecurity => text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase) || text.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.ServerMonitoring => text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.RemoteSupport => text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase) || text.Contains("Remote Support", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.TwoFactorAuthentication => text.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || text.Contains("2FA", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool IsTargetedWindowsAntecedent(DiagnosticEvent e, TsplusProduct product, string? semanticComponent)
    {
        if (e.Capa == DiagnosticLayer.Tsplus || e.Severidad == DiagnosticSeverity.Informativo) return false;
        var text = $"{e.Fuente} {e.Componente} {e.Tipo} {e.Mensaje} {e.Codigo}";

        if (product == TsplusProduct.AdvancedSecurity &&
            !string.IsNullOrWhiteSpace(semanticComponent) &&
            semanticComponent.Contains("Firewall", StringComparison.OrdinalIgnoreCase))
        {
            string[] firewallMarkers = ["BFE", "Base Filtering Engine", "MpsSvc", "Windows Firewall", "Filtering Platform", "WFP", "WinDivert"];
            return firewallMarkers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
        }

        if (product == TsplusProduct.ServerMonitoring &&
            !string.IsNullOrWhiteSpace(semanticComponent) &&
            (semanticComponent.Contains("Report", StringComparison.OrdinalIgnoreCase) || semanticComponent.Contains("Export", StringComparison.OrdinalIgnoreCase)))
        {
            string[] storageMarkers = ["Disk", "Ntfs", "volmgr", "Resource-Exhaustion", "access denied", "file not found", "path not found", "I/O"];
            return storageMarkers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
        }

        return false;
    }

    private static bool IsExplicitDependencyFailure(DiagnosticEvent e) =>
        e.Tipo is "SIDEBYSIDE_DEPENDENCY_FAILURE" or "DEPENDENCY_NOT_FOUND" or "DEPENDENCY_LOAD_FAILURE" or "DLL_NOT_FOUND" or "INVALID_IMAGE_FORMAT" or "DEFENDER_ACTION_TAKEN" or "THIRD_PARTY_SECURITY_INTERFERENCE_SIGNAL" or "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE" ||
        e.Codigo is "7000" or "7001" or "7009" or "7011" or "7023" or "7024";

    private static string DependencyOriginCategory(DiagnosticEvent e)
    {
        if (e.Tipo == "THIRD_PARTY_SECURITY_INTERFERENCE_SIGNAL") return "DEPENDENCIA EXTERNA";
        if (e.Tipo is "DEFENDER_ACTION_TAKEN" or "DEFENDER_THREAT_DETECTED" or
            "WINDOWS_AD_AUTH_DEPENDENCY_FAILURE" or "WINDOWS_AD_TERMSRV_SPN_FAILURE" or "WINDOWS_AD_DOMAIN_CONNECTIVITY_FAILURE")
            return "WINDOWS";

        var declared = e.Evidencia?.FirstOrDefault(x => x.Clave.Equals("Clasificación de dependencia", StringComparison.OrdinalIgnoreCase))?.Valor?.Trim();
        if (string.Equals(declared, "EXTERNO", StringComparison.OrdinalIgnoreCase)) return "DEPENDENCIA EXTERNA";
        if (string.Equals(declared, "WINDOWS", StringComparison.OrdinalIgnoreCase)) return "WINDOWS";
        if (string.Equals(declared, "TSPLUS", StringComparison.OrdinalIgnoreCase)) return "TSPLUS";
        return "INDETERMINADO";
    }

    private static string SpecificDependencyOriginator(DiagnosticEvent e, bool windowsFallback)
    {
        string E(string key) => e.Evidencia?.FirstOrDefault(x => x.Clave.Contains(key, StringComparison.OrdinalIgnoreCase))?.Valor ?? string.Empty;
        var explicitOriginator = E("Originador específico");
        if (!string.IsNullOrWhiteSpace(explicitOriginator) && !explicitOriginator.Equals("N/D", StringComparison.OrdinalIgnoreCase)) return explicitOriginator;
        var text = $"{e.Fuente} {e.Componente} {e.Mensaje} {e.Archivo} {E("Dependencia")} {E("Módulo")} {E("Archivo")}";
        string[] products =
        [
            "Microsoft Defender", "CrowdStrike", "SentinelOne", "Sophos", "ESET", "Trend Micro",
            "McAfee", "Bitdefender", "Carbon Black", "Fortinet", "Palo Alto", "Zscaler", "Symantec"
        ];
        foreach (var product in products)
            if (text.Contains(product, StringComparison.OrdinalIgnoreCase)) return product;

        if (e.Tipo == "DEFENDER_ACTION_TAKEN" || e.Tipo == "DEFENDER_THREAT_DETECTED") return "Microsoft Defender";

        var dependency = E("Dependencia detectada");
        if (string.IsNullOrWhiteSpace(dependency)) dependency = E("Dependencia");
        if (string.IsNullOrWhiteSpace(dependency)) dependency = E("Módulo");
        if (string.IsNullOrWhiteSpace(dependency)) dependency = e.Archivo ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(dependency))
        {
            var declared = E("Clasificación de dependencia");
            string display = dependency;
            try
            {
                var file = Path.GetFileName(dependency);
                if (!string.IsNullOrWhiteSpace(file)) display = file;
            }
            catch { }
            if (string.Equals(declared, "EXTERNO", StringComparison.OrdinalIgnoreCase)) return $"Dependencia externa: {display}";
            if (string.Equals(declared, "WINDOWS", StringComparison.OrdinalIgnoreCase)) return $"Windows / {display}";
            if (string.Equals(declared, "TSPLUS", StringComparison.OrdinalIgnoreCase)) return $"TSplus / {display}";
            return $"Dependencia no atribuida: {display}";
        }

        if (!string.IsNullOrWhiteSpace(e.Componente) &&
            !e.Componente.Equals("Windows", StringComparison.OrdinalIgnoreCase))
            return e.Componente;

        return windowsFallback ? "Windows / dependencia subyacente" : "Dependencia externa no identificada";
    }

    private static bool IsExplicitProductCause(DiagnosticEvent e)
    {
        var text = $"{e.Mensaje} {e.Tipo}";
        string[] causalMarkers = [
            "configuration error", "config error", "access denied", "permission denied", "file not found",
            "database is locked", "database corrupt", "corrupt", "cannot open", "failed to load", "missing"
        ];
        return causalMarkers.Any(m => text.Contains(m, StringComparison.OrdinalIgnoreCase));
    }

    private static string DirectedDependencySnapshot(DiagnosticReport report, TsplusProduct product, string? semanticComponent)
    {
        var health = report.Eventos.LastOrDefault(e => e.Tipo == "TSPLUS_DEPENDENCY_HEALTH");
        if (health?.Evidencia is not { Count: > 0 }) return "Sin snapshot consolidado";

        IEnumerable<string> keys = [];
        if (product == TsplusProduct.AdvancedSecurity &&
            !string.IsNullOrWhiteSpace(semanticComponent) && semanticComponent.Contains("Firewall", StringComparison.OrdinalIgnoreCase))
            keys = ["Base Filtering Engine (BFE)", "Windows Defender Firewall (MpsSvc)", "Network Store Interface (NSI)", "Remote Procedure Call (RPC)"];
        else if (product == TsplusProduct.ServerMonitoring &&
                 !string.IsNullOrWhiteSpace(semanticComponent) && (semanticComponent.Contains("Report", StringComparison.OrdinalIgnoreCase) || semanticComponent.Contains("Export", StringComparison.OrdinalIgnoreCase)))
            keys = ["Windows Event Log", "Windows Management Instrumentation", "Remote Procedure Call (RPC)"];

        var selected = health.Evidencia.Where(x => keys.Contains(x.Clave, StringComparer.OrdinalIgnoreCase)).Select(x => $"{x.Clave}={x.Valor}").ToList();
        return selected.Count == 0 ? "Sin dependencias dirigidas adicionales para este componente" : string.Join(" | ", selected);
    }

    private static string? SemanticComponent(TsplusProduct product, string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var text = raw;
        if (product == TsplusProduct.AdvancedSecurity &&
            (text.Contains("WinDivert", StringComparison.OrdinalIgnoreCase) || text.Contains("Security_Common.Firewall", StringComparison.OrdinalIgnoreCase)))
            return "Advanced Security / Firewall / WinDivert";
        if (product == TsplusProduct.AdvancedSecurity && text.Contains("Firewall", StringComparison.OrdinalIgnoreCase))
            return "Advanced Security / Firewall";
        if (product == TsplusProduct.ServerMonitoring && text.Contains("ReportExportMonitor", StringComparison.OrdinalIgnoreCase))
        {
            if (text.Contains("StopMonitoring", StringComparison.OrdinalIgnoreCase)) return "Server Monitoring / Report Export / StopMonitoring";
            return "Server Monitoring / Report Export";
        }
        if (product == TsplusProduct.ServerMonitoring && text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase))
            return "Server Monitoring / servicio interno";
        if (product == TsplusProduct.RemoteSupport && text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase))
            return "Remote Support / componente interno";
        if (product == TsplusProduct.TwoFactorAuthentication && text.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase))
            return "2FA / componente interno";
        if (product == TsplusProduct.RemoteAccess && (text.Contains("APSC", StringComparison.OrdinalIgnoreCase) || text.Contains("Application Publishing", StringComparison.OrdinalIgnoreCase)))
            return "Remote Access / Application Publishing";
        return null;
    }

    private static bool ArtifactTouchesCandidate(DiagnosticEvent e, string appName, TsplusProduct product)
    {
        if (product != TsplusProduct.Ninguno && e.Producto == product) return true;
        return Mentions(e, appName);
    }

    private static bool MentionsProduct(DiagnosticEvent e, TsplusProduct product, string appName)
    {
        if (Mentions(e, appName)) return true;
        if (e.Producto == product && product != TsplusProduct.Ninguno) return true;
        var text = $"{e.Componente} {e.Mensaje} {e.Archivo}";
        return product switch
        {
            TsplusProduct.AdvancedSecurity => text.Contains("TSplus-Security", StringComparison.OrdinalIgnoreCase) || text.Contains("Advanced Security", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.ServerMonitoring => text.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.RemoteSupport => text.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase) || text.Contains("Remote Support", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.TwoFactorAuthentication => text.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase) || text.Contains("2FA", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.RemoteAccess => text.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || text.Contains("APSC", StringComparison.OrdinalIgnoreCase) || text.Contains("wsession", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static bool Mentions(DiagnosticEvent e, string appName)
    {
        var stem = Path.GetFileNameWithoutExtension(appName);
        var text = $"{e.Componente} {e.Mensaje} {e.Archivo}";
        return text.Contains(appName, StringComparison.OrdinalIgnoreCase) ||
               (!string.IsNullOrWhiteSpace(stem) && text.Contains(stem, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLikelyProductInternalFrame(string? frame, TsplusProduct product, string appName)
    {
        if (string.IsNullOrWhiteSpace(frame)) return false;
        var f = frame;
        var stem = Path.GetFileNameWithoutExtension(appName);
        if (!string.IsNullOrWhiteSpace(stem) && f.Contains(stem, StringComparison.OrdinalIgnoreCase)) return true;
        return product switch
        {
            TsplusProduct.AdvancedSecurity => f.Contains("Security_", StringComparison.OrdinalIgnoreCase) || f.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || f.Contains("Firewall", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.ServerMonitoring => f.Contains("ServerMonitoring", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.RemoteSupport => f.Contains("RemoteSupport", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.TwoFactorAuthentication => f.Contains("TwoFactor", StringComparison.OrdinalIgnoreCase),
            TsplusProduct.RemoteAccess => f.Contains("TSplus", StringComparison.OrdinalIgnoreCase) || f.Contains("wsession", StringComparison.OrdinalIgnoreCase) || f.Contains("UserDesktop", StringComparison.OrdinalIgnoreCase),
            _ => false
        };
    }

    private static string? EvidenceValue(DiagnosticEvent? e, string key) =>
        e?.Evidencia?.FirstOrDefault(x => x.Clave.Equals(key, StringComparison.OrdinalIgnoreCase))?.Valor;

    private static string Describe(DiagnosticEvent e, DateTimeOffset incident)
    {
        var delta = incident - e.Timestamp!.Value;
        var msg = e.Mensaje.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return $"-{FormatDelta(delta)} | {e.Fuente} | {e.Codigo ?? e.Tipo} | {msg}";
    }

    private static string FormatDelta(TimeSpan delta)
    {
        if (delta < TimeSpan.Zero) delta = delta.Duration();
        if (delta.TotalHours >= 1) return $"{(int)delta.TotalHours:00}:{delta.Minutes:00}:{delta.Seconds:00}";
        return $"{delta.Minutes:00}:{delta.Seconds:00}";
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

    private static string FormatWindow(TimeSpan value)
    {
        if (value.TotalHours >= 1) return value.TotalHours == 1 ? "1 h" : $"{value.TotalHours:0.#} h";
        if (value.TotalMinutes >= 1) return value.TotalMinutes == 1 ? "1 min" : $"{value.TotalMinutes:0.#} min";
        return $"{value.TotalSeconds:0} s";
    }

    private static ProcessCrashAssessment Empty() => new(
        "No determinado", "INDETERMINADO", "INDETERMINADO", "El crash no tiene timestamp verificable.", null, null, null,
        0, 0, 0, null, null, false,
        [new EvidenceItem("Origen técnico más bajo sustentado", "No determinado")]);
}
