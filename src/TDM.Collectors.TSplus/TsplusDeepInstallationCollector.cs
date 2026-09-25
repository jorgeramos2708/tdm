using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Auditoría recursiva y conservadora de la instalación Remote Access.
/// Lee metadatos y configuraciones conocidas; nunca modifica ni ejecuta componentes TSplus.
/// </summary>
public sealed class TsplusDeepInstallationCollector : IReadOnlyCollector
{
    public string Nombre => "TSplus profundo / instalación y granja";

    private const int MaxFiles = 75000;
    private const int MaxTextBytes = 8 * 1024 * 1024;
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ini", ".cfg", ".conf", ".config", ".json", ".xml", ".js", ".bat", ".cmd", ".ps1",
        ".properties", ".txt", ".log", ".trace", ".mnu", ".bin", ".html", ".htm", ".css", ".dat"
    };
    private static readonly HashSet<string> BinaryExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".jar"
    };
    private static readonly string[] TempTokens = [".tmp", ".temp", ".partial", ".download", ".new", ".old", ".bak", ".pending", ".lock"];
    private static readonly Regex FarmServerRegex = new(@"^server(?:\d+)?$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        if (!context.Sistema.TsplusDetectado || string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
            return Task.FromResult(CollectorResult.Empty);

        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var root = Path.GetFullPath(context.Sistema.TsplusRuta!);

        AuditReleaseFamily(context, root, events);
        AuditUpdateBlockers(root, context, findings, events);
        AuditKnownComponents(root, findings, events);
        var treeIndex = AuditFullTree(root, context, findings, events, cancellationToken);
        AuditFarm(root, treeIndex, findings, events);
        AuditFunctionalModuleTrees(root, treeIndex, context, events);

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static void AuditReleaseFamily(DiagnosticContext context, string root, List<DiagnosticEvent> events)
    {
        var raw = context.Sistema.TsplusVersion ?? string.Empty;
        var major = ParseMajor(raw);
        var family = major switch
        {
            >= 19 => "Rama actual v19+",
            18 => "v18 / LTS 18 compatible",
            17 => "v17 / LTS 17 compatible",
            16 => "v16 / LTS 16 (legado)",
            15 => "v15 / LTS 15 (legado)",
            14 => "v14 / LTS 14 (legado)",
            > 0 => $"Versión histórica {major}",
            _ => "No determinada"
        };

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TSplus",
            "Familia de versión",
            DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo,
            "TSPLUS_RELEASE_FAMILY",
            $"Familia de versión observada: {family}.",
            Evidencia:
            [
                new EvidenceItem("Versión detectada", string.IsNullOrWhiteSpace(raw) ? "N/D" : raw),
                new EvidenceItem("Familia", family),
                new EvidenceItem("Raíz", root),
                new EvidenceItem("Regla", "Las comprobaciones toleran layouts actuales y LTS; la ausencia de un archivo exclusivo de otra familia no se declara falla.")
            ],
            Producto: TsplusProduct.RemoteAccess));
    }

    private static void AuditUpdateBlockers(string root, DiagnosticContext context, List<DiagnosticFinding> findings, List<DiagnosticEvent> events)
    {
        var rebootFile = Path.Combine(root, "reboot_required.dat");
        var rebootProbe = FileSystemProbe.File(rebootFile);
        if (rebootProbe.IsAvailable)
        {
            var info = new FileInfo(rebootFile);
            findings.Add(new DiagnosticFinding(
                "TSPLUS-UPDATE-REBOOT-REQUIRED-DAT",
                "TSplus Update Release",
                DiagnosticSeverity.Critico,
                "Se detectó reboot_required.dat en la raíz de TSplus.",
                "TSplus documenta este archivo como un estado que puede impedir que Update Release continúe. TDM sólo lo detecta; no elimina el archivo ni reinicia el servidor.",
                [
                    new EvidenceItem("Archivo", rebootFile),
                    new EvidenceItem("Tamaño", info.Length.ToString()),
                    new EvidenceItem("Última modificación", info.LastWriteTime.ToString("O"))
                ],
                ConfidenceLevel.Confirmada,
                "TSplus — Updating Remote Access",
                "https://docs.tsplus.net/tsplus/updating-terminal-service-plus/",
                "Si el síntoma es una actualización bloqueada, siga el procedimiento oficial de TSplus: valide mantenimiento/reinicio y el estado del archivo antes de reintentar Update Release. TDM no ejecuta la corrección.",
                DiagnosticLayer.Tsplus));

            events.Add(new DiagnosticEvent(
                info.LastWriteTimeUtc == DateTime.MinValue ? DateTimeOffset.Now : new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero),
                "TSplus Update",
                "reboot_required.dat",
                DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Critico,
                "TSPLUS_UPDATE_BLOCKER",
                "Archivo reboot_required.dat presente en la raíz de TSplus.",
                Archivo: rebootFile,
                Producto: TsplusProduct.RemoteAccess));
        }

        if (rebootProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-UPDATE-REBOOT-COVERAGE", "TSplus Update Release", DiagnosticSeverity.Advertencia,
                "reboot_required.dat quedó NO EVALUADO.",
                "TDM no interpreta un fallo de acceso/E/S como ausencia del marcador de reinicio.",
                [new EvidenceItem("Archivo", rebootFile), new EvidenceItem("Estado", rebootProbe.StatusText), new EvidenceItem("Detalle", rebootProbe.Detail ?? "N/D")],
                ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Tsplus));
        }

        var suspicious = new List<FileInfo>();
        try
        {
            foreach (var path in Directory.EnumerateFiles(root, "*", SearchOption.TopDirectoryOnly))
            {
                var name = Path.GetFileName(path);
                if (name.Equals("reboot_required.dat", StringComparison.OrdinalIgnoreCase)) continue;
                var ext = Path.GetExtension(name);
                if (TempTokens.Contains(ext, StringComparer.OrdinalIgnoreCase) ||
                    name.Contains("update", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("upgrade", StringComparison.OrdinalIgnoreCase) ||
                    name.Contains("pending", StringComparison.OrdinalIgnoreCase))
                    suspicious.Add(new FileInfo(path));
            }
        }
        catch { }

        foreach (var info in suspicious.Take(30))
        {
            var ts = new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero);
            events.Add(new DiagnosticEvent(
                ts,
                "TSplus Filesystem",
                info.Name,
                DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Informativo,
                "TSPLUS_UPDATE_TEMP_ARTIFACT",
                "Artefacto temporal/de actualización observado. Se conserva como contexto y no se declara causa por su sola existencia.",
                Archivo: info.FullName,
                Evidencia:
                [
                    new EvidenceItem("Tamaño", info.Length.ToString()),
                    new EvidenceItem("Reciente en ventana", ts >= context.PeriodoInicio() ? "Sí" : "No")
                ],
                Producto: TsplusProduct.RemoteAccess));
        }
    }

    private static void AuditFarm(string root, InstallationTreeIndex treeIndex, List<DiagnosticFinding> findings, List<DiagnosticEvent> events)
    {
        var legacyLb = Path.Combine(root, "UserDesktop", "files", "GatewayPortalLoadBalancing.ini");
        var standardBalance = Path.Combine(root, "Clients", "webserver", "balance.bin");

        var lbCandidates = treeIndex.LegacyFarmConfigFiles.Prepend(legacyLb).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var balanceCandidates = treeIndex.BalanceFiles.Prepend(standardBalance).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var lb = lbCandidates.FirstOrDefault(path => FileSystemProbe.File(path).IsAvailable) ?? legacyLb;
        var balance = balanceCandidates.FirstOrDefault(path => FileSystemProbe.File(path).IsAvailable) ?? standardBalance;

        var lbFileProbe = FileSystemProbe.File(lb);
        var balanceFileProbe = FileSystemProbe.File(balance);
        var lbDataProbe = lbFileProbe.IsAvailable ? ReadSimpleIni(lb) : Propagate<Dictionary<string, Dictionary<string, string>>>(lbFileProbe);
        var serverEntriesProbe = lbFileProbe.IsAvailable ? ReadFarmServerLines(lb) : Propagate<List<KeyValuePair<string, string>>>(lbFileProbe);
        var balanceEntriesProbe = balanceFileProbe.IsAvailable ? ParseBalanceEntries(balance) : Propagate<Dictionary<string, BalanceEntryState>>(balanceFileProbe);

        var lbData = lbDataProbe.IsAvailable ? lbDataProbe.Value ?? new(StringComparer.OrdinalIgnoreCase) : new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        var settings = lbData.TryGetValue("Settings", out var set) ? set : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var load = lbData.TryGetValue("LoadComputation", out var lc) ? lc : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var serverEntries = serverEntriesProbe.IsAvailable ? serverEntriesProbe.Value ?? [] : [];
        var balanceEntries = balanceEntriesProbe.IsAvailable ? balanceEntriesProbe.Value ?? new(StringComparer.OrdinalIgnoreCase) : new Dictionary<string, BalanceEntryState>(StringComparer.OrdinalIgnoreCase);

        var activationKnown = false;
        var act = string.Empty;
        if (lbDataProbe.IsAvailable
            && settings.TryGetValue("Activated", out var activationValue)
            && activationValue is not null)
        {
            act = activationValue;
            activationKnown = true;
        }

        var activated = activationKnown && IsEnabled(act);
        var parsedServers = ParseFarmServers(serverEntries);
        var reverseProxyNames = balanceEntries.Keys.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();
        var validLegacyServers = parsedServers.Count(x => x.Valid);
        var farmEvidenceDetected = validLegacyServers > 0 || reverseProxyNames.Count > 0 || activated;
        var gatewayRole = farmEvidenceDetected;
        var coveragePartial = lbFileProbe.IsUnavailable || balanceFileProbe.IsUnavailable || lbDataProbe.IsUnavailable || serverEntriesProbe.IsUnavailable || balanceEntriesProbe.IsUnavailable;

        var farmEvidence = new List<EvidenceItem>
        {
            new("GatewayPortalLoadBalancing.ini (legado)", FileSystemProbe.Display(lbFileProbe, lb, "No localizado; no prueba ausencia de granja")),
            new("Fuente INI descubierta recursivamente", lbCandidates.Any(path => FileSystemProbe.File(path).IsAvailable) ? string.Join(" | ", lbCandidates.Where(path => FileSystemProbe.File(path).IsAvailable).Take(5)) : "Ninguna accesible"),
            new("Lectura INI", lbDataProbe.StatusText),
            new("Load Balancing activado", activationKnown ? (activated ? "Sí" : "No") : "No determinado"),
            new("Servidores definidos por INI legado", serverEntriesProbe.IsAvailable ? serverEntries.Count.ToString() : "NO EVALUADO"),
            new("Servidores válidos por INI legado", serverEntriesProbe.IsAvailable ? validLegacyServers.ToString() : "NO EVALUADO"),
            new("balance.bin", FileSystemProbe.Display(balanceFileProbe, balance, "No localizado")),
            new("Lectura balance.bin", balanceEntriesProbe.StatusText),
            new("Application Servers derivados de Reverse Proxy", balanceEntriesProbe.IsAvailable ? reverseProxyNames.Count.ToString() : "NO EVALUADO"),
            new("Nombres internos Reverse Proxy", balanceEntriesProbe.IsAvailable ? (reverseProxyNames.Count == 0 ? "Ninguno" : string.Join(" | ", reverseProxyNames)) : "NO EVALUADO"),
            new("Rol local inferido", coveragePartial && !farmEvidenceDetected ? "No determinado por cobertura parcial" : gatewayRole ? "Farm Controller / Gateway (evidencia local)" : "No determinado"),
            new("Evidencia de granja local", farmEvidenceDetected ? "Sí" : coveragePartial ? "No determinada" : "No"),
            new("Cobertura", coveragePartial ? "Parcial" : "Disponible")
        };
        if (settings.TryGetValue("StickySessions", out var sticky)) farmEvidence.Add(new("StickySessions", sticky));
        if (settings.TryGetValue("HeartbeatRefresh", out var hb)) farmEvidence.Add(new("HeartbeatRefresh", hb));
        if (load.Count > 0) farmEvidence.Add(new("Pesos", string.Join(" | ", load.Select(kv => $"{kv.Key}={kv.Value}"))));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TSplus Farm", "Load Balancing / Reverse Proxy", DiagnosticLayer.Tsplus,
            coveragePartial ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "TSPLUS_FARM_CONFIGURATION_STATE",
            coveragePartial ? "Configuración de granja inspeccionada con cobertura parcial; TDM no infiere Standalone ni ausencia desde fuentes no legibles." : "Configuración local de granja inspeccionada en modo de solo lectura.",
            Evidencia: farmEvidence, Producto: TsplusProduct.RemoteAccess));

        if (coveragePartial)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-FARM-COVERAGE", "TSplus Farm / Load Balancing", DiagnosticSeverity.Advertencia,
                "La configuración Farm/Reverse Proxy quedó parcialmente NO EVALUADA.",
                "No se emiten conclusiones críticas dependientes de archivos que no pudieron leerse.",
                farmEvidence, ConfidenceLevel.Confirmada, Capa: DiagnosticLayer.Tsplus));
        }

        if (activated && serverEntriesProbe.IsAvailable && balanceEntriesProbe.IsAvailable && parsedServers.All(x => !x.Valid) && reverseProxyNames.Count == 0)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-FARM-NO-SERVERS", "TSplus Farm / Load Balancing", DiagnosticSeverity.Critico,
                "Load Balancing aparece activado pero no se detectaron servidores válidos en fuentes legibles.",
                "La conclusión se emite sólo porque INI y balance.bin pudieron evaluarse; TDM no modifica la granja.",
                farmEvidence, ConfidenceLevel.Alta, "TSplus Farm / Load Balancing",
                "https://docs.tsplus.net/tsplus/load-balancing/",
                "Revise la granja en AdminTool y confirme Application Servers/nombres/puertos.", DiagnosticLayer.Tsplus));
        }

        if (serverEntriesProbe.IsAvailable)
        {
            foreach (var item in parsedServers.Where(x => !x.Valid))
            {
                findings.Add(new DiagnosticFinding(
                    $"TSPLUS-FARM-SERVER-{Sanitize(item.Key)}", "TSplus Farm / Server entry", DiagnosticSeverity.Advertencia,
                    $"La entrada de granja '{item.Key}' no tiene un formato de destino válido.",
                    "La fuente fue legible, pero la entrada no pudo interpretarse de forma segura.",
                    [new EvidenceItem("Archivo", lb), new EvidenceItem("Entrada", item.Raw)], ConfidenceLevel.Media,
                    "TSplus Farm / Load Balancing", "https://docs.tsplus.net/tsplus/load-balancing/",
                    "Compare la entrada con AdminTool; no edite el INI directamente sin respaldo.", DiagnosticLayer.Tsplus));
            }
        }

        if (activated && balanceEntriesProbe.IsAvailable && serverEntriesProbe.IsAvailable && balanceFileProbe.IsAvailable)
        {
            var balanceNames = balanceEntries.Keys.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var farmNames = parsedServers.Where(x => x.Valid && !string.IsNullOrWhiteSpace(x.InternalName)).Select(x => x.InternalName!).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (farmNames.Count > 0)
            {
                var missing = farmNames.Where(n => !balanceNames.Contains(n)).ToList();
                if (missing.Count > 0)
                {
                    findings.Add(new DiagnosticFinding(
                        "TSPLUS-FARM-BALANCE-NAME-MISMATCH", "TSplus Farm / Reverse Proxy", DiagnosticSeverity.Critico,
                        "Los nombres internos de la granja no coinciden completamente con balance.bin.",
                        "Ambas fuentes fueron legibles y la discrepancia es estructural.",
                        [new EvidenceItem("GatewayPortalLoadBalancing.ini", lb), new EvidenceItem("balance.bin", balance), new EvidenceItem("Nombres faltantes", string.Join(" | ", missing))],
                        ConfidenceLevel.Alta, "TSplus Support — Load Balancing and Reverse Proxy config files",
                        "https://support.tsplus.net/support/solutions/articles/44002263273-load-balancing-and-reverse-proxy-config-files",
                        "Compare ambos archivos con AdminTool y la topología real.", DiagnosticLayer.Tsplus));
                }
                foreach (var name in farmNames.Where(balanceEntries.ContainsKey))
                {
                    var entry = balanceEntries[name];
                    if (entry.LineCount >= 2 && entry.HasWeb && entry.HasRdp) continue;
                    findings.Add(new DiagnosticFinding(
                        $"TSPLUS-FARM-BALANCE-INCOMPLETE-{Sanitize(name)}", "TSplus Farm / Reverse Proxy", DiagnosticSeverity.Critico,
                        $"El Application Server '{name}' no tiene las dos rutas requeridas en balance.bin.",
                        "balance.bin fue legible y falta una ruta web o RDP esperada.",
                        [new EvidenceItem("Servidor interno", name), new EvidenceItem("Líneas detectadas", entry.LineCount.ToString()), new EvidenceItem("Ruta web", entry.HasWeb ? "Sí" : "No"), new EvidenceItem("Ruta RDP", entry.HasRdp ? "Sí" : "No"), new EvidenceItem("Archivo", balance)],
                        ConfidenceLevel.Alta, "TSplus Support — Load Balancing and Reverse Proxy config files",
                        "https://support.tsplus.net/support/solutions/articles/44002263273-load-balancing-and-reverse-proxy-config-files",
                        "Revise la definición del servidor en AdminTool.", DiagnosticLayer.Tsplus));
                }
            }
        }
    }

    private static void AuditKnownComponents(string root, List<DiagnosticFinding> findings, List<DiagnosticEvent> events)
    {
        var known = new (string Name, string Path, bool Strong)[]
        {
            ("AdminTool", Path.Combine(root, "UserDesktop", "files", "AdminTool.exe"), true),
            ("AppControl.ini", Path.Combine(root, "UserDesktop", "files", "AppControl.ini"), true),
            ("Web Portal", Path.Combine(root, "Clients", "www"), false),
            ("Web server", Path.Combine(root, "Clients", "webserver"), false)
        };

        foreach (var item in known)
        {
            var fileProbe = FileSystemProbe.File(item.Path);
            var dirProbe = fileProbe.IsAbsent ? FileSystemProbe.Directory(item.Path) : default;
            var present = fileProbe.IsAvailable || dirProbe.IsAvailable;
            var unavailable = fileProbe.IsUnavailable || (fileProbe.IsAbsent && dirProbe.IsUnavailable);
            var state = present ? "Presente" : unavailable ? "NO EVALUADO" : "Ausente confirmado";
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "TSplus Installation", item.Name, DiagnosticLayer.Tsplus,
                unavailable || (!present && item.Strong) ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
                "TSPLUS_KNOWN_COMPONENT_STATE",
                present ? "Componente/ruta esperado localizado." : unavailable ? "Componente/ruta NO EVALUADO por acceso/E/S." : "Componente/ruta no localizado en el layout actual.",
                Archivo: item.Path,
                Evidencia: [new EvidenceItem("Estado", state), new EvidenceItem("Cobertura", unavailable ? "Parcial" : "Disponible")],
                Producto: TsplusProduct.RemoteAccess));
        }
    }

    private static InstallationTreeIndex AuditFullTree(string root, DiagnosticContext context, List<DiagnosticFinding> findings, List<DiagnosticEvent> events, CancellationToken ct)
    {
        var index = new InstallationTreeIndex();
        var total = 0;
        var textCandidate = 0;
        var binaries = 0;
        var zeroBinaries = 0;
        var tempArtifacts = 0;
        var tempReported = 0;
        var recentChanges = 0;
        var configArtifacts = 0;
        var iniArtifacts = 0;
        var jsArtifacts = 0;
        var binArtifacts = 0;
        var configIssues = 0;
        var configBlocked = 0;
        var blocked = 0;
        var reparseSkipped = 0;
        var truncated = false;
        var start = context.PeriodoInicio();

        try
        {
            foreach (var path in EnumerateFilesBestEffort(root, cancellationToken: ct, onBlocked: () => blocked++, onReparseSkipped: () => reparseSkipped++))
            {
                ct.ThrowIfCancellationRequested();
                if (++total > MaxFiles) { truncated = true; break; }

                FileInfo info;
                try { info = new FileInfo(path); if (!info.Exists) continue; }
                catch { blocked++; continue; }

                TrackFarmArtifact(root, path, index);
                TrackFunctionalModuleArtifact(root, path, index);

                var ext = info.Extension;
                if (IsConfigurationArtifact(ext))
                {
                    configArtifacts++;
                    if (ext.Equals(".ini", StringComparison.OrdinalIgnoreCase)) iniArtifacts++;
                    if (ext.Equals(".js", StringComparison.OrdinalIgnoreCase)) jsArtifacts++;
                    if (ext.Equals(".bin", StringComparison.OrdinalIgnoreCase)) binArtifacts++;
                    var artifact = AuditConfigurationArtifact(root, path, info, context, findings, events);
                    if (artifact.Issue) configIssues++;
                    if (artifact.Blocked) configBlocked++;
                }
                if (TextExtensions.Contains(ext)) textCandidate++;
                if (BinaryExtensions.Contains(ext))
                {
                    binaries++;
                    if (info.Length == 0)
                    {
                        zeroBinaries++;
                        findings.Add(new DiagnosticFinding(
                            $"TSPLUS-ZERO-BINARY-{Sanitize(Relative(root, path))}",
                            "Integridad instalación TSplus",
                            DiagnosticSeverity.Critico,
                            "Se encontró un binario/archivo ejecutable TSplus de 0 bytes.",
                            "Un EXE/DLL/JAR vacío es una inconsistencia física verificable de la instalación. El impacto causal depende de si el componente participa en el incidente.",
                            [new EvidenceItem("Archivo", path), new EvidenceItem("Tamaño", "0 bytes")],
                            ConfidenceLevel.Confirmada,
                            Capa: DiagnosticLayer.Tsplus));
                    }
                }

                var isTemp = IsTempArtifact(info.Name);
                if (isTemp)
                {
                    tempArtifacts++;
                    if (tempReported < 50 && !info.Name.Equals("reboot_required.dat", StringComparison.OrdinalIgnoreCase))
                    {
                        tempReported++;
                        events.Add(new DiagnosticEvent(
                            DateTimeOffset.Now,
                            "TSplus Filesystem",
                            Relative(root, path),
                            DiagnosticLayer.Tsplus,
                            DiagnosticSeverity.Informativo,
                            "TSPLUS_TEMP_ARTIFACT_STATE",
                            "Artefacto temporal/de actualización localizado en el árbol TSplus. Su existencia se registra como estado y no se declara causa por sí sola.",
                            Archivo: path,
                            Evidencia:
                            [
                                new EvidenceItem("Última modificación", info.LastWriteTimeUtc.ToString("O")),
                                new EvidenceItem("Tamaño", info.Length.ToString()),
                                new EvidenceItem("Regla", "Contexto hasta que exista documentación específica o correlación con el incidente")
                            ],
                            Producto: TsplusProduct.RemoteAccess));
                    }
                }
                var modified = new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero);
                if (modified >= start && modified <= context.PeriodoFin())
                {
                    recentChanges++;
                    if (IsConfigOrCode(ext) || isTemp)
                    {
                        events.Add(new DiagnosticEvent(
                            modified,
                            "TSplus Filesystem",
                            Relative(root, path),
                            DiagnosticLayer.Tsplus,
                            DiagnosticSeverity.Informativo,
                            isTemp ? "TSPLUS_TEMP_FILE_CHANGE" : "TSPLUS_FILE_CHANGE",
                            "Archivo TSplus modificado dentro del periodo investigado; se conserva como antecedente temporal.",
                            Archivo: path,
                            Evidencia:
                            [
                                new EvidenceItem("Tamaño", info.Length.ToString()),
                                new EvidenceItem("Extensión", string.IsNullOrWhiteSpace(ext) ? "Sin extensión" : ext),
                                new EvidenceItem("Versión", TryVersion(path))
                            ],
                            Producto: TsplusProduct.RemoteAccess));
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { blocked++; }
        catch (IOException) { blocked++; }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Árbol completo TSplus",
            DiagnosticLayer.Tsplus,
            blocked > 0 || truncated ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "TSPLUS_FULL_TREE_AUDIT",
            "Inventario recursivo completo de la raíz TSplus finalizado en modo de solo lectura.",
            Archivo: root,
            Evidencia:
            [
                new EvidenceItem("Archivos examinados", Math.Min(total, MaxFiles).ToString()),
                new EvidenceItem("Candidatos de texto/configuración", textCandidate.ToString()),
                new EvidenceItem("Binarios EXE/DLL/JAR", binaries.ToString()),
                new EvidenceItem("Binarios de 0 bytes", zeroBinaries.ToString()),
                new EvidenceItem("Temporales/artefactos", tempArtifacts.ToString()),
                new EvidenceItem("Cambios recientes", recentChanges.ToString()),
                new EvidenceItem("Artefactos de configuración", configArtifacts.ToString()),
                new EvidenceItem("Archivos .ini", iniArtifacts.ToString()),
                new EvidenceItem("Archivos .js", jsArtifacts.ToString()),
                new EvidenceItem("Archivos .bin", binArtifacts.ToString()),
                new EvidenceItem("Configuraciones con incidencia", configIssues.ToString()),
                new EvidenceItem("Configuraciones no legibles", configBlocked.ToString()),
                new EvidenceItem("Rutas/archivos bloqueados", blocked.ToString()),
                new EvidenceItem("Reparse points omitidos", reparseSkipped.ToString()),
                new EvidenceItem("Inventario truncado", truncated ? $"Sí; límite {MaxFiles}" : "No"),
                new EvidenceItem("Cobertura", blocked > 0 || truncated ? "Parcial" : "Disponible"),
                new EvidenceItem("Cobertura de árbol", "Recursiva desde la raíz TSplus; todos los archivos accesibles se registran por nombre/metadatos hasta el límite de seguridad"),
                new EvidenceItem("Interpretación de contenido", "Selectiva: sólo formatos/configuraciones conocidos se analizan semánticamente; no se abre el contenido de cada archivo"),
                new EvidenceItem("Límite de archivos", MaxFiles.ToString())
            ],
            Producto: TsplusProduct.RemoteAccess));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Cobertura de configuración TSplus",
            DiagnosticLayer.Tsplus,
            configBlocked > 0 || truncated ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo,
            "TSPLUS_CONFIG_ARTIFACT_COVERAGE",
            "TDM examinó los artefactos de configuración accesibles del árbol TSplus, incluidos .ini, .js y .bin, sin ejecutar scripts ni modificar archivos.",
            Archivo: root,
            Evidencia:
            [
                new EvidenceItem("Cobertura", configBlocked > 0 || truncated ? "Parcial" : "Disponible"),
                new EvidenceItem("Artefactos examinados", configArtifacts.ToString()),
                new EvidenceItem(".ini", iniArtifacts.ToString()),
                new EvidenceItem(".js", jsArtifacts.ToString()),
                new EvidenceItem(".bin", binArtifacts.ToString()),
                new EvidenceItem("Incidencias de estructura/integridad", configIssues.ToString()),
                new EvidenceItem("No legibles", configBlocked.ToString()),
                new EvidenceItem("Inventario truncado", truncated ? "Sí" : "No"),
                new EvidenceItem("Interpretación", "INI: estructura básica; JS: metadatos/estructura conservadora sin ejecución; BIN: metadatos salvo parsers específicos conocidos como balance.bin")
            ],
            Producto: TsplusProduct.RemoteAccess));

        if (truncated)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-FULL-TREE-TRUNCATED",
                "Cobertura instalación TSplus",
                DiagnosticSeverity.Advertencia,
                "El árbol TSplus superó el límite de archivos de seguridad de TDM.",
                "No se puede declarar cobertura completa del árbol local porque el inventario fue limitado para evitar consumo excesivo.",
                [new EvidenceItem("Límite", MaxFiles.ToString()), new EvidenceItem("Raíz", root)],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
        }

        return index;
    }

    private static void AuditFunctionalModuleTrees(
        string root,
        InstallationTreeIndex index,
        DiagnosticContext context,
        List<DiagnosticEvent> events)
    {
        AddModuleFileSetState(
            root,
            "Web Server / HTML5 / Web Portal",
            "TSPLUS_WEB_FILESET_STATE",
            index.WebArtifactCandidates,
            context,
            events,
            ["runwebserver.bat", "httpwebs.jar", "HTML5Service.exe", "settings.bin", "appsettings.json", "common_applications.js"]);

        AddModuleFileSetState(
            root,
            "Publicación de aplicaciones",
            "TSPLUS_APPLICATION_FILESET_STATE",
            index.ApplicationArtifactCandidates,
            context,
            events,
            ["AppControl.ini"]);

        AddModuleFileSetState(
            root,
            "Sesiones / logon TSplus",
            "TSPLUS_SESSION_FILESET_STATE",
            index.SessionArtifactCandidates,
            context,
            events,
            ["logonsession.exe"]);

        // Un inventario recursivo sirve para descubrir cambios y ausencias respecto a un baseline,
        // pero no convierte por sí mismo un archivo en causa raíz. Las causas siguen exigiendo
        // correlación con configuración, servicio/proceso, eventos/logs o impacto funcional.
        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            "Cobertura recursiva por módulo",
            DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo,
            "TSPLUS_MODULE_RECURSIVE_COVERAGE",
            "Web, Aplicaciones y Sesiones reutilizan el inventario recursivo completo de la raíz TSplus; la interpretación causal continúa siendo selectiva.",
            Archivo: root,
            Evidencia:
            [
                new EvidenceItem("Raíz", root),
                new EvidenceItem("Web / candidatos", index.WebArtifactCandidates.Count.ToString()),
                new EvidenceItem("Aplicaciones / candidatos", index.ApplicationArtifactCandidates.Count.ToString()),
                new EvidenceItem("Sesiones / candidatos", index.SessionArtifactCandidates.Count.ToString()),
                new EvidenceItem("Regla", "Archivo faltante/cambiado = evidencia; causa raíz sólo con correlación funcional")
            ],
            Producto: TsplusProduct.RemoteAccess));
    }

    private static void AddModuleFileSetState(
        string root,
        string component,
        string type,
        IReadOnlyList<string> candidates,
        DiagnosticContext context,
        List<DiagnosticEvent> events,
        IReadOnlyList<string> knownNames)
    {
        var distinct = candidates
            .Where(path => FileSystemProbe.File(path).IsAvailable)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(p => Relative(root, p), StringComparer.OrdinalIgnoreCase)
            .ToList();

        var stable = distinct.Where(IsStableModuleFile).ToList();
        var dynamicFiles = distinct.Count - stable.Count;
        var binaries = stable.Count(p => BinaryExtensions.Contains(Path.GetExtension(p)));
        var configs = stable.Count(p => TextExtensions.Contains(Path.GetExtension(p)));
        var zeroBytes = stable.Count(p => SafeLength(p) == 0);
        var start = context.PeriodoInicio();
        var end = context.PeriodoFin();
        var recent = stable.Count(p =>
        {
            var ts = SafeLastWrite(p);
            return ts.HasValue && ts.Value >= start && ts.Value <= end;
        });

        var manifest = BuildManifest(root, stable, 120);
        var fingerprint = BuildModuleFingerprint(root, stable);
        var evidence = new List<EvidenceItem>
        {
            new("Cobertura", "Recursiva desde la raíz TSplus; un único recorrido del árbol alimenta este módulo"),
            new("Archivos funcionales estables", stable.Count.ToString()),
            new("Archivos dinámicos/logs", dynamicFiles.ToString()),
            new("Binarios EXE/DLL/JAR", binaries.ToString()),
            new("Configuración/script", configs.ToString()),
            new("Archivos de 0 bytes", zeroBytes.ToString()),
            new("Cambios recientes", recent.ToString()),
            new("Huella del conjunto", fingerprint),
            new("Manifest funcional", manifest)
        };

        foreach (var name in knownNames)
        {
            var matches = distinct.Where(p => Path.GetFileName(p).Equals(name, StringComparison.OrdinalIgnoreCase)).Take(5).ToList();
            var match = matches.FirstOrDefault();
            evidence.Add(new EvidenceItem(name, matches.Count == 0 ? "No localizado en el árbol" : string.Join(" | ", matches)));

            // Estado estable por archivo funcional conocido. Mantener una observación aun cuando
            // el archivo no esté presente permite que el baseline detecte Presente → Ausente
            // sin interpretar como falla cualquier archivo opcional que nunca estuvo instalado.
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now,
                "TDM",
                $"{component} / {name}",
                DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Informativo,
                "TSPLUS_MODULE_CRITICAL_FILE_STATE",
                string.IsNullOrWhiteSpace(match)
                    ? "Archivo funcional conocido no localizado en el árbol actual; por sí solo no se declara falla."
                    : "Archivo funcional conocido localizado en el árbol TSplus.",
                Evidencia:
                [
                    new EvidenceItem("Módulo", component),
                    new EvidenceItem("Nombre", name),
                    new EvidenceItem("Presente", string.IsNullOrWhiteSpace(match) ? "No" : "Sí"),
                    new EvidenceItem("Ruta detectada", match ?? "No localizada"),
                    new EvidenceItem("Tamaño", string.IsNullOrWhiteSpace(match) ? "N/D" : SafeLength(match).ToString()),
                    new EvidenceItem("Versión", string.IsNullOrWhiteSpace(match) ? "N/D" : TryVersion(match)),
                    new EvidenceItem("SHA-256", string.IsNullOrWhiteSpace(match) ? "N/D" : TrySha256(match))
                ],
                Producto: TsplusProduct.RemoteAccess));
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now,
            "TDM",
            component,
            DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo,
            type,
            "Inventario funcional recursivo del módulo construido en modo de solo lectura.",
            Archivo: root,
            Evidencia: evidence,
            Producto: TsplusProduct.RemoteAccess));
    }

    private static void TrackFunctionalModuleArtifact(string root, string path, InstallationTreeIndex index)
    {
        var relative = Relative(root, path).Replace('\\', '/').ToLowerInvariant();
        var name = Path.GetFileName(path).ToLowerInvariant();

        var web = relative.StartsWith("clients/webserver/", StringComparison.Ordinal)
            || relative.StartsWith("clients/webportal/", StringComparison.Ordinal)
            || relative.StartsWith("clients/www/", StringComparison.Ordinal)
            || name is "runwebserver.bat" or "httpwebs.jar" or "html5service.exe" or "appsettings.json" or "common_applications.js" or "webportal.log";
        if (web) AddBounded(index.WebArtifactCandidates, path, 6000);

        var application = name == "appcontrol.ini"
            || relative.Contains("appcontrol", StringComparison.Ordinal)
            || relative.Contains("remoteapp", StringComparison.Ordinal)
            || relative.Contains("seamless", StringComparison.Ordinal)
            || relative.Contains("applicationpanel", StringComparison.Ordinal)
            || relative.Contains("application-panel", StringComparison.Ordinal)
            || relative.Contains("floatingpanel", StringComparison.Ordinal)
            || relative.Contains("floating-panel", StringComparison.Ordinal)
            || name.Contains("myremoteapp", StringComparison.Ordinal);
        if (application) AddBounded(index.ApplicationArtifactCandidates, path, 3000);

        var session = name.StartsWith("apsc", StringComparison.Ordinal)
            || name.StartsWith("logonsession", StringComparison.Ordinal)
            || relative.Contains("sessioncontrol", StringComparison.Ordinal)
            || relative.Contains("session-control", StringComparison.Ordinal)
            || relative.Contains("sessions/", StringComparison.Ordinal)
            || relative.Contains("/session/", StringComparison.Ordinal);
        if (session) AddBounded(index.SessionArtifactCandidates, path, 3000);
    }

    private static void AddBounded(List<string> list, string path, int max)
    {
        if (list.Count < max) list.Add(path);
    }

    private static bool IsStableModuleFile(string path)
    {
        var ext = Path.GetExtension(path);
        if (ext.Equals(".log", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".trace", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".tmp", StringComparison.OrdinalIgnoreCase) ||
            ext.Equals(".temp", StringComparison.OrdinalIgnoreCase)) return false;
        return TextExtensions.Contains(ext) || BinaryExtensions.Contains(ext);
    }

    private static long SafeLength(string path)
    {
        try { return new FileInfo(path).Length; } catch { return -1; }
    }

    private static DateTimeOffset? SafeLastWrite(string path)
    {
        try { return new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero); } catch { return null; }
    }

    private static string TrySha256(string path)
    {
        try
        {
            // Sólo se calcula para el pequeño conjunto de archivos funcionales conocidos.
            // No se hashea todo el árbol para evitar I/O innecesario en servidores de cliente.
            const long maxBytes = 64L * 1024 * 1024;
            var info = new FileInfo(path);
            if (!info.Exists) return "N/D";
            if (info.Length > maxBytes) return $"Omitido (>{maxBytes / 1024 / 1024} MB)";
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.SequentialScan);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch
        {
            return "No disponible";
        }
    }

    private static string BuildManifest(string root, IReadOnlyList<string> files, int maxItems)
    {
        var parts = files.Take(maxItems).Select(p => Relative(root, p)).ToList();
        var value = parts.Count == 0 ? "Ninguno" : string.Join(" | ", parts);
        if (files.Count > maxItems) value += $" | … +{files.Count - maxItems} archivo(s)";
        return value.Length <= 6000 ? value : value[..6000] + "…";
    }

    private static string BuildModuleFingerprint(string root, IReadOnlyList<string> files)
    {
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var path in files.OrderBy(p => Relative(root, p), StringComparer.OrdinalIgnoreCase))
        {
            var lastWrite = SafeLastWrite(path);
            var row = $"{Relative(root, path)}|{SafeLength(path)}|{TryVersion(path)}|{(lastWrite.HasValue ? lastWrite.Value.UtcDateTime.Ticks : 0)}\n";
            sha.AppendData(Encoding.UTF8.GetBytes(row));
        }
        return Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
    }

    private static void TrackFarmArtifact(string root, string path, InstallationTreeIndex index)
    {
        var name = Path.GetFileName(path);
        if (name.Equals("GatewayPortalLoadBalancing.ini", StringComparison.OrdinalIgnoreCase))
            index.LegacyFarmConfigFiles.Add(path);
        if (name.Equals("balance.bin", StringComparison.OrdinalIgnoreCase))
            index.BalanceFiles.Add(path);

        if (index.FarmArtifactCandidates.Count >= 250) return;
        var relative = Relative(root, path);
        var lower = relative.ToLowerInvariant();
        if (lower.Contains("farm") || lower.Contains("gateway") || lower.Contains("loadbalanc")
            || lower.Contains("reverseproxy") || lower.Contains("reverse-proxy") || lower.Contains("balance"))
            index.FarmArtifactCandidates.Add(path);
    }

    private static IEnumerable<string> EnumerateFilesBestEffort(
        string root,
        CancellationToken cancellationToken,
        Action onBlocked,
        Action onReparseSkipped)
    {
        var pending = new Stack<string>();
        pending.Push(root);
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = pending.Pop();

            string[] files;
            try { files = Directory.GetFiles(current); }
            catch (UnauthorizedAccessException) { onBlocked(); continue; }
            catch (IOException) { onBlocked(); continue; }

            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return file;
            }

            string[] directories;
            try { directories = Directory.GetDirectories(current); }
            catch (UnauthorizedAccessException) { onBlocked(); continue; }
            catch (IOException) { onBlocked(); continue; }

            for (var i = directories.Length - 1; i >= 0; i--)
            {
                var directory = directories[i];
                try
                {
                    if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                    {
                        onReparseSkipped();
                        continue;
                    }
                }
                catch
                {
                    onBlocked();
                    continue;
                }
                pending.Push(directory);
            }
        }
    }

    private static int ParseMajor(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return 0;
        var match = Regex.Match(value, @"(?<!\d)(\d{1,2})(?:\.|$)");
        return match.Success && int.TryParse(match.Groups[1].Value, out var n) ? n : 0;
    }

    private static ProbeResult<Dictionary<string, Dictionary<string, string>>> ReadSimpleIni(string path)
    {
        var result = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (new FileInfo(path).Length > MaxTextBytes) return ProbeResult<Dictionary<string, Dictionary<string, string>>>.Unavailable("Archivo supera límite de lectura");
            var section = string.Empty;
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#')) continue;
                if (line.StartsWith('[') && line.EndsWith(']'))
                {
                    section = line[1..^1].Trim();
                    if (!result.ContainsKey(section)) result[section] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    continue;
                }
                var idx = line.IndexOf('=');
                if (idx <= 0) continue;
                if (!result.TryGetValue(section, out var dict)) result[section] = dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                dict[line[..idx].Trim()] = line[(idx + 1)..].Trim();
            }
            return ProbeResult<Dictionary<string, Dictionary<string, string>>>.Available(result);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<Dictionary<string, Dictionary<string, string>>>.AccessDenied(ex.Message); }
        catch (IOException ex) { return ProbeResult<Dictionary<string, Dictionary<string, string>>>.Error(ex.Message); }
    }

    private static ProbeResult<List<KeyValuePair<string, string>>> ReadFarmServerLines(string path)
    {
        var output = new List<KeyValuePair<string, string>>();
        try
        {
            if (new FileInfo(path).Length > MaxTextBytes) return ProbeResult<List<KeyValuePair<string, string>>>.Unavailable("Archivo supera límite de lectura");
            var section = string.Empty;
            var index = 0;
            foreach (var raw in File.ReadLines(path))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#')) continue;
                if (line.StartsWith('[') && line.EndsWith(']')) { section = line[1..^1].Trim(); continue; }
                if (!section.Equals("Servers", StringComparison.OrdinalIgnoreCase)) continue;
                var sep = line.IndexOf('=');
                if (sep <= 0) continue;
                var key = line[..sep].Trim();
                if (!FarmServerRegex.IsMatch(key)) continue;
                output.Add(new KeyValuePair<string, string>($"{key}[{++index}]", line[(sep + 1)..].Trim()));
            }
            return ProbeResult<List<KeyValuePair<string, string>>>.Available(output);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<List<KeyValuePair<string, string>>>.AccessDenied(ex.Message); }
        catch (IOException ex) { return ProbeResult<List<KeyValuePair<string, string>>>.Error(ex.Message); }
    }

    private static List<FarmServer> ParseFarmServers(IEnumerable<KeyValuePair<string, string>> servers)
    {
        var output = new List<FarmServer>();
        foreach (var kv in servers)
        {
            var raw = kv.Value.Trim();
            if (string.IsNullOrWhiteSpace(raw))
            {
                output.Add(new FarmServer(kv.Key, raw, null, false));
                continue;
            }

            // Formato documentado: título|host/~~internalName|protocolo|puerto||estado (enabled/disabled)
            var parts = raw.Split('|');
            var address = parts.Length > 1 ? parts[1].Trim() : string.Empty;
            var protocol = parts.Length > 2 ? parts[2].Trim() : string.Empty;
            var portText = parts.Length > 3 ? parts[3].Trim() : string.Empty;
            var state = parts.Length > 5 ? parts[^1].Trim() : string.Empty;
            var internalName = ExtractInternalName(address);
            var validProtocol = protocol.Equals("http", StringComparison.OrdinalIgnoreCase) || protocol.Equals("https", StringComparison.OrdinalIgnoreCase);
            var validPort = int.TryParse(portText, out var port) && port is > 0 and <= 65535;
            var validState = state.Equals("enabled", StringComparison.OrdinalIgnoreCase) || state.Equals("disabled", StringComparison.OrdinalIgnoreCase);
            var valid = parts.Length >= 6 && !string.IsNullOrWhiteSpace(parts[0]) && !string.IsNullOrWhiteSpace(address) && validProtocol && validPort && validState;
            output.Add(new FarmServer(kv.Key, raw, internalName, valid));
        }
        return output;
    }

    private static string? ExtractInternalName(string raw)
    {
        var m = Regex.Match(raw, @"/~~([^/:?\s]+)", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : null;
    }

    private static ProbeResult<Dictionary<string, BalanceEntryState>> ParseBalanceEntries(string path)
    {
        var entries = new Dictionary<string, BalanceEntryState>(StringComparer.OrdinalIgnoreCase);
        var probe = FileSystemProbe.File(path);
        if (probe.IsAbsent) return ProbeResult<Dictionary<string, BalanceEntryState>>.Absent();
        if (probe.IsUnavailable) return Propagate<Dictionary<string, BalanceEntryState>>(probe);
        try
        {
            if (new FileInfo(path).Length > MaxTextBytes) return ProbeResult<Dictionary<string, BalanceEntryState>>.Unavailable("Archivo supera límite de lectura");
            foreach (var line in File.ReadLines(path))
            {
                var m = Regex.Match(line, @"/~~([^=/:?\s]+)\s*=", RegexOptions.IgnoreCase);
                if (!m.Success) continue;
                var name = m.Groups[1].Value;
                entries.TryGetValue(name, out var state);
                state ??= new BalanceEntryState();
                state.LineCount++;
                if (line.Contains("RDPPORT", StringComparison.OrdinalIgnoreCase)) state.HasRdp = true;
                else state.HasWeb = true;
                entries[name] = state;
            }
            return ProbeResult<Dictionary<string, BalanceEntryState>>.Available(entries);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<Dictionary<string, BalanceEntryState>>.AccessDenied(ex.Message); }
        catch (IOException ex) { return ProbeResult<Dictionary<string, BalanceEntryState>>.Error(ex.Message); }
    }

    private static ProbeResult<T> Propagate<T>(ProbeResult<bool> probe) => probe.State switch
    {
        ProbeState.Absent => ProbeResult<T>.Absent(probe.Detail ?? "Ausencia confirmada"),
        ProbeState.AccessDenied => ProbeResult<T>.AccessDenied(probe.Detail ?? "Acceso denegado"),
        ProbeState.Error => ProbeResult<T>.Error(probe.Detail ?? "Error de lectura"),
        _ => ProbeResult<T>.Unavailable(probe.Detail ?? "No disponible")
    };

    private static ArtifactAuditResult AuditConfigurationArtifact(
        string root,
        string path,
        FileInfo info,
        DiagnosticContext context,
        List<DiagnosticFinding> findings,
        List<DiagnosticEvent> events)
    {
        var ext = info.Extension.ToLowerInvariant();
        var name = info.Name;
        var descriptor = TsplusConfigurationArtifactCatalog.Find(name);
        var known = descriptor is not null;
        var modified = new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero);
        var recent = modified >= context.PeriodoInicio() && modified <= context.PeriodoFin();
        var issue = info.Length == 0;
        var blocked = false;
        var structure = "Metadatos solamente";
        var parser = descriptor?.ParserPolicy ?? "Genérico / metadatos";
        var detail = "Archivo de configuración inventariado.";

        if (info.Length == 0)
        {
            detail = "Archivo de configuración de 0 bytes.";
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-CONFIG-ZERO-{Sanitize(Relative(root, path))}",
                name,
                DiagnosticSeverity.Error,
                "Se encontró un archivo de configuración TSplus de 0 bytes.",
                "Un archivo de configuración vacío puede impedir que el componente asociado cargue sus parámetros. TDM no modifica el archivo.",
                [new EvidenceItem("Archivo", path), new EvidenceItem("Extensión", ext)],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Tsplus));
        }

        if (info.Length > 0 && info.Length <= MaxTextBytes)
        {
            if (ext == ".ini")
            {
                parser = "INI / estructura básica";
                try
                {
                    var lines = File.ReadAllLines(path);
                    var meaningful = 0;
                    var malformed = 0;
                    var sections = 0;
                    foreach (var raw in lines)
                    {
                        var line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith(';') || line.StartsWith('#')) continue;
                        meaningful++;
                        if (line.StartsWith('[') && line.EndsWith(']')) { sections++; continue; }
                        if (!line.Contains('=')) malformed++;
                    }
                    structure = malformed == 0 ? $"Estructura legible; secciones={sections}; entradas={meaningful - sections}" : $"Estructura dudosa; líneas no reconocidas={malformed}/{meaningful}";
                    if (meaningful > 0 && malformed >= Math.Max(4, meaningful / 3))
                    {
                        issue = true;
                        findings.Add(new DiagnosticFinding(
                            $"TSPLUS-CONFIG-INI-STRUCTURE-{Sanitize(Relative(root, path))}",
                            name,
                            DiagnosticSeverity.Advertencia,
                            "La estructura básica del archivo INI no coincide con un formato clave/valor esperado.",
                            "TDM sólo valida la estructura básica y no asume que todas las claves sean conocidas. Revise el archivo si el componente asociado presenta una falla.",
                            [new EvidenceItem("Archivo", path), new EvidenceItem("Líneas no reconocidas", malformed.ToString()), new EvidenceItem("Líneas evaluadas", meaningful.ToString())],
                            ConfidenceLevel.Media,
                            Capa: DiagnosticLayer.Tsplus));
                    }
                }
                catch (UnauthorizedAccessException ex) { blocked = true; structure = "No legible: " + ex.Message; }
                catch (IOException ex) { blocked = true; structure = "No legible: " + ex.Message; }
            }
            else if (ext == ".js")
            {
                parser = "JavaScript / lectura segura sin ejecución";
                try
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
                    using var reader = new StreamReader(stream, Encoding.UTF8, true, 4096, leaveOpen: false);
                    var text = reader.ReadToEnd();
                    var hasNull = text.IndexOf('\0') >= 0;
                    structure = hasNull ? "Contenido no textual o codificación no reconocida" : $"Texto legible; caracteres={text.Length}";
                    if (hasNull)
                    {
                        issue = true;
                        findings.Add(new DiagnosticFinding(
                            $"TSPLUS-CONFIG-JS-STRUCTURE-{Sanitize(Relative(root, path))}", name, DiagnosticSeverity.Advertencia,
                            "El archivo JavaScript de configuración no pudo interpretarse de forma segura como texto.",
                            "TDM no ejecuta JavaScript. La comprobación se limita a legibilidad/codificación y metadatos; revise este archivo si el componente asociado presenta una falla.",
                            [new EvidenceItem("Archivo", path), new EvidenceItem("Estado", structure)], ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus));
                    }
                }
                catch (UnauthorizedAccessException ex) { blocked = true; structure = "No legible: " + ex.Message; }
                catch (IOException ex) { blocked = true; structure = "No legible: " + ex.Message; }
            }
            else if (ext == ".json")
            {
                parser = "JSON / sintaxis";
                try
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
                    using var document = JsonDocument.Parse(stream, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
                    structure = $"JSON válido; raíz={document.RootElement.ValueKind}";
                }
                catch (JsonException ex)
                {
                    issue = true;
                    structure = "JSON inválido: " + ex.Message;
                    findings.Add(new DiagnosticFinding(
                        $"TSPLUS-CONFIG-JSON-STRUCTURE-{Sanitize(Relative(root, path))}", name, DiagnosticSeverity.Advertencia,
                        "La configuración JSON no pudo interpretarse como JSON válido.",
                        "TDM validó sintaxis únicamente; no modifica el archivo ni presupone qué claves son obligatorias para esta versión.",
                        [new EvidenceItem("Archivo", path), new EvidenceItem("Error", ex.Message)], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Tsplus));
                }
                catch (UnauthorizedAccessException ex) { blocked = true; structure = "No legible: " + ex.Message; }
                catch (IOException ex) { blocked = true; structure = "No legible: " + ex.Message; }
            }
            else if (ext is ".xml" or ".config")
            {
                parser = "XML/configuración / sintaxis";
                try
                {
                    using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);
                    var document = XDocument.Load(stream, LoadOptions.None);
                    structure = $"XML válido; raíz={document.Root?.Name.LocalName ?? "N/D"}";
                }
                catch (System.Xml.XmlException ex)
                {
                    issue = true;
                    structure = "XML inválido: " + ex.Message;
                    findings.Add(new DiagnosticFinding(
                        $"TSPLUS-CONFIG-XML-STRUCTURE-{Sanitize(Relative(root, path))}", name, DiagnosticSeverity.Advertencia,
                        "La configuración XML no pudo interpretarse como XML válido.",
                        "TDM validó sintaxis únicamente; no modifica el archivo ni presupone qué nodos son obligatorios para esta versión.",
                        [new EvidenceItem("Archivo", path), new EvidenceItem("Error", ex.Message)], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Tsplus));
                }
                catch (UnauthorizedAccessException ex) { blocked = true; structure = "No legible: " + ex.Message; }
                catch (IOException ex) { blocked = true; structure = "No legible: " + ex.Message; }
            }
            else if (ext is ".cfg" or ".conf" or ".properties")
            {
                parser = "Clave/valor / estructura básica";
                try
                {
                    var lines = File.ReadAllLines(path);
                    var meaningful = 0;
                    var malformed = 0;
                    foreach (var raw in lines)
                    {
                        var line = raw.Trim();
                        if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;
                        meaningful++;
                        if (!line.Contains('=') && !line.Contains(':')) malformed++;
                    }
                    structure = malformed == 0 ? $"Estructura legible; entradas={meaningful}" : $"Estructura dudosa; líneas no reconocidas={malformed}/{meaningful}";
                    if (meaningful > 0 && malformed >= Math.Max(4, meaningful / 3))
                    {
                        issue = true;
                        findings.Add(new DiagnosticFinding(
                            $"TSPLUS-CONFIG-KV-STRUCTURE-{Sanitize(Relative(root, path))}", name, DiagnosticSeverity.Advertencia,
                            "La estructura básica del archivo de configuración no coincide con un formato clave/valor esperado.",
                            "TDM sólo valida la estructura conservadora del archivo y no presupone qué claves son obligatorias para esta versión.",
                            [new EvidenceItem("Archivo", path), new EvidenceItem("Líneas no reconocidas", malformed.ToString()), new EvidenceItem("Líneas evaluadas", meaningful.ToString())],
                            ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus));
                    }
                }
                catch (UnauthorizedAccessException ex) { blocked = true; structure = "No legible: " + ex.Message; }
                catch (IOException ex) { blocked = true; structure = "No legible: " + ex.Message; }
            }
            else if (ext == ".bin")
            {
                if (name.Equals("balance.bin", StringComparison.OrdinalIgnoreCase))
                {
                    parser = "balance.bin / granja y Reverse Proxy";
                    var entriesProbe = ParseBalanceEntries(path);
                    if (entriesProbe.IsAvailable) structure = $"Parser específico; servidores internos detectados={entriesProbe.Value?.Count ?? 0}";
                    else { blocked = true; structure = $"NO EVALUADO: {entriesProbe.StatusText}"; }
                }
                else
                {
                    parser = "BIN / metadatos solamente";
                    structure = "No se interpreta como texto sin un parser específico conocido";
                }
            }
        }
        else if (info.Length > MaxTextBytes && ext is ".ini" or ".js")
        {
            structure = $"Contenido omitido por límite de {MaxTextBytes / 1024 / 1024} MB; metadatos disponibles";
        }

        var shouldEmit = known || recent || issue || blocked;
        if (shouldEmit)
        {
            var severity = blocked || issue ? DiagnosticSeverity.Advertencia : DiagnosticSeverity.Informativo;
            events.Add(new DiagnosticEvent(
                modified,
                "TSplus Filesystem",
                TsplusConfigurationArtifactCatalog.ClassifyComponent(path),
                DiagnosticLayer.Tsplus,
                severity,
                "TSPLUS_CONFIG_ARTIFACT_STATE",
                detail,
                Archivo: path,
                Evidencia:
                [
                    new EvidenceItem("Archivo", Relative(root, path)),
                    new EvidenceItem("Extensión", string.IsNullOrWhiteSpace(ext) ? "Sin extensión" : ext),
                    new EvidenceItem("Tamaño", info.Length.ToString()),
                    new EvidenceItem("Última modificación", info.LastWriteTimeUtc.ToString("O")),
                    new EvidenceItem("Conocido por TDM", known ? "Sí" : "No"),
                    new EvidenceItem("Modificado en ventana", recent ? "Sí" : "No"),
                    new EvidenceItem("Parser", parser),
                    new EvidenceItem("Estructura", structure),
                    new EvidenceItem("SHA-256", known && info.Length <= 64L * 1024 * 1024 ? TrySha256(path) : "Omitido para reducir I/O")
                ],
                Producto: TsplusConfigurationArtifactCatalog.ClassifyProduct(path)));
        }

        return new ArtifactAuditResult(issue, blocked);
    }

    private static bool IsConfigurationArtifact(string ext)
        => ext.Equals(".ini", StringComparison.OrdinalIgnoreCase)
           || ext.Equals(".js", StringComparison.OrdinalIgnoreCase)
           || ext.Equals(".bin", StringComparison.OrdinalIgnoreCase)
           || ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
           || ext.Equals(".xml", StringComparison.OrdinalIgnoreCase)
           || ext.Equals(".cfg", StringComparison.OrdinalIgnoreCase)
           || ext.Equals(".conf", StringComparison.OrdinalIgnoreCase)
           || ext.Equals(".config", StringComparison.OrdinalIgnoreCase)
           || ext.Equals(".properties", StringComparison.OrdinalIgnoreCase)
           || ext.Equals(".dat", StringComparison.OrdinalIgnoreCase);

    private sealed record ArtifactAuditResult(bool Issue, bool Blocked);

    private static bool IsEnabled(string value) => value.Trim() is "1" or "true" or "yes" or "on" or "si" or "sí";
    private static bool IsTempArtifact(string name)
    {
        var lower = name.ToLowerInvariant();
        return TempTokens.Any(lower.EndsWith) || lower.Contains("reboot_required") || lower.Contains("pending") || lower.Contains("update.tmp") || lower.Contains("upgrade.tmp");
    }
    private static bool IsConfigOrCode(string ext) => TextExtensions.Contains(ext) || BinaryExtensions.Contains(ext);
    private static string Relative(string root, string path)
    {
        try { return Path.GetRelativePath(root, path); } catch { return path; }
    }
    private static string TryVersion(string path)
    {
        try
        {
            var ext = Path.GetExtension(path);
            if (!ext.Equals(".exe", StringComparison.OrdinalIgnoreCase) && !ext.Equals(".dll", StringComparison.OrdinalIgnoreCase)) return "N/D";
            return FileVersionInfo.GetVersionInfo(path).FileVersion ?? "N/D";
        }
        catch { return "N/D"; }
    }
    private static string Sanitize(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value) sb.Append(char.IsLetterOrDigit(c) ? c : '-');
        return sb.ToString().Trim('-');
    }

    private sealed record FarmServer(string Key, string Raw, string? InternalName, bool Valid);
    private sealed class InstallationTreeIndex
    {
        public List<string> LegacyFarmConfigFiles { get; } = [];
        public List<string> BalanceFiles { get; } = [];
        public List<string> FarmArtifactCandidates { get; } = [];
        public List<string> WebArtifactCandidates { get; } = [];
        public List<string> ApplicationArtifactCandidates { get; } = [];
        public List<string> SessionArtifactCandidates { get; } = [];
    }

    private sealed class BalanceEntryState
    {
        public int LineCount { get; set; }
        public bool HasWeb { get; set; }
        public bool HasRdp { get; set; }
    }
}

internal static class DiagnosticContextWindowExtensions
{
    public static DateTimeOffset PeriodoFin(this DiagnosticContext context) => context.HoraIncidente ?? DateTimeOffset.Now;
    public static DateTimeOffset PeriodoInicio(this DiagnosticContext context) => context.PeriodoFin() - context.Lookback;
}
