using System.Diagnostics;
using Microsoft.Win32;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

public sealed class TsplusBaselineCollector : IReadOnlyCollector
{
    public string Nombre => "Baseline de instalación TSplus";

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();

        if (!context.Sistema.TsplusDetectado || string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
        {
            events.Add(new DiagnosticEvent(
                DateTimeOffset.Now, "TDM", "TSplus Baseline", DiagnosticLayer.Tsplus,
                DiagnosticSeverity.Informativo, "TSPLUS_BASELINE_UNAVAILABLE",
                "No se construyó baseline de Remote Access porque el producto no está detectado."));
            return Task.FromResult(new CollectorResult(findings, events));
        }

        var installPath = context.Sistema.TsplusRuta!;
        var adminTool = Path.Combine(installPath, "UserDesktop", "files", "AdminTool.exe");
        var webRoot = Path.Combine(installPath, "Clients", "www");
        var systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        var wsession = Path.Combine(systemDrive, "wsession");
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var tsplusMajor = ParseMajor(context.Sistema.TsplusVersion);
        var modernRuntime = tsplusMajor >= 18;
        var netRequirementLabel = modernRuntime ? ".NET Framework 4.7.2+" : ".NET Framework 4.6.2+";
        var netReleaseMinimum = modernRuntime ? 461808 : 394802;
        var netProbe = HasNetFrameworkReleaseAtLeast(netReleaseMinimum);
        var installProbe = FileSystemProbe.Directory(installPath);
        var adminProbe = FileSystemProbe.File(adminTool);
        var wsessionProbe = FileSystemProbe.Directory(wsession);
        var webProbe = FileSystemProbe.Directory(webRoot);

        var evidence = new List<EvidenceItem>
        {
            new("Ruta de instalación", installPath),
            new("Ruta existe", FileSystemProbe.Display(installProbe, "Sí", "No")),
            new("Versión detectada", context.Sistema.TsplusVersion ?? "N/D"),
            new("AdminTool.exe", DescribeFile(adminTool, adminProbe)),
            new("C:\\wsession", FileSystemProbe.Display(wsessionProbe)),
            new("Raíz web Clients\\www", FileSystemProbe.Display(webProbe)),
            new(netRequirementLabel, netProbe.IsAvailable ? (netProbe.Value == true ? "Detectado" : "No cumple/no confirmado") : netProbe.IsAbsent ? "Ausente confirmado" : "NO EVALUADO"),
            new("Regla de requisito .NET", modernRuntime ? "TSplus 18+ → 4.7.2+" : "Rama anterior → 4.6.2+"),
            new("Sistema compatible con objetivo TDM", IsSupportedTargetOs(context.Sistema) ? "Sí" : "No confirmado")
        };

        var documentedProgramDataFiles = new[]
        {
            "alternateshell.exe", "logonsession.exe", "removelastfolders.exe", "svcr.exe", "uninst.exe"
        };
        foreach (var name in documentedProgramDataFiles)
        {
            var path = Path.Combine(programData, name);
            evidence.Add(new EvidenceItem($"ProgramData:{name}", FileSystemProbe.Display(FileSystemProbe.File(path))));
        }

        var logs = TsplusLogDiscovery.Discover(installPath);
        var remoteAccessLogs = logs.Where(x => !x.Componente.Equals("TSplus Advanced Security", StringComparison.OrdinalIgnoreCase)).ToList();
        evidence.Add(new EvidenceItem("Fuentes de log Remote Access disponibles", $"{remoteAccessLogs.Count(x => x.Existe)}/{remoteAccessLogs.Count}"));
        foreach (var log in remoteAccessLogs)
            evidence.Add(new EvidenceItem($"Log:{log.Componente}", log.Existe ? $"Disponible ({log.Ruta})" : $"No disponible ({log.Ruta})"));

        var java = FindJava(installPath);
        evidence.Add(new EvidenceItem("Java/OpenJDK", java.Description));

        if (adminProbe.IsAbsent)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-BASELINE-ADMINTOOL",
                "TSplus Remote Access",
                DiagnosticSeverity.Advertencia,
                "No se encontró AdminTool.exe en la ubicación documentada de la instalación detectada.",
                "Esto puede indicar una instalación incompleta, una ruta no estándar o que TDM no identificó correctamente la raíz de instalación. TDM no modifica ni repara archivos.",
                [new EvidenceItem("Ruta esperada", adminTool), new EvidenceItem("Ruta instalación", installPath)],
                ConfidenceLevel.Media,
                "TSplus — Installation / soporte oficial",
                "https://docs.tsplus.net/tsplus/installation/",
                "Verifique primero que la ruta de instalación detectada sea correcta y contraste el contenido con la instalación/documentación oficial antes de reinstalar o modificar TSplus.",
                DiagnosticLayer.Tsplus));
        }

        if (adminProbe.IsUnavailable || installProbe.IsUnavailable || wsessionProbe.IsUnavailable || webProbe.IsUnavailable || netProbe.IsUnavailable)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-BASELINE-COVERAGE",
                "TSplus Installation Baseline",
                DiagnosticSeverity.Advertencia,
                "Una o más fuentes del baseline quedaron NO EVALUADAS.",
                "TDM conserva la incertidumbre y no transforma un fallo de acceso/lectura en ausencia o estado sano.",
                [new EvidenceItem("Instalación", installProbe.StatusText), new EvidenceItem("AdminTool", adminProbe.StatusText),
                 new EvidenceItem("wsession", wsessionProbe.StatusText), new EvidenceItem("Web", webProbe.StatusText), new EvidenceItem(".NET", netProbe.StatusText)],
                ConfidenceLevel.Alta, Capa: DiagnosticLayer.Tsplus));
        }

        if (netProbe.IsAbsent || (netProbe.IsAvailable && netProbe.Value != true))
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-BASELINE-DOTNET",
                ".NET Framework",
                DiagnosticSeverity.Advertencia,
                $"No se pudo confirmar {netRequirementLabel}.",
                "TDM aplica el requisito por familia de versión TSplus para evitar validar una rama moderna contra un mínimo histórico.",
                [new EvidenceItem("Requisito aplicado", netRequirementLabel), new EvidenceItem("Versión TSplus", context.Sistema.TsplusVersion ?? "N/D")],
                ConfidenceLevel.Alta,
                "TSplus — Remote Access Prerequisites",
                "https://docs.tsplus.net/tsplus/pre-requisites/",
                "Confirme la versión de .NET Framework instalada siguiendo la documentación oficial. TDM no instala ni actualiza componentes.",
                DiagnosticLayer.Windows));
        }

        if (webProbe.IsAvailable && !java.Is17OrGreater)
        {
            findings.Add(new DiagnosticFinding(
                "TSPLUS-BASELINE-JAVA",
                "TSplus Web Server / Java",
                DiagnosticSeverity.Advertencia,
                "Se detectaron componentes web de TSplus, pero no se pudo confirmar Java/OpenJDK 17 o superior.",
                "La documentación actual de TSplus indica OpenJDK 17 o superior para el servidor web integrado. La detección de TDM es conservadora y no concluye que Java esté ausente si no puede resolver su versión.",
                [new EvidenceItem("Raíz web", webRoot), new EvidenceItem("Java detectado", java.Description)],
                ConfidenceLevel.Media,
                "TSplus — Remote Access Prerequisites",
                "https://docs.tsplus.net/tsplus/pre-requisites/",
                "Compruebe la instalación/configuración de Java/OpenJDK según la documentación oficial de TSplus. No realice cambios hasta confirmar que el servidor web integrado está en uso.",
                DiagnosticLayer.Tsplus));
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "TSplus Installation Baseline", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_INSTALLATION_BASELINE",
            "Baseline técnico de la instalación TSplus capturado en modo de solo lectura.",
            Evidencia: evidence));

        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static string DescribeFile(string path, ProbeResult<bool>? knownProbe = null)
    {
        var probe = knownProbe ?? FileSystemProbe.File(path);
        if (probe.IsAbsent) return "No presente";
        if (!probe.IsAvailable) return "NO EVALUADO · " + probe.StatusText;
        try
        {
            var info = FileVersionInfo.GetVersionInfo(path);
            var version = info.ProductVersion ?? info.FileVersion ?? "N/D";
            return $"Presente; versión {version}";
        }
        catch (Exception ex) { return $"Presente; versión NO EVALUADA ({ex.GetType().Name})"; }
    }

    private static ProbeResult<bool> HasNetFrameworkReleaseAtLeast(int minimumRelease)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            using var ndp = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full", false);
            if (ndp is null) return ProbeResult<bool>.Absent("Clave .NET v4 Full ausente");
            var release = ndp.GetValue("Release");
            return release is int value ? ProbeResult<bool>.Available(value >= minimumRelease)
                : ProbeResult<bool>.Available(false);
        }
        catch (UnauthorizedAccessException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (System.Security.SecurityException ex) { return ProbeResult<bool>.AccessDenied(ex.Message); }
        catch (Exception ex) { return ProbeResult<bool>.Error(ex.Message); }
    }

    private static int ParseMajor(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return 0;
        var digits = new string(raw.SkipWhile(c => !char.IsDigit(c)).TakeWhile(char.IsDigit).ToArray());
        return int.TryParse(digits, out var value) ? value : 0;
    }

    private static bool IsSupportedTargetOs(SystemSnapshot s)
    {
        var text = $"{s.SistemaOperativo} {s.Version}";
        if (text.Contains("Windows 11", StringComparison.OrdinalIgnoreCase)) return true;
        return new[] { "Server 2016", "Server 2019", "Server 2022", "Server 2025" }
            .Any(v => text.Contains(v, StringComparison.OrdinalIgnoreCase));
    }

    private static (bool Is17OrGreater, string Description) FindJava(string installPath)
    {
        var candidates = new List<string>();
        var javaHome = Environment.GetEnvironmentVariable("JAVA_HOME");
        if (!string.IsNullOrWhiteSpace(javaHome)) candidates.Add(Path.Combine(javaHome, "bin", "java.exe"));

        candidates.AddRange(new[]
        {
            Path.Combine(installPath, "Java", "bin", "HTML5service.exe"),
            Path.Combine(installPath, "Java", "bin", "java.exe"),
            Path.Combine(installPath, "jre", "bin", "java.exe"),
            Path.Combine(installPath, "jdk", "bin", "java.exe")
        });

        foreach (var candidate in candidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var candidateProbe = FileSystemProbe.File(candidate);
                if (!candidateProbe.IsAvailable) continue;
                var info = FileVersionInfo.GetVersionInfo(candidate);
                var raw = info.ProductVersion ?? info.FileVersion ?? string.Empty;
                var majorText = new string(raw.TakeWhile(char.IsDigit).ToArray());
                var ok = int.TryParse(majorText, out var major) && major >= 17;
                return (ok, $"{candidate}; versión {raw}; {(ok ? "17+ confirmado" : "17+ no confirmado")}");
            }
            catch { }
        }

        return (false, "No determinado");
    }

}
