using System.ComponentModel;
using System.Diagnostics;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.TSplus;

/// <summary>
/// Dependencias no-SCM por proceso: inventaría los módulos cargados por cada proceso
/// cuyo ejecutable vive bajo la raíz TSplus y señala ejecutables/DLL ausentes en disco
/// (falla de arranque predecible) y cargas desde rutas temporales (sospecha de
/// interferencia). Solo lectura; cada proceso se aísla en try/catch para que un
/// proceso protegido no tumbe el inventario. Con topes de procesos y módulos.
/// </summary>
public sealed class TsplusProcessDependencyCollector : IReadOnlyCollector
{
    public string Nombre => "Dependencias por proceso TSplus";

    private const int MaxProcesses = 32;
    private const int MaxModulesPerProcess = 256;
    private const int MaxMissingFindings = 5;
    private const int MaxSuspiciousFindings = 5;

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        if (!context.Sistema.TsplusDetectado || string.IsNullOrWhiteSpace(context.Sistema.TsplusRuta))
            return Task.FromResult(new CollectorResult(findings, events));

        var install = context.Sistema.TsplusRuta!;
        var examined = 0;
        var skippedProtected = 0;
        var beyondCap = 0;
        var processEvidence = new List<EvidenceItem>();
        var missing = new List<(string Process, int Pid, string Module)>();
        var suspicious = new List<(string Process, int Pid, string Module)>();

        foreach (var proc in Process.GetProcesses())
        {
            cancellationToken.ThrowIfCancellationRequested();
            using (proc)
            {
                string? mainPath = null;
                try { mainPath = proc.MainModule?.FileName; }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or UnauthorizedAccessException)
                {
                    skippedProtected++;
                    continue;
                }
                if (!TsplusProcessModulePolicy.IsUnderRoot(mainPath, install)) continue;
                if (examined >= MaxProcesses) { beyondCap++; continue; }
                examined++;

                var moduleCount = 0;
                var missingCount = 0;
                try
                {
                    foreach (ProcessModule module in proc.Modules)
                    {
                        if (moduleCount++ >= MaxModulesPerProcess) break;
                        string? modulePath = null;
                        try { modulePath = module.FileName; }
                        catch (Exception ex) when (ex is Win32Exception or InvalidOperationException) { continue; }
                        if (string.IsNullOrWhiteSpace(modulePath)) continue;
                        var exists = true;
                        try { exists = File.Exists(modulePath); }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
                        if (!exists)
                        {
                            missingCount++;
                            if (missing.Count < MaxMissingFindings * 4)
                                missing.Add((proc.ProcessName, proc.Id, modulePath));
                        }
                        else if (TsplusProcessModulePolicy.IsSuspiciousLocation(modulePath)
                                 && suspicious.Count < MaxSuspiciousFindings * 4)
                        {
                            suspicious.Add((proc.ProcessName, proc.Id, modulePath));
                        }
                    }
                }
                catch (Exception ex) when (ex is Win32Exception or InvalidOperationException or UnauthorizedAccessException)
                {
                    skippedProtected++;
                    continue;
                }
                processEvidence.Add(new EvidenceItem($"{proc.ProcessName} (PID {proc.Id})",
                    $"{moduleCount} módulos, {missingCount} faltantes"));
            }
        }

        foreach (var (process, pid, module) in missing.Take(MaxMissingFindings))
        {
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-PROCESS-MODULE-MISSING-{Sanitize(process)}-{Sanitize(Path.GetFileName(module))}",
                process,
                DiagnosticSeverity.Error,
                $"Un proceso TSplus tiene cargado o referenciado un módulo que ya no existe en disco: {module}.",
                "Un módulo ausente anticipa fallos de arranque o errores de carga (SideBySide/Dependencia) aunque el proceso siga vivo por ahora. Verifique reinstalación, antivirus/cuarentena o limpieza de disco.",
                [new EvidenceItem("Proceso", $"{process} (PID {pid})"),
                 new EvidenceItem("Módulo ausente", module)],
                ConfidenceLevel.Alta,
                Capa: DiagnosticLayer.Tsplus));
        }
        foreach (var (process, pid, module) in suspicious.Take(MaxSuspiciousFindings))
        {
            findings.Add(new DiagnosticFinding(
                $"TSPLUS-PROCESS-MODULE-SUSPICIOUS-{Sanitize(process)}-{Sanitize(Path.GetFileName(module))}",
                process,
                DiagnosticSeverity.Advertencia,
                $"Un proceso TSplus cargó un módulo desde una ruta temporal o de descargas: {module}.",
                "Cargar código fuera de la instalación y del sistema es el patrón típico de interferencia de terceros o de despliegues manuales. TDM no lo declara malicioso sin más evidencia.",
                [new EvidenceItem("Proceso", $"{process} (PID {pid})"),
                 new EvidenceItem("Módulo", module)],
                ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Tsplus));
        }

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Dependencias por proceso TSplus", DiagnosticLayer.Tsplus,
            DiagnosticSeverity.Informativo, "TSPLUS_PROCESS_DEPENDENCY_COVERAGE",
            $"Inventario de módulos: {examined} procesos TSplus, {missing.Count} módulos faltantes, {suspicious.Count} en rutas sospechosas.",
            Evidencia: [.. processEvidence.Take(32),
                new EvidenceItem("Procesos examinados", examined.ToString()),
                new EvidenceItem("Procesos no evaluables", skippedProtected.ToString()),
                new EvidenceItem("Procesos fuera de tope", beyondCap.ToString()),
                new EvidenceItem("Módulos faltantes", missing.Count.ToString()),
                new EvidenceItem("Módulos sospechosos", suspicious.Count.ToString())],
            Producto: TsplusProduct.RemoteAccess));
        return Task.FromResult(new CollectorResult(findings, events));
    }

    private static string Sanitize(string? value)
        => new((value ?? "X").Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).Take(24).ToArray());
}
