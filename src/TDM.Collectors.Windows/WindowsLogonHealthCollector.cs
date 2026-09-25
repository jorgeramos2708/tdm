using System.Diagnostics.Eventing.Reader;
using TDM.Core;
using TDM.Models;

namespace TDM.Collectors.Windows;

/// <summary>
/// Impacto medido de autenticación: cuenta 4624/4625/4634/4740 del log de Seguridad
/// en la ventana y solo eleva hallazgos con volumen y tasa suficientes (ver
/// <see cref="EvaluateCounts"/>). No convierte eventos individuales; el incremental
/// ya cubre la señal en vivo. Solo lectura, con techo de enumeración y salida
/// ordenada de más reciente a más antiguo para cortar al salir de la ventana.
/// </summary>
public sealed class WindowsLogonHealthCollector : IReadOnlyCollector
{
    public string Nombre => "Salud de inicio de sesión Windows";

    private const int MaxRecords = 5000;
    public const int MinFailures = 10;
    public const double MinFailureRate = 0.2;
    public const int MinLockouts = 3;

    public Task<CollectorResult> CollectAsync(DiagnosticContext context, CancellationToken cancellationToken = default)
    {
        var findings = new List<DiagnosticFinding>();
        var events = new List<DiagnosticEvent>();
        var windowEnd = context.HoraIncidente ?? DateTimeOffset.Now;
        var windowStart = windowEnd - context.Lookback;
        long success = 0, failed = 0, logoffs = 0, lockouts = 0, examined = 0;
        var coverage = "Disponible";
        var coverageDetail = "Conteo completado dentro de la ventana.";

        var xpath = $"*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4740) and TimeCreated[@SystemTime>='{windowStart.UtcDateTime:O}']]]";
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, xpath) { ReverseDirection = true };
            using var reader = new EventLogReader(query);
            while (reader.ReadEvent() is { } record)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using (record)
                {
                    if (examined >= MaxRecords) { coverage = "Parcial"; coverageDetail = $"Techo de enumeración alcanzado ({MaxRecords})."; break; }
                    var time = record.TimeCreated?.ToUniversalTime();
                    if (time.HasValue && time.Value < windowStart.UtcDateTime) break;
                    examined++;
                    switch (record.Id)
                    {
                        case 4624: success++; break;
                        case 4625: failed++; break;
                        case 4634: logoffs++; break;
                        case 4740: lockouts++; break;
                    }
                }
            }
        }
        catch (EventLogNotFoundException ex)
        {
            coverage = "No evaluado"; coverageDetail = "Canal Security no disponible: " + ex.Message;
        }
        catch (UnauthorizedAccessException ex)
        {
            coverage = "No evaluado"; coverageDetail = "Sin permisos de lectura: " + ex.Message;
        }
        catch (EventLogException ex)
        {
            coverage = "No evaluado"; coverageDetail = "No legible: " + ex.Message;
        }

        if (coverage == "Disponible")
            findings.AddRange(EvaluateCounts(success, failed, lockouts, windowEnd));

        events.Add(new DiagnosticEvent(
            DateTimeOffset.Now, "TDM", "Autenticación Windows", DiagnosticLayer.Seguridad,
            coverage == "Disponible" ? DiagnosticSeverity.Informativo : DiagnosticSeverity.Advertencia,
            "WINDOWS_LOGON_COVERAGE",
            $"Conteo medido de autenticación en ventana: {success} correctos, {failed} fallidos, {logoffs} cierres, {lockouts} bloqueos.",
            Evidencia:
            [
                new EvidenceItem("Cobertura", coverage),
                new EvidenceItem("Detalle", coverageDetail),
                new EvidenceItem("Inicios correctos (4624)", success.ToString()),
                new EvidenceItem("Fallos (4625)", failed.ToString()),
                new EvidenceItem("Cierres (4634)", logoffs.ToString()),
                new EvidenceItem("Bloqueos (4740)", lockouts.ToString()),
                new EvidenceItem("Registros examinados", examined.ToString())
            ]));
        return Task.FromResult(new CollectorResult(findings, events));
    }

    /// <summary>
    /// Regla pura de elevación: volumen Y tasa, nunca una sola anécdota.
    /// </summary>
    public static IReadOnlyList<DiagnosticFinding> EvaluateCounts(long success, long failed, long lockouts, DateTimeOffset windowEnd)
    {
        var findings = new List<DiagnosticFinding>();
        var total = success + failed;
        if (failed >= MinFailures && total > 0 && failed / (double)total >= MinFailureRate)
        {
            var rate = failed / (double)total;
            findings.Add(new DiagnosticFinding(
                "WINDOWS-LOGON-FAILURE-SURGE",
                "Autenticación Windows",
                failed >= 50 ? DiagnosticSeverity.Error : DiagnosticSeverity.Advertencia,
                $"Oleada medida de fallos de inicio de sesión: {failed} de {total} intentos ({rate:P0}) en la ventana.",
                "Tasa y volumen medidos en el log de Seguridad, no inferidos. Un pico de 4625 sostenido suele preceder o acompañar bloqueos y quejas de acceso; correlacione con 4740 y con el origen antes de atribuir.",
                [new EvidenceItem("Inicios correctos (4624)", success.ToString()),
                 new EvidenceItem("Fallos (4625)", failed.ToString()),
                 new EvidenceItem("Tasa de fallo", rate.ToString("P1")),
                 new EvidenceItem("Ventana fin", windowEnd.ToString("O"))],
                total >= 50 ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Seguridad));
        }
        if (lockouts >= MinLockouts)
        {
            findings.Add(new DiagnosticFinding(
                "WINDOWS-ACCOUNT-LOCKOUTS",
                "Autenticación Windows",
                DiagnosticSeverity.Advertencia,
                $"Se midieron {lockouts} bloqueos de cuenta (4740) en la ventana.",
                "Los bloqueos confirman impacto a usuarios concretos. Revise qué cuentas y desde qué origen antes de tratarlo como ataque o como falla.",
                [new EvidenceItem("Bloqueos (4740)", lockouts.ToString()),
                 new EvidenceItem("Ventana fin", windowEnd.ToString("O"))],
                lockouts >= 10 ? ConfidenceLevel.Alta : ConfidenceLevel.Media,
                Capa: DiagnosticLayer.Seguridad));
        }
        return findings;
    }
}
