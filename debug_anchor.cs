using System;
using System.IO;
using System.Text;
using TDM.Models;
using TDM.Reporting;

class Program
{
    static void Main()
    {
        var now = DateTimeOffset.Now;
        var prev = new DiagnosticReport(
            new SystemSnapshot("TEST", "Windows", "1.0", "1", "x64", TimeSpan.FromHours(1), now, true, @"C:\TSplus", "1.0"),
            [], [],
            now.AddHours(-4), now)
        {
            Lookback = TimeSpan.FromHours(4),
            LookbackSolicitado = TimeSpan.FromHours(4),
            PeriodoAnalizadoInicio = now.AddHours(-4),
            PeriodoAnalizadoFin = now,
            EvidenciaDisponibleLookback = TimeSpan.FromHours(4),
            PeriodoEvidenciaInicio = now.AddHours(-4),
            PeriodoEvidenciaFin = now,
            CausasRaiz = [
                new RootCauseCandidate(2, "ROOT-A", "Comp-ROOT-A", DiagnosticLayer.Tsplus, 80, ConfidenceLevel.Alta, "resumen", "explicacion", [], Producto: TsplusProduct.RemoteAccess, OrigenClasificado: "TSPLUS")
            ]
        };
        
        var current = new DiagnosticReport(
            new SystemSnapshot("TEST", "Windows", "1.0", "1", "x64", TimeSpan.FromHours(1), now, true, @"C:\TSplus", "1.0"),
            [], [],
            now.AddHours(-4), now)
        {
            Lookback = TimeSpan.FromHours(4),
            LookbackSolicitado = TimeSpan.FromHours(4),
            PeriodoAnalizadoInicio = now.AddHours(-4),
            PeriodoAnalizadoFin = now,
            EvidenciaDisponibleLookback = TimeSpan.FromHours(4),
            PeriodoEvidenciaInicio = now.AddHours(-4),
            PeriodoEvidenciaFin = now,
            CausasRaiz = [
                new RootCauseCandidate(2, "ROOT-A", "Comp-ROOT-A", DiagnosticLayer.Tsplus, 80, ConfidenceLevel.Alta, "resumen", "explicacion", [], Producto: TsplusProduct.RemoteAccess, OrigenClasificado: "TSPLUS")
            ]
        };
        current = current with
        {
            Hallazgos = [
                new DiagnosticFinding("F-NEW", "Comp-New", DiagnosticSeverity.Error, "hallazgo nuevo", "", [], ConfidenceLevel.Alta, Capa: DiagnosticLayer.Tsplus),
                new DiagnosticFinding("F-REL", "Comp-ROOT-A", DiagnosticSeverity.Advertencia, "hallazgo relacionado", "", [], ConfidenceLevel.Media, Capa: DiagnosticLayer.Tsplus)
            ]
        };
        current = current with
        {
            CausasRaiz = [new RootCauseCandidate(2, "ROOT-A", "Comp-ROOT-A", DiagnosticLayer.Tsplus, 80, ConfidenceLevel.Alta, "resumen", "explicacion", [], Producto: TsplusProduct.RemoteAccess, OrigenClasificado: "TSPLUS")]
        };

        var dir = Path.Combine(Path.GetTempPath(), "TDM-Test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var result = ReportExporter.ExportAsync(current, dir, CancellationToken.None, prev).GetAwaiter().GetResult();
            var html = File.ReadAllText(result.HtmlPath);
            
            Console.WriteLine("=== HTML Contains cau-2 ===");
            Console.WriteLine(html.Contains("id='cau-2'"));
            
            Console.WriteLine("=== HTML Contains cau-2 (double quotes) ===");
            Console.WriteLine(html.Contains("id=\"cau-2\""));
            
            // Find the cause section
            var start = html.IndexOf("<h3");
            while (start >= 0)
            {
                var end = html.IndexOf("</h3>", start);
                if (end < 0) break;
                Console.WriteLine(html.Substring(start, end - start + 5));
                start = html.IndexOf("<h3", end);
            }
        }
        finally { Directory.Delete(dir, true); }
    }
}