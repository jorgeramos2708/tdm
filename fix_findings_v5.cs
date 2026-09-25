using System;
using System.IO;
using System.Text;

class Program
{
    static void Main()
    {
        var path = @"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs";
        var content = File.ReadAllText(path, Encoding.UTF8);

        // Fix findings loop - add anchors
        var oldFindings = "foreach (var f in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200))\r\n            sb.Append($\"<tr><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td>{H(f.Componente)}</td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>\");";

        var newFindings = @"foreach (var (f, fi) in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200).Select((x, i) => (x, i + 1)))
            sb.Append($""<tr id='fnd-{fi}' class='anchor-target'><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td><a class='anchor-link' href='#fnd-{fi}'>{H(f.Componente)}</a></td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>"");";

        var content = File.ReadAllText(path, Encoding.UTF8);
        content = content.Replace(oldFindings, newFindings);
        File.WriteAllText(path, content, Encoding.UTF8);
        Console.WriteLine("Done");
    }
}