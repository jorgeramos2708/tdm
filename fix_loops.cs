using System;
using System.IO;
using System.Text;

class Program
{
    static void Main()
    {
        var path = @"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs";
        var content = File.ReadAllText(path, Encoding.UTF8);

        // Fix causes loop
        var oldCauses = "foreach (var c in report.CausasRaiz.Take(8))\r\n            {\r\n            sb.Append($\"<h3>#{c.Posicion} \u2020 {H(c.Componente)}</h3><p><span class='badge'>{H(c.Confianza.ToString())}</span><span class='badge muted'>ranking {c.Puntaje}/100</span><span class='badge'>{H(c.Capa.ToString())}</span><span class='badge'>{H(c.Producto.ToString())}</span><span class='badge'>Origen {H(c.OrigenClasificado)}</span></p>\");";

        var newCauses = @"foreach (var c in report.CausasRaiz.Take(8))
            {
                var causeAnchor = ""cau-"" + c.Posicion;
                sb.Append($""<h3 id='{causeAnchor}' class='anchor-target'><a class='anchor-link' href='#{causeAnchor}'>#{c.Posicion} \u2020 {H(c.Componente)}</a></h3><p><span class='badge'>{H(c.Confianza.ToString())}</span><span class='badge muted'>ranking {c.Puntaje}/100</span><span class='badge'>{H(c.Capa.ToString())}</span><span class='badge'>{H(c.Producto.ToString())}</span><span class='badge'>Origen {H(c.OrigenClasificado)}</span></p>"");";

        content = content.Replace(oldCauses, newCauses);

        // Fix findings loop
        var oldFindings = "foreach (var f in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200))\r\n            sb.Append($\"<tr><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td>{H(f.Componente)}</td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>\");";

        var newFindings = @"foreach (var (f, fi) in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200).Select((x, i) => (x, i + 1)))
            sb.Append($""<tr id='fnd-{fi}' class='anchor-target'><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td><a class='anchor-link' href='#fnd-{fi}'>{H(f.Componente)}</a></td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>"");";

        content = content.Replace(oldCauses, newCauses);
        content = content.Replace(oldFindings, newFindings);

        File.WriteAllText(path, content, Encoding.UTF8);
        Console.WriteLine("Done");
    }
}