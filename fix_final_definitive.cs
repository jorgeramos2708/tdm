using System;
using System.IO;
using System.Text;

class Program
{
    static void Main()
    {
        var path = @"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs";
        var content = File.ReadAllText(path, Encoding.UTF8);

        // Find the causes loop start
        var startMarker = "foreach (var c in report.CausasRaiz.Take(8))";
        var startIndex = content.IndexOf(startMarker);
        if (startIndex < 0) { Console.WriteLine("Start marker not found"); return; }
        
        // Find the matching closing brace
        var braceCount = 0;
        var endIndex = -1;
        var inString = false;
        var escapeNext = false;
        
        for (int i = startIndex; i < content.Length; i++)
        {
            char c = content[i];
            if (escapeNext) { escapeNext = false; continue; }
            if (c == '\\') { escapeNext = true; continue; }
            if (c == '"' && !escapeNext) inString = !inString;
            if (!inString)
            {
                if (c == '{') braceCount++;
                else if (c == '}') { braceCount--; if (braceCount == 0) { endIndex = i + 1; break; } }
            }
        }
        
        if (endIndex > 0)
        {
            var newBlock = @"foreach (var c in report.CausasRaiz.Take(8))
            {
                var causeAnchor = ""cau-"" + c.Posicion;
                sb.Append($""<h3 id='{causeAnchor}' class='anchor-target'><a class='anchor-link' href='#{causeAnchor}'>#{c.Posicion} \u2020 {H(c.Componente)}</a></h3><p><span class='badge'>{H(c.Confianza.ToString())}</span><span class='badge muted'>ranking {c.Puntaje}/100</span><span class='badge'>{H(c.Capa.ToString())}</span><span class='badge'>{H(c.Producto.ToString())}</span><span class='badge'>Origen {H(c.OrigenClasificado)}</span></p>"");";
            
            var newContent = content.Substring(0, startIndex) + newBlock + content.Substring(endIndex);
            File.WriteAllText(path, newContent, Encoding.UTF8);
            Console.WriteLine("Done");
        }
        else
        {
            Console.WriteLine("End not found");
        }
    }
}