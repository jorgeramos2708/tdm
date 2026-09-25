using System;
using System.IO;
using System.Text;

var path = @"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs";
var content = File.ReadAllText(path, Encoding.UTF8);

// Fix the causes loop
var oldCauses = @"foreach (var c in report.CausasRaiz.Take(8))
            {
            sb.Append($""<h3>#{c.Posicion} \u2020 {H(c.Componente)}</h3><p><span class='badge'>{H(c.Confianza.ToString())}</span><span class='badge muted'>ranking {c.Puntaje}/100</span><span class='badge'>{H(c.Capa.ToString())}</span><span class='badge'>{H(c.Producto.ToString())}</span><span class='badge'>Origen {H(c.OrigenClasificado)}</span></p>"");";

var newCauses = @"foreach (var c in report.CausasRaiz.Take(8))
            {
                var causeAnchor = ""cau-"" + c.Posicion;
                sb.Append($""<h3 id='{causeAnchor}' class='anchor-target'><a class='anchor-link' href='#{causeAnchor}'>#{c.Posicion} \u2020 {H(c.Componente)}</a></h3><p><span class='badge'>{H(c.Confianza.ToString())}</span><span class='badge muted'>ranking {c.Puntaje}/100</span><span class='badge'>{H(c.Capa.ToString())}</span><span class='badge'>{H(c.Producto.ToString())}</span><span class='badge'>Origen {H(c.OrigenClasificado)}</span></p>"");";

var content = File.ReadAllText(path, Encoding.UTF8);
content = content.Replace(oldCauses, newCauses);
File.WriteAllText(path, content, Encoding.UTF8);
Console.WriteLine("Done");