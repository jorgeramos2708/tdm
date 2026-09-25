using System;
using System.IO;
using System.Text;

class Program
{
    static void Main()
    {
        var path = @"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs";
        var content = File.ReadAllText(path, Encoding.UTF8);

        // 1. Fix ExportAsync signature
        content = content.Replace(
            "public static async Task<ReportExportResult> ExportAsync(\n        DiagnosticReport report,\n        string directory,\n        CancellationToken ct = default)",
            "public static async Task<ReportExportResult> ExportAsync(\n        DiagnosticReport report,\n        string directory,\n        CancellationToken ct = default,\n        DiagnosticReport? previousReport = null)");

        // 2. Add diff injection logic
        var oldWrite = @"await File.WriteAllTextAsync(jsonPath, json, new UTF8Encoding(false), ct);
        await File.WriteAllTextAsync(htmlPath, BuildHtml(safeReport, sanitized: true), new UTF8Encoding(false), ct);

        // P23: un reporte vac�o/corrupto nunca debe exportarse como �xito operativo.
        var jsonBytes = new FileInfo(jsonPath).Length;
        var htmlBytes = new FileInfo(htmlPath).Length;
        if (jsonBytes <= 0 || htmlBytes <= 0)
            throw new IOException($""La exportaci�n gener� archivos vac�os: json={jsonBytes} bytes, html={htmlBytes} bytes."");

        // Mission Assurance: la acci�n Generar reporte produce exclusivamente dos archivos operativos:
        // HTML para lectura humana y JSON para evidencia estructurada. No se crea ZIP ni archivos auxiliares.
        return new ReportExportResult(jsonPath, htmlPath);
    }";

        var newWrite = @"await File.WriteAllTextAsync(jsonPath, json, new UTF8Encoding(false), ct);
        var html = BuildHtml(safeReport, sanitized: true);
        // P0-diff: tarjeta día-a-día. Se calcula sobre versiones sanitizadas (la anterior se
        // sanitiza igual que la actual) y se inyecta antes del cierre del body. Sin reporte
        // anterior o sin cambios, el HTML es byte-idéntico al de antes. El diff jamás tumba la exportación.
        if (previousReport is not null)
        {
            try
            {
                var diff = ReportDiffer.Compute(SupportBundleSanitizer.Sanitize(previousReport), safeReport);
                if (diff is { Changes.Count: > 0 })
                    html = html.Replace(""</body>"", ReportDiffer.ToHtmlCard(diff) + ""</body>"", StringComparison.Ordinal);
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                _ = ex;
            }
        }
        await File.WriteAllTextAsync(htmlPath, html, new UTF8Encoding(false), ct);

        // P23: un reporte vac�o/corrupto nunca debe exportarse como �xito operativo.
        var jsonBytes = new FileInfo(jsonPath).Length;
        var htmlBytes = new FileInfo(htmlPath).Length;
        if (jsonBytes <= 0 || htmlBytes <= 0)
            throw new IOException($""La exportaci�n gener� archivos vac�os: json={jsonBytes} bytes, html={htmlBytes} bytes."");

        // Mission Assurance: la acci�n Generar reporte produce exclusivamente dos archivos operativos:
        // HTML para lectura humana y JSON para evidencia estructurada. No se crea ZIP ni archivos auxiliares.
        return new ReportExportResult(jsonPath, htmlPath);
    }";

        content = content.Replace(oldWrite, newWrite);

        // 3. Add anchor and diff styles to CSS
        var oldCssEnd = @"@media print{body{background:#fff;color:#111}.card,.quick-card,.impact-item,.technical-bundle{background:#fff;border-color:#ccc;box-shadow:none}h1,h2,h3,.mono{color:#111}.muted,.report-sub,.quick-label,.support-meta,.compact-time{color:#555}th{color:#111}.technical-bundle{display:block}.technical-bundle>summary{color:#111}.technical-bundle:not([open])>:not(summary){display:none!important}}</style></head><body>");";

        var newCssEnd = @"@media print{body{background:#fff;color:#111}.card,.quick-card,.impact-item,.technical-bundle{background:#fff;border-color:#ccc;box-shadow:none}h1,h2,h3,.mono{color:#111}.muted,.report-sub,.quick-label,.support-meta,.compact-time{color:#555}th{color:#111}.technical-bundle{display:block}.technical-bundle>summary{color:#111}.technical-bundle:not([open])>:not(summary){display:none!important}}
.anchor-link{position:relative}.anchor-link::after{content:'#';position:absolute;right:-18px;top:0;color:#39d0ff;opacity:0;transition:opacity .2s;font-size:12px;text-decoration:none}.anchor-link:hover::after{opacity:1}h2 .anchor-link,h3 .anchor-link{color:inherit;text-decoration:none}.anchor-target{scroll-margin-top:80px}
.diff-banner{background:#173a4a;border:1px solid #243247;border-radius:8px;padding:10px;margin:8px 0;color:#e6edf5}.diff-banner h3{margin:0 0 8px;color:#67d9ff}.diff-summary{font-size:13px;margin-bottom:8px}.diff-list{display:grid;gap:6px;max-height:300px;overflow:auto}.diff-item{background:#0d141e;border:1px solid #243247;border-radius:6px;padding:8px;font-size:12px}.diff-item.added{border-left:3px solid #67e8a5}.diff-item.removed{border-left:3px solid #ff8a3d}.diff-item.changed{border-left:3px solid #ffd166}.diff-item .cat{color:#39d0ff;font-weight:700}.diff-item .key{color:#e6edf5}.diff-item .kind{font-size:10px;text-transform:uppercase;padding:2px 6px;border-radius:3px}.diff-kind-added{background:#14532e;color:#67e8a5}.diff-kind-removed{background:#5c1a1a;color:#ff8a3d}.diff-kind-changed{background:#5c4a1a;color:#ffd166}.diff-item .summary{color:#b7c8d8;margin-top:4px}.diff-toggle{cursor:pointer;color:#67d9ff;background:none;border:none;font-size:12px;text-decoration:underline}.diff-toggle:hover{color:#39d0ff}</style></head><body>");";

        content = content.Replace(oldCssEnd, newCssEnd);

        // 4. Fix causes loop
        var oldCauses = @"foreach (var c in report.CausasRaiz.Take(8))
            {
            sb.Append($""<h3>#{c.Posicion} \u2020 {H(c.Componente)}</h3><p><span class='badge'>{H(c.Confianza.ToString())}</span><span class='badge muted'>ranking {c.Puntaje}/100</span><span class='badge'>{H(c.Capa.ToString())}</span><span class='badge'>{H(c.Producto.ToString())}</span><span class='badge'>Origen {H(c.OrigenClasificado)}</span></p>"");";

        var newCauses = @"foreach (var c in report.CausasRaiz.Take(8))
            {
                var causeAnchor = ""cau-"" + c.Posicion;
                sb.Append($""<h3 id='{causeAnchor}' class='anchor-target'><a class='anchor-link' href='#{causeAnchor}'>#{c.Posicion} \u2020 {H(c.Componente)}</a></h3><p><span class='badge'>{H(c.Confianza.ToString())}</span><span class='badge muted'>ranking {c.Puntaje}/100</span><span class='badge'>{H(c.Capa.ToString())}</span><span class='badge'>{H(c.Producto.ToString())}</span><span class='badge'>Origen {H(c.OrigenClasificado)}</span></p>"");";

        content = content.Replace(oldCauses, newCauses);

        // 5. Fix findings loop
        var oldFindings = @"foreach (var f in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200))
            sb.Append($""<tr><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td>{H(f.Componente)}</td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>"");";

        var newFindings = @"foreach (var (f, fi) in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200).Select((x, i) => (x, i + 1)))
            sb.Append($""<tr id='fnd-{fi}' class='anchor-target'><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td><a class='anchor-link' href='#fnd-{fi}'>{H(f.Componente)}</a></td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>"");";

        content = content.Replace(oldFindings, newFindings);

        File.WriteAllText(path, content, Encoding.UTF8);
        Console.WriteLine("All changes applied successfully!");
    }
}