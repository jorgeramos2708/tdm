using System;
using System.IO;
using System.Text;

class Program
{
    static void Main()
    {
        var path = @"C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs";
        var content = File.ReadAllText(path, Encoding.UTF8);

        // 1. Add anchor and diff CSS styles
        var cssInsertion = @"
        sb.Append("".anchor-link{position:relative}.anchor-link::after{content:'#';position:absolute;right:-18px;top:0;color:#39d0ff;opacity:0;transition:opacity .2s;font-size:12px;text-decoration:none}.anchor-link:hover::after{opacity:1}h2 .anchor-link,h3 .anchor-link{color:inherit;text-decoration:none}.anchor-target{scroll-margin-top:80px}"");
        sb.Append("".diff-banner{background:#173a4a;border:1px solid #243247;border-radius:8px;padding:10px;margin:8px 0;color:#e6edf5}.diff-banner h3{margin:0 0 8px;color:#67d9ff}.diff-summary{font-size:13px;margin-bottom:8px}.diff-list{display:grid;gap:6px;max-height:300px;overflow:auto}.diff-item{background:#0d141e;border:1px solid #243247;border-radius:6px;padding:8px;font-size:12px}.diff-item.added{border-left:3px solid #67e8a5}.diff-item.removed{border-left:3px solid #ff8a3d}.diff-item.changed{border-left:3px solid #ffd166}.diff-item .cat{color:#39d0ff;font-weight:700}.diff-item .key{color:#e6edf5}.diff-item .kind{font-size:10px;text-transform:uppercase;padding:2px 6px;border-radius:3px}.diff-kind-added{background:#14532e;color:#67e8a5}.diff-kind-removed{background:#5c1a1a;color:#ff8a3d}.diff-kind-changed{background:#5c4a1a;color:#ffd166}.diff-item .summary{color:#b7c8d8;margin-top:4px}.diff-toggle{cursor:pointer;color:#67d9ff;background:none;border:none;font-size:12px;text-decoration:underline}.diff-toggle:hover{color:#39d0ff}"");
";
        content = content.Replace(
            @"sb.Append(""</style></head><body>"");",
            cssInsertion + @"        sb.Append(""</style></head><body>"");");

        // 2. Add anchor to causes h3
        content = content.Replace(
            @"foreach (var c in report.CausasRaiz.Take(8))
            {
            sb.Append($""<h3>#{c.Posicion} \u2020 {H(c.Componente)}</h3>"");",
            @"foreach (var c in report.CausasRaiz.Take(8))
            {
                var causeAnchor = ""cause-"" + c.Id.Replace("":"", ""-"").Replace(""/"", ""-"");
                sb.Append($""<h3 id=\""{causeAnchor}\"" class=\""anchor-target\""><a class=\""anchor-link\"" href=\""#{causeAnchor}\"">#{c.Posicion} \u2020 {H(c.Componente)}</a></h3>"");");

        // 3. Add anchor to findings table rows
        content = content.Replace(
            @"foreach (var f in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200))
            sb.Append($""<tr><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td>{H(f.Componente)}</td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>"");",
            @"foreach (var f in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200))
            {
                var findingAnchor = ""finding-"" + f.Id;
                sb.Append($""<tr id=\""{findingAnchor}\"" class=\""anchor-target\""><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td><a class=\""anchor-link\"" href=\""#{findingAnchor}\"">{H(f.Componente)}</a></td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>""); }");

        // 4. Add diff rendering script and banner before closing body
        var diffScript = @"
        // Diff rendering
        var prevReportPath = null;
        try {
            var files = Array.from(document.querySelectorAll('a[href$="".json""]')).map(a => a.href);
            if (files.length > 1) {
                // Find previous report JSON (simplified - in real use would need server-side)
            }
        } catch {}

        // Inject diff banner if diff data available (embedded in page)
        var diffData = null;
        try {
            var scriptTag = document.getElementById('tdm-diff-data');
            if (scriptTag) diffData = JSON.parse(scriptTag.textContent);
        } catch {}

        if (diffData && diffData.changes && diffData.changes.length > 0) {
            var banner = document.createElement('div');
            banner.className = 'card diff-banner';
            banner.innerHTML = '<h3>Cambios respecto a la muestra anterior</h3>' +
                '<div class=diff-summary>' + diffData.changes.length + ' cambio(s) detectado(s): ' +
                diffData.changes.filter(c => c.kind === 'Added').length + ' nuevos, ' +
                diffData.changes.filter(c => c.kind === 'Removed').length + ' eliminados, ' +
                diffData.changes.filter(c => c.kind === 'Changed').length + ' modificados</div>' +
                '<button class=diff-toggle onclick=\"this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'grid\':\'none\';this.textContent=this.nextElementSibling.style.display===\'none\'?\'Mostrar detalles\':\'Ocultar detalles\'\">Mostrar detalles</button>' +
                '<div class=diff-list style=\"display:none\">' +
                diffData.changes.map(c => 
                    '<div class=\"diff-item ' + c.kind.toLowerCase() + '\">' +
                    '<span class=cat>' + c.category + '</span> ' +
                    '<span class=key>' + c.key + '</span> ' +
                    '<span class=\"kind diff-kind-' + c.kind.toLowerCase() + '\">' + c.kind + '</span>' +
                    (c.summary ? '<div class=summary>' + c.summary + '</div>' : '') +
                    (c.previousValue || c.currentValue ? '<div class=summary>Antes: ' + (c.previousValue || '-') + ' → Ahora: ' + (c.currentValue || '-') + '</div>' : '') +
                    '</div>'
                ).join('') + '</div>';
            document.querySelector('.support-main').after(banner);
        }

        // Add click-to-copy for anchor links
        document.querySelectorAll('.anchor-link').forEach(link => {
            link.addEventListener('click', e => {
                e.preventDefault();
                var target = document.querySelector(link.getAttribute('href'));
                if (target) target.scrollIntoView({behavior: 'smooth', block: 'center'});
                navigator.clipboard.writeText(window.location.origin + window.location.pathname + link.getAttribute('href'));
                link.title = 'Enlace copiado';
                setTimeout(() => link.title = '', 2000);
            });
        });
";
        content = content.Replace(
            @"sb.Append(""</div></details></div></details></body></html>"");",
            @"sb.Append(""<script id='tdm-diff-data' type='application/json'>"" + (diffJson ?? \"null\") + ""</script>"");");
        content = content.Replace(
            @"return sb.ToString();",
            @"sb.Append(""<script>"" + diffScript + ""</script></body></html>"");");
        content = content.Replace(
            @"return sb.ToString();",
            @"return sb.ToString();");

        // Actually we need to inject the diffJson parameter. Let me add it properly.
        // First, add the diff computation at the beginning of BuildHtml
        var diffInjection = @"
        // Compute diff with previous report if available
        string diffJson = null;
        try {
            var reportDir = Path.GetDirectoryName(htmlPath);
            if (reportDir != null && Directory.Exists(reportDir)) {
                var jsonFiles = Directory.GetFiles(reportDir, ""TDM-*.json\"")
                    .OrderByDescending(f => File.GetLastWriteTimeUtc(f))
                    .ToArray();
                if (jsonFiles.Length >= 2) {
                    var prevJson = File.ReadAllText(jsonFiles[1]);
                    var prevReport = JsonSerializer.Deserialize<DiagnosticReport>(prevJson, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                    if (prevReport != null) {
                        var diff = ReportDiffer.Compute(prevReport, report);
                        if (diff != null) diffJson = ReportDiffer.ToJson(diff);
                    }
                }
            }
        } catch { }
";
        content = content.Replace(
            @"var sb = new StringBuilder();",
            diffInjection + @"        var sb = new StringBuilder();");

        File.WriteAllText(path, content, Encoding.UTF8);
        Console.WriteLine("Done");
    }
}