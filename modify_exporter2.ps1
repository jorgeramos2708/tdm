$r = "C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs"
$content = Get-Content -LiteralPath $r -Raw

# Fix the causes section - remove the extra { and fix the h3
$content = $content -replace 'foreach \(var c in report\.CausasRaiz\.Take\(8\)\) \{ var causeAnchor = "cause-" \+ c\.Id\.Replace\(":", "-"\)\.Replace\("/", "-"\); \{\s+sb\.Append\(\$"<h3>#{c\.Posicion} . {H\(c\.Componente\)}</h3>"\)\;', 'foreach (var c in report.CausasRaiz.Take(8)) { var causeAnchor = "cause-" + c.Id.Replace(":", "-").Replace("/", "-"); sb.Append($"<h3 id=\"{causeAnchor}\" class=\"anchor-target\"><a class=\"anchor-link\" href=\"#{causeAnchor}\">#{c.Posicion} \xe2\x80\xa0 {H(c.Componente)}</a></h3>");'

# Fix the findings section - add anchor to table rows
$content = $content -replace 'foreach \(var f in report\.Hallazgos\.OrderByDescending\(x => x\.Severidad\)\.Take\(200\)\)', 'foreach (var f in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200)) { var findingAnchor = "finding-" + f.Id;'

$content = $content -replace 'sb\.Append\(\$"<tr><td>{H\(f\.Severidad\.ToString\(\)\)}</td><td>{H\(EvidenceSourceForFindingReport\(f\)\)}</td><td>{H\(f\.Capa\.ToString\(\)\)}</td><td>{H\(f\.Componente\)}</td><td>{H\(f\.Resumen\)}</td><td>{H\(f\.Confianza\.ToString\(\)\)}</td></tr>"\)\;', 'sb.Append($"<tr id=\"{findingAnchor}\" class=\"anchor-target\"><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td><a class=\"anchor-link\" href=\"#{findingAnchor}\">{H(f.Componente)}</a></td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>"); }'

Set-Content -LiteralPath $r -Value $content -Encoding utf8