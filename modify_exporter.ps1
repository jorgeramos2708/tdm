$r = "C:\Users\Jorge Ramos\Downloads\TDM-ORIGINAL-ZIP\TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX\src\TDM.Reporting\ReportExporter.cs"
$content = Get-Content -LiteralPath $r -Raw

# 1. Add anchor to causes - modify the foreach line to add anchor variable
$content = $content -replace 'foreach \(var c in report\.CausasRaiz\.Take\(8\)\)', 'foreach (var c in report.CausasRaiz.Take(8)) { var causeAnchor = "cause-" + c.Id.Replace(":", "-").Replace("/", "-");'

# 2. Add anchor to the h3 for causes
$content = $content -replace 'sb\.Append\(\$"<h3>#{c\.Posicion} \xe2\x80\xa0 {H\(c\.Componente\)}</h3>"\)\;', 'sb.Append($"<h3 id=\"{causeAnchor}\" class=\"anchor-target\"><a class=\"anchor-link\" href=\"#{causeAnchor}\">#{c.Posicion} \xe2\x80\xa0 {H(c.Componente)}</a></h3>");'

# 3. Add anchor to findings table rows - need to modify the foreach loop
$content = $content -replace 'foreach \(var f in report\.Hallazgos\.OrderByDescending\(x => x\.Severidad\)\.Take\(200\)\)', 'foreach (var f in report.Hallazgos.OrderByDescending(x => x.Severidad).Take(200)) { var findingAnchor = "finding-" + f.Id;'

# 4. Add anchor to findings table row
$content = $content -replace 'sb\.Append\(\$"<tr><td>{H\(f\.Severidad\.ToString\(\)\)}</td><td>{H\(EvidenceSourceForFindingReport\(f\)\)}</td><td>{H\(f\.Capa\.ToString\(\)\)}</td><td>{H\(f\.Componente\)}</td><td>{H\(f\.Resumen\)}</td><td>{H\(f\.Confianza\.ToString\(\)\)}</td></tr>"\)\;', 'sb.Append($"<tr id=\"{findingAnchor}\" class=\"anchor-target\"><td>{H(f.Severidad.ToString())}</td><td>{H(EvidenceSourceForFindingReport(f))}</td><td>{H(f.Capa.ToString())}</td><td><a class=\"anchor-link\" href=\"#{findingAnchor}\">{H(f.Componente)}</a></td><td>{H(f.Resumen)}</td><td>{H(f.Confianza.ToString())}</td></tr>"); }'

Set-Content -LiteralPath $r -Value $content -Encoding utf8