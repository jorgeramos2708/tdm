# Auditoría senior TDM FIX93 R7

## Objetivo
Cerrar los bloqueadores encontrados en la auditoría exhaustiva de R6 sobre detección, correlación, eventos Windows, logs TSplus, configuración, monitoreo y dependencias.

## Correcciones R7
- Detección TSplus trivalente: `ConfirmedPresent`, `ConfirmedAbsent`, `NotEvaluated`.
- La detección de instalación usa `FileSystemProbe` y conserva errores de acceso/E/S.
- El fallback de la GUI usa el mismo descubrimiento de TSplus; no vuelve a inferir instalación con `Directory.Exists`.
- RootCauseCorrelator ya no elimina todo el análisis cuando TSplus está `NotEvaluated`; sólo lo hace ante ausencia confirmada.
- `ServiceDependencyGraphCollector` y `WindowsServiceCollector` comparten la misma semántica de estados; Manual/Bajo demanda no se interpreta como caída.
- Las dependencias SCM con estado ilegible se marcan como `NO EVALUADO`.
- Cursor corrupto se distingue de cursor inexistente.
- Tras pérdida/corrupción de cursor Windows se realiza replay acotado; no se salta silenciosamente al último RecordId.
- Tras pérdida/corrupción de cursor TSplus se inicia recuperación desde offset seguro y se mantiene la continuidad hasta persistir nuevamente.
- `DiagnosticTimeWindow` evalúa intervalos completos (Primer/Último evento) por solapamiento con la ventana, no por el primer timestamp disponible.
- Se eliminaron comprobaciones directas `File.Exists/Directory.Exists` de los collectors TSplus revisados; las rutas diagnósticas pasan por `FileSystemProbe`.
- Nuevas ProductionTests: cursor corrupto y solapamiento de intervalo temporal.
- Readiness gate ampliado para comprobar las garantías R7.

## Validación estática
- 172 archivos C#.
- 18 AXAML.
- 19 proyectos en solución/tests considerados por el árbol actual.
- 0 `TolerateQueryErrors = true`.
- 0 texto visible antiguo de recuperación en los archivos C# auditados.
- 0 `File.Exists/Directory.Exists` en collectors TSplus revisados.
- Balance sintáctico de llaves OK en todos los archivos modificados.
- ZIP sin `bin`, `obj` ni `.git`.

## Limitaciones
El entorno de auditoría no dispone de `dotnet`/PowerShell/Windows, por lo que no se pudo ejecutar aquí la compilación ni los ProductionTests sobre Windows. R6 había compilado correctamente en el Windows del usuario; R7 requiere repetir el gate completo en ese mismo entorno.

Tampoco se declara todavía certificación dinámica de TSplus: hay que probar en Windows real detención/reinicio de `Spooler`, `TermService`, `RpcSs`, corrupción de cursor, ACL denegada, rotación de logs, Event Log clear/recreate, RDP/HTML5, Universal Printer, Virtual Printer, 2FA y Farm.

## Estado
**R7 = candidato para validación Windows. No se declara GO empresarial hasta que `VALIDAR-FIX93.cmd` complete 7/7 y la matriz dinámica confirme causalidad.**
