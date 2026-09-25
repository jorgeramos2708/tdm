# TDM FIX93 — P0 R9 (cierre de loops abiertos)

## Objetivo
Cerrar los tres P0 pendientes del análisis de efectividad del pipeline
**monitoreo → causa raíz → reporte**: (1) el historial verificado por el técnico
alimenta el ranking, (2) el servicio no se queda ciego bajo carga ni muere en
silencio, (3) el diff día-a-día y la trazabilidad clicable llegan al HTML.

## P0-1. Loop feedback → ranking (con guardarraíles)
- Nuevo `src/TDM.Correlation/VerifiedHistoryCalibrator.cs` (función pura, sin E/S):
  ajuste = redondeo((tasa − 0.5) × 2 × 15 × min(veredictos/5, 1)).
- Reglas: sin historial la lista vuelve intacta; tope ±15 y clamp 0..100; una sola
  anécdota mueve ±3 como máximo; **veto de inversión** (un descarte nunca resta a
  un candidato con "Evidencia primaria independiente = Sí"); **veto de
  adelantamiento** (el feedback no supera a quien venía arriba con evidencia dura;
  el empate conserva el orden base por ordenamiento estable); todo ajuste efectivo
  (y todo veto total) queda como `EvidenceItem("Historial verificado por técnico")`.
- `DiagnosticWorkflow.Analyze` acepta `verifiedHitRates = null` (opcional: sin
  historial el comportamiento previo no cambia; ningún llamador existente se tocó
  en firma obligatoria). El ajuste ocurre antes de la selección de
  `CausaRaizPrincipal`, así que el gap de 5 puntos y el veto P15/R1 operan sobre
  puntajes ya calibrados por historial.
- `TdmWorker` (servicio) y `DiagnosticExecutionService` (GUI) cargan el historial
  de 90 días en best-effort (`IOException`/`UnauthorizedAccessException` → null +
  ranking solo con evidencia actual). Sin `ProjectReference` nuevos: el servicio
  usa la misma ventana de 90 días como literal documentado.
- 7 tests pin en `TDM.ProductionTests`: boost, demote, veto de inversión,
  veto de adelantamiento, muestra única (±3), clamp 0..100, ausencia intacta.

## P0-2. Emergencia + watchdog
- `TdmWorker`: contador `_consecutiveDefers` (se resetea con cada muestra normal).
  Cada 3er ciclo aplazado consecutivo ejecuta `RunEmergencySampleAsync`: solo los
  readers incrementales, timeout 5 s, tope 300 eventos, sin fase pesada ni
  longitudinal, pero con el mismo pipeline de persistencia/ledger/dispatch
  (los paros y crashes siguen generando incidentes y alertas). Usa el último
  snapshot conocido; sin snapshot aún, se omite. Nunca tumba el ciclo
  (`catch` con `when (!stoppingToken.IsCancellationRequested)` → sigue PROTECTED).
  El heartbeat de fin de ciclo ya cubría la rama defer, así que el watchdog no
  tiene falsos positivos por aplazamiento.
- Nuevos `REGISTER-TDM-WATCHDOG.cmd` + `Register-TdmWatchdog.ps1` (ASCII, sintaxis
  validada con el parser): tarea programada cada 5 min como SYSTEM que ejecuta
  `-Check`: si el servicio no está Running lo arranca; si está Running pero el
  heartbeat falta o supera 180 s (umbral interno Q8 = 150 s + margen), lo reinicia.
  Opt-out por archivo `watchdog.pause` para mantenimientos; log rotativo
  `watchdog.log` junto al heartbeat; `-Unregister` para retirar.

## P0-3. Diff + trazabilidad en el HTML
- `ReportDiffer.ToHtmlCard`: tarjeta "Cambios desde el reporte anterior"
  (conteos + hasta 40 cambios, contenido escapado, marcado ASCII).
- `ReportExporter.ExportAsync(..., previousReport = null)` (opcional: el único
  llamador existente compila igual): sanitiza el anterior con la misma regla,
  calcula el diff y lo inyecta antes de `</body>`. Sin anterior o sin cambios,
  el HTML es byte-idéntico al de antes. El diff jamás tumba la exportación
  (`ArgumentException`/`InvalidOperationException` → se omite la tarjeta).
- Anclas clicables: causas `cau-{Posicion}`, filas de hallazgos `fnd-{N}`
  (mismo orden/Take que la tabla), y bloque "Hallazgos relacionados en este
  reporte" por coincidencia de componente (tope 5, mínimo 4 caracteres contra
  ruido de nombres genéricos). Estilos en un segundo bloque `<style>` tras el h1.
- 1 test pin: exporta con/sin anterior y asserts de tarjeta, altas/bajas,
  `id='fnd-1'`, `id='cau-2'` y bloque relacionado.

## Nota de reconstrucción (honestidad del cambio)
Durante esta ronda, una edición con PowerShell corrompió el encoding de
`ReportExporter.cs` y se restauró desde el ZIP del 10/09, que resultó ser
anterior a la copia de trabajo (1085 vs 1099 líneas). Se reconstruyeron los
bloques S9 (gate de JSON válido + gate de HTML completo) con el comportamiento
documentado; P23 estaba intacto. Ningún test pinea el texto exacto de esos
bloques, solo su comportamiento, que quedó verificado por el gate.

## Validación
- `dotnet build TDM.sln -c Release --no-restore -warnaserror`: 0 warnings, 0 errores.
- `TDM.ProductionTests.exe`: **37/37 PASS** (7 feedback + 1 diff/export nuevos).
- `TDM.ParityTests.exe`: **26/26 PASS**.
- `VERIFY-TDM-READINESS.cmd`: **[OK] TDM READINESS GATE PASS** (incluye restore
  locked-mode, tests, arranque GUI/Notifier y paquete limpio). Nota: el gate
  falló primero por un `packages.lock.json` huérfano en `src/TDM.Service/bin/...`
  (residuo de un publish anterior, no fuente); eliminado y PASS.
- `PUBLISH-PORTABLE-WIN-X64.cmd`: `dist\TDM-portable-win-x64\TDM.exe` (~133 MB).
