# Auditoría senior — TDM v1.0-rc18.21.0-FIX93

Lista maestra de hallazgos de la auditoría senior sobre el ZIP original `TDM-v1.0-rc18.21.0-FIX93.zip`
(SHA256 `63E56DE60F0511FA456AEBEE3BB4C752A3FA0FED34B8F09A94B7F65C90DB3413`, intacto) y las fases
de corrección aplicadas sobre el árbol de trabajo de este repositorio.

- Correcciones en inglés para `git log`; textos de UI y CHANGELOG en español.
- Gates obligatorios por fase: `dotnet build TDM.sln -c Release --no-restore -warnaserror` (0/0) →
  ProductionTests → ParityTests → `.\VERIFY-TDM-READINESS.cmd` (7/7) → `.\PUBLISH-PORTABLE-WIN-X64.cmd` →
  `git restore -- ":(glob)**/packages.lock.json"` → CHANGELOG → commit + push `origin/main`.
- Sin comentarios nuevos en el código (los preexistentes pueden mantenerse/ajustarse).

## Estado

| Fase | Alcance | Estado | Commit |
|---|---|---|---|
| Fase A | 4 hallazgos P0 | ✅ completada | `7fa346d` |
| Fase B | 6 hallazgos P1 (pipeline y reglas) | ✅ completada | `59b4a62` |
| Fase 1 | Colectores incrementales en la GUI | ✅ completada | — |
| Fase 2 | Paridad export ↔ GUI | ⬜ pendiente | — |
| Fase 3 | Brechas de privacidad | ⬜ pendiente | — |
| — | Simulación de remediación sobre grafo inventado | ❌ descartada | — |

---

## Fase A — 4 hallazgos P0 (commit `7fa346d`)

1. **Ledger de incidentes borraba identidad clasificada.** `ManagedIncident` se creaba con
   `Classification`/`Product` a `null`; el filtro de `ReadAsync` rechazaba los incidentes de identidad y
   `ReconcileAsync`/`AddNoteAsync`/`CloseAsync` los eliminaban del JSONL en la siguiente reescritura.
   Fix: campos persistidos + rewrites leen con `ReadRawAsync` (todas las filas válidas) y sólo la lectura
   pública aplica el filtro; `ReconcileAsync` devuelve sólo lo operativo.
   Test: `LedgerKeepsIdentityClassifiedIncidents`.
2. **Clústeres de identidad ignoraban evidencia en español.** `IncidentClusterAnalyzer.IdentityKey`
   normalizaba la clave consultada pero no la almacenada en la evidencia, así que `Usuario`/`Equipo`/
   `Servicio` nunca coincidían. Fix: `EvidenceKeyNormalizer` en ambos lados.
   Test: `SpanishUserEvidenceSplitsIdentityClusters`.
3. **Umbrales de disco no aplicados en Rendimiento.** `MainWindowViewModel` llamaba
   `Performance.ApplyLiveResources(...)`/`Apply(...)` sin umbrales (siempre defaults). Fix: pasa
   `Administration.CurrentThresholds`.
4. **Ranking con candidatos de Id duplicado.** `DiagnosticPrecisionAnalyzer.Calibrate` buscaba por `Id`;
   dos crashes `ROOT-PROCESS-CRASH` o variantes `ROOT-SCM-SERVICE-FAILURE-{servicio}` heredaban brecha y
   estado del primero. Fix: rank por instancia; evidencia primaria independiente acepta Id con sufijo;
   marcador `[PRINCIPAL]` sólo en la instancia real (`Posicion` + `Id`).
   Tests: `DuplicateCandidateIdsRankIndependently` y `RootCause_PrincipalMarkerOnlyOnPrimaryInstance`.

## Fase B — 6 hallazgos P1 de pipeline y reglas (commit `59b4a62`)

1. **Umbral de flapping inerte.** `TdmWorker` calculaba la estabilidad con
   `DiagnosticExecutionPolicy.ForLookback(...)` fijo, ignorando
   `DiagnosticOptions.CauseStabilityFlappingThreshold`. Fix: `options?.CauseStabilityFlappingThreshold ?? 2`.
   Test: `FlappingThresholdHonorsConfiguredOptions`.
2. **Impacto funcional por subcadena.** `FunctionalImpactAnalyzer.AddCauseDrivenImpact` hacía
   `text.Contains(...)` simple: "80" casaba con "8080", "shell" con "PowerShell", "Web" con "8080".
   Fix: `ContainsToken` (límites de palabra) sólo en los chequeos dirigidos por causa; los stems
   ("CRÍT") y los estados directos no cambian. Test: `CauseDrivenImpactUsesWordBoundaries`.
3. **Acción de disco con `15 %` fijo.** `PreventiveDashboardViewModel.BuildActions` ignoraba
   `DiskFreeWarningPercent`. Fix: `DiskActionFloor(thresholds) = Max(15, DiskFreeWarningPercent)` en
   ambos call sites (default intacto; respeta umbrales ≥ 15). Test: `Preventive_DiskActionHonorsThresholds`.
4. **Anomalías EWMA muertas.** `IntegratedMonitoringService` instanciaba `AnomalyDetectionService` y
   descartaba el resultado, con `Debug.WriteLine` en producción. Fix: cada anomalía se añade como
   `DiagnosticFinding` al informe (fluye a contadores de bitácora y alertas del portable) con
   enfriamiento de 5 min por métrica. Test: `EwmaAnomaliesSurfaceAsReportFindings`.
5. **`DiagnosticOptions.MaxEvents` ignorado por los logs de Windows.** `WindowsEventCollector` aplicaba
   el límite por canal (mismo tope en cada uno). Fix: presupuesto global decrementado por evento guardado,
   `ResolveRelevantLimit(lookback, maxEvents)` y cobertura "Parcial" al agotarse.
   Test: `WindowsEventCollectorHonorsMaxEventsOption`.
6. **Tests dependientes de la cultura.** Formatos `double`/fechas sensibles a la cultura regional
   (es-ES con "," decimal rompía aserciones). Fix: ambas suites fijan
   `CultureInfo.InvariantCulture` en hilos y por defecto.
   Tests: `TestsRunUnderPinnedInvariantCulture`, `CultureIsPinnedForDeterministicFormatting`.

---

## Fase 1 — Colectores incrementales en la GUI (completada)

**Hallazgo.** La GUI ejecuta los colectores completos desde cero en cada ciclo; no existe incrementalidad.
La infraestructura incremental ya está construida y probada en el servicio, pero cableada sólo allí.

Evidencia (exploración del árbol actual):

- `DiagnosticExecutionService.cs:75` llama `CollectorCatalog.CreateFull()` **dentro** de cada
  `RunAsync`: 40 instancias nuevas por ciclo, ninguna conserva estado entre ciclos.
- `DiagnosticWorkspaceViewModel.cs:161` — el loop "Tiempo real" re-ejecuta `RunAsync` cada 5 s;
  `:489-491` sustituye `_allEvents` completo en cada informe.
- Cero referencias a cursores/incremental en `src\TDM.Gui.Avalonia`.
- **Los dos colectores caros ya tienen versión incremental con cursor**, usada sólo por el servicio:
  - `IncrementalWindowsEventCollector` (cursor `EventRecordID` por canal, key `windows-event-cursors`)
    — `IncrementalWindowsEventCollector.cs:62,255`; sólo `TdmWorker.cs:28,182,421`.
  - `IncrementalTsplusLogCollector` (offset por fichero, key `tsplus-log-cursors`)
    — `IncrementalTsplusLogCollector.cs:54,337`; sólo `TdmWorker.cs:29,183,421`.
- Los 37 colectores restantes releen ventana/snapshot completo cada ciclo
  (Event Log: `WindowsEventCollector.cs:36-46`, `WindowsForensicEventCollector.cs:69-74`,
  `WindowsLogonHealthCollector.cs:36-38`, `UserSessionProfileCollector.cs:310,702,771,948`, …;
  ficheros: `TsplusLogCollector.cs:204-309`, `TsplusDeepInstallationCollector.cs:359,782-796`;
  WMI/SCM: `WindowsServiceCollector.cs:97`, `SystemResourceCollector.cs:56,115`).
- `WindowsPushEventCollector.cs:43-47` crea 5 `EventLogWatcher` nuevos **por ciclo** y sólo los libera
  con `ct.Register` (`:79`), acumulándose durante la sesión (sólo relevante si se aumenta la frecuencia).

**Riesgos si se cambia a ciegas** (a mitigar en la implementación):

1. `DiagnosticEngine.cs:211-221` filtra estrictamente a `[now-lookback, now]`: con sólo datos nuevos,
   los eventos del ciclo anterior desaparecerían del informe.
2. `DiagnosticWorkspaceViewModel.cs:489-491` limpia `_allEvents` cada ciclo → la UI se vaciaría sin fusión.
3. `ObservabilityStore.BuildSample` (`ObservabilityStore.cs:192-291`) calcula contadores a partir de
   `report.Eventos/Hallazgos` → caerían a 0 con datos incrementales.
4. `CollectorExecutionBoundary.InFlight` es estático por proceso (`CollectorExecutionBoundary.cs:14`):
   mantener instancias vivas exige un `Prime()` único, no por ciclo.

**Extension points naturales** (sin romper nada):
`CollectorCatalog.cs:16-62` (composición única, añadir variante incremental) ·
`DiagnosticExecutionService.cs:75` (único call site del engine en la GUI) ·
`DiagnosticContext` (`DiagnosticModels.cs:198-203`, adicional con default) ·
`CollectorCursorStore` (`TDM.Core\CollectorCursorStore.cs:9`, infraestructura ya probada) ·
fase post-ejecución `DiagnosticExecutionService.cs:84-138` (fusión con el informe previo).

**Alcance propuesto.** Cablear `IncrementalWindowsEventCollector` + `IncrementalTsplusLogCollector`
(las dos fuentes más caras) en el ciclo "Tiempo real" de la GUI, con fusión del informe previo para
que ventana, UI y contadores no pierdan datos. Dejar el resto de colectores (snapshot barato) como está.

**Implementación.**

1. `src\TDM.Core\DiagnosticEventIdentity.cs` (nuevo): identidad WER/RecordId/FALLBACK extraída de
   `DiagnosticEngine`; el engine delega (`Deduplicate` llama `Resolve`) y el merger la reutiliza,
   colapsando lectura completa e incremental del mismo registro. `RootCauseCorrelator.EventIdentity`
   sigue siendo un caso propio (fuera de alcance, preexistente).
2. `ContinuousDiagnosticMerger.cs`: nuevo `ShouldContinue(baseline, lookback, now)` (siembra al
   crecer la ventana o sin línea base); `Merge` parte ahora de `incremental` (paridad de rendimiento
   con el modo puntual); arrastre de hallazgos por familia allowlist `IsContinuousFinding`
   (`EVT-*`/`LIVE-EVT-*`/`TSLOG-*`/`LIVE-TSLOG-*`, sin `-ACCESS`/`-READ`), sustituyendo a la
   regla inversa `!IsCurrentStateFinding` que dejaba pegados `SVC-*`/`MONITOR-RDP-*` recuperados.
3. `CollectorCatalog.cs`: `CreateFull()` delega a `Build(null, null)` y `CreateContinuous(windows,
   tsplus)` sustituye sólo las dos fuentes pesadas (ArgumentNull checks; resto idéntico).
4. `DiagnosticExecutionService.cs`: campos vivos `_windowsIncremental`/`_tsplusIncremental`
   (una sola instancia por sesión), `_continuousBaseline`, `_continuousSamples`; en `RunAsync`:
   `ShouldContinue` → si no continúa: `Prime()` de ambos cursores ANTES de la siembra (posición
   de partida sin hueco, cursores persistidos compartidos con el servicio) y reset de muestras;
   tras el engine, `Merge` y asignación de `DiagnosticoContinuo`/`UltimaActualizacionContinua`/
   `IntervaloContinuoSegundos`/`MuestrasContinuas` ANTES de `DiagnosticWorkflow.Analyze`.
5. `DiagnosticCoverageAnalyzer.AddTsplusLogs`: prefiere `TSPLUS_INCREMENTAL_LOG_COVERAGE`
   (disponibles = candidatas − no evaluadas) y cae a `TSPLUS_LOG_COVERAGE`; sin ninguno mantiene
   "No disponible". Corrige también el hueco preexistente del modo servicio (sin `TSPLUS_LOG_COVERAGE`).
6. Tests: 5 nuevos en ProductionTests (`ContinuousMergerKeepsWindowStateAndAnchoredEvents`,
   `ContinuousRunReplansSeedWhenWindowGrows`, `ContinuousCatalogSwapsHeavySourcesForIncremental`,
   `TsplusCoverageAcceptsIncrementalSource`, `GuiRealtimeWiresIncrementalContinuousDiagnostics`)
   → 60/60; Parity 33/33; gates VERIF Y 7/7 y publish portable (138 751 175 bytes).

**Residuales documentados (aceptados en esta fase).**

- Los demás colectores de eventos (forense, crash, cambios, logon, integridad…) siguen releyendo
  su ventana completa en cada ciclo continuo; sólo se sustituyeron las dos fuentes caras.
- `WindowsPushEventCollector` sigue creando 5 `EventLogWatcher` por ciclo (liberados con `ct.Register`).
- Los snapshots de tipo `Snapshot` que no son `MergeCurrentState` (p. ej. `WINDOWS_FORENSIC_COVERAGE`)
  se acumulan por ciclo en la línea base hasta los límites 12 000/4 000 del merger.
- `IncrementalTsplusLogCollector.Prime` relee hashes de hasta 240 ficheros; se ejecuta sólo en los
  ciclos de siembra (primero y al ampliar ventana), no en cada ciclo continuo.
- El catálogo continuo comparte cursores con TDM.Service si el servicio está vivo (misma clave y
  misma semántica de lectura, pensada originalmente para ambos consumidores).

## Fase 2 — Paridad export ↔ GUI (pendiente)

El HTML/JSON exportado puede divergir de las pestañas de la GUI: mismos datos, distinta lógica de
formato/filtrado (buscadores, límites "… y N más", secciones, coloreado de marcadores). A mapear:
`ReportExport`/`FormattedReportView` vs cada ViewModel de pestaña. Pendiente de levantar el detalle
concreto con file:line en la fase.

## Fase 3 — Brechas de privacidad (pendiente)

Campos que la GUI enmascara (IPs, correos, rutas de perfil, cuentas) pero que el export o la
persistencia guardan en claro. Pendiente de levantar el detalle concreto con file:line en la fase.

## Descartado — Simulación de remediación sobre grafo inventado

La simulación de remediación se ejecuta sobre un grafo de dependencias inventado en lugar de uno real;
descartada a propósito. Sólo se retomaría con un grafo de dependencias real (SCM/TSplus) como fuente.
