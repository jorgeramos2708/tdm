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
| Fase 1 | Colectores incrementales en la GUI | ✅ completada | `7a5db5d` |
| Fase 2 | Paridad export ↔ GUI | ✅ completada | `ed22b9e` |
| Fase 3 | Brechas de privacidad | ✅ completada | `ab52e62` |
| Fase 4 | Críticos C1–C3 (cobertura, continuidad Event Viewer, cursor TSplus) | ✅ completada | `ab6d42e` |
| Fase 5 | Altos H1/H2/H3/H8/H9/H11 (detección y cobertura) | ✅ completada | `d288174` |
| Fase 6 | Altos H4/H5/H6/H7/H12–H15 + tests extremo-a-extremo de coherencia HTML | ✅ completada | `940e4b7` |
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

## Fase 2 — Paridad export ↔ GUI (completada)

**Hallazgo.** El HTML/JSON exportado divergía de las pestañas de la GUI: mismos datos, distinta lógica
de formato/filtrado. 26 divergencias (D1-D26) levantadas con file:line contra el árbol de trabajo.

**Implementación.**

1. `ReportExporter.cs`: sección de causas con marcador `[PRINCIPAL]` en el candidato de
   `CausaRaizPrincipal`, aviso "Sin causa principal declarada…" y pies de truncado para candidatos
   (más de 8) y evidencia (más de 24); anclas `cau-N`/`fnd-N` intactas. Resolución guiada reordenada
   por acción+severidad con `InvestigationGuidanceBuilder.RequiresAction`, línea de conteos
   "Resoluciones | Requieren acción | Mostrando", grupos "Requiere acción (N):"/"Sin acción requerida:",
   marcadores `[CRÍTICO]/[ERROR]/[ADVERTENCIA]`, fila "Síntoma", comprobaciones y tarjetas Take(12)
   con pie de truncado; tabla resumen con columna Severidad. Patrones sin filtro `Incidentes > 1`
   (título "Patrones de falla", 11 columnas, Take(20) + pie, estado vacío en paridad con la GUI).
   Cobertura con línea de conteos (Parciales = todos los estados Parcial/No consultado) y tabla
   ordenada por críticas. Pies "Mostrando X de N … El JSON conserva la colección completa" en cuentas
   (100), sesiones (60), autenticación (80), perfiles (50), aplicaciones publicadas (100), artefactos
   (60), anomalías internas (60) e incidentes (20). JSON con `JsonStringEnumConverter`. Detalle de
   evidencia con fallback `Timestamp ?? IngestedAt`.
2. `DiagnosticNarrativeBuilder.cs`: fechas con `ToLocalTime()` (antes UTC) y pies de colección en
   incidentes (12), crash-loops (8), patrones (12), cuentas (60), sesiones (30), perfiles (30),
   inventario (12) y anomalías internas (40).
3. `SupportBundleSanitizer.cs`: `Pseudonym` idempotente — un valor con formato `{prefijo}-XXXXXXXX`
   ya pseudonimizado se devuelve tal cual (antes se re-hasheaba, y el re-sanitizado del reporte
   previo en `ReportExporter` producía una tarjeta diff espuria).
4. `DiagnosticExecutionService.cs`: lector del reporte previo con `JsonStringEnumConverter`
   (compatible con JSON legible y numérico).
5. `InvestigationGuidanceBuilder.cs`: `RequiresAction` público, compartido por export y GUI.
6. `DiagnosticWorkspaceViewModel.cs`: `BuildSummary` cae a `Inicio − Lookback` con ventana vacía
   (sin `01/01/0001`); `BuildCoverage` con conteos y "Bloqueos duros" = críticas bloqueadas reales;
   `BuildPatterns` con Producto, singletons y mismo estado vacío; delegación a `RequiresAction`
   compartido; estado de exportación "paquete sanitizado; revise antes de compartir";
   `BuildSummary/BuildCoverage/BuildPatterns/ApplyReport/ExportReportAsync` públicos para paridad.
7. Tests: 8 nuevos en ProductionTests (`ExportRootCauseMarkersAndFooters`,
   `ExportGuidedResolutionOrderAndDetails`, `ExportPatternsShowSingletonsAndFullColumns`,
   `ExportCoverageCountsAndCriticalFirst`, `ExportJsonUsesStringEnumsAndRoundTrips`,
   `SanitizerIdempotentAvoidsSpuriousDiff`, `NarrativeUsesLocalTimeForWindows`,
   `EvidenceDetailsFallBackToIngestedAt`) → 68/68; 4 nuevos en ParityTests
   (`Gui_CoverageCountsMatchExport`, `Gui_SummaryWindowWithoutYearZero`, `Gui_PatternsMatchExport`,
   `Gui_ExportStatusDeclaresSanitizedPackage`) → 37/37; gates VERIF Y 7/7 y publish portable
   (138 771 655 bytes).

**Residuales documentados (aceptados en esta fase).**

- D13: la GUI no tiene pestaña de hallazgos (el export es más rico: Take(200) + 2 pies).
- D14/D15/D20/D21/D22: textos de estado vacío contextualmente distintos en secciones concretas del
  export vs GUI (sólo se igualaron patrones/impactos principales; el resto es vocabulario propio).
- Las fechas de la GUI siguen sin año (`dd/MM`), el export con año (`dd/MM/yyyy`).
- Extractos narrativos de apoyo (hallazgos relacionados 16, causas comunes 5) y extractos visuales
  de tarjetas rápidas: sólo en export por diseño.
- El modelo de precisión conserva `FuentesBloqueadas` (agregado histórico); "Bloqueos duros" de la
  GUI y la línea de cobertura del export ahora calculan el conteo propio de críticas bloqueadas.
- Marcador `[CRÍTICA]` (GUI) vs columna "Crítica" (export): distinta presentación, mismo dato.
- `LocalStateStore` persistía el reporte crudo (sólo local, nunca en el paquete sanitizado);
  cerrado en Fase 3 (`latest-report.json` ahora se guarda sanitizado).
- Ficheros `.bak`/`fix_exporter.cs` sueltos en el repo: no compilados, fuera de alcance.

## Fase 3 — Brechas de privacidad (commit `ab52e62`)

Campos que la GUI enmascara (`[IP]`/`[IDENTIDAD]`, `ObservabilityStore.cs:532-540`) pero que el export o
la persistencia guardaban en claro. Levantamiento con file:line y correcciones:

1. **`CausaRaizPrincipal` sin sanitizar en el export.** `SupportBundleSanitizer.Sanitize`
   (`SupportBundleSanitizer.cs:100-111`) reconstruía `CausasRaiz` pero no `CausaRaizPrincipal`
   (`DiagnosticModels.cs:233`, asignada en `DiagnosticWorkflow.cs:49`): el JSON exportaba la causa en
   claro y el HTML/narrativo la renderizaban crudos desde `safeReport` (`ReportExporter.cs:157,294,935`;
   `DiagnosticNarrativeBuilder.cs:43,396,475`), mientras la misma causa dentro de `CausasRaiz` iba
   pseudonimizada. Fix: `CausaRaizPrincipal` → `SanitizeCause`.
2. **`Incidentes` sin sanitizar** (`DiagnosticModels.cs:245`). La evidencia "Identidad del grupo"
   (`IncidentClusterAnalyzer.cs:128`; `IdentityKey` `:182-206` → `USUARIO|HOST|SERVICIO`) salía en claro
   en el JSON export. Fix: helper `SanitizeCluster` — `Identidad del grupo` → `Pseudonym("USR", …)`,
   `Dominio` (valor funcional `AD_AUTENTICACION`…, no un dominio AD) → `SanitizeText`, resto →
   `SanitizeEvidence`.
3. **`PrecisionDiagnostica`, `Tensiones` y `MotivoAmpliacion` sin sanitizar**
   (`DiagnosticModels.cs:246,258,239`) → ahora `SanitizeText`/`SanitizeEvidence`.
4. **`NormalizeKey` no normalizaba a minúsculas** (`SupportBundleSanitizer.cs:264`): las claves exactas
   `Usuario`/`Dominio`/`Cuenta` con inicial mayúscula (como las escriben los collectors) no coincidían
   con las constantes en minúscula de `IsIdentityKey`/`IsDomainKey` y valores en claro (p. ej. `alice`)
   pasaban al paquete pese a la sanitización. Fix: `.ToLowerInvariant()`.
5. **`latest-report.json` en claro.** `LocalStateStore.SaveLatestReportAsync`
   (`LocalStateStore.cs:348-358`), escrito desde `DiagnosticExecutionService.cs:227`, persistía el
   informe completo (usuarios, IPs, correos, rutas) mientras los dashboards enmascaran esos campos
   (`ObservabilityStore.cs:357-387,532-540`). Fix: guardar `SupportBundleSanitizer.Sanitize(report)` en
   el call site (la GUI ya referencia TDM.Reporting; sin nuevos project references). El diff día-a-día
   no cambia: `ReportExporter.cs:50` ya sanitiza el reporte previo (idempotente desde Fase 2).
6. **Superficies verificadas limpias** (sin cambios): muestras `observability-window.jsonl`
   (`ObservabilityStore.cs:357-387` enmascara en origen), `incident-ledger.jsonl` (resúmenes
   enmascarados de origen), `desktop-journal.jsonl`/`email-journal.jsonl` (señales desde el ledger
   enmascarado), Sistema/Hallazgos/Eventos/CausasRaiz/Patrones/Guided/Impacto/Plan/Cobertura del
   export. `RendimientoDiagnostico`: sólo nombres de collectors TDM (sin PII), sin cambios.
7. **Tests**: `SanitizeCoversPreviouslyRawSections`, `ExportJsonMasksPrimaryCauseAndClusterIdentity`
   (ProductionTests → 70/70); `Export_LatestReportStoredSanitized` (ParityTests → 38/38, raíz de datos
   hermética vía `TDM_DATA_DIR`); VERIFY 7/7 y publish portable (138 771 655 bytes).

**Residuales documentados (aceptados en esta fase).**

- Logs GUI (`LogService.cs:132`, `<raíz>/logs/tdm-gui-*.log`): mensajes operativos; las excepciones
  pueden incluir rutas locales. Fuera de alcance: no son campos que la GUI enmascara.
- El journal SMTP guarda destinatarios (configuración del operador) y títulos/resúmenes provenientes
  del ledger ya enmascarado; sin identidades de terceros.
- `Tensiones`/`PrecisionDiagnostica` son texto de auto-chequeo de TDM (sin PII por construcción);
  se sanitizan por consistencia y para no depender de esa garantía futura.

## Fase 4 — Críticos C1–C3 (commit `ab6d42e`)

Los tres hallazgos críticos de la auditoría, con sus cadenas completas:

1. **C1 — `"No disponible"` clasificado como `"Disponible"`.** `DiagnosticCoverageAnalyzer.cs:159`
   evaluaba `Contains("Disponible")` antes que `Contains("No disponible")`, y "No disponible" contiene
   "Disponible": el Security Log no leído (`UserSessionProfileCollector.cs:303,453-459`) se registraba
   "Disponible" (peso crítico ×2 completo, sin limitación `Cobertura de autenticación/NLA/Kerberos
   limitada`) y `CriticalHardBlockedCount`/el resumen de cobertura lo trataban como sano. Fix: orden
   `IsBlocked → No disponible → Disponible → Parcial` (permisos/no legible → "Bloqueada").
2. **C2 — evidencia perdida tras reinicio/parada del servicio (cadena).**
   - `WindowsCursorState` (`IncrementalWindowsEventCollector.cs:25-28`) no persistía `_lastSuccessUtc`
     (`:23`, memoria volátil): tras reinicio el mark era null.
   - Rama GAP (`:168`): condición sobre `_lastSuccessUtc.HasValue` → nunca se declaraba el hueco post-reinicio.
   - `TdmWorker.cs:180,418`: ciclos normal/emergencia usaban fijo `NormalInterval` (60 s) y
     `EmergencyPolicy.Lookback` (2 min); ninguna ventana cubría el arranque.
   - Persistencia (antes `:279`→`:294`): el estado se guardaba antes de calcular `lost`; con el
     nuevo campo había que decidir el `LastSuccessUtc` a guardar sin que una muestra parcial
     firmara continuidad (avance condicionado a `lost == 0 && persistOk`).
   - Mensaje GAP (`:178`) decía sólo "El cursor se perdió", inaplicable a reinicio.
   Fix (cinco piezas): `LastSuccessUtc` persistido con fallback a `SavedAt` (estados legados);
   `Prime()` restaura la marca y resetea `_gapDeclared`/`_firstCollectStarted`; método público
   `RecoveryLookback(now)` (≤1 min → null; 1–15 min → hueco; >15 min o cursor corrupto → 15 min;
   ya ejecutada la primera colección → null, desarme por proceso vivo); `TdmWorker` lo aplica con
   `recoveryLookback ?? NormalInterval` y `recoveryLookback ?? EmergencyPolicy.Lookback`; la
   persistencia se reordenó (`advancedLastSuccess` = `lost == 0 ? Now : _lastSuccessUtc` calculado
   antes de guardar y guardado en el estado; avance real sólo si `lost == 0 && persistOk`), el
   hallazgo GAP se declara una sola vez por hueco (`_gapDeclared`, rearmed por muestra exitosa) y el
   mensaje cubre "reinicio del servicio o discontinuidad prolongada".
3. **C3 — cursor TSplus: replay completo + hash de archivo entero.** `ComputeFileHash`
   (`IncrementalTsplusLogCollector.cs`, antes `:624`) leía el archivo entero en `Prime()` (antes
   `:67`) y en cada `PersistCursorState()` (antes `:333`); como el hash cubría el archivo completo,
   cualquier append posterior al último guardado (típico en `hb.log`) hacía fallar la validación y el
   offset se reiniciaba a 0 → replay total del log en cada arranque, más I/O completo por muestra en
   archivos grandes. Fix: hash de prefijo acotado a 1 MiB (`MaxCursorHashBytes`) con lectura
   incremental (`TransformBlock`), y `Prime()` exige además `Offset >= 0 && Offset <= info.Length`
   (conserva `CreationUtcTicks`); append normal conserva cursor, rotación/truncamiento sigue forzando
   replay. Estados legados con hash de archivo completo → un único replay al subir de versión.
4. **Tests**: `SecurityLogMissingStatusIsNotAvailable` (C1: cuatro estados + limitación + penalización
   de puntaje), `WindowsEventRecoveryLookbackRestoresPersistedGap` (C2: fresco→null, 30 s→null,
   5 min→5 min, 2 h→15 min, legado sin `lastSuccessUtc`→cae a `savedAt`), 
   `WindowsEventRecoveryLookbackDisarmsAfterFirstCollect` (C2: desarme tras primera colección
   cancelada), `TsplusCursorKeepsOffsetAfterAppend` (C3: cursor de prefijo + hash real conservado,
   sólo la línea nueva se emite), `WindowsEventGapRecoveryIsWiredInWorker` (C2: cableado en
   `TdmWorker` y campos en el collector). Gates: build 0/0, ProductionTests 75/75, ParityTests
   38/38, VERIFY 7/7, publish portable (138 779 847 bytes), lock files restaurados.

## Fase 5 — Altos de detección/cobertura (commit `d288174`)

Seis hallazgos altos de la auditoría:

1. **H3 — `"Canal no disponible"` no contaba como parcial y `WINDOWS_EVENT_COVERAGE` nadie lo
   consumía.** `WindowsEventCollector.cs:134` añadía el valor ante `EventLogNotFoundException`, pero
   el chequeo de `partial` (`:157-160`) sólo comprobaba `Parcial`/`Sin permisos`/`No legible`, así que
   la cobertura base emitía "La lectura base … se completó" con un canal caído; y aunque el evento
   `WINDOWS_EVENT_COVERAGE` (`:167`) se emitía, sólo se renderizaba `WINDOWS_FORENSIC_COVERAGE`
   (`ReportExporter.cs:806`). Fix: helper público `IsPartialCoverage` (añade el prefijo
   "Canal no disponible"), call site `IsPartialCoverage(coverage.Skip(1))` y tabla "Cobertura base de
   eventos Windows" en la tarjeta "Diagnóstico forense".
2. **H1 — panel de causalidad siempre vacío.** `CausalityDashboardViewModel.cs:21` y
   `PreventiveDashboardViewModel.cs:56` filtraban `SampleKind == "diagnostic"`, que ningún productor
   escribe (GUI: `diagnostic-avalonia` en `DiagnosticExecutionService.cs:161,291`; servicio:
   `service-monitor` en `TdmWorker.cs:314,440`; monitor: `avalonia-monitor`/`monitor`/
   `monitor-summary`), y los fixtures Parity escribían `"diagnostic"` enmascarando el defecto. Fix:
   predicado compartido `ObservabilitySample.IsDiagnosticSample` (acepta `diagnostic` legado,
   `diagnostic-avalonia`, `service-monitor`; excluye kinds de muestreo) usado por ambos viewmodels.
3. **H2 — anomalías CPU/memoria muertas en la GUI.** `IntegratedMonitoringService.cs:238-239` leía
   `"CpuPercent"`/`"MemoryFreePercent"` mientras los collectors emiten
   `ResourceMetricKeys.CpuPercent`/`MemoryFreePercent` (`Metric.Cpu.Percent`/`Metric.Memory.FreePercent`
   en `ResourceMetricKeys.cs:10-11`). Fix: lectores públicos `ObservabilityStore.ParseCpu/ParseMemory`
   (clave estable primero, texto legado como respaldo, sin parseo con cultura del proceso).
4. **H11 — permiso denegado comunicado como ausencia TSplus.** Con `TsplusEstadoDeteccion ==
   NotEvaluated` (`TsplusInstallDiscovery.cs:30,75`, propagado por `SystemSnapshotReader.cs:24`), la
   narrativa (`DiagnosticNarrativeBuilder.cs:90-92`), el export (`ReportExporter.cs:251,924`) y la GUI
   (`DiagnosticWorkspaceViewModel.cs:592`) afirmaban "no está detectado" sin comunicar la limitación.
   Fix: `SystemSnapshot.EstadoDeteccionTexto()` (Detectado/No evaluado/No detectado) y
   `DeteccionInconclusa()`; los cuatro textos distinguen el estado inconcluso. La correlación ya sólo
   salía con `ConfirmedAbsent` (`RootCauseCorrelator.cs:27`), por lo que no se tocó.
5. **H8 — cobertura de logs TSplus evaluada sin TSplus.** `DiagnosticCoverageAnalyzer.cs:22` llamaba
   `AddTsplusLogs` fuera del `if (report.Sistema.TsplusDetectado)` (`:24`): un host sin TSplus recibía
   la fuente crítica "Logs TSplus Remote Access = No disponible" y penalización falsa del score
   (`:192-194`). Fix: sin detección → "No aplica" (excluida del score); con detección inconclusa →
   "No consultado" + limitación; con TSplus detectado sin cobertura → "No disponible" (sin cambios).
6. **H9 — denominador observado, no esperado.** `IncrementalTsplusLogCollector.cs:275` emitía
   "Fuentes candidatas" (sólo ficheros existentes, `EnumerateCandidates` filtra `x.Existe`) y
   `DiagnosticCoverageAnalyzer.cs:180-182` lo usaba como total: si `hb.log`/`APSC.log` dejaban de
   existir desaparecían del censo y todo seguía "Disponible". Fix: `TsplusLogDiscovery` marca
   `hb.log`/`APSC.log` como `optional: false` (`FuenteOpcional`, campo que no se usaba), el evento
   incremental emite "Fuentes esperadas"/"Fuentes esperadas disponibles" y el analizador degrada a
   "Parcial" con "fuentes esperadas ausentes=N" cuando N > 0 (eventos legados sin las claves: sin
   cambios).
7. **Tests**: `WindowsEventBaseCoverageCountsMissingChannelAsPartial`,
   `ExportRendersBaseWindowsEventCoverage`, `DiagnosticSampleKindUnifiesProducers`,
   `ResourceMetricReadersUseStableKeys`, `NotEvaluatedTsplusDetectionIsCommunicated`,
   `TsplusLogCoverageNotEvaluatedWithoutDetection`, `IncrementalCoverageCountsMissingExpectedSources`
   (ProductionTests, 82/82), `Causality_UsesRealDiagnosticKinds` (ParityTests, 39/39). Gates: build
   0/0, VERIFY 7/7, publish portable (138 796 231 bytes), lock files restaurados.

## Fase 6 — Altos H4/H5/H6/H7/H12–H15 (commit `940e4b7`)

Ocho hallazgos altos de la auditoría:

1. **H4 — el modo servicio no correlacionaba con las transiciones recientes.** `TdmWorker` no
   llamaba a `StateReportIntegrator.AddRecentMonitorTransitionsAsync`, que la GUI sí invoca en
   `DiagnosticExecutionService.cs:119-121` antes de correlacionar: los candidatos longitudinales de
   mayor puntaje (94/90), que emparejan una transición con una falla posterior, jamás se generaban
   en el servicio. Fix: el ciclo añade las transiciones de `PeriodoAnalizadoInicio − 15 min`
   (margen de emparejamiento del correlacionador) hasta `PeriodoAnalizadoFin` con `_root`, justo
   antes de `DiagnosticWorkflow.Analyze`.
   Test: `ServiceRecentTransitionsWiredBeforeCorrelation`.
2. **H15 — `TDM_STATE_TRANSITION` sin deduplicar.** `RecordAndEnrichAsync` emitía las transiciones
   del `preRecordedResult` aunque el informe ya las hubiera enriquecido (el canal monitor sí
   deduplicaba). Fix: `events.Any(e => SamePhysicalTransition(e, transition))` → `continue`.
   Test: `RecordAndEnrichDeduplicatesPreRecordedTransitions`.
3. **H5 — una observación descartada borraba la última buena de `latest.json`.**
   `StateSnapshotBuilder.cs:96-102` descarta estados longitudinales cuya cobertura no empieza por
   "Disponible"/"Completa" y `RecordAsync` reescribía `latest.json` sólo con la captura nueva; al
   volver el acceso, `CompareTransitions` no encontraba el valor previo (`:205` `continue`) y el
   cambio real quedaba permanentemente indetectado. Fix: `latest.json` se escribe con
   `CarryForwardMissing(previous, snapshot)` (sólo si coincide `SchemaVersion`); la historia JSONL
   y `RecordResult.Snapshot` conservan la captura cruda.
   Test: `CarryForwardKeepsDroppedObservationLinked`.
4. **H6 — un fichero ilegible contaba como eliminado.** `TryReadFile` no distinguía ausencia de
   fallo de lectura: un permiso denegado o un `AppControl.ini` mayor que `MaxHashBytes` entraba en
   `removed` (falso `TSPLUS-CONFIG-DRIFT`) y la baseline se reescribía sin él. Fix:
   `TryReadFile(..., out present)` con `FileSystemProbe` ("No presente" / "No evaluado · …" /
   "Omitido por tamaño" / "No legible: …"); los ilegibles se excluyen de `removed`, se conservan en
   `baselineFinal` (hashes e INI) y se filtran de `baselineIni` antes de `DiffIni`, y la evidencia
   por `ShortName` no se duplica cuando dos rutas comparten nombre.
   Test: `ConfigDriftUnreadableFileKeepsBaseline`.
5. **H7 — artefactos web fuera del seguimiento de deriva.** `web.config`, `balance.bin` y
   `settings.bin` no estaban en las candidatas ni `web.config` en el catálogo, y los ficheros ya
   existentes al primer baseline aparecían como añadidos. Fix: 5 rutas nuevas en candidatas
   (`web.config` en `Clients\webserver|www|webportal`), entrada en
   `TsplusConfigurationArtifactCatalog`, y clasificación "Incorporados al seguimiento" cuando
   `TryGetCreationUtc(path) <= baseline.SavedAt` en lugar de `added`.
   Test: `ConfigDriftTracksWebArtifactsAndSeedsExisting`.
6. **H12 — `Tensiones` invisible en HTML y GUI.** Fix: tarjeta "Tensiones de coherencia" en el
   export (tras la tarjeta de impacto funcional) y sección "Tensiones de coherencia" en
   `BuildSummary` de la GUI.
   Tests: `ExportRendersTensionesSection`, `Gui_SummaryRendersTensiones`.
7. **H13 — tarjetas contradictorias con los mismos datos.** (a) `quickImpactState` declara
   "NO EVALUADO" cuando `SinImpactoObservado` llega con cobertura crítica incompleta;
   (b) la narrativa cuenta todos los hallazgos `TSPLUS-*` (antes 7 prefijos fijos que excluían
   anomalías reales); (c) la fila "Cobertura crítica" separa los bloqueos duros de fuentes
   críticas (desde `CoberturaDiagnostica.Fuentes`, con respaldo a `FuentesBloqueadas`) de
   "N sin cobertura completa", y la evidencia de precisión se etiqueta "Fuentes críticas sin
   cobertura completa".
   Tests: `ExportExecutiveCardsAndCountsAreCoherent`,
   `NarrativeCountsTsplusFindingsAsInternalAnomalies`.
8. **H14 — un umbral inválido revertía toda la configuración en silencio.** `LoadAsync` devolvía
   `SupportMonitoringSettings.Default` enteros ante cualquier valor fuera de rango, sin persistir
   y sin lanzar (el `catch` de `TdmWorker` jamás se activaba). Fix:
   `SupportThresholdsValidator.Sanitize` repara cada grupo de umbrales por separado hacia sus
   defaults sin descartar el resto, y `LoadAsync` devuelve lo saneado y lo re-guarda en disco
   (best-effort, con el stream ya cerrado).
   Test: `SettingsLoadRepairsInvalidThresholdsPerGroup`.
9. **Tests**: los 9 de ProductionTests anteriores (91/91) y `Gui_SummaryRendersTensiones`
   (ParityTests, 40/40). Gates: build 0/0, VERIFY 7/7, publish portable (138 820 807 bytes),
   lock files restaurados.

### Anexo — tabla completa de hallazgos altos H1–H15 (persistida)

| # | Hallazgo | file:line | Estado |
|---|---|---|---|
| H1 | Panel de causalidad **siempre vacío**: filtra `SampleKind=="diagnostic"` pero ningún productor lo emite (escribe `avalonia-monitor`/`service-monitor`/`diagnostic-avalonia`/`monitor`/`monitor-summary`) | `CausalityDashboardViewModel.cs:21`, `ObservabilityStore.cs:247,678` | ✅ Fase 5 |
| H2 | Anomalías CPU/memoria muertas en la GUI: lee claves `"CpuPercent"`/`"MemoryFreePercent"`, los collectors emiten `"Metric.Cpu.Percent"`/`"Metric.Memory.FreePercent"` | `IntegratedMonitoringService.cs:238-239` vs `ResourceMetricKeys.cs:10-11` | ✅ Fase 5 |
| H3 | `"Canal no disponible"` no cuenta como parcial ⇒ la cobertura base de Event Log emite *"La lectura base … se completó"*; además `WINDOWS_EVENT_COVERAGE` se emite y **nadie lo consume** (solo se renderiza `WINDOWS_FORENSIC_COVERAGE`) | `WindowsEventCollector.cs:132-170,167`, `ReportExporter.cs:806` | ✅ Fase 5 |
| H4 | En modo servicio, `RecordAsync` de canales forensic/integrity **se descarta el resultado** ⇒ los candidatos longitudinales de mayor puntaje (94/90) jamás se generan (solo la GUI los recupera) | `TdmWorker.cs:656` vs `DiagnosticExecutionService.cs:119-121`, `Longitudinal.cs:10` | ✅ Fase 6 |
| H5 | Observación con cobertura ≠"Disponible" no se persiste ⇒ un cambio real ocurrido en un ciclo con acceso denegado queda **permanentemente indetectable** | `StateSnapshotBuilder.cs:99-102`, `LocalStateStore.cs:195` | ✅ Fase 6 |
| H6 | Deriva de config: archivo presente-pero-ilegible cuenta como "eliminado" ⇒ falso `TSPLUS-CONFIG-DRIFT` y la baseline se reescribe sin él | `TsplusConfigurationDriftCollector.cs:60-64,86-87,156` | ✅ Fase 6 |
| H7 | `web.config` (y `balance.bin`/`settings.bin`) no están en el baseline SHA-256 ni en el catálogo `known` ⇒ ediciones de Web no generan deriva ni transición | `TsplusConfigurationDriftCollector.cs:44-50`, `TsplusConfigurationArtifactCatalog.cs:23-32` | ✅ Fase 6 |
| H8 | Cobertura de logs TSplus se evalúa **aunque TSplus no esté detectado** (`AddTsplusLogs` fuera del `if (TsplusDetectado)`) ⇒ fuente crítica "No disponible" y penalización falsa del score en hosts sin TSplus | `DiagnosticCoverageAnalyzer.cs:22,192-194`, `TsplusLogDiscovery.cs:57-68` | ✅ Fase 5 |
| H9 | Cobertura incremental usa como denominador los ficheros **observados**, no los esperados: si `hb.log`/`APSC.log` dejan de emitirse, todo sigue "Disponible" | `DiagnosticCoverageAnalyzer.cs:180-182`, `IncrementalTsplusLogCollector.cs:276` | ✅ Fase 5 |
| H10 | Versión TSplus desconocida ⇒ `Soportado=false` ⇒ ausencia de `settings.js` deja de reportarse (`TSPLUS-WEB-SETTINGSJS-MISSING` silenciado) | `TsplusReleaseCatalog.cs:16-30`, `TsplusInternalConfigurationCollector.cs:529` | ⏳ sin fase asignada |
| H11 | `NotEvaluated` (permiso denegado al detectar) se comporta como `ConfirmedAbsent`: correlación sale (`RootCauseCorrelator.cs:27`) y el informe afirma "no está detectado" sin comunicar la limitación real | `TsplusInstallDiscovery.cs:30,75`, `DiagnosticModels.cs:181,195` | ✅ Fase 5 (texto del informe; la correlación ya sólo salía con `ConfirmedAbsent`) |
| H12 | Consistencia: `Tensiones` (JSON/sanitizado) **no se renderiza en HTML ni GUI**, pese a que `ReportConsistencyAnalyzer` detecta "causa sin causa"/"impacto sin causa" — nadie lo ve | `DiagnosticWorkflow.cs:58`, `ReportConsistencyAnalyzer.cs:28-30` | ✅ Fase 6 |
| H13 | Tarjetas contradictorias con los mismos datos: `ExecutiveState`="NO EVALUADO" junto a `CompactImpactState`="SALUDABLE"; narrativa "0 anomalías" junto a tabla poblada; tres números distintos de "fuentes bloqueadas" en un mismo HTML | `ReportExporter.cs:1042-1078,167-171,288,409-411`, `DiagnosticNarrativeBuilder.cs:320-328` | ✅ Fase 6 |
| H14 | Umbral fuera de rango ⇒ **toda** la config del administrador revierte a defaults en silencio (`LoadAsync` nunca lanza, así que el `catch` de TdmWorker jamás dispara) | `SupportMonitoringSettings.cs:162-168` | ✅ Fase 6 |
| H15 | Transiciones duplicadas: `TDM_MONITOR_STATE_TRANSITION` (con dedup) + `TDM_STATE_TRANSITION` **sin dedup** por el mismo `preRecordedResult` | `TdmWorker.cs:236`, `StateReportIntegrator.cs:73-91,166` | ✅ Fase 6 |

Plan de fases: Fase 4 = C1–C3 (✅ `ab6d42e`); Fase 5 = H3/H1/H2/H11/H8/H9 (✅ `d288174`);
Fase 6 = H4, H5, H6/H7, H12–H15 + tests extremo-a-extremo de coherencia HTML (✅ `940e4b7`).

## Descartado — Simulación de remediación sobre grafo inventado

La simulación de remediación se ejecuta sobre un grafo de dependencias inventado en lugar de uno real;
descartada a propósito. Sólo se retomaría con un grafo de dependencias real (SCM/TSplus) como fuente.
