# Auditoría general de efectividad — cadena completa

**Versión auditada**: TDM v1.0-rc18.21.0-FIX93, tras Fase 14 (`5c880d6`).
**Método**: 4 agentes de exploración (~50 hallazgos) sobre monitoreo → transiciones → detección → agrupación → correlación → ranking → causa raíz → impacto → dependencias → eventos → logs → configuración → consistencia → GUI; verificación manual de los hallazgos más graves (marcados ✅) y re-verificación de los hallazgos conocidos abiertos de la auditoría previa.
**Gates vigentes**: build 0/0 · ProductionTests 138/138 · ParityTests 47/47 · VERIFY 7/7 · publish 138960071.

## 1. Monitoreo real (colectores/cadencia)

| Sev | Hallazgo | Lugar |
|---|---|---|
| **Alta ✅** | Colector "push" se suscribe y drena en la misma llamada → ~0 eventos por ventana + acumula `EventLogWatcher` por ciclo sin dispose | `WindowsPushEventCollector.cs:30,44` |
| Media | `requiredNow` calculado distinto por `ServiceDependencyGraphCollector` vs `WindowsServiceCollector` → la misma fuente dice "sano" y "crítico" | C#4 |
| Media | `ServiceDependencyGraphCollector` sin try/catch por servicio + `ServiceController` sin dispose (hasta ~320 handles/ciclo) → **corregido en Fase 12** (cualquier excepción no-cancelación aísla por servicio en los 4 puntos; dispose verificado por gate) | C#5 |
| Media | Lectura fallida de dependencias persistida como baseline vacía → drift falso o perdido | C#6 |
| Media | Descubrimiento cae a catálogo fijo sin señal de cobertura (C#7); contador compartido en integridad de logs deja Security 1102 sin examinar con cobertura "Disponible" (C#8) → **corregido en Fase 14** (hallazgo `SVC-DISCOVERY-COVERAGE` con `Cobertura=No evaluado`; presupuesto `MaxFindingsPerChannel` con corte y cobertura `Parcial; límite de 8 hallazgos por canal alcanzado`) | C#7-8 |
| Media | Drift de registro saltado con `baseline.Registry` null (bases viejas, C#9); canales forenses inexistentes hunden fuente a "Parcial" permanente (C#11) → **corregido en Fase 14** (evento `TSPLUS_CONFIG_REGISTRY_BASELINE_INITIALIZED` + snapshot persistido para comparar; distinción `No existe en este SO` con bucket `no aplicables` en `DiagnosticCoverageAnalyzer`) | C#9,11 |
| Media | Muestras de emergencia no escriben journal/canal longitudinal ni transiciones → monitor congelado en ventanas de carga; ciclo longitudinal saltado a >45s con presupuesto 180s → **corregido en Fase 12** (emergencia espeja el ciclo normal; gate `HasBudgetForLongitudinal` con reserva de 23 s) | A#9-10 |
| Baja | Catálogo ligero no incluye dependencias/salud (ciclo pesado ~10min vs 5min de GUI) | `CollectorCatalog.cs:73-80` ✅ |

## 2. Transiciones de estado

| Sev | Hallazgo | Lugar |
|---|---|---|
| Media ✅ | Transiciones se fechan con `CapturedAt` de la foto, no con el momento del cambio (rompe cercanía temporal) → **corregido en Fase 14** (`StateTransition.ChangedAfter` = cota inferior, evidencia "Cambio después de" en los 3 eventos, precedencia longitudinal por `earliestPossible`) | `LocalStateStore.cs:207` |
| Media ✅ | Snapshot corrupto → `return null` silencioso, sin log ni hallazgo → **corregido en Fase 10** (contador `CorruptSnapshotReadCount`, `Trace.TraceWarning` con la ruta y `LocalStoreStatus.CorruptSnapshotReads`) | `LocalStateStore.cs:242-249` |
| Media | Tolerancia de dedup 5s vs cadencias 60/120s → misma transición doble-contada en RCA (A#3, **corregido en Fase 9** con tolerancia 10 min + guardia de inversión); lectura barre 30 días completos por ciclo (A#4); canal `diagnostic-avalonia` excluido de lecturas (A#5, **corregido en Fase 10**) | A#3-5 |
| Media | Fallo al leer transiciones recientes traga sin límite → **corregido en Fase 14** (`TDM_RECENT_TRANSITIONS_UNAVAILABLE` con `Cobertura historial reciente=No evaluado` + `Trace.TraceWarning`, eventos originales intactos) | `StateReportIntegrator.cs:254-257` |
| Baja ✅ | `TDM_LOCAL_HISTORY_UNAVAILABLE`: grep en todo `src/` → 1 sola aparición (emisión), cero consumidores | `StateReportIntegrator.cs:142` |

## 3. Detección — eventos Windows

- **Alta ✅**: el XPath global `Level=1 or Level=2` se aplica también al canal **Security** (`WindowsEventCollector.cs:20,24`); los eventos de auditoría 4625/4740 son Level=0 → **0 registros leídos y cobertura "Disponible"** (falso "todo bien"). Ningún test usa 4625. → **ya cerrado en Fase 8 (`085e799`)**: `ResolveEventQuery` fija `EventID=4625/4740/4771/4776` para Security y el test `SecurityLogTargetsAuditEventIdsAndAlignsDedupKeys` pinea los IDs; fila desactualizada.
- Media: tolerancia 5s del journal produce transiciones duplicadas (B#21, **duplicado de A#3**, ya cerrado en Fase 9 con tolerancia 10 min + guardia de inversión); líneas sin timestamp entran en la ventana y el atajo de nivel no entiende `[fecha] [ERROR]` (C#12) → **corregido en Fase 14** (los eventos sin `Timestamp` caducan por `IngestedAt` contra la cota inferior de la ventana en `KeepEvent`; regex del parser aceptan el prefijo `[fecha] [NIVEL]`).

## 4. Detección — logs Windows/TSplus

- **Media ✅**: `TsplusLogParser` clasifica sólo con tokens en inglés (`fatal/error/...`, sin "falló/denegado/no se pudo") y descarta todo lo `Informativo` (`TsplusLogParser.cs:9-19,42`) → logs en español generan casi nada — **corregido en Fase 10** (tokens/prefijos/regex en español + resúmenes sanos, `TsplusLogParser.cs:9-21,81-102,107-128`).
- Baja: UTF-16 sin BOM no detectado en el incremental (`IncrementalTsplusLogCollector.cs:479-480`); fallback cultural `es-MX` (`TsplusLogParser.cs:226`) — **corregido en Fase 11** (paridad de bytes por pares sobre 32 bytes con comentario `D#UTF16`; formatos invariantes generados + `SplitTimestampOffset` para `Z`/`±HH:MM`, sin `es-MX` ni `GetCultureInfo`).

## 5. Configuración TSplus

- **Media ✅**: `ConfigurationHistoryStore.GetGenerationAsync` devuelve `null` con TODO (`:76-83`) → `DiffAgainstGenerationAsync` siempre vacío y el resumen multi-generación siempre "Sin cambios"; `PruneOldEntriesAsync` = `await Task.CompletedTask` (`:127-134`) — **corregido en Fase 10** (historial/generación/podado reales, `ConfigurationHistoryStore.cs:56-147`).
- Cerrado en Fase 7: `settings.js` con versión desconocida (H10).

## 6. Agrupación de incidentes

| Sev | Hallazgo | Lugar |
|---|---|---|
| Media | **Dos universos sin puente**: la GUI jamás lee `report.Incidentes` (HTML/narrativo sí) — métricas incompatibles sin explicación | D#5 |
| Media | Señales de incidente no se recortan a `PeriodoAnalizado` (amplificado por candidatos con `IncidentTime=null`) | `IncidentClusterAnalyzer.cs:85-91` ✅ |
| Media | Contrato de severidad ledger vs clusters divergente (B#16); sólo el logon-failure más antiguo genera candidato (B#23) → **corregido en Fase 13** (B#16 `IsOperationalImpact` exige `IsIncidentSeverity` más `SERVICE_STATE` RemoteAccess no-Running / `GAP|DELAY` / `WINDOWS_AD_*`: stages de éxito y states en Advertencia quedan `EVIDENCIA_CORRELACIONABLE`; B#23 un candidato por usuario con síntoma vía `emittedLogonUsers` sin `break`, deduplicado y sin ruido) | B#16,23 |
| Baja | IDs posicionales `INC-GRP-NNN` cambian de significado entre ejecuciones (D#6); ráfaga etiquetada `/60s` abarca minutos y hereda `Subject` del último (D#7); `TakeLast(120)` sin aviso en los 3 dashboards (D#13); ramas muertas en `IncidentLedger` (D#8) — **corregido en Fase 11** (D#6 IDs content-derived con `SHA256(dominio|identidad|timestamp)`, D#7 span real + `MergeBurstSubject` con tope 6 y regex de legado, D#13 `ObservabilitySample.IncidentsDropped` + `DashboardRules.DroppedIncidents` en los 3 paneles, D#8 bloque muerto eliminado y constante `Persistent`) | D#6-8,13 |

## 7. Correlación → ranking → causa raíz

| Sev | Hallazgo | Lugar |
|---|---|---|
| **Alta ✅** | Candidatos **estáticos** de compatibilidad Windows (RDP 96/Alta, RDS 97/Alta) se promueven con sólo existir el hallazgo: sin ventana temporal, sin síntoma; el texto `:20` promete gating "sólo cuando el síntoma requiere crear sesión RDP" que **no existe** (`IsPrimaryEligible` sólo mira confianza) | `Rules.WindowsFarm.cs:10-44`, `DiagnosticWorkflow.cs:62-68` |
| Media | `[PRINCIPAL]` coexiste con "Evidencia primaria independiente: No" (B#14); logons RDP **exitosos** cuentan como señal causal e impacto → infla score y fabrica `INCIDENTE_OPERATIVO` (B#15); NLA-password-change 98/Alta sin ventana (B#17); candidatos de config ≥75 sin correlación disparan conflicto de origen −15 (B#18) → **corregido en Fase 13** (B#14 tensión explícita en `ReportConsistencyAnalyzer`; B#15 stages 1149/21/22 fuera de `IsCausalSignal`, sólo `GAP|DELAY` siguen causales; B#17 98/Alta y `HoraIncidente` exigen `WINDOWS_NLA_PASSWORD_CHANGE_CONFLICT` en la ventana con evidencia "No observado" sin ella; B#18 `HasOriginConflict` exige `HoraIncidente` en ambos); exclusión WMI/DCOM distinta entre analizadores (intencional, pineada por `ObservabilityClusterIsNotFunctionalCause`) | B#14-18 |
| Baja | Patrones de falla sólo sobre los 8 primeros candidatos (B#19); tres fallbacks incompatibles de `PeriodoAnalizadoFin` (B#20) → **corregido en Fase 13** (B#19 `PatronesFalla` se calcula sobre la lista calibrada completa y `CausasRaiz` conserva el recorte `Take(8)` de presentación; B#20 helper único `DiagnosticReportWindow.EffectivePeriodEnd` (`PeriodoAnalizadoFin → Fin`) en los 14 sitios; `ReportDiffer.EffectiveTimestamp` conserva su cadena `→ Inicio` de la Fase 12) | B#19-20 |

## 8. Impacto → dependencias

- **Media ✅**: tabla SCM del HTML imprime `N/D` en "Servicio" para todas las transitivas (clave `"Servicio"` vs `"Servicio origen"`) — `ReportExporter.cs:893` vs `ServiceDependencyGraphCollector.cs:259-262`.
- **Media**: el "Mapa de dependencias" pinta de **verde** los `No evaluado/No identificado` (`DependencyClassForReport` cae a `ok`, `ReportExporter.cs:1228-1234`) — contrapuesta del conocido que los pintaba rojo.
- Media: `requiredNow` no se aplica en profundidad ≥1 del grafo → Advertencia espuria (C#10); aviso de truncamiento calculado **sin** el filtro mientras `Take()` va **después** (`:901` vs `:890,:895`) ✅ — con 130/150 filas relevantes se ocultan 10 **sin aviso**.
- Baja: "No evaluado" y la tabla coexisten (`:873-874` vs `:887-899`, D#3); "No disponible" en rojo = falla real (`:1204-1210`, conocido).

## 9. Consistencia del reporte y precisión

- Media: `ReportDiffer` usa `ToDictionary(f => f.Id)` — IDs duplicados lanzan `ArgumentException` que `ReportExporter.cs:54-56` traga con `_ = ex;` → la tarjeta "Cambios desde el reporte anterior" desaparece sin rastro; fecha sin fallback → "01/01/0001" (D#12) → **corregido en Fase 12** (last-wins por Id, fallback `PeriodoAnalizadoFin → Fin → Inicio` con "Fecha no declarada" y tarjeta de respaldo en el export).
- Baja: campos de ventana autoampliada sólo en JSON; precisión penalizada por los candidatos estáticos de la §7.

## 10. GUI — servicios/dependencias/procesos/sesiones

| Sev | Hallazgo | Lugar |
|---|---|---|
| Media | Contadores **CRÍTICOS/ERRORES** suman hallazgos+eventos → `14+11 > 20`; no cuadran con HTML ni JSON | `DiagnosticWorkspaceViewModel.cs:478-481` |
| Media | Donut "SERVICIOS/DEPENDENCIAS" mide 3 cosas (centro=sanos, arco=afectados, aro verde siempre; `healthy` incluye "No requerido") → contradice el panel Servicios → **corregido en Fase 12** (centro `afectados/total` como arco y módulos; aro verde sólo con sanos/neutrales reales) | `SupportDashboardViewModel.cs:92-103,64` |
| Media | Score **preventivo** evalúa el diccionario SCM crudo sin el subgrafo TSplus que aplican los demás paneles → se contradicen sobre el mismo dato → **corregido en Fase 12** (`scoringLatest` e inestabilidad pasan por `TsplusOperationalStates`) | `PreventiveDashboardViewModel.cs:94-95,352` |
| Media ✅ | Truncados sin aviso (`Take(60)`/`Take(30)`); "y N más" calculado sobre 10 filas pero se muestran 30 → **corregido en Fase 10** (`TruncationNotice` + detalle de sesiones a 30) | `IncidentsDashboardViewModel.cs:41-44`, `SessionsDashboardViewModel.cs:51-54,92-99` |
| Media | GUI sin pre-record antes de `Analyze` (paridad rota vs servicio); feedback escrito en `MachineRootPath` pero leído de otra raíz → la GUI ignora veredictos verificados (A#6-8) | A#6-8 |
| Baja ✅ | `SERVICE_STATE` sin sección HTML y fuera de ambas timelines; sin sección de procesos afectados en HTML (la GUI sí lista "Proceso:") → **corregido en Fase 10** (tabla en "Salud y dependencias" + tarjeta "Procesos afectados") | `ReportExporter.cs:903-925,560-577` |

## 11. Huecos de tests

1. **Ningún test ejecuta `WindowsEventCollector` contra eventos de auditoría** (4625): sólo `ResolveRelevantLimit`/`IsPartialCoverage` y *source-text gates* (`Program.cs:898-911,1262-1274`) → el bug de Security nunca puede caer.
2. **Ciclo de emergencia sin tests** (grep `EmergencySample` en `tests/` → 0) → **cerrado en Fase 12** con `EmergencySamplePersistsJournalTransitionsAndLongitudinal` (source-gate de pre-registro/transiciones/enriquecimiento/longitudinal).
3. Patrón dominante de *source-text gates* (tests leen el `.cs`, ej. `:875,:910,:1252`) — detectan cambios de texto, no de comportamiento.
4. Cero tests de caminos de fallo de colectores (permisos, canales inexistentes, fuga de watchers).
5. Reglas RCA `WindowsFarm` sin test de gating sintomático/temporal (no existe código que probar) → **cerrado en Fase 13**: el gating temporal NLA existe (`DiagnosticTimeWindow.IsEventInside`) y lo cubre `NlaPasswordChangeNeedsWindowedConflict` (sin conflicto en ventana 84/Media, con conflicto 98/Alta y hora anclada); el gating sintomático está cubierto por `StaticWindowsConfigCandidatesNeedRemoteSessionSymptom`.
6. `ReportDiffer` sin test de IDs duplicados (pies vs `Take()` cubierto desde Fase 9; aserción de `SERVICE_STATE`/procesos en el HTML cubierta desde Fase 10 con `ExportRendersServiceStateAndProcessSections`) → **cerrado en Fase 12** con `ReportDifferHandlesDuplicateFindingIdsAndUndatedReports` y `ExportKeepsDiffCardWithDuplicateFindingIds`.

## 12. Correcciones detectadas en esta ronda (no re-reportar)

- `CauseStabilityFlappingThreshold` **ya leído** en `TdmWorker.cs:275` (`options?… ?? 2`) con test en `:875` y CHANGELOG → el bajo "umbral muerto" queda **cerrado**.
- La persistencia de causa principal ya loguea `LogWarning` (`TdmWorker.cs:281`) → baja residual, ya no silenciosa.

## Prioridades para "~100% efectiva"

- **P0 ✅ cerrado en Fase 8 (`085e799`)**: filtro del canal Security (§3 Alta) · start-mode antes de `Critico` en TSplus ligero (§1 H2) · gating sintomático+ventana en candidatos Windows estáticos (§7 Alta) · dreno del push collector (§1 Alta) · paridad GUI pre-record + margen −15 min + raíz de feedback (§10).
- **P1 ✅ cerrado en Fase 9 (`85a64c8`)**: `requiredNow` unificado (`WindowsServiceCatalog.RequiredNow`/`StoppedSeverity` + depth≥1 con modo de inicio) · dos universos de incidentes (puente en `BuildSummary` + rótulo de alcance operativo en los dashboards) · contadores GUI CRÍTICOS/ERRORES sólo sobre hallazgos · dedup de transiciones (tolerancia 10 min + guardia de inversión intermedia) · recorte a `PeriodoAnalizado` en clusters y RCA (`DiagnosticTimeWindow.IsEventInside`; fallback histórico AD intacto) · `N/D` del grafo SCM (respaldo `Servicio origen`) y verde de "No evaluado" → `warn` · pies vs `Take()` (pie con el número real de ocultas sobre 120/60) · baseline fallida no persistida (`SCM_GRAPH_BASELINE_STALE`).
- **P2 ✅ cerrado en Fase 10 (`80fe6d4`)**: parser de logs en español (`TsplusLogParser` tokens/prefijos/regex + `ClassifyType`) · telemetría de snapshot corrupto (`CorruptSnapshotReadCount`/`LastCorruptSnapshotPath` + `Trace.TraceWarning` + `LocalStoreStatus.CorruptSnapshotReads` + `RetentionState`) · `ConfigurationHistory` multi-generación (historial/generación/podado reales) · umbrales conectados a más paneles (`General`/`MultiServer`/`Preventive` desde `CurrentThresholds`) · secciones `SERVICE_STATE`+procesos en HTML (tabla en "Salud y dependencias" + tarjeta "Procesos afectados") · avisos de truncado en GUI (`TruncationNotice` + detalle de sesiones a 30) · canal `diagnostic-avalonia` en lecturas.
- **P3 ✅ cerrado en Fase 11 (`5894fc1`)**: IDs de clúster content-derived (`INC-GRP-` + 8 hex de `SHA256(dominio|identidad|primer timestamp)`, sin posición) · ráfaga con span real (`(ráfaga ×N en 45 s|2.5 min)`) y `Subject` unido con tope 6 + `(+N más)` (regex acepta legado `/60s`) · aviso de `TakeLast(120)` (`ObservabilitySample.IncidentsDropped` + `DashboardRules.DroppedIncidents` en Incidentes, Sesiones y Soporte, detalle y axaml) · ramas muertas de `IncidentLedger` (bloque `fallbackCandidate` irrecorrible + constante `ManagedIncidentState.Persistent`) · parser sin `es-MX` (180 formatos invariantes generados, `SplitTimestampOffset` para `Z`/`±HH:MM`, ambigüedad exige ventana) · UTF-16 sin BOM (paridad por pares sobre 32 bytes). 6 tests nuevos (117/117) + `GuiDashboardsDeclareTruncatedRows` extendido (45/45).
- **P4 ✅ cerrado en Fase 12 (`f327867`)**: `ReportDiffer` tolerante a IDs duplicados (last-wins por `Id`, igual que las causas) y fechas sin `01/01/0001` (fallback `PeriodoAnalizadoFin → Fin → Inicio` + "Fecha no declarada" + tarjeta de respaldo en el export) (D#12) · muestra de emergencia con el pipeline completo del ciclo normal (pre-registro `service-monitor`, transiciones recientes, `RecordAndEnrichAsync` y despacho longitudinal) (A#9) · gate longitudinal sobre el presupuesto real (`HasBudgetForLongitudinal`: consumido + 23 s ≤ 180 s, en vez de 45 s fijos) (A#10) · aislamiento por servicio en el grafo SCM ante cualquier excepción no-cancelación en los 4 puntos + dispose verificado (C#5) · dona Soporte con una sola medida (centro `afectados/total`, aro gris sin elementos sanos) · score preventivo e inestabilidad sobre el subgrafo TSplus alcanzable (mismos paneles). 5 tests nuevos (122/122) + 2 tests de paridad y `Support_ServiceRatio` ajustado (47/47).
- **P5 ✅ cerrado en Fase 13 (`1554726`)**: tensión `[PRINCIPAL]` sin evidencia primaria independiente (B#14) · stages RDP exitosos fuera de `IsCausalSignal` (B#15) · contrato `IsIncidentSeverity` en `IsOperationalImpact` de clusters (B#16) · NLA anclado a la ventana con evidencia "No observado" sin ella (B#17, cierra el hueco §11.5-5) · conflicto de origen exige `HoraIncidente` en ambos candidatos (B#18) · `PatronesFalla` sobre la lista calibrada completa (B#19) · helper único `DiagnosticReportWindow.EffectivePeriodEnd` en los 14 sitios de cierre de periodo (B#20) · candidato de logon por usuario con síntoma, sin `break` ni duplicados (B#23). 7 tests nuevos (129/129), Parity 47/47, VERIFY 7/7.
- **P6 ✅ cerrado en Fase 14 (`5c880d6`)**: cobertura declarada en el fallback del catálogo de servicios (C#7) · presupuesto de hallazgos de integridad por canal (C#8) · inicialización del snapshot de registro TSplus con evento (C#9) · canal inexistente en el SO como "no aplicable" en vez de Parcial permanente (C#11) · atajo de nivel `[fecha] [NIVEL]` en `TsplusLogParser` + caducidad de eventos sin timestamp por `IngestedAt` (C#12/B#21) · `StateTransition.ChangedAfter` como cota inferior del cambio con precedencia longitudinal por `earliestPossible` (§2) · fallo del journal reciente declarado como `TDM_RECENT_TRANSITIONS_UNAVAILABLE` (§2). 9 tests nuevos (138/138), Parity 47/47, VERIFY 7/7, publish 138960071.
