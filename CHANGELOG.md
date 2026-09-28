# Changelog

All notable changes to TDM (TSplus Diagnostic Monitor) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc18.21.0-FIX93] - 2026-09-24

### Fixed — Fase A de la auditoría senior (4 hallazgos P0)

- **Ledger de incidentes: identidad persistida y sin borrados por reescritura**: `ManagedIncident` ahora conserva `Classification` y `Product` (antes se creaba con `null` y el filtro de `ReadAsync` rechazaba los incidentes de identidad, por lo que `ReconcileAsync`/`AddNoteAsync`/`CloseAsync` los eliminaban del JSONL en la siguiente reescritura). Los rewrites leen ahora con `ReadRawAsync` (todas las filas JSONL válidas) y sólo la lectura pública aplica el filtro de incidentes operativos, ahora pasando clasificación y producto; `ReconcileAsync` devuelve además sólo lo operativo para no exponer filas legadas.
- **Clústeres de identidad con evidencia en español**: `IncidentClusterAnalyzer.IdentityKey` normalizaba la clave consultada pero no la clave almacenada en la evidencia, así que `Usuario`/`Equipo`/`Servicio` de los collectors nunca se encontraban y señales con usuarios distintos caían en el mismo clúster. Ahora normaliza ambos lados con `EvidenceKeyNormalizer`.
- **Umbrales de disco aplicados en Rendimiento**: `MainWindowViewModel` llamaba `Performance.ApplyLiveResources(...)` y `Performance.Apply(...)` sin umbrales (siempre los valores por defecto). Ahora pasa `Administration.CurrentThresholds`, igual que Preventivo y Salud TDM; `ApplyLiveResources` quedó como único método público con umbral opcional.
- **Ranking con candidatos de Id duplicado**: `DiagnosticPrecisionAnalyzer.Calibrate` buscaba la posición por `Id`, así que dos crashes (`ROOT-PROCESS-CRASH`) o una variante `ROOT-SCM-SERVICE-FAILURE-{servicio}` heredaban la brecha y el estado del primero ("0 puntos" y `CANDIDATO_PRINCIPAL` para ambos). El rank ahora se resuelve por instancia, la evidencia primaria independiente de SCM acepta el Id con sufijo (evidencia "Crash posterior cercano") y el marcador `[PRINCIPAL]` de la pestaña Diagnóstico sólo se pinta en la instancia real de la causa principal (`Posicion` + `Id`).
- **Tests de regresión**: `LedgerKeepsIdentityClassifiedIncidents`, `SpanishUserEvidenceSplitsIdentityClusters`, `DuplicateCandidateIdsRankIndependently` (ProductionTests, 50/50) y `RootCause_PrincipalMarkerOnlyOnPrimaryInstance` (Parity, 31/31).

### Fixed — Fase B de la auditoría senior (6 hallazgos P1)

- **Umbral de flapping configurable**: `TdmWorker` calculaba el estabilidad del diagnóstico con `DiagnosticExecutionPolicy.ForLookback(...)` fijo, ignorando `DiagnosticOptions.CauseStabilityFlappingThreshold`. Ahora el análisis lee `options?.CauseStabilityFlappingThreshold ?? 2`.
- **Impacto funcional por palabra completa**: `FunctionalImpactAnalyzer.AddCauseDrivenImpact` buscaba subcadenas ("80" coincidía con "8080", "shell" con "PowerShell", "Web" con "8080"), produciendo impactos espurios. Ahora usa coincidencia por límites de palabra (`ContainsToken`); los filtros de estado directo y los stems ("CRÍT") no cambian.
- **Acción de disco con el umbral configurado**: `PreventiveDashboardViewModel.BuildActions` usaba `15 %` fijo para recomendar "Liberar o ampliar almacenamiento", ignorando `DiskFreeWarningPercent`. Ahora ambos call sites usan `DiskActionFloor(thresholds) = Max(15, DiskFreeWarningPercent)`, conservando el comportamiento por defecto (15) y respetando umbrales mayores (p. ej. 20 %).
- **Anomalías EWMA visibles en el informe**: `IntegratedMonitoringService` instanciaba `AnomalyDetectionService` y descartaba los resultados, y registraba `Debug.WriteLine` en producción. Ahora cada anomalía EWMA se añade como `DiagnosticFinding` al informe (flujo a contadores de bitácora y alertas del portable) con enfriamiento de 5 min por métrica.
- **`DiagnosticOptions.MaxEvents` respetado por los logs de Windows**: `WindowsEventCollector` aplicaba el límite por canal (mismo tope en cada uno) e ignoraba `MaxEvents`. Ahora un presupuesto global decrementa el límite por evento guardado, `ResolveRelevantLimit` aplica `MaxEvents` sobre el límite por ventana de lookback y el presupuesto agotado se reporta como cobertura "Parcial".
- **Tests deterministas en cualquier configuración regional**: ambas suites fijan la cultura de hilos a `CultureInfo.InvariantCulture` (es-ES/"," rompían formatos); `TsplusLogParser` ya era explícito con `InvariantCulture` + fallback `es-MX`.
- **Tests de regresión**: `CauseDrivenImpactUsesWordBoundaries`, `FlappingThresholdHonorsConfiguredOptions`, `EwmaAnomaliesSurfaceAsReportFindings`, `WindowsEventCollectorHonorsMaxEventsOption`, `TestsRunUnderPinnedInvariantCulture` (ProductionTests, 55/55) y `Preventive_DiskActionHonorsThresholds`, `CultureIsPinnedForDeterministicFormatting` (Parity, 33/33).

### Fixed — Fase 1 de la auditoría senior (colectores incrementales en la GUI)

- **Diagnóstico continuo incremental**: cada ciclo de 5 s en "Tiempo real" re-ejecutaba los 40 colectores completos desde cero. `DiagnosticExecutionService` siembra con `CollectorCatalog.CreateFull()` la primera vez (y al ampliar la ventana), posiciona los cursores de los dos colectores incrementales al inicio de la siembra (`Prime()`, sin hueco de datos entre siembra y primera muestra incremental) y a partir de ahí ejecuta `CollectorCatalog.CreateContinuous(...)`, que sustituye únicamente `WindowsEventCollector` y `TsplusLogCollector` por `IncrementalWindowsEventCollector` e `IncrementalTsplusLogCollector` (cursores `windows-event-cursors`/`tsplus-log-cursors` compartidos con TDM.Service); el resto de fuentes y el recuento de collectors no cambian.
- **Fusión de informes con ventana móvil**: cada muestra incremental se fusiona con la línea base mediante `ContinuousDiagnosticMerger` (`ShouldContinue` decide siembra vs. continuo según la ventana analizada): ventana acotada al lookback, reemplazo de estados actuales (`SERVICE_STATE`, `RDP_STATE`, …), deduplicación por identidad compartida y límites de 12 000 eventos / 4 000 hallazgos. Los hallazgos sólo se arrastran de las fuentes sustituidas (`EVT-*`, `LIVE-EVT-*`, `TSLOG-*`, `LIVE-TSLOG-*`, excluidos los de acceso `-ACCESS`/`-READ`); los hallazgos de estado se recalculan en cada muestra y desaparecen si la condición se recuperó.
- **Identidad de eventos compartida**: la lógica WER/RecordId/FALLBACK se extrajo a `DiagnosticEventIdentity`, usada tanto por `DiagnosticEngine.Deduplicate` como por el merger, de modo que una lectura incremental colapsa con la lectura completa del mismo registro (mismo `RecordId`/`ReportId`) en lugar de duplicarse.
- **Modo continuo declarado en el informe**: `DiagnosticoContinuo`, `UltimaActualizacionContinua`, `IntervaloContinuoSegundos` y `MuestrasContinuas` (campos previamente nunca asignados) se establecen en cada ciclo: el export HTML/JSON muestra "Modo: Continuo · cada 5 s · muestras=N" y la cobertura añade las fuentes incrementales de Event Viewer y logs TSplus.
- **Cobertura de logs TSplus acepta la fuente incremental**: `DiagnosticCoverageAnalyzer.AddTsplusLogs` lee también `TSPLUS_INCREMENTAL_LOG_COVERAGE` (candidatas − no evaluadas) además de `TSPLUS_LOG_COVERAGE`; antes, en modo continuo o desde el servicio, la fuente crítica aparecía como "No disponible" pese a que el incremental sí informaba de su cobertura.
- **Tests de regresión**: `ContinuousMergerKeepsWindowStateAndAnchoredEvents`, `ContinuousRunReplansSeedWhenWindowGrows`, `ContinuousCatalogSwapsHeavySourcesForIncremental`, `TsplusCoverageAcceptsIncrementalSource`, `GuiRealtimeWiresIncrementalContinuousDiagnostics` (ProductionTests, 60/60); ParityTests 33/33.

### Fixed — Fase 2 de la auditoría senior (paridad exportación ↔ GUI)

- **`[PRINCIPAL]` en las causas del export**: el HTML listaba los candidatos sin indicar cuál es la causa principal (la GUI sí lo marcaba). Ahora la sección de causas antepona `[PRINCIPAL]` al candidato de `CausaRaizPrincipal`, añade "Sin causa principal declarada…" cuando ningún candidato alcanza el margen de evidencia, y pies de truncado para candidatos (más de 8) y evidencia (más de 24 ítems); las anclas `cau-N` y `fnd-N` se conservan.
- **Resolución guiada completa en el export**: la tabla perdía la severidad, las tarjetas sólo listaban estados Error/Advertencia y no había orden por criticidad. Ahora export y GUI comparten `InvestigationGuidanceBuilder.RequiresAction`, ordenan por acción+severidad, muestran la línea "Resoluciones: N | Requieren acción: N | Mostrando: N", agrupan "Requiere acción (N):"/"Sin acción requerida:" con marcadores `[CRÍTICO]/[ERROR]/[ADVERTENCIA]`, fila "Síntoma", lista de comprobaciones y pie de truncado (toma 12).
- **Patrones de falla sin filtro de recurrencia**: el export filtraba `Incidentes > 1` (ocultaba singletons) con el título "Patrones recurrentes" y 7 columnas; la GUI decía "recurrentes" en el estado vacío. Ambos muestran todos los patrones (hasta 20) con 11 columnas (Origen, Intervalo promedio, Incidentes relacionados…), pie "… y N patrón(es) más sin mostrar" y el mismo estado vacío; la métrica superior sigue contando sólo recurrentes.
- **Cobertura con conteos y críticas primero**: export y GUI añaden "Fuentes: N | Críticas: N | Críticas bloqueadas: N | Parciales: N" (Parciales cuenta todos los estados Parcial/No consultado, no sólo no-críticas), la tabla lista primero las fuentes críticas y "Bloqueos duros" ahora refleja ese conteo de críticas bloqueadas (antes mostraba `FuentesBloqueadas`, un agregado de otra sección).
- **JSON con enums legibles**: el export escribía enums como números; ahora `JsonStringEnumConverter` emite `"Critico"`, `"Windows"`, … (la lectura admite texto y números, también al cargar el reporte previo en `DiagnosticExecutionService`).
- **Sanitización idempotente**: `SupportBundleSanitizer.Pseudonym` re-hasheaba pseudónimos ya generados (`USR-XXXXXXXX` se convertía en otro hash), por lo que un reporte previo ya sanitizado generaba una tarjeta diff espuria; ahora un pseudónimo con formato `{prefijo}-XXXXXXXX` se devuelve tal cual (las redacciones por regex ya eran idempotentes).
- **Narrativo en hora local y con pies de colección**: `DiagnosticNarrativeBuilder` imprimía ventana/ejecución en UTC; ahora usa `ToLocalTime()` como el export, y cada enumeración truncada declara "… y N … (colección completa en JSON)" (incidentes, crash-loops, patrones, cuentas, sesiones, perfiles, inventario y anomalías internas).
- **Evidencia sin fecha usa `IngestedAt`**: los eventos sin `Timestamp` mostraban "Sin fecha" aunque tuvieran `IngestedAt`; ahora el detalle del export cae a `IngestedAt` antes de "Sin fecha".
- **Pie de enumeraciones en el export**: cuentas locales (100), sesiones (60), autenticación (80), perfiles (50), aplicaciones publicadas (100), artefactos de configuración (60), anomalías internas (60) e incidentes (20) anuncian "Mostrando X de N … El JSON conserva la colección completa."
- **GUI**: `BuildSummary` cae a `Inicio − Lookback` cuando la ventana analizada está vacía (sin `01/01/0001`), el estado de exportación declara "paquete sanitizado; revise antes de compartir" junto a la ruta, y `BuildSummary/BuildCoverage/BuildPatterns` quedan públicos para las pruebas de paridad.
- **Tests de regresión**: `ExportRootCauseMarkersAndFooters`, `ExportGuidedResolutionOrderAndDetails`, `ExportPatternsShowSingletonsAndFullColumns`, `ExportCoverageCountsAndCriticalFirst`, `ExportJsonUsesStringEnumsAndRoundTrips`, `SanitizerIdempotentAvoidsSpuriousDiff`, `NarrativeUsesLocalTimeForWindows`, `EvidenceDetailsFallBackToIngestedAt` (ProductionTests, 68/68); `Gui_CoverageCountsMatchExport`, `Gui_SummaryWindowWithoutYearZero`, `Gui_PatternsMatchExport`, `Gui_ExportStatusDeclaresSanitizedPackage` (ParityTests, 37/37).

### Fixed — Fase 3 de la auditoría senior (brechas de privacidad exportación/persistencia)

- **Causa principal sin sanitizar en el export**: `SupportBundleSanitizer.Sanitize` reconstruía `CausasRaiz` pero dejaba `CausaRaizPrincipal` sin sanitizar; el JSON export la conservaba en claro y el HTML/narrativo la renderizaban crudos desde `safeReport`, mientras la misma causa dentro de `CausasRaiz` iba pseudonimizada. Ahora `CausaRaizPrincipal` se sanitiza con el mismo `SanitizeCause`.
- **Clústeres de incidentes en claro**: `Incidentes` no entraba en `Sanitize()`, por lo que la evidencia "Identidad del grupo" (`USUARIO|HOST|SERVICIO`, construida por `IncidentClusterAnalyzer.IdentityKey`) salía en claro en el JSON export. Ahora cada clúster se sanitiza: `Identidad del grupo` → pseudónimo `USR-XXXXXXXX`, `Dominio` (valor funcional tipo `AD_AUTENTICACION`, no un dominio AD) se conserva con `SanitizeText` y el resto de la evidencia pasa por `SanitizeEvidence`.
- **Precisión, tensiones y motivo de ampliación en claro**: `PrecisionDiagnostica` (Resumen/Evidencia), `Tensiones` y `MotivoAmpliacion` viajaban sin sanitizar en el JSON export; ahora Resumen/textos pasan por `SanitizeText` y la evidencia por `SanitizeEvidence`.
- **Claves de evidencia con inicial mayúscula no detectadas**: `SupportBundleSanitizer.NormalizeKey` no normalizaba a minúsculas, así que las claves exactas `Usuario`/`Dominio`/`Cuenta` (como las escriben los collectors) no coincidían con las constantes en minúscula de `IsIdentityKey`/`IsDomainKey` y valores en claro (p. ej. `alice`) salían en el paquete a pesar de la sanitización. Ahora `NormalizeKey` devuelve el texto en minúsculas.
- **`latest-report.json` en claro**: `DiagnosticExecutionService.ExportAsync` persistía el informe completo (evidencia con usuarios, IPs, correos y rutas de perfil) en `state/latest-report.json`, mientras los dashboards de la GUI muestran esos mismos campos enmascarados (`[IP]`/`[IDENTIDAD]`). Ahora guarda `SupportBundleSanitizer.Sanitize(report)`; el diff día-a-día no cambia porque `ReportExporter` ya sanitiza el reporte previo en el punto de comparación.
- **Superficies verificadas limpias**: muestras de `observability-window.jsonl` (incidentes y labels enmascarados en origen por `ObservabilityStore.SanitizeLabel`), `incident-ledger.jsonl` (resúmenes enmascarados), journals de escritorio/correo (señales desde el ledger) y el resto del export (Sistema, Hallazgos, Eventos, CausasRaiz, Patrones, Resoluciones, Impacto, Plan, Cobertura) ya sanitizados; `RendimientoDiagnostico` sólo contiene nombres de collectors TDM (sin PII) y no requiere cambios. Residuo documentado fuera de alcance: los logs de la GUI (`logs/tdm-gui-*.log`) guardan mensajes operativos y excepciones que pueden incluir rutas locales.
- **Tests de regresión**: `SanitizeCoversPreviouslyRawSections`, `ExportJsonMasksPrimaryCauseAndClusterIdentity` (ProductionTests, 70/70); `Export_LatestReportStoredSanitized` (ParityTests, 38/38, con raíz de datos hermética vía `TDM_DATA_DIR`).

### Fixed — Fase 4 de la auditoría senior (críticos C1–C3)

- **C1 — Security Log ausente clasificado como disponible**: `DiagnosticCoverageAnalyzer.AddSecurityLog` evaluaba `Contains("Disponible")` antes que `Contains("No disponible")` y "No disponible" contiene "Disponible", así que el Security Log no leído se registraba "Disponible": ganaba el peso crítico completo y no emitía la limitación `Cobertura de autenticación/NLA/Kerberos limitada`. Ahora el orden es `IsBlocked → No disponible → Disponible → Parcial`, de modo que permisos/no legible quedan "Bloqueada" y la ausencia real castiga el puntaje de cobertura.
- **C2 — continuidad de Event Viewer tras reinicio del servicio**: `WindowsCursorState` no persistía la última muestra con cobertura completa (`_lastSuccessUtc` sólo en memoria), por lo que tras un reinicio o una parada mayor de 15 min la marca era null: el branch GAP no declaraba la discontinuidad, el servicio seguía con el ciclo normal de 60 s (o el de emergencia de 2 min) sin ampliar la ventana y un reinicio dejaba el hueco silencioso. Ahora `LastSuccessUtc` se persiste con respaldo a `SavedAt` para estados legados, `Prime()` restaura la marca y resetea `_gapDeclared`/`_firstCollectStarted`, el collector expone `RecoveryLookback(now)` (hueco ≤1 min → ciclo normal; 1–15 min → amplía hasta el hueco; >15 min o cursor corrupto → 15 min; ya ejecutada la primera muestra → null) y `TdmWorker` lo aplica en el ciclo normal (`?? NormalInterval`) y en el de emergencia (`?? EmergencyPolicy.Lookback`). Además el hallazgo GAP se declara una sola vez por hueco (rearmando sólo con una muestra de cobertura total) y la persistencia se reordenó: `LastSuccessUtc` sólo avanza si la muestra no perdió canales y el cursor se guardó (antes el estado se guardaba antes de calcular `lost`, con lo que una muestra parcial podía firmar continuidad).
- **C3 — cursor TSplus con replay completo y hash de archivo entero**: `IncrementalTsplusLogCollector.ComputeFileHash` leía y hasheaba el archivo completo tanto en `Prime()` como en cada `PersistCursorState()`; como el hash cubría el archivo entero, cualquier byte escrito tras el último guardado hacía fallar la validación y el cursor se reiniciaba a 0, releyendo el log completo desde el origen en cada arranque (y pagando I/O completo por muestra con logs de gigabytes). Ahora el hash es un prefijo acotado a 1 MiB (`MaxCursorHashBytes`) calculado con lectura incremental, y `Prime()` valida además que el `Offset` persistido no supere el tamaño actual del archivo, de modo que un append normal conserva el cursor, una rotación/truncamiento sigue forzando replay y ninguna validación dispara lecturas sin límite. Los estados legados con hash de archivo completo producen un único replay al subir de versión.
- **Tests de regresión**: `SecurityLogMissingStatusIsNotAvailable`, `WindowsEventRecoveryLookbackRestoresPersistedGap`, `WindowsEventRecoveryLookbackDisarmsAfterFirstCollect`, `TsplusCursorKeepsOffsetAfterAppend`, `WindowsEventGapRecoveryIsWiredInWorker` (ProductionTests, 75/75); ParityTests 38/38; VERIFY 7/7 y publish portable (138 779 847 bytes).

### Fixed — Pestaña Logs (correcciones de interfaz reportadas en pruebas)

- **Filtros "Nivel" y "Sistema"**: ambos ComboBox enlazaban `SelectedItem` directamente con `ComboBoxItem` en XML, por lo que al seleccionar cualquier opción se producía un error de binding al escribir el valor en `LogLevel?`/`LogSourceSystem?`. Ahora se enlazan a opciones tipadas (`LogFilterOption`) mediante `ItemsSource` + `ItemTemplate`, eliminando el mensaje de error.
- **Logs en tiempo real**: `DiagnosticExecutionService` instanciaba su propio `LogService`, así que los ciclos del diagnóstico (cada 5 s en "Tiempo real") nunca llegaban al observable al que se suscribe la pestaña Logs. Ahora usa la instancia compartida `App.LogService` y la lista avanza durante la ejecución.
- **Selección inicial de filtros**: ambos filtros arrancan en "Todos" y "Limpiar filtros" restaura "Todos" en lugar de dejar el ComboBox vacío.
- **Barra de estado**: se eliminó por completo la tarjeta del pie de la pestaña Logs (texto "Arrastre para seleccionar · Ctrl+C para copiar").
- **Segunda instancia**: al abrir TDM con otra instancia en ejecución, la nueva ventana salía con el error "Dispatcher shut down" (código 0xE0434352). Ahora la segunda instancia termina limpia (código 0).

### Added — Centro de Soporte, diagnóstico y gráficas (solicitud de mejora)

- **Detalle de Incidentes**: además de los conteos, lista los elementos a revisar (hora, severidad, tipo, asunto y resumen) ordenados por severidad, con desglose por tipo de incidente.
- **Detalle de Sesiones**: lista las sesiones/incidencias con la cuenta o sesión afectada (`ObservabilityIncident.Subject`), hora, tipo y resumen, para saber qué usuario revisar. IP, correo y rutas de perfil siguen enmascarados.
- **Servicios y dependencias**: el detalle incluye ahora el estado localizado de cada elemento detenido o pendiente de revisión (por ejemplo `Servicio TSplusGateway (Detenido)`).
- **Módulos TSplus**: el detalle añade el estado normalizado de cada módulo afectado.
- **Resumen técnico de Diagnóstico**: nueva sección "Elementos a revisar" con servicios no operativos, dependencias caídas, procesos con crash y sesiones/usuarios con incidencia en la ventana.
- **Asunto en incidentes persistidos**: `ObservabilityIncident` incorpora `Subject` (cuenta, servicio o proceso) extraído de la evidencia, para que los detalles del dashboard indiquen qué revisar.
- **Gráficas sin líneas "mordidas"**: `DashboardRules.ContinuousSeries` completa los huecos de CPU/memoria/red con el último valor conocido en lugar de dejar `NaN` intercalados (serie discontinua en General, Rendimiento, Preventivo y Salud TDM).
- **Precisión diagnóstica más justa**: una fuente crítica *parcial* ya no penaliza el puntaje como si estuviera bloqueada (sólo el bloqueo duro resta); los incidentes funcionales detectados (servicios, procesos, sesiones) suman hasta 12 puntos y la evidencia nueva expone "Bloqueos duros" e "Incidentes funcionales detectados".
- **Calibración de candidatos**: el descenso de confianza por cobertura incompleta aplica sólo cuando hay bloqueo duro de una fuente crítica; la cobertura parcial se reporta como limitación.

### Fixed — Pestaña Logs (columnas desalineadas y mensaje cortado)

- **Alineación de columnas**: la plantilla de fila usaba `Auto,Auto,Auto,Auto,*,Auto`, con la columna flexible en "Componente" y el mensaje en `Auto`. Como cada fila tenía su propio `Grid`, la columna de sistema origen caía en una posición distinta en cada renglón y el mensaje se desbordaba del panel (scroll horizontal y texto cortado a la derecha). Ahora las columnas son de ancho fijo (`20,96,72,80,140,*`), el mensaje ocupa la columna flexible con ajuste de línea y la lista ya no genera scroll horizontal.
- **Cabecera de columnas**: nueva fila fija `HORA · NIVEL · SISTEMA · COMPONENTE · MENSAJE` alineada con el contenido de cada fila.
- **Componente**: recorte con "…" y tooltip con el valor completo (antes sólo `MaxWidth`, que competía con la columna flexible).

### Added — Paneles con detalle ya calculado (texto sin enlazar)

- **Preventivo**: las tarjetas "Riesgo preventivo", "Servicios y dependencias", "Predicción de saturación" e "Inestabilidad operativa" muestran ahora su detalle (`PreventiveDetail`, `DependencyDetail`, `SaturationDetail`, `InstabilityDetail`), que se calculaba y se descartaba.
- **Servicios y dependencias**: las secciones muestran el resumen ("N en ejecución · M detenidos · …") que el ViewModel ya generaba pero no se enlazaba.
- **Salud TDM**: nueva tira de telemetría con modo de monitoreo, frecuencia, muestras, muestras diferidas, timeouts, tamaño de bitácora JSONL y el colector más lento (con su duración), propiedades que ya se calculaban pero no se mostraban.

### Added — Pestañas de Diagnóstico con evidencia y límites visibles

- **Causa raíz**: encabezado `[PRINCIPAL]` con la causa principal (el que indica a qué candidata aplican "Confirmar/Descartar causa"), nota cuando existe evidencia pero ningún candidato alcanza el margen, hora del incidente, capa, rol causal, hasta 4 evidencias por candidato ("… y N más") y fuente oficial con URL; pie "… y N candidato(s) más" cuando la lista supera 8.
- **Cobertura**: fuentes críticas marcadas con `[CRÍTICA]` (primero en la lista) y coloreadas; línea de conteos `Fuentes | Críticas | Críticas bloqueadas | Parciales` usando el mismo criterio de bloqueo duro del analizador; se añade precisión diagnóstica (score, nivel, cobertura completa, bloqueos duros, señales causales).
- **Resolución guiada**: ahora se ordena "Requiere acción" primero (crítico/error/advertencia) y se separa en secciones `Requiere acción` / `Sin acción requerida` con cabeceras; cada entrada muestra severidad, comprobaciones (nombre/estado/detalle), cobertura y fuente oficial con URL; pie "… y N resolución(es) más".
- **Evidencia/Eventos**: nuevo buscador (mensaje, componente, tipo, código o asunto), contadores `Total · Filtrados · Mostrados` con aviso del límite de 500, columna **Asunto** (cuenta o servicio afectado, sanitizado), fecha de respaldo desde `IngestedAt` cuando el evento no tiene timestamp y estado vacío "Sin eventos para los filtros actuales".
- **Resumen y Patrones**: pies "… y N más" en hallazgos destacados (10) y patrones (20); Patrones añade componente semántico, tipo de excepción e incidentes relacionados.
- **Marcadores coloreados**: `FormattedReportView` pinta las líneas que empiezan por `[CRÍTICO]`, `[ERROR]`, `[ADVERTENCIA]`, `[CRÍTICA]` o `[PRINCIPAL]` sin partir la línea en clave/valor.

### Added — Dashboards: paneles de detalle, contadores explícitos y umbrales configurables

- **Ver detalle (Sesiones)**: nuevo panel con activas/desconectadas, cobertura, fallos logon/NLA de la última muestra y hasta 10 sesiones con incidencia (hora, severidad, tipo, componente y resumen; "… y N más").
- **Ver detalle (Incidentes)**: nuevo panel con totales (total, críticos, error, componentes afectados), desglose por tipo y hasta 15 elementos a revisar (críticos y errores primero) con "… y N más".
- **Ver detalle (Servidores/Granja)**: nuevo panel con el reparto de nodos (en línea/degradados/sin datos) y el estado por nodo: salud, conectividad, CPU, sesiones, incidentes, antigüedad de la última muestra y desfase de reloj, marcando `[MUESTRA ANTIGUA]`, `[SIN DATOS]` o `[DESFASE DE RELOJ]` según `SupportThresholds` (`NodeStaleWarningSeconds`, `NodeOfflineSeconds`, `ClockDriftWarningSeconds`).
- **Ver detalle (Salud TDM)**: nuevo panel con la telemetría del monitor (modo, frecuencia, muestras, diferidas, timeouts, bitácora JSONL, colector más lento), CPU/memoria de TDM con sus umbrales configurados, estado de recursos abiertos e hilos frente a `TdmHandlesWarning/Critical` y `TdmThreadsWarning/Critical` (Normal/Advertencia/Crítico) y la duración media/máxima en la ventana.
- **Contadores "0 = sin datos" explícitos**: en Sesiones, los fallos logon/NLA muestran "No evaluado" cuando el colector de sesiones no aportó datos (en lugar de un "0" ambiguo); en Incidentes, todos los contadores muestran "No evaluado" cuando no hay muestras en la ventana.
- **Granja con conteos particionados**: "En línea", "Degradados" y "Sin datos" forman ahora una partición disjunta (cada nodo se cuenta una sola vez); un nodo `EN LÍNEA` con salud `FALLA` pasa a Degradados en vez de contar como En línea.
- **Último dato presente (Rendimiento)**: CPU, memoria, entrada y salida de red se toman de la última muestra que sí tiene cada valor (`LastOrDefault` con dato presente) en lugar de la última muestra, que puede ser una captura ligera sin esas métricas (mismo criterio para TSplus con `ModuleHealth` y para Sesiones con datos de sesión).
- **Umbrales desde la configuración**: las gráficas de CPU/memoria de Rendimiento y Preventivo usan ahora `SupportThresholds.CpuWarning/CpuCritical` y `MemoryUsedWarning/MemoryUsedCritical` (antes 70/85 fijos en Rendimiento y 85/95 fijos en Preventivo, sin relación con la configuración).

### Changed — Último dato presente en General, Soporte y Salud TDM

- **General**: CPU, memoria libre, salud de módulos, cobertura, hallazgos críticos/error y crash loops se toman de la última muestra que sí tiene cada dato (`LastOrDefault` con presencia) en lugar de la última muestra; una captura ligera al final de la ventana ya no deja "N/D" o "NO EVALUADO" injustos.
- **General — acentos configurables**: el color de CPU y memoria usa `SupportThresholds.CpuWarning/CpuCritical` y `MemoryUsedWarning/MemoryUsedCritical` (antes 85/95 y 20/10 fijos), alineado con las gráficas.
- **Soporte — tarjeta Sesiones**: los contadores provienen de la última muestra con datos de sesión; sin datos muestra "N/D", "Sin datos de sesiones" y "Cobertura: No evaluado" en lugar de un "0" ambiguo.
- **Salud TDM**: modo/frecuencia/diferidas/timeouts (última muestra de monitoreo), CPU, memoria, recursos abiertos, hilos, bitácora JSONL, colector más lento y duración se toman de la última muestra presente de cada métrica.
- **Helper compartido**: `DashboardRules.LastSessionSample` concentra el criterio de "muestra con datos de sesión" y lo usan Soporte y Sesiones.
- **Gate de verificación**: la comprobación estática "Sesiones calcula el total observado" se actualiza a la nueva expresión (`sessionSample`), conservando la misma intención (activas + desconectadas).

### Added — Umbrales de disco libre configurables y pruebas de regresión de fases 4–5

- **`SupportThresholds.DiskFreeWarningPercent/DiskFreeCriticalPercent`**: nuevos umbrales de espacio libre en disco (por defecto 10 % y 5 %, antes fijos en el código). Como a menor libre peor, el validador exige que el nivel de aviso sea mayor que el crítico y ambos entre 1 y 100; la configuración guardada sin estos campos sigue cargando con los valores por defecto.
- **Rendimiento — acentos de disco configurables**: las filas de discos (muestra persistida y captura ligera en vivo) pintan Danger/Warn/Good según `DiskFreeCriticalPercent`/`DiskFreeWarningPercent` (antes `<= 5` y `<= 10` fijos); `Apply` acepta umbrales opcionales como en Salud TDM y Preventivo.
- **Preventivo — señal "Disco X" configurable**: el filtro de discos con poco espacio y sus acentos (Danger/Error/Warn) usan los umbrales configurados (el filtro conserva el suelo de 15 % cuando el aviso no lo supera).
- **Configuración — fila "Disco libre (%)"**: nueva fila de umbrales (Advertencia/Crítico) en el panel de Administración con carga y guardado en `BuildThresholds`/`ApplyThresholds`, respetando la geometría aprobada de la fila de memoria.
- **Pruebas de regresión (fases 4–5)**: cuatro nuevas pruebas de paridad — `Federation_PartitionCountsAddUp` (en línea + degradados + sin datos = total, con `EN LÍNEA`+`FALLA` degradado), `EmptyWindowShowsNotEvaluated` (Incidentes/Sesiones/Soporte sin ventana), `LastPresentSampleWins` (muestra ligera final no desplaza CPU/memoria/red/módulos/sesiones/Salud TDM) y `DiskFreeThresholds_Configurable` (validación y acentos según umbrales). Paridad: 30/30.

### Sprint 2 — Inteligencia Causal y Simulación What-If

#### S2.1 — Grafo Causal Temporal (`TemporalCausalGraph.cs`)
- **Correlación con retardo temporal**: Ventanas deslizantes configurables para detectar precedencia temporal entre métricas (CPU, memoria, red, disco, procesos, TSplus).
- **Prueba de causalidad de Granger**: Implementación simplificada de F-test para validar si una serie temporal mejora la predicción de otra (causalidad predictiva vs. correlación espuria).
- **Detección de aristas causales**: Scoring de confianza (0-1) combinando significancia estadística, retardo óptimo y fuerza de predicción.
- **Búsqueda de caminos**: Rastreo de cadenas causales para localización de causa raíz (root cause tracing).

#### S2.2 — Propagación de Salud en Grafo de Dependencias (`DependencyHealthPropagator.cs`)
- **Estados de salud**: `Unknown`, `Healthy`, `Warning`, `Error`, `Critical` (enum `ServiceHealth`).
- **Grafo bidireccional**: Dependencias aguas arriba (upstream) y dependientes aguas abajo (downstream).
- **Propagación recursiva**: Con detección de ciclos (conjunto `visited`) y cooldown configurable para evitar flapping.
- **Reglas de propagación**:
  - Dependencia `Critical` → dependiente `Critical`
  - Dependencia `Error` → dependiente `Error`
  - Dependencia `Warning` → dependiente `Warning`
  - Todas `Healthy` → dependiente `Healthy`
- **API**: `UpdateHealth()`, `GetPropagationPath()`, `GetDependencies()`, `GetDependents()`, `GetNodes()`.

#### S2.3 — Motor Contrafactual (`CounterfactualEngine.cs`)
Simulador básico what-if para decisiones operativas seguras.

**Acciones soportadas**: `RestartService`, `StopService`, `StartService`, `KillProcess`, `RestartProcess`, `ClearCache`, `ResetConnection`, `RebootHost`.

**Tres modos de uso**:
1. **`Simulate(action, propagator)`** — Análisis de impacto de una acción única con propagación downstream/upstream.
2. **`SimulateScenario(actions, propagator)`** — Planificación multi-paso con actualización de estado simulado entre pasos.
3. **`FindRemediationActions(degradedService, propagator)`** — Sugiere hasta 5 acciones seguras ordenadas por impacto (bajo → alto) para un servicio degradado.

**Salida (`SimulationResult`)**:
- `OverallImpact`: `None` | `Low` | `Medium` | `High` | `Critical`
- `AffectedServices`: Lista de `ServiceImpact` (servicio, salud actual → simulada, razón, recuperación estimada)
- `IsSafe`: `true` si impacto ≤ Medium y sin advertencias
- `Summary`: Resumen legible para operadores

**Integración UI**: Panel "Simulador de Remediación" en Configuración → Administración, con selector de servicio objetivo, acción (combo), botones "Simular" y "Buscar mejor acción", y detalle de impacto por servicio con iconos de razonamiento (🎯 directo, ⬇ downstream, ⬆ upstream).

---

### FIX93 — Precisión diagnóstica empresarial

- `EventTime` queda separado de `IngestedAt`; evidencia sin fecha no puede convertirse en incidente funcional ni causa temporal.
- Correlación Windows ↔ TSplus más conservadora: exige identidad técnica y ventanas temporales acotadas.
- Cursor durable/replay para Event Viewer y logs TSplus; pérdida de persistencia degrada cobertura.
- Parser TSplus multilinea, continuidad de stack trace y manejo seguro de límites de caracteres UTF-8/UTF-16.
- Fechas `dd/MM` vs `MM/dd` se resuelven sólo si la ventana de investigación hace inequívoca una interpretación.
- Servicios manuales/trigger-start y productos complementarios no se convierten automáticamente en fallas.
- Puertos Web/HTML5 se validan con PID/proceso propietario; incertidumbre = `NO EVALUADO`.
- Identidad de usuario exacta; se evitan coincidencias por substring.
- `IncidentLedger` con serialización entre procesos y endurecimiento de estado/SMTP/sanitización.
- Alertas visibles con títulos explícitos (por ejemplo, `TDM · Alerta de memoria libre en descenso`) y sin notificaciones de recuperación.
- Nueva suite `TDM.ProductionTests` y gate de restore reproducible con `packages.lock.json` + `--locked-mode`.

---

### FIX92 — Configuración de memoria en porcentaje
- `Memoria de TDM` se configura directamente en porcentaje, con valores predeterminados de 5% para advertencia y 10% para crítico.
- La gráfica Salud TDM consume los porcentajes configurados sin conversiones intermedias.
- Se elimina el bloque superior de estado, origen, ruta y recarga de configuración.
- El encabezado `CONFIGURACIÓN Y ESTADO` cambia a `CONFIGURACIÓN`.

---

### FIX91 — Umbrales de Salud TDM y textos preventivos en español
- La serie `Memoria TDM` de la gráfica CPU y memoria pasa a mostrarse como `Memoria`.
- La gráfica incorpora umbrales independientes de advertencia y crítico para CPU y memoria de TDM.
- Los umbrales configurados de memoria, almacenados en MB, se convierten a porcentaje usando la memoria física detectada.
- Los estados visibles `Stopped`, `Running`, `Failed`, `Unknown`, `Paused` y `Pending` se presentan en español dentro de Preventivo.
- Los nombres funcionales visibles se normalizan como `Acceso remoto/RDP`, `Sesiones/inicio de sesión` y `Granja/Puerta de enlace`.
- Los textos saludables eliminan los espacios alrededor de la diagonal: `SALUDABLE/SIN FALLA OBSERVADA` y `SIN FALLA OBSERVADA/COBERTURA LOCAL`.

---

### FIX88 — Interfaz operativa diseñada para TDM
- Se sustituye el patrón visual de tarjetas genéricas por franjas métricas, divisores y áreas de trabajo abiertas.
- Centro de soporte reorganiza servicios, módulos TSplus, sesiones e incidentes según su función.
- Rendimiento y Salud TDM integran las gráficas directamente en el espacio de trabajo.
- Las retículas y bandas de umbral de las seis gráficas reducen su intensidad para dar prioridad a los datos.

---

### FIX86 — Cronómetro acumulativo y exportación visible
- Pausar conserva el tiempo transcurrido y ejecutar reanuda desde ese punto; iniciar ya no sustituye el tiempo acumulado.
- Únicamente el botón de actualizar reinicia el cronómetro a `00:00:00`.
- Descargar reporte abre un selector de carpeta, genera los archivos HTML y JSON, comprueba que ambos existan y no estén vacíos, muestra la ruta guardada y revela el HTML en el Explorador.

---

### FIX81 — Nueva identidad visual TDM
- Se reemplaza el logotipo anterior por el diseño de diagnóstico basado en documento, telemetría y lupa con las letras `TDM`.
- El fondo del recurso es transparente y los trazos usan blanco, cian y verde eléctrico.
- La cabecera utiliza el PNG de 512 px y los ejecutables comparten un ICO multirresolución de 16 a 256 px.

---

### Sprint 1 — Detección de Anomalías y Logs Estructurados

#### S1.1 — Streaming Anomaly Detector (EWMA)
- Detección de anomalías en tiempo real sobre métricas clave: CPU, memoria, red, TCP, disco, procesos, TSplus.
- Algoritmo EWMA (Exponentially Weighted Moving Average) con umbrales adaptativos Z-score.

#### S1.2 — TSplus Structured Sidecar (JSONL + schema v1)
- Writer de logs estructurados en formato JSONL con schema versionado.
- Factory y registro de schema para validación.

#### S1.3 — Parser Registry versionado + Schema Registry
- Registro de parsers con versionado semántico.
- Hot-reload de esquemas sin reinicio.
- Validación JSON Schema integrada.

---

### FIX79 — TDM Portable y arranque rápido
- `TDM.exe` portable: no instala archivos, no registra servicios, no deja proceso de Setup abierto.
- Monitor local de 5 segundos y notificaciones visuales integrados en la misma aplicación.
- Primera captura diagnóstica en segundo plano (no bloquea apertura de ventana).
- ReadyToRun activado; edición portable evita compresión interna del bundle.
- Modo portable funciona mientras `TDM.exe` permanece abierto.

---

### FIX78 — Instalador EXE sin IExpress
- Proyecto de instalador .NET integra `payload.zip` y procedimiento como recursos internos.
- `dotnet publish` genera `dist\TDM-Setup-x64.exe` como archivo único autocontenido.
- Solicita privilegios de administrador mediante manifiesto.
- Fallos registrados en `%TEMP%\TDM-Setup.log`.

---

### FIX63–FIX77 — Mejoras acumulativas
- Servicios y dependencias ampliados (34 servicios objetivo Windows relevantes para TSplus/RDP).
- Readiness determinista del Notifier con probes independientes.
- Nombres visibles sanitizados (`TDM.Application.exe`, `TDM.Notifier.exe`).
- Identidades NuGet únicas y ensamblados sin colisión (`TDM.Application.Core.dll`).
- Notificaciones consolidadas por crash (`.NET Runtime`, `Application Error`, `WER`).
- Lectura visual mejorada (donas con verde para tramo correcto, amarillo/naranja/rojo solo para afectado).
- Arranque CMD compatible Windows (CRLF, sin `chcp 65001`).
- Publicación e instalador autocontenido con limpieza previa.

---

## [1.0.0-rc17] - 2026-09-XX

### Added
- Initial release candidate with core monitoring pipeline.
- Real-time monitoring → transitions → detection → grouping → correlation → ranking → root cause → impact → dependencies.
- Windows Events + TSplus logs collection.
- HTML/JSON report generation.
- Portable and installer distribution modes.

---

## Notes

- **Original ZIP preserved**: `TDM-v1.0-rc18.21.0-FIX93.zip` (SHA256: `63E56DE60F0511FA456AEBEE3BB4C752A3FA0FED34B8F09A94B7F65C90DB3413`) remains untouched.
- **Working copy**: All changes in `TDM-v1.0-rc18.21.0-FIX93-CLEAN-R8-P1-P2-COMPILEFIX/`.
- **VERIFY Gate**: 7 stages, 73 tests (26 parity + 47 production) — all passing.
- **Build**: 0 warnings, 0 errors (Release, warnings-as-errors).
- **Portable**: Self-contained, no .NET Runtime 8 required, runs on Windows 10/11 / Server 2019+ as Admin.