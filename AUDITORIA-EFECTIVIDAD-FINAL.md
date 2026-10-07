# Auditoría Senior de Efectividad — TDM v1.0-rc18.21 (post-Fase 28)

**Fecha**: 04-10-2026 · **HEAD base**: `70a4b74` (post Fase 28, gates en verde)
**Alcance**: pipeline completo — monitoreo real → transiciones → detección → agrupación → correlación → ranking → causa raíz → impacto → dependencias → eventos Windows → logs Windows/TSplus → configuración TSplus → consistencia del reporte, además de precisión de detección y presentación correcta de servicios/dependencias/procesos afectados.
**Método**: 6 agentes de exploración (uno por segmento) + verificación documental oficial (Microsoft/TSplus) + re-verificación empírica manual de todos los hallazgos CRITICAL/HIGH.
**Marcas de estado por hallazgo**: `ver.` = re-verificado leyendo el código en esta sesión; `ag.` = reportado por agente con `archivo:línea`, no re-verificado; **ABIERTO** = sin remediar.

**Restricción documental (requisito del cliente)**: toda recomendación se apoya sólo en documentación oficial de Microsoft y TSplus. Cada URL citada fue verificada en esta sesión (salvo indicación). Los IDs de evento sin documentación oficial se declaran explícitamente en §Brecha documental y **no** se usan como base de remediación.

**Recuento**: **5 CRITICAL · 12 HIGH · 22 MEDIUM · 17 LOW = 56 hallazgos** (**C1 en F29; C2, C3 y M-19 en F30; C4, C5 y L-08 en F31; H2, H3, H9, H11 y M-14 en F32** → 44 abiertos).

---

## Resumen ejecutivo

La arquitectura de TDM es sólida en su clase: dedup por RecordId, filtros temporales, tie-breaker `IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO`, calibración ±15 con veto de evidencia primaria, tensiones de consistencia, cobertura crítica con fuente ausente → "NO EVALUADO", guardas de carga (`ResourceLoadGuard`) y SafeWmi cerrado en Fase 28. **Pero no llega a ~100 % de efectividad por tres fallas estructurales**:

1. **La configuración del usuario no gobiernan la detección** (C1): los umbrales de `SupportMonitoringSettings` sólo mueven gráficos de la GUI; los hallazgos usan literales `95`, `5`, `10`.
2. **Los síntomas de recursos y la licencia TSplus nunca llegan al ranking** (C2, C3): TDM detecta disco lleno/memoria crítica y errores de licencia, pero el correlador no los convierte en candidatos de causa raíz.
3. **Fuentes que declaran cobertura sin entregar datos** (C4): el collector ETW RDP es no funcional en tres niveles distintos (drenaje, entrega de cobertura, API).

Además, el monitoreo 24/7 no tiene recuperación declarada (C5) y la ventana de observabilidad muestra `sesiones 0` / `No evaluado` en casi todas las muestras (H1). Con F29–F35 (§Plan) la herramienta cubre las brechas críticas y altas; MEDIUM/LOW en F35.

---

## Base documental oficial verificada

| # | Documento oficial | URL | Estado / uso |
|---|---|---|---|
| 1 | MS KB922918 — *A service does not start, events 7000 and 7011* (SCM espera `ServicesPipeTimeout` antes de registrar 7000/7011) | https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/service-not-start-events-7000-7011-time-out-error | ✅ verificada (esta sesión) — H9/C5 |
| 2 | MS KB839803 — 7000: timeout SCM por defecto 30 000 ms; `ServicesPipeTimeout` | https://learn.microsoft.com/en-us/troubleshoot/windows-client/system-management-components/windows-trace-session-manager-service-not-start-event-id-7000 | ✅ verificada — H9 |
| 3 | MS — *Sc failure* (acciones de recuperación: `restart/reboot/run`, `reset=`) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742019(v=ws.11) | ✅ verificada — C5/H11 |
| 4 | MS — *sc.exe config* (`start= delayed-auto`, `error=`) | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config | ✅ verificada — H11 |
| 5 | MS — *Sc failureflag* (disparar recuperación al stop por error) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc742011(v=ws.11) | ✅ verificada — C5 |
| 6 | MS — *Consuming Events* (XPath oficial `*[System[(Level <= 3)…]]`) | https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events | ✅ verificada — H3 |
| 7 | MS — *Defining Severity Levels* (`win:Warning` y amigos) | https://learn.microsoft.com/en-us/windows/win32/wes/defining-severity-levels | ✅ verificada — H3 |
| 8 | MS .NET — *EventLevel enum* (Critical=1, Error=2, Warning=3) | https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.tracing.eventlevel | ✅ verificada — H3 |
| 9 | MS — *Memory Performance Information* (contadores ↔ `MEMORYSTATUSEX`) | https://learn.microsoft.com/en-us/windows/win32/memory/memory-performance-information | ✅ verificada — H8 |
| 10 | MS — *Troubleshoot memory consumption* (contadores `Available MBytes`, `% Committed Bytes In Use`) | https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-consumption-between-identical-windows-server-environments | ✅ verificada — H8 |
| 11 | MS — *Performance Counters Reference* | https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-counters-reference | ✅ (búsqueda) — H8 |
| 12 | MS — evento 4624 (logon exitoso; LogonType 10 = RemoteInteractive) | https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624 | ✅ verificada — H9 |
| 13 | MS — evento 4740 (bloqueo de cuenta) | https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4740 | ✅ verificada — cobertura actual |
| 14 | MS — evento 4778 (reconexión de sesión Terminal Services) | https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4778 | ✅ verificada — H9 |
| 15 | MS — evento 4648 (logon con credenciales explícitas; enlazado desde 4624) | https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4648 | ✅ referenciada — H9 |
| 16 | MS — `Win32_Processor.LoadPercentage` (uint16) | https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-processor | ✅ (Fase 28) — C1/H8 |
| 17 | TSplus — *Advanced Features / Logs* (logs **deshabilitados por defecto**; 5 tipos y rutas; logs de setup en `%TEMP%`; modo Troubleshooting) | https://docs.tsplus.net/tsplus/advanced-features-logs | ✅ verificada — M-04/L-14 |
| 18 | TSplus — *Activating your license* (estado de licencia, problema de activación) | https://docs.tsplus.net/tsplus/activating-your-license | ✅ verificada — C3 |
| 19 | TSplus — *Rehosting your license* (`end of use date`, rehost cada 6 meses con soporte) | https://docs.tsplus.net/tsplus/rehosting-your-license | ✅ verificada — C3 |
| 20 | TSplus — *Web Credentials* (credenciales web e-mail/PIN) | https://docs.tsplus.net/tsplus/web-credentials | ✅ verificada — **no aplica a licencia** (nota en C3) |
| 21 | MS .NET — `Double.TryParse`, `Process.Modules`, `IOException`, `ServiceController.GetServices`, `Task` cancellation, *Standard date/time format strings*, *Design Guidelines: Exceptions* | (URLs verificadas en Fases 17–28, sesiones previas) | ✅ — cerrados en auditorías previas |
| 22 | MS — *Correct disk space problems on NTFS volumes* (chkdsk de solo lectura distingue datos/metadatos/cuotas; limpieza de disco) | https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/disk-space-problems-on-ntfs-volumes | ✅ verificada — C2 |
| 23 | MS — *Disk Cleanup* (`cleanmgr`, liberación de espacio en Windows Server) | https://learn.microsoft.com/en-us/windows-server/storage/file-server/disk-cleanup | ✅ verificada — C2 (remediación) |
| 24 | MS DSC — *RebootPending resource* (CBS, Windows Update, `PendingFileRenameOperations`, renombre de equipo) | https://learn.microsoft.com/en-us/powershell/dsc/reference/resources/microsoft/windows/rebootpending/ | ✅ verificada — M-19 |
| 25 | MS .NET — `EventListener` ("el objetivo de todos los eventos generados por implementaciones de `EventSource` en el dominio de aplicación actual") | https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.tracing.eventlistener | ✅ verificada — C4 |
| 26 | MS .NET — `EventLogWatcher` (suscripción a eventos entrantes del Event Log; `EventRecordWritten` por evento publicado) | https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogwatcher | ✅ verificada — C4 (sink real) |
| 27 | MS — *Bookmarking Events* (bookmark = posición exacta del último evento leído; reanudación de la lectura) | https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events | ✅ verificada (F32) — H2 |
| 28 | MS — *Querying for Events* (`EvtQueryReverseDirection`: leer de más reciente a más antiguo para obtener el punto de partida) | https://learn.microsoft.com/en-us/windows/win32/wes/querying-for-events | ✅ verificada (F32) — H2 |
| 29 | MS — evento 4732 (miembro añadido a grupo local; recomendación de monitoreo con `Level=0`) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732 | ✅ verificada (F32) — H9 |
| 30 | MS — evento 4771 (falla de preautenticación Kerberos) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771 | ✅ verificada (F32) — H9 |
| 31 | MS — evento 4776 (falla de credenciales NTLM) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776 | ✅ verificada (F32) — H9 |
| 32 | MS — evento 4779 (desconexión de sesión Terminal Services / Fast User Switching) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779 | ✅ verificada (F32) — H9 |
| 33 | MS KB2001093 — DNS 4013 (el servidor DNS espera la réplica inicial de AD; arranque demorado) | https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/troubleshoot-dns-event-id-4013 | ✅ verificada (F32) — H9 |
| 34 | MS KB969488 — DNS 4015 (el servidor DNS encontró un error crítico) | https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/event-4015-dns-server-encounters-critical-error | ✅ verificada (F32) — H9 |
| 35 | MS — Kernel-Power 41 (el sistema se reinició sin apagado limpio; `Level: Critical`) | https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart | ✅ verificada (F32) — H9 |
| 36 | MS — evento 7022 (servicio NSI colgado al iniciar, SCM) | https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/azure-vm-nsi-not-starting | ✅ verificada (F32) — H9 |
| 37 | MS KB2702157 — evento 7036 (transición de estado de servicio, `Level: Information`) | https://learn.microsoft.com/en-us/troubleshoot/system-center/orchestrator/runbook-service-stops | ✅ verificada (F32) — H11 |
| 38 | MS KB933757 — eventos 7000/7026 (driver de dispositivo habilitado sin hardware presente) | https://learn.microsoft.com/en-us/troubleshoot/windows-client/setup-upgrade-and-drivers/system-log-event-id-7000-7026 | ✅ verificada (F32) — H9 (sólo contexto; §Brecha) |
| 39 | MS — *Service Trigger Events* (arranque por disparo; `SERVICE_TRIGGER_INFO`) | https://learn.microsoft.com/en-us/windows/win32/services/service-trigger-events | ✅ verificada (F32) — H11 |
| 40 | MS — `SERVICE_DELAYED_AUTO_START_INFO` (nivel 3 de `QueryServiceConfig2`) | https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_delayed_auto_start_info | ✅ verificada (F32) — H11 |
| 41 | MS — `QueryServiceConfig2A` (`dwInfoLevel` 1–4 y 8) | https://learn.microsoft.com/en-us/windows/desktop/api/Winsvc/nf-winsvc-queryserviceconfig2a | ✅ verificada (F32) — H11 |

---

## CRITICAL (5)

### C1 — Los umbrales configurados por el usuario no gobiernan la detección · CERRADO (Fase 29)

- **Evidencia** (`ver.`): `SystemResourceCollector.cs:86,98` memoria con literales `freePct <= 5 / <= 10`; `:130` CPU `average >= 95`; `:172,184` disco `freePct <= 5 / <= 10`; `ResourceLoadGuard.cs:55,61` `>= 85` / `< 70`. La configuración `SupportMonitoringSettings.cs:7-18` (`CpuWarning=70`, `MemoryUsedWarning=80`, `DiskFreeWarningPercent=10`, `DiskFreeCriticalPercent=5`, `SessionWarning=80`, `TdmCpuWarning=3`) sólo se consume en dashboards de GUI (`PerformanceDashboardViewModel.cs:41-44`, `GeneralDashboardViewModel.cs:36`, `PreventiveDashboardViewModel.cs:50-52`) — nunca llega a los detectores.
- **Impacto**: el operador fija un umbral en Administración y cree haber endurecido la alerta; la detección sigue con valores duros distintos (p.ej. CPU 95 % vs 70 % configurado). Umbral "configurado pero no aplicado" es un fallo silencioso de efectividad.
- **Doc oficial**: MS `Win32_Processor.LoadPercentage` (doc 16) valida la *captura* (promedio último segundo), no los umbrales; los umbrales son contrato interno TDM y deben respetar la configuración.
- **Fix (F29)**: inyectar los thresholds en los detectores y reemplazar todos los literales; añadir *gate de configuración* (test que falle si un `*Warning/*Critical` de settings no tiene consumidor detector). → **corregido en Fase 29** (`e434104`: contrato `ResourceDetectionThresholds` en TDM.Models + `SupportThresholds.ToDetectionThresholds()` como único punto de traducción en TDM.Persistence, inyección vía `DiagnosticContext.ResourceThresholds` en los 6 puntos de construcción, evaluadores puros `EvaluateCpuSeverity`/`EvaluateMemorySeverity`/`EvaluateDiskSeverity` con mensajes que citan el umbral configurado, nuevo hallazgo `RESOURCE-CPU-CRITICAL` para consumir `CpuCritical`, `ResourceLoadGuard` paramétrico (idéntico por defecto: 85/70 CPU, 10/20 % libre); tests `DetectionHonorsConfiguredThresholds` + `ConfiguredResourceThresholdsAreWiredIntoDetection` (mapeo de los 6 keys + gate estático de literales/inyección), gates 192/192 · 47/47 · 7/7 · publish 139082951)

### C2 — Disco lleno / saturación de memoria jamás pueden ser causa raíz · CERRADO (Fase 30)

- **Evidencia**: `SystemResourceCollector.cs:175,187,89` genera `RESOURCE-DISK-CRITICAL-*`, `RESOURCE-DISK-WARNING-*`, `RESOURCE-MEMORY-CRITICAL` (severidad Crítico/Advertencia); `TdmWorker.cs:566-568` sólo los ve como señal; grep en `src\TDM.Correlation` no encuentra ningún candidato con prefijo `RESOURCE-` (sólo mención en `DiagnosticPrecisionAnalyzer.cs:225`). (`ag.` + `ver. parcial`)
- **Impacto**: si el disco lleno causó el incidente (logs, temporales, actualizaciones TSplus), TDM lo **detecta pero nunca lo rankea** → causa raíz ausente pese a evidencia confirmada. Rompe el pipeline detección → correlación → ranking para el síntoma más común de servidores.
- **Doc oficial**: coherente con el texto del propio hallazgo («puede afectar logs, temporales, actualizaciones») y con MS doc 10 (contadores de memoria) como fuente de medición.
- **Fix (F30)**: reglas `AddResourceExhaustionCandidates` con umbral configurado, ventana temporal y exigencia de evidencia acompañante (consistente con el diseño conservador actual). → **corregido en Fase 30** (`2da0be6`: `RootCauseCorrelator.Rules.Resources.cs` — cada hallazgo Critico `RESOURCE-DISK-CRITICAL-*`/`RESOURCE-MEMORY-CRITICAL` genera candidato (ids `ROOT-RESOURCE-DISK-EXHAUSTION-{letra}`/`ROOT-RESOURCE-MEMORY-EXHAUSTION`); elevación a 93/Alta con `IncidentTime` sólo con señal funcional independiente (`IsCausalSignal` + ventana + ≤15 min del fin), sin ella 76/Media; evidencia `Umbral crítico configurado` añadida por el collector; KB `MS-DISK-SPACE`/`MS-LOW-MEMORY` (docs 22–23 + doc 10); tests `ResourceExhaustionFindingsReachRootCauseRanking` + `ResourceExhaustionCandidateNeedsRecentWindowedSymptom`, gates 196/196 · 47/47 · 7/7 · publish 139107527)

### C3 — Licencia TSplus excluida del pool causal de correlación · CERRADO (Fase 30)

- **Evidencia** (`ver.`): `RootCauseCorrelator.cs:33` `.Where(e => e.Tipo != "LICENSE")` filtra la entrada `tsplusErrors` que alimenta la mayoría de reglas TSplus; pero `TsplusLogParser.cs:118` y `TsplusStructuredLogSidecar.cs:266` sí clasifican eventos como `LICENSE`, y `TsplusGuidedTroubleshooter.cs:432,440` sí los usa → inconsistencia interna (el guiado habla de licencia, el ranking nunca).
- **Impacto**: expiración/estado de licencia TSplus como causa de caída de sesión web nunca aparece en `CausasRaiz`.
- **Doc oficial**: TSplus docs 18 y 19 (estado de licencia y `end of use date` son condiciones operativas documentadas). **Nota**: el doc 20 (`web-credentials`) trata credenciales web e-mail/PIN y **no** respalda este hallazgo; se retiró como citación (auditorías previas la usaron indebidamente).
- **Fix (F30)**: candidato `LICENSE` conservador (sólo con temporalidad + severidad Error/Crítico), sin bajar el listón de evidencia primaria. → **corregido en Fase 30** (`2da0be6`: `RootCauseCorrelator.Rules.License.cs` — `AddLicenseCandidates` lee `report.Eventos` `Tipo == "LICENSE"` fechados dentro de la ventana con severidad Error/Crítico y emite `ROOT-TSPLUS-LICENSE` a 76/Media con `HoraIncidente` del evento más reciente; KB `TSPLUS-LICENSE` (docs 18–19); el filtro `Tipo != "LICENSE"` del pool `tsplusErrors` se conserva intacto; test `LicenseErrorNeedsTimestampedSeverityInWindow`)

### C4 — Collector ETW RDP no funcional y cobertura declarada sin entregar · CERRADO (Fase 31)

- **Evidencia** (`ver.`): `RdpEtwCollector.cs`
  1. **Sin drenaje**: `CollectAsync` crea listas locales (`:28-29`) y las devuelve vacías en `:40,53,93`; el listener recibe los campos `_events/_findings` (`:65`) que jamás se leen.
  2. **Cobertura no entregable**: la lista `coverage` (`:30,39,52,56,78-80,90`) no se retorna nunca — `CollectorResult` sólo tiene `Hallazgos` y `Eventos` (`DiagnosticModels.cs:226-231`).
  3. **API inadecuada**: `EventSource.GetSources()`/`EventListener` (`:67-76,136-143`) sólo observa `EventSource` .NET **en-proceso**; los proveedores ETW nativos nombrados (`Microsoft-Windows-TerminalServices-*`) no pueden aparecer jamás → cero captura posible.
- **Impacto**: característica "P2-01 ETW sub-segundo" declarada en GUI/servicio sin producir ni un evento, y sin forma de saberlo (cobertura descartada). Confianza artificial en cobertura de transiciones RDP.
- **Fix (F31)**: o reescritura con sink válido (lector `EventLogWatcher`/suscripción con drenaje real + campo de cobertura entregable), o desactivación explícita con estado "No soportado" en cobertura. Preferente: eliminar el claim hasta tener sink correcto. → **corregido en Fase 31** (`a830356`: retirada del claim — se eliminan `RdpEtwCollector.cs`, su registro en `CollectorCatalog` y la opción `EnableRdpEtw` en los 4 puntos de construcción; la cobertura de transiciones RDP queda sólo en fuentes reales con evidencia entregable por corrida — `WINDOWS_PUSH_EVENT_COVERAGE` de `WindowsPushEventCollector`, sink `EventLogWatcher` sobre los 3 canales Operational (docs 25–26), más `RdpEventCollector` por lote e incremental/forense; tests `PhantomRdpEtwCollectorRetiredAndRealSinkDeclaresCoverage` + `RunScopeDisposesDisposableCollectors` (renombrado desde `RdpEtwCollectorIsDisposableAndRunScopedDisposed`), gates 198/198 · 47/47 · 7/7 · publish 139091143)

### C5 — Monitoreo 24/7 sin recuperación ni watchdog declarados · CERRADO (Fase 31)

- **Evidencia** (`ag.`): no hay `sc failure`/`sc failureflag` en el instalador ni watchdog/watchdog-heartbeat; el propio servicio TDM puede caerse sin acción de recuperación ni alerta STALLED.
- **Doc oficial**: docs 3 (`sc failure`: `restart/5000`…), 5 (`sc failureflag`), 4 (`error=` en arranque).
- **Fix (F31/F33)**: declarar `sc failure` + `failureflag=1` para servicios TDM/TSplus monitorizados, heartbeat con estado STALLED, y documentar en informe la ausencia de recuperación. → **corregido en Fase 31** (`a830356`: `Install-TDM.cmd` declara `sc.exe failure TDM.Service reset= 86400 actions= restart/5000/restart/15000/restart/60000` + `sc.exe failureflag TDM.Service 1` (docs 3 y 5, re-verificadas; fallo de instalación si SCM los rechaza) — sólo para `TDM.Service`, que es el servicio del que TDM es propietario: Windows/TSplus conservan su propia recuperación; `ServiceHeartbeatStore.DescribeStatus`/`StalledFinding` convierten un latido >150 s en el hallazgo `TDM-SERVICE-HEARTBEAT-STALLED` (Advertencia con edad/umbral/PID y remedio `sc qfailure` citando doc 3) que el diagnóstico GUI añade al informe, y `TelemetryReadService` muestra `TDM.Service · STALLED` en la fuente; el watchdog externo ya existía como script de repositorio (`Register-TdmWatchdog.ps1`, fuera del paquete instalado); test `ServiceRecoveryIsDeclaredAndStalledHeartbeatSurfaces`)

---

## HIGH (12)

| ID | Hallazgo | Evidencia | Doc oficial | Fix |
|---|---|---|---|---|
| H1 | **Sesiones=0 / "No evaluado" en casi todas las muestras**: sin evento `USER_SESSION_INVENTORY`, `ActiveSessions` cae a `0` (dato falso, no "desconocido") y cobertura a `No evaluado`; el inventario sólo sale en ciclos heavy/full, pero el pipeline realtime y la GUI muestran el 0 como cifra | `ObservabilityStore.cs:246-255` (`ver.`); `SupportDashboardViewModel.cs:170,316`; `CollectorCatalog.cs:42,118,148` | — | F33: inventario en ciclo ligero o `ActiveSessions=null` cuando no hay dato |
| H2 | **Push con query `"*"` sin filtro temporal/RecordId**: escaneo completo del canal cada ciclo; sin cursor no hay contabilidad de pérdida | `WindowsPushEventCollector.cs:81` (`ver.` query; `ag.` drops/FALLBACK) | docs 27–28 (bookmark y lectura inversa) | F32: filtro `EventRecordID > cursor` + drops contabilizados → **corregido en Fase 32** (`50c8173`: `ReadLatestRecordId` con lectura inversa siembra `*[System[(EventRecordID > N)]]` antes de `watcher.Enabled`, cobertura `Suscripción activa desde RecordId N`, huecos de RecordId y descartes del ring en mensaje y evidencia de `WINDOWS_PUSH_EVENT_COVERAGE`, `StopWatchers` limpia cursor y contadores; test `Phase32PushCursorAccountsDropsAndRecordIdGaps`) |
| H3 | **Nivel 3 (Warning) excluido** en base e incremental de System/Application, mientras el forense sí lo lee → cobertura inconsistente y pérdidas (p.ej. warnings de servicio) | `WindowsEventCollector.cs:183` y `IncrementalWindowsEventCollector.cs:48` (`Level=1 or Level=2`) vs `WindowsForensicEventCollector.cs:52` (`Level=1 or 2 or 3`) (`ver.`) | docs 6–8 (`Level <= 3` XPath oficial; Warning=3) | F32: `Level <= 3` en base+incremental → **corregido en Fase 32** (`50c8173`: base no-Security e incremental Application/LocalSessionManager/RemoteConnectionManager/RdpCoreTS pasan a `Level=1 or Level=2 or Level=3` — System se mantiene por EventID; test `Phase32EventQueriesCarryWarningAndHighValueIds`) |
| H4 | **Take(12) ocurre ANTES de calibrar**: el correlador corta a 12 y luego `Calibrate`/historial verificado opera sólo sobre esos 12; un candidato real en el puesto 13 jamás recibe ajuste | `RootCauseCorrelator.cs:82` → `DiagnosticWorkflow.cs:25,33` (`ver.`) | — | F34: mover recorte a post-calibración (o ampliar pool) |
| H5 | **~30 de ~39 candidatos sin guía oficial**: `ToCandidate` sólo adjunta URL si `GuidanceId != null`; KB TSplus/MS existentes quedan sin usar → causa mostrada sin fuente oficial | `RootCauseCorrelator.cs:428-441` (`ag.`) | docs 1, 17–19 (KBs y guías TSplus disponibles) | F33: mapear GuidanceId en top candidatos |
| H6 | **Dependencias**: tabla filtrada por ~16 marcadores de texto silencia dependientes de terceros; profundidad no visible en reporte → no se "muestran correctamente las dependencias" | `ServiceDependencyGraphCollector.cs` filtro (`ag.`); evidencia `Profundidad` existe en `:283` (`ver.` parcial) | MS `sc enumdepend` (doc. sc, referencia oficial de dependencias) | F34: mostrar terceros + profundidad en informe |
| H7 | **Servicio (modo continuo) no colecta Schannel, cambios ni dependencias** — esos collectors sólo corren en GUI/CLI | `TdmWorker.cs:171,419,680` vs `DiagnosticExecutionService.cs:71` (`ag.`) | — | F33: alinear sets de collectors GUI vs servicio |
| H8 | **Sin contadores de rendimiento MS y métricas reales sólo en ciclo heavy**: falta `Available MBytes`, `% Committed Bytes In Use`, CPU % dedicado con histéresis de ventana | `SystemResourceCollector.cs:115-128` WMI-only (`ver. parcial`); `ag.` ciclos | docs 9–11 | F33: colector de contadores MS en ciclo normal |
| H9 | **IDs de alto valor ausentes**: 7022/7026 (cadena de arranque), 4648, 4778/4779 (reconexión de sesión), 4732, W32Time 1/36/37, DNS 4013/4015 — ninguna query los incluye | `IncrementalWindowsEventCollector.cs:47-66`, `WindowsLogonHealthCollector.cs:33` (`ver.` ausencia; `ag.` detalle) | docs 12–15, 29–36, 38 (4648/4732/4771/4776/4778/4779, DNS 4013/4015, Kernel-Power 41, 7022, 7026); W32Time → §Brecha | F32: añadir IDs con doc oficial primero → **corregido en Fase 32** (`50c8173`: 4648/4732/4778/4779 en base+incremental+`IsRelevant`+`WindowsLogonHealthCollector` con evidencia propia — `EXPLICIT_CREDENTIAL_LOGON`/`LOCAL_GROUP_MEMBERSHIP_CHANGE` elevan a Advertencia, `SESSION_RECONNECTION`/`SESSION_DISCONNECTION` Informativo vía `HasDedicatedSecurityEvidence` —, 7022 en System incremental, canal `DNS Server` 4013/4015 con `OptionalRole` ("No aplica; canal de rol no instalado" sin evento de pérdida); W32Time 1/36/37 queda en §Brecha; test `Phase32EventQueriesCarryWarningAndHighValueIds`) |
| H10 | **Detección de desfase de reloj sin productor** (rama `WINDOWS_TIME_SYNC_FAILURE` declarada, ningún colector la emite) + `TimeCreated` re-evaluado al leer → timestamps inventados si el reloj corre | rama dead (`ag.`) | MS doc de niveles/tiempo (doc 6; fecha ISO: docs previas `standard-date-and-time-format-strings`) | F35: productor W32Time o eliminar rama |
| H11 | **Avisos SCM incompletos**: sin 7036 (transición de servicio), auto-start retrasado no leído, rama "Trigger" muerta, sin lectura de `failure`/recovery de servicios | `ag.` (M5) | docs 3–5, 37, 39–41 (`sc failure`, `sc.exe config`, `sc failureflag`, 7036, trigger events, delayed-auto, `QueryServiceConfig2`) | F32/F33 → **corregido en Fase 32** (`50c8173`: 7036 como `SERVICE_STATE_TRANSITION` sólo incremental con evidencia Servicio/Estado, `ReadStartMode` con niveles 3/8 de `QueryServiceConfig2W` → `Automático (retrasado)`/`Trigger` con consumidor único `IsAutoStart` (×4 sitios, `ShouldWarnWhenStopped` incluido), rama Trigger viva en presentadores, `ReadRecovery` niveles 2+4 → evidencia `Recuperación` vía `FormatRecoveryActions`; test `Phase32ServiceStartModesAndRecoveryReadScm`) |
| H12 | **El analizador de cobertura no penaliza `WINDOWS_EVENT_COVERAGE`/push caído** → cobertura global sobreestimada | `DiagnosticCoverageAnalyzer.cs` (`ag.`) | — | F34 |

---

## MEDIUM (22) — ABIERTOS

| ID | Hallazgo | Evidencia | Estado |
|---|---|---|---|
| M-01 | Recuento de drift de configuración capado a 24: `.Take(8)` corre **antes** de contar (`added/removed/changed`) y se presenta como total | `TsplusConfigurationDriftCollector.cs:110-117` (+`147`) | `ver.` |
| M-02 | Estado ejecutivo "SALUDABLE" con hallazgos Error cuando `ImpactoFuncional=SinImpactoObservado`; el chequeo `Hallazgos.Any(Error)` (`:1158`) sólo aplica si el impacto es null; la tensión `ReportConsistencyAnalyzer.cs:17-19` avisa pero no cambia el titular | `ReportExporter.cs:1146-1159` | `ver.` (con matiz) |
| M-03 | Ítems de revisión truncados sin contador ("mostrar N más") en servicios/dependencias/procesos | reporting/GUI (`ag.`) | `ag.` |
| M-04 | Logs TSplus esperados-faltantes no operacionalizados (`TSPLUS_LOGS_NOT_ENABLED` ausente): según doc oficial 17 los logs están **deshabilitados por defecto** y requieren AdminTool > Advanced > Logs + `C:\wsession\Trace` — el informe debe distinguir "deshabilitado (default)" de "roto" | doc 17; `TsplusLogDiscovery` (`ag.`) | `ag.` + doc ✅ |
| M-05 | `ReportConsistencyAnalyzer` sin cruce recuento-vs-export de hallazgos/eventos | `src\TDM.Correlation\ReportConsistencyAnalyzer.cs` (`ag.`) | `ag.` |
| M-06 | "No evaluado" comparte bucket de scoring con "Advertencia" (penaliza/ensucia rankings y semántica) | `DashboardSupport.cs:138,144`, `ReportExporter.cs:1307`, `ServicesDashboardViewModel.cs:64-97` | `ver.` parcial |
| M-07 | Reglas longitudinales ignoran la ventana de análisis | correlador longitudinal (`ag.`) | `ag.` |
| M-08 | Merge de identidad fusiona usuarios distintos que comparten host/IP | `RootCauseCorrelator` identidad (`ag.`) | `ag.` |
| M-09 | La tensión `TDM-CAUSE-UNSTABLE` se pierde en el camino del servicio (se recalcula sin el contexto GUI) | workflow vs servicio (`ag.`) | `ag.` |
| M-10 | Sin detección de límite de sesiones (`MaxInstanceCount` RDP) — desconexiones por tope parecen falla aleatoria | (`ag.`) | `ag.` |
| M-11 | Heurísticas de substrings blandos (`MissionServiceMarkers`) → FP potencial | (`ag.`) | `ag.` |
| M-12 | Igualdad de `Fuente` (exacta) vs `StartsWith` inconsistente entre módulos | (`ag.`) | `ag.` |
| M-13 | El mismo evento Windows llega con 4 identidades distintas (fuente/canal/RecordId) sin colapso → duplicidad en agrupación | (`ag.`) | `ag.` |
| M-14 | Trim (`Take`) **antes** de dedup consume el presupuesto de eventos con duplicados | (`ag.`) | **CERRADO (F32, `50c8173`)**: `IdentityIncidentPromoter.Promote` + `Deduplicate` se ejecutan antes del trim en `DiagnosticEngine` (seguro: los cursores ya se persistieron en recolección), `rawEventCount` sigue midiendo el crudo y `strictEvents` opera sobre la lista saneada; test `Phase32DedupPrecedesVolumeTrim` |
| M-15 | Política de auditoría "desconocida" reportada como sana | (`ag.`) | `ag.` |
| M-16 | Canary escribe eventos pese al mandato read-only de diagnóstico | (`ag.`) | `ag.` |
| M-17 | Identidad de evento rota en colectores secundarios (mismos campos distintos) | (`ag.`) | `ag.` |
| M-18 | Evidencia de impacto se **crea** (`"Causa del paro demostrada": No`, `"Alcance potencial (sesiones observadas)"`) pero su render en informe/GUI no está garantizado — verificar presencia en export | creación: `RootCauseCorrelator.cs:140`, `FunctionalImpactAnalyzer.cs:370-371` (`ver.`); render: pendiente | `ver.`/pendiente |
| M-19 | *Pending reboot* nunca compite como causa raíz (condición temporal documentable) | (`ag.`) | **CERRADO (F30, `2da0be6`)**: `ROOT-WINDOWS-PENDING-REBOOT` en `Rules.WindowsFarm.cs` — 72/Media sin síntoma, 88/Alta con síntoma de sesión en ventana; KB `MS-REBOOT-PENDING` (doc 24); test `PendingRebootCandidateScalesWithSessionSymptom` |
| M-20 | Hallazgos `TSPLUS-PROCESS-MODULE-MISSING` sin consumidor → procesos afectados no mostrados | (`ag.`) | `ag.` |
| M-21 | Sin declaración de hueco cuando TDM estuvo caído (path servicio): la ventana se lee como "sin novedad" | (`ag.`) | `ag.` |
| M-22 | `TimeCreated` re-evaluado al leer (offset vs escritura) y deriva federada midiendo retardo del escritor, no del host | (`ag.`) | `ag.` |

## LOW / LATENT (17) — ABIERTOS

| ID | Hallazgo | Evidencia |
|---|---|---|
| L-01 | Retención declarada vs efectiva de datos | (`ag.`) |
| L-02 | `AnomalyDetectionService` sin consumidor real | `src\TDM.Core\AnomalyDetectionService.cs` (`ag.`) |
| L-03 | Clusters de incidentes no alimentan correlación (sólo presentación) — contrato a declarar | `IncidentClusterAnalyzer` (`ag.`) |
| L-04 | Patrones de falla calculados sólo para crashes | `FailurePatternAnalyzer` (`ag.`) |
| L-05 | `DriftProximityMatcher` con cultura actual (F28 ya demostró el riesgo es-ES) | (`ag.`) |
| L-06 | Encadenamiento de clusters sin límite | `IncidentClusterAnalyzer` (`ag.`) |
| L-07 | `@SystemTime` con `+00:00` vs `Z` en escrituras | (`ag.`) |
| L-08 | Severidad ETW fija Informativo sin mapeo | `RdpEtwCollector.cs:154` (`ver.`); **corregido en Fase 31** (`a830356`: el código vivía en el collector retirado por C4) |
| L-09 | Formatos de log pequeños no evaluados por el detector de formato | `TsplusLogDiscovery` (`ag.`) |
| L-10 | Método muerto `RefreshCoverage` en GUI | (`ag.`) |
| L-11 | Sidecar de logs estructurado sin cablear en pipeline | `TsplusStructuredLogSidecar` (`ag.`) |
| L-12 | Hallazgos citan eventos que el trim posterior descartó | (`ag.`) |
| L-13 | INI TSplus sin auditoría de contenido (sólo hash) | `TsplusConfigurationDriftCollector` (`ag.`) |
| L-14 | Logs de setup TSplus en `%TEMP%` no descubiertos — **el doc oficial 17 los documenta** (`Setup TSplus Remote Access.txt`, `Setup Log YYYY-MM-DD #XXX.txt`) | doc 17 ✅ |
| L-15 | API async falsa (síncrona envuelta en Task) | (`ag.`) |
| L-16 | `src\TDM.Reporting\ReportExporter.cs.bak` versionado en fuente | `ReportExporter.cs.bak` (`ver.`) |
| L-17 | Certificado RDP caducado sin candidato de causa (baja frecuencia) | (`ag.`) |

---

## Lo que ya funciona bien (no tocar)

- Dedup y claves de identidad de eventos (`EVT|Canal|Fuente|Codigo|RecordId`) con RecordId como ancla — `WindowsEventCollector.cs:95-112` (`ver.`).
- Cursors incrementales por RecordId con persistencia y contabilidad de rango `primero..último` — `IncrementalWindowsEventCollector.cs:244,710-719` (`ver.`).
- Ventana temporal con auto-ampliación y motivos declarados; `DiagnosticTimeWindow.IsEventInside` aplicado en reglas — `RootCauseCorrelator.cs:99,208` (`ver.`).
- Tie-breaker y penalización del rol `IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO` con comentario de diseño — `RootCauseCorrelator.cs:68-84` (`ver.`).
- Calibración con guardarraíles (±15, veto de evidencia primaria) aplicada **sobre la lista completa antes del Take(8)** — `DiagnosticWorkflow.cs:26-33` (`ver.`).
- Elegibilidad de causa principal conservadora (Media/Baja sin evidencia independiente → hipótesis) — `DiagnosticWorkflow.cs:39-52,75-81` (`ver.`).
- Tensiones de consistencia en el propio informe — `ReportConsistencyAnalyzer.cs:17-19,39` (`ver.`).
- Gate de cobertura: fuente crítica ausente → "NO EVALUADO" en estado ejecutivo — `ReportExporter.cs:1143-1159` (`ver.`).
- Guardas de carga (`ResourceLoadGuard` 85/70) y collectors ligeros para ciclo realtime.
- SafeWmi con tipos estrechos + parseo invariante (Fase 28) — `SafeWmi.cs` (`ver.`).
- Prevención de ruido: fallbacks de settings validados y restaurados a defaults (`SupportMonitoringSettings.cs:143-160`) (`ver.`).

---

## Brecha documental oficial (requisito del cliente)

- **Sin documentación oficial de Microsoft** (sólo Q&A/comunidad): **7031, 7034, 1149, 1002, 1026**. Ya se usan en queries actuales (`IncrementalWindowsEventCollector.cs:47`, `WindowsEventCollector.cs:207`, `WindowsForensicEventCollector.cs:229-230,260`, `CrashEventCollector.cs:22`). **Regla de remediación**: usarlos como *señal* está bien, pero **no** citarlos como base de recomendación en el informe; para recomendaciones citar sólo IDs con doc oficial (docs 1, 2, 12–15) o consultas por nivel (docs 6–7).
- **7026**: la referencia oficial (doc 38, `system-log-event-id-7000-7026`) se circunscribe a drivers → usar como contexto, no como prueba de dependencias. ✅ verificada (F32).
- **Pendientes de verificación**: **W32Time 1/36/37** — sin documentación oficial de Microsoft (sólo Q&A/comunidad) → no citarlos como base de remediación. Los demás pendientes de F32 (7022, 4771, 4776, 4732, Kernel-Power 41, DNS 4013/4015) fueron verificados y añadidos a §Base documental (docs 29–37).
- **TSplus**: docs 17–19 cubren logs, licencia y rehosting; para puertos/web-server (`hb.log`, `hb.exe.config`) falta verificar la página oficial correspondiente antes de citarla.

---

## Plan de remediación (Fases 29–35)

Gates obligatorios por fase (en orden): `dotnet build TDM.sln -c Release --no-restore -warnaserror` (0/0) → `TDM.ProductionTests` → `TDM.AvaloniaParityTests` (47/47) → `.\VERIFY-TDM-READINESS.cmd` (7/7) → `.\PUBLISH-PORTABLE-WIN-X64.cmd` → `git restore ":(glob)**/packages.lock.json"` + `dotnet restore TDM.sln --locked-mode`. Sin cambios a `.csproj`. Edit tool para editar. CHANGELOG bloque `### Fixed — Fase N` con URLs verificadas. Doble commit por fase (`Fix audit Phase N: …` / `Record audit Phase N …`) + anotación en este archivo `→ **corregido en Fase N** (\`hash\`: detalle)`.

| Fase | Hallazgos | Alcance |
|---|---|---|
| **F29** | C1 | Inyectar `SupportThresholds`/`SupportMonitoringSettings` en detectores; reemplazar literales en `SystemResourceCollector.cs` y `ResourceLoadGuard.cs`; test `DetectionHonorsConfiguredThresholds` + **gate de configuración** (todo `*Warning/*Critical` de settings con consumidor detector). |
| **F30** | C2, C3, M-19 | Candidatos `RESOURCE-DISK/MEMORY` con umbral configurado + evidencia temporal; candidato `LICENSE` conservador (doc 18–19); candidato *pending reboot*; tests de ranking. |
| **F31** | C4, C5 | ETW: sink con drenaje real + cobertura entregable **o** retirada del claim; `sc failure`/`failureflag` (docs 3, 5) + heartbeat STALLED en servicio; tests de contrato de cobertura. |
| **F32** | H2, H3, H9, H11 | `Level <= 3` en base+incremental (docs 6–8); IDs con doc oficial (7000/7001/7009/7011/7023/7024 + 4648/4778/4779/4624/4740…); push con cursor RecordId; trim tras dedup; 7036/`delayed-auto` (doc 4). |
| **F33** | H1, H5, H7, H8, M-04 | Inventario de sesiones en ciclo ligero (sin `0` falso); contadores MS (docs 9–11); alinear collectors GUI vs servicio; GuidanceId en top-3; estado de logs TSplus según doc 17 (default deshabilitado ≠ roto). |
| **F34** | H4, H6, H12, M-01, M-02, M-03, M-18, M-20 | Take(12) post-calibración; SALUDABLE con gate de Error findings; contadores de truncado en reporte; render de evidencia de impacto; dependencias terceros+profundidad; cobertura penaliza push/events caídos; drift sin cap de 24. |
| **F35** | HIGH restantes (H10) + 22 MEDIUM + 17 LOW + §Brecha | Productor de W32Time o eliminar rama; MEDIUM/LOW listados; verificación pendiente de URLs (§Brecha) y poda de `.bak`. |

**Criterio de cierre de la auditoría**: 56 hallazgos anotados `→ corregido en Fase N (hash)` con gates verdes en cada fase; entonces actualizar recuento a 0 abiertos (formato de auditorías previas).

## Estado

- **Hallazgos abiertos**: 44 (0 C · 8 H · 20 M · 16 L).
- **Cerrados**: 12 — C1 (F29, `e434104`), C2 · C3 · M-19 (F30, `2da0be6`), C4 · C5 · L-08 (F31, `a830356`), H2 · H3 · H9 · H11 · M-14 (F32, `50c8173`).
- **Remediación**: plan F29–F35 aprobado por el usuario; F29–F32 completadas con gates verdes; F33 (H1, H5, H7, H8, M-04) pendiente de inicio.
