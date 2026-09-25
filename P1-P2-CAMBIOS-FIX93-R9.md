# TDM FIX93 — P1/P2 R9 (profundidad pendiente del pipeline)

## Objetivo
Cubrir los P1/P2 del análisis de efectividad: detección que se auto-verifica,
pérdida contabilizada, drift que dice QUÉ cambió, impacto medido, dependencias
por proceso, formato desconocido por archivo y causa estable entre muestras.

## P1. Detección que se auto-verifica
- Nuevo `WindowsLogIntegrityCollector` (Full + heavy cada 10 min): marcas de
  manipulación 104/1100/1102 y apagados sucios 6008 con ventana = Lookback
  (`WINDOWS-LOG-CLEARED` Error/Alta, `WINDOWS-UNEXPECTED-SHUTDOWN` y
  `WINDOWS-EVENTSERVICE-STOP` Advertencia). Cumple el gate anti-Y1
  (`catch (EventLogException` literal).
- Canario extremo a extremo: escribe `TDM-SELFTEST-CANARY` en Application (una
  vez cada 10 min vía cursor, solo con privilegio) y lo lee de vuelta cada ciclo.
  Escrito-pero-no-legible → `TDM-CANARY-FAILURE` Advertencia/Alta. Sin escritura
  reciente no se declara nada (no evaluado, no sano).

## P1. Pérdida contabilizada
- `IncrementalWindowsEventCollector`: cada canal informa `rango=primero..último`
  RecordId leído (helper público `FormatChannelCoverage`, pineado). El backlog y
  los replays ya se declaraban Parcial; ahora además se ve la posición exacta.
- Sin cambios de comportamiento: solo evidencia adicional en cobertura.

## P1. Drift semántico + registro
- `TsplusConfigSemanticDiff` (puro, pineado): `ParseIniKeys` (secciones/claves,
  ignora comentarios y duplicados), `DiffIni` (+seccion/-seccion/+clave/-clave,
  orden determinista), `Summarize`, y `FingerprintValue` (huella SHA-256 de
  valores de registro sin exponer contenidos; `string[]` unidos, binarios
  capados, textos largos resumidos).
- `TsplusConfigurationDriftCollector`: lectura única por archivo (mismo buffer
  para hash y estructura, sin TOCTOU), baseline extendida con `IniStructure` y
  `Registry` (compatibles hacia atrás: una base antigua inicializa sin comparar).
  La evidencia de `TSPLUS-CONFIG-DRIFT` ahora dice QUÉ claves cambiaron.
- Snapshot de `HKLM\SOFTWARE\TSplus` (vistas 64/32, profundidad 4, tope 500
  valores): cambios → hallazgo separado `TSPLUS-CONFIG-DRIFT-REGISTRY`
  Advertencia/Media. Sin acceso → NO EVALUADO, nunca falla el collector.

## P1. Impacto medido
- Nuevo `WindowsLogonHealthCollector` (Full + heavy): cuenta 4624/4625/4634/4740
  en ventana, de lo más reciente hacia atrás con corte al salir de la ventana y
  techo de 5000. Regla pura pineada: oleada con ≥10 fallos Y tasa ≥20%
  (`WINDOWS-LOGON-FAILURE-SURGE`, Error si ≥50 fallos), bloqueos con ≥3
  (`WINDOWS-ACCOUNT-LOCKOUTS`). Volumen y tasa, nunca anécdotas.

## P2. Dependencias por proceso
- Nuevo `TsplusProcessDependencyCollector` (Full + heavy): inventaría módulos de
  procesos bajo la raíz TSplus (tope 32 procesos / 256 módulos, cada proceso
  aislado en try/catch). `TSPLUS-PROCESS-MODULE-MISSING` Error/Alta (predictivo
  de fallos de arranque) y `TSPLUS-PROCESS-MODULE-SUSPICIOUS` Advertencia/Media
  (cargas desde Temp/Downloads). Reglas puras en `TsplusProcessModulePolicy`,
  pineadas. Sin firmas (coste) por diseño documentado.

## P2. Formato desconocido por archivo
- `TsplusLogFormatDetector` (puro, pineado): por archivo, ≥200 líneas y >80% sin
  evento → `TSPLUS-LOG-UNKNOWN-FORMAT` Advertencia/Media (tope 5, ordenado por
  volumen ciego). Cableado en `TsplusLogCollector` con conteo por archivo.
  (Los cursores por archivo del incremental ya existían: verificación previa.)

## P2. Estabilidad de causa (anti-flapping)
- `CauseStabilityAnalyzer` (puro, pineado): ventana 6, mínimo 4 muestras no
  vacías, 3+ causas distintas → `TDM-CAUSE-UNSTABLE` Advertencia/Alta ("lea el
  top-3 como hipótesis competitivas"). Vacíos = sin causa, se ignoran.
- `TdmWorker` mantiene historial de 12 en cursor `primary-cause-history` y añade
  el hallazgo post-`Analyze` (fluye a observabilidad/ledger/dispatch sin tocar
  la selección de primaria). Solo servicio: el manual es esporádico y la ventana
  no tendría sentido. Nueva referencia Service→Correlation (dirección correcta).

## Registro en catálogos
- `CreateFull`: logon tras `RdpEventCollector`, integridad tras
  `WindowsEventCollector`, process-dep tras drift. `CreateServiceMonitor` heavy:
  los tres. Sin pins de catálogo en tests ni en VERIFY (solo Contains de un
  collector preexistente): aditivo y seguro.

## Tests (referencia tests→Collectors.Windows agregada: dirección tests→src)
- 10 pins nuevos: volumen/tasa de oleada, umbral de bloqueos, formato por
  archivo (4 casos), INI parse+diff+resumen, huella estable y sin secretos,
  política de módulos (6 casos), formato de cobertura (3 casos), estabilidad
  (calma/flap/vacíos).

## Validación
- `dotnet build TDM.sln -c Release --no-restore -warnaserror`: 0 warnings, 0 errores.
- `TDM.ProductionTests.exe`: **47/47 PASS** (10 nuevos).
- `TDM.ParityTests.exe`: **26/26 PASS** (verificado en gate).
- `VERIFY-TDM-READINESS.cmd`: **[OK] TDM READINESS GATE PASS**.
- `PUBLISH-PORTABLE-WIN-X64.cmd`: `dist\TDM-portable-win-x64\TDM.exe` (~133 MB).

## Pendiente consciente (P2-alto, su propia ronda)
Multicausa explícita + contrafácticos: cirugía en la selección de primaria con
riesgo real de regresión. La base quedó lista (vetos, estabilidad, feedback).
No iniciado a propósito en esta ronda.
