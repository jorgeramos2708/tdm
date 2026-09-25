# Changelog

All notable changes to TDM (TSplus Diagnostic Monitor) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-rc18.21.0-FIX93] - 2026-09-24

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