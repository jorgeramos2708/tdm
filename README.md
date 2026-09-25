# TDM FIX93 CLEAN

Paquete limpio de desarrollo, validación y distribución de TSplus Diagnostic Monitor.

## Uso
1. `VERIFY-TDM-READINESS.cmd` — valida estructura, compatibilidad de interfaz, restaura, compila, ejecuta pruebas y comprueba startup.
2. `BUILD-TDM.cmd` — restaura y compila Release.
3. `START-TDM.cmd` — inicia Notifier y GUI ya compilados.
4. `PUBLISH-DISTRIBUCION-WIN-X64.cmd` — genera publicaciones self-contained para Windows x64.
5. `PUBLISH-PORTABLE-WIN-X64.cmd` — genera `dist\TDM-portable-win-x64\TDM.exe` para uso sin instalación.
6. `CREAR-INSTALADOR-EXE.cmd` — genera `dist\TDM-Setup-x64.exe` para monitoreo permanente mediante servicio.

## Ajustes FIX63
- Se retiran de las tarjetas de Centro de soporte los textos auxiliares visibles `1 con atención` y `1 servicio/dependencia requiere atención...`; la información sigue disponible en `Ver detalle`.
- Preventivo recupera las tarjetas de Riesgo preventivo, Servicios y dependencias, Predicción de saturación e Inestabilidad operativa.
- También recupera Estabilidad de servicios/dependencias y Acciones preventivas sugeridas.
- La sección Preventivo se reorganiza con alturas cómodas y sin superposición; el scroll vertical de la pestaña se conserva cuando la resolución lo necesita.
- Se mantiene el filtrado interno que excluye `TDM.Service` como servicio objetivo.
- Se añaden scripts de publicación/distribución para Windows x64.

## Distribución
Consulte `DISTRIBUCION.md`.

## Contenido
Se conservan únicamente los proyectos y scripts necesarios para GUI, Notifier, Servicio, motor diagnóstico, persistencia, reporting y pruebas de paridad.


## FIX65 — Servicios y dependencias ampliados

La vista **Servicios/Dependencias** amplía el monitoreo de Windows relevante para TSplus/RDP a 34 servicios objetivo (cuando existen en el servidor), además de descubrir dinámicamente servicios TSplus por nombre, nombre visible o `ImagePath`. El grafo SCM real se renueva en el muestreo ampliado de `TDM.Service` y en diagnósticos completos. Los servicios bajo demanda en inicio Manual no se marcan como falla sólo por estar detenidos.

Áreas cubiertas: RDP, RPC/COM, Event Log/WMI, red/firewall/DNS/NLA, perfiles e identidad, tiempo/Kerberos/Netlogon, impresión y roles RDS opcionales.

## FIX66 — Readiness determinista del Notifier

- El gate activa el modo `TDM_AVALONIA_NOTIFIER_READINESS_PROBE=1` durante la prueba de startup.
- GUI y Notifier deben emitir marcadores `READY` independientes antes de aprobar.
- La validación ya no compite con una instancia interactiva del Notifier ni falla por su mutex de instancia única.
- Los procesos, archivos temporales y variables de entorno se limpian y restauran incluso si la prueba falla.

## FIX67 — Nombres visibles, iconos y estados operativos

- Los ejecutables públicos ahora se generan como `TDM.Application.exe` y `TDM.Notifier.exe`.
- Un sanitizador compartido elimina nombres técnicos del framework en notificaciones nuevas, journal, incidentes históricos y reportes visibles.
- Actualizar, Descargar reporte y Configuración usan glifos ampliados y escalados dentro de un área central uniforme; el engrane ya no depende de un `LineHeight` que lo recortaba.
- Servicios y Dependencias comparten las mismas columnas `Nombre | Origen | Estado`, con origen y estado presentados como etiquetas centradas.
- El estado visible se limita a `En ejecución` en verde o `Detenido` en amarillo; los estados técnicos completos permanecen únicamente en la telemetría interna.

## FIX68 — Identidades de restauración únicas

- Se conserva `TDM.Application.exe` como nombre público de la interfaz y `TDM.Notifier.exe` como nombre público del notificador.
- GUI, Notifier y pruebas usan `PackageId` internos únicos para que NuGet no confunda el ejecutable `TDM.Application` con la biblioteca interna del mismo nombre.
- El gate comprueba todos los CSPROJ antes del restore y falla con un diagnóstico directo si detecta algún `PackageId` o `AssemblyName` efectivo duplicado.

## FIX69 — Ensamblados sin colisión

- La biblioteca interna conserva sus namespaces y API, pero ahora genera `TDM.Application.Core.dll`.
- La interfaz continúa generando el ejecutable público `TDM.Application.exe`.
- Se elimina la colisión física de ensamblados que impedía al compilador XAML resolver `App`, `MainWindow` y las 13 vistas restantes.
- El gate valida por separado la unicidad de identidades NuGet y de nombres de ensamblado antes de restaurar o compilar.

## FIX70 — Notificaciones y centro de soporte coherentes

- Los eventos `.NET Runtime`, `Application Error` y `WER` pertenecientes al mismo crash se consolidan por proceso en una sola notificación.
- Inicio y pausa usan geometrías vectoriales dentro de una fila común de 40 px, centradas exactamente con el temporizador.
- `Salud general` se reemplaza por `Módulos TSplus`, con cantidad de módulos críticos o con error respecto del total evaluado.
- La gráfica operativa combina servicios y dependencias, muestra el total en ejecución y desglosa ambas categorías.
- `Ver detalle` utiliza el mismo snapshot, se actualiza junto con la tarjeta y clasifica cada elemento únicamente como `En ejecución` o `Detenido`, sin mezclar conteos de falla y atención.

## FIX71 — Lectura visual y alcance TSplus

- Las notificaciones dejan de mostrar el pie técnico `Recuperado/Informativo/fecha`; transición, severidad y hora permanecen como datos internos.
- Las donas de Servicios/Dependencias y Módulos TSplus usan verde para el tramo correcto y amarillo/naranja/rojo únicamente para el tramo afectado.
- Sesiones muestra como cifra principal el total observado (`activas + desconectadas`) y separa los incidentes en una línea independiente.
- Toda la pestaña TSplus elimina espacios alrededor de `/`: por ejemplo, `Remote Access/RDP` y `ERROR/FALLA OBSERVADA`.
- Servicios y Dependencias muestran solo el subgrafo alcanzable desde servicios TSplus o desde el núcleo RDP utilizado por TSplus; se excluyen elementos generales sin relación SCM real.

## FIX72 — Notificador vigente, incidentes legibles y porcentajes

- El inicio sustituye una instancia de `TDM.Notifier.exe` cargada desde una entrega anterior; el binario actual ya no queda bloqueado por el mutex heredado ni conserva el pie visual antiguo.
- El instalador detiene el notificador antes de actualizar sus archivos y vuelve a iniciar el ejecutable recién instalado.
- La Línea de incidentes presenta cada incidente en un bloque con Fecha/Hora, Estado, Tipo, Componente y Detalle, sin columnas superpuestas.
- Los registros `.NET Runtime`, `Application Error` y `WER` del mismo cierre se consolidan también en el historial visible y se prioriza la evidencia de `Application Error`.
- Entrada y Salida aparecen juntas en la leyenda de Red.
- Tendencia preventiva muestra los porcentajes actuales de CPU y memoria utilizada.
- Salud TDM expresa la memoria del proceso como porcentaje de la memoria física total; muestras antiguas sin ese dato se muestran como `N/D`.

## FIX73 — Arranque CMD compatible con Windows

- `START-TDM.cmd` ya no ejecuta `chcp 65001` ni depende de variables `set` para las rutas de GUI y Notifier.
- Todos los scripts `.cmd` de la raíz se distribuyen con terminadores Windows `CRLF`.
- El gate verifica los bytes de `START-TDM.cmd` y rechaza saltos `LF` aislados.
- Se conserva el reemplazo automático de una instancia anterior de `TDM.Notifier.exe` antes de iniciar la GUI.

## FIX74 — Notificación sin pie técnico y compilación limpia

- La notificación de escritorio muestra únicamente el título, el mensaje principal y los botones; no presenta `Detectado`, `Escalado`, `Recuperado`, severidad ni fecha/hora.
- `BUILD-TDM.cmd`, el gate y la publicación ejecutan una limpieza previa para impedir que MSBuild reutilice XAML o binarios de una entrega anterior.
- El ensamblado del Notifier incorpora la revisión `FIX93_EXPLICIT_ALERTS_NO_RECOVERED`; el gate valida que esté dentro del DLL compilado.
- `START-TDM.cmd` rechaza un Notifier obsoleto y solicita recompilar, en vez de iniciar silenciosamente una interfaz anterior.
- El arranque termina instancias actuales y heredadas del Notifier antes de abrir el binario de FIX74.

## FIX75 — Publicación e instalador autocontenido

- El publicador termina primero las instancias de GUI y Notifier que puedan bloquear los DLL de Release.
- Cada proyecto se restaura explícitamente para `win-x64` con `--force-evaluate`, incluyendo las propiedades de publicación de archivo único.
- La publicación usa `--no-restore`, evitando que NuGet vuelva a entrar en modo bloqueado con un lock file incompatible y genere `NU1004`.
- El instalador detiene GUI, Notifier y el servicio antes de reemplazar archivos instalados.
- Las copias de App, Service y Notifier ahora detienen la instalación si `xcopy` falla.

## FIX76 — Conteo correcto en el readiness gate

- El gate deja de usar `String.Split()` para contar las opciones `--force-evaluate` y `--no-restore` del publicador.
- PowerShell ahora utiliza coincidencias literales mediante `Regex.Escape`, evitando el falso fallo `La publicación no fuerza las tres restauraciones win-x64`.
- El publicador de FIX75 se conserva sin cambios funcionales: contiene tres restauraciones forzadas y tres publicaciones sin restauración implícita.

## FIX77 — Empaquetado IExpress determinista

- App, Service y Notifier se comprimen en un único `payload.zip` preservando sus tres carpetas.
- IExpress recibe solamente `install.cmd` y `payload.zip`, en vez de intentar procesar cientos de rutas anidadas.
- El instalador expande el payload en una carpeta temporal, valida los tres ejecutables y luego instala los componentes.
- La solicitud de privilegios administrativos espera a que termine la instalación elevada, evitando que IExpress elimine sus temporales antes de tiempo.
- El servicio existente se actualiza mediante `sc config`; una instalación nueva utiliza `sc create`.

## FIX78 — Instalador EXE sin IExpress

- Se elimina IExpress de la ruta de creación porque en FIX77 podía terminar sin producir el ejecutable, aun cuando la publicación y `payload.zip` fueran correctos.
- Un proyecto de instalador .NET integra `payload.zip` y el procedimiento de instalación como recursos internos.
- `dotnet publish` genera directamente `dist\TDM-Setup-x64.exe` como archivo único y autocontenido para Windows x64.
- El EXE solicita privilegios de administrador mediante manifiesto, instala App, Service y Notifier y crea el acceso directo.
- Los fallos de ejecución quedan registrados en `%TEMP%\TDM-Setup.log` y se muestran en un cuadro de error.

## FIX79 — TDM Portable y arranque rápido

- Se agrega `TDM.exe` portable: no instala archivos, no registra servicios y no deja abierto un proceso de Setup.
- El monitor local de 5 segundos y las notificaciones visuales se integran en la misma aplicación, evitando procesos separados de Notifier y Service en esta modalidad.
- La primera captura diagnóstica se mueve al segundo plano para que la ventana no espere hasta ocho segundos antes de quedar utilizable.
- Las compilaciones de la interfaz activan ReadyToRun; la edición portable evita la compresión interna del bundle para priorizar el tiempo de arranque.
- El modo portable funciona mientras `TDM.exe` permanece abierto. Para monitoreo y notificaciones después de cerrar la interfaz, se conserva `TDM-Setup-x64.exe`.

### Crear la edición portable

Ejecute:

`PUBLISH-PORTABLE-WIN-X64.cmd`

Comparta únicamente:

`dist\TDM-portable-win-x64\TDM.exe`

## FIX80 — Corrección de restauración portable NU1005

- Se conserva `RestorePackagesWithLockFile=true`, coherente con los `packages.lock.json` incluidos en los proyectos.
- Se desactiva únicamente `RestoreLockedMode` durante la restauración específica para `win-x64`, permitiendo que NuGet actualice el grafo del RID y de ReadyToRun.
- `--force-evaluate` vuelve a evaluar las dependencias antes de publicar y `--no-restore` garantiza que la publicación use exactamente ese resultado.
- El gate rechaza cualquier regresión que combine archivos lock existentes con `RestorePackagesWithLockFile=false`.

## FIX81 — Nueva identidad visual TDM

- Se reemplaza el logotipo anterior por el diseño de diagnóstico basado en documento, telemetría y lupa con las letras `TDM`.
- El fondo del recurso es transparente y los trazos usan blanco, cian y verde eléctrico para conservar contraste sobre la interfaz azul oscuro.
- El pequeño acento ámbar comunica detección de incidentes sin competir con la lectura principal.
- La cabecera utiliza el PNG de 512 px y los ejecutables portable, instalado, Notifier, servicio e instalador comparten un ICO multirresolución de 16 a 256 px.

## FIX82 — Cabecera visual aprobada y compatibilidad del gate

- Se elimina el cuadro exterior del logotipo y el símbolo transparente queda directamente sobre la barra superior.
- El nombre se organiza en tres líneas nativas y nítidas: `TSplus` en cian, `Diagnostic` en blanco frío y `Monitor` en verde turquesa.
- `Monitoreo y diagnóstico operativo` se muestra en blanco y conserva contraste sobre el fondo oscuro.
- El mismo logotipo sin marco permanece como icono multirresolución de la aplicación portable, GUI instalada, Notifier, servicio e instalador.
- El gate deja de depender de `Get-FileHash` y calcula SHA-256 mediante las clases criptográficas de .NET, compatibles con entornos antiguos de PowerShell.

## FIX83 — Controles superiores centrados

- El selector `Tiempo real` y todos los controles de ejecución comparten el mismo eje vertical.
- Ejecutar y pausar adoptan cajas uniformes de 40 × 40 px, iguales a actualizar, descargar y configuración.
- El cronómetro queda dentro de un contenedor fijo de 104 × 40 px para evitar desplazamientos cuando cambia su valor.
- Los seis elementos se agrupan dentro de la sección `TIEMPO DE EJECUCIÓN`, con separaciones constantes y sin márgenes laterales independientes.
- Los iconos se reducen y quedan centrados horizontal y verticalmente dentro de sus botones.

## FIX84 — Corrección visual real de los botones

- Se corrige el `ContentPresenter` interno que contraía el marco visible al tamaño del icono aunque el botón reservara 40 × 40 px.
- La superficie del botón ahora se estira a la caja completa y solamente el icono permanece centrado.
- Pausa y descarga conservan una caja gris de 40 × 40 px cuando están deshabilitados, sin dejar huecos visuales.
- El selector, los cinco botones y el cronómetro quedan sobre el mismo centro vertical, como en la vista previa aprobada basada en la captura real.

## FIX85 — Barra superior limpia sin cajas

- Se eliminan el fondo y el borde visibles de ejecutar, pausar, actualizar, descargar y configuración.
- Los botones conservan áreas de interacción fijas de 40 × 40 px aunque su superficie sea transparente.
- Los estados deshabilitados se comunican solamente mediante opacidad, sin cuadros grises.
- El cronómetro conserva un espacio fijo de 104 × 40 px, pero elimina completamente fondo, borde y esquinas visibles.
- El texto del cronómetro baja 3 px para igualar su centro óptico con los iconos de ejecutar y pausar.

## FIX86 — Iconos uniformes, cronómetro acumulativo y exportación visible

- Los cinco iconos de la barra superior usan un área visual uniforme de 24 × 24 px, sin modificar las columnas, separaciones ni la posición aprobada de los controles.
- Pausar conserva el tiempo transcurrido y ejecutar reanuda desde ese punto; iniciar ya no sustituye el tiempo acumulado.
- Únicamente el botón de actualizar reinicia el cronómetro a `00:00:00`. Los refrescos automáticos de telemetría y los ciclos internos del diagnóstico no lo reinician.
- Descargar reporte abre un selector de carpeta, genera los archivos HTML y JSON, comprueba que ambos existan y no estén vacíos, muestra la ruta guardada en la vista de diagnóstico y revela el HTML en el Explorador de Windows.
- El gate incluye pruebas de pausa/reanudación/reinicio y de exportación real a una carpeta seleccionada.

## FIX87 — Tipografía e iconos idénticos a la vista previa

- El cronómetro sustituye `Consolas` por `DejaVu Sans Mono Bold`, la tipografía observada en la vista previa aprobada.
- La fuente se integra como recurso interno y se registra dinámicamente con el nombre real del ensamblado, por lo que funciona tanto en `TDM.Application.exe` como en el portable `TDM.exe` sin depender de fuentes instaladas en Windows.
- Play, pausa, reiniciar, descargar y configuración utilizan las mismas geometrías vectoriales de Lucide mostradas en la vista previa.
- Los cinco iconos conservan 24 × 24 px; no cambian las columnas, separaciones, áreas de interacción de 40 × 40 px ni el ajuste vertical del cronómetro.
- Se incluyen los avisos de licencia de DejaVu y Lucide, junto con verificaciones de integridad y antirregresión en el readiness gate.

## FIX88 — Interfaz operativa diseñada para TDM

- Se sustituye el patrón visual de tarjetas genéricas por franjas métricas, divisores y áreas de trabajo abiertas.
- Centro de soporte reorganiza servicios, módulos TSplus, sesiones e incidentes según su función, sin cuatro cajas equivalentes.
- Diagnóstico, Sesiones, Incidentes, Causalidad, Preventivo y Servidores/Granja presentan sus cifras en franjas compactas y alineadas.
- Rendimiento y Salud TDM integran las gráficas directamente en el espacio de trabajo, separadas por estructura y no por contenedores decorativos.
- Servicios/Dependencias conserva las columnas fijas aprobadas y elimina las cápsulas exteriores de origen y estado; los puntos y colores mantienen la semántica.
- La línea de incidentes elimina cajas por evento y agrega un marcador de severidad conectado a una lectura vertical más natural.
- Las retículas y bandas de umbral de las seis gráficas reducen su intensidad para dar prioridad a los datos.
- El encabezado, el logotipo, los iconos de 24 px, la posición del cronómetro y los comandos permanecen sin cambios funcionales.
- El readiness gate incorpora comprobaciones específicas de las once pestañas y de la nueva gramática visual.

## FIX89 — Pestañas con mayor legibilidad

- Los títulos de las once pestañas principales aumentan de 12 a 14 px.
- Las siete pestañas internas de Diagnóstico adoptan el mismo tamaño de 14 px.
- Se conservan el peso Medium, el espaciado, la alineación, los colores y el comportamiento de selección de FIX88.
- No se modifican vistas, bindings, comandos ni lógica funcional.

## FIX90 — Área ajustada del botón Actualizar

- El botón `Actualizar y reiniciar cronómetro` reduce su área interactiva de 40 × 40 a 38 × 38 px.
- El icono vectorial permanece en 24 × 24 px y centrado horizontal y verticalmente.
- La columna reservada conserva 40 px, por lo que no cambian las separaciones ni la posición del cronómetro y los demás controles.
- Los otros cuatro botones mantienen sus áreas de 40 × 40 px.

## FIX91 — Umbrales de Salud TDM y textos preventivos en español

- La serie `Memoria TDM` de la gráfica CPU y memoria pasa a mostrarse como `Memoria`.
- La gráfica incorpora umbrales independientes de advertencia y crítico para CPU y memoria de TDM.
- Los umbrales configurados de memoria, almacenados en MB, se convierten a porcentaje usando la memoria física detectada para coincidir con la escala de la gráfica.
- Los estados visibles `Stopped`, `Running`, `Failed`, `Unknown`, `Paused` y `Pending` se presentan en español dentro de Preventivo, sin alterar los identificadores reales de servicios de Windows o TSplus.
- Los nombres funcionales visibles se normalizan como `Acceso remoto/RDP`, `Sesiones/inicio de sesión` y `Granja/Puerta de enlace`.
- Los textos saludables eliminan los espacios alrededor de la diagonal: `SALUDABLE/SIN FALLA OBSERVADA` y `SIN FALLA OBSERVADA/COBERTURA LOCAL`.
- La clasificación evita interpretar la frase `SIN FALLA` como una falla real.

## FIX92 — Configuración de memoria en porcentaje

- `Memoria de TDM` se configura directamente en porcentaje, con valores predeterminados de 5% para advertencia y 10% para crítico.
- La fila conserva las columnas, anchos, alineación y posición exactos del formulario anterior; únicamente cambian la unidad, los límites y el formato numérico.
- La gráfica Salud TDM consume los porcentajes configurados sin conversiones intermedias.
- Se elimina el bloque superior de estado, origen, ruta y recarga de configuración.
- El encabezado `CONFIGURACIÓN Y ESTADO` cambia a `CONFIGURACIÓN`.
- Los archivos de configuración anteriores que aún contengan campos de memoria en MB cargan los nuevos valores porcentuales predeterminados; los demás ajustes se conservan.


## FIX93 — Precisión diagnóstica empresarial

FIX93 parte de FIX92 y endurece el núcleo diagnóstico y de observabilidad sin modificar la filosofía de solo lectura. Cambios principales:

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

La validación estática de este paquete no sustituye el gate dinámico de Windows/TSplus. Antes de promoción a producción debe ejecutarse `VERIFY-TDM-READINESS.cmd` en un host Windows compatible y completar las pruebas operativas/laboratorio documentadas.

## Sprint 2 — Inteligencia Causal y Simulación What-If

Implementación de los tres componentes del roadmap senior auditor:

### S2.1 — Grafo Causal Temporal (`TemporalCausalGraph.cs`)
- **Correlación con retardo temporal**: Ventanas deslizantes configurables para detectar precedencia temporal entre métricas (CPU, memoria, red, disco, procesos, TSplus).
- **Prueba de causalidad de Granger**: Implementación simplificada de F-test para validar si una serie temporal mejora la predicción de otra (causalidad predictiva vs. correlación espuria).
- **Detección de aristas causales**: Scoring de confianza (0-1) combinando significancia estadística, retardo óptimo y fuerza de predicción.
- **Búsqueda de caminos**: Rastreo de cadenas causales para localización de causa raíz (root cause tracing).

### S2.2 — Propagación de Salud en Grafo de Dependencias (`DependencyHealthPropagator.cs`)
- **Estados de salud**: `Unknown`, `Healthy`, `Warning`, `Error`, `Critical` (enum `ServiceHealth`).
- **Grafo bidireccional**: Dependencias aguas arriba (upstream) y dependientes aguas abajo (downstream).
- **Propagación recursiva**: Con detección de ciclos (conjunto `visited`) y cooldown configurable para evitar flapping.
- **Reglas de propagación**:
  - Dependencia `Critical` → dependiente `Critical`
  - Dependencia `Error` → dependiente `Error`
  - Dependencia `Warning` → dependiente `Warning`
  - Todas `Healthy` → dependiente `Healthy`
- **API**: `UpdateHealth()`, `GetPropagationPath()`, `GetDependencies()`, `GetDependents()`, `GetNodes()`.

### S2.3 — Motor Contrafactual (`CounterfactualEngine.cs`)
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
