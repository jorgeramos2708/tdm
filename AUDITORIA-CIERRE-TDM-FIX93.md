# Cierre técnico — TDM v1.0 RC18.21.0 FIX93

Fecha: 6 de septiembre de 2026  
Base: `TDM-v1.0-rc18.21.0-FIX92-CLEAN`  
Objetivo: corregir los bloqueadores de precisión/causalidad detectados en FIX92 y preparar una candidata empresarial verificable en Windows.

## Revisión R4

Se corrigió el error de compilación CS1009 detectado por el gate Windows en `TsplusInternalConfigurationCollector.cs`: la referencia textual a `Clients\www` se expresa ahora como literal verbatim C#, sin modificar la lógica funcional. También se revisaron las cadenas nuevas con rutas/backslashes para detectar el mismo patrón.

## Dictamen de esta etapa

**Validación estática: PASS.**  
**Promoción a producción: PENDIENTE del gate dinámico Windows/TSplus.**

No se declara GO empresarial desde este entorno porque no dispone de .NET SDK/MSBuild, Windows Event Log, Service Control Manager ni una instalación TSplus real. El paquete incorpora un gate actualizado para ejecutar esas comprobaciones en Windows.

## Controles estáticos finales

- 18 proyectos `.csproj`.
- 5 proyectos raíz en `TDM.sln`; los 18 proyectos quedan alcanzables por referencias transitivas.
- 0 `ProjectReference` rotos.
- 0 ciclos entre proyectos.
- 170 archivos C# revisados léxicamente.
- 18 AXAML parseables.
- 17 `TDM.ProductionTests` de verdad funcional/regresión.
- 0 carpetas `bin/obj` en el SOURCE.
- 0 usos de `TolerateQueryErrors = true`.
- 0 usos de `EffectiveTime(...)` como sustituto causal.
- 0 coincidencias `Contains(user...)` para identidad.
- 0 textos visibles `Condición recuperada`, `Recuperado · ...`, `Memoria / tendencia` o `CPU / tendencia` en `src`.
- 0 referencias a la revisión binaria antigua `FIX74_NO_NOTIFICATION_FOOTER` en `src`.

## Correcciones principales

### Tiempo causal e incidentes

- `EventTime` (`Timestamp`) es obligatorio para una incidencia funcional.
- `IngestedAt` queda sólo como metadato de adquisición/orden auxiliar y no convierte evidencia histórica sin fecha en incidente actual.
- Evidencia sin fecha se conserva como contexto no temporal y queda fuera de la causalidad temporal.
- Fechas TSplus ambiguas `dd/MM` vs `MM/dd` sólo se resuelven si la ventana de investigación hace inequívoca una interpretación; de lo contrario permanecen sin hora causal.

### Logs TSplus

- Cursor durable por archivo.
- Detección de truncado/recreación.
- Backlog controlado.
- Lectura segura de prefijos UTF-8/UTF-16 sin avanzar sobre caracteres incompletos.
- Registros multilinea: excepción + inner exception + stack trace se conservan como una sola evidencia.
- Si no puede persistirse el cursor se degrada cobertura; no se presenta continuidad garantizada.

### Event Viewer

- Cursor durable y replay acotado.
- Detección de discontinuidad/recreación de canal.
- Consultas críticas dejan de tolerar silenciosamente errores parciales.
- Fallos de lectura se representan como pérdida de cobertura, no como “0 eventos”.

### Servicios, dependencias y módulos

- Servicio detenido no equivale automáticamente a incidente.
- Se consideran modo de inicio/rol/producto y evidencia SCM relacionada.
- Se redujo la clasificación por tokens genéricos de servicios TSplus.
- Perfiles/archivos inaccesibles se distinguen de ausencia confirmada mediante `FileSystemProbe`.
- Web/HTML5 valida listener + PID/proceso propietario; puerto ocupado por otro proceso es conflicto y propietario indeterminado es `NO EVALUADO`.

### Correlación Windows ↔ TSplus

- Ventanas temporales acotadas por regla.
- Identidad exacta de usuario en lugar de substrings (`ann` no coincide con `joann`).
- Schannel no se promueve por mera proximidad temporal.
- EDR/Defender requiere proceso/ruta/producto compartido para ser antecedente fuerte de un crash.
- Disk/NTFS/volmgr/Resource-Exhaustion requiere identidad técnica compatible; un volumen ajeno permanece como contexto.
- Configuración, integridad y granja no adquieren confianza alta sólo por estar en la misma ventana.
- La granja local se conserva como hipótesis Media hasta disponer de validación distribuida de nodos.

### RDP

- El gap de shell sólo se declara después de vencer realmente el SLA de 3 minutos.
- Una sesión todavía dentro del SLA queda pendiente, no degradada.
- Eventos sanos del pipeline RDP permanecen como contexto y no inflan calidad causal.

### Persistencia y autosalud

- `IncidentLedger` serializa escritores concurrentes dentro y entre procesos.
- Errores de persistencia/monitor/SMTP dejan de quedar silenciosos en rutas corregidas.
- Se endurece el almacenamiento de la contraseña SMTP y sus ACL en Windows.
- La sanitización cubre identidades asignadas adicionales.

### Alertas

- Títulos explícitos, por ejemplo: `TDM · Alerta de memoria libre en descenso`.
- Eliminadas las etiquetas visibles `/ tendencia`.
- Una condición que vuelve a la normalidad se cierra en el estado interno pero **no genera popup, alerta portable ni correo de recuperación**.
- Journal, coordinadores de popup y SMTP tienen barreras defensivas contra `Recovered`.
- El Notifier usa la revisión binaria `FIX93_EXPLICIT_ALERTS_NO_RECOVERED`; el arranque y el gate rechazan binarios anteriores.

### QA

- Nueva suite `tests/TDM.ProductionTests` con 17 pruebas, incluyendo evidencia sin fecha, timestamps, fechas ambiguas, stack trace, alertas, recuperación, cursores, concurrencia, identidad, configuración histórica, Schannel y distractores Windows.
- `VERIFY-TDM-READINESS.ps1` ejecuta paridad + ProductionTests y verifica `TDM.Service`.
- Restore reproducible: primer restore genera `packages.lock.json`; se exige un lock por proyecto y después se repite con `--locked-mode`.

## Pendiente obligatorio en Windows antes de GO

Ejecutar desde la raíz del paquete:

```cmd
VALIDAR-FIX93.cmd
```

El gate debe terminar en PASS. En particular debe confirmar restore locked, build Release con warnings-as-errors, ParityTests, ProductionTests, generación de GUI/Service/Notifier y startup.

Después del gate de compilación deben ejecutarse pruebas dinámicas sobre un laboratorio Windows Server + TSplus: caída real de servicios, Event IDs SCM, ACL denegada, clear/recreate de EVTX, rotación/truncado de logs, RDP/RemoteApp/HTML5, certificados, impresión, 2FA, complementos y, si aplica, granja. Para promoción empresarial se mantiene además el requisito de soak prolongado y revisión de diagnósticos reales.

## Limitaciones todavía abiertas

1. Este SOURCE no incluye `packages.lock.json` pregenerados porque el entorno de preparación no dispone de `dotnet`; el gate Windows los genera y luego exige `--locked-mode`.
2. Los proyectos siguen usando .NET 8. Debe planificarse migración a una LTS con horizonte suficiente antes del fin de soporte de .NET 8; no se migró dentro de FIX93 para no introducir una regresión de plataforma sin compilación Windows disponible.
3. TDM no puede certificar de forma autónoma todos los nodos de una granja remota si no existe sondeo distribuido. FIX93 reduce la confianza de esa hipótesis en vez de afirmar salud/causa remota.
4. Ninguna auditoría estática reemplaza la medición real de falsos positivos/falsos negativos en el corpus y laboratorio objetivo.

## Criterio para GO

No promover a producción general hasta obtener: gate Windows PASS, cero bloqueadores funcionales en el corpus P0/P1, continuidad comprobada ante reinicio/rotación, 100% de pérdida de cobertura representada explícitamente y soak sin degradación o crecimiento anormal de TDM.
