# TDM FIX93 R5 — Mapa funcional TSplus → Windows

## Objetivo

R5 corrige una brecha de FIX93 R4: la vista **Servicios / Dependencias** mostraba principalmente relaciones reales del Service Control Manager (SCM) y dos estados virtuales (`RDP/Listener` y `Red/Gateway`). Eso era insuficiente para explicar fallas donde el síntoma aparece en TSplus pero la dependencia que falla pertenece a Windows.

R5 combina dos fuentes sin confundirlas:

1. **Dependencias SCM reales**, leídas desde `ServicesDependedOn` / `DependentServices`.
2. **Dependencias funcionales tipadas TSplus → Windows**, emitidas sólo cuando la función/topología correspondiente aplica.

Una relación funcional no significa automáticamente causa raíz. `Stopped` sólo se eleva cuando el servicio es requerido en ese contexto; servicios Manual/Trigger y relaciones condicionales quedan como contexto hasta existir evidencia funcional/temporal.

## Relaciones añadidas

| Función TSplus | Dependencia Windows | Tipo | Criterio |
|---|---|---|---|
| Remote Access / RDP | `TermService` | Directa funcional | Requerida para la pila RDP |
| Remote Access / perfiles | `ProfSvc` | Directa funcional | Requerida para carga de perfil/sesión |
| Remote Access / RPC | `RpcSs` | Base Windows | Prerrequisito de componentes Windows usados por Remote Access |
| Remote Access / configuración RDP | `SessionEnv` | Bajo demanda | Manual/Trigger: detenido no equivale a falla |
| Remote Access / redirección | `UmRdpService` | Bajo demanda | Se interpreta con síntomas RDP/redirección |
| Universal Printer | `Spooler` | Directa funcional | Sólo si se detecta componente server-side de Universal Printer |
| Virtual Printer | `Spooler` | Directa funcional | Sólo si se detecta Virtual Printer realmente instalado/activo; el instalador solo no cuenta |
| 2FA | `W32Time` | Temporal/condicional | Se requiere reloj sincronizado; servicio detenido solo no prueba desfase |
| Farm/Gateway | `W32Time` | Temporal/condicional | Coherencia de hora entre nodos |
| Farm/Gateway | `Dnscache` | Red/condicional | Relevante cuando los nodos se resuelven por hostname |
| Autenticación de dominio | `Netlogon` | Dominio/condicional | Sólo si el servidor está unido a dominio |
| Autenticación de dominio | `Dnscache` | DNS/condicional | Sólo si el servidor está unido a dominio |
| Kerberos | `W32Time` | Tiempo/condicional | Sólo si el servidor está unido a dominio |

## Impresión: correlación Windows antes que TSplus

`PrintingHealthCollector` ahora reconoce Universal/Virtual Printer por evidencia server-side, no únicamente por una impresora visible vía WMI. Esto es importante porque si Spooler está caído, WMI puede no ofrecer una enumeración útil precisamente durante la incidencia.

Si existe un componente TSplus de impresión y Spooler no está Running:

- TDM registra la dependencia Windows degradada.
- `Spooler` aparece en Servicios/Dependencias.
- El grafo SCM puede continuar transitivamente a `Spooler → RpcSs` cuando Windows declara esa relación.
- La causa `ROOT-PRINT-SPOOLER` queda en **Media** si sólo se observa el estado detenido.
- Sólo sube a **Alta** cuando además existe un síntoma de impresión TSplus/PrintService relacionado dentro de la ventana temporal.

Esto evita tanto el falso negativo (no detectar Spooler por falta de impresoras WMI) como el falso positivo (declarar Spooler causa raíz alta sólo porque está detenido).

## Presentación de servicios

La vista ya no reduce todos los estados a `En ejecución` / `Detenido`:

- `En ejecución`
- `Detenido`
- `Revisar`
- `No evaluado`
- `Bajo demanda`
- `No requerido`
- `Complementario`

Por ejemplo, `RemoteSupportUnattended-Service` es un producto complementario y no debe interpretarse como requisito del núcleo Remote Access. `SessionEnv`/`UmRdpService` pueden ser bajo demanda según el modo/start type y no deben generar automáticamente una falla.

## Protección de causalidad

Los eventos `TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE` están excluidos de los pools genéricos de síntomas del `RootCauseCorrelator`. El propio mapa de dependencias no puede autocorrelacionarse consigo mismo para fabricar una causa. La elevación causal continúa dependiendo de eventos, logs, función afectada, identidad técnica y ventana temporal.

## Lo que NO se modela como servicio requerido fijo

R5 deliberadamente no convierte en dependencias duras permanentes servicios como BFE/MpsSvc, CryptSvc/KeyIso, NlaSvc, LanmanWorkstation o Winmgmt sólo porque puedan participar en ciertos escenarios. Se siguen monitoreando, pero se elevan cuando existe contexto técnico específico. Esto evita que un servicio opcional/manual contamine la salud general de TSplus.

Web/HTML5 tampoco se reduce a un único servicio Windows: TDM sigue evaluando listener/puerto, PID propietario, red, TLS/certificado y runtime web, porque esos son mejores indicadores que inventar una dependencia de servicio genérica.

## Validación

Validación estática R5:

- 19 proyectos `.csproj` en el árbol.
- 5 proyectos raíz en `TDM.sln` y 18 proyectos alcanzables transitivamente.
- 172 archivos C#.
- 18 AXAML.
- 17 ProductionTests declarados.
- 0 ProjectReference rotos.
- 0 errores XML/AXAML detectados.
- Gate PowerShell conserva UTF-8 BOM + CRLF.
- Sin `.git`, `bin` ni `obj` en el paquete fuente.

**Pendiente obligatorio:** compilar y ejecutar `VALIDAR-FIX93.cmd` en Windows. Este entorno no dispone de .NET SDK, SCM/EVTX real ni TSplus para certificar el gate dinámico.
