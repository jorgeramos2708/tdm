# TDM FIX93 R6 — Corrección del contrato de estados operativos

## Motivo
R5 introdujo estados operativos más precisos para servicios y dependencias (`Bajo demanda`, `No requerido`, `Complementario`, `Revisar`, `No evaluado`), pero el readiness gate y las pruebas de paridad aún conservaban la regla antigua de sólo `En ejecución` / `Detenido`.

El gate fallaba en `[1/7] Validación estática` con:

> La UI no limita el estado a En ejecución/Detenido.

Ese fallo era una incompatibilidad del gate con el nuevo modelo, no una regresión de la UI.

## Cambios de R6

### 1. Gate de readiness
Se reemplazó la aserción binaria por el contrato visible permitido:

- En ejecución
- Detenido
- Bajo demanda
- No requerido
- Complementario
- Revisar
- No evaluado

### 2. Servicios / Dependencias
`Unknown` y cualquier estado no reconocido ya no se convierten en `N/D` silencioso: se presentan como `No evaluado`.

### 3. Semántica de salud operativa
La clasificación compartida ya no considera como fallas:

- servicios complementarios;
- servicios Manual/Trigger bajo demanda;
- servicios deliberadamente no requeridos/deshabilitados;
- dependencias condicionales que no son requeridas en ese instante.

Una dependencia condicional detenida queda en `Revisar`, no en `Detenido`.
Una fuente no evaluable queda en `No evaluado`, no se asume sana ni caída.

### 4. Centro de soporte
La dona `SERVICIOS / DEPENDENCIAS` ahora separa:

- saludables/neutrales;
- pendientes de revisión;
- detenidos/falla real.

`Bajo demanda`, `No requerido` y `Complementario` dejan de inflar el tramo afectado.

### 5. ParityTests
Las pruebas fueron actualizadas para validar el contrato de siete estados y para comprobar que `RemoteSupportUnattended-Service` se presenta como `Complementario` en vez de contaminar la salud de Remote Access.

## Validación estática R6

- 19 proyectos `.csproj` en el árbol.
- 18 proyectos alcanzables desde la solución.
- 172 archivos C#.
- 18 AXAML.
- 26 ParityTests declarados.
- 17 ProductionTests declarados.
- 0 referencias de proyecto rotas detectadas.
- 0 ciclos de proyecto detectados.
- 0 `bin/obj` en SOURCE.
- Gate PowerShell conserva UTF-8 BOM.
- `START-TDM.cmd` conserva CRLF.

## Validación dinámica pendiente
Ejecutar en Windows:

```cmd
.\VALIDAR-FIX93.cmd
```

El SOURCE no incluye `packages.lock.json`; el gate debe generarlos y después repetir el restore en `--locked-mode`.
