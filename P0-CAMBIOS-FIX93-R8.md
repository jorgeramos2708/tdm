# TDM FIX93 — P0 R8

## Objetivo
Corregir la cadena **monitoreo → detección → correlación → RCA → reporte** para que un estado operativo demostrado no se confunda con su causa y que fallas concurrentes no se mezclen en una única causa global.

## Correcciones P0

### 1. Monitoreo continuo / transición en el mismo ciclo
- `TdmWorker` persiste el snapshot actual antes de ejecutar la correlación.
- Las transiciones recién observadas se incorporan al reporte antes de `DiagnosticWorkflow.Analyze`.
- `RecordAndEnrichAsync` reutiliza el resultado pre-registrado para evitar doble escritura.

### 2. Detección de servicios TSplus
- `LightweightTsplusStateCollector` observa explícitamente servicios relacionados con TSplus y emite `SERVICE_STATE`.
- El clasificador reconoce Web Portal / Web Server / HTML5 además de marcadores TSplus existentes.
- Un servicio TSplus requerido en `Stopped`, `StopPending` o `StartPending` puede elevarse como incidencia operativa si la evidencia lo respalda.

### 3. Separación impacto vs causa
- Se agregó el rol `IMPACTO_DIRECTO_SIN_CAUSA_DEL_PARO` a `RootCauseCandidate`.
- Un `Web Portal Service = Stopped` demuestra impacto Web/HTML5, pero no demuestra por sí mismo por qué se detuvo el servicio.
- El impacto funcional se deriva directamente del estado operativo, sin exigir una causa raíz previamente seleccionada.

### 4. Ranking y conflictos
- `CausaRaizPrincipal` sólo existe cuando existe una candidatura causal con margen mínimo de 5 puntos sobre la segunda.
- Una brecha menor de 5 puntos se reporta como `EMPATE_TECNICO / HIPÓTESIS_COMPETITIVAS`.
- La marca final de conflicto se calcula después de la calibración para evitar contradicciones entre secciones.
- Los candidatos de impacto directo quedan fuera del cálculo de conflicto causal.

### 5. Reporte / lenguaje
- La narrativa y la exportación ya no seleccionan automáticamente el primer candidato como causa principal.
- `CausalResponsibilityFormatter` distingue impacto directo, empate técnico y origen causal sustentado.
- Observabilidad utiliza sólo `CausaRaizPrincipal` para poblar el origen causal agregado.

## Caso de prueba representativo

Para un servidor donde coexistieran:
- `Web Portal Service = Stopped`
- `manifest.json` malformado
- falla de canal seguro/AD
- errores WMI

TDM debe separar estas señales en lugar de afirmar que `manifest.json` es la causa única. El paro del Web Portal debe aparecer como impacto demostrado; la causa del paro debe permanecer como no demostrada si no existe una cadena temporal/mecánica suficiente.

## Validación
El contenedor Linux de esta sesión no dispone de `dotnet`, por lo que no se ejecutó compilación de C# ni pruebas de runtime Windows. Se añadieron pruebas de regresión al `TDM.ProductionTests` y debe ejecutarse el build/test oficial en Windows antes de declarar R8 compilado y liberable.
