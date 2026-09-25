# TDM FIX93 — P1/P2 R8-P2

## P1 — Incidentes independientes y correlación
- Se agregó `DiagnosticIncidentCluster` al modelo.
- `IncidentClusterAnalyzer` separa por dominio funcional y una ventana máxima de 5 minutos.
- Web/HTML5, AD/autenticación, RDP/sesiones y observabilidad/WMI no se mezclan en una sola causa por proximidad temporal.
- El agrupador marca explícitamente que la agrupación no demuestra una causa común.
- El workflow calcula los grupos después de la correlación para que el reporte pueda mostrar la estructura de incidentes concurrentes.

## P2 — Precisión de señales y presentación
- WMI/DCOM quedan fuera de la señal causal y del ledger de incidentes operativos; permanecen disponibles como evidencia de observabilidad.
- `SERVICE_STATE` no aumenta la señal causal: demuestra estado/impacto; la causalidad exige eventos de terminación/inicio fallido u otro antecedente válido.
- El reporte muestra los incidentes agrupados con dominio, ventana, severidad, señales y explicación.
- El reporte reduce el grafo SCM a dependencias funcionalmente relevantes para TSplus/RDP/impresión/autenticación; no se pretende que cada dependencia profunda sea causal.
- Se preserva el inventario completo en los datos subyacentes.

## Pruebas de regresión
- WMI no es causal.
- SERVICE_STATE no es causal.
- WMI no entra al ledger de incidentes operativos.
- Web/HTML5 y AD concurrentes generan grupos independientes.
- WMI queda identificado como OBSERVABILIDAD.

## Validación pendiente
El proyecto sigue requiriendo `dotnet build`/`dotnet test` en Windows y una ejecución real durante al menos una hora. El diagnóstico real compartido por el usuario será la prueba de integración principal para cerrar P1/P2.
