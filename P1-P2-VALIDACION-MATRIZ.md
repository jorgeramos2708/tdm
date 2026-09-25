# FIX93 R8 — Matriz P1/P2

| ID | Caso | Esperado |
|---|---|---|
| P1-01 | Web Portal detenido + manifest.json inválido | Web/HTML5 = impacto demostrado; manifest = hipótesis/anomalía salvo cadena causal suficiente |
| P1-02 | AD secure-channel failure simultáneo con Web | Incidente AD separado del incidente Web |
| P1-03 | WMI 0x80041032 repetitivo | Dominio OBSERVABILIDAD; no causa raíz TSplus; no ledger operativo |
| P1-04 | Dos candidatos 71/70 | EMPATE_TECNICO / HIPÓTESIS_COMPETITIVAS; sin causa única |
| P1-05 | Servicio Running -> Stopped | Transición disponible antes de correlación y evidencia de impacto en el mismo ciclo |
| P2-01 | Dependencias SCM profundas sin relación funcional | No deben dominar el resumen de dependencias |
| P2-02 | SERVICE_STATE crítico | Estado/impacto, no señal causal por sí solo |
| P2-03 | Dashboard/ledger con WMI | WMI visible como evidencia técnica, no como incidente operativo persistente |
| P2-04 | Reporte | Debe presentar dominios/incidentes agrupados y declarar que agrupación != causalidad |
| P2-05 | Fuentes bloqueadas | Debe conservar limitación y no elevar ausencia de evidencia a estado sano |
