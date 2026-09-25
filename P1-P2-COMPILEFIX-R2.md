# FIX93 R8 P1-P2 CompileFix R2

Correccion del error CS8604 reportado por el readiness gate en RootCauseCorrelator.cs:116.

`DiagnosticEvent.Evidencia` es nullable; el Merge del candidato de estado operativo ahora usa una lista vacia cuando no hay evidencia: `state.Evidencia ?? []`.

No se modifica la semantica de P0/P1/P2; solo se elimina la advertencia nullable que, con warnings-as-errors, bloqueaba la compilacion.
