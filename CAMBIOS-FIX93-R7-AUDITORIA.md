# TDM FIX93 R7 — Cierre de bloqueadores de auditoría

R7 incorpora correcciones derivadas de la auditoría senior de R6:

- detección TSplus trivalente: presente / ausente confirmado / no evaluado;
- descubrimiento protegido por FileSystemProbe;
- cursor corrupto distinguido de cursor inexistente;
- replay seguro tras pérdida de cursor Windows/TSplus;
- semántica única del estado de servicios en grafo SCM y collector principal;
- ventana temporal basada en solapamiento de intervalos Primer/Último evento;
- filesystem probes normalizados en collectors TSplus críticos;
- pruebas de regresión para cursor corrupto y ventanas de intervalo;
- readiness gate ampliado para exigir estas garantías.

La ACL explícita del secreto SMTP y la certificación dinámica sobre Windows/TSplus siguen siendo tareas de hardening/certificación posteriores; no se declara GO empresarial sólo por este paquete.
