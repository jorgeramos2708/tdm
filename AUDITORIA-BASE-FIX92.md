# Auditoría TDM FIX92 CLEAN

## Objetivo

FIX92 conserva la interfaz operativa de FIX91 y cambia la configuración de memoria de TDM de MB a porcentaje. También elimina el bloque superior de estado de Configuración y simplifica el encabezado de la vista.

La revisión se concentra en tres riesgos:

1. pérdida accidental de bindings o comandos;
2. uso de propiedades XAML incompatibles con Avalonia 11.1.3;
3. regresiones visuales en datos extensos o en la resolución mínima.

## Alcance visual

| Vista | Tratamiento FIX88 |
|---|---|
| Centro de soporte | Composición operativa diferenciada para donas, sesiones e incidentes |
| Diagnóstico | Franja métrica y reportes abiertos |
| Rendimiento | Gráficas integradas y listas separadas por divisores |
| TSplus | Estado global y tabla funcional sin tarjetas |
| Servidores/Granja | Franja métrica, cabecera de columnas y editor abierto |
| Servicios/Dependencias | Tablas abiertas; origen y estado sin cápsulas |
| Sesiones | Franja métrica y tabla operativa |
| Incidentes | Resumen compacto y línea temporal sin cajas |
| Causalidad | Franja causal y dos áreas de evidencia |
| Preventivo | Dos franjas métricas, tres áreas de evidencia y gráfica abierta |
| Salud TDM | Seis series distribuidas en tres gráficas abiertas |

## Invariantes funcionales

- Se conservan todos los bindings existentes en las vistas.
- Los comandos de detalle continúan asociados a los mismos ViewModels.
- La barra superior mantiene cuatro botones de 40 × 40 px y el botón Actualizar de 38 × 38 px; los cinco iconos permanecen en 24 × 24 px.
- El cronómetro conserva su columna fija, fuente integrada, pausa, reanudación y reinicio manual.
- La exportación conserva selector de carpeta, validación de HTML/JSON y revelado del archivo.
- Las columnas de Servicios/Dependencias conservan la geometría fija 18,*,118,122.
- CPU, memoria, red, duración, recursos abiertos e hilos mantienen sus series, máximos y umbrales.
- Las pestañas principales e internas comparten el estilo global de 14 px, peso Medium y espaciado aprobado.
- Actualizar permanece centrado dentro de su columna fija de 40 px y conserva `RefreshFromToolbarCommand`.
- CPU y memoria de TDM mantienen escalas porcentuales comunes, con umbrales independientes ligados a la configuración vigente.
- Los umbrales de memoria se almacenan, validan y representan directamente como porcentaje.
- Los nombres de servicio permanecen intactos; sólo se traducen estados y nombres funcionales de presentación.

## Validaciones incorporadas

VERIFY-TDM-READINESS.ps1 comprueba:

- parseo XML de todos los archivos AXAML;
- presencia de los cuatro estilos estructurales de FIX88;
- ausencia del radio genérico de 14 px;
- composición específica de las once pestañas;
- conservación de las reglas funcionales acumuladas de FIX65 a FIX87;
- retícula y bandas de umbral de baja intensidad;
- tamaño global de 14 px para todos los títulos de pestaña;
- conexión de los cuatro umbrales configurables de CPU/memoria de TDM;
- conversión de MB a porcentaje para los umbrales gráficos de memoria;
- ausencia de estados operativos ingleses en las tarjetas preventivas;
- clasificación correcta de `SIN FALLA` como estado saludable;
- contrato porcentual de memoria de TDM con rango válido de 0.1 a 100;
- conservación de las columnas `260,126,126` y controles de 118 px en la fila modificada;
- ausencia del bloque visual de estado/ruta/recarga solicitado;
- encabezado único `CONFIGURACIÓN`;
- compilación Release con advertencias tratadas como errores;
- pruebas de paridad;
- inicio real de GUI y Notifier;
- estructura limpia del paquete.

## Resultado estático en el entorno de preparación

- 18 archivos AXAML analizados.
- 0 errores XML.
- 0 bindings eliminados.
- 1 uso adicional de Accent para el marcador visual de la línea de incidentes.
- 0 cambios en servicios de recopilación, persistencia, notificaciones o exportación.
- 1 cambio visual global: `TabItem.FontSize`, de 12 a 14 px.
- 1 ajuste de FIX90: área interactiva de Actualizar, de 40 × 40 a 38 × 38 px.
- FIX91 amplía `LineChart` con umbrales independientes por serie y actualiza únicamente la presentación/cálculo gráfico de Salud TDM y Preventivo.
- FIX92 sustituye los campos persistentes `TdmRamWarningMb` y `TdmRamCriticalMb` por `TdmMemoryWarningPercent` y `TdmMemoryCriticalPercent`.

La compilación y la prueba de inicio requieren Windows con .NET SDK 8; el gate incluido ejecuta ambas antes de considerar la entrega validada en el equipo de destino.
