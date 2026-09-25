# Distribución TDM

## Publicación por componentes
Ejecute `PUBLISH-DISTRIBUCION-WIN-X64.cmd` en Windows con .NET SDK 8 instalado. Genera:

- `dist\TDM-win-x64\App\TDM.Application.exe`
- `dist\TDM-win-x64\Service\TDM.Service.exe`
- `dist\TDM-win-x64\Notifier\TDM.Notifier.exe`

Las publicaciones son `win-x64` y `self-contained`.

## Ejecutable portable

Ejecute `PUBLISH-PORTABLE-WIN-X64.cmd` para generar:

`dist\TDM-portable-win-x64\TDM.exe`

Este archivo puede copiarse y ejecutarse directamente en otro equipo Windows x64. No necesita instalación, SDK de .NET ni los directorios `App`, `Service` o `Notifier`. El monitoreo local y las notificaciones funcionan dentro del mismo proceso mientras `TDM.exe` permanece abierto.

La edición portable prioriza el arranque: utiliza ReadyToRun, no comprime el bundle de archivo único y realiza la primera captura diagnóstica en segundo plano. Algunas fuentes protegidas de Windows o TSplus pueden requerir ejecutar `TDM.exe` como administrador.

## Instalador EXE
Ejecute `CREAR-INSTALADOR-EXE.cmd` desde PowerShell o CMD. El script cierra la GUI y el Notifier si están abiertos, restaura específicamente para `win-x64` y publica un instalador .NET autocontenido para generar:

`dist\TDM-Setup-x64.exe`

El instalador copia los componentes a `%ProgramFiles%\TDM`, registra `TDM.Service` como servicio automático y crea un acceso directo al escritorio.

Durante el empaquetado, los tres componentes se guardan temporalmente en `installer-work\payload.zip`. El proyecto del instalador integra ese payload y el procedimiento de instalación dentro del EXE único.

El equipo que recibe `TDM-Setup-x64.exe` no necesita código fuente, SDK de .NET ni compilación. El runtime requerido queda incluido en los ejecutables autocontenidos.

No reutilice un archivo `TDM-Setup-x64.exe` anterior: el script elimina el instalador previo y comprueba que `dotnet publish` haya creado uno nuevo con tamaño mayor que cero antes de indicar éxito.

Al ejecutar el instalador en el equipo destino, Windows solicitará permisos de administrador. Si ocurre un fallo, consulte `%TEMP%\TDM-Setup.log`.

Use el instalador cuando TDM deba continuar monitoreando después de cerrar la interfaz. Use `TDM.exe` portable para validaciones rápidas o ejecución bajo demanda.
