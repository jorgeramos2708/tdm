<#
.SYNOPSIS
  Watchdog externo de TDM.Service: reinicia el servicio si muere o si su
  heartbeat deja de actualizarse. No modifica configuracion de TDM.
.DESCRIPTION
  - Sin parametros (o -Register): crea una tarea programada que ejecuta -Check
    cada N minutos como SYSTEM.
  - -Check: una sola pasada (la invoca la tarea programada).
  - -Unregister: elimina la tarea programada.
  Opt-out para mantenimientos: si existe el archivo "watchdog.pause" junto al
  heartbeat, -Check no hace nada hasta que se elimine.
.EXAMPLE
  .\Register-TdmWatchdog.ps1
  .\Register-TdmWatchdog.ps1 -Unregister
#>
[CmdletBinding()]
param(
    [string]$ServiceName = "TDM Service",
    [int]$MaxAgeSeconds = 180,
    [string]$TaskName = "TDM Watchdog",
    [int]$IntervalMinutes = 5,
    [switch]$Register,
    [switch]$Unregister,
    [switch]$Check
)

$ErrorActionPreference = "Stop"

function Get-HeartbeatPath {
    return Join-Path $env:ProgramData "TSplus Diagnostic Monitor\Data\runtime\service-heartbeat.json"
}

function Write-WatchdogLog([string]$Message) {
    try {
        $log = Join-Path (Split-Path (Get-HeartbeatPath) -Parent) "watchdog.log"
        if ((Test-Path $log) -and ((Get-Item $log).Length -gt 1MB)) {
            Move-Item $log ($log + ".old") -Force
        }
        Add-Content $log ("{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message)
    } catch { }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-WatchdogCheck {
    param([string]$Name, [int]$MaxAge)

    $hbPath = Get-HeartbeatPath
    $pauseFile = Join-Path (Split-Path $hbPath -Parent) "watchdog.pause"
    if (Test-Path $pauseFile) {
        Write-WatchdogLog "SKIP: watchdog.pause presente (ventana de mantenimiento)."
        return 0
    }

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        Write-WatchdogLog "WARN: servicio '$Name' no encontrado; no se puede vigilar."
        return 2
    }
    if ($service.Status -ne "Running") {
        Write-WatchdogLog "RESTART: servicio '$Name' en estado $($service.Status); intentando arranque."
        try {
            Start-Service -Name $Name -ErrorAction Stop
            Write-WatchdogLog "OK: servicio '$Name' arrancado."
            return 1
        } catch {
            Write-WatchdogLog "FAIL: no se pudo arrancar '$Name': $($_.Exception.Message)"
            return 1
        }
    }

    # Servicio en ejecucion: el heartbeat decide si el ciclo sigue vivo.
    # 150 s es el umbral interno de frescura (Q8); aqui se usa MaxAgeSeconds.
    if (-not (Test-Path $hbPath)) {
        Write-WatchdogLog "RESTART: servicio en ejecucion pero sin heartbeat; reiniciando '$Name'."
        try { Restart-Service -Name $Name -Force -ErrorAction Stop; Write-WatchdogLog "OK: reinicio ordenado." }
        catch { Write-WatchdogLog "FAIL: reinicio fallido: $($_.Exception.Message)" }
        return 1
    }
    try {
        $hb = Get-Content $hbPath -Raw | ConvertFrom-Json
        $ts = [DateTimeOffset]::Parse($hb.timestamp)
        $age = ((Get-Date).ToUniversalTime() - $ts.UtcDateTime).TotalSeconds
        if ($age -gt $MaxAge) {
            Write-WatchdogLog ("RESTART: heartbeat rancio ({0:N0} s > {1} s); reiniciando '{2}'." -f $age, $MaxAge, $Name)
            try { Restart-Service -Name $Name -Force -ErrorAction Stop; Write-WatchdogLog "OK: reinicio ordenado." }
            catch { Write-WatchdogLog "FAIL: reinicio fallido: $($_.Exception.Message)" }
            return 1
        }
    } catch {
        Write-WatchdogLog "WARN: heartbeat ilegible ($($_.Exception.Message)); no se actúa."
        return 0
    }
    return 0
}

if ($Unregister) {
    schtasks /Delete /TN $TaskName /F
    Write-Output "Tarea '$TaskName' eliminada."
    return
}

if ($Check) {
    exit (Invoke-WatchdogCheck -Name $ServiceName -MaxAge $MaxAgeSeconds)
}

# Registro (accion por defecto).
if (-not (Test-IsAdmin)) {
    Write-Error "Ejecute como administrador para registrar la tarea programada."
    exit 1
}
$script = $MyInvocation.MyCommand.Path
$action = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`" -Check -ServiceName `"$ServiceName`" -MaxAgeSeconds $MaxAgeSeconds"
schtasks /Create /TN $TaskName /TR $action /SC MINUTE /MO $IntervalMinutes /RU SYSTEM /RL HIGHEST /F
if ($LASTEXITCODE -ne 0) { Write-Error "schtasks fallo con codigo $LASTEXITCODE."; exit 1 }
Write-Output "Watchdog registrado: tarea '$TaskName' cada $IntervalMinutes min como SYSTEM."
Write-Output "Vigila servicio '$ServiceName' + heartbeat (max $MaxAgeSeconds s)."
Write-Output "Para pausar en mantenimientos: cree el archivo watchdog.pause junto al heartbeat."
Write-Output "Para eliminar: .\Register-TdmWatchdog.ps1 -Unregister"
