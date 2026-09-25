$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $root

function Require([bool]$ok,[string]$message) { if(-not $ok){ throw $message } }
function Get-Sha256Hex([string]$path) {
    $stream = [System.IO.File]::OpenRead($path)
    try {
        $algorithm = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '')
        }
        finally {
            $algorithm.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}
function Step([string]$label,[scriptblock]$body) {
    Write-Host "`n$label" -ForegroundColor Cyan
    & $body
}

try {
    Write-Host '============================================================'
    Write-Host 'TDM Readiness Gate - CLEAN'
    Write-Host '============================================================'

    Step '[1/7] Validación estática...' {
        $required = @(
            'src\TDM.Gui.Avalonia\TDM.Gui.Avalonia.csproj',
            'src\TDM.Notifier.Avalonia\TDM.Notifier.Avalonia.csproj',
            'src\TDM.Service\TDM.Service.csproj',
            'src\TDM.Application\TDM.Application.csproj',
            'tests\TDM.AvaloniaParityTests\TDM.AvaloniaParityTests.csproj',
            'tests\TDM.ProductionTests\TDM.ProductionTests.csproj',
            'tests\TDM.ProductionTests\Program.cs',
            'src\TDM.Core\CollectorCursorStore.cs',
            'src\TDM.Collectors.Windows\TsplusWindowsFunctionalDependencyCollector.cs',
            'src\TDM.Notifications\AlertTitleFormatter.cs',
            'src\TDM.Models\TdmVisibleText.cs',
            'src\TDM.Notifications\NotificationSignalPolicy.cs',
            'src\TDM.Gui.Avalonia\Assets\tdm-logo.png',
            'src\TDM.Gui.Avalonia\Assets\tdm-logo.ico',
            'src\TDM.Gui.Avalonia\Assets\Fonts\DejaVuSansMono-Bold.ttf',
            'src\TDM.Gui.Avalonia\Assets\Fonts\LICENSE-DejaVu.txt',
            'src\TDM.Gui.Avalonia\Assets\Icons\LICENSE-LUCIDE.txt',
            'src\TDM.Gui.Avalonia\TdmFontCollection.cs',
            'installer\TDM.Installer\TDM.Installer.csproj',
            'installer\TDM.Installer\Program.cs',
            'installer\TDM.Installer\Install-TDM.cmd',
            'installer\TDM.Installer\app.manifest',
            'PUBLISH-PORTABLE-WIN-X64.cmd',
            'src\TDM.Core\PortableRuntime.cs',
            'src\TDM.Gui.Avalonia\Services\ResumableExecutionClock.cs',
            'src\TDM.Gui.Avalonia\Views\PortableNotificationWindow.axaml',
            'src\TDM.Gui.Avalonia\Views\PortableNotificationWindow.axaml.cs',
            'src\TDM.Gui.Avalonia\Views\PortableNotificationCoordinator.cs'
        )
        foreach($f in $required){ Require (Test-Path -LiteralPath (Join-Path $root $f)) "Falta $f" }

        $gui = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\TDM.Gui.Avalonia.csproj') -Raw -Encoding UTF8
        $notifier = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Notifier.Avalonia\TDM.Notifier.Avalonia.csproj') -Raw -Encoding UTF8
        $applicationCore = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Application\TDM.Application.csproj') -Raw -Encoding UTF8
        $notifierApp = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Notifier.Avalonia\App.axaml.cs') -Raw -Encoding UTF8
        $guiProgram = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Program.cs') -Raw -Encoding UTF8
        $fontCollection = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\TdmFontCollection.cs') -Raw -Encoding UTF8
        Require ($gui.Contains('<AvaloniaVersion>11.1.3</AvaloniaVersion>')) 'GUI no está fijada en la versión 11.1.3 del framework.'
        Require ($notifier.Contains('<AvaloniaVersion>11.1.3</AvaloniaVersion>')) 'Notifier no está fijado en la versión 11.1.3 del framework.'
        Require ($gui.Contains('>TDM.Application</AssemblyName>')) 'La GUI no genera TDM.Application.exe.'
        Require ($gui.Contains('>TDM</AssemblyName>')) 'La compilación portable no genera TDM.exe.'
        Require ($gui.Contains('TDM_PORTABLE')) 'La GUI no contiene la variante portable integrada.'
        Require ($notifier.Contains('<AssemblyName>TDM.Notifier</AssemblyName>')) 'El Notifier no genera TDM.Notifier.exe.'
        Require ($gui.Contains('>TDM.Desktop.Application</PackageId>')) 'La GUI no tiene un PackageId interno único.'
        Require ($gui.Contains('>TDM.Desktop.Portable</PackageId>')) 'La variante portable no tiene un PackageId interno único.'
        Require ($notifier.Contains('<PackageId>TDM.Desktop.Notifier</PackageId>')) 'El Notifier no tiene un PackageId interno único.'
        Require ($applicationCore.Contains('<AssemblyName>TDM.Application.Core</AssemblyName>')) 'La biblioteca de aplicación colisiona con TDM.Application.exe.'
        Require ($applicationCore.Contains('<PackageId>TDM.Application.Core</PackageId>')) 'La biblioteca de aplicación no tiene un PackageId único.'
        Require ($notifierApp.Contains('TDM_AVALONIA_NOTIFIER_READINESS_PROBE')) 'Notifier no contiene el modo aislado de readiness.'
        Require ($notifierApp.Contains('TDM_AVALONIA_NOTIFIER_READY_FILE')) 'Notifier no contiene el marcador de readiness.'
        Require ($notifierApp.Contains('TryTakeOverNotifierFromAnotherDelivery')) 'Notifier no puede sustituir una instancia cargada desde otra entrega.'
        Require ($gui.Contains('<ApplicationIcon>Assets\tdm-logo.ico</ApplicationIcon>')) 'Falta icono de aplicación.'
        Require ($notifier.Contains('<ApplicationIcon>..\TDM.Gui.Avalonia\Assets\tdm-logo.ico</ApplicationIcon>')) 'El Notifier no usa el nuevo icono TDM.'
        $serviceProject = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Service\TDM.Service.csproj') -Raw -Encoding UTF8
        Require ($serviceProject.Contains('<ApplicationIcon>..\TDM.Gui.Avalonia\Assets\tdm-logo.ico</ApplicationIcon>')) 'El servicio no usa el nuevo icono TDM.'
        $logoPngHash = Get-Sha256Hex (Join-Path $root 'src\TDM.Gui.Avalonia\Assets\tdm-logo.png')
        $logoIcoHash = Get-Sha256Hex (Join-Path $root 'src\TDM.Gui.Avalonia\Assets\tdm-logo.ico')
        $timerFontHash = Get-Sha256Hex (Join-Path $root 'src\TDM.Gui.Avalonia\Assets\Fonts\DejaVuSansMono-Bold.ttf')
        Require ($logoPngHash -eq 'A58E7A9EBBC99AD98C1787EE02C2DBCD7B356D824BBA2B6B67B15ACA1C104564') 'La cabecera no contiene el logotipo aprobado.'
        Require ($logoIcoHash -eq '10AB66591B33C5008626DB10CCE4065CF27CD20D37B6EC21195818A9C88BF9EF') 'Los ejecutables no contienen el icono multirresolución aprobado.'
        Require ($timerFontHash -eq '3A3C502EEFF669A231549E80DF9F7C49DE109BAFE303170409E905D0B31A38FE') 'La tipografía integrada del cronómetro no coincide con la vista previa aprobada.'
        Require ($gui.Contains('<AvaloniaResource Include="Assets\**" />')) 'Los recursos de fuente e iconos no se integran en la aplicación.'
        Require ($guiProgram.Contains('fontManager.AddFontCollection(new TdmFontCollection())')) 'La GUI no registra la fuente integrada del cronómetro.'
        Require ($fontCollection.Contains('new Uri("fonts:Tdm", UriKind.Absolute)')) 'La colección de fuentes no expone el identificador fonts:Tdm.'
        Require ($fontCollection.Contains('typeof(TdmFontCollection).Assembly.GetName().Name')) 'La fuente no resuelve dinámicamente los ensamblados instalado y portable.'

        $allAxaml = Get-ChildItem -Path (Join-Path $root 'src') -Filter *.axaml -Recurse
        foreach($file in $allAxaml){
            $raw = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
            Require (-not $raw.Contains('ColumnSpacing=')) "API no compatible detectada: ColumnSpacing en $($file.FullName)"
            Require (-not $raw.Contains('RowSpacing=')) "API no compatible detectada: RowSpacing en $($file.FullName)"
            Require (-not [regex]::IsMatch($raw, '(?i)(Text|Content|Title|ToolTip\.Tip)\s*=\s*"[^"]*Avalonia')) "Nombre técnico visible detectado en $($file.FullName)"
            [xml]$null = $raw
        }

        $visibleSanitizer = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Models\TdmVisibleText.cs') -Raw -Encoding UTF8
        $notificationDispatcher = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Notifications\NotificationDispatcher.cs') -Raw -Encoding UTF8
        $notificationSignalPolicy = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Notifications\NotificationSignalPolicy.cs') -Raw -Encoding UTF8
        $alertTitleFormatter = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Notifications\AlertTitleFormatter.cs') -Raw -Encoding UTF8
        $diagnosticEventCatalog = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Models\DiagnosticEventCatalog.cs') -Raw -Encoding UTF8
        $diagnosticEngine = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Core\DiagnosticEngine.cs') -Raw -Encoding UTF8
        $resourceTrend = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Persistence\ResourceTrendAnalyzer.cs') -Raw -Encoding UTF8
        $functionalDependencies = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Collectors.Windows\TsplusWindowsFunctionalDependencyCollector.cs') -Raw -Encoding UTF8
        $collectorCatalog = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Application\CollectorCatalog.cs') -Raw -Encoding UTF8
        $observabilityStore = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Persistence\ObservabilityStore.cs') -Raw -Encoding UTF8
        $servicesDashboard = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\ViewModels\ServicesDashboardViewModel.cs') -Raw -Encoding UTF8
        $rootCauseCorrelator = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Correlation\RootCauseCorrelator.cs') -Raw -Encoding UTF8
        $printingCollector = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Collectors.Windows\PrintingHealthCollector.cs') -Raw -Encoding UTF8
        Require ($visibleSanitizer.Contains('TDM.Notifier.exe')) 'Falta el nombre público TDM.Notifier.exe en el sanitizador.'
        Require ($visibleSanitizer.Contains('TDM.Application.exe')) 'Falta el nombre público TDM.Application.exe en el sanitizador.'
        Require ($notificationDispatcher.Contains('TdmVisibleText.Sanitize')) 'Las notificaciones no aplican el sanitizador global.'
        Require ($notificationDispatcher.Contains('NotificationSignalPolicy.CanonicalKey')) 'Las notificaciones no consolidan eventos equivalentes de un mismo crash.'
        Require ($notificationSignalPolicy.Contains('"PROCESS_CRASH"')) 'Falta la identidad canónica para crashes correlacionados.'
        Require ($alertTitleFormatter.Contains('memoria libre en descenso')) 'Las alertas de memoria no usan un título explícito.'
        Require ($functionalDependencies.Contains('TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE')) 'Falta el mapa funcional TSplus -> Windows.'
        Require ($functionalDependencies.Contains('"Universal Printer", "Spooler"')) 'Universal Printer no está relacionado funcionalmente con Spooler.'
        Require ($functionalDependencies.Contains('"Virtual Printer", "Spooler"')) 'Virtual Printer no está relacionado funcionalmente con Spooler.'
        Require ($functionalDependencies.Contains('"Two-Factor Authentication (2FA)", "W32Time"')) '2FA no conserva la dependencia temporal de Windows.'
        Require ($functionalDependencies.Contains('"Remote Access / autenticación de dominio", "Netlogon"')) 'Falta la dependencia condicional AD/Netlogon.'
        Require ($collectorCatalog.Contains('new TsplusWindowsFunctionalDependencyCollector()')) 'El collector funcional TSplus/Windows no está registrado.'
        Require ($observabilityStore.Contains('TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE')) 'Observabilidad no persiste dependencias funcionales TSplus/Windows.'
        Require ($servicesDashboard.Contains('ClassifyDependencyOrigin')) 'La vista de dependencias no atribuye el origen al servicio dependiente.'
        Require ($servicesDashboard.Contains('"Bajo demanda"')) 'La vista vuelve a tratar servicios Manual/Trigger como detenidos.'
        Require ($rootCauseCorrelator.Contains('e.Tipo != "TSPLUS_WINDOWS_FUNCTIONAL_DEPENDENCY_STATE"')) 'El mapa funcional puede autocorrelacionarse como síntoma.'
        Require ($printingCollector.Contains('universalFeatureObserved') -and $printingCollector.Contains('virtualFeatureObserved')) 'Spooler no se valida contra componentes de impresión TSplus detectados.'
        $installDiscovery = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Collectors.Windows\TsplusInstallDiscovery.cs') -Raw -Encoding UTF8
        $systemModels = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Models\DiagnosticModels.cs') -Raw -Encoding UTF8
        $cursorStore = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Core\CollectorCursorStore.cs') -Raw -Encoding UTF8
        $windowsIncremental = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Collectors.Windows\IncrementalWindowsEventCollector.cs') -Raw -Encoding UTF8
        $tsplusIncremental = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Collectors.TSplus\IncrementalTsplusLogCollector.cs') -Raw -Encoding UTF8
        $timeWindow = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Core\DiagnosticTimeWindow.cs') -Raw -Encoding UTF8
        $serviceGraph = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Collectors.Windows\ServiceDependencyGraphCollector.cs') -Raw -Encoding UTF8
        Require ($systemModels.Contains('TsplusDetectionState') -and $systemModels.Contains('NotEvaluated')) 'El modelo no conserva el estado trivalente de detección TSplus.'
        Require ($installDiscovery.Contains('FileSystemProbe.Directory') -and $installDiscovery.Contains('TsplusDetectionState.NotEvaluated')) 'La detección TSplus todavía puede convertir un error de acceso en ausencia.'
        Require ($cursorStore.Contains('El cursor existe pero está vacío o no contiene un estado válido.')) 'CollectorCursorStore no distingue cursor corrupto de cursor inexistente.'
        Require ($windowsIncremental.Contains('_forceReplayAfterCursorLoss')) 'EventLog incremental no activa replay cuando pierde el cursor durable.'
        Require ($tsplusIncremental.Contains('_forceReplayAfterCursorLoss')) 'Logs TSplus incrementales no detectan pérdida de cursor durable.'
        Require ($timeWindow.Contains('timestamps.Min()') -and $timeWindow.Contains('timestamps.Max()')) 'DiagnosticTimeWindow todavía descarta hallazgos usando sólo el primer timestamp.'
        Require ($serviceGraph.Contains('WindowsServiceCatalog.ShouldWarnWhenStopped(status, startMode, requiredNow)')) 'El grafo SCM volvió a usar una semántica de estado distinta al collector principal.'
        Require (-not $resourceTrend.Contains('Memoria / tendencia')) 'La etiqueta obsoleta Memoria / tendencia sigue presente.'
        Require (-not $resourceTrend.Contains('CPU / tendencia')) 'La etiqueta obsoleta CPU / tendencia sigue presente.'
        Require (-not $notificationDispatcher.Contains('NotificationTransition.Recovered')) 'NotificationDispatcher todavía emite recuperaciones visibles.'
        Require ($diagnosticEventCatalog.Contains('if (e.Timestamp is null')) 'Las incidencias funcionales todavía aceptan IngestedAt como EventTime.'
        Require ($diagnosticEngine.Contains('IsNonTemporalContext')) 'DiagnosticEngine no separa evidencia sin tiempo de la causalidad.'
        $tolerantQueries = @(Get-ChildItem -Path (Join-Path $root 'src') -Filter *.cs -Recurse | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8).Contains('TolerateQueryErrors = true') })
        Require ($tolerantQueries.Count -eq 0) 'Persisten consultas EventLog con TolerateQueryErrors=true que pueden ocultar cobertura parcial.'

        $projectIdentities = foreach($projectFile in Get-ChildItem -Path (Join-Path $root 'src'),(Join-Path $root 'tests') -Filter *.csproj -Recurse){
            [xml]$projectXml = Get-Content -LiteralPath $projectFile.FullName -Raw -Encoding UTF8
            $packageIdNode = @($projectXml.Project.PropertyGroup.PackageId) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -First 1
            $assemblyNameNode = @($projectXml.Project.PropertyGroup.AssemblyName) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -First 1
            $projectBaseName = [System.IO.Path]::GetFileNameWithoutExtension($projectFile.Name)
            $assemblyName = if($assemblyNameNode){ [string]$assemblyNameNode } else { $projectBaseName }
            $restoreName = if($packageIdNode){ [string]$packageIdNode } else { $assemblyName }
            [pscustomobject]@{ RestoreName = $restoreName; AssemblyName = $assemblyName; Project = $projectFile.FullName }
        }
        $duplicateRestoreNames = @($projectIdentities | Group-Object RestoreName | Where-Object Count -gt 1)
        $duplicateAssemblyNames = @($projectIdentities | Group-Object AssemblyName | Where-Object Count -gt 1)
        Require ($duplicateRestoreNames.Count -eq 0) ("Identidad NuGet ambigua: " + (($duplicateRestoreNames | ForEach-Object Name) -join ', '))
        Require ($duplicateAssemblyNames.Count -eq 0) ("Nombre de ensamblado ambiguo: " + (($duplicateAssemblyNames | ForEach-Object Name) -join ', '))

        $diagVm = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\ViewModels\DiagnosticWorkspaceViewModel.cs') -Raw -Encoding UTF8
        $mainWindowVm = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\ViewModels\MainWindowViewModel.cs') -Raw -Encoding UTF8
        $diagnosticService = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Services\DiagnosticExecutionService.cs') -Raw -Encoding UTF8
        $executionClock = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Services\ResumableExecutionClock.cs') -Raw -Encoding UTF8
        $diagnosticView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\DiagnosticWorkspaceView.axaml') -Raw -Encoding UTF8
        $parityTests = Get-Content -LiteralPath (Join-Path $root 'tests\TDM.AvaloniaParityTests\Program.cs') -Raw -Encoding UTF8
        Require ($diagVm.Contains('Task.Delay(TimeSpan.FromSeconds(1), ct)')) 'El timer no conserva actualización de 1 segundo.'
        Require ($diagVm.Contains('DiagnosticCycleInterval = TimeSpan.FromSeconds(5)')) 'Falta el ciclo diagnóstico continuo de 5 s.'
        Require ($diagVm.Contains('while (!runCts.IsCancellationRequested)')) 'El diagnóstico no conserva ejecución continua.'
        Require ($diagVm.Contains('private readonly ResumableExecutionClock _executionClock = new();')) 'El cronómetro no utiliza acumulación reanudable.'
        Require (-not $diagVm.Contains('_executionStopwatch')) 'El cronómetro conserva la implementación anterior que reiniciaba al ejecutar.'
        Require (-not $diagVm.Contains('.Restart()')) 'Existe un reinicio implícito del cronómetro al ejecutar.'
        Require ($diagVm.Contains('runCts.CancelAfter(_executionLimit.Value - elapsedBeforeStart)')) 'Al reanudar no se respeta el tiempo acumulado del periodo.'
        Require ($diagVm.Contains('public void ResetExecutionTimer()')) 'Falta el reinicio explícito del cronómetro.'
        Require (([regex]::Matches($mainWindowVm, 'Diagnostics\.ResetExecutionTimer\(\);')).Count -eq 1) 'El cronómetro debe reiniciarse exclusivamente desde la actualización manual.'
        Require ($mainWindowVm.Contains('public Task RefreshAsync() => RefreshAllAsync();')) 'El refresco automático no está aislado del reinicio manual del cronómetro.'
        Require ($mainWindowVm.Contains('private async Task RefreshFromToolbarAsync()')) 'Falta el comando de actualización manual.'
        Require ($executionClock.Contains('_accumulated += _activeSegment.Elapsed;')) 'Pausar no conserva el segmento de tiempo activo.'
        Require ($executionClock.Contains('public void Reset(bool continueRunning)')) 'El reloj acumulativo no expone un reinicio controlado.'
        Require ($diagVm.Contains('SelectExportDirectoryAsync')) 'La descarga no solicita una carpeta de destino.'
        Require ($diagVm.Contains('File.Exists(result.HtmlPath)') -and $diagVm.Contains('File.Exists(result.JsonPath)')) 'La descarga no valida los dos archivos generados.'
        Require ($diagnosticService.Contains('ExportAsync(DiagnosticReport report, string directory, CancellationToken ct)')) 'El servicio no permite exportar a la carpeta elegida.'
        Require ($diagnosticView.Contains('IsVisible="{Binding HasExportStatus}"') -and $diagnosticView.Contains('Text="{Binding ExportStatus}"')) 'La descarga no muestra una confirmación visible.'
        Require ($parityTests.Contains('ExecutionClock_PauseResumeAndExplicitReset')) 'Falta la prueba de pausa, reanudación y reinicio explícito.'
        Require ($parityTests.Contains('ReportExport_SelectedDirectoryCreatesHtmlAndJson')) 'Falta la prueba de exportación HTML/JSON.'

        $window = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\MainWindow.axaml') -Raw -Encoding UTF8
        $applicationStyles = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\App.axaml') -Raw -Encoding UTF8
        $servicesView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\ServicesDashboardView.axaml') -Raw -Encoding UTF8
        $servicesVm = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\ViewModels\ServicesDashboardViewModel.cs') -Raw -Encoding UTF8
        $supportView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\SupportDashboardView.axaml') -Raw -Encoding UTF8
        $supportVm = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\ViewModels\SupportDashboardViewModel.cs') -Raw -Encoding UTF8
        $tsplusVm = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\ViewModels\TsplusDashboardViewModel.cs') -Raw -Encoding UTF8
        $notifierPopup = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Notifier.Avalonia\PopupWindow.axaml') -Raw -Encoding UTF8
        $notifierPopupCode = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Notifier.Avalonia\PopupWindow.axaml.cs') -Raw -Encoding UTF8
        $startScript = Get-Content -LiteralPath (Join-Path $root 'START-TDM.cmd') -Raw -Encoding UTF8
        $installerScript = Get-Content -LiteralPath (Join-Path $root 'CREAR-INSTALADOR-EXE.cmd') -Raw -Encoding UTF8
        $installerProject = Get-Content -LiteralPath (Join-Path $root 'installer\TDM.Installer\TDM.Installer.csproj') -Raw -Encoding UTF8
        $installerProgram = Get-Content -LiteralPath (Join-Path $root 'installer\TDM.Installer\Program.cs') -Raw -Encoding UTF8
        $installerCommand = Get-Content -LiteralPath (Join-Path $root 'installer\TDM.Installer\Install-TDM.cmd') -Raw -Encoding UTF8
        $installerManifest = Get-Content -LiteralPath (Join-Path $root 'installer\TDM.Installer\app.manifest') -Raw -Encoding UTF8
        $publisherScript = Get-Content -LiteralPath (Join-Path $root 'PUBLISH-DISTRIBUCION-WIN-X64.cmd') -Raw -Encoding UTF8
        $portablePublisher = Get-Content -LiteralPath (Join-Path $root 'PUBLISH-PORTABLE-WIN-X64.cmd') -Raw -Encoding UTF8
        $integratedMonitor = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Services\IntegratedMonitoringService.cs') -Raw -Encoding UTF8
        $mainWindowCode = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\MainWindow.axaml.cs') -Raw -Encoding UTF8
        $portablePopup = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\PortableNotificationWindow.axaml') -Raw -Encoding UTF8
        $portablePopupCode = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\PortableNotificationWindow.axaml.cs') -Raw -Encoding UTF8
        $startBytes = [System.IO.File]::ReadAllBytes((Join-Path $root 'START-TDM.cmd'))
        $bareLf = 0
        for($i = 0; $i -lt $startBytes.Length; $i++){
            if($startBytes[$i] -eq 10 -and ($i -eq 0 -or $startBytes[$i - 1] -ne 13)){ $bareLf++ }
        }
        $incidentsView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\IncidentsDashboardView.axaml') -Raw -Encoding UTF8
        $dashboardRules = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\ViewModels\DashboardSupport.cs') -Raw -Encoding UTF8
        $performanceView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\PerformanceDashboardView.axaml') -Raw -Encoding UTF8
        $preventiveView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\PreventiveDashboardView.axaml') -Raw -Encoding UTF8
        $tdmHealthView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\TdmHealthDashboardView.axaml') -Raw -Encoding UTF8
        $tdmHealthVm = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\ViewModels\TdmHealthDashboardViewModel.cs') -Raw -Encoding UTF8
        $operationalHealthAnalyzer = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Correlation\OperationalHealthAnalyzer.cs') -Raw -Encoding UTF8
        $administrationView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\AdministrationWorkspaceView.axaml') -Raw -Encoding UTF8
        $administrationVm = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\ViewModels\AdministrationWorkspaceViewModel.cs') -Raw -Encoding UTF8
        $supportMonitoringSettings = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Persistence\SupportMonitoringSettings.cs') -Raw -Encoding UTF8
        $sessionsView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\SessionsDashboardView.axaml') -Raw -Encoding UTF8
        $causalityView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\CausalityDashboardView.axaml') -Raw -Encoding UTF8
        $tsplusView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\TsplusDashboardView.axaml') -Raw -Encoding UTF8
        $multiServerView = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Views\MultiServerDashboardView.axaml') -Raw -Encoding UTF8
        $lineChartControl = Get-Content -LiteralPath (Join-Path $root 'src\TDM.Gui.Avalonia\Controls\LineChart.cs') -Raw -Encoding UTF8
        Require ($window.Contains('Icon="/Assets/tdm-logo.ico"')) 'La ventana no usa el icono TDM.'
        Require ($window.Contains('Source="/Assets/tdm-logo.png"')) 'La cabecera no usa el logo TDM.'
        Require (-not $window.Contains('Background="#071522" BorderBrush="#2A7898"')) 'El logotipo todavía conserva el cuadro exterior de FIX81.'
        Require ($window.Contains('<Image Width="78" Height="78" Source="/Assets/tdm-logo.png"')) 'El logotipo no conserva el tamaño y la presentación sin marco aprobados.'
        Require ($window.Contains('Text="TSplus" FontSize="17" FontWeight="SemiBold" Foreground="#19C8FF"')) 'TSplus no usa el cian aprobado del icono.'
        Require ($window.Contains('Text="Diagnostic" FontSize="19" FontWeight="Bold" Foreground="#EAF7FF"')) 'Diagnostic no usa el blanco frío aprobado del icono.'
        Require ($window.Contains('Text="Monitor" FontSize="19" FontWeight="Bold" Foreground="#35F2C0"')) 'Monitor no usa el verde eléctrico aprobado del icono.'
        Require ([regex]::IsMatch($window, 'Text="Monitoreo y diagnóstico operativo"[^>]*Foreground="#FFFFFF"')) 'El subtítulo no conserva el blanco aprobado.'
        Require (-not $window.Contains('Text="TSplus Diagnostic Monitor"')) 'La cabecera todavía usa el nombre anterior en una sola línea.'
        Require ($window.Contains('<Grid ColumnDefinitions="*,Auto" VerticalAlignment="Center">')) 'La barra superior no mantiene identidad y controles en dos grupos estables.'
        Require ($window.Contains('ColumnDefinitions="40,8,40,12,104,16,40,12,40,12,40" Height="40" VerticalAlignment="Center"')) 'Los controles superiores no comparten la cuadrícula centrada aprobada.'
        Require (([regex]::Matches($window, 'Classes="icon-nav" Width="40" Height="40"')).Count -eq 4) 'Los cuatro botones superiores no modificados no conservan sus áreas de 40 x 40.'
        Require ($window.Contains('Grid.Column="6" Classes="icon-nav" Width="38" Height="38" Command="{Binding RefreshFromToolbarCommand}"')) 'Actualizar no usa el área de interacción de 38 x 38 aprobada para FIX90.'
        Require ($window.Contains('Grid.Column="4" Width="104" Height="40" Background="Transparent" BorderBrush="Transparent" BorderThickness="0"')) 'El cronómetro no conserva su espacio fijo y transparente de 104 x 40.'
        Require (([regex]::Matches($window, '<Viewbox Width="24" Height="24"')).Count -eq 5) 'Los cinco iconos superiores no usan el tamaño uniforme de 24 x 24.'
        Require ($window.Contains('Command="{Binding RefreshFromToolbarCommand}"')) 'Actualizar no usa el comando manual que reinicia el cronómetro.'
        Require ($applicationStyles.Contains('<Style Selector="Button.icon-nav /template/ ContentPresenter">')) 'Falta el estilo interno de los botones superiores.'
        Require (([regex]::Matches($applicationStyles, '<Setter Property="HorizontalAlignment" Value="Stretch"')).Count -ge 1) 'El marco interno de los botones superiores todavía se contrae al tamaño del icono.'
        Require (([regex]::Matches($applicationStyles, '<Setter Property="VerticalAlignment" Value="Stretch"')).Count -ge 1) 'El marco interno de los botones superiores no ocupa los 40 px de altura.'
        Require ($applicationStyles.Contains('<Style Selector="Button.icon-nav:disabled">')) 'Falta el estado deshabilitado de los botones superiores.'
        Require (([regex]::Matches($applicationStyles, '<Setter Property="Background" Value="Transparent"')).Count -ge 4) 'Los botones superiores todavía muestran una caja de fondo.'
        Require ($applicationStyles.Contains('<Setter Property="BorderThickness" Value="0" />')) 'Los botones superiores todavía muestran un borde visible.'
        Require ($window.Contains('TextAlignment="Center" Margin="0,3,0,0"')) 'El cronómetro no conserva el ajuste óptico vertical aprobado.'
        Require ($window.Contains('FontFamily="fonts:Tdm#DejaVu Sans Mono" FontSize="20" FontWeight="Bold"')) 'El cronómetro no utiliza la tipografía integrada de la vista previa.'
        Require (-not [regex]::IsMatch($window, 'ExecutionTimerText\}" FontFamily="Consolas"')) 'El cronómetro todavía depende de Consolas en Windows.'
        Require ($mainWindowCode.Contains('OpenFolderPickerAsync(new FolderPickerOpenOptions')) 'La descarga no abre el selector de carpeta.'
        Require ($mainWindowCode.Contains('vm.Diagnostics.RevealExportedFile = RevealExportedFile;')) 'La descarga no revela el reporte generado.'
        Require (([regex]::Matches($servicesView, 'ColumnDefinitions="18,\*,118,122"')).Count -eq 4) 'Servicios y Dependencias no comparten las columnas fijas acordadas.'
        Require ($servicesVm.Contains('"En ejecución"') -and $servicesVm.Contains('"Detenido"') -and $servicesVm.Contains('"Bajo demanda"') -and $servicesVm.Contains('"No requerido"') -and $servicesVm.Contains('"Complementario"') -and $servicesVm.Contains('"Revisar"') -and $servicesVm.Contains('"No evaluado"')) 'La UI no conserva el contrato explícito de estados operativos.'
        Require ($window.Contains('Points="6,3 20,12 6,21"')) 'Inicio no usa el icono Play vectorial aprobado.'
        Require ($window.Contains('Rectangle Canvas.Left="6" Canvas.Top="4" Width="4" Height="16"')) 'Pausa no usa el icono vectorial aprobado.'
        Require ($window.Contains('Data="M21,12 A9,9 0 1 1 12,3')) 'Actualizar no usa el icono Rotate CW vectorial aprobado.'
        Require ($window.Contains('Data="M21,15 V19 A2,2 0 0 1 19,21')) 'Descargar no usa el icono vectorial aprobado.'
        Require ($window.Contains('M12.22,2 H11.78')) 'Configuración no usa el icono Settings vectorial aprobado.'
        Require (-not $window.Contains('Text="↻"') -and -not $window.Contains('Text="⇩"') -and -not $window.Contains('Text="⚙"')) 'La barra superior todavía depende de glifos del sistema.'
        Require ($window.Contains('Grid.Row="1" Grid.Column="2" ColumnDefinitions="40,8,40,12,104,16,40,12,40,12,40" Height="40" VerticalAlignment="Center"')) 'Selector, acciones y temporizador no comparten la misma fila centrada.'
        Require ($supportView.Contains('Text="MÓDULOS TSPLUS"')) 'Falta la gráfica de módulos TSplus con error/críticos.'
        Require ($supportView.Contains('Text="SERVICIOS / DEPENDENCIAS"')) 'La gráfica operativa no identifica ambos conjuntos.'
        Require ($supportVm.Contains('var total = services.Count + dependencies.Count;')) 'La gráfica operativa no combina servicios y dependencias.'
        Require ($supportVm.Contains('RefreshVisibleDetail();')) 'Ver detalle no se actualiza junto con el snapshot visible.'
        Require ($supportVm.Contains('affected / (double)total')) 'La dona operativa no representa únicamente fallas e incertidumbre como tramo afectado.'
        Require ($supportView.Contains('TrackBrush="{Binding ServiceHealthyAccent}"')) 'La dona operativa no conserva el tramo saludable en verde.'
        Require ($supportView.Contains('TrackBrush="{Binding ModuleHealthyAccent}"')) 'La dona modular no conserva el tramo saludable en verde.'
        Require ($supportVm.Contains('latest.ActiveSessions + latest.DisconnectedSessions')) 'Sesiones no calcula el total observado.'
        Require ($supportView.Contains('Text="TOTAL OBSERVADAS"')) 'La tarjeta Sesiones no identifica su cifra principal.'
        Require ($supportView.Contains('Foreground="{Binding SessionIncidentAccent}"')) 'Sesiones no separa visualmente total e incidentes.'
        Require ($servicesVm.Contains('DashboardRules.TsplusOperationalStates')) 'Servicios/Dependencias no filtra el subgrafo relevante para TSplus.'
        Require ($supportVm.Contains('DashboardRules.TsplusOperationalStates')) 'La dona operativa no usa el mismo filtro de relevancia TSplus.'
        Require ($tsplusVm.Contains('DashboardRules.CompactSlashes')) 'La pestaña TSplus no normaliza espacios alrededor de diagonales.'
        Require (-not $notifierPopup.Contains('MetaText')) 'La notificación todavía muestra transición/severidad/fecha.'
        Require (-not $notifierPopupCode.Contains('MetaText.Text')) 'El código de notificación todavía escribe el pie técnico.'
        Require (-not $notifierPopupCode.Contains('TransitionText(')) 'El Notifier conserva el formateador del pie técnico eliminado.'
        Require ($notifierPopupCode.Contains('FIX93_EXPLICIT_ALERTS_NO_RECOVERED')) 'Falta la revisión FIX93 del Notifier para alertas explícitas sin recuperación.'
        Require ($startScript.Contains('taskkill /IM TDM.Notifier.exe /T /F')) 'El arranque no sustituye una instancia antigua del notificador.'
        Require ($startScript.Contains('taskkill /IM TDM.Notifier.Avalonia.exe /T /F')) 'El arranque no termina una instancia heredada del notificador.'
        Require ($startScript.Contains('FIX93_EXPLICIT_ALERTS_NO_RECOVERED')) 'El arranque no rechaza binarios anteriores a la revisión de alertas FIX93.'
        Require ($installerCommand.Contains('taskkill /IM TDM.Notifier.exe /T /F')) 'El instalador no termina el árbol del Notifier actual.'
        Require ($installerCommand.Contains('taskkill /IM TDM.Notifier.Avalonia.exe /T /F')) 'El instalador no termina el Notifier heredado.'
        Require ($installerCommand.Contains('taskkill /IM TDM.Application.exe /T /F')) 'El instalador no termina la GUI antes de actualizarla.'
        $serviceStopIndex = $installerCommand.IndexOf("Get-Service -Name 'TDM.Service'",[StringComparison]::OrdinalIgnoreCase)
        $serviceCopyIndex = $installerCommand.IndexOf('robocopy "%PAYLOAD%\Service"',[StringComparison]::OrdinalIgnoreCase)
        Require ($serviceStopIndex -ge 0 -and $serviceCopyIndex -ge 0 -and $serviceStopIndex -lt $serviceCopyIndex) 'El instalador intenta copiar el servicio antes de detenerlo.'
        Require ($installerScript.Contains('Compress-Archive -LiteralPath')) 'El instalador no genera el payload ZIP autocontenido.'
        Require ($installerScript.Contains('installer\TDM.Installer\TDM.Installer.csproj')) 'El generador no publica el instalador .NET.'
        Require ($installerScript.Contains('dotnet publish "%PROJECT%"')) 'El generador no invoca dotnet publish para crear el EXE.'
        Require (-not [regex]::IsMatch($installerScript, '(?im)^\s*iexpress\.exe\b')) 'El generador todavía ejecuta IExpress.'
        Require (-not $installerScript.Contains('Class=IEXPRESS')) 'El generador todavía crea archivos SED.'
        Require ($installerScript.Contains('if not exist "%OUT%"')) 'El generador no comprueba la creación real del instalador.'
        Require ($installerProject.Contains('<PublishSingleFile>true</PublishSingleFile>')) 'El instalador no está configurado como archivo único.'
        Require ($installerProject.Contains('LogicalName="TDM.Payload.zip"')) 'El instalador no integra payload.zip como recurso.'
        Require ($installerProject.Contains('LogicalName="TDM.Install.cmd"')) 'El instalador no integra el procedimiento de instalación.'
        Require ($installerProject.Contains('<ApplicationIcon>..\..\src\TDM.Gui.Avalonia\Assets\tdm-logo.ico</ApplicationIcon>')) 'El instalador no usa el icono de TDM.'
        Require ($installerProgram.Contains('GetManifestResourceStream')) 'El instalador no extrae sus recursos integrados.'
        Require ($installerProgram.Contains('TDM-Setup.log')) 'El instalador no conserva un registro de diagnóstico.'
        Require ($installerManifest.Contains('level="requireAdministrator"')) 'El instalador no solicita privilegios administrativos.'
        Require ($portablePublisher.Contains('-p:TdmPortable=true')) 'El publicador portable no activa la compilación de un solo proceso.'
        Require ($portablePublisher.Contains('-p:RestorePackagesWithLockFile=true')) 'El publicador portable no conserva los packages.lock.json durante el restore por RID.'
        Require (-not $portablePublisher.Contains('-p:RestorePackagesWithLockFile=false')) 'El publicador portable contiene la combinación que provoca NU1005 con packages.lock.json existentes.'
        Require ($portablePublisher.Contains('-p:RestoreLockedMode=false')) 'El publicador portable no permite actualizar el grafo win-x64 de los packages.lock.json.'
        Require ($portablePublisher.Contains('-p:PublishReadyToRun=true')) 'El ejecutable portable no activa ReadyToRun.'
        Require ($portablePublisher.Contains('-p:EnableCompressionInSingleFile=false')) 'El ejecutable portable todavía comprime el bundle y penaliza el arranque.'
        Require ($portablePublisher.Contains('if not exist "%OUT%\TDM.exe"')) 'El publicador portable no verifica TDM.exe.'
        Require ($publisherScript.Contains('-p:PublishReadyToRun=true')) 'La aplicación instalada no activa ReadyToRun.'
        Require ($publisherScript.Contains('-p:RestorePackagesWithLockFile=true')) 'La publicación instalada no conserva los packages.lock.json durante el restore de la GUI.'
        Require (-not $publisherScript.Contains('-p:RestorePackagesWithLockFile=false')) 'La publicación instalada contiene la combinación que provoca NU1005 con packages.lock.json existentes.'
        Require ($integratedMonitor.Contains('PortableNotificationsProduced')) 'El monitor integrado no emite avisos en modo portable.'
        Require ($integratedMonitor.Contains('new NotificationDispatcher(')) 'El modo portable no conserva la lógica antirruido.'
        Require ($integratedMonitor.Contains('new SmtpEmailNotificationSink(_writeRoot)')) 'El modo portable no integra las notificaciones de correo configuradas.'
        Require ($integratedMonitor.Contains('_loopTask = Task.Run(() => RunLoopAsync')) 'La primera captura todavía bloquea la apertura de la ventana.'
        $readyMarkerIndex = $mainWindowCode.IndexOf('EmitReadyMarker();',[StringComparison]::Ordinal)
        $initializeIndex = $mainWindowCode.IndexOf('await vm.InitializeAsync();',[StringComparison]::Ordinal)
        Require ($readyMarkerIndex -ge 0 -and $initializeIndex -ge 0 -and $readyMarkerIndex -lt $initializeIndex) 'La ventana espera la inicialización antes de mostrarse lista.'
        Require (-not $portablePopup.Contains('MetaText')) 'La notificación portable muestra metadatos técnicos.'
        Require ($portablePopupCode.Contains('FIX93_EXPLICIT_ALERTS_NO_RECOVERED')) 'Falta la revisión FIX93 de la notificación portable para alertas explícitas sin recuperación.'
        Require (([regex]::Matches($publisherScript, [regex]::Escape('--force-evaluate'))).Count -eq 3) 'La publicación no fuerza las tres restauraciones win-x64.'
        Require (([regex]::Matches($publisherScript, [regex]::Escape('--no-restore'))).Count -eq 3) 'La publicación no separa restore y publish en los tres ejecutables.'
        Require ($publisherScript.Contains('taskkill /IM TDM.Application.exe /T /F')) 'La publicación no cierra la GUI que bloquea los DLL.'
        Require ($publisherScript.Contains('tasklist /FI "IMAGENAME eq TDM.Application.exe"')) 'La publicación no verifica que la GUI haya terminado.'
        Require ($bareLf -eq 0) 'START-TDM.cmd no usa terminadores CRLF compatibles con cmd.exe.'
        Require (-not $startScript.Contains('chcp 65001')) 'START-TDM.cmd no debe cambiar la página de códigos antes de interpretar el lote.'
        Require (-not [regex]::IsMatch($startScript, '(?im)^set\s+"(?:GUI|NOTIFIER)=')) 'START-TDM.cmd volvió a depender de variables que cmd.exe interpretó como et.'
        Require ($incidentsView.Contains('Text="DETALLE"')) 'La línea de incidentes no usa la estructura visual por bloques.'
        Require ($dashboardRules.Contains('DisplayIncidentKey')) 'La línea de incidentes no consolida registros Windows del mismo crash.'
        Require ($performanceView.Contains('Orientation="Horizontal" Spacing="18"')) 'Entrada y Salida no están agrupadas en la leyenda de red.'
        Require ($preventiveView.Contains('Text="{Binding CpuValue}"')) 'La tendencia preventiva no muestra el porcentaje actual de CPU.'
        Require ($preventiveView.Contains('Text="{Binding MemoryValue}"')) 'La tendencia preventiva no muestra el porcentaje actual de memoria.'
        Require ($tdmHealthView.Contains('SeriesBValueSuffix="%"')) 'Salud TDM todavía grafica memoria en MB.'
        Require ($tdmHealthView.Contains('SeriesBLabel="Memoria"') -and -not $tdmHealthView.Contains('SeriesBLabel="Memoria TDM"')) 'La gráfica de Salud TDM no usa la etiqueta Memoria aprobada.'
        Require ($tdmHealthView.Contains('SeriesAWarningThreshold="{Binding CpuWarningThreshold}"') -and $tdmHealthView.Contains('SeriesACriticalThreshold="{Binding CpuCriticalThreshold}"')) 'La gráfica de Salud TDM no conecta los umbrales configurados de CPU.'
        Require ($tdmHealthView.Contains('SeriesBWarningThreshold="{Binding MemoryWarningThreshold}"') -and $tdmHealthView.Contains('SeriesBCriticalThreshold="{Binding MemoryCriticalThreshold}"')) 'La gráfica de Salud TDM no conecta los umbrales configurados de memoria.'
        Require ($tdmHealthVm.Contains('Math.Clamp(thresholds.TdmMemoryWarningPercent') -and $tdmHealthVm.Contains('Math.Clamp(thresholds.TdmMemoryCriticalPercent')) 'Salud TDM no consume directamente los umbrales porcentuales de memoria.'
        Require ($mainWindowVm.Contains('TdmHealth.Apply(result.Samples, Administration.CurrentThresholds);')) 'Salud TDM no recibe la configuración vigente de umbrales.'
        Require ($lineChartControl.Contains('SeriesAWarningThresholdProperty') -and $lineChartControl.Contains('SeriesACriticalThresholdProperty') -and $lineChartControl.Contains('SeriesBWarningThresholdProperty') -and $lineChartControl.Contains('SeriesBCriticalThresholdProperty')) 'LineChart no admite umbrales independientes para ambas series.'
        Require ($dashboardRules.Contains('.Replace("Stopped", "Detenido"') -and $dashboardRules.Contains('.Replace("Running", "En ejecución"')) 'Preventivo no traduce los estados operativos ingleses principales.'
        Require ($dashboardRules.Contains('"Remote Access/RDP" => "Acceso remoto/RDP"') -and $dashboardRules.Contains('"Farm/Gateway" => "Granja/Puerta de enlace"')) 'Preventivo no traduce los nombres funcionales acordados.'
        Require ($operationalHealthAnalyzer.Contains('"SALUDABLE/SIN FALLA OBSERVADA"') -and $operationalHealthAnalyzer.Contains('"SIN FALLA OBSERVADA/COBERTURA LOCAL"')) 'La salud modular conserva espacios alrededor de la diagonal.'
        Require (-not $operationalHealthAnalyzer.Contains('"SALUDABLE / SIN FALLA OBSERVADA"') -and -not $operationalHealthAnalyzer.Contains('"SIN FALLA OBSERVADA / COBERTURA LOCAL"')) 'La salud modular conserva los textos anteriores con espacios.'
        Require ($parityTests.Contains('Preventive_FIX91_LocalizesVisibleOperationalStates') -and $parityTests.Contains('TdmHealth_FIX91_UsesConfiguredCpuAndMemoryThresholds')) 'Faltan las pruebas de paridad de FIX91.'
        Require ($administrationView.Contains('Text="CONFIGURACIÓN" Classes="panel-title"') -and -not $administrationView.Contains('CONFIGURACIÓN Y ESTADO')) 'La vista no usa el encabezado CONFIGURACIÓN aprobado.'
        Require (-not $administrationView.Contains('Text="{Binding ConfigurationSource}"') -and -not $administrationView.Contains('Text="{Binding ConfigurationRoot}"') -and -not $administrationView.Contains('Command="{Binding RefreshCommand}"')) 'La tarjeta superior de estado/configuración todavía está visible.'
        Require ($administrationView.Contains('Text="Memoria de TDM (%)"') -and $administrationView.Contains('Grid.Row="6" ColumnDefinitions="260,126,126"')) 'La fila de memoria no conserva la unidad porcentual o su geometría aprobada.'
        Require (([regex]::Matches($administrationView, 'Value="\{Binding TdmRam(?:Warning|Critical)\}" Minimum="0.1" Maximum="100" Increment="0.5" FormatString="N1"')).Count -eq 2) 'Los controles de memoria de TDM no usan el rango porcentual acordado.'
        Require ($supportMonitoringSettings.Contains('TdmMemoryWarningPercent') -and $supportMonitoringSettings.Contains('TdmMemoryCriticalPercent')) 'La persistencia no contiene los umbrales porcentuales de memoria de TDM.'
        Require (-not $supportMonitoringSettings.Contains('TdmRamWarningMb') -and -not $supportMonitoringSettings.Contains('TdmRamCriticalMb')) 'La persistencia conserva campos de memoria de TDM en MB.'
        Require ($administrationVm.Contains('TdmMemoryWarningPercent = TdmRamWarning') -and $administrationVm.Contains('TdmMemoryCriticalPercent = TdmRamCritical')) 'Configuración no guarda los porcentajes de memoria de TDM.'
        Require ($parityTests.Contains('SupportThresholds_FIX92_ValidatesTdmMemoryAsPercentage')) 'Falta la prueba de validación porcentual de FIX92.'
        Require ($applicationStyles.Contains('<Style Selector="Border.workspace-section">')) 'Falta la superficie abierta para secciones operativas.'
        Require ($applicationStyles.Contains('<Style Selector="Border.workspace-slice">')) 'Falta el divisor vertical para áreas de trabajo.'
        Require ($applicationStyles.Contains('<Style Selector="Border.metric-strip">')) 'Falta la franja métrica sin tarjetas.'
        Require ($applicationStyles.Contains('<Style Selector="Border.metric-cell">')) 'Faltan las celdas métricas separadas por divisores.'
        Require ([regex]::IsMatch($applicationStyles, '(?s)<Style Selector="TabItem">.*?<Setter Property="FontSize" Value="14" />.*?</Style>')) 'Las pestañas principales e internas no usan el tamaño de 14 px aprobado para FIX89.'
        Require (-not $applicationStyles.Contains('<Setter Property="CornerRadius" Value="14" />')) 'La interfaz conserva el estilo anterior de tarjetas redondeadas.'
        Require (-not $supportView.Contains('Classes="card"')) 'Centro de soporte conserva tarjetas genéricas.'
        Require ($supportView.Contains('Classes="workspace-slice"') -and $supportView.Contains('Text="ESTADO OPERATIVO"')) 'Centro de soporte no usa la composición operativa aprobada.'
        Require ($performanceView.Contains('Classes="workspace-slice"') -and $performanceView.Contains('Classes="workspace-section"')) 'Rendimiento no usa áreas abiertas para gráficas y listas.'
        Require ($tsplusView.Contains('Classes="workspace-section"') -and -not $tsplusView.Contains('Classes="card"')) 'TSplus conserva contenedores genéricos.'
        Require ($multiServerView.Contains('Classes="metric-strip"') -and $multiServerView.Contains('Text="CONECTIVIDAD"')) 'Servidores/Granja no contiene la franja y cabecera operativas.'
        Require (-not $servicesView.Contains('CornerRadius="10"') -and -not $servicesView.Contains('Background="#0E1B28"')) 'Servicios/Dependencias conserva cápsulas visuales innecesarias.'
        Require ($sessionsView.Contains('Classes="metric-strip"') -and $sessionsView.Contains('Classes="metric-cell"')) 'Sesiones no usa la franja métrica aprobada.'
        Require ($incidentsView.Contains('Classes="metric-strip"') -and $incidentsView.Contains('Background="Transparent"')) 'Incidentes no usa resumen y línea temporal abiertos.'
        Require ($causalityView.Contains('Classes="metric-strip"') -and $causalityView.Contains('Classes="workspace-slice"')) 'Causalidad no conserva la composición por evidencia y divisores.'
        Require (([regex]::Matches($preventiveView, 'Classes="metric-strip"')).Count -eq 2) 'Preventivo no contiene las dos franjas métricas previstas.'
        Require ($tdmHealthView.Contains('Classes="workspace-slice"') -and $tdmHealthView.Contains('Classes="workspace-section"')) 'Salud TDM conserva contenedores visuales genéricos.'
        Require ($lineChartControl.Contains('Color.FromArgb(72, 27, 49, 66)')) 'Las gráficas no usan la retícula visual reducida de FIX88.'
        Require ($lineChartControl.Contains('Color.FromArgb(9, 255, 209, 102)') -and $lineChartControl.Contains('Color.FromArgb(11, 255, 77, 79)')) 'Las bandas de umbral no usan la intensidad discreta de FIX88.'
        Write-Host '[OK] Estático PASS' -ForegroundColor Green
    }

    Step '[2/7] Limpieza de binarios anteriores...' {
        & dotnet clean '.\TDM.sln' -c Release
        if($LASTEXITCODE -ne 0){ throw "dotnet clean devolvió $LASTEXITCODE" }
    }

    Step '[3/7] Restore reproducible + locked-mode...' {
        & dotnet restore '.\TDM.sln' --force-evaluate -p:RestorePackagesWithLockFile=true
        if($LASTEXITCODE -ne 0){ throw "dotnet restore inicial devolvió $LASTEXITCODE" }

        $projectFiles = @(Get-ChildItem -Path (Join-Path $root 'src'),(Join-Path $root 'tests') -Filter *.csproj -Recurse)
        $lockFiles = @(Get-ChildItem -Path (Join-Path $root 'src'),(Join-Path $root 'tests') -Filter packages.lock.json -Recurse)
        Require ($lockFiles.Count -eq $projectFiles.Count) "packages.lock.json incompletos: $($lockFiles.Count)/$($projectFiles.Count)."

        & dotnet restore '.\TDM.sln' --locked-mode
        if($LASTEXITCODE -ne 0){ throw "dotnet restore --locked-mode devolvió $LASTEXITCODE" }
    }

    Step '[4/7] Build Release warnings-as-errors...' {
        & dotnet build '.\TDM.sln' -c Release --no-restore -warnaserror
        if($LASTEXITCODE -ne 0){ throw "dotnet build devolvió $LASTEXITCODE" }

        $notifierDll = Join-Path $root 'src\TDM.Notifier.Avalonia\bin\Release\net8.0-windows\TDM.Notifier.dll'
        Require (Test-Path -LiteralPath $notifierDll) 'No se generó TDM.Notifier.dll.'
        $serviceDll = Join-Path $root 'src\TDM.Service\bin\Release\net8.0-windows\TDM.Service.dll'
        Require (Test-Path -LiteralPath $serviceDll) 'No se generó TDM.Service.dll.'
        $notifierBinaryBytes = [IO.File]::ReadAllBytes($notifierDll)
        $notifierBinaryUtf8 = [Text.Encoding]::UTF8.GetString($notifierBinaryBytes)
        $notifierBinaryUtf16 = [Text.Encoding]::Unicode.GetString($notifierBinaryBytes)
        Require ($notifierBinaryUtf8.Contains('FIX93_EXPLICIT_ALERTS_NO_RECOVERED') -or $notifierBinaryUtf16.Contains('FIX93_EXPLICIT_ALERTS_NO_RECOVERED')) 'Se generó un Notifier obsoleto sin la revisión FIX93 de alertas explícitas/sin recuperación.'
    }

    Step '[5/7] Pruebas de paridad + producción...' {
        $dll = Join-Path $root 'tests\TDM.AvaloniaParityTests\bin\Release\net8.0-windows\TDM.ParityTests.dll'
        Require (Test-Path $dll) "No existe $dll"
        & dotnet $dll
        if($LASTEXITCODE -ne 0){ throw "ParityTests devolvió $LASTEXITCODE" }

        $productionDll = Join-Path $root 'tests\TDM.ProductionTests\bin\Release\net8.0-windows\TDM.ProductionTests.dll'
        Require (Test-Path $productionDll) "No existe $productionDll"
        & dotnet $productionDll
        if($LASTEXITCODE -ne 0){ throw "ProductionTests devolvió $LASTEXITCODE" }
    }

    Step '[6/7] Startup GUI + Notifier...' {
        $guiExe = Join-Path $root 'src\TDM.Gui.Avalonia\bin\Release\net8.0-windows\TDM.Application.exe'
        $notExe = Join-Path $root 'src\TDM.Notifier.Avalonia\bin\Release\net8.0-windows\TDM.Notifier.exe'
        Require (Test-Path $guiExe) "No existe $guiExe"
        Require (Test-Path $notExe) "No existe $notExe"

        $guiReady = Join-Path $env:TEMP ("TDM-gui-ready-{0}.txt" -f $PID)
        $notifierReady = Join-Path $env:TEMP ("TDM-notifier-ready-{0}.txt" -f $PID)
        Remove-Item $guiReady,$notifierReady -Force -ErrorAction SilentlyContinue

        $oldGuiReady = $env:TDM_AVALONIA_STARTUP_READY_FILE
        $oldNotifierReady = $env:TDM_AVALONIA_NOTIFIER_READY_FILE
        $oldNotifierProbe = $env:TDM_AVALONIA_NOTIFIER_READINESS_PROBE
        $env:TDM_AVALONIA_STARTUP_READY_FILE = $guiReady
        $env:TDM_AVALONIA_NOTIFIER_READY_FILE = $notifierReady
        $env:TDM_AVALONIA_NOTIFIER_READINESS_PROBE = '1'
        $gp = $null; $np = $null
        try {
            $np = Start-Process -FilePath $notExe -PassThru
            $gp = Start-Process -FilePath $guiExe -PassThru
            $deadline = (Get-Date).AddSeconds(25)
            $guiOk = $false
            $notifierOk = $false
            do {
                Start-Sleep -Milliseconds 250

                if(Test-Path $guiReady){
                    $content = Get-Content $guiReady -Raw -ErrorAction SilentlyContinue
                    if($content -and $content.StartsWith('ERROR|',[System.StringComparison]::Ordinal)){
                        throw "GUI reportó fallo de startup: $content"
                    }
                    if($content -and $content.StartsWith('READY|',[System.StringComparison]::Ordinal)){ $guiOk = $true }
                }

                if(Test-Path $notifierReady){
                    $content = Get-Content $notifierReady -Raw -ErrorAction SilentlyContinue
                    if($content -and $content.StartsWith('ERROR|',[System.StringComparison]::Ordinal)){
                        throw "Notifier reportó fallo de startup: $content"
                    }
                    if($content -and $content.StartsWith('READY|',[System.StringComparison]::Ordinal)){ $notifierOk = $true }
                }

                if($gp.HasExited -or $np.HasExited -or ($guiOk -and $notifierOk)){ break }
            } while((Get-Date) -lt $deadline)

            Require (-not $gp.HasExited) "La GUI terminó prematuramente (ExitCode=$($gp.ExitCode))."
            Require (-not $np.HasExited) "Notifier terminó prematuramente (ExitCode=$($np.ExitCode))."
            Require $guiOk 'La GUI no alcanzó READY en 25 segundos.'
            Require $notifierOk 'El Notifier no alcanzó READY en 25 segundos.'
            Write-Host '[OK] Startup PASS' -ForegroundColor Green
        }
        finally {
            if($gp -and -not $gp.HasExited){ Stop-Process -Id $gp.Id -Force -ErrorAction SilentlyContinue }
            if($np -and -not $np.HasExited){ Stop-Process -Id $np.Id -Force -ErrorAction SilentlyContinue }
            Remove-Item $guiReady,$notifierReady -Force -ErrorAction SilentlyContinue

            if($null -eq $oldGuiReady){ Remove-Item Env:TDM_AVALONIA_STARTUP_READY_FILE -ErrorAction SilentlyContinue }
            else { $env:TDM_AVALONIA_STARTUP_READY_FILE = $oldGuiReady }
            if($null -eq $oldNotifierReady){ Remove-Item Env:TDM_AVALONIA_NOTIFIER_READY_FILE -ErrorAction SilentlyContinue }
            else { $env:TDM_AVALONIA_NOTIFIER_READY_FILE = $oldNotifierReady }
            if($null -eq $oldNotifierProbe){ Remove-Item Env:TDM_AVALONIA_NOTIFIER_READINESS_PROBE -ErrorAction SilentlyContinue }
            else { $env:TDM_AVALONIA_NOTIFIER_READINESS_PROBE = $oldNotifierProbe }
        }
    }

    Step '[7/7] Verificación de estructura limpia...' {
        foreach($legacy in @('src\TDM.Gui','src\TDM.Notifier','src\TDM.Cli','tools')){
            Require (-not (Test-Path -LiteralPath (Join-Path $root $legacy))) "Contenido no necesario presente: $legacy"
        }
        Write-Host '[OK] Paquete limpio PASS' -ForegroundColor Green
    }

    Write-Host "`n============================================================"
    Write-Host '[OK] TDM READINESS GATE PASS' -ForegroundColor Green
    Write-Host '============================================================'
    exit 0
}
catch {
    Write-Host "`n============================================================"
    Write-Host '[FAIL] TDM READINESS GATE' -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host '============================================================'
    exit 1
}
