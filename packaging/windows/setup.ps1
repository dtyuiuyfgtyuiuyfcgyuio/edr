param(
    [ValidateSet('Preflight','Install','Uninstall')][string]$Action = 'Install',
    [string]$AppDir, [string]$DataDir,
    [switch]$Console, [switch]$Driver, [switch]$StartServices,
    [switch]$StageOnly, [string]$DriverFile, [string]$DriverThumbprint,
    [string]$ResultFile
)
$ErrorActionPreference = 'Stop'

function Assert-EdrLocalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\' -or
        $Path.IndexOfAny([char[]]@([char]0,[char]10,[char]13,[char]34)) -ge 0) {
        throw 'A local absolute Windows path without control characters is required.'
    }
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw ('Reparse points are not allowed: ' + $current)
            }
        }
        $parent = Split-Path -Parent $current
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Read-EdrMarker([string]$StateDir, [string]$ApplicationDir) {
    $marker = Join-Path $StateDir 'installation.json'
    if (Test-Path -LiteralPath $marker) {
        $state = Get-Content -LiteralPath $marker -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($state.app_dir -ne [IO.Path]::GetFullPath($ApplicationDir)) {
            throw 'This data directory belongs to another EDR installation.'
        }
        return $state
    }
    if ((Test-Path -LiteralPath $StateDir) -and
        @(Get-ChildItem -LiteralPath $StateDir -Force).Count -ne 0) {
        throw 'Refusing to overwrite an existing unowned data directory.'
    }
    return $null
}

function Write-EdrJson([string]$Path, $Value) {
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 64), [Text.UTF8Encoding]::new($false))
}

function New-EdrSecret {
    $bytes = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ([BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

function Initialize-EdrInstallation {
    param([string]$ApplicationDir, [string]$StateDir,
          [bool]$WithConsole, [bool]$WithDriver, [bool]$Staging)
    Assert-EdrLocalPath $ApplicationDir
    Assert-EdrLocalPath $StateDir
    $previous = Read-EdrMarker $StateDir $ApplicationDir
    foreach ($path in @($StateDir,(Join-Path $StateDir 'config'),(Join-Path $StateDir 'agent'),(Join-Path $StateDir 'console'))) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    if (-not $Staging) {
        & "$env:SystemRoot\System32\icacls.exe" $StateDir '/inheritance:r' '/grant:r' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not protect EDR state and credentials.' }
    }
    $keysPath = Join-Path $StateDir 'console-keys.json'
    $configPath = Join-Path $StateDir 'config\edr.config.json'
    if (-not (Test-Path -LiteralPath $keysPath)) {
        if (Test-Path -LiteralPath $configPath) { throw 'Existing configuration has no matching credentials; restore the original key file.' }
        $keys = [ordered]@{ingest=(New-EdrSecret);read=(New-EdrSecret);admin=(New-EdrSecret)}
        Write-EdrJson $keysPath $keys
        [IO.File]::WriteAllText((Join-Path $StateDir 'console-access.txt'),
            "EDR local console: http://127.0.0.1:8080`r`nRead API key: $($keys.read)`r`nAdmin API key: $($keys.admin)`r`nKeep this administrator-only file private.`r`n")
    }
    $keys = Get-Content -LiteralPath $keysPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not (Test-Path -LiteralPath $configPath)) {
        $cfg = Get-Content -LiteralPath (Join-Path $ApplicationDir 'config\edr.config.template.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $cfg.enable_driver_collector = $WithDriver
        $cfg.enable_imonitor = $false
        $cfg.driver_enable_block = $false
        $cfg.enable_host_isolation = $false
        $cfg.auto_response.enable = $false
        $cfg.response_channel.enable = $false
        $cfg.webhook.enable = $false
        $cfg.alerts_path = Join-Path $StateDir 'agent\alerts.jsonl'
        $cfg.rules_path = Join-Path $ApplicationDir 'rules\rules.json'
        $cfg.reporter.enable = $WithConsole
        $cfg.reporter.url = 'http://127.0.0.1:8080/ingest'
        $cfg.reporter.api_key = $keys.ingest
        $cfg.reporter.spool.directory = Join-Path $StateDir 'agent\spool\alerts'
        $cfg.reporter.spool.event_directory = Join-Path $StateDir 'agent\spool\events'
        $cfg.event_log_replay.checkpoint_directory = Join-Path $StateDir 'agent\checkpoints'
        $cfg.correlation.incident_path = Join-Path $StateDir 'console\incidents.jsonl'
        Write-EdrJson $configPath $cfg
    }
    if ($previous -and (($WithDriver -and -not $previous.driver) -or ($WithConsole -and -not $previous.console))) {
        $cfg = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($WithDriver -and -not $previous.driver) { $cfg.enable_driver_collector = $true }
        if ($WithConsole -and -not $previous.console) {
            $cfg.reporter.enable = $true
            $cfg.reporter.url = 'http://127.0.0.1:8080/ingest'
            $cfg.reporter.api_key = $keys.ingest
        }
        Write-EdrJson $configPath $cfg
    }
    $withExistingConsole = $WithConsole -or ($previous -and $previous.console)
    $withExistingDriver = $WithDriver -or ($previous -and $previous.driver)
    Write-EdrJson (Join-Path $StateDir 'installation.json') ([ordered]@{
        version=1; app_dir=[IO.Path]::GetFullPath($ApplicationDir)
        console=[bool]$withExistingConsole;driver=[bool]$withExistingDriver;staging=$Staging
    })
}

function Assert-EdrDriverReady([string]$DriverFile, [string]$ExpectedThumbprint) {
    if ($ExpectedThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'Missing pinned driver signer.' }
    $sig = Get-AuthenticodeSignature -LiteralPath $DriverFile
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Thumbprint -ne $ExpectedThumbprint) {
        throw 'The optional test driver requires its signing certificate to be trusted on the target test VM. Uncheck the driver component to install user-mode EDR.'
    }
    if (-not ('EdrInstallerCodeIntegrity' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class EdrInstallerCodeIntegrity {
    [StructLayout(LayoutKind.Sequential)] public struct Info { public uint Length, Options; }
    [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int c, ref Info i, int l, out int r);
    public static bool TestSigningEnabled() {
        Info i = new Info(); i.Length = 8; int r;
        return NtQuerySystemInformation(103, ref i, 8, out r) == 0 && (i.Options & 2) != 0;
    }
}
'@
    }
    if (-not [EdrInstallerCodeIntegrity]::TestSigningEnabled()) {
        throw 'This driver is test-signed. Prepare a test VM with test-signing enabled, or uncheck the driver component. Setup does not change boot security.'
    }
}

function Assert-EdrSystemDestination([string]$ApplicationDir) {
    $prefix = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
    if (-not [IO.Path]::GetFullPath($ApplicationDir).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Service installation must be inside the protected Program Files directory.'
    }
}

function Get-EdrOwnedService([string]$Name, [string]$ExpectedExe) {
    $class = if ($Name -eq 'edrdrv') { 'Win32_SystemDriver' } else { 'Win32_Service' }
    $svc = Get-CimInstance $class -Filter ("Name='" + $Name + "'")
    if ($svc) {
        if ($Name -eq 'edrdrv') {
            $binary = $svc.PathName.Trim('"')
            if ($binary.StartsWith('\??\')) { $binary = $binary.Substring(4).Trim('"') }
            $ownedPathMatches = $binary -eq $ExpectedExe
        } else {
            $ownedPathMatches = $svc.PathName.StartsWith(('"' + $ExpectedExe + '"'),[StringComparison]::OrdinalIgnoreCase)
        }
        if (-not $ownedPathMatches) { throw ('Refusing to modify a service owned by another installation: ' + $Name) }
    }
    return $svc
}

function Stop-EdrOwnedComponents([string]$ApplicationDir, [string]$StateDir) {
    $null = Read-EdrMarker $StateDir $ApplicationDir
    $svc = Get-EdrOwnedService 'edr' (Join-Path $ApplicationDir 'edr.exe')
    if ($svc -and $svc.State -ne 'Stopped') {
        Stop-Service -Name edr -ErrorAction Stop
        (Get-Service -Name edr).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    }
    $task = Get-ScheduledTask -TaskName 'EDR Local Console' -ErrorAction SilentlyContinue
    if ($task) {
        $expected = Join-Path $ApplicationDir 'runtime\node.exe'
        if ($task.Actions.Count -ne 1 -or $task.Actions[0].Execute -ne $expected -or
            $task.Actions[0].Arguments -ne ('"' + (Join-Path $ApplicationDir 'console\installed-launcher.js') + '" "' + $StateDir + '"')) {
            throw 'Refusing to change an unrelated console task.'
        }
        if ($task.State -eq 'Running') {
            [IO.File]::WriteAllText((Join-Path $StateDir 'console\shutdown.request'), 'stop')
            $limit = [DateTime]::UtcNow.AddSeconds(15)
            while ((Get-ScheduledTask -TaskName 'EDR Local Console').State -eq 'Running' -and [DateTime]::UtcNow -lt $limit) { Start-Sleep -Milliseconds 100 }
            if ((Get-ScheduledTask -TaskName 'EDR Local Console').State -eq 'Running') { Stop-ScheduledTask -TaskName 'EDR Local Console' }
        }
    }
}

function Invoke-EdrSc([string[]]$Arguments) {
    & "$env:SystemRoot\System32\sc.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw ('Service configuration failed: ' + ($Arguments -join ' ')) }
}

function Get-EdrAgentDependencies {
    $properties = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\edr' -ErrorAction Stop
    foreach ($name in @($properties.DependOnService)) { if ($name) { [string]$name } }
    foreach ($name in @($properties.DependOnGroup)) { if ($name) { '+' + $name } }
}

function Get-EdrDependencyArgument([string[]]$Names) {
    if (-not $Names -or $Names.Count -eq 0) { return '/' }
    return ($Names -join '/')
}

function Invoke-EdrSetup {
    Assert-EdrLocalPath $AppDir
    Assert-EdrLocalPath $DataDir
    if (-not $StageOnly) { Assert-EdrSystemDestination $AppDir }
    if ($Action -eq 'Preflight') {
        $previous = Read-EdrMarker $DataDir $AppDir
        if ($previous -and (($previous.console -and -not $Console) -or ($previous.driver -and -not $Driver))) {
            throw 'Keep previously installed components selected for repair. Use uninstall to remove components.'
        }
        if ($Driver) { Assert-EdrDriverReady $DriverFile $DriverThumbprint }
        if (-not $StageOnly) { $null = Get-EdrOwnedService 'edrdrv' (Join-Path $AppDir 'driver\edrdrv.sys') }
        if (-not $StageOnly) { Stop-EdrOwnedComponents $AppDir $DataDir }
        return
    }
    if ($Action -eq 'Uninstall') {
        $state = Read-EdrMarker $DataDir $AppDir
        if (-not $StageOnly) {
            Stop-EdrOwnedComponents $AppDir $DataDir
            # Refuse a busy driver before unregistering the remaining components.
            if ($state.driver) {
                $driverSvc = Get-EdrOwnedService 'edrdrv' (Join-Path $AppDir 'driver\edrdrv.sys')
                if ($driverSvc -and $driverSvc.State -ne 'Stopped') {
                    & "$env:SystemRoot\System32\fltmc.exe" unload edrdrv
                    if ($LASTEXITCODE -ne 0) { throw 'Driver is busy; stop its consumers and retry uninstall. Driver files have been preserved.' }
                }
            }
            if (Get-EdrOwnedService 'edr' (Join-Path $AppDir 'edr.exe')) {
                & (Join-Path $AppDir 'edr.exe') --uninstall-service
                if ($LASTEXITCODE -ne 0) { throw 'Agent service removal failed.' }
            }
            if ($state.console) { Unregister-ScheduledTask -TaskName 'EDR Local Console' -Confirm:$false -ErrorAction SilentlyContinue }
            if ($state.driver) {
                $driverSvc = Get-EdrOwnedService 'edrdrv' (Join-Path $AppDir 'driver\edrdrv.sys')
                if ($driverSvc) {
                    Invoke-EdrSc -Arguments @('delete','edrdrv')
                }
            }
        }
        return # Preserve configuration, credentials and telemetry on uninstall.
    }
    Initialize-EdrInstallation $AppDir $DataDir ([bool]$Console) ([bool]$Driver) ([bool]$StageOnly)
    if ($StageOnly) { return }
    $config = Join-Path $DataDir 'config\edr.config.json'
    $newAgent = $false
    $newDriver = $false
    $newConsoleTask = $false
    $dependenciesChanged = $false
    $previousDependencies = @()
    try {
    if ($Driver) {
        Assert-EdrDriverReady (Join-Path $AppDir 'driver\edrdrv.sys') $DriverThumbprint
        if (-not (Get-EdrOwnedService 'edrdrv' (Join-Path $AppDir 'driver\edrdrv.sys'))) {
            Invoke-EdrSc -Arguments @('create','edrdrv','type=','filesys','start=','demand','depend=','FltMgr','binPath=',('"' + (Join-Path $AppDir 'driver\edrdrv.sys') + '"'))
            $newDriver = $true
            foreach ($suffix in @('Instances','Parameters\Instances')) {
                $root = 'HKLM:\SYSTEM\CurrentControlSet\Services\edrdrv\' + $suffix
                New-Item -Path ($root + '\EDR Instance') -Force | Out-Null
                New-ItemProperty -Path $root -Name DefaultInstance -Value 'EDR Instance' -Force | Out-Null
                New-ItemProperty -Path ($root + '\EDR Instance') -Name Altitude -Value '370000' -Force | Out-Null
                New-ItemProperty -Path ($root + '\EDR Instance') -Name Flags -PropertyType DWord -Value 0 -Force | Out-Null
            }
        }
    }
    if (-not (Get-EdrOwnedService 'edr' (Join-Path $AppDir 'edr.exe'))) {
        & (Join-Path $AppDir 'edr.exe') --install-service --config $config --rules (Join-Path $AppDir 'rules\rules.json')
        if ($LASTEXITCODE -ne 0) { throw 'Agent service registration failed.' }
        $newAgent = $true
    }
    if ($Driver) {
        $previousDependencies = @(Get-EdrAgentDependencies)
        $desiredDependencies = @(@($previousDependencies) + @('edrdrv') | Sort-Object -Unique)
        Invoke-EdrSc -Arguments @('config','edr','depend=',(Get-EdrDependencyArgument $desiredDependencies))
        $dependenciesChanged = $true
    }
    if ($Console) {
        $previousTask = Get-ScheduledTask -TaskName 'EDR Local Console' -ErrorAction SilentlyContinue
        $consoleArguments = '"' + (Join-Path $AppDir 'console\installed-launcher.js') + '" "' + $DataDir + '"'
        $taskAction = New-ScheduledTaskAction -Execute (Join-Path $AppDir 'runtime\node.exe') -Argument $consoleArguments -WorkingDirectory (Join-Path $AppDir 'console')
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName 'EDR Local Console' -Action $taskAction -Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM -RunLevel Highest -Settings $settings -Force | Out-Null
        $newConsoleTask = -not $previousTask
    }
    if ($StartServices) {
        if ($Console) { Start-ScheduledTask -TaskName 'EDR Local Console' }
        if ($Console) {
            $keys = Get-Content -LiteralPath (Join-Path $DataDir 'console-keys.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            $ready = $false
            $limit = [DateTime]::UtcNow.AddSeconds(15)
            while ([DateTime]::UtcNow -lt $limit -and -not $ready) {
                try {
                    $null = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/api/alerts?limit=1' -Headers @{'X-API-Key'=$keys.read} -TimeoutSec 2
                    $ready = $true
                } catch { Start-Sleep -Milliseconds 250 }
            }
            if (-not $ready) { throw 'The local console did not become ready. Check console\service.log and port 8080.' }
        }
        Start-Service -Name edr -ErrorAction Stop
        (Get-Service -Name edr).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    }
    } catch {
        $originalError = $_
        # Restore a pre-existing service before removing a newly-created dependency.
        if ($dependenciesChanged -and -not $newAgent) {
            Invoke-EdrSc -Arguments @('config','edr','depend=',(Get-EdrDependencyArgument $previousDependencies))
        }
        if ($newAgent) { & (Join-Path $AppDir 'edr.exe') --uninstall-service | Out-Null }
        if ($newConsoleTask) {
            Stop-ScheduledTask -TaskName 'EDR Local Console' -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName 'EDR Local Console' -Confirm:$false -ErrorAction SilentlyContinue
        }
        if ($newDriver) {
            $owned = Get-EdrOwnedService 'edrdrv' (Join-Path $AppDir 'driver\edrdrv.sys')
            if ($owned -and $owned.State -ne 'Stopped') { & "$env:SystemRoot\System32\fltmc.exe" unload edrdrv | Out-Null }
            if (-not $owned -or $owned.State -eq 'Stopped' -or $LASTEXITCODE -eq 0) { Invoke-EdrSc -Arguments @('delete','edrdrv') }
        }
        throw $originalError
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-EdrSetup; exit 0 }
    catch {
        if ($ResultFile) { [IO.File]::WriteAllText($ResultFile, $_.Exception.Message, [Text.UTF8Encoding]::new($false)) }
        Write-Error $_ -ErrorAction Continue
        exit 1
    }
}
