param([Parameter(Mandatory=$true)][string]$PayloadDir)
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path $PSScriptRoot '..\packaging\windows\setup.ps1'
. $scriptPath
function Assert($condition, [string]$message) {
    if (-not $condition) { throw $message }
}
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('edr-install-test-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $app = (Resolve-Path -LiteralPath $PayloadDir).Path
    $data = Join-Path $testRoot 'data with spaces'
    Initialize-EdrInstallation -ApplicationDir $app -StateDir $data -WithConsole $true -WithDriver $false -Staging $true
    $config = Get-Content -LiteralPath (Join-Path $data 'config\edr.config.json') -Raw | ConvertFrom-Json
    $keysPath = Join-Path $data 'console-keys.json'
    $keys = Get-Content -LiteralPath $keysPath -Raw | ConvertFrom-Json
    Assert (-not $config.enable_driver_collector) 'Driver must be disabled when not selected'
    Assert (-not $config.enable_imonitor) 'Unavailable iMonitor must be disabled'
    Assert (-not $config.auto_response.enable -and -not $config.response_channel.enable) 'Destructive response must remain disabled'
    Assert ($config.reporter.api_key -eq $keys.ingest) 'Agent and console ingestion credentials must agree'
    Assert (@($keys.ingest,$keys.read,$keys.admin | Sort-Object -Unique).Count -eq 3) 'Roles must use different keys'
    Assert ($keys.read -match '^[0-9a-f]{64}$') 'Keys must contain 256 bits of cryptographic randomness'
    Assert ($config.rules_path -eq (Join-Path $app 'rules\rules.json')) 'Rules path must be absolute and support spaces'
    Assert ($config.correlation.incident_path -eq (Join-Path $data 'console\incidents.jsonl')) 'Native incidents and console readback must share one ledger'
    $before = (Get-FileHash -LiteralPath $keysPath).Hash
    $config.redact = $false
    [IO.File]::WriteAllText((Join-Path $data 'config\edr.config.json'), ($config | ConvertTo-Json -Depth 32))
    Initialize-EdrInstallation -ApplicationDir $app -StateDir $data -WithConsole $true -WithDriver $false -Staging $true
    Assert ((Get-FileHash -LiteralPath $keysPath).Hash -eq $before) 'Repair must preserve credentials'
    $repaired = Get-Content -LiteralPath (Join-Path $data 'config\edr.config.json') -Raw | ConvertFrom-Json
    Assert (-not $repaired.redact) 'Repair must preserve user configuration'
    $minimalData = Join-Path $testRoot 'minimal'
    Initialize-EdrInstallation $app $minimalData $false $false $true
    $minimalConfig = Join-Path $minimalData 'config\edr.config.json'
    Assert (-not (Get-Content -LiteralPath $minimalConfig -Raw -Encoding UTF8 | ConvertFrom-Json).reporter.enable) 'Agent-only install must not report to an absent console'
    Initialize-EdrInstallation $app $minimalData $true $false $true
    Assert ((Get-Content -LiteralPath $minimalConfig -Raw -Encoding UTF8 | ConvertFrom-Json).reporter.enable) 'Adding console migrates only the required reporter settings'
    $foreign = Join-Path $testRoot 'foreign'
    New-Item -ItemType Directory -Path $foreign | Out-Null
    Set-Content -LiteralPath (Join-Path $foreign 'keep.txt') -Value 'unrelated'
    $rejected = $false
    try { Initialize-EdrInstallation -ApplicationDir $app -StateDir $foreign -WithConsole $false -WithDriver $false -Staging $true }
    catch { $rejected = $true }
    Assert $rejected 'Existing unowned state must not be overwritten'
    Assert ((Get-Content -LiteralPath (Join-Path $foreign 'keep.txt')) -eq 'unrelated') 'Unowned state must be preserved'
    $bad = $false
    try { Assert-EdrLocalPath '\\server\share\edr' } catch { $bad = $true }
    Assert $bad 'UNC installation paths must be refused'
    $driverRejected = $false
    try { Assert-EdrDriverReady -DriverFile (Join-Path $app 'edr.exe') -ExpectedThumbprint ('0' * 40) }
    catch { $driverRejected = $true }
    Assert $driverRejected 'Unsigned or wrong-signer payload must never install as a driver'
    function Get-CimInstance { param($ClassName,$Filter) return [pscustomobject]@{PathName=$script:fakeServicePath} }
    $script:fakeServicePath = '"C:\foreign\edr.exe" --service'
    $foreignRejected = $false
    try { $null = Get-EdrOwnedService 'edr' (Join-Path $app 'edr.exe') } catch { $foreignRejected = $true }
    Assert $foreignRejected 'An unrelated service with the same name must be refused'
    $script:fakeServicePath = '\??\' + (Join-Path $app 'driver\edrdrv.sys')
    Assert ($null -ne (Get-EdrOwnedService 'edrdrv' (Join-Path $app 'driver\edrdrv.sys'))) 'Kernel service ownership must recognize native path prefixes'
    # Exercise the actual transaction with every system mutation replaced by a local fake.
    function Initialize-EdrInstallation { }
    function Assert-EdrDriverReady { }
    function New-Item { }
    function New-ItemProperty { }
    function Get-ItemProperty { return [pscustomobject]@{DependOnService=@('existing');DependOnGroup=@('Group')} }
    function Get-EdrOwnedService {
        param($Name,$ExpectedExe)
        if ($Name -eq 'edr' -or $script:fakeDriverCreated) { return [pscustomobject]@{State='Stopped'} }
        return $null
    }
    function Start-Service { throw 'Injected service start failure' }
    $script:fakeDriverCreated = $false
    $script:fakeDependencies = @('existing','+Group')
    function Invoke-EdrSc {
        param([string[]]$Arguments)
        if ($Arguments[0] -eq 'create') { $script:fakeDriverCreated = $true }
        if ($Arguments[0] -eq 'delete') { $script:fakeDriverCreated = $false }
        if ($Arguments[0] -eq 'config') {
            $script:fakeDependencies = if ($Arguments[3] -eq '/') { @() } else { $Arguments[3].Split('/') }
        }
    }
    $AppDir = Join-Path $env:ProgramFiles 'EDR Installer Unit Fixture'
    $DataDir = $data
    $Action = 'Install'; $StageOnly = $false; $Driver = $true; $Console = $false; $StartServices = $true
    $failedAsExpected = $false
    try { Invoke-EdrSetup } catch { $failedAsExpected = $_.Exception.Message -eq 'Injected service start failure' }
    Assert $failedAsExpected 'The simulated integration failure must remain visible'
    Assert (-not $script:fakeDriverCreated) 'A driver created by the failed transaction must be removed'
    Assert (($script:fakeDependencies -join '/') -eq 'existing/+Group') 'Failure must restore the existing agent service and group dependencies before driver deletion'
    function Get-ItemProperty { return [pscustomobject]@{} }
    $script:fakeDependencies = @()
    $failedAsExpected = $false
    try { Invoke-EdrSetup } catch { $failedAsExpected = $_.Exception.Message -eq 'Injected service start failure' }
    Assert $failedAsExpected 'Dependency-free rollback must retain the original failure'
    Assert (-not $script:fakeDriverCreated -and @($script:fakeDependencies).Count -eq 0) 'Rollback must clear dependencies when the original agent had none'
    Write-Output 'PASS installer configuration, repair, ownership, role keys, path, driver rejection and transaction rollback'
} finally {
    $resolved = [IO.Path]::GetFullPath($testRoot)
    if (-not $resolved.StartsWith([IO.Path]::GetFullPath([IO.Path]::GetTempPath()), [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe fixture cleanup path' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
