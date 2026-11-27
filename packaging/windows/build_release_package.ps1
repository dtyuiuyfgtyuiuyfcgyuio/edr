param(
    [Parameter(Mandatory=$true)][string]$SourceDir,
    [Parameter(Mandatory=$true)][string]$SourceCommit,
    [Parameter(Mandatory=$true)][string]$Version,
    [Parameter(Mandatory=$true)][string]$OutputDir,
    [Parameter(Mandatory=$true)][string]$WorkDir
)
$ErrorActionPreference = 'Stop'

function Assert-Hash([string]$File, [string]$Expected) {
    if ((Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash -ne $Expected) {
        throw "SHA-256 mismatch for $File"
    }
}

function Get-PinnedFile([string]$Url, [string]$Destination, [string]$Hash) {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Destination
    Assert-Hash $Destination $Hash
}

function Invoke-Setup([string]$Executable, [string[]]$Arguments) {
    $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "$Executable exited with code $($process.ExitCode)" }
}

if ($Version -notmatch '^\d{1,5}(\.\d{1,5}){3}$' -or $SourceCommit -notmatch '^[a-f0-9]{40}$') {
    throw 'The release requires an installer version and an exact Git commit.'
}
if ((& git -C $SourceDir rev-parse HEAD) -ne $SourceCommit -or $LASTEXITCODE -ne 0) {
    throw 'Package sources differ from the selected release tag.'
}
New-Item -ItemType Directory -Path $WorkDir, $OutputDir -Force | Out-Null

$driverBase = 'https://github.com/dtyuiuyfgtyuiuyfcgyuio/edr/releases/download/v1.3.2026.1020'
$previousInstaller = Join-Path $WorkDir 'previous-installer.exe'
$certificate = Join-Path $WorkDir 'edr-test-signing.cer'
$extractorZip = Join-Path $WorkDir 'innounp.zip'
$extractorDir = Join-Path $WorkDir 'extractor'
$extracted = Join-Path $WorkDir 'previous-payload'
$driverHash = 'c96e1077c93e8708baa073ecc4562e5fdeb3d319d0e14e988c6d81cb5a3e0f30'
Get-PinnedFile "$driverBase/EDR-Setup-1.3.2026.1020-x64.exe" $previousInstaller '723c7217cd0c7bd0a297540e7163aefed0cbbd0c156cd1b081618f9e06958e10'
Get-PinnedFile "$driverBase/EDR-driver-test-signing.cer" $certificate '185bcd6a1cfed56d2c93d60c6baf01742f0e5443bcba548dfed833c2b5078906'
Get-PinnedFile 'https://github.com/jrathlev/InnoUnpacker-Windows-GUI/releases/download/oi_2_2_11/innounp-2.zip' $extractorZip '851772538a041229102ad9964542d49dc00c74002e3091a70469c079ae368f52'
Expand-Archive -LiteralPath $extractorZip -DestinationPath $extractorDir
New-Item -ItemType Directory -Path $extracted -Force | Out-Null
# Extract the signed payload as data. Running the old installer would change the test machine.
& (Join-Path $extractorDir 'innounp.exe') -x "-d$extracted" -y $previousInstaller > (Join-Path $WorkDir 'extract.log')
if ($LASTEXITCODE -ne 0) { throw "Inno Unpacker exited with code $LASTEXITCODE" }
$drivers = @(Get-ChildItem -LiteralPath $extracted -Recurse -File -Filter 'edrdrv.sys')
if ($drivers.Count -ne 1) { throw 'Expected exactly one edrdrv.sys in the previous payload.' }
Assert-Hash $drivers[0].FullName $driverHash

$innoInstaller = Join-Path $WorkDir 'innosetup-6.7.3.exe'
$innoDir = Join-Path $WorkDir 'inno'
Get-PinnedFile 'https://github.com/jrsoftware/issrc/releases/download/is-6_7_3/innosetup-6.7.3.exe' $innoInstaller '9c73c3bae7ed48d44112a0f48e66742c00090bdb5bef71d9d3c056c66e97b732'
Invoke-Setup $innoInstaller @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', "/DIR=`"$innoDir`"", '/TASKS=""')

$nodeVersion = '24.22.1'
$nodeZip = Join-Path $WorkDir 'node.zip'
$nodeDir = Join-Path $WorkDir "node-v$nodeVersion-win-x64"
Get-PinnedFile "https://nodejs.org/dist/v$nodeVersion/node-v$nodeVersion-win-x64.zip" $nodeZip 'd2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5'
Expand-Archive -LiteralPath $nodeZip -DestinationPath $WorkDir
$node = Join-Path $nodeDir 'node.exe'
$env:Path = "$nodeDir;$env:Path"
if ((& $node --version) -ne "v$nodeVersion" -or $LASTEXITCODE -ne 0) { throw 'Unexpected bundled Node version.' }

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vsPath = & $vswhere -latest -products '*' -version '[17.0,18.0)' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
if (-not $vsPath) { throw 'Visual Studio 2022 with x64 C++ is required.' }
$vsPath = $vsPath.Trim()
$vcvars = Join-Path $vsPath 'VC/Auxiliary/Build/vcvarsall.bat'
$buildDir = Join-Path $WorkDir 'build'
$batchFile = Join-Path $WorkDir 'build-release.cmd'
$sdk = '10.0.22621.0'
@"
@echo off
call "$vcvars" x64 $sdk
if errorlevel 1 exit /b 1
cmake -S "$SourceDir" -B "$buildDir" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_VERSION=$sdk -DEDR_IMONITOR=OFF -DEDR_DRIVER_FEATURES=NONE -DBUILD_TESTING=OFF
if errorlevel 1 exit /b 1
cmake --build "$buildDir" --target edr --parallel 4
exit /b %errorlevel%
"@ | Set-Content -LiteralPath $batchFile -Encoding ascii
& cmd.exe /d /c "call `"$batchFile`""
if ($LASTEXITCODE -ne 0) { throw "Windows agent build failed with code $LASTEXITCODE" }

$buildScript = Join-Path $SourceDir 'packaging/windows/build_installer.ps1'
$crt = Get-ChildItem -LiteralPath (Join-Path $vsPath 'VC/Redist/MSVC') -Directory |
    Where-Object Name -match '^\d+\.' | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
if (-not $crt) { throw 'VC143 application-local runtime not found.' }
$crtDir = Join-Path $crt.FullName 'x64/Microsoft.VC143.CRT'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $buildScript `
    -BuildDir $buildDir -Version $Version -OutputDir $OutputDir `
    -IsccPath (Join-Path $innoDir 'ISCC.exe') -NodeExe $node -NodeLicense (Join-Path $nodeDir 'LICENSE') `
    -CrtDirectory $crtDir -DriverPath $drivers[0].FullName -DriverCertificate $certificate -BuildVerificationInstaller
if ($LASTEXITCODE -ne 0) { throw "Installer build failed with code $LASTEXITCODE" }
$resultPath = Join-Path $SourceDir '.omo/installer-20261018/build-result.json'
$result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
Assert-Hash $result.installer $result.sha256

& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $SourceDir 'tests/installer_package_tests.ps1') -PayloadDir $result.payload
if ($LASTEXITCODE -ne 0) { throw "Installer package tests failed with code $LASTEXITCODE" }

$stagingDir = Join-Path $WorkDir 'verification-install'
$setupFlags = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-', '/COMPONENTS=agent,console', "/DIR=`"$stagingDir`"")
Invoke-Setup $result.verification_installer ($setupFlags + "/LOG=`"$WorkDir\verification-install.log`"")
$smoke = & $node (Join-Path $SourceDir 'tests/installer_smoke_test.js') $stagingDir
if ($LASTEXITCODE -ne 0) { throw "Installed smoke test failed with code $LASTEXITCODE" }
$smoke | Write-Host
$stateDir = Join-Path $stagingDir 'TestData'
$config = Join-Path $stateDir 'config/edr.config.json'
$keys = Join-Path $stateDir 'console-keys.json'
$history = Join-Path $stateDir 'selftest-alerts.jsonl'
$preserved = @($config, $keys, $history) | ForEach-Object { Get-FileHash -LiteralPath $_ -Algorithm SHA256 }
Invoke-Setup $result.verification_installer ($setupFlags + "/LOG=`"$WorkDir\verification-repair.log`"")
foreach ($file in $preserved) { Assert-Hash $file.Path $file.Hash }
Invoke-Setup (Join-Path $stagingDir 'unins000.exe') @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/LOG=`"$WorkDir\verification-uninstall.log`"")
foreach ($file in $preserved) { Assert-Hash $file.Path $file.Hash }
if (Test-Path -LiteralPath (Join-Path $stagingDir 'edr.exe')) { throw 'Uninstall left the installed executable behind.' }

$proof = [ordered]@{
    version = $Version
    source_commit = $SourceCommit
    sdk = $sdk
    node = "v$nodeVersion"
    installer = [IO.Path]::GetFileName($result.installer)
    installer_sha256 = $result.sha256
    installer_signing = 'unsigned'
    driver_origin = 'v1.3.2026.1020'
    driver_signing = 'test'
    driver_sha256 = $driverHash
    package_tests = 'passed'
    staging_install_repair_uninstall = 'passed'
    installed_smoke = ($smoke | ConvertFrom-Json)
    admin_service_boot_and_driver_loading = 'not_run'
    workflow_run = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
}
$proof | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $OutputDir 'EDR-release-verification.json') -Encoding utf8
$checksums = Get-ChildItem -LiteralPath $OutputDir -File | Sort-Object Name | ForEach-Object {
    '{0}  {1}' -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
}
$checksums | Set-Content -LiteralPath (Join-Path $OutputDir 'SHA256SUMS.txt') -Encoding ascii
