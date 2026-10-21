param(
    [Parameter(Mandatory=$true)][string]$IsccPath,
    [Parameter(Mandatory=$true)][string]$DriverPath,
    [Parameter(Mandatory=$true)][string]$DriverCertificate,
    [Parameter(Mandatory=$true)][string]$NodeLicense,
    [string]$BuildDir = 'build-edr-expansion-20261011',
    [string]$Version = '1.0.2026.1018',
    [string]$OutputDir = 'dist',
    [string]$NodeExe = (Get-Command node.exe -ErrorAction Stop).Source,
    [string]$CrtDirectory,
    [switch]$BuildVerificationInstaller
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
function Resolve-Input([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { $Path = Join-Path $repo $Path }
    return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
}
function Write-JsonFile([string]$Path, $Object) {
    [IO.File]::WriteAllText($Path, ($Object | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
}
if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$' -or @($Version.Split('.') | Where-Object { [int64]$_ -gt 65535 }).Count) { throw 'Version must contain four UInt16 numbers.' }
$IsccPath = Resolve-Input $IsccPath
$DriverPath = Resolve-Input $DriverPath
$DriverCertificate = Resolve-Input $DriverCertificate
$NodeLicense = Resolve-Input $NodeLicense
$NodeExe = Resolve-Input $NodeExe
$agent = Resolve-Input (Join-Path $BuildDir 'edr.exe')
$cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($DriverCertificate)
$sig = Get-AuthenticodeSignature -LiteralPath $DriverPath
if (-not $sig.SignerCertificate -or $sig.SignerCertificate.Thumbprint -ne $cert.Thumbprint -or
    $sig.Status -notin @('Valid','NotTrusted','UnknownError')) { throw 'A matching signed test driver and public certificate are required.' }
if ((& $NodeExe -p 'process.arch') -ne 'x64') { throw 'An x64 Node.js runtime is required.' }
if (-not $CrtDirectory) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vs = & $vswhere -latest -products '*' -property installationPath
    if (-not $vs) { throw 'Visual Studio is not registered with vswhere; supply -CrtDirectory explicitly.' }
    $redist = Get-ChildItem -LiteralPath (Join-Path $vs 'VC\Redist\MSVC') -Directory |
        Where-Object Name -match '^\d+\.' | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
    if (-not $redist) { throw 'No MSVC redistributable directory found; supply -CrtDirectory explicitly.' }
    $CrtDirectory = Join-Path $redist.FullName 'x64\Microsoft.VC143.CRT'
}
$CrtDirectory = Resolve-Input $CrtDirectory
if (-not [IO.Path]::IsPathRooted($OutputDir)) { $OutputDir = Join-Path $repo $OutputDir }
$OutputDir = [IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$work = Join-Path $repo ('.omo\installer-20261018\payload-' + [guid]::NewGuid())
foreach ($dir in @($work, "$work\rules", "$work\config", "$work\installer", "$work\runtime", "$work\console", "$work\driver")) {
    New-Item -ItemType Directory -Path $dir | Out-Null
}
Copy-Item -LiteralPath $agent -Destination "$work\edr.exe"
Get-ChildItem -LiteralPath $CrtDirectory -Filter '*.dll' -File | Copy-Item -Destination $work
Get-ChildItem -LiteralPath (Join-Path $repo 'rules') -Filter '*.json' -File | Copy-Item -Destination "$work\rules"
$template = Get-Content -LiteralPath (Join-Path $repo 'config\edr.config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$template.reporter.api_key = ''
$template.reporter.url = 'http://127.0.0.1:8080/ingest'
$template.reporter.enable = $false
$template.response_channel.command_key_file = ''
$template.response_channel.enable = $false
$template.auto_response.enable = $false
$template.webhook.enable = $false
$template.webhook.url = ''
$template.enable_driver_collector = $false
$template.enable_imonitor = $false
Write-JsonFile "$work\config\edr.config.template.json" $template
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'setup.ps1'),(Join-Path $PSScriptRoot 'access.ps1') -Destination "$work\installer"
Copy-Item -LiteralPath $NodeExe -Destination "$work\runtime\node.exe"
Copy-Item -LiteralPath $NodeLicense -Destination "$work\runtime\node-LICENSE.txt"
foreach ($item in Get-ChildItem -LiteralPath (Join-Path $repo 'console') -File -Filter '*.js') {
    if ($item.Name -notmatch '\.test\.js$|^(smoke_test|check_html_js|debug_export)\.js$') { Copy-Item -LiteralPath $item.FullName -Destination "$work\console" }
}
Copy-Item -LiteralPath (Join-Path $repo 'console\public') -Destination "$work\console\public" -Recurse
Copy-Item -LiteralPath (Join-Path $repo 'console\package.json'),(Join-Path $repo 'console\package-lock.json') -Destination "$work\console"
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'console-launcher.js') -Destination "$work\console\installed-launcher.js"
& npm.cmd ci --prefix "$work\console" --omit=dev --ignore-scripts --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw 'Locked production dependency installation failed.' }
Copy-Item -LiteralPath $DriverPath -Destination "$work\driver\edrdrv.sys"
Copy-Item -LiteralPath $DriverCertificate -Destination "$work\driver\edr-test-signing.cer"
$guide = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'INSTALL.txt'), [Text.Encoding]::UTF8)
[IO.File]::WriteAllText("$work\INSTALL.txt", $guide, [Text.UTF8Encoding]::new($true))
$files = @(Get-ChildItem -LiteralPath $work -Recurse -File | Sort-Object FullName | ForEach-Object {
    if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Payload links are not allowed.' }
    if ($_.Name -match '\.(pfx|p12|key)$|^\.env|^(console-keys\.json|console-access\.txt|installation\.json|alerts\.jsonl)$') { throw 'Private state or signing keys must not enter the payload.' }
    [ordered]@{path=$_.FullName.Substring($work.Length + 1).Replace('\','/');bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
})
$manifest = [ordered]@{version=$Version;architecture='x64';created_utc=[DateTime]::UtcNow.ToString('o');driver_variant='ALL';driver_signing='test';driver_signer_thumbprint=$cert.Thumbprint;node_version=(& $NodeExe --version);files=$files}
Write-JsonFile "$work\payload-manifest.json" $manifest
$compileArguments = @('/Qp',('/DPayloadDir=' + $work),('/DOutputDir=' + $OutputDir),('/DPackageVersion=' + $Version),('/DDriverThumbprint=' + $cert.Thumbprint),(Join-Path $PSScriptRoot 'edr.iss'))
& $IsccPath @compileArguments
if ($LASTEXITCODE -ne 0) { throw 'Installer compilation failed.' }
$setup = Join-Path $OutputDir ('EDR-Setup-' + $Version + '-x64.exe')
$hash = (Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText(($setup + '.sha256'), ($hash + '  ' + [IO.Path]::GetFileName($setup) + "`r`n"))
Copy-Item -LiteralPath "$work\payload-manifest.json" -Destination (Join-Path $OutputDir 'EDR-payload-manifest.json')
Copy-Item -LiteralPath "$work\INSTALL.txt" -Destination (Join-Path $OutputDir 'EDR-INSTALL.txt')
Copy-Item -LiteralPath $DriverCertificate -Destination (Join-Path $OutputDir 'EDR-driver-test-signing.cer')
$verification = ''
if ($BuildVerificationInstaller) {
    $verifyDir = Join-Path $repo '.omo\installer-20261018\verification-installer'
    New-Item -ItemType Directory -Path $verifyDir -Force | Out-Null
    $verifyArguments = @('/Qp','/DStagingTest',('/DPayloadDir=' + $work),('/DOutputDir=' + $verifyDir),('/DPackageVersion=' + $Version),('/DDriverThumbprint=' + $cert.Thumbprint),(Join-Path $PSScriptRoot 'edr.iss'))
    & $IsccPath @verifyArguments
    if ($LASTEXITCODE -ne 0) { throw 'Verification installer compilation failed.' }
    $verification = Join-Path $verifyDir 'EDR-Installer-Verification.exe'
}
$result = [ordered]@{installer=$setup;sha256=$hash;payload=$work;manifest=(Join-Path $OutputDir 'EDR-payload-manifest.json');verification_installer=$verification}
Write-JsonFile (Join-Path $repo '.omo\installer-20261018\build-result.json') $result
$result | ConvertTo-Json
