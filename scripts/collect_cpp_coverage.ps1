[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $BuildDirectory,
    [string] $OutputDirectory = $(if ($env:RUNNER_TEMP) {
        Join-Path $env:RUNNER_TEMP 'edr-cpp-coverage'
    } else {
        Join-Path ([System.IO.Path]::GetTempPath()) 'edr-cpp-coverage'
    })
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$buildPath = (Resolve-Path $BuildDirectory).Path
$coverageCommand = Get-Command OpenCppCoverage.exe -ErrorAction SilentlyContinue
if (-not $coverageCommand) {
    throw 'OpenCppCoverage.exe is required; install pinned version 0.9.9.0 before this report step.'
}
$ctestCommand = Get-Command ctest.exe -ErrorAction SilentlyContinue
if (-not $ctestCommand) {
    throw 'ctest.exe was not found on PATH; initialize the Visual Studio/CMake environment.'
}

$testExe = Join-Path $buildPath 'edr_native_tests.exe'
$testPdb = Join-Path $buildPath 'edr_native_tests.pdb'
if (-not (Test-Path $testExe)) { throw "Native test executable not found: $testExe" }
if (-not (Test-Path $testPdb)) {
    throw "Native test PDB not found: $testPdb; configure and build the coverage target with Debug symbols."
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
$cobertura = Join-Path $OutputDirectory 'cpp-coverage.xml'
$html = Join-Path $OutputDirectory 'html'
$testRegex = '^edr_native_tests$'
$coverageArgs = @(
    '--cover_children',
    '--sources', (Join-Path $repositoryRoot 'user'),
    '--sources', (Join-Path $repositoryRoot 'common'),
    '--modules', $repositoryRoot,
    '--export_type', "cobertura:$cobertura",
    '--export_type', "html:$html",
    '--', $ctestCommand.Source,
    '--test-dir', $buildPath,
    '--output-on-failure',
    '-R', $testRegex
)
& $coverageCommand.Source @coverageArgs
$coverageExit = $LASTEXITCODE
if ($coverageExit -ne 0) {
    throw "OpenCppCoverage/CTest failed with exit code $coverageExit"
}
if (-not (Test-Path $cobertura) -or (Get-Item $cobertura).Length -eq 0) {
    throw "OpenCppCoverage did not create the Cobertura report: $cobertura"
}
Write-Output "Coverage reports: $cobertura and $html"
