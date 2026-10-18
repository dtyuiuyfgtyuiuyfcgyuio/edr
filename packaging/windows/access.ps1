param([Parameter(Mandatory=$true)][string]$StateDir)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -StateDir "' + $StateDir + '"'
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden
    exit
}
$file = Join-Path $StateDir 'console-access.txt'
if (-not (Test-Path -LiteralPath $file)) { throw 'Console access information is missing.' }
# User explicitly opened this shortcut to view the administrator-only keys.
Start-Process -FilePath "$env:SystemRoot\System32\notepad.exe" -ArgumentList ('"' + $file + '"')
