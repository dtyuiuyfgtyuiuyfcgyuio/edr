@echo off
setlocal
set "TRAY_DIR=%~dp0"

if exist "%TRAY_DIR%bin\Release\net10.0-windows\EdrTray.exe" (
    start "EDR Endpoint UI" "%TRAY_DIR%bin\Release\net10.0-windows\EdrTray.exe"
    exit /b 0
)

if exist "%TRAY_DIR%bin\Debug\net10.0-windows\EdrTray.exe" (
    start "EDR Endpoint UI" "%TRAY_DIR%bin\Debug\net10.0-windows\EdrTray.exe"
    exit /b 0
)

if exist "%TRAY_DIR%bin\Release\net10.0-windows\EdrTray.dll" (
    start "EDR Endpoint UI" dotnet "%TRAY_DIR%bin\Release\net10.0-windows\EdrTray.dll"
    exit /b 0
)

where dotnet >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] EDR endpoint UI is not built and the .NET SDK is not installed.
    echo Run console\install.cmd after installing the .NET 10 SDK.
    pause
    exit /b 1
)

echo [EDR Endpoint UI] Building and starting...
dotnet run --project "%TRAY_DIR%EdrTray.csproj"
