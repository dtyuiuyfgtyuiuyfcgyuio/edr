#ifndef PayloadDir
  #error PayloadDir is required
#endif
#ifndef OutputDir
  #error OutputDir is required
#endif
#ifndef PackageVersion
  #define PackageVersion "1.0.2026.1018"
#endif

[Setup]
AppName=EDR Agent
AppVersion={#PackageVersion}
AppPublisher=EDR Project
DefaultGroupName=EDR Agent
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.19041
#ifdef StagingTest
PrivilegesRequired=lowest
DefaultDirName={localappdata}\EDR Installer Verification
AppId={{269B558E-1917-43F5-AB5A-3793C59649C5}
OutputBaseFilename=EDR-Installer-Verification
#else
PrivilegesRequired=admin
AppId={{261A4389-DA22-4DA3-9DDE-96D48A9175C1}
DefaultDirName={autopf}\EDR Agent
OutputBaseFilename=EDR-Setup-{#PackageVersion}-x64
#endif
OutputDir={#OutputDir}
Compression=lzma2/fast
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
CloseApplications=no
RestartApplications=no
UninstallDisplayIcon={app}\edr.exe
SetupLogging=yes
InfoBeforeFile={#PayloadDir}\INSTALL.txt

[Languages]
Name: english; MessagesFile: compiler:Default.isl

[Types]
Name: standard; Description: "Agent and local Web console"
Name: minimal; Description: "Agent only"
Name: custom; Description: "Custom (optional test driver)"; Flags: iscustom

[Components]
Name: agent; Description: "EDR Agent / EDR 代理"; Types: standard minimal custom; Flags: fixed
Name: console; Description: "Local Web console / 本地 Web 控制台"; Types: standard
Name: driver; Description: "Test-signed kernel driver / 内核驱动（仅限已准备的测试虚拟机）"; Types: custom

[Tasks]
Name: startservices; Description: "Start EDR after installation / 安装完成后启动 EDR"

[Files]
Source: "{#PayloadDir}\edr.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\*.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\rules\*.json"; DestDir: "{app}\rules"; Flags: ignoreversion
Source: "{#PayloadDir}\config\*"; DestDir: "{app}\config"; Flags: ignoreversion
Source: "{#PayloadDir}\installer\*.ps1"; DestDir: "{app}\installer"; Flags: ignoreversion
Source: "{#PayloadDir}\INSTALL.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\payload-manifest.json"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PayloadDir}\runtime\*"; DestDir: "{app}\runtime"; Components: console; Flags: ignoreversion
Source: "{#PayloadDir}\console\*"; DestDir: "{app}\console"; Components: console; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#PayloadDir}\driver\*"; DestDir: "{app}\driver"; Components: driver; Flags: ignoreversion
Source: "{#PayloadDir}\installer\setup.ps1"; DestName: preflight.ps1; Flags: dontcopy
Source: "{#PayloadDir}\driver\edrdrv.sys"; DestName: driver-check.sys; Flags: dontcopy

[Icons]
Name: "{autoprograms}\EDR Agent\Open Web Console"; Filename: "http://127.0.0.1:8080"; Components: console
Name: "{autoprograms}\EDR Agent\Console access keys (administrator)"; Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\access.ps1"" -StateDir ""{commonappdata}\EDRAgent"""; Components: console
Name: "{autoprograms}\EDR Agent\Installation guide"; Filename: "{app}\INSTALL.txt"
Name: "{autoprograms}\EDR Agent\Uninstall EDR"; Filename: "{uninstallexe}"

[Code]
var IntegrationError: String;

function StateDir: String;
begin
#ifdef StagingTest
  Result := ExpandConstant('{app}\TestData');
#else
  Result := ExpandConstant('{commonappdata}\EDRAgent');
#endif
end;

function InvokeSetupAction(Action, ScriptPath, Extra: String): String;
var
  Params, ResultPath: String;
  ExitCode: Integer;
  ErrorText: AnsiString;
begin
  Result := '';
  ResultPath := ExpandConstant('{tmp}\edr-setup-result.txt');
  DeleteFile(ResultPath);
  Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ScriptPath +
    '" -Action ' + Action + ' -AppDir "' + ExpandConstant('{app}') +
    '" -DataDir "' + StateDir + '" -ResultFile "' + ResultPath + '" ' + Extra;
#ifdef StagingTest
  Params := Params + ' -StageOnly';
#endif
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params,
      ExpandConstant('{tmp}'), SW_HIDE, ewWaitUntilTerminated, ExitCode) then
    Result := 'Could not run the Windows installation helper.'
  else if ExitCode <> 0 then begin
    if LoadStringFromFile(ResultPath, ErrorText) then Result := String(ErrorText)
    else Result := 'EDR setup action failed. See the setup log; exit code ' + IntToStr(ExitCode);
  end;
end;

function ComponentArguments: String;
begin
  Result := '';
  if WizardIsComponentSelected('console') then Result := Result + ' -Console';
  if WizardIsComponentSelected('driver') then Result := Result + ' -Driver -DriverThumbprint {#DriverThumbprint}';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Extra: String;
begin
  ExtractTemporaryFile('preflight.ps1');
  Extra := ComponentArguments;
  if WizardIsComponentSelected('driver') then begin
    ExtractTemporaryFile('driver-check.sys');
    Extra := Extra + ' -DriverFile "' + ExpandConstant('{tmp}\driver-check.sys') + '"';
  end;
  Result := InvokeSetupAction('Preflight', ExpandConstant('{tmp}\preflight.ps1'), Extra);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Extra, Error: String;
begin
  if CurStep = ssPostInstall then begin
    Extra := ComponentArguments;
    if WizardIsTaskSelected('startservices') then Extra := Extra + ' -StartServices';
    Error := InvokeSetupAction('Install', ExpandConstant('{app}\installer\setup.ps1'), Extra);
    if Error <> '' then begin
      IntegrationError := Error;
      Log('EDR system integration failed: ' + Error);
      SuppressibleMsgBox('EDR integration failed. Files are retained for repair or uninstall.' + #13#10 + Error, mbError, MB_OK, IDOK);
    end;
  end;
end;

function GetCustomSetupExitCode: Integer;
begin
  if IntegrationError <> '' then Result := 1 else Result := 0;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpFinished) and (IntegrationError <> '') then begin
    WizardForm.FinishedHeadingLabel.Caption := 'EDR setup needs attention';
    WizardForm.FinishedLabel.Caption := 'System integration failed. Installed files were retained for repair or uninstall.' + #13#10 + IntegrationError;
  end;
end;

function InitializeUninstall: Boolean;
var
  Error: String;
begin
  Error := InvokeSetupAction('Uninstall', ExpandConstant('{app}\installer\setup.ps1'), '');
  Result := Error = '';
  if not Result then SuppressibleMsgBox(Error, mbError, MB_OK, IDOK);
end;
