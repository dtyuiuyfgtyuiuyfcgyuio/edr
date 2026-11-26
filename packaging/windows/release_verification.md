# Windows release verification record

Use this record on an authorized Windows 10 2004+ or Windows 11 x64 test VM. Restore a clean VM snapshot before testing. Do not enable real response actions; leave automatic response, response channel, host isolation, and the driver component off unless a separate driver run is explicitly approved and prepared.

## Choose the installation path

| Path | What it verifies | What it does not verify |
| --- | --- | --- |
| Normal administrator install | The normal elevated installer, protected Program Files / ProgramData locations, agent service, optional SYSTEM console task, credentials, repair, and uninstall behavior. Select only the agent and console unless the VM is prepared for the test signed driver. | It does not by itself prove driver loading, real log-channel availability, service startup after a reboot, or Driver Verifier behavior. |
| `StagingTest` / `StageOnly` installer | The staging installer and file lifecycle in the current user's profile. It is intentionally non-elevated and skips service, SYSTEM task, and driver registration. | It is not a substitute for normal administrator or SYSTEM integration. |

Build and smoke commands are maintained in the [Windows packaging README](README.md). Reuse `tests/installer_package_tests.ps1` for package checks and `tests/installer_smoke_test.js` for the installed console/agent smoke checks. For the source suite, use the CMake/CTest commands in [README.md](../../README.md). Record separately which source snapshot, payload manifest, installer hash, and test scripts were used.

The repository's [Windows CI workflow](../../.github/workflows/edr-ci.yml) uses a GitHub-hosted `windows-2022` runner for MSVC build/CTest and Node checks. Its existence is not evidence that a particular revision passed; record the run URL and result when available. CI does not replace an authorized interactive Windows VM for installer, real collection, service/SYSTEM startup, or driver loading checks.

## Normal administrator lifecycle

On the disposable VM, install the agent and console as administrator, keep the driver unchecked, and start the services. Confirm `Get-Service edr` reaches `Running`, `EDR Local Console` is registered to run as SYSTEM, and the authenticated console responds on loopback. Reboot once; confirm the service and SYSTEM task return to `Running` and the console responds again. Run the harmless checks below, then use the same installer to repair and verify that config, access keys, and history are retained. Uninstall and confirm those data files remain. Keep the console key values out of logs and screenshots.

Exercise service recovery on this VM only: save an exact backup of the protected `edr.config.json`, replace it temporarily with invalid JSON, stop and start `edr`, and record the failed start/restart state and SCM log. Restore the exact config in a `finally`/cleanup step, start `edr`, and confirm it returns to `Running` and telemetry is queryable. Do not leave the invalid config installed. If recovery cannot be observed safely, mark the injection `Not run` and retain the failure reason. The installed service passes both `--config` and `--rules` on its command line, so corrupting `rules_path` alone does not force a rules-load failure.

`StageOnly` uses the non-elevated `StagingTest` installer, writes under the current user's profile, and skips SCM service, SYSTEM task, and driver registration. Its file install/repair/uninstall result belongs in a separate record; it cannot satisfy the administrator lifecycle checks.

## Harmless real-collection check

Run these only after the normal agent and console are installed and running. The shipped template enables process ETW and file fallback, while the Task Scheduler log collector is off by default. Event channels, permissions, and host policy still apply. Back up config before temporarily changing it; restore it and remove all created files/tasks after the run. Do not enable a real response action.

First launch `whoami.exe` and look for its process start event in the authenticated local console. The PID query avoids matching an older run:

```powershell
$state = Join-Path $env:ProgramData 'EDRAgent'
$keys = Get-Content (Join-Path $state 'console-keys.json') -Raw | ConvertFrom-Json
$headers = @{ 'X-API-Key' = $keys.read }
$proc = Start-Process -FilePath (Join-Path $env:WINDIR 'System32\whoami.exe') -PassThru -Wait
$uri = "http://127.0.0.1:8080/api/events?type=PROCESS_START&pid=$($proc.Id)&limit=500"

$deadline = [DateTime]::UtcNow.AddSeconds(30)
$match = $null
while ([DateTime]::UtcNow -lt $deadline -and -not $match) {
    $response = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 5
    $match = $response.events | Where-Object {
        $_.raw.fields.image -like '*\whoami.exe'
    } | Select-Object -First 1
    if (-not $match) { Start-Sleep -Milliseconds 500 }
}
if (-not $match) { throw 'No whoami.exe PROCESS_START event reached the local console.' }
$match | ConvertTo-Json -Depth 8
```

Use a fresh `$runId` and a temporary `log`-only rule to prove detection and alert persistence. The service's `--rules` argument overrides config `rules_path`; set `$rulesPath` to the actual catalog path in the `edr` SCM command line (normally `%ProgramFiles%\EDR Agent\rules\rules.json`). This PowerShell block backs up the catalog, appends a rule to its `rules` array, starts a harmless marked script, verifies the matching alert, and restores the exact file in `finally`:

```powershell
$state = Join-Path $env:ProgramData 'EDRAgent'
$verifyDir = Join-Path $state 'verification'
$rulesPath = Join-Path $env:ProgramFiles 'EDR Agent\rules\rules.json' # use the SCM --rules path
$runId = [Guid]::NewGuid().ToString('N').Substring(0, 12).ToLowerInvariant()
$marker = "edrverify-$runId"
$ruleId = "EDR-VERIFY-$runId"
$rulesBackup = Join-Path $verifyDir "rules-$runId.backup.json"
$scriptPath = Join-Path $verifyDir "$marker.cmd"
New-Item -ItemType Directory -Path $verifyDir -Force | Out-Null
Copy-Item -LiteralPath $rulesPath -Destination $rulesBackup
try {
    $catalog = Get-Content -LiteralPath $rulesPath -Raw | ConvertFrom-Json
    $rule = @{ id = $ruleId; severity = 'low'; action = 'log'; condition = 'all';
        match = @{ type = @{ eq = 'PROCESS_START' }; command_line = @{ contains = $marker } } }
    $catalog.rules = @($catalog.rules) + @($rule)
    [IO.File]::WriteAllText($rulesPath, ($catalog | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText($scriptPath, "@echo off`r`n%SystemRoot%\System32\whoami.exe`r`n", [Text.Encoding]::ASCII)
    Restart-Service -Name edr
    Start-Process -FilePath (Join-Path $env:WINDIR 'System32\cmd.exe') `
        -ArgumentList "/c `"$scriptPath`"" -Wait

    $keys = Get-Content (Join-Path $state 'console-keys.json') -Raw | ConvertFrom-Json
    $headers = @{ 'X-API-Key' = $keys.read }
    $uri = "http://127.0.0.1:8080/api/alerts?rule=$ruleId&limit=20"
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $response = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -TimeoutSec 5
        if ($response.total -gt 0) { break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $response -or $response.total -lt 1) { throw "No alert for $ruleId reached the console." }
    "Verified alert count: $($response.total); rule: $ruleId"
}
finally {
    Stop-Service -Name edr -ErrorAction SilentlyContinue
    Copy-Item -LiteralPath $rulesBackup -Destination $rulesPath -Force
    Start-Service -Name edr
    (Get-Service -Name edr).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Remove-Item -LiteralPath $rulesBackup, $scriptPath -Force -ErrorAction SilentlyContinue
}
```

The alert endpoint filters by exact `rule` and returns `{ total, alerts }`. The rule only logs a low severity alert; no responder is instantiated by this check.

For a harmless file event, add a dedicated temporary directory to `watch_dirs`, enable `enable_file_fallback`, restart the agent, create a uniquely named text file directly inside that directory, and confirm a `FILE_CREATE` event whose `raw.fields.file_path` contains the marker. Do not use a protected Windows path.

For a harmless scheduled task event, enable `enable_taskscheduler_log` and confirm `Microsoft-Windows-TaskScheduler/Operational` is already enabled. Only enable that channel on the test VM if its owner approves and record its previous state. Register and start a uniquely named one-time task whose action is `cmd.exe /c exit 0`; for example, use `New-ScheduledTaskAction`, `New-ScheduledTaskTrigger -Once`, and `New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest` with a name `EDR-VERIFY-$runId`. Then remove it with `Unregister-ScheduledTask`. Confirm `TASK_SCHEDULER` records for the unique `raw.fields.task_name` (registration and/or start/completion). Restore the collector config and channel to their prior state. If the channel is unavailable or policy prevents collection, record `Not run` with the reason.

Confirm the three independent API roles without printing their values. Use the read key for `GET /api/events` (200); the other two keys should get 401. Use the ingest key to repost the already observed event's `raw` object to `POST /ingest/events`; expected response is `{ ok: true, accepted: 0, dedup: 1 }`, and read/admin keys should get 401. Use the admin key for read-only `GET /api/playbooks` (200); read/ingest keys should get 401. The ingest check reuses the observed event ID, so it should deduplicate without adding another ledger row. Do not place keys in command arguments, transcripts, or evidence attachments.

If an actual event or alert is absent, record collector health, agent log, OS policy/channel state, and console ingest status. Synthetic selftest events do not count as proof of real collection.

## Driver verification (separate sign-off)

Do not infer kernel verification from a user-mode pass. Only run this section on a disposable test VM whose owner has prepared test signing and trusted the matching public test certificate. The build/package inputs are documented in the [Windows packaging README](README.md); the installer checks the SYS signer against the public CER. Never place a PFX or private key in the repository or test record. If no authorized, prepared VM and matching signed SYS/CER are available, mark every driver result `Not run`.

Record driver build variant (`ALL`), SYS SHA-256, signer thumbprint, CER SHA-256, Code Integrity/test-signing state, install/start result, emitted driver events, removal result, and any Driver Verifier coverage. Record a skipped or unavailable check as such; do not convert it into a pass.

## Verification record

| Field | Result |
| --- | --- |
| Run ID / UTC date / operator | |
| Authorized VM owner and snapshot | |
| Windows edition, version, build, architecture | |
| Source revision / dirty state | |
| Installer filename and SHA-256 | |
| Payload manifest path and SHA-256 | |
| Installation path (`Normal admin` or `StageOnly`) | |
| Selected components; driver selected? | |
| Package tests and exit codes | |
| Installed smoke test and exit code | |
| Windows CI workflow run URL / result | |
| Harmless `whoami.exe` event observed (event ID/time) | |
| Temporary log-only rule ID and matching alert observed | |
| Harmless file event observed (path/action/time) | |
| Harmless scheduled task events observed / channel state restored | |
| Three-role API checks (record status codes/counts only) | |
| Reboot / SCM service / SYSTEM task results (normal install only) | |
| Injected bad-config startup failure and recovery result | |
| Repair / uninstall / retained data results | |
| Driver SYS/CER hashes and signer (separate driver run) | |
| Driver load / event / removal / Driver Verifier results | |
| Failures, skips, logs, and evidence paths | |
| Final status (`Pass`, `Fail`, `Partial`, `Not run`) | |

## Current workspace availability

This record was prepared from a Linux x86_64 workspace. A GitHub-hosted `windows-2022` CI runner is configured in the repository, but there is no attached Windows session or run result in this workspace. No authorized Windows VM or signed SYS/CER/installer artifact was present in the repository file tree. Windows installation, real event collection, service/SYSTEM startup and recovery, and driver checks therefore remain pending until run on an authorized Windows environment.
