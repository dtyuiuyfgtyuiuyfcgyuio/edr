# EDR System Tray App
# Run: PowerShell -NoProfile -File EdrTray.ps1
# Or double-click EdrTray.cmd

$nativeCandidates = @(
    (Join-Path $PSScriptRoot "bin\Release\net10.0-windows\EdrTray.exe"),
    (Join-Path $PSScriptRoot "bin\Debug\net10.0-windows\EdrTray.exe")
)
$nativeClient = $nativeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if ($nativeClient) {
    Start-Process -FilePath $nativeClient
    exit
}

$frameworkClient = Join-Path $PSScriptRoot "bin\Release\net10.0-windows\EdrTray.dll"
if (Test-Path -LiteralPath $frameworkClient) {
    Start-Process -FilePath "dotnet" -ArgumentList @($frameworkClient)
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Net.Http

$script:tray = New-Object System.Windows.Forms.NotifyIcon
$script:tray.Icon = [System.Drawing.SystemIcons]::Shield
$script:tray.Text = "EDR Agent - starting..."
$script:tray.Visible = $true
$script:tray.BalloonTipTitle = "EDR Alert"

# Context menu
$menu = New-Object System.Windows.Forms.ContextMenuStrip

$dashItem = $menu.Items.Add("Open Dashboard")
$dashItem.Add_Click({ [System.Diagnostics.Process]::Start("http://localhost:8080") })

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$statusItem = $menu.Items.Add("Status: checking...")
$statusItem.Enabled = $false

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$restartItem = $menu.Items.Add("Restart Backend")
$restartItem.Add_Click({
    try {
        $p = Get-Process -Name "node" -ErrorAction SilentlyContinue |
            Where-Object { $_.CommandLine -match "server.js" }
        if ($p) { $p.Kill() }
        Start-Process -WindowStyle Hidden -FilePath "node" -ArgumentList "C:\EDR\console\server.js"
        $statusItem.Text = "Status: restarting..."
    } catch { }
})

$menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

$exitItem = $menu.Items.Add("Exit")
$exitItem.Add_Click({
    $script:tray.Visible = $false
    [System.Windows.Forms.Application]::Exit()
})
$script:tray.ContextMenuStrip = $menu

# Alert click handler - open dashboard
$script:tray.Add_BalloonTipClicked({
    [System.Diagnostics.Process]::Start("http://localhost:8080")
})

# HTTP client
$client = New-Object System.Net.Http.HttpClient
$client.BaseAddress = New-Object System.Uri("http://localhost:8080")
$client.Timeout = [System.TimeSpan]::FromSeconds(5)
$script:lastCount = 0

function Poll-Alerts {
    try {
        $resp = $client.GetAsync("/api/stats").GetAwaiter().GetResult()
        $json = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $stats = $json | ConvertFrom-Json
        $total = $stats.total

        if ($total -gt $script:lastCount -and $script:lastCount -gt 0) {
            $newAlerts = $total - $script:lastCount
            $severities = $stats.bySeverity.PSObject.Properties |
                Where-Object { $_.Value -gt 0 } |
                ForEach-Object { "$($_.Name): $($_.Value)" }
            $body = "$newAlerts new alert(s)`n$($severities -join ', ')"
            $script:tray.ShowBalloonTip(8000, "EDR Alert - $newAlerts new", $body,
                [System.Windows.Forms.ToolTipIcon]::Warning)
        }
        $script:lastCount = $total
        $script:tray.Text = "EDR Agent - $total alerts"
        $statusItem.Text = "Status: OK ($total alerts)"
    } catch {
        $script:tray.Text = "EDR Agent - disconnected"
        $statusItem.Text = "Status: disconnected"
    }
}

# Start polling
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 10000
$timer.Add_Tick({ Poll-Alerts })
$timer.Start()
Poll-Alerts

# Keep running
[System.Windows.Forms.Application]::Run()
