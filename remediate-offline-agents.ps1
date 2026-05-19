# remediate-offline-agents.ps1
# Queries WatchTower for disconnected agents and remotely restarts the
# SentinelWatchNode service on each one via WinRM (Invoke-Command).
#
# Usage:
#   .\remediate-offline-agents.ps1 -ServerIP 192.168.100.215
#   .\remediate-offline-agents.ps1 -ServerIP 192.168.100.215 -CsvFile machines.csv -DryRun
#   .\remediate-offline-agents.ps1 -ServerIP 192.168.100.215 -ApiKey "my-key" -TimeoutSeconds 20

param(
    [string]$ServerIP      = "192.168.100.215",   # SIEM server IP
    [int]$ServerPort       = 9400,                 # WatchTower API port
    [string]$ApiKey        = "sentinel-dev-api-key", # API key
    [string]$CsvFile       = "",                   # Optional: machines.csv (ComputerName,IP)
    [int]$TimeoutSeconds   = 10,                   # WinRM timeout per machine
    [switch]$DryRun                                # Show what would be done without doing it
)

# ─── Colour helpers ───────────────────────────────────────────────────────────
function Write-Info    { param($Msg) Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-OK      { param($Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn    { param($Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Fail    { param($Msg) Write-Host "[-] $Msg" -ForegroundColor Red }
function Write-Section { param($Msg) Write-Host "`n$('=' * 48)`n  $Msg`n$('=' * 48)" -ForegroundColor Yellow }

# ─── Banner ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================" -ForegroundColor Yellow
Write-Host "  Sentinel SIEM — Offline Agent Remediation     " -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Yellow
if ($DryRun) {
    Write-Host "  ** DRY-RUN MODE — no changes will be made **" -ForegroundColor Magenta
}
Write-Host ""

# ─── Load optional CSV (ComputerName -> IP lookup) ───────────────────────────
$CsvLookup = @{}
if ($CsvFile -ne "" -and (Test-Path $CsvFile)) {
    Write-Info "Loading CSV: $CsvFile"
    Import-Csv $CsvFile | ForEach-Object {
        if ($_.ComputerName -and $_.IP) {
            $CsvLookup[$_.ComputerName.Trim()] = $_.IP.Trim()
        }
    }
    Write-Info "  Loaded $($CsvLookup.Count) entries from CSV"
} elseif ($CsvFile -ne "") {
    Write-Warn "CSV file '$CsvFile' not found — will connect by hostname only"
}

# ─── Query WatchTower API ─────────────────────────────────────────────────────
Write-Section "Querying WatchTower API"
$ApiUrl = "http://${ServerIP}:${ServerPort}/api/v1/agents"
Write-Info "GET $ApiUrl"

try {
    $Headers = @{ "Authorization" = "Bearer $ApiKey" }
    $Response = Invoke-RestMethod -Uri $ApiUrl -Headers $Headers -Method Get -TimeoutSec 15 -ErrorAction Stop
} catch {
    Write-Fail "Failed to reach WatchTower API: $($_.Exception.Message)"
    Write-Fail "  URL : $ApiUrl"
    Write-Fail "  Hint: Verify -ServerIP / -ServerPort / -ApiKey and that WatchTower is running"
    exit 1
}

# Support both a bare array response and a { agents: [...] } envelope
$AllAgents = if ($Response -is [System.Array]) { $Response }
             elseif ($Response.agents) { $Response.agents }
             else { @($Response) }

Write-Info "Total agents returned: $($AllAgents.Count)"

$DisconnectedAgents = $AllAgents | Where-Object { $_.status -eq "disconnected" }
$DisconnectedCount  = ($DisconnectedAgents | Measure-Object).Count

if ($DisconnectedCount -eq 0) {
    Write-OK "No disconnected agents found — nothing to do."
    Write-Host ""
    exit 0
}

Write-Warn "$DisconnectedCount disconnected agent(s) found:"
$DisconnectedAgents | ForEach-Object {
    $lastSeen = if ($_.last_seen) { $_.last_seen } else { "unknown" }
    Write-Host "  - $($_.hostname)  (last seen: $lastSeen)" -ForegroundColor Gray
}

# ─── Remediate each disconnected agent ───────────────────────────────────────
Write-Section "Restarting Services"

# Result tracking
$Restarted   = [System.Collections.Generic.List[string]]::new()
$Failed      = [System.Collections.Generic.List[string]]::new()
$Unreachable = [System.Collections.Generic.List[string]]::new()

$RestartBlock = {
    # Runs on the remote machine
    $svc = Get-Service -Name "SentinelWatchNode" -ErrorAction SilentlyContinue
    if (-not $svc) {
        throw "Service 'SentinelWatchNode' does not exist on this host"
    }
    Restart-Service -Name "SentinelWatchNode" -Force -ErrorAction Stop
    # Return the new status
    (Get-Service -Name "SentinelWatchNode").Status.ToString()
}

$Current = 0
foreach ($Agent in $DisconnectedAgents) {
    $Current++
    $Hostname = $Agent.hostname
    if (-not $Hostname) {
        Write-Warn "[$Current/$DisconnectedCount] Agent has no hostname field — skipping"
        $Failed.Add("<no-hostname>")
        continue
    }

    # Resolve connection target: prefer CSV IP lookup, fall back to hostname
    $Target = if ($CsvLookup.ContainsKey($Hostname)) { $CsvLookup[$Hostname] } else { $Hostname }

    Write-Host ""
    Write-Info "[$Current/$DisconnectedCount] $Hostname  →  target: $Target"

    if ($DryRun) {
        Write-Warn "  [DRY-RUN] Would run: Restart-Service SentinelWatchNode on $Target"
        $Restarted.Add($Hostname)
        continue
    }

    try {
        $SessionOptions = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000) `
                                              -OperationTimeout ($TimeoutSeconds * 1000)

        $NewStatus = Invoke-Command `
            -ComputerName $Target `
            -ScriptBlock  $RestartBlock `
            -SessionOption $SessionOptions `
            -ErrorAction Stop

        Write-OK "  Restarted successfully — service is now: $NewStatus"
        $Restarted.Add($Hostname)

    } catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
        # WinRM not available / port closed / auth failure
        Write-Fail "  UNREACHABLE — WinRM error: $($_.Exception.Message)"
        $Unreachable.Add($Hostname)

    } catch [System.Net.WebException] {
        Write-Fail "  UNREACHABLE — network error: $($_.Exception.Message)"
        $Unreachable.Add($Hostname)

    } catch {
        Write-Fail "  FAILED — $($_.Exception.Message)"
        $Failed.Add($Hostname)
    }
}

# ─── Summary table ────────────────────────────────────────────────────────────
Write-Section "Remediation Summary"

$DryNote = if ($DryRun) { " (dry-run)" } else { "" }

Write-Host ("  {0,-18} {1}" -f "Disconnected:", $DisconnectedCount)
Write-Host ("  {0,-18} {1}{2}" -f "Restarted:", $Restarted.Count, $DryNote) -ForegroundColor $(if ($Restarted.Count -gt 0) { "Green" } else { "Gray" })
Write-Host ("  {0,-18} {1}" -f "Failed (WinRM):", $Unreachable.Count) -ForegroundColor $(if ($Unreachable.Count -gt 0) { "Yellow" } else { "Gray" })
Write-Host ("  {0,-18} {1}" -f "Failed (other):", $Failed.Count) -ForegroundColor $(if ($Failed.Count -gt 0) { "Red" } else { "Gray" })
Write-Host ""

if ($Restarted.Count -gt 0) {
    Write-Host "  Restarted$DryNote:" -ForegroundColor Green
    $Restarted | ForEach-Object { Write-Host "    - $_" -ForegroundColor Green }
    Write-Host ""
}

if ($Unreachable.Count -gt 0) {
    Write-Host "  Unreachable (WinRM not available or auth failed):" -ForegroundColor Yellow
    $Unreachable | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
    Write-Host "  Hint: Ensure WinRM is enabled (winrm quickconfig) and firewall allows TCP 5985/5986." -ForegroundColor Gray
    Write-Host ""
}

if ($Failed.Count -gt 0) {
    Write-Host "  Failed (service error or missing):" -ForegroundColor Red
    $Failed | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host ""
}

Write-Info "Dashboard: http://${ServerIP}:5050"
Write-Host ""

# ─── Exit code ───────────────────────────────────────────────────────────────
# 0 = all succeeded (or nothing to do), 1 = at least one failure / unreachable
if ($Unreachable.Count -gt 0 -or $Failed.Count -gt 0) {
    exit 1
}
exit 0
