# Sentinel Agent - One-Click Windows Installer
# Run this from PowerShell as Administrator. No execution policy changes needed.
#
# USAGE:
#   Right-click PowerShell → Run as Administrator, then run:
#   powershell -ExecutionPolicy Bypass -File .\INSTALL-AGENT.ps1 -ServerIP 192.168.100.100
#
# Or if you saved this as a .ps1, just paste this block into an Admin PowerShell:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
#   .\INSTALL-AGENT.ps1 -ServerIP 192.168.100.100

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIP,
    [string]$ServerPort = "50051",
    [string]$Token = "sentinel-enroll-secret-2024"
)

$ErrorActionPreference = "Stop"

# --- Self-elevate if not Administrator ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-launching as Administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" -ServerIP $ServerIP -ServerPort $ServerPort -Token $Token"
    exit
}

$InstallDir = "C:\Program Files\SentinelAgent"
$ServiceName = "SentinelAgent"
$BinaryPath = "$InstallDir\watchnode.exe"
$ConfigPath = "$InstallDir\config.yaml"
$CertsDir = "$InstallDir\certs"
$DataDir = "C:\ProgramData\SentinelAgent"
$LogDir = "$DataDir\logs"

Write-Host "`n=== Sentinel Agent Installer ===" -ForegroundColor Cyan
Write-Host "Server: $ServerIP`:$ServerPort" -ForegroundColor White
Write-Host ""

# --- Step 1: Stop and remove any existing service ---
Write-Host "[1/7] Cleaning up any existing installation..." -ForegroundColor Yellow
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    if ($existingService.Status -eq 'Running') { Stop-Service -Name $ServiceName -Force }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}
# Also kill any orphan watchnode.exe processes
Get-Process -Name watchnode -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# --- Step 2: Verify files are in place ---
Write-Host "[2/7] Verifying installation files..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$missing = @()
foreach ($f in @("watchnode.exe", "config.yaml", "certs\ca.crt", "certs\watchnode.crt", "certs\watchnode.key")) {
    if (-not (Test-Path "$scriptDir\$f")) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-Host "[X] Missing required files:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host "Make sure you extracted the SentinelAgent.zip correctly." -ForegroundColor Red
    exit 1
}
Write-Host "  All required files found." -ForegroundColor Green

# --- Step 3: Copy files to Program Files ---
Write-Host "[3/7] Installing files to $InstallDir..." -ForegroundColor Yellow
if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
if (-not (Test-Path $CertsDir)) { New-Item -ItemType Directory -Path $CertsDir -Force | Out-Null }
if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

Copy-Item "$scriptDir\watchnode.exe" $BinaryPath -Force
Copy-Item "$scriptDir\certs\ca.crt" "$CertsDir\ca.crt" -Force
Copy-Item "$scriptDir\certs\watchnode.crt" "$CertsDir\watchnode.crt" -Force
Copy-Item "$scriptDir\certs\watchnode.key" "$CertsDir\watchnode.key" -Force
Write-Host "  Files copied." -ForegroundColor Green

# --- Step 4: Generate config.yaml with the actual server IP ---
Write-Host "[4/7] Writing config with ServerIP=$ServerIP..." -ForegroundColor Yellow
$configTemplate = Get-Content "$scriptDir\config.yaml" -Raw
$configTemplate = $configTemplate -replace 'YOUR_SERVER_IP', $ServerIP
$configTemplate = $configTemplate -replace 'sentinel-enroll-secret-2024', $Token
Set-Content -Path $ConfigPath -Value $configTemplate -Encoding UTF8
Write-Host "  Config written: $ConfigPath" -ForegroundColor Green

# --- Step 5: Test TCP connectivity to server ---
Write-Host "[5/7] Testing TCP connectivity to ${ServerIP}:${ServerPort}..." -ForegroundColor Yellow
$tcpTest = Test-NetConnection -ComputerName $ServerIP -Port $ServerPort -WarningAction SilentlyContinue
if (-not $tcpTest.TcpTestSucceeded) {
    Write-Host "[X] Cannot reach ${ServerIP}:${ServerPort}" -ForegroundColor Red
    Write-Host "    Check firewall, network, and that WatchTower is running on the server." -ForegroundColor Red
    Write-Host "    Continuing anyway — agent will retry once you fix connectivity." -ForegroundColor Yellow
} else {
    Write-Host "  TCP reachable." -ForegroundColor Green
}

# --- Step 6: Register the Windows Service using sc.exe (no nssm needed) ---
Write-Host "[6/7] Installing as Windows service..." -ForegroundColor Yellow
$svcCmd = "`"$BinaryPath`" --config `"$ConfigPath`""
sc.exe create $ServiceName binPath= $svcCmd start= auto DisplayName= "Sentinel Core SIEM Agent" | Out-Null
sc.exe description $ServiceName "Sentinel Core SIEM endpoint agent — telemetry collection and threat detection" | Out-Null
# Set service to auto-restart on failure
sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
Write-Host "  Service registered." -ForegroundColor Green

# --- Step 7: Start the service ---
Write-Host "[7/7] Starting service..." -ForegroundColor Yellow
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3
$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq 'Running') {
    Write-Host "`n=== INSTALLATION COMPLETE ===" -ForegroundColor Green
    Write-Host "Service: $ServiceName ($($svc.Status))" -ForegroundColor Green
    Write-Host "`nUseful commands:" -ForegroundColor White
    Write-Host "  Status:    Get-Service $ServiceName" -ForegroundColor Gray
    Write-Host "  Stop:      Stop-Service $ServiceName" -ForegroundColor Gray
    Write-Host "  Start:     Start-Service $ServiceName" -ForegroundColor Gray
    Write-Host "  Logs:      Get-EventLog -LogName Application -Source $ServiceName -Newest 20" -ForegroundColor Gray
    Write-Host "  Live test: cd '$InstallDir'; .\watchnode.exe --config '$ConfigPath'" -ForegroundColor Gray
} else {
    Write-Host "[X] Service installed but failed to start. Status: $($svc.Status)" -ForegroundColor Red
    Write-Host "Run this to see what's wrong:" -ForegroundColor Yellow
    Write-Host "  cd '$InstallDir'; .\watchnode.exe --config '$ConfigPath'" -ForegroundColor White
}
