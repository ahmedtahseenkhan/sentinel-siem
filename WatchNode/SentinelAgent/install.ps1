#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sentinel Core SIEM Agent Installer for Windows
.DESCRIPTION
    Installs the Sentinel WatchNode agent as a Windows service.
    Must be run as Administrator.
.EXAMPLE
    .\install.ps1
    .\install.ps1 -ServerIP "192.168.1.100" -Silent
#>

param(
    [string]$ServerIP   = "",
    [string]$ServerPort = "50051",
    [string]$Token      = "sentinel-enroll-secret-2024",
    [switch]$Silent,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$ServiceName  = "SentinelAgent"
$DisplayName  = "Sentinel Core SIEM Agent"
$InstallDir   = "C:\Program Files\SentinelAgent"
$ConfigPath   = "$InstallDir\config.yaml"
$BinaryPath   = "$InstallDir\watchnode.exe"
$LogDir       = "C:\ProgramData\SentinelAgent\logs"
$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Definition

function Write-Banner {
    Write-Host ""
    Write-Host "  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗" -ForegroundColor Cyan
    Write-Host "  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║" -ForegroundColor Cyan
    Write-Host "  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║" -ForegroundColor Cyan
    Write-Host "  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║" -ForegroundColor Cyan
    Write-Host "  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗" -ForegroundColor Cyan
    Write-Host "  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Sentinel Core SIEM — Agent Installer v1.0" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
}

function Write-Step($msg) {
    Write-Host "  [>] $msg" -ForegroundColor Yellow
}

function Write-OK($msg) {
    Write-Host "  [✓] $msg" -ForegroundColor Green
}

function Write-Fail($msg) {
    Write-Host "  [✗] $msg" -ForegroundColor Red
}

# ── UNINSTALL ─────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Banner
    Write-Step "Stopping and removing Sentinel Agent service..."
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 2
        }
        sc.exe delete $ServiceName | Out-Null
        Write-OK "Service removed."
    } else {
        Write-Host "  [i] Service not found — already uninstalled." -ForegroundColor DarkGray
    }
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Write-OK "Files removed from $InstallDir"
    }
    Write-Host ""
    Write-Host "  Sentinel Agent has been uninstalled." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# ── INSTALL ───────────────────────────────────────────────────────────────────
Write-Banner

# Verify running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail "This script must be run as Administrator."
    Write-Host "  Right-click install.ps1 and choose 'Run with PowerShell as Administrator'" -ForegroundColor DarkGray
    exit 1
}

# Get server IP
if (-not $ServerIP) {
    if (-not $Silent) {
        Write-Host "  Enter the Sentinel server IP address or hostname." -ForegroundColor White
        Write-Host "  (This is the IP of the Ubuntu machine running Sentinel)" -ForegroundColor DarkGray
        $ServerIP = Read-Host "  Server IP"
    }
    if (-not $ServerIP) {
        Write-Fail "Server IP is required. Use: .\install.ps1 -ServerIP 1.2.3.4"
        exit 1
    }
}

Write-Host ""
Write-Host "  Installing Sentinel Agent" -ForegroundColor White
Write-Host "  Server  : $ServerIP`:$ServerPort" -ForegroundColor DarkGray
Write-Host "  Install : $InstallDir" -ForegroundColor DarkGray
Write-Host "  Service : $ServiceName" -ForegroundColor DarkGray
Write-Host ""

# Stop existing service if running
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Step "Stopping existing service..."
    if ($existing.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
    Write-OK "Old service removed."
}

# Create directories
Write-Step "Creating installation directory..."
New-Item -ItemType Directory -Force -Path $InstallDir  | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir      | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\configs\sca" | Out-Null
Write-OK "Directories created."

# Copy binary
Write-Step "Copying agent binary..."
$srcBinary = Join-Path $ScriptDir "watchnode.exe"
if (-not (Test-Path $srcBinary)) {
    Write-Fail "watchnode.exe not found in $ScriptDir"
    exit 1
}
Copy-Item -Force $srcBinary $BinaryPath
Write-OK "Binary copied to $BinaryPath"

# Copy SCA configs if present
$srcSca = Join-Path $ScriptDir "configs\sca"
if (Test-Path $srcSca) {
    Copy-Item -Recurse -Force "$srcSca\*" "$InstallDir\configs\sca\"
    Write-OK "SCA policies copied."
}

# Write config.yaml with the provided server IP
Write-Step "Writing configuration..."
$configContent = @"
agent:
  id: ""
  name: "{{hostname}}"
  labels:
    environment: production
    team: security
    _enroll_token: "$Token"

manager:
  url: "${ServerIP}:${ServerPort}"
  tls: {}
  reconnect:
    max_attempts: 0
    initial_backoff: "5s"
    max_backoff: "2m"

collectors:
  system:
    enabled: true
    interval: "30s"
    metrics: ["cpu", "memory", "disk", "network", "processes"]
  process:
    enabled: true
    interval: "30s"
  network:
    enabled: true
    interval: "30s"
  logs:
    enabled: true
    sources:
      - type: eventlog
        channels: ["Security", "Application", "System"]
  fim:
    enabled: true
    interval: "60s"
    paths:
      - path: "C:\\Windows\\System32"
        recursive: false
        realtime: false
      - path: "C:\\Users"
        recursive: false
        realtime: false
  sca:
    enabled: true
    interval: "12h"
    policy_dirs:
      - "configs\sca"
  syscollector:
    enabled: true
    interval: "1h"
    hardware: true
    os: true
    packages: true
    ports: true
    network_interfaces: true
    users: true
    services: true
    hotfixes: true

performance:
  max_cpu_percent: 20
  max_memory_bytes: 268435456
  batch_size: 500
  flush_interval: "30s"
  queue_size: 10000
"@
$configContent | Out-File -Encoding UTF8 -FilePath $ConfigPath
Write-OK "Config written to $ConfigPath"

# Install as Windows service
Write-Step "Installing Windows service..."
$binPathQuoted = "`"$BinaryPath`" --config `"$ConfigPath`""
sc.exe create $ServiceName `
    binPath= $binPathQuoted `
    DisplayName= $DisplayName `
    start= auto | Out-Null

sc.exe description $ServiceName "Sentinel Core SIEM endpoint monitoring agent" | Out-Null

# Set service to restart on failure
sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/10000/restart/30000 | Out-Null

Write-OK "Service '$ServiceName' created."

# Start service
Write-Step "Starting service..."
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3
$status = (Get-Service -Name $ServiceName).Status
if ($status -eq "Running") {
    Write-OK "Service is RUNNING."
} else {
    Write-Host "  [!] Service status: $status — check logs at $LogDir" -ForegroundColor Yellow
}

# Done
Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────────┐" -ForegroundColor Green
Write-Host "  │  Sentinel Agent installed successfully!          │" -ForegroundColor Green
Write-Host "  │                                                   │" -ForegroundColor Green
Write-Host "  │  Service : $ServiceName                    │" -ForegroundColor Green
Write-Host "  │  Status  : $status                                │" -ForegroundColor Green
Write-Host "  │  Config  : $ConfigPath  │" -ForegroundColor Green
Write-Host "  │                                                   │" -ForegroundColor Green
Write-Host "  │  The agent will appear in your Sentinel dashboard │" -ForegroundColor Green
Write-Host "  │  within 30 seconds.                               │" -ForegroundColor Green
Write-Host "  └─────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor DarkGray
Write-Host "    Check status : Get-Service $ServiceName" -ForegroundColor DarkGray
Write-Host "    Stop agent   : Stop-Service $ServiceName" -ForegroundColor DarkGray
Write-Host "    Start agent  : Start-Service $ServiceName" -ForegroundColor DarkGray
Write-Host "    Uninstall    : .\install.ps1 -Uninstall" -ForegroundColor DarkGray
Write-Host ""
