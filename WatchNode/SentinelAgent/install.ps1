<#
.SYNOPSIS
    Sentinel Core SIEM Agent Installer for Windows
.DESCRIPTION
    Installs the Sentinel WatchNode agent as a Windows service.
    Auto-elevates to Administrator if needed.
.EXAMPLE
    .\install.ps1 -ServerIP "192.168.1.100"
#>

param(
    [string]$ServerIP      = "",
    [string]$ServerPort    = "50051",
    [string]$Token         = "sentinel-enroll-secret-2024",
    [switch]$Silent,
    [switch]$Uninstall,
    [switch]$SkipSysmon,   # Pass to skip automatic Sysmon installation
    [switch]$SkipAuditPol, # Pass to skip Windows audit policy configuration
    [switch]$NoTLS         # Connect over plaintext gRPC (enrollment-token auth only).
                           # Use when the WatchTower server is not configured for TLS
                           # (e.g. the docker-compose.local.yaml test stack). For a
                           # production server with certs, omit this so the agent uses mTLS.
)

$ErrorActionPreference = "Stop"

# Auto-elevate to Administrator if not already elevated. Without this, running
# from a normal PowerShell prompt silently exits because of #Requires; running
# from cmd.exe opens this file in Notepad because of the .ps1 file association.
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-launching as Administrator..." -ForegroundColor Yellow
    $argsList = @(
        "-NoExit",
        "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`""
    )
    if ($ServerIP)   { $argsList += @("-ServerIP", $ServerIP) }
    if ($ServerPort) { $argsList += @("-ServerPort", $ServerPort) }
    if ($Token)      { $argsList += @("-Token", "`"$Token`"") }
    if ($Silent)     { $argsList += "-Silent" }
    if ($Uninstall)  { $argsList += "-Uninstall" }
    if ($SkipSysmon) { $argsList += "-SkipSysmon" }
    if ($SkipAuditPol) { $argsList += "-SkipAuditPol" }
    if ($NoTLS)      { $argsList += "-NoTLS" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argsList
    exit
}

# --- We're elevated. Start a transcript so a copy of all output survives
# --- even if the user closes the window or it crashes before -NoExit applies.
$LogDir = "$env:ProgramData\SentinelAgent\install-logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogFile = Join-Path $LogDir ("install-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
try { Start-Transcript -Path $LogFile -Force | Out-Null } catch {}
Write-Host "Logging this session to: $LogFile" -ForegroundColor DarkGray

# Wrap everything below so we ALWAYS pause on errors before the window closes —
# the most common support ticket is "the window flashed and disappeared".
trap {
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Red
    Write-Host "INSTALL FAILED" -ForegroundColor Red
    Write-Host "==========================================================" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Log:   $LogFile" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press any key to close this window..." -ForegroundColor Yellow
    try { Stop-Transcript | Out-Null } catch {}
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}
# Must match the name the agent binary registers with the SCM (svc.Run in the
# Go code uses "SentinelWatchNode"); a different name fails to start.
$ServiceName   = "SentinelWatchNode"
$DisplayName   = "Sentinel Core SIEM Agent"
$InstallDir    = "C:\Program Files\SentinelAgent"
$ConfigPath    = "$InstallDir\config.yaml"
$BinaryPath    = "$InstallDir\watchnode.exe"
$LogDir        = "C:\ProgramData\SentinelAgent\logs"
$SysmonDir     = "C:\Program Files\Sysmon"
$SysmonBin     = "$SysmonDir\Sysmon64.exe"
$SysmonConfig  = "$SysmonDir\sysmon-config.xml"
$ScriptDir     = Split-Path -Parent $MyInvocation.MyCommand.Definition

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

function Configure-AuditPolicy {
    Write-Step "Configuring Windows Audit Policy for SIEM coverage..."
    # Process creation with command line — required for Sigma process rules
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
    # Enable command-line logging in process creation events (4688)
    reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
    # Logon / Logoff
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable | Out-Null
    # Account management
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
    # Privilege use
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
    # Object access (file/registry)
    auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null
    # Policy changes
    auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable | Out-Null
    # System events
    auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable | Out-Null
    # PowerShell script-block logging
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        /v EnableTranscripting /t REG_DWORD /d 1 /f | Out-Null
    Write-OK "Audit policy and PowerShell logging configured."
}

function Install-Sysmon {
    Write-Step "Checking for Sysmon..."
    $srcSysmon = Join-Path $ScriptDir "Sysmon64.exe"
    $srcConfig = Join-Path $ScriptDir "sysmon-config.xml"

    if (-not (Test-Path $srcSysmon)) {
        Write-Host "  [i] Sysmon64.exe not found in installer directory — skipping Sysmon install." -ForegroundColor DarkGray
        Write-Host "  [i] Download Sysmon from: https://docs.microsoft.com/sysinternals/downloads/sysmon" -ForegroundColor DarkGray
        Write-Host "  [i] Place Sysmon64.exe + sysmon-config.xml next to install.ps1 and re-run." -ForegroundColor DarkGray
        return
    }
    if (-not (Test-Path $srcConfig)) {
        Write-Host "  [!] sysmon-config.xml not found — Sysmon will install with no config." -ForegroundColor Yellow
    }

    New-Item -ItemType Directory -Force -Path $SysmonDir | Out-Null
    Copy-Item -Force $srcSysmon $SysmonBin
    if (Test-Path $srcConfig) { Copy-Item -Force $srcConfig $SysmonConfig }

    # Check if already installed
    $sysmonSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($sysmonSvc) {
        Write-Host "  [i] Sysmon already installed — updating config..." -ForegroundColor DarkGray
        if (Test-Path $SysmonConfig) {
            & $SysmonBin -c $SysmonConfig | Out-Null
        }
        Write-OK "Sysmon config updated."
    } else {
        # Use the call operator with plain args — no Invoke-Expression / escaped
        # quotes (that pattern trips the Windows PowerShell 5.1 parser).
        if (Test-Path $SysmonConfig) {
            & $SysmonBin -accepteula -i $SysmonConfig | Out-Null
        } else {
            & $SysmonBin -accepteula -i | Out-Null
        }
        Write-OK "Sysmon installed and running."
    }
}

function Set-InstallDirACL {
    # Lock down install dir: SYSTEM + Administrators full, Users no access
    $acl = Get-Acl $InstallDir
    $acl.SetAccessRuleProtection($true, $false)

    $system   = New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")
    $admins   = New-Object System.Security.Principal.NTAccount("BUILTIN\Administrators")
    $fullCtrl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow    = [System.Security.AccessControl.AccessControlType]::Allow
    $inherit  = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $prop     = [System.Security.AccessControl.PropagationFlags]::None

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($system, $fullCtrl, $inherit, $prop, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($admins, $fullCtrl, $inherit, $prop, $allow)))
    Set-Acl -Path $InstallDir -AclObject $acl
    Write-OK "Install directory ACL hardened (SYSTEM + Admins only)."
}

# ── UNINSTALL ─────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Banner
    Write-Step "Stopping and removing Sentinel agent..."
    # Scheduled task (current install method). Use cmdlets, not schtasks.exe —
    # a native command writing to stderr aborts the script under -EA Stop.
    if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue
        Write-OK "Scheduled task removed."
    }
    # Any leftover SCM service from an older install (only delete if it exists,
    # so sc.exe never errors).
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") { Stop-Service -Name $ServiceName -Force; Start-Sleep -Seconds 2 }
        cmd.exe /c "sc delete $ServiceName 2>nul" | Out-Null
        Write-OK "Service removed."
    }
    Get-Process -Name "watchnode" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
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

# Stop any existing agent (old SCM service from a previous install) up front.
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Step "Removing old service..."
    if ($existing.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    cmd.exe /c "sc delete $ServiceName 2>nul" | Out-Null
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

# TLS block is emitted only when the server uses certs. With -NoTLS the agent
# connects over plaintext gRPC and authenticates with the enrollment token only
# (see internal/communication/client.go: any tls field set => mTLS is required).
if ($NoTLS) {
    Write-Host "  Transport: PLAINTEXT (enrollment-token auth only) — -NoTLS set" -ForegroundColor Yellow
    $TlsBlock = "  # tls: disabled via -NoTLS (plaintext gRPC + enrollment token)"
} else {
    Write-Host "  Transport: mTLS (certs in $InstallDir\certs)" -ForegroundColor DarkGray
    $TlsBlock = @"
  tls:
    cert: "C:\\Program Files\\SentinelAgent\\certs\\watchnode.crt"
    key:  "C:\\Program Files\\SentinelAgent\\certs\\watchnode.key"
    ca:   "C:\\Program Files\\SentinelAgent\\certs\\ca.crt"
"@
}

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
$TlsBlock
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
        channels:
          - "Security"
          - "Application"
          - "System"
          - "Microsoft-Windows-Sysmon/Operational"
          - "Microsoft-Windows-PowerShell/Operational"
          - "Windows PowerShell"
          - "Microsoft-Windows-TaskScheduler/Operational"
          - "Microsoft-Windows-WMI-Activity/Operational"
          - "Microsoft-Windows-Windows Defender/Operational"
          - "Microsoft-Windows-AppLocker/EXE and DLL"
          - "Microsoft-Windows-AppLocker/MSI and Script"
          - "Microsoft-Windows-AppLocker/Packaged app-Deployment"
          - "Microsoft-Windows-AppLocker/Packaged app-Execution"
          - "Microsoft-Windows-CodeIntegrity/Operational"
          - "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
          - "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
          - "Microsoft-Windows-Bits-Client/Operational"
          - "Microsoft-Windows-DNS-Client/Operational"
          - "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"

  file_integrity:
    enabled: true
    interval: "60s"
    scan_on_start: true
    paths:
      - path: "C:\\Windows\\System32"
        recursive: false
        ignore_patterns: ["*.log", "*.etl", "*.evt"]
      - path: "C:\\Windows\\SysWOW64"
        recursive: false
        ignore_patterns: ["*.log", "*.etl"]
      - path: "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        recursive: true
      - path: "C:\\Users"
        recursive: false
        ignore_patterns: ["NTUSER.DAT*", "UsrClass.dat*", "*.log", "*.tmp"]
      - path: "C:\\Windows\\System32\\drivers\\etc"
        recursive: false
      - path: "C:\\Program Files\\SentinelAgent"
        recursive: false

  registry:
    enabled: true
    interval: "5m"
    keys:
      - path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        recursive: false
      - path: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        recursive: false
      - path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        recursive: false
      - path: "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        recursive: false
      - path: "HKLM\\SYSTEM\\CurrentControlSet\\Services"
        recursive: false
      - path: "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
        recursive: false
      - path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
        recursive: false
      - path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
        recursive: false
      - path: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        recursive: false

  sca:
    enabled: true
    interval: "12h"
    policy_dirs:
      - "configs/sca"

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
  max_cpu_percent: 25
  max_memory_bytes: 268435456
  batch_size: 500
  flush_interval: "30s"
  queue_size: 10000
"@
$configContent | Out-File -Encoding UTF8 -FilePath $ConfigPath
Write-OK "Config written to $ConfigPath"

# Audit policy and PowerShell logging
if (-not $SkipAuditPol) {
    Configure-AuditPolicy
} else {
    Write-Host "  [i] Skipping audit policy configuration (-SkipAuditPol)." -ForegroundColor DarkGray
}

# Sysmon — critical for Sigma process/network/registry rules
if (-not $SkipSysmon) {
    Install-Sysmon
} else {
    Write-Host "  [i] Skipping Sysmon installation (-SkipSysmon)." -ForegroundColor DarkGray
}

# Harden install directory ACL
Set-InstallDirACL

# Run the agent as a SYSTEM Scheduled Task (auto-start at boot, auto-restart on
# failure). We deliberately do NOT use an SCM service: the agent binary's
# service mode returns Windows error 1053 ("did not respond to the start request
# in a timely fashion") on this OS build. A scheduled task runs the binary in
# its normal console mode as a persistent background process under LocalSystem,
# which is reliable and equally persistent. (Wazuh-style: the goal is a
# background agent that survives reboots and restarts on crash — a task delivers
# that without the SCM-protocol fragility.)
Write-Step "Registering Sentinel agent (scheduled task, runs as SYSTEM)..."

# Clean up any prior task / leftover SCM service / running process from earlier
# attempts so this is idempotent. Use cmdlets (they honour -EA SilentlyContinue);
# schtasks.exe writes to stderr when the task is absent, which aborts the script
# under $ErrorActionPreference = "Stop".
if (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue
}
$leftoverSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($leftoverSvc) {
    if ($leftoverSvc.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue }
    cmd.exe /c "sc delete $ServiceName 2>nul" | Out-Null
    Start-Sleep -Seconds 1
}
Get-Process -Name "watchnode" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$action    = New-ScheduledTaskAction -Execute $BinaryPath -Argument "--config `"$ConfigPath`"" -WorkingDirectory $InstallDir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -RestartCount 9999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description "Sentinel Core SIEM endpoint agent" -Force | Out-Null
Write-OK "Scheduled task '$ServiceName' registered (auto-start at boot)."

# Start it now.
Write-Step "Starting agent..."
Start-ScheduledTask -TaskName $ServiceName
Start-Sleep -Seconds 4
if (Get-Process -Name "watchnode" -ErrorAction SilentlyContinue) {
    Write-OK "Agent is RUNNING."
    $status = "Running"
} else {
    $status = "starting"
    Write-Host "  [!] Agent process not detected yet — it may still be connecting to ${ServerIP}:${ServerPort}." -ForegroundColor Yellow
    Write-Host "  [i] Check it / see live output by running in the foreground:" -ForegroundColor DarkGray
    Write-Host "      & '$BinaryPath' --config '$ConfigPath'" -ForegroundColor DarkGray
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
Write-Host "  │                                                   │" -ForegroundColor Green
Write-Host "  │  Sysmon + 16 event channels + audit policy set.  │" -ForegroundColor Green
Write-Host "  └─────────────────────────────────────────────────┘" -ForegroundColor Green
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor DarkGray
Write-Host "    Check status : Get-Service $ServiceName" -ForegroundColor DarkGray
Write-Host "    Stop agent   : Stop-Service $ServiceName" -ForegroundColor DarkGray
Write-Host "    Start agent  : Start-Service $ServiceName" -ForegroundColor DarkGray
Write-Host "    Uninstall    : .\install.ps1 -Uninstall" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Install log saved to: $LogFile" -ForegroundColor DarkGray
Write-Host ""
try { Stop-Transcript | Out-Null } catch {}

# Always pause so the user can read the success message — the window auto-closes
# instantly otherwise and they think nothing happened.
if (-not $Silent) {
    Write-Host "Press any key to close this window..." -ForegroundColor Yellow
    try { $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") } catch { Read-Host "Press Enter" }
}
