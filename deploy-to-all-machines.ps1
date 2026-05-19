# deploy-to-all-machines.ps1
# Bulk deployment script for Sentinel WatchNode to multiple Windows machines
# Requires: Admin access on all target machines, active network connectivity

param(
    [Parameter(Mandatory=$true)]
    [string]$ServerIP,
    
    [Parameter(Mandatory=$false)]
    [array]$ComputerNames = @(),
    
    [Parameter(Mandatory=$false)]
    [string]$CsvFile = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$Test
)

# Color output
function Write-Status { Write-Host "[*] $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "[+] $args" -ForegroundColor Green }
function Write-Error { Write-Host "[-] $args" -ForegroundColor Red }

Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Sentinel WatchNode Bulk Deployment" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""

# Get list of machines
if ($CsvFile -and (Test-Path $CsvFile)) {
    Write-Status "Loading computer names from CSV: $CsvFile"
    $ComputerNames = (Import-Csv $CsvFile).ComputerName
} elseif ($ComputerNames.Count -eq 0) {
    Write-Error "No computers specified. Usage:"
    Write-Host "  .\deploy-to-all-machines.ps1 -ServerIP 192.168.1.100 -ComputerNames comp1,comp2,comp3"
    Write-Host "  OR"
    Write-Host "  .\deploy-to-all-machines.ps1 -ServerIP 192.168.1.100 -CsvFile machines.csv"
    exit 1
}

Write-Status "Target Server IP: $ServerIP"
Write-Status "Target Computers: $($ComputerNames.Count) machines"
Write-Host ""

# Test network connectivity
Write-Status "Testing network connectivity..."
$OnlineMachines = @()
$OfflineMachines = @()

foreach ($Computer in $ComputerNames) {
    if (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
        Write-Success "$Computer - ONLINE"
        $OnlineMachines += $Computer
    } else {
        Write-Error "$Computer - OFFLINE"
        $OfflineMachines += $Computer
    }
}

Write-Host ""
Write-Status "Online: $($OnlineMachines.Count) | Offline: $($OfflineMachines.Count)"

if ($OfflineMachines.Count -gt 0) {
    Write-Host "Offline machines:"
    $OfflineMachines | ForEach-Object { Write-Host "  - $_" }
    Write-Host ""
}

if ($Test) {
    Write-Host "Test mode - exiting here without deploying"
    exit 0
}

Write-Host "Proceeding with deployment to $($OnlineMachines.Count) online machines..."
Write-Host ""

# Deployment script for remote execution
$DeploymentScript = {
    param(
        [string]$ServerIP,
        [string]$WatchnodeExePath,
        [string]$AgentConfigContent
    )
    
    $InstallDir = "C:\Sentinel\WatchNode"
    
    try {
        # Create directory
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        }
        
        # Write executable (base64 encoded from UNC path)
        Copy-Item -Path $WatchnodeExePath -Destination "$InstallDir\watchnode.exe" -Force -ErrorAction Stop
        
        # Write config
        Set-Content -Path "$InstallDir\agent.yaml" -Value $AgentConfigContent -Force
        
        # Set Windows Firewall rule
        netsh advfirewall firewall add rule name="SentinelWatchNode" dir=out action=allow protocol=tcp remoteport=50051 program="$InstallDir\watchnode.exe" 2>$null
        
        # Create Windows Service
        nssm.exe install SentinelWatchNode "$InstallDir\watchnode.exe" "-c $InstallDir\agent.yaml" 2>$null

        # Ensure service starts automatically on Windows boot
        nssm.exe set SentinelWatchNode Start SERVICE_AUTO_START

        # Auto-restart on failure: 5s, 30s, 60s delays, then keep trying
        nssm.exe set SentinelWatchNode AppRestartDelay 5000
        nssm.exe set SentinelWatchNode AppThrottle 60000
        nssm.exe set SentinelWatchNode AppExit Default Restart
        # Also set via sc.exe for redundancy
        sc.exe failure SentinelWatchNode reset= 86400 actions= restart/5000/restart/30000/restart/60000 2>$null

        nssm.exe start SentinelWatchNode 2>$null

        return @{
            Success = $true
            Message = "Installation successful"
        }
    }
    catch {
        return @{
            Success = $false
            Message = $_.Exception.Message
        }
    }
}

# Deploy to each machine
$Results = @()
$SuccessCount = 0
$FailureCount = 0

foreach ($Computer in $OnlineMachines) {
    Write-Host ""
    Write-Status "Deploying to: $Computer"
    
    try {
        # Create agent config for this machine
        $AgentConfig = @"
agent:
  id: ""
  name: "$Computer"
  labels:
    environment: production
    team: security

manager:
  url: "$ServerIP`:50051"
  tls: {}

collectors:
  system:
    enabled: true
    interval: "30s"
    metrics: ["cpu", "memory", "disk", "network", "processes"]
  
  process:
    enabled: true
    interval: "5s"
  
  network:
    enabled: true
    interval: "5s"
  
  logs:
    enabled: true
    sources:
      - type: eventlog
        channel: "Security"
        tags: ["security"]
"@
        
        # Note: This assumes watchnode.exe is accessible on a shared path
        # In production, you would serve it from a web server or share
        $WatchnodeSource = "\\$Computer\C$\temp\watchnode.exe"
        
        # Alternative: use psexec or remoting to push files
        # For simplicity, assuming files are pre-staged or mapped
        
        $Result = Invoke-Command -ComputerName $Computer -ScriptBlock $DeploymentScript -ArgumentList $ServerIP, $WatchnodeSource, $AgentConfig -ErrorAction Stop
        
        if ($Result.Success) {
            Write-Success "$Computer - $($Result.Message)"
            $SuccessCount++
        } else {
            Write-Error "$Computer - $($Result.Message)"
            $FailureCount++
        }
        
        $Results += @{
            Computer = $Computer
            Status = $Result.Success
            Message = $Result.Message
        }
    }
    catch {
        Write-Error "$Computer - $_"
        $FailureCount++
        $Results += @{
            Computer = $Computer
            Status = $false
            Message = $_.Exception.Message
        }
    }
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Deployment Summary" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Success "Successful: $SuccessCount"
Write-Error "Failed: $FailureCount"

if ($FailureCount -gt 0) {
    Write-Host ""
    Write-Host "Failed deployments:"
    $Results | Where-Object { -not $_.Status } | ForEach-Object {
        Write-Host "  $($_.Computer): $($_.Message)"
    }
}

Write-Host ""
Write-Status "Deployment complete. Check dashboard at http://$ServerIP:5050"
