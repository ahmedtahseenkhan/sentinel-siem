# Install WatchNode Agent on Windows.
# Run as Administrator. Requires NSSM or sc.exe to install as a service.
$ErrorActionPreference = "Stop"
$AgentDir = "C:\Program Files\WatchNode Agent"
$ConfigPath = "$AgentDir\config.yaml"
$BinaryName = "watchnode.exe"

if (-not $env:AGENT_BINARY) {
    $Binary = Join-Path $PSScriptRoot ".." $BinaryName
} else {
    $Binary = $env:AGENT_BINARY
}
if (-not (Test-Path $Binary)) {
    Write-Error "Binary not found: $Binary. Build with: go build -o watchnode.exe ./cmd/agent"
    exit 1
}

New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null
Copy-Item -Force $Binary (Join-Path $AgentDir $BinaryName)
$ExampleConfig = Join-Path $PSScriptRoot ".." "configs" "agent.yaml.example"
if ((Test-Path $ExampleConfig) -and -not (Test-Path $ConfigPath)) {
    Copy-Item $ExampleConfig $ConfigPath
    Write-Host "Created $ConfigPath from example. Edit it before starting."
}
Write-Host "Agent installed to $AgentDir"
Write-Host "To install as a Windows Service, use NSSM or:"
Write-Host "  sc create WatchNodeAgent binPath= `"$AgentDir\$BinaryName --config $ConfigPath`" start= auto"
Write-Host "  sc start WatchNodeAgent"
