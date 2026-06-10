# Sentinel SIEM Deployment Guide
## For 1 Ubuntu Server + 60 Windows Clients

---

## PART 1: SERVER SETUP (Ubuntu Machine)

### What You Need
- 1 Ubuntu 20.04+ server (minimum 4GB RAM, 30GB disk)
- Docker and Docker Compose installed
- Docker networking configured

### Step 1: Prepare Server Files

Copy these folders to Ubuntu server:
```
/WatchTower/       (Manager service)
/WatchVault/       (Indexer service)
/OpenSearch/       (Data storage - handled by Docker)
/corenestDashboard/  (Web dashboard)
docker-compose.full.yaml  (Orchestration file)
```

### Step 2: Configure docker-compose.full.yaml

Edit the file and ensure:

```yaml
version: '3.8'
services:
  opensearch:
    image: opensearchproject/opensearch:2.12.0
    ports:
      - "9200:9200"
    environment:
      - discovery.type=single-node
      - OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m

  opensearch-dashboards:
    image: opensearchproject/opensearch-dashboards:2.12.0
    ports:
      - "5601:5601"
    depends_on:
      - opensearch

  watchtower:
    build: ./WatchTower
    ports:
      - "50051:50051"
      - "9400:9400"
    environment:
      - WATCHTOWER_WATCHVAULT_ADDRESS=watchvault:50052
      - WATCHTOWER_ENGINE_WORKERS=1
    depends_on:
      - opensearch
    volumes:
      - ./WatchTower/data:/var/lib/watchtower

  watchvault:
    build: ./WatchVault
    ports:
      - "50052:50052"
      - "9500:9500"
    depends_on:
      - opensearch
    environment:
      - WATCHVAULT_OPENSEARCH_URL=http://opensearch:9200

  dashboard:
    build: ./corenestDashboard
    ports:
      - "5050:5050"
    depends_on:
      - watchtower
      - watchvault
    environment:
      - FLASK_ENV=production
```

### Step 3: Start Server Services

```bash
cd /path/to/docker/compose
docker-compose -f docker-compose.full.yaml up -d

# Verify all services are running
docker ps
```

**Check endpoints:**
- Dashboard: http://server-ip:5050 (login: superadmin/superadmin)
- WatchTower API: http://server-ip:9400
- OpenSearch: http://server-ip:9200 (admin/admin)
- Dashboards: http://server-ip:5601

---

## PART 2: WINDOWS CLIENT SETUP (60 Machines)

### What Each Windows Machine Needs

1. **WatchNode executable** (compiled binary)
2. **Agent configuration file** (YAML)
3. **Certificates** (if using mTLS - optional for now)
4. **Windows Service installer** (optional - for auto-start)

### Step 1: Build WatchNode for Windows

On your build machine (Linux or Windows with Go):

```bash
# For Windows 64-bit
cd WatchNode/cmd/agent
GOOS=windows GOARCH=amd64 go build -o watchnode.exe

# For Windows 32-bit (if needed)
GOOS=windows GOARCH=386 go build -o watchnode.exe
```

**Output file:** `watchnode.exe` (~15-30 MB)

### Step 2: Create Agent Configuration File

Save as `agent.yaml` on each Windows machine:

```yaml
agent:
  id: ""  # Leave blank - auto-generated
  name: "{{hostname}}"  # Auto-uses Windows computer name
  labels:
    environment: production
    department: sales  # Change per department

manager:
  # Replace SERVER_IP with your Ubuntu server IP
  url: "SERVER_IP:50051"
  tls:
    # For now, leave empty for simple setup
    # cert: ""
    # key: ""
    # ca: ""

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
      - type: eventlog
        channel: "System"
        tags: ["system"]
```

---

## INSTALLATION STEPS FOR EACH WINDOWS MACHINE

### Option A: Manual Installation (Simple)

**On each Windows computer:**

1. Create folder:
   ```
   C:\Sentinel\WatchNode\
   ```

2. Copy these files to the folder:
   - `watchnode.exe`
   - `agent.yaml`

3. Edit `agent.yaml`:
   - Replace `SERVER_IP` with your Ubuntu server IP address
   - Example: `url: "192.168.1.100:50051"`

4. Run agent manually:
   ```
   cd C:\Sentinel\WatchNode
   watchnode.exe -c agent.yaml
   ```

5. Check if it connects:
   - Should print: `Successfully connected to manager`
   - Should print: `Starting collectors...`

### Option B: Automated Installation (Recommended)

**Create a PowerShell installer script:** `install-agent.ps1`

```powershell
# install-agent.ps1
param(
    [string]$ServerIP = "192.168.1.100",
    [string]$AgentName = $env:COMPUTERNAME
)

# Create directory
New-Item -ItemType Directory -Force -Path "C:\Sentinel\WatchNode" | Out-Null

# Download watchnode.exe from server
$DownloadURL = "http://$ServerIP:5000/watchnode.exe"
Invoke-WebRequest -Uri $DownloadURL -OutFile "C:\Sentinel\WatchNode\watchnode.exe"

# Create agent.yaml
$YamlContent = @"
agent:
  id: ""
  name: "$AgentName"
  labels:
    environment: production

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

Set-Content -Path "C:\Sentinel\WatchNode\agent.yaml" -Value $YamlContent

# Create Windows Service
sc.exe create SentinelWatchNode `
  binPath= "C:\Sentinel\WatchNode\watchnode.exe -c C:\Sentinel\WatchNode\agent.yaml" `
  start= auto `
  DisplayName= "Sentinel WatchNode Agent"

# Start service
Start-Service SentinelWatchNode

Write-Host "Installation complete. Service started."
```

**To deploy to 60 machines:**

```powershell
# On a central deployment machine
$Computers = @("comp1", "comp2", ..., "comp60")
$ServerIP = "192.168.1.100"

foreach ($Computer in $Computers) {
    Invoke-Command -ComputerName $Computer -ScriptBlock {
        param($IP)
        & "C:\temp\install-agent.ps1" -ServerIP $IP
    } -ArgumentList $ServerIP
}
```

### Option C: Windows Service Installation (For Production)

Use `nssm` (Non-Sucking Service Manager):

```batch
# Download nssm
# Install service
nssm install SentinelWatchNode "C:\Sentinel\WatchNode\watchnode.exe" "-c C:\Sentinel\WatchNode\agent.yaml"

# Start service
nssm start SentinelWatchNode

# Check service status
nssm status SentinelWatchNode
```

---

## VERIFICATION CHECKLIST

### On Ubuntu Server

✅ Check services running:
```bash
docker ps
```

✅ Check WatchTower agents connected:
```bash
curl http://localhost:9400/api/v1/agents
```

Expected output: Should show agent IDs, hostnames, and status "streaming"

### On Each Windows Client

✅ Agent process running:
```batch
tasklist | findstr watchnode
```

✅ Check connection logs:
```batch
# If running in console
# Should show: "Connected to manager at SERVER_IP:50051"
```

✅ Check Windows Event Log for errors:
- Event Viewer → Windows Logs → Application

### On Dashboard (5050)

✅ Login: superadmin / superadmin

✅ Go to Agents page

✅ Should see all 60 Windows machines listed with status "active" or "streaming"

✅ Check Discover page to see events from all machines

---

## TROUBLESHOOTING

### Agent can't connect to manager

**Problem:** "Connection refused" error

**Solution:**
1. Check server IP is correct in agent.yaml
2. Check firewall allows port 50051:
   ```batch
   netsh advfirewall firewall add rule name="SentinelManager" dir=in action=allow protocol=tcp localport=50051
   ```
3. Ping server from client:
   ```batch
   ping SERVER_IP
   ```

### Agent shows "disconnected" on dashboard

**Problem:** Agent connected then disconnected

**Solution:**
1. Check agent resources (Task Manager):
   - watchnode.exe using <50MB RAM?
   - CPU spikes?
2. Restart agent:
   ```batch
   net stop SentinelWatchNode
   net start SentinelWatchNode
   ```

### No events appearing

**Problem:** Agents connected but no data in dashboard

**Solution:**
1. Check collectors enabled in agent.yaml
2. Wait 2-3 minutes for initial data collection
3. Check OpenSearch has indices:
   ```bash
   curl -u admin:admin http://server-ip:9200/_cat/indices
   ```

---

## FILES CHECKLIST FOR YOUR TEAM

### Server Side (Ubuntu) - Give to server admin
```
✓ docker-compose.full.yaml
✓ WatchTower/ (full folder)
✓ WatchVault/ (full folder)
✓ corenestDashboard/ (full folder)
✓ Certificates (if using mTLS)
```

### Client Side (Windows) - Give to each client
```
✓ watchnode.exe
✓ agent.yaml (customized with server IP)
✓ install-agent.ps1 (deployment script)
✓ nssm.exe (if using Windows Service)
✓ README.txt (simple instructions)
```

---

## QUICK DEPLOYMENT SUMMARY

1. **Server Setup:** 5-10 minutes
   - Copy files
   - Edit docker-compose.yaml with server IP
   - Run: `docker-compose up -d`

2. **Per-Client Setup:** 2-3 minutes/machine
   - Copy watchnode.exe + agent.yaml
   - Edit agent.yaml with server IP
   - Run executable or install as service

3. **Total for 60 machines:** ~5-10 minutes (automated) to 3 hours (manual)

---

## PRODUCTION RECOMMENDATIONS

1. **Use mTLS certificates** for secure communication
2. **Enable log rotation** on server (OpenSearch)
3. **Set resource limits** for containers (CPU/Memory)
4. **Create backup** of OpenSearch data
5. **Monitor server disk space** (rules engine generates many alerts)
6. **Use centralized deployment tool** (Ansible, SCCM) for 60+ machines

---

## SUPPORT & ESCALATION

If any team member has issues:
1. Check troubleshooting section above
2. Verify agent.yaml syntax (YAML is whitespace-sensitive)
3. Check Windows Event Log for errors
4. Run `watchnode.exe` in console to see live logs
5. Check server firewall and network connectivity

