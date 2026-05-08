# SENTINEL SIEM - IMPLEMENTATION GUIDE
## For IT Teams and System Administrators

---

## WHAT IS SENTINEL SIEM?

A complete Security Information and Event Management system with:
- **Event Collection** - From 60 Windows machines
- **Event Processing** - Rules engine detects threats
- **Event Storage** - Indexed in OpenSearch
- **Alert Dashboard** - Real-time visualization
- **Search & Discovery** - Deep-dive investigation

---

## ARCHITECTURE OVERVIEW

```
Windows Machines (60)           Ubuntu Server (1)
     |                          |
WatchNode Agent ─────────→ WatchTower Manager (50051)
  (collects data)               |
                                ↓
                          WatchVault Indexer (50052)
                                |
                                ↓
                          OpenSearch Database (9200)
                                |
                                ↓
                    Dashboard Browser (5050)
                                |
                          User sees alerts
```

---

## FILES PROVIDED

### Server-Side (Ubuntu Machine)

| File/Folder | Purpose | Size |
|-------------|---------|------|
| `WatchTower/` | Manager service - receives and processes agent data | ~200MB |
| `WatchVault/` | Indexer service - stores events in OpenSearch | ~150MB |
| `sentinelCoreDashboard/` | Web dashboard - visualizes alerts | ~50MB |
| `docker-compose.full.yaml` | Orchestration - starts all services | ~5KB |
| `DEPLOYMENT_GUIDE.md` | Detailed deployment instructions | ~20KB |

### Client-Side (Windows Machines)

| File | Purpose | Size |
|------|---------|------|
| `watchnode.exe` | Agent executable - runs on each Windows machine | ~25MB |
| `agent.yaml` | Configuration file - defines what to collect | ~2KB |
| `install-watchnode.bat` | Simple installer script | ~3KB |

### Deployment Automation

| File | Purpose | For |
|------|---------|-----|
| `deploy-to-all-machines.ps1` | Bulk deployment script | DevOps / Windows Admins |
| `machines.csv` | List of 60 computer names | Input to deployment script |

### Documentation

| File | Purpose |
|------|---------|
| `SIMPLE_CHECKLIST.md` | One-page quick-start for non-technical staff |
| `DEPLOYMENT_GUIDE.md` | Comprehensive guide with troubleshooting |
| `THIS FILE` | Architecture and file descriptions |

---

## DEPLOYMENT TIMELINE

### Week 1: Server Setup
- **Day 1-2:** Prepare Ubuntu server (4GB RAM, 30GB disk minimum)
- **Day 2-3:** Run docker-compose, verify all services online
- **Day 3:** Test dashboard access from Windows machines
- **Day 4:** Create agent.yaml template
- **Day 5:** Build watchnode.exe for Windows

**Time Estimate:** 1-2 days for an experienced Linux admin

### Week 2-3: Client Deployment (60 Machines)

#### Option A: Automated (1-2 hours total)
```powershell
# Run this on a central admin machine
.\deploy-to-all-machines.ps1 -ServerIP 192.168.1.100 -CsvFile machines.csv
```

#### Option B: Semi-Automated (2-3 hours)
- Create shared folder with watchnode.exe
- Send install-watchnode.bat to each team
- Users run locally: `install-watchnode.bat 192.168.1.100`

#### Option C: Manual (8-16 hours)
- Deploy to each machine individually
- Follow SIMPLE_CHECKLIST.md on each machine

**Time Estimate:** 1-2 hours (automated) to 1 day (manual)

---

## STEP-BY-STEP DEPLOYMENT

### PHASE 1: SERVER DEPLOYMENT (On Ubuntu)

1. **Prepare environment:**
   ```bash
   # Install Docker & Docker Compose
   sudo apt-get update
   sudo apt-get install docker.io docker-compose
   sudo usermod -aG docker $USER
   ```

2. **Copy files:**
   ```bash
   scp -r /local/path/* ubuntu@server-ip:/opt/sentinel/
   ```

3. **Start services:**
   ```bash
   cd /opt/sentinel
   docker-compose -f docker-compose.full.yaml up -d
   ```

4. **Verify:**
   ```bash
   # Check services running
   docker ps
   
   # Test endpoints
   curl http://localhost:9400/api/v1/status  # WatchTower
   curl http://localhost:9500/health          # WatchVault
   curl http://localhost:5050                 # Dashboard
   ```

5. **Access dashboard:**
   - Open: http://[SERVER_IP]:5050
   - Login: superadmin / superadmin
   - Should see empty agent list (agents not connected yet)

### PHASE 2: AGENT BUILD

On a machine with Go installed:

```bash
cd WatchNode/cmd/agent
GOOS=windows GOARCH=amd64 go build -o watchnode.exe

# Copy to distribution location
scp watchnode.exe ubuntu@server-ip:/opt/sentinel/watchnode.exe
```

### PHASE 3: CLIENT DEPLOYMENT

**Option A - RECOMMENDED (Bulk deployment with Ansible/SCCM):**

```bash
# Create machines.csv with your 60 computer names
# Run PowerShell script
.\deploy-to-all-machines.ps1 -ServerIP [SERVER_IP] -CsvFile machines.csv
```

**Option B - GROUP POLICY (Windows Domain Environment):**

1. Create Group Policy Object (GPO)
2. Run PowerShell logon script:
   ```powershell
   & "\\server\share\install-watchnode.bat" "192.168.1.100"
   ```

**Option C - MANUAL INSTALLER:**

For each machine:
```cmd
cd temp
install-watchnode.bat 192.168.1.100
```

### PHASE 4: VERIFICATION

**On Dashboard:**
1. Refresh agents page (5050/agents)
2. Should see 60 machines with status "streaming"
3. Check Discover page for incoming events

**In Command Line:**
```bash
# Check agent registration
curl http://server:9400/api/v1/agents

# Should show 60 agents with status "streaming"
```

---

## OPERATIONAL TASKS

### Daily Monitoring

1. **Check dashboard agent status** (5050)
   - Any "disconnected" agents?
   - Any new agents?

2. **Review alerts** on Dashboard
   - High/Critical priority first
   - Investigate suspicious activity

3. **Monitor disk space** on server
   - OpenSearch stores 30 days by default
   - ~50GB for 60 machines with normal activity

### Maintenance

**Weekly:**
- Review agent logs for errors
- Check server disk space
- Create backup of OpenSearch data

**Monthly:**
- Update WatchNode agents (if new version available)
- Review and update rules (add/remove based on threats)
- Tune alert thresholds

**Quarterly:**
- Audit agent configurations
- Review data retention policies
- Security assessment

---

## TROUBLESHOOTING MATRIX

| Issue | Cause | Solution |
|-------|-------|----------|
| "All agents disconnected" | Server firewall blocks 50051 | Allow port 50051 inbound |
| "Dashboard empty" | No events flowing | Check agent logs, verify collectors enabled |
| "Server out of disk" | OpenSearch growing too fast | Increase retention or cleanup old indices |
| "Agents online but no events" | Collectors disabled in agent.yaml | Update agent.yaml and restart agents |
| "Dashboard slow" | Too many agents/events | Increase server RAM or filter older events |

---

## CAPACITY PLANNING

### For 60 Windows Machines

**Storage per month:**
- 100 events/minute = 50GB/month (~1.7GB/day)
- 1000 events/minute = 500GB/month (~17GB/day)

**Server sizing:**
- **CPU:** 2-4 cores recommended
- **RAM:** 8GB minimum, 16GB recommended
- **Disk:** 200GB (6 months of data)

**Network:**
- Upstream: ~1Mbps per 10 agents during active collection
- Upstream: ~100Kbps per agent during idle

---

## SECURITY CONSIDERATIONS

### Before Production Deployment

- [ ] Enable mTLS certificates for agent-manager communication
- [ ] Change default dashboard password (superadmin)
- [ ] Enable authentication on OpenSearch API
- [ ] Setup firewall rules (only allow admin access to 5050)
- [ ] Enable audit logging on all components
- [ ] Setup regular backups of OpenSearch data
- [ ] Network isolation (SIEM on separate VLAN)
- [ ] Monitor WatchTower/WatchVault for failed authentications

### Ongoing Security

1. **Patch regularly:** Keep Docker images updated
2. **Rotate credentials:** Change passwords every 90 days
3. **Audit access:** Review who accessed dashboard/APIs
4. **Monitor disk:** Ensure encryption at rest is enabled
5. **Test recovery:** Verify backups work quarterly

---

## SUCCESS CRITERIA

Your deployment is **successful** when:

✅ All 60 Windows agents show "streaming" status on dashboard
✅ Dashboard receiving events from all machines
✅ Average alert latency < 30 seconds
✅ Discover page shows events with searchable fields
✅ Dashboard loads and responds in < 2 seconds
✅ No errors in agent or server logs

## ESTIMATED COSTS

### Infrastructure (One-time)
- Ubuntu server (VM or physical): $1K-3K
- Network infrastructure (VLAN, firewall rules): $0-1K
- Storage for 6 months data: $500-2K

### Operational (Monthly)
- Linux admin time: 8hrs/month (~$200)
- Security analyst time: 40hrs/month (~$2000)
- Tools/licenses: $0 (open source)

### Total: ~$2-5K one-time + $2200/month

---

## SUPPORT ESCALATION

**Level 1 - End User Support:**
- Agent not starting → Check agent.yaml syntax
- Can't see my machine on dashboard → Wait 2-3 minutes
- Dashboard not loading → Refresh browser

**Level 2 - IT Admin Support:**
- Networks issues → Check firewall rules
- Agent crashing → Check event logs, increase logging
- High server load → Check number of events, optimize rules

**Level 3 - DevOps/Engineering:**
- Scale issues → Increase server resources
- Data corruption → Restore from backup
- Performance tuning → Adjust index settings

---

## QUICK REFERENCE

| Task | Command | Notes |
|------|---------|-------|
| Check server status | `docker ps` | All containers should be `Up` |
| View WatchTower logs | `docker logs watchtower` | See what manager is processing |
| Stop agent on Windows | `nssm stop SentinelWatchNode` | Service stops gracefully |
| Restart all services | `docker-compose restart` | Wait 30 seconds for recovery |
| Backup data | `docker exec opensearch ...` | Use opensearch backup tools |
| Check agent status | `curl http://ip:9400/api/v1/agents` | Shows all connected agents |

---

## NEXT STEPS

1. **Start with documentation:** Read SIMPLE_CHECKLIST.md
2. **Build your team:** Assign roles (Server Admin, Network Admin, Security Analyst)
3. **Stage in dev first:** Test with 5-10 machines before production
4. **Run through phase 1:** Get server running
5. **Build agents:** Compile watchnode.exe for Windows
6. **Stage phase 2:** Deploy to first batch of machines
7. **Verify functionality:** Test Discover, alerts, dashboards
8. **Final deployment:** Roll out to remaining 50+ machines
9. **Go live:** Start monitoring, tune rules
10. **Handoff:** Train operations team

**Estimated total timeline:** 2-4 weeks from start to full 60-machine production deployment

