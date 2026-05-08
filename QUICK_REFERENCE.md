# QUICK REFERENCE CARD - PRINT THIS

## SENTINEL SIEM DEPLOYMENT - 2 PAGE QUICK REFERENCE

---

## PAGE 1: TERMINOLOGY (Share with Team)

| Term | Means | Example |
|------|-------|---------|
| **WatchNode (Agent)** | Software running on each Windows machine | Installed on Sales-PC-01 |
| **WatchTower (Manager)** | Central service that receives data from agents | Running on Ubuntu server |
| **WatchVault (Indexer)** | Database that stores and searches events | Stores all alerts |
| **OpenSearch** | Backend storage engine | Like SQL database |
| **Dashboard** | Web portal where you see alerts | Login page: 5050 |
| **Rule** | Alert trigger (detects suspicious behavior) | "Detect new process" |
| **Event** | Single action captured (process started, file changed) | User opened Notepad |
| **Alert** | Event that matched a rule (generated warning) | Rule triggered = Alert |
| **Collector** | Part of agent that gathers data | Process collector, Network collector |

---

## PAGE 2: SERVER SETUP (For Linux Admin)

### Network Requirements
- Ubuntu 20.04+ server
- 4GB RAM minimum
- 30GB disk space minimum
- Network access from all 60 Windows machines to port 50051 (TCP)

### Install Docker
```bash
sudo apt-get update
sudo apt-get install docker.io docker-compose
sudo usermod -aG docker $USER
```

### Expected Ports
- 5050: Dashboard (for viewing alerts)
- 9400: WatchTower API (for agents to connect)
- 9200: OpenSearch (for data storage)
- 50051: gRPC (agents talk to manager on this port)

### Start Services
```bash
cd /path/to/sentinel
docker-compose -f docker-compose.full.yaml up -d
```

### Check Status
```bash
docker ps        # Should show 4 running containers
curl localhost:5050  # Should get HTML response
curl localhost:9400/api/v1/agents  # Should get JSON
```

### Firewall Rules Needed
Allow inbound on port 50051 from all Windows machines

---

## PAGE 3: WINDOWS AGENT SETUP (For Windows Users)

### What Each Computer Gets
- watchnode.exe (~25MB)
- agent.yaml (text config file)
- Installation instructions

### Step 1: Create Folder
```
C:\Sentinel\WatchNode\
```

### Step 2: Copy Files
- Copy watchnode.exe to C:\Sentinel\WatchNode\
- Copy agent.yaml to C:\Sentinel\WatchNode\

### Step 3: Edit agent.yaml
Open in Notepad and change:
```
manager:
  url: "YOUR_SERVER_IP:50051"
```

### Step 4: Test Connection
```cmd
cd C:\Sentinel\WatchNode
watchnode.exe -c agent.yaml
```

Should see:
```
Connected to manager
Starting collectors...
Streaming data...
```

### Step 5: Install as Service
```cmd
nssm install SentinelWatchNode watchnode.exe -c agent.yaml
nssm start SentinelWatchNode
```

Now runs automatically at startup!

---

## PAGE 4: VERIFICATION CHECKLIST

### After Server Starts (In Dashboard: 5050)

- [ ] Dashboard loads
- [ ] Can login (superadmin / superadmin)
- [ ] Agents page shows → empty list (no agents yet, that's OK)

### After First Agent Installed

- [ ] Check dashboard Agents page → should see 1 agent listed
- [ ] Status should be "streaming"
- [ ] Check Discover page → should see events flowing in

### After All 60 Agents Installed

- [ ] Dashboard shows 60 agents
- [ ] All showing "streaming" or "active"
- [ ] Discover shows 30,000+ events/day
- [ ] Alerts appear on Dashboard

---

## PAGE 5: DEPLOYMENT DECISION TREE

```
Deploying to 60 machines?

     ↓
Have Ansible/SCCM/Group Policy?
     ├─ YES → Use automated deploy script
     │ (15 min for all machines)
     │
     └─ NO → Can you create shared folder?
              ├─ YES → Semi-automated
              │ (2-3 hours, users run script)
              │
              └─ NO → Manual install
                     (1-2 hours per 5 machines)
```

---

## PAGE 6: TROUBLESHOOTING

### Problem: "Connection refused" on Windows

**Check:**
1. Ubuntu server IP correct in agent.yaml?
2. Firewall allows 50051? (On server, run: `sudo ufw allow 50051`)
3. Can you ping server? (cmd: `ping SERVER_IP`)

**Fix:**
- Update agent.yaml with correct IP
- Restart agent: `nssm restart SentinelWatchNode`

### Problem: Agent installed but not in dashboard

**Check:**
1. Wait 1-2 minutes (processing time)
2. Check agent running: `tasklist | findstr watchnode`
3. Check logs in Event Viewer

**Fix:**
- Restart agent: `net stop SentinelWatchNode`
- Then: `net start SentinelWatchNode`

### Problem: Dashboard shows "disconnected" agent

**Cause:** Agent lost connection

**Fix:**
1. Check Windows machine can reach server
2. Restart agent
3. Restart server: `docker-compose restart`

### Problem: No events showing in Discover

**Check:**
1. Agents all connected?
2. Wait 2-3 minutes for data pipeline
3. Check OpenSearch: `curl http://server:9200/_cat/indices`

**Fix:**
- Make sure collectors enabled in agent.yaml
- Restart agent and wait

---

## PAGE 7: CONTACT & ESCALATION

### Common Issues → Who to Call

| Problem | Contact | Solution |
|---------|---------|----------|
| Agent won't start | Local IT | Check Windows Event Viewer |
| Server services down | DevOps / Linux Admin | Run: docker-compose up -d |
| Agents disconnected | Network Team | Check firewall port 50051 |
| Dashboard empty | Security Team | Wait 2-3 min, check collectors |
| Server out of disk | DevOps | Cleanup old indices in OpenSearch |

### Critical Contacts

- **Server Admin:** _________________ Phone: _________
- **Network Admin:** ________________ Phone: _________
- **Security Lead:** ________________ Phone: _________
- **Help Desk:** ___________________ Phone: _________

---

## PAGE 8: KEY STATISTICS

### For 60 Machines

**Data generated per day:**
- Process events: ~15,000
- Network events: ~30,000
- Total: ~45,000 events/day

**Storage needed:**
- Per month: ~50-100GB
- Per year: ~600-1200GB

**Performance:**
- Avg alert delay: 5-30 seconds
- Dashboard load time: < 2 seconds
- Query response: < 1 second

**Typical False Positives:**
- Week 1: 20-30% (needs tuning)
- After 4 weeks: < 2% (after rule tuning)

---

## PRINT INSTRUCTION

- Print 2-sided on 4 sheets (or 8 pages if 1-sided)
- Laminate or put in plastic sleeve
- Distribute to:
  - [ ] Linux Admin
  - [ ] Windows Admins
  - [ ] Network Team
  - [ ] Security Operations
  - [ ] IT Manager
  - [ ] Keep one in ticket system


---

## QR CODES (If Printing)

[Server Setup Details] → DEPLOYMENT_GUIDE.md
[Windows Agent Setup] → SIMPLE_CHECKLIST.md
[Team Training] → IMPLEMENTATION_GUIDE.md

