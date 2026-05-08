# WHERE TO START - FILE GUIDE FOR DIFFERENT ROLES

## Quick Navigation by Role

---

## FOR PROJECT MANAGER / DECISION MAKER

**READ THESE FIRST:**

1. **IMPLEMENTATION_GUIDE.md**
   - Understand architecture and timeline
   - See capacity planning and costs
   - Review success criteria

2. **QUICK_REFERENCE.md** (Pages 1-2)
   - Learn terminology to discuss with team
   - Understand server requirements

**THEN DECIDE:**
- Which deployment option (automated vs manual)
- Timeline and budget
- Team size needed

**SHARE WITH TEAM:**
- [ ] QUICK_REFERENCE.md (entire document)
- [ ] SIMPLE_CHECKLIST.md

---

## FOR LINUX / UBUNTU ADMIN (Server Infrastructure)

**START HERE:**

1. **IMPLEMENTATION_GUIDE.md** → Section "Phase 1: Server Deployment"
2. **DEPLOYMENT_GUIDE.md** → Section "Part 1: Server Setup"
3. **QUICK_REFERENCE.md** → Pages 2, 6

**YOUR TASKS:**
- [ ] Setup Ubuntu 20.04+ server
- [ ] Install Docker and Docker Compose
- [ ] Copy WatchTower, WatchVault, Dashboard folders
- [ ] Edit docker-compose.full.yaml (set server IP)
- [ ] Run: `docker-compose -f docker-compose.full.yaml up -d`
- [ ] Verify: `docker ps` (should show 4 running containers)
- [ ] Test: `curl http://localhost:5050` → should get dashboard
- [ ] Configure firewall: Allow inbound port 50051
- [ ] Create backup plan for OpenSearch data

**TOOLS NEEDED:**
- Docker & Docker Compose
- SSH access to server
- Text editor (nano/vim)

**DELIVERABLE TO TEAM:**
```
Server is ready:
- URL: http://[SERVER_IP]:5050
- Login: superadmin / superadmin
- WatchTower API: http://[SERVER_IP]:9400
- gRPC port: 50051 (for agents)
```

---

## FOR WINDOWS SYSTEMS ADMIN (Client Deployment)

**START HERE:**

1. **SIMPLE_CHECKLIST.md** → Section "Step 2: Windows Client Setup"
2. **DEPLOYMENT_GUIDE.md** → Section "Part 2: Windows Client Setup"
3. **QUICK_REFERENCE.md** → Pages 3, 6

**YOUR CHOICES:**

### Option A: Automated Deployment (RECOMMENDED)
1. Get list of 60 computer names
2. Create `machines.csv` file
3. Get `watchnode.exe` and `deploy-to-all-machines.ps1`
4. Run on admin machine:
   ```powershell
   .\deploy-to-all-machines.ps1 -ServerIP 192.168.1.100 -CsvFile machines.csv
   ```
5. Wait 30 minutes
6. Verify all agents in dashboard

**Files needed:**
- deploy-to-all-machines.ps1
- watchnode.exe
- machines.csv

### Option B: Semi-Automated Deployment
1. Copy `watchnode.exe` to shared network folder
2. Create `install-watchnode.bat`
3. Send to Windows admins on each machine
4. Users run locally: `install-watchnode.bat 192.168.1.100`

**Files needed for each user:**
- watchnode.exe
- agent.yaml (pre-configured with server IP)
- install-watchnode.bat

### Option C: Manual Installation
1. For each group of machines:
   - Copy watchnode.exe + agent.yaml
   - Run installer
   - Verify connection

**Files needed:**
- watchnode.exe
- agent.yaml template
- SIMPLE_CHECKLIST.md

**YOUR CHECKLIST:**
- [ ] Verify watchnode.exe builds successfully for Windows
- [ ] Test on 1-2 machines first (QA)
- [ ] Create agent.yaml with correct server IP
- [ ] Deploy to first batch (10 machines)
- [ ] Check dashboard → should see 10 agents
- [ ] Deploy remaining 50 machines
- [ ] Final verification → all 60 agents showing

---

## FOR SECURITY OPERATIONS / SIEM ANALYST

**START HERE:**

1. **IMPLEMENTATION_GUIDE.md** → Section "Operational Tasks"
2. **DEPLOYMENT_GUIDE.md** → Full guide
3. **QUICK_REFERENCE.md** → All pages

**YOUR RESPONSIBILITIES:**

**Day 1-2 (Setup):**
- [ ] Familiarize with dashboard interface
- [ ] Login to dashboard (5050)
- [ ] Review Agents page
- [ ] Check Discover page
- [ ] Understand Rules → Alerts flow

**Day 3+ (Daily Operations):**
- [ ] Monitor dashboard for alerts
- [ ] Investigate high/critical alerts
- [ ] Use Discover to search events
- [ ] Document false positives
- [ ] Report suspicious activity

**Weekly:**
- [ ] Review agent status
- [ ] Check for disconnected agents
- [ ] Analyze alert trends
- [ ] Tune rules (reduce false positives)

**Monthly:**
- [ ] Security assessment
- [ ] Audit agent configurations
- [ ] Plan rule updates
- [ ] Review disk usage

**YOUR DELIVERABLES:**
- Daily alert summary
- Monthly threat report
- Quarterly security assessment

---

## FOR NETWORK ADMIN / FIREWALL

**START HERE:**

1. **QUICK_REFERENCE.md** → Pages 1, 4
2. **DEPLOYMENT_GUIDE.md** → Port requirements

**YOUR TASKS:**
- [ ] Ensure port 50051 (TCP) open from all Windows machines to Server
- [ ] Ensure port 5050 (TCP) open for dashboard access
- [ ] Setup VLAN for SIEM if security-sensitive
- [ ] Configure firewall rules
- [ ] Enable logging on firewall rules
- [ ] Monitor for connection attempts

**FIREWALL RULES NEEDED:**

```
Rule: Allow WatchNode to Manager
- Source: Any Windows machine
- Destination: Server IP
- Port: 50051 (TCP)
- Protocol: TCP
- Direction: Outbound

Rule: Allow Dashboard Access
- Source: Admin workstations
- Destination: Server IP:5050
- Protocol: TCP
```

**TESTING:**
```cmd
# On Windows machine to test connectivity:
telnet SERVER_IP 50051

# Should connect (port open)
```

---

## FOR DEVOPS / AUTOMATION ENGINEER

**START HERE:**

1. **deploy-to-all-machines.ps1** → PowerShell deployment script
2. **IMPLEMENTATION_GUIDE.md** → Deployment phase details
3. **machines.csv** → Template for computer list

**YOUR TASKS:**
- [ ] Setup build pipeline for watchnode.exe
- [ ] Create Ansible/SCCM playbooks (optional)
- [ ] Automate docker-compose deployment
- [ ] Setup backup and recovery procedures
- [ ] Create monitoring for services
- [ ] Setup CI/CD for agent updates

**SAMPLE ANSIBLE PLAYBOOK** (if using):

```yaml
---
- hosts: windows_machines
  tasks:
    - name: Create install directory
      win_file:
        path: C:\Sentinel\WatchNode
        state: directory

    - name: Copy watchnode.exe
      win_copy:
        src: watchnode.exe
        dest: C:\Sentinel\WatchNode\

    - name: Deploy agent.yaml
      template:
        src: agent.yaml.j2
        dest: C:\Sentinel\WatchNode\agent.yaml

    - name: Install Windows Service
      win_service:
        name: SentinelWatchNode
        path: >
          C:\Sentinel\WatchNode\watchnode.exe
          -c C:\Sentinel\WatchNode\agent.yaml
        state: started
        start_mode: auto
```

---

## FOR IT / TECH SUPPORT TEAM

**START HERE:**

1. **SIMPLE_CHECKLIST.md** → Entire document
2. **QUICK_REFERENCE.md** → Pages 3, 6, 7

**YOUR TRAINING:**
- [ ] How to restart agent on Windows machine
- [ ] How to check agent status
- [ ] Common troubleshooting steps
- [ ] When to escalate to DevOps

**COMMON SUPPORT QUESTIONS:**

**Q: Agent not starting**
A: Check agent.yaml for typos, then restart:
```cmd
nssm restart SentinelWatchNode
```

**Q: Can't see my machine in dashboard**
A: Wait 1-2 minutes, then refresh dashboard

**Q: What's my server IP?**
A: Contact server admin. It's the Ubuntu machine IP.

**Q: How do I remove the agent?**
A: `nssm remove SentinelWatchNode`

---

## RECOMMENDED TEAM STRUCTURE

For 60 machines, you'll need:

```
Project Manager (1)
    ├── Linux Admin (1)         - Server setup & maintenance
    ├── Windows Admin (1-2)     - Agent deployment
    ├── Network Admin (1)       - Firewall & connectivity
    ├── Security Analyst (1-2)  - Monitoring & alerts
    ├── DevOps (1)              - Automation & updates
    └── Help Desk (2-3)         - First-line support
```

---

## IMPLEMENTATION CHECKLIST

Use this to track progress:

### Phase 0: Planning (Week 1)
- [ ] Read all documentation
- [ ] Assign roles
- [ ] Schedule deployment
- [ ] Prepare Ubuntu server

### Phase 1: Server Setup (Week 1-2)
- [ ] Install Docker
- [ ] Deploy services
- [ ] Verify dashboard access
- [ ] Test WatchTower API

### Phase 2: Agent Build (Week 2)
- [ ] Build watchnode.exe
- [ ] Create agent.yaml template
- [ ] Test on 1-2 machines

### Phase 3: Pilot Deployment (Week 2-3)
- [ ] Deploy to 10 machines
- [ ] Verify data flow
- [ ] Tune rules
- [ ] Document process

### Phase 4: Full Deployment (Week 3-4)
- [ ] Deploy to remaining 50 machines
- [ ] Verify all agents
- [ ] Final testing
- [ ] Go live

### Phase 5: Operations (Ongoing)
- [ ] Monitor alerts daily
- [ ] Tune rules weekly
- [ ] Maintenance monthly
- [ ] Training & documentation

---

## DOCUMENT DISTRIBUTION

**Print or share these files:**

- [ ] **Project Manager:** IMPLEMENTATION_GUIDE.md + QUICK_REFERENCE.md
- [ ] **Linux Admin:** DEPLOYMENT_GUIDE.md (Part 1) + IMPLEMENTATION_GUIDE.md
- [ ] **Windows Admin:** SIMPLE_CHECKLIST.md + deploy-to-all-machines.ps1 + machines.csv
- [ ] **Network Admin:** QUICK_REFERENCE.md (Pages 1, 4) + firewall rules doc
- [ ] **Security Analyst:** IMPLEMENTATION_GUIDE.md (Operational Tasks) + DEPLOYMENT_GUIDE.md
- [ ] **DevOps:** deploy-to-all-machines.ps1 + IMPLEMENTATION_GUIDE.md (Phase 1-3)
- [ ] **Tech Support:** SIMPLE_CHECKLIST.md + QUICK_REFERENCE.md (Pages 3, 6, 7)

---

## SUCCESS INDICATORS

By end of Week 4, you should have:

✅ 60 Windows machines connected to dashboard
✅ 30,000+ events per day flowing
✅ Dashboard responding in < 2 seconds
✅ All team trained
✅ Runbooks documented
✅ Escalation paths defined

**You're ready for production!**

