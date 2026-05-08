# DEPLOYMENT CHECKLIST - SIMPLE VERSION
## For Team Members to Follow

---

## STEP 1: SERVER SETUP (Do this ONCE on Ubuntu)

- [ ] Have Ubuntu server ready (20.04 or newer)
- [ ] Install Docker + Docker Compose
- [ ] Copy all files (WatchTower, WatchVault, Dashboard, docker-compose.full.yaml)
- [ ] Edit docker-compose.full.yaml - note server IP address
- [ ] Run: `docker-compose -f docker-compose.full.yaml up -d`
- [ ] Wait 30 seconds
- [ ] Open browser: http://SERVER_IP:5050
- [ ] Login with: superadmin / superadmin
- [ ] **TEST SUCCESSFUL** ✓ Dashboard loads

---

## STEP 2: WINDOWS CLIENT SETUP (Do this on EACH Windows PC)

### Before You Start
- Get from IT: 
  - [ ] watchnode.exe file
  - [ ] agent.yaml file
  - [ ] Server IP address (e.g., 192.168.1.100)

### Installation

1. **Create folder on Windows:**
   ```
   C:\Sentinel\WatchNode\
   ```
   *(Right-click Desktop → New → Folder → Name it)*

2. **Copy files into that folder:**
   - watchnode.exe
   - agent.yaml

3. **Edit agent.yaml file:**
   - Open with Notepad
   - Find this line: `url: "SERVER_IP:50051"`
   - Replace `SERVER_IP` with actual IP (e.g., `url: "192.168.1.100:50051"`)
   - Save file

4. **Test connection (first time):**
   - Open Command Prompt
   - Type:
     ```
     cd C:\Sentinel\WatchNode
     watchnode.exe -c agent.yaml
     ```
   - Should print: `Connected to manager`
   - Should print: `Streaming data...`
   - Press Ctrl+C to stop

5. **Install as Windows Service (permanent):**
   - Download nssm.exe (Google: "nssm download")
   - Put nssm.exe in C:\Sentinel\WatchNode\
   - Open Command Prompt as Administrator
   - Type:
     ```
     cd C:\Sentinel\WatchNode
     nssm install SentinelWatchNode watchnode.exe -c agent.yaml
     nssm start SentinelWatchNode
     ```
   - Now agent runs automatically at startup

---

## STEP 3: VERIFY IN DASHBOARD

1. Go to dashboard: http://SERVER_IP:5050
2. Click "Agents" menu
3. **You should see your Windows computer listed** ✓
4. Status should be: **streaming** or **active**

---

## IF SOMETHING DOESN'T WORK

| Problem | Solution |
|---------|----------|
| "Connection refused" | Check IP address is correct in agent.yaml |
| Agent won't start | Make sure agent.yaml file has correct format (no extra spaces) |
| Agent shows "disconnected" | Restart: Type `nssm restart SentinelWatchNode` |
| Can't see agent in dashboard | Wait 1-2 minutes after starting agent |

---

## KEY FILES TO SHARE

**Give Server Admin:**
- [ ] WatchTower folder
- [ ] WatchVault folder  
- [ ] sentinelCoreDashboard folder
- [ ] docker-compose.full.yaml
- [ ] DEPLOYMENT_GUIDE.md (this guide)

**Give to Each Windows User:**
- [ ] watchnode.exe
- [ ] agent.yaml (with SERVER_IP already filled in!)
- [ ] Simple README with steps above

---

## QUICK NOTES

- **Server IP:** This is the IP address of your Ubuntu machine (ask IT team)
- **First time:** Takes 5-10 minutes to setup
- **After that:** Automatic - no maintenance needed
- **Questions?** Contact IT team or system admin

