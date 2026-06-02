# Sentinel SIEM — Operations Playbook

Practical, copy-pasteable steps for: **(1) validating detections with attack
simulation, (2) rolling out agents to DC01 / Windows2, (3) production
hardening** before a client. Assumes the lab server is the Ubuntu VM at
`192.168.100.215` and the stack is up via `docker-compose.local.yaml`.

---

## 1. Validate detections (attack simulation)

Goal: prove the SIEM *catches* threats, not just collects logs. Run these on a
Windows box that has the agent installed, then confirm the alerts fire. (These
are benign simulations — no real malware.)

> Verify on the VM after each test:
> ```bash
> curl -s -H "Authorization: Bearer sentinel-dev-api-key" \
>   'http://localhost:9200/watchvault-alerts*/_search?size=20&sort=timestamp:desc' \
>   | python3 -m json.tool | grep -E 'rule_id|title|agent_name'
> ```
> or watch live: `docker compose -f docker-compose.local.yaml logs -f watchtower | grep ALERT`

### a) Failed-logon brute force → correlation rules
PowerShell (as a normal user), 6+ bad logons:
```powershell
1..6 | % { runas /user:$env:COMPUTERNAME\ghostuser cmd 2>$null }   # wrong password each time
```
**Expect:** Windows 4625 logon-failure rules, and the **correlation** rule
`18912 — credential stuffing (4624 after many 4625)` once the threshold trips.

### b) Discovery / recon → process + MITRE rules
```powershell
whoami /all
net user
net group "Domain Admins" /domain   # on a domain box
tasklist
```
**Expect:** `5600 New process`, `12011 MITRE T1059.003 cmd.exe`,
`12111 MITRE T1057 Process Discovery`.

### c) Credential-tool name detection
```powershell
Copy-Item C:\Windows\System32\cmd.exe "$env:TEMP\mimikatz.exe"
& "$env:TEMP\mimikatz.exe" /?      # benign — just the name triggers the rule
Remove-Item "$env:TEMP\mimikatz.exe"
```
**Expect:** a Mimikatz/credential-dumping process-name rule (level 13–14).

### d) Persistence → scheduled task
```powershell
schtasks /create /tn "sentinel_test" /tr "calc.exe" /sc onlogon /f
schtasks /delete /tn "sentinel_test" /f
```
**Expect:** `4698`/scheduled-task creation rules.

### Tuning
If something is too noisy (e.g. `5600 New process` fires on everything), add a
**log filter** in the dashboard (Settings → Log Filters) or tighten the rule's
`match`. If something *doesn't* fire, check the event actually reached
OpenSearch (`watchvault-events*` search for the `win_event_id`) — if the event
isn't there, it's a collection/audit-policy gap (see §2), not a rule gap.

---

## 2. Roll out agents to DC01 / Windows2

The installer is the same one you used; repeat per machine.

**Build the package once (VM):**
```bash
cd ~/sentinel-siem && git checkout main && git pull
scripts/build-agent-package.sh
```
Copy `WatchNode/SentinelAgent.zip` to each box (or download from
`http://192.168.100.215:5050/deploy`), then **as Administrator**:
```powershell
Remove-Item -Recurse -Force C:\SentinelAgent -ErrorAction SilentlyContinue
Expand-Archive -Force "$HOME\Downloads\SentinelAgent.zip" -DestinationPath C:\
C:\SentinelAgent\install.bat        # enter 192.168.100.215 when prompted
```

### DC01 needs extra auditing (Domain Controller)
The installer enables endpoint auditing, but **Kerberos and AD-change events
(4768/4769/5136) require subcategories the generic installer doesn't set.** On
DC01, as Administrator:
```powershell
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```
Without these, the SPN/Kerberoasting/AS-REP and AD rule batches have no events to fire on.

**Confirm each agent enrolled (VM):**
```bash
curl -s -H "Authorization: Bearer sentinel-dev-api-key" http://localhost:9400/api/v1/agents \
  | python3 -c "import sys,json;[print(a['hostname'],a.get('ip_address')) for a in json.load(sys.stdin)['data']]"
```
You should see DC01 / Windows / Windows2 by **hostname** (the stable-id + hostname fixes).

> Reachability: each box needs TCP **50051** to the server (`Test-NetConnection 192.168.100.215 -Port 50051`). Open `5050/50051` on the VM (`ufw`) and any pfSense rule between segments.

---

## 3. Production hardening (before any client)

The local stack ships **dev defaults** — change every one of these before a
client sees it. Edit the `environment:` blocks in `docker-compose.local.yaml`
(or your client compose), then `docker compose ... up -d`.

| What | Dev default | Action |
|---|---|---|
| Dashboard admin | `admin / admin` | strong password (`DASHBOARD_ADMIN_PASSWORD`) |
| Dashboard super-admin | `superadmin / superadmin` | strong password (`DASHBOARD_SUPER_ADMIN_PASSWORD`) |
| WatchTower/WatchVault API key | `sentinel-dev-api-key` | unique random (`WATCHTOWER_API_KEY`, `WATCHVAULT_API_KEY` — must match) |
| Agent enroll token | `sentinel-enroll-secret-2024` | unique per client (`WATCHTOWER_GRPC_ENROLL_TOKEN`) **and** update every agent's `config.yaml` / the installer `-Token` |
| Postgres password | `watchtower_dev_pass` | strong (`POSTGRES_PASSWORD` + `WATCHTOWER_DATABASE_URL`) |
| Dashboard `SECRET_KEY` | `sentinel-dev-key` | random 32+ bytes |

Generate values:
```bash
openssl rand -hex 24   # API key / enroll token
openssl rand -hex 32   # SECRET_KEY
```

### Enable mTLS (agent ↔ manager encryption)
1. Generate a CA + server + client certs: `scripts/gen-mtls-certs.sh` (repo root).
2. Mount the server cert into WatchTower and set `WATCHTOWER_GRPC_TLS_CERT/KEY/CA`.
3. Build the agent package in mTLS mode: `scripts/build-agent-package.sh --mode prod` (ships the client certs; installer omits `-NoTLS`).
4. The agent then connects over TLS + enroll token instead of plaintext.

### Firewall (server)
Expose only what's needed: `5050` (dashboard), `50051` (agents), `5140` (syslog if used). Keep `9200` (OpenSearch), `9400` (WatchTower REST), `5432` (Postgres) **internal**.

---

## Pre-deploy checklist (run before handing to a client)
```bash
scripts/build-agent-package.sh --mode prod   # or lab for internal testing
scripts/e2e-smoke.sh                          # full pipeline must pass
```
- [ ] e2e smoke green
- [ ] dev creds rotated (§3 table)
- [ ] mTLS enabled (production)
- [ ] agents enrolled and showing **hostnames** in `/api/v1/agents`
- [ ] a test detection fired (§1) and is visible on the Alerts page
- [ ] DC auditing enabled on domain controllers (§2)
