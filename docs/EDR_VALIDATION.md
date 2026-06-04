# EDR Feature Validation Runbook

How to prove each EDR feature actually works on a **real Windows endpoint** (the
dev container can't exercise active-response, registry, AppLocker, or memory
scanning — so these MUST be validated on a real box before production).

Work through it top to bottom. Each test has **Trigger → Expect → Verify → Cleanup**.
Record pass/fail in the checklist at the bottom.

---

## 0. Prerequisites

**On the manager host (Ubuntu VM running the stack):**
```bash
cd ~/sentinel-siem && git checkout main && git pull
docker compose -f docker-compose.local.yaml up -d --build watchtower watchvault dashboard
# watch the manager while you test:
docker compose -f docker-compose.local.yaml logs -f watchtower
```

**On the Windows test box:**
1. Re-deploy the agent so it has the latest build + config (rebuild the package with
   `scripts/build-agent-package.sh` or drop the new `watchnode.exe` + `config.yaml`).
2. Confirm the agent is running and checked in:
   ```powershell
   Get-ScheduledTask -TaskName SentinelWatchNode
   ```
   Dashboard → **Agents**: the host shows **active** and its **hostname** (not hex).
3. Confirm `active_response.enabled: true` is in `C:\Program Files\SentinelAgent\config.yaml`.

> ⚠️ **Use ONE test box, not production.** Several tests block execution or network.

**Find the manager's view of the agent:**
```bash
curl -s -H "Authorization: Bearer sentinel-dev-api-key" \
  http://localhost:9400/api/v1/agents | python3 -m json.tool | grep -E '"id"|"hostname"'
```

---

## 1. Host isolation (PR #30)

**Make it safe first:** in `config.yaml` set a short auto-release while testing:
```yaml
active_response:
  block_ttl_secs: 120   # auto-release after 2 min
```
Restart the agent task after editing.

- **Trigger:** Dashboard → **Agents** → the host → 🛡 **Isolate host** → confirm.
- **Expect:** all network blocked *except* the manager channel; auto-release after 120s.
- **Verify (on the box):**
  ```powershell
  ping 8.8.8.8                 # should FAIL (timeout) while isolated
  netsh advfirewall show allprofiles | findstr /i "Outbound"   # default = Block
  ```
  **Verify (dashboard):** the host **keeps heartbeating** (still "active") — proves the
  manager channel survived. Active-response history shows `isolate-host` = executed.
- **Verify release:** after ~2 min (or click **Release**), `ping 8.8.8.8` succeeds again.
- **Cleanup:** click **Release** if still isolated; restore `block_ttl_secs` to your prod value.

❌ If the box loses the dashboard heartbeat during isolation, the manager IP wasn't
allow-listed correctly — the TTL will still auto-release it. Report it.

---

## 2. Ransomware canary (PR #31)

- **Trigger:** on the box, modify a decoy file:
  ```powershell
  Add-Content "C:\Users\Public\Documents\0_Passwords.docx" "encrypted"
  ```
- **Expect:** within ~10s, a **critical** alert.
- **Verify (dashboard):** Alerts → **"RANSOMWARE: canary file tampered"** (rule 19570,
  MITRE T1486), agent = your host.
- **Cleanup:** none — the agent re-plants the canary automatically.

---

## 3. Application control / prevention (PR #34)

> Enforcement needs Windows **Enterprise/Education/Server**. On Pro, only Audit works.

- **Trigger (Audit first):** Dashboard → Agents → host → 🔒 **App-control** → **Audit**.
- **Then on the box**, run something from a user-writable folder:
  ```powershell
  Copy-Item C:\Windows\System32\notepad.exe $env:TEMP\test.exe
  & "$env:TEMP\test.exe"
  ```
- **Expect (Audit):** it still runs, but Windows logs a "would-have-blocked" event.
- **Verify:** `Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 5`
  → an 8003 (audit) event for `test.exe`. These also flow to the dashboard.
- **Enforce test:** App-control → **Enforce**, run `test.exe` again → it's **blocked**
  ("This app has been blocked by your system administrator"), event 8004.
- **Cleanup:** App-control → **Clear**. Delete `$env:TEMP\test.exe`.

---

## 4. Registry deception (PR #37)

- **Trigger:** on the box, modify the decoy value:
  ```powershell
  Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SecurityHealthService_" -Value "C:\evil.exe"
  ```
- **Expect:** within ~30s, a **critical** alert.
- **Verify (dashboard):** Alerts → **"Deception: registry autorun token tampered"**
  (rule 19871, MITRE T1547.001).
- **Cleanup:** none — the agent re-plants the decoy.

---

## 5. Forensic collection (PR #38)

- **Trigger:** Dashboard → Agents → host → 📄 **Collect evidence** → **Collect new evidence**.
- **Expect:** ~10–30s later a bundle appears in the modal list.
- **Verify:** click **Refresh list** → a `*.zip` row appears → **Download** → open it; it
  contains `manifest.txt`, `processes.txt`, `network.txt`, `autoruns_*.txt`,
  `scheduled_tasks.csv`, `tasklist.txt`, `netstat.txt`, `prefetch_listing.txt`.
- **Cleanup:** none.

---

## 6. Active response — block IP & kill process (PR #29 + base)

Easiest via a **SOAR playbook** in **dry-run** first:
- Playbooks → New Playbook → trigger Min Level `10`, group `brute_force`; action **Block IP**
  (`ip = {{src_ip}}`); ✅ **Dry run** → Create.
- Generate a brute-force alert (RDP/SSH failures from a test IP **outside** `192.168.100.0/24`).
- **Expect (dry-run):** playbook **⋮ History** shows the action it *would* run, status `dry_run`.
- **Arm it:** edit the playbook, uncheck Dry run. Re-trigger.
- **Verify (on the box):** `netsh advfirewall firewall show rule name=all | findstr WatchNode_Block`
  → a block rule for the attacker IP. Auto-removes after the TTL.

> If the attacker IP is inside `192.168.100.0/24`, the block is **refused by the safelist**
> (by design) — test from an IP outside it.

---

## 7. YARA memory scan (PR #32) — only if you installed the binary

- **Prereq:** `yara64.exe` in `C:\Program Files\SentinelAgent\`, `yara_memory.enabled: true`.
- **Trigger:** run a process whose memory holds the test marker:
  ```powershell
  powershell -NoExit -Command '$x = "SENTINEL_YARA_MEMTEST"; while($true){Start-Sleep 5}'
  ```
- **Expect:** on the next scan cycle (≤10 min, or lower `interval` for the test), a critical alert.
- **Verify (dashboard):** Alerts → **"YARA: malware signature in process memory"** (rule 19860).
- **Cleanup:** close the powershell window.

---

## 8. Process-tree view (PR #36) — read-only

- Dashboard → **Process Tree** → pick the host → **Last 24h**.
- **Expect:** an indented parent→child tree of processes that started on the host;
  binaries like `powershell.exe`/`cmd.exe` highlighted red.
- **Verify:** spawn a chain on the box (`cmd.exe` → `powershell.exe`) and Refresh →
  it appears under its parent. Use the filter box to search by name/cmdline.

---

## Results checklist

| # | Feature | Pass? | Notes |
|---|---|---|---|
| 1 | Host isolation (+ auto-release) | ☐ | |
| 2 | Ransomware canary | ☐ | |
| 3 | App-control Audit | ☐ | |
| 3 | App-control Enforce (Ent/Edu/Srv) | ☐ | |
| 4 | Registry deception | ☐ | |
| 5 | Forensic collection + download | ☐ | |
| 6 | Block IP (dry-run → armed) | ☐ | |
| 7 | YARA memory (if yara installed) | ☐ | |
| 8 | Process-tree view | ☐ | |

If anything fails: grab the WatchTower log (`docker compose logs watchtower`) around the
test time and the agent's command result (dashboard active-response history), and report
the exact symptom — that's enough to pinpoint the seam.
