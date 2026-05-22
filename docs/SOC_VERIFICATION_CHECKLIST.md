# Sentinel SIEM — SOC Analyst Verification Checklist

**Audience:** SOC analyst / security lead doing the post-deployment review.
**Goal:** confirm every gap from the original review is closed AND each new
feature behaves correctly against real fleet data.

If anything on this list fails, file it under "fix" before any further
feature work.

---

## 0 · Pre-flight (Linux admin runs once)

```bash
# 1. Pull latest, rebuild dashboard image to pick up bcrypt
cd /opt/sentinel        # or wherever the project lives
git pull
docker compose -f docker-compose.full.yaml build dashboard

# 2. Environment knobs (add to .env or compose env)
#    All optional — defaults are sane.
SESSION_TIMEOUT_HOURS=12          # idle session timeout
MIN_PASSWORD_LEN=10               # dashboard account password minimum
CSRF_STRICT=false                 # set true once you confirm no internal
                                  # automation calls write endpoints
WATCHVAULT_RETENTION_DAYS=90      # shown on Retention page as the
                                  # configured value
# Optional file-mode for System Logs page when docker socket isn't mounted:
# SYSTEM_LOG_SOURCES=watchtower:/var/log/wt.log,watchvault:/var/log/wv.log

# 3. Restart and reload
docker compose -f docker-compose.full.yaml up -d
```

**Hard-refresh the browser (Ctrl+Shift+R)** after the dashboard restarts so
new HTML/JS loads.

---

## 1 · Liveness sanity (30 seconds)

| # | Check | Expected |
|---|---|---|
| 1.1 | `curl -sf http://localhost:5050/healthz` | `{"status":"ok"}` exit 0 |
| 1.2 | `curl -sf http://localhost:5050/readyz \| python3 -m json.tool` | all checks "ok" |
| 1.3 | Open `/login` in browser | renders, no 5xx |
| 1.4 | Log in as super_admin | sidebar shows new entries: Logs · Correlations · Silent Sources · Log Filters · System Logs · Users & Roles · Retention · Config Audit |

If 1.2 returns 503, one of the SQLite DBs failed to open — check the
dashboard container logs for the failing module name.

---

## 2 · Core data flow (verifies dashboards aren't lying)

Run this on the Ubuntu host **before** clicking around — confirms data is
actually in OpenSearch so any empty page is a query bug, not missing data.

```bash
# Any Windows eventlog docs in the last hour?
curl -s "http://localhost:9200/watchvault-events-*/_search?size=2" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"term":{"type":"log.eventlog"}},{"range":{"timestamp":{"gte":"now-1h"}}}]}},"sort":[{"timestamp":"desc"}]}' \
  | python3 -m json.tool | head -50
```

Expected: at least one hit per active Windows agent. **If empty, fix the
agent → manager → indexer pipeline before validating the dashboard.**

---

## 3 · Feature verification (one analyst, ~20 minutes)

For each feature: complete the action, confirm the expected result, tick the
box. Use a **disposable test user** for state-changing actions so audit
entries are unambiguous.

### 3.1 Logs explorer
- [ ] Sidebar → **Logs** → time range **Last 1h** → table populates with
      mixed sources (eventlog, process, fim).
- [ ] Click **Logon (4624)** chip → only logon events remain.
- [ ] Pick **Last 7d** → same data, larger count, no errors.
- [ ] Pick **Custom…** → set From = 3 days ago, To = today → click **Search**
      → results constrained to that window.
- [ ] Click **View** on any row → side drawer opens with full JSON.

### 3.2 Audit Trail (existing page, formerly Linux-only)
- [ ] Sidebar → **Audit Trail** → see Windows logon events from your test box
      (4624 / 4634 / 1074 / 6005). Pre-fix this page only showed Linux SSH
      events.

### 3.3 Config Audit Log (P0)
- [ ] Open any Sigma rule under **Rules** → save without changes.
- [ ] Sidebar → **Config Audit** → most recent row shows your user, role,
      target `rule:<filename>`, action `edit`, status 200.
- [ ] Toggle **Only failures** → row disappears.
- [ ] Filter by your username → only your actions remain.
- [ ] Click **View** → drawer shows scrubbed payload (no `password` fields
      should ever appear; values are `***`).

### 3.4 Log Filters / Whitelist (P0)
- [ ] **Log Filters** → **+ New filter** → name "Hide my logons", field
      `TargetUserName`, op `contains`, value your test username, scope
      `events`. Save.
- [ ] Back to **Logs** page → click **Logon (4624)** → your test username no
      longer appears.
- [ ] Return to **Log Filters** → toggle the filter **OFF** → re-run Logs
      query → your logons reappear.
- [ ] Delete the filter.
- [ ] **Config Audit** → confirm create / toggle / delete were all recorded.

### 3.5 Backup & Restore (P0)
- [ ] Sidebar → **Stack Status** → **⤓ Backup now** → downloads
      `sentinel-<host>-<ts>.tar.gz`. Open it locally:
      - [ ] `MANIFEST.txt` present with timestamp.
      - [ ] `WatchTower/rules/`, `WatchTower/decoders/` present.
      - [ ] `sentinelCoreDashboard/audit_log.db`, `log_filters.db`,
            `users.db`, `silent_sources.db`, `correlations.db`,
            `custom_dashboards.db` present.
- [ ] On the host: `scripts/sentinel-restore.sh <archive> --dry-run` →
      lists contents, modifies nothing.
- [ ] Backup list at the bottom of the card shows the new archive.

### 3.6 Silent-source monitor (P1)
- [ ] Sidebar → **Silent Sources** → **+ New threshold** → pattern `*`, kind
      `agent`, minutes `5`, severity `high`. Save.
- [ ] Stop one Windows agent service: `Stop-Service WatchNodeAgent`.
- [ ] Wait 6 minutes, then sidebar → **Silent Sources** → click **▶ Run
      check now** → incident opens for that host.
- [ ] Restart the agent → click **Run check now** again → incident moves to
      **Resolved**.
- [ ] If you configured `SMTP_HOST` / Slack webhook in `notifier.py`, you
      should see one alert per opened incident.

### 3.7 Pipeline Health (P1)
- [ ] Sidebar → **Stack Status** → **PIPELINE HEALTH** card.
- [ ] Status badge should be **HEALTHY** (green dot).
- [ ] DLQ depth = 0 under normal load.
- [ ] Dropped events / alerts = 0 (any non-zero is a real incident — see
      §5).
- [ ] Agents count matches `/api/v1/agents` from WatchTower.

### 3.8 User management (P1)
- [ ] Sidebar → **Users & Roles** → **+ New user** → username `analyst1`,
      role `security_analyst`, password ≥ 10 chars. Save.
- [ ] Try password `short` → blocked (server enforces too).
- [ ] Try username `bad name!` → blocked.
- [ ] Log out, log back in as `analyst1`.
  - [ ] Sidebar **should NOT** show: Users & Roles, Config Audit, Log
        Filters, Silent Sources, System Logs, Retention.
  - [ ] **Rules** page → cannot save (403).
  - [ ] **Alerts** page → can read.
- [ ] Log back in as super_admin → disable `analyst1` → attempt login → fails.
- [ ] Try to **delete yourself** → blocked (400 "cannot delete own account").
- [ ] Try to demote the last super_admin → blocked.

### 3.9 Correlations / impossible travel (P1)
- [ ] From two different machines, RDP/log on as the **same** AD user
      within 2 minutes.
- [ ] Sidebar → **Correlations** → click **▶ Run all now** → incident
      appears with detector `multi_location_logon`, severity medium/high,
      distinct IPs ≥ 2.
- [ ] Click **View** → evidence shows both IPs and (where present)
      workstation names.
- [ ] Click **Resolve** → moves to Resolved tab.
- [ ] Repeat the action → new incident opens (resolved ones don't suppress
      future ones — by design).

### 3.10 System Logs viewer (P1)
- [ ] Sidebar → **System Logs** → click each tab (watchtower / watchvault /
      opensearch / dashboard).
- [ ] Output area shows recent stdout with timestamps.
- [ ] Substring filter narrows results.
- [ ] If output is empty AND hint mentions "docker CLI not available":
      either mount `/var/run/docker.sock` into the dashboard container, or
      set `SYSTEM_LOG_SOURCES` env var (see §0).

### 3.11 Retention (P2)
- [ ] Sidebar → **Retention**.
  - [ ] 4 KPIs populate: indices count, storage, docs, configured days.
  - [ ] Per-family table lists at least `events`, `alerts`.
  - [ ] Indices list paginates / filters by name.
- [ ] **Force-purge** card → days `9999` → **Preview (dry run)** → 0 matches
      (nothing is that old). Verify no indices were touched.
- [ ] Days `1` → **Preview** → shows indices > 1 day old. Verify dashboards
      still work afterwards (they should — preview is read-only).
- [ ] **Do not run ⚠ Delete now in production unless you intend to delete.**

### 3.12 Discover custom range (P2)
- [ ] Sidebar → **Discover** → time range **Custom range…** → pick a 6-hour
      window from yesterday → **Apply** → results constrained.

### 3.13 Default mTLS + cert paths still healthy
- [ ] `docker compose logs watchtower --tail 50 | grep -i tls` → no
      handshake errors.
- [ ] Agents page → all expected hosts marked **active** (last_seen < 5m).

---

## 4 · Security baseline (~10 minutes)

| # | Check | How to verify |
|---|---|---|
| 4.1 | Session cookie has HTTPOnly, SameSite=Lax | Browser dev tools → Application → Cookies → `sentinel_session` |
| 4.2 | Secure flag set when behind HTTPS | Same place, only when `FLASK_HTTPS=true` |
| 4.3 | Session idle timeout | Log in, leave for `SESSION_TIMEOUT_HOURS`, return → forced re-login |
| 4.4 | Login lockout | Try 6 wrong passwords → page says "Too many failed attempts" |
| 4.5 | CSRF origin guard | `curl -X POST -H 'Origin: https://evil.example' --cookie '<copy your session>' http://localhost:5050/api/admin/filters` → 403 |
| 4.6 | Bcrypt hashes stored, not plaintext | `sqlite3 sentinelCoreDashboard/users.db 'select password_hash from dashboard_users limit 1'` → starts with `$2b$` |
| 4.7 | Audit log redacts secrets | Create a user with password `topsecret123` → audit row's `payload` shows `"password": "***"` |
| 4.8 | super_admin paths refuse non-super_admin | As `analyst1`, `curl --cookie ... http://localhost:5050/api/admin/audit-log` → 403 |
| 4.9 | No default passwords | Confirm `DASHBOARD_USERS` env var (or new DB users) — never leave `admin:admin` in prod |
| 4.10 | Read-only roles cannot write | As `viewer`, `curl -X DELETE ...` on a protected resource → 403 |

---

## 5 · Operational drills (~15 minutes)

Real incidents the SOC will face. Practice once now, document the resolution
path in your runbook.

### 5.1 "Logs from device X stopped"
1. Sidebar → **Silent Sources** → confirm an open incident for X.
2. Sidebar → **System Logs** → watchtower tab → grep for the agent ID.
3. SSH to X → restart agent → incident auto-resolves.

### 5.2 "Suspicious user activity"
1. Sidebar → **Correlations** → review open `multi_location_logon`.
2. Click **View** → note IPs / hosts.
3. Sidebar → **Logs** → set source `eventlog`, EventID `4624`, agent name
   (or filter by user via the search box `TargetUserName:<name>`) → pivot
   into the full event timeline.

### 5.3 "Disk filling up"
1. Sidebar → **Retention** → confirm size + oldest age per family.
2. Decide: shorter retention or purge now?
3. Use **Preview (dry run)** → confirm match count → if expected, run.

### 5.4 "Someone changed a rule and now nothing fires"
1. Sidebar → **Config Audit** → filter target prefix `rule:` → find the
   last edit, note who and when.
2. Sidebar → **Rules** → rule versions → diff → restore previous content.
3. (Rule versioning already existed — Config Audit adds the "who".)

### 5.5 "DLQ depth keeps climbing"
1. Sidebar → **Stack Status** → Pipeline Health card.
2. If dropped_events > 0: WatchVault → OpenSearch is slow. Check OpenSearch
   heap / disk / cluster status (`curl localhost:9200/_cluster/health`).
3. Temporary mitigation: scale OpenSearch or **reduce ingest** via the
   **Log Filters** page (add a filter to drop the noisiest source).

---

## 6 · Sign-off

After completing §1–5, the analyst signs the box below and emails the
admin. Any unchecked item is filed as a remediation ticket before further
feature work.

```
SOC analyst:        ____________________________
Date completed:     ____________________________
Items failed:       ____________________________
Items deferred:     ____________________________

I confirm Sentinel SIEM is functioning per the verification checklist for
this deployment, with the exceptions noted above.

Signature:          ____________________________
```

---

## Appendix A — What was NOT built (and why)

| Feature | Status | Reason |
|---|---|---|
| Manager-side log dropping | Not built | Query-side filters + retention is the industry-standard pattern. Manager-side adds Go work, debug complexity, and is only worth it at very high event volumes. |
| Postgres for dashboard tables | Not built | Single-tenant deployment; SQLite matches existing `custom_store.py` pattern and is backed up by `sentinel-backup.sh`. |
| OpenSearch snapshot via UI | Not built | OpenSearch has a native snapshot API; out of scope for the dashboard. |
| Multi-instance dashboard / HA | Not built | Single-tenant per client deployment. |

If the customer profile changes (multi-tenant, high EPS, regulated industry
with hard storage caps), revisit these.

---

## Appendix B — Environment variable reference (new)

| Variable | Default | Purpose |
|---|---|---|
| `SESSION_TIMEOUT_HOURS` | `12` | Idle session timeout. PCI=0.25, HIPAA=0.5 typical. |
| `MIN_PASSWORD_LEN` | `10` | Minimum length for dashboard accounts. |
| `CSRF_STRICT` | `false` | Reject writes lacking Origin/Referer (breaks some scripted automation). |
| `CSRF_ALLOWED_HOSTS` | _empty_ | Comma-separated extra origins permitted to make writes. |
| `SILENT_DEFAULT_MIN` | `15` | Default silence threshold (minutes) for sources without a matching pattern. |
| `CORR_WINDOW_MIN` | `10` | Look-back window for stateful correlations. |
| `CORR_MIN_IPS` | `2` | Minimum distinct IPs/hosts for impossible-travel incident. |
| `WATCHVAULT_RETENTION_DAYS` | _empty_ | UI hint shown on Retention page. Authoritative value is in `watchvault.yaml`. |
| `SYSTEM_LOG_SOURCES` | _empty_ | `name:path,name:path` — file-mode fallback for System Logs page when docker isn't mounted. |
