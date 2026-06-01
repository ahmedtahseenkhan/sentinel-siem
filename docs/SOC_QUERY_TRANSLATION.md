# SOC Query Translation — Wazuh KQL → Sentinel (OpenSearch query_string)

This converts the Wazuh-style use-case queries (the "SIEM/XDR/EDR Use Cases" sheet)
into queries that actually run on **this** Sentinel stack.

> **Read this first — three hard rules of our stack:**
> 1. **Query language = Lucene `query_string`** (what the dashboard Discover/logs search
>    sends to OpenSearch — see [app.py](../sentinelCoreDashboard/app.py) `q: Lucene query_string`).
>    There is **no `| stats`, `| where`, `PER`, `IN ()`, `LIKE`, `length()`, `dc()`** — those
>    are Splunk/Wazuh-isms. Threshold/aggregation use-cases need an OpenSearch `aggs` body
>    (templates in §4), not a Discover query.
> 2. **Field names differ from Wazuh.** Use the map in §2. Detection queries filter
>    `rule_level`, so they run on **`watchvault-alerts*`** where OS fields live under
>    **`event_data.*`** (raw telemetry in `watchvault-events*` uses `data.*`).
> 3. **A query only "verifies" against real data.** Enrol an agent and generate the
>    activity first, or you'll get 0 hits on a perfectly valid query.

---

## 1. How to run & verify a query

**In the dashboard:** Discover → paste the `query_string` (the part in quotes below) →
set time range + index `watchvault-alerts*`.

**From the VM (authoritative test — proves syntax + match count):**
```bash
curl -s 'http://localhost:9200/watchvault-alerts*/_search' \
  -H 'Content-Type: application/json' -d '{
    "size": 0,
    "query": { "query_string": { "query": "agent_name: win-* AND rule_level: [8 TO 15]" } }
  }' | python3 -m json.tool
```
- `hits.total.value` = matches → **valid**.
- `"error"` (`query_shard_exception` / `parse_exception`) → bad field/syntax.

**Confirm the field names on YOUR live data before trusting any translation:**
```bash
curl -s 'http://localhost:9200/watchvault-alerts*/_search?size=1' | python3 -m json.tool   # inspect event_data.* keys
curl -s 'http://localhost:9200/watchvault-alerts*/_mapping' | python3 -m json.tool          # full field list
```

---

## 2. Field map (Wazuh → Sentinel)

| Wazuh (PDF) | Sentinel (alerts index) | Notes |
|---|---|---|
| `agent_name` | `agent_name` | ✅ identical; use `agent_name.keyword` for aggregations |
| `rule_level` | `rule_level` | ✅ int; ranges `[8 TO 15]` work |
| `rule.description` | `rule_description` | flat, not nested |
| `rule.id` | `rule_id` | |
| `rule.groups` | `rule_groups` | array of tags |
| `rule.mitre.tactic` | `mitre.tactic_name` / `mitre.tactic_id` | now indexed (array of objects) |
| `rule.mitre.technique` | `mitre.technique_id` / `mitre.technique_name` | e.g. `mitre.technique_id: T1110` |
| `data.srcip` / `data.src_ip` | `event_data.src_ip` | some decoders also emit `srcip` |
| `data.dstip` | `event_data.dst_ip` | |
| `data.srcport` / `data.dstport` | `event_data.src_port` / `event_data.dst_port` | |
| `data.protocol` | `event_data.protocol` | |
| `data.event_id` | `event_data.win_event_id` | **numeric**; `event_data.event_id` is the string form |
| `data.process_name` | `event_data.process_name` | |
| `data.command_line` | `event_data.command_line` | |
| `data.user` | `event_data.user` | also `username`, `src_user`, `dst_user` |
| `data.url` | `event_data.http_path` | full path; `event_data.url` on some sources |
| `data.http_status` | `event_data.status_code` | |
| `data.method` | `event_data.http_method` | |
| `data.user_agent` | `event_data.user_agent` | ✅ identical |
| `data.file_name` | `event_data.filename` | |
| `data.file_path` | `event_data.file_path` / `fim_path` | FIM events |
| `data.registry_key` | `event_data.registry_key` | ⚠️ verify against live data |
| `data.logon_type` | `event_data.logon_type` | ⚠️ depends on Sigma field-normalisation |

**Operator translation:**

| Wazuh/Splunk | Lucene `query_string` |
|---|---|
| `data.user IN (a, b)` | `event_data.user:(a OR b)` |
| `data.url LIKE "*x*"` | `event_data.http_path: *x*` |
| `NOT data.user: admin` | `NOT event_data.user: admin` |
| `timestamp: [now-1h TO now]` | set the **time picker** (don't put `now-1h` in query_string) |
| `… \| stats count by X \| where count > N` | **aggregation body** — see §4 |

---

## 3. Translated queries (runnable as `query_string` on `watchvault-alerts*`)

> Paste the string inside quotes into Discover. ✅ = runnable now · 🔢 = needs §4 aggregation · 🚫 = needs a log source/field you don't have yet.

### Table 1 — Port Scanning & External Recon
- 🔢 Port/horizontal scan (counts of dst_port/dst_ip per src_ip) → §4 *distinct-count* template; filter `rule_groups: recon` or `rule_description: *scan*`.
- ✅ Known VA scan tools: `agent_name: win-* AND rule_level:[8 TO 15] AND (rule_description: *nmap* OR rule_description: *masscan* OR event_data.user_agent: (*nmap* OR *masscan*))`

### Table 2 — Internal Recon
- ✅ Internal scan on vuln ports: `rule_level:[8 TO 15] AND event_data.src_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16) AND event_data.dst_port:(445 OR 3389 OR 22 OR 1433)`
- ✅ ARP scan: `rule_level:[8 TO 15] AND event_data.protocol: ARP AND rule_description: *scan*`
- 🔢 Slow/aggressive scans (rate over time) → §4.

### Table 3 — Asset Discovery
- ✅ SMB/share enumeration: `rule_level:[8 TO 15] AND (rule_description:(*share* OR *SMB*)) AND event_data.src_ip:*`
- ✅ net share/view: `rule_level:[8 TO 15] AND event_data.command_line:(*net?share* OR *net?view*)`
- ✅ UPnP: `rule_level:[8 TO 15] AND event_data.dst_port:1900 AND event_data.protocol: UDP`

### Table 4 — SPN Discovery / Kerberos
- ✅ SPN request: `rule_level:[8 TO 15] AND event_data.win_event_id:4769 AND rule_description: *SPN*`
- ✅ Kerberoasting (RC4 ticket): `rule_level:[8 TO 15] AND event_data.win_event_id:4769 AND event_data.ticket_encryption: RC4` — ⚠️ `ticket_encryption` only present if the 4769 decoder extracts it; verify, else use `rule_description: *kerberoast*`.
- ✅ AS-REP roasting: `rule_level:[8 TO 15] AND event_data.win_event_id:4768 AND event_data.pre_auth_not_required: true` — ⚠️ verify field; fallback `rule_description: *AS-REP*`.

### Table 5 — Exploitation Tools
- ✅ Mimikatz/Cobalt: `rule_level:[8 TO 15] AND (event_data.process_name:(*mimikatz* OR *cobalt*) OR event_data.command_line: *sekurlsa*)`
- ✅ SharpHound/BloodHound: `rule_level:[8 TO 15] AND (event_data.process_name: SharpHound.exe OR event_data.command_line: *-CollectionMethod*)`
- ✅ Impacket (psexec/wmiexec): `rule_level:[8 TO 15] AND event_data.command_line:(*wmiexec* OR *psexec* OR *smbexec*)`
- ✅ Nmap UA in web logs: `rule_level:[8 TO 15] AND event_data.user_agent:(*nmap* OR *masscan*)`

### Table 6 — Phishing / Email  🚫
All of these need an **email-gateway / O365 message-trace log source** (`email_subject`,
`sender`, `recipient`, `attachment`). You don't ingest that yet → **detection gap**, not a
translation problem. See §5.

### Table 7 — Web-based Malware  🚫 (mostly)
Needs a **proxy/URL-filtering feed** (`url_category`, malware-domain lists). If you only
have web-server access logs, you can do:
- ✅ Suspicious download by extension: `rule_level:[8 TO 15] AND event_data.http_path:(*.exe OR *.scr OR *.msi)`

### Table 8 — System Malware Delivery
- ✅ PowerShell encoded: `rule_level:[8 TO 15] AND event_data.process_name: powershell.exe AND event_data.command_line:(*-enc* OR *-EncodedCommand* OR *FromBase64String*)`
- ✅ LOLBins: `rule_level:[8 TO 15] AND event_data.process_name:(certutil.exe OR bitsadmin.exe OR rundll32.exe OR regsvr32.exe OR mshta.exe)`
- ✅ New binary in system dirs: `rule_level:[8 TO 15] AND event_data.file_path:(*\\Windows\\* OR *\\Program?Files\\*) AND rule_groups: fim`
- ✅ DCSync: `rule_level:[8 TO 15] AND event_data.win_event_id:4662 AND rule_description: *replication*` (⚠️ verify `access_mask` extraction; fallback to description).

### Table 9 — Web App Exploits (web-server logs)
- ✅ SQLi: `rule_level:[8 TO 15] AND event_data.http_path:(*SELECT* OR *UNION* OR *1=1* OR *DROP*)`
- ✅ Directory traversal: `rule_level:[8 TO 15] AND event_data.http_path:(*../* OR *%2e%2e%2f*)`
- ✅ XSS: `rule_level:[8 TO 15] AND event_data.http_path:(*<script* OR *onload=* OR *javascript:*)`
- ✅ Command injection: `rule_level:[8 TO 15] AND event_data.http_path:(*;ls* OR *|id* OR *whoami* OR *$(*)`
- ✅ SSRF: `rule_level:[8 TO 15] AND event_data.http_path:(*127.0.0.1* OR *localhost* OR *169.254.169.254*)`
- ✅ Sensitive-file access: `rule_level:[8 TO 15] AND event_data.http_path:(*/etc/passwd* OR *web.config* OR *.env*) AND event_data.status_code:200`
- 🔢 "Excessive 4xx/5xx then 200", "abnormal URL length" → §4 (count/where).

### Table 10 — Brute Force  🔢
Every one is a count-over-threshold → §4 *count-threshold* template. Base filter:
`rule_level:[8 TO 15] AND event_data.win_event_id:4625` (Windows) or `4771` (Kerberos),
`logon_type:10` for RDP. Single non-aggregated check still works:
- ✅ RDP failures present: `rule_level:[8 TO 15] AND event_data.win_event_id:4625 AND event_data.logon_type:10`

### Table 11 — Auth Failure Anomalies  🔢
- ✅ Failed logon on disabled/expired (single match): `rule_level:[8 TO 15] AND event_data.win_event_id:4625 AND event_data.sub_status:(0xC0000072 OR 0xC0000193)` (disabled / expired status codes; ⚠️ verify `sub_status` extraction).
- ✅ Linux SSH failures: `agent_name: linux-* AND rule_level:[8 TO 15] AND rule_description:(*authentication?failure* OR *Failed?password*)`
- 🔢 spraying / low-and-slow / lockout patterns → §4.
- 🚫 Impossible travel → needs geo enrichment (not in pipeline).

### Table 12 — Internal Malware Infection
- ✅ LSASS access (cred dump): `rule_level:[8 TO 15] AND event_data.command_line: *lsass* `  (or `rule_description: *credential?dump*`)
- ✅ Ransomware note: `rule_level:[8 TO 15] AND event_data.filename:(*ransom*.txt OR *readme*.txt OR *recover*.txt) AND rule_groups: fim`
- ✅ Malicious Office child: `rule_level:[8 TO 15] AND event_data.parent_process:(WINWORD.EXE OR EXCEL.EXE) AND event_data.process_name:(cmd.exe OR powershell.exe)` — ⚠️ verify `parent_process` key.
- ✅ New service on critical host: `rule_level:[8 TO 15] AND event_data.win_event_id:4697`

### Table 13 — Privilege Escalation
- ✅ Added to admin group: `rule_level:[8 TO 15] AND event_data.win_event_id:(4732 OR 4728) AND event_data.target_group:(Administrators OR "Domain Admins")` — ⚠️ verify `target_group`.
- ✅ Special privileges assigned: `rule_level:[8 TO 15] AND event_data.win_event_id:4672`
- ✅ User created/deleted: `rule_level:[8 TO 15] AND event_data.win_event_id:(4720 OR 4726)`
- ✅ UAC bypass: `rule_level:[8 TO 15] AND (rule_description: *UAC?bypass* OR event_data.process_name:(*fodhelper* OR *eventvwr*))`

### Table 14 — Lateral Movement
- ✅ RDP internal→external: `rule_level:[8 TO 15] AND event_data.logon_type:10 AND NOT event_data.dst_ip:(10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16)`
- ✅ Audit log cleared: `rule_level:[8 TO 15] AND (event_data.win_event_id:1102 OR rule_description: *audit?log?cleared*)`
- ✅ Event-log service stopped: `rule_level:[8 TO 15] AND event_data.win_event_id:1100`
- ✅ Pass-the-Hash (NTLM, logon_type 9): `rule_level:[8 TO 15] AND event_data.win_event_id:4624 AND event_data.logon_type:9`
- ✅ GPO modified: `rule_level:[8 TO 15] AND (event_data.win_event_id:5136 OR rule_description: *GPO?modified*)`

### Table 15 — Persistence
- ✅ Run-key persistence: `rule_level:[8 TO 15] AND event_data.registry_key:(*\\Run* OR *\\RunOnce*)` — ⚠️ verify `registry_key`.
- ✅ Scheduled task: `rule_level:[8 TO 15] AND (event_data.win_event_id:4698 OR event_data.process_name: schtasks.exe)`
- ✅ Web shell: `agent_name: web-* AND rule_level:[8 TO 15] AND event_data.filename:(*.jsp OR *.php OR *.aspx) AND rule_groups: fim`
- ✅ AppInit DLL / IFEO: `rule_level:[8 TO 15] AND event_data.registry_key:(*AppInit_DLLs* OR *Image?File?Execution?Options*)`

### Table 16 — Data Exfiltration  🔢 / 🚫
- ✅ Removable device: `rule_level:[8 TO 15] AND event_data.win_event_id:6416`
- ✅ DB export tools: `rule_level:[8 TO 15] AND event_data.command_line:(*mysqldump* OR *pg_dump* OR *expdp* OR *bcp*)`
- 🔢 large outbound volume / excessive POST → §4 (sum/count). 🚫 cloud-upload + DLP need those feeds.

### Table 17 — DoS / DDoS  🔢
All rate-based → §4 *count-threshold*. Single-shot signal:
- ✅ SYN flood signature: `rule_level:[8 TO 15] AND event_data.tcp_flags: SYN AND NOT event_data.tcp_flags: ACK` (⚠️ verify `tcp_flags`).

### Table 18 — Cryptomining
- ✅ Miner process: `rule_level:[8 TO 15] AND event_data.process_name:(xmrig.exe OR miner.exe OR cpuminer.exe OR nbminer.exe)`
- ✅ Mining pool ports: `rule_level:[8 TO 15] AND event_data.dst_port:(3333 OR 4444 OR 5555 OR 7777)`
- 🚫 mining-site URL categories → needs proxy feed. 🔢 sustained high CPU → §4 (needs a CPU metric field).

### Table 19 — Genomics  🚫
Entirely custom (`sequencer-*`, `synthesis-*`, `crispr-*`, `genomics-*` agents and fields
like `fragment_length`, `guide_sequence`, `target_organism`). **None of these log sources
or fields exist in the stack** — this is net-new instrumentation, not a translation. See §5.

---

## 4. Aggregation templates (for every `| stats … | where count > N` use-case)

These **cannot** be Discover query_strings. Run against `_search` with a body, or wire into
a rule. Combine the `query_string` (the filter) with an `aggs` block.

**A) Count-threshold** (brute force, floods, "excessive X from single source"):
```bash
curl -s 'http://localhost:9200/watchvault-alerts*/_search' -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": { "bool": { "must": [
    { "query_string": { "query": "rule_level:[8 TO 15] AND event_data.win_event_id:4625" } },
    { "range": { "timestamp": { "gte": "now-5m" } } }
  ]}},
  "aggs": { "by_src": {
    "terms": { "field": "event_data.src_ip.keyword", "size": 50, "min_doc_count": 10 }
  }}
}'
```
Buckets returned = sources with ≥10 failures in 5 min (the `| stats count by src_ip | where count>10`).

**B) Distinct-count** (port/host scanning — "many dst_ports per src_ip"):
```json
"aggs": { "by_src": {
  "terms": { "field": "event_data.src_ip.keyword", "size": 50 },
  "aggs": { "uniq_ports": { "cardinality": { "field": "event_data.dst_port" } },
            "ports_gt_20": { "bucket_selector": {
              "buckets_path": { "p": "uniq_ports" }, "script": "params.p > 20" } } }
}}
```

**C) Login-failure-then-success** (`stats values(event_id) by user`):
use a `terms` on `event_data.user.keyword` with a sub-agg `terms` on `event_data.win_event_id`
and a `bucket_selector` requiring both 4625 and 4624 present.

**D) Beaconing / time-bucketing** (`span(timestamp,1h)`):
`date_histogram` on `timestamp` with `fixed_interval: "1h"`, nested under a `terms` on the
src/dst pair.

> Note: `terms`/`cardinality` need a `keyword`/numeric field. String fields use the
> `.keyword` sub-field (`event_data.src_ip.keyword`); numeric (`win_event_id`, `dst_port`)
> are used directly. Confirm via the `_mapping` call in §1.

---

## 5. Missing — gaps to flag before the SOC engineer relies on these

These use-cases **cannot be satisfied by translation** because the data isn't in the
pipeline. Each is a decision: add the source/field, or drop the use-case.

| Gap | Affected tables | What's needed |
|---|---|---|
| ~~**MITRE tactic/technique as a queryable field**~~ ✅ **FIXED** | cross-cutting | WatchVault now indexes the rule's MITRE block as a `mitre` array. Query `mitre.technique_id: T1110`, `mitre.tactic_name: "Credential Access"`. (Rebuild watchtower+watchvault; only applies to alerts indexed after the fix.) |
| **Email gateway / O365 message trace** | 6 (Phishing) | ingest message-trace logs → `email_subject`, `sender`, `recipient`, `attachment`. |
| **Proxy / URL-category feed** | 7, 18 | ingest proxy logs with `url_category`; today only web-server access logs exist. |
| **DLP / cloud-upload telemetry** | 16 | needs a DLP or CASB source. |
| **Geo-IP enrichment** | 11 (impossible travel) | no geo field on events; add a geo enricher. |
| **CPU / host metrics as fields** | 18 (high-CPU mining) | syscollector metrics aren't indexed per-event as `cpu_usage`. |
| **Windows 4769/4768 sub-fields** (`ticket_encryption`, `pre_auth_not_required`, `logon_type`, `target_group`, `sub_status`, `access_mask`, `tcp_flags`, `registry_key`, `parent_process`) | 4, 11, 12, 13, 15, 17 | these depend on the eventlog decoder's field normalisation. **Verify each against a live doc** (`_search?size=1`); where absent, the rule must extract them or the query falls back to `rule_description`. |
| **Genomics sources** (`sequencer-*`, `synthesis-*`, `crispr-*`, `ml-*`) | 19 | entirely net-new agents/log shippers + fields. Nothing exists today. |

---

## TL;DR for the SOC engineer
- Paste the **§3** strings into Discover against `watchvault-alerts*`; they're already in
  our field names.
- Anything marked **🔢** must be run as a **§4** aggregation, not a Discover search.
- Anything marked **🚫** is a **data-source gap** (§5), not a query you can fix.
- Always confirm a field exists with `_search?size=1` before trusting a translation — the
  Windows event sub-fields (⚠️) are the ones most likely to need a rule/decoder tweak.
