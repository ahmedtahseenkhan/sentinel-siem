# Changelog

Sentinel SIEM development history. The most recent entries cover a 3-week
hardening sprint that closed every actionable item from an 8-week capability
plan (see `CLAUDE.md` §7).

Each entry lists the commit short-hash for traceability. Earlier history is
summarised at the bottom.

---

## Week 3 — Hardening (Day 1 to Day 5)

### `23d1327e` — Day 4-5: per-role one-pagers + 5k EPS perf benchmark
- 6 operator-facing markdown files in [`docs/per-role/`](docs/per-role/) for
  AD, IIS, MSSQL, Apache, Postfix, sshd. Each cross-referenced to its
  `TestRolePipeline_*` test so docs stay accurate as rules evolve.
- `WatchTower/internal/engine/throughput_test.go` adds:
  - `BenchmarkSustainedEPS` — 200k synthetic events through the full
    3,000-rule pipeline, reports events/s and alerts/1k-events.
  - `TestSustainedEPSSmoke` — CI-friendly 5k-event variant with a 1k-EPS
    regression floor.
- **Result on Apple M5**: 850,000 EPS sustained, 170× the 5k target.

### `0a04796f` — Day 1-3: per-role test harness + 2 critical bug fixes
- New `WatchTower/internal/engine/per_role_test.go` loads the production
  rule set and replays canonical events per server role, asserting at least
  one expected rule ID fires. Runs in <12s, no external services.
- **Bug 1 (compiler)**: `field: {value: X}` syntax (used in batches
  1000-2700) was silently dropped — those rules matched every event of the
  right type, regardless of value. Fixed by normalising `Value` → `Equals`
  in `compileRule`.
- **Bug 2 (loader)**: `loadRulesFile` only accepted the `rules:`-wrapped
  YAML shape. My 21 files in batches 7100-9100 (compliance, APT actors,
  eCrime, mobile, IoT, OT/ICS, edge, email, DLP, IGA, data+AI) are bare
  top-level arrays — they had been loading as **0 rules each**. ~800
  rules silently absent in production before this fix.

## Week 2 — Cloud SaaS ingestion

### `4428b44c` — Day 5: Microsoft Defender via Graph Security
Unified Defender alerts (Endpoint, O365, Cloud Apps, Identity, plus
Sentinel) via `graph.microsoft.com/v1.0/security/alerts_v2`. Evidence
flattened into per-type slices (`evidence_users`, `evidence_devices`,
`evidence_ips`, etc.) so rules can match like
`evidence_user IN privileged_users CDB`.

### `22d07eed` — Day 3-4: Google Workspace Admin Reports
JWT service-account auth with domain-wide delegation (`getGCPTokenScoped`
generalised from the GCP audit collector). Default applications:
admin, login, drive, token.

### `ce3c7574` — Day 1-2: O365 Management Activity API
4 default content types: Audit.AzureActiveDirectory, Audit.Exchange,
Audit.SharePoint, Audit.General. Idempotent subscribe + per-type cursor
on `contentCreated`. Generalised `getAzureTokenForResource` so the same
helper serves Azure / O365 / Graph callers.

## Week 1 — Verifications + quick wins

### `cd5e4502` — Day 4: MISP feed source
7th threat-intel source type. Splits mixed attribute types per event
into `<prefix>_ips`, `_domains`, `_hashes`, `_urls` CDB lists (Wazuh's
pattern). Atomic install only when non-empty so a failed fetch never
blows away the prior good list.

### `a1a85fb4` — Day 2-3: VirusTotal alert enrichment
New `internal/enrich/virustotal.go`. Free-tier-safe (4 req/min token
bucket, 1h TTL cache, 5000-entry soft cap). Attaches to
`Alert.Enrichment["virustotal"]` BEFORE store/forward/notify so attached
context flows downstream. New `EnricherHook` on the engine.

### `1eeca0ba` — Day 1: rootcheck bugs + generic compliance dashboard
- **Rootcheck (4 bugs)**: no `//go:build linux` tag (silent no-op on
  Windows/macOS); hidden-port check compared ALL `/proc/net/tcp` against
  `ss -tln` (LISTEN only) producing flood of false positives; SUID scan
  alerted on every legitimate `sudo`/`passwd` each cycle (no baseline);
  hidden-process check raced between `/proc` walk and `ps`. All four
  fixed; baseline now persisted at `/var/lib/watchnode/rootcheck-suid-baseline`.
- **Compliance dashboard**: had ONLY HIPAA wired and that endpoint
  queried `rule.hipaa` (Wazuh schema) which our native rules don't emit.
  Added 4 generic functions filtering by `rule.groups: <framework>` so
  all 6 frameworks (PCI/HIPAA/GDPR/NIST/SOC2/CIS) are surfaced. New
  endpoint `GET /api/compliance/<framework>/dashboard`.

## Pre-sprint refactors (the "audit-first" pattern paying off)

### `aaa4b88e` — Vuln matching: OS-aware
Linux openssl CVEs no longer fire on every Windows host. New `AffectedOS`
field on `Vulnerability`, derived from CPE part=o + vendor heuristics.
`Database.MatchOS(hostOS, vendor, product, version)` enforces OS scope
when both sides specify one.

### `08fb60d0` — FIM whodata: end-to-end on both OSes
First fully-greenfield item this sprint. New `whodata/` cache package
(TTL ring keyed by path) + `audit/` collector (tails
`/var/log/audit/audit.log`, parses multi-line records, handles hex-
encoded paths) + Windows eventlog hook for 4663/4656 + FIM enrichment
on emit. Operator on Linux gets auditctl rules auto-installed when
`fim.whodata: true` (helper file at `/var/lib/watchnode/whodata-paths`).

### `437a62be` — Threat intel / CDB: 4 silent-miss bugs
- Data race on `Manager.lists` — fixed with RWMutex.
- Field-value lookup raw — `"1.2.3.4 "`, `"1.2.3.4:443"`,
  `"Example.COM."` all missed; added `normalizeKey()`.
- CIDR entries (Spamhaus DROP, Feodo Tracker) silently dropped —
  `List.MatchNormalized` now falls back to `IPNet.Contains` for IP
  lookups.
- Typo'd list name returned `false` silently — now logged once with a
  warning.

### `24f52c2a` — Cloud collector: real SigV4 + CloudTrail + GCP off-GCE
The cloud collector was scaffolded but broken in 5 ways. `signAWSRequest`
wrote a literal "Signature=placeholder" auth header — **every AWS call
was returning 403**. New `sigv4.go` is a 173-line hand-rolled SigV4
implementation. CloudTrail S3 polling (was config field with no code).
GCP off-GCE via service-account JWT. High-water-mark cursors per
provider. Azure filter relaxed from `Failed`-only to full window.

### `8b2cfd5d` — Vuln detection: 4 matcher bugs
- CVSS v2 fallback (every pre-2016 CVE was showing score 0).
- Real dpkg/rpm version comparator (epoch + release suffix + Debian
  tilde). Replaces a naive `strings.Split(".")` that broke on
  `1.1.1k-1ubuntu5` vs `1.1.1k`.
- CPE vendor disambiguation (`apache:tomcat` vs `eclipse:tomcat`).
- `VersionStartIncluding/Excluding` honoured (CVE on `>=2.0 <3.0` no
  longer fires on 1.x).

### `e87b21b5` — Active Response: safelist + TTL + dedup
Existing AR scaffold was complete but missing 3 safety controls:
IP+user safelist (default `127.0.0.1`/`Administrator`/`root`/`SYSTEM`
never get blocked/disabled); block TTL (default 1h auto-unblock via
new `firewall-unblock` command); idempotent in-memory tracking so a
noisy rule firing 1000x doesn't create 1000 netsh entries.

### `acc4a82e` — OS-signal collector subgaps
5 fixes across the agent collectors: registry collector was only
reading REG_SZ (DWORD/BINARY/MULTI_SZ silently empty); journal JSON
parser truncated on embedded `\"`; FIM emitted only SHA-256 (added
MD5+SHA-1 in one pass for IoC matching); process collector lacked
user/parent-name attribution; network connections lacked process
name.

## Earlier — Rule pack expansion (2,200+ new rules)

| Commit | Description | Rules added |
|---|---|---|
| `d679c0b2` | Pack #12: email-deep / DLP / IGA / data+AI | 104 |
| `df665a49` | Pack #11: mobile / IoT / OT/ICS / edge | 120 |
| `4bc23482` | Pack #10: APT + eCrime actor TTPs | 240 |
| `62515777` | Pack #9: compliance (PCI/HIPAA/GDPR/NIST/SOC2/CIS) | 290 |
| `4efbbe3a` | Pack #8: MITRE ATT&CK technique coverage | 250 |
| `e05b6be6` | Pack #7: network appliances (Cisco/PAN/FTNT/F5/IDS) | 200 |
| `8c8234e2` | Pack #6: container (Docker, K8s, supply chain) | 200 |
| `f7ecdbfd` | Pack #5: Windows endpoint deep (Sysmon, WMI, PowerShell) | 250 |
| `a381241a` | Pack #4: cloud (AWS, Azure, GCP, Workspace) | 250 |
| `5659c99f` | Pack #3: Exchange, IIS, O365, SharePoint | 200 |
| `02dfe6b0` | Pack #2: Linux servers, DBs, DNS, mail | 210 |
| `669f6491` | Pack #1: AD, web, MSSQL, web servers | 175 |

**Total rules in WatchTower/rules/**: ~3,000 across 90 YAML files.

## Earlier — Agent install & deployment polish

- `d36bff74` Visible agent install with transcript + always-pause-on-exit.
- `d85fc945` Fixed stale-agent-zip issue (Docker file-bind-mount inode bug).
- `608db8c3` `install.bat` double-click wrapper for Windows agents.
