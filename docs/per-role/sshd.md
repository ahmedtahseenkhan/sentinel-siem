# Sentinel SIEM — SSH server (sshd)

## What you get
Detection for: brute-force (5+ failed in 5 min from one IP), root login,
public-key auth from new IP, sshd config reload, suspicious shell
commands post-login (when paired with auditd). Rules in
`3500-sshd_deep`, plus correlation thresholds in
`engine/correlation/`.

## Prerequisites
- Linux host with OpenSSH server (`sshd`) running.
- Auth events routed to syslog or journald (default on every modern
  distro).
- WatchNode agent installed.

## Agent config snippet
```yaml
collectors:
  logs:
    enabled: true
    journal:
      enabled: true
      units: [sshd.service, ssh.service]   # name varies by distro
    sources:
      - type: file
        path: /var/log/secure       # RHEL/CentOS
        tags: [auth, sshd]
      - type: file
        path: /var/log/auth.log     # Debian/Ubuntu
        tags: [auth, sshd]
```

For WHO-attribution on file changes by ssh sessions, enable the
`audit` collector and set `whodata: true` on the FIM collector
(see [docs/whodata.md](../whodata.md) — covers SACL on Windows / auditd
on Linux).

## Events that flow
- `log.journal` with `unit=sshd.service`
- `logs.syslog` with `program=sshd`
- Fields: `program`, `message`, `user`, `src_ip`, `auth_method`

## Rules that fire (from `TestRolePipeline_SSHD`)
- 6× `Failed password for root from 198.51.100.7` in 2s → rule 7001
  (sshd brute force) fires after the threshold trips.
- Single root login from a new IP → rules in 3500 + identity batch 9000.

## Expected first-alert latency
- Single events: ≤ 5 seconds.
- Threshold-based brute force: ≤ 60 seconds (correlation window default 5 min, but it fires as soon as the count is met).

## Troubleshooting
1. **No sshd events**
   - `journalctl -u sshd --since '5 min ago' | head` shows events?
   - Some Ubuntu installs use `ssh.service` not `sshd.service`. Adjust
     `units:` accordingly.

2. **Single failed-login events flow but the brute-force threshold rule
    never fires**
   - The rule needs the SAME `src_ip` across N events within the window.
     If your agent ships events without parsing the IP out of the
     message text, the correlator can't group them. Confirm
     `src_ip` is set on the events in dashboard Discover.
   - The 3500 rules expect the `src_ip` field. If sshd is behind a
     load balancer the IP may be in `X-Forwarded-For` or similar —
     decode that upstream.

3. **Verify pipeline**
   ```
   cd WatchTower && go test -race -v -run TestRolePipeline_SSHD ./internal/engine/
   ```
