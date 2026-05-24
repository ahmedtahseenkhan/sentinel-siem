# Sentinel SIEM — Active Directory (Domain Controller)

## What you get
Detection on every Domain Controller for: failed/successful logons (4624/4625),
privileged group changes (4728), service account abuse, Kerberos
pre-auth failures, DCSync, ZeroLogon-style account resets, and audit log
tampering. ~70 rules across batches `1000-windows_security`,
`2300-windows_security_events`, `3000-active_directory_attacks`,
`6700-mitre_privilege_escalation`, `6800-mitre_defense_evasion`,
`6900-mitre_credential_access`.

## Prerequisites
- Windows Server 2016+ DC, joined to the domain.
- WatchNode agent installed (see [SentinelAgent install guide](../../WatchNode/SentinelAgent/)).
- Windows audit policy: Advanced Audit Configuration set to:
  - Account Logon → Audit Credential Validation: Success + Failure
  - Logon/Logoff → Audit Logon: Success + Failure
  - Account Management → Audit Security Group Management: Success + Failure
  - DS Access → Audit Directory Service Changes: Success
  - System → Audit Security State Change: Success
  - Privilege Use → Audit Sensitive Privilege Use: Success + Failure

The above can be set via GPO (`Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration`).

## Agent config snippet
```yaml
collectors:
  logs:
    enabled: true
    eventlog:
      enabled: true
      channels:
        - Security
        - System
        - Microsoft-Windows-Sysmon/Operational   # if Sysmon installed
        - Microsoft-Windows-PowerShell/Operational
  registry:
    enabled: true
    keys:
      - path: HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters
        recursive: true
```

## Events that flow
- `log.eventlog` with channel=Security and a `win_event_id` between 4xxx/5xxx
- `log.eventlog` with channel=Microsoft-Windows-PowerShell/Operational, event 4104
- (optional) Sysmon process-create events

## Rules that fire (from `TestRolePipeline_ActiveDirectory`)
A canonical failed-logon (4625) + admin group add (4728) trips at least 12
rules including 6001, 6007, 11005, 11006, 11026, 12037, 12096, 15110, 15115,
18909, 18911, 19244. Rule list updates automatically as more rules are
written — the test asserts ≥1 alert, individual IDs are informational.

## Expected first-alert latency
≤ 10 seconds from event generation on the DC to alert visible in the
Sentinel dashboard, on a 2-core / 4 GB DC under normal load.

## Troubleshooting
1. **No `log.eventlog` events reaching the manager**
   - On the DC: `Get-WinEvent -LogName Security -MaxEvents 5` returns events?
   - On the manager: `docker compose logs watchtower | grep agent_id=<dc-name>`
   - If neither: check firewall — agent → manager TCP 50051.

2. **Events flow but no alerts**
   - Confirm audit policy is in effect: `auditpol /get /category:*` should show "Success and Failure" for the categories above.
   - In dashboard go to Discover → filter `agent.id=<dc>`, you should see events.
   - Check rule loader logs: `docker compose logs watchtower | grep "rules loaded"` — should be > 2900.

3. **Want to verify rules without a real event**
   ```
   cd WatchTower
   go test -race -v -run TestRolePipeline_ActiveDirectory ./internal/engine/
   ```
