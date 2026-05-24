# Sentinel SIEM — Microsoft SQL Server

## What you get
Detection on every MSSQL instance for: `xp_cmdshell` use, mass `SELECT *`
against sensitive tables, schema changes, audit-log tampering, login
spike, broken sp_configure (security off), and CDE/PCI rule mapping.
Rules in batches `3200-mssql_audit`, plus compliance overlays from
batch 7100 (PCI Req 8.7) and 7200 (HIPAA technical safeguards).

## Prerequisites
- MSSQL Server 2016+ (Windows or Linux container).
- SQL Server Audit enabled and routed to the Windows Application log
  (or file → tailed by agent). Required audit specifications:
  - SCHEMA_OBJECT_CHANGE_GROUP
  - DATABASE_PRINCIPAL_CHANGE_GROUP
  - SERVER_ROLE_MEMBER_CHANGE_GROUP
  - FAILED_LOGIN_GROUP
  - SUCCESSFUL_LOGIN_GROUP (optional)
  - DATABASE_OBJECT_PERMISSION_CHANGE_GROUP

## Agent config snippet
```yaml
collectors:
  logs:
    enabled: true
    eventlog:
      enabled: true
      channels: [Application]    # SQL Server Audit writes here
    sources:
      - type: file
        path: C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\LOG\ERRORLOG*
        tags: [mssql]
```

## Events that flow
- `log.eventlog` from Application channel with `Source=MSSQLSERVER`
- `log.file` from ERRORLOG with `tags=[mssql]`
- Fields the rules use: `service`, `query`, `user`, `app_zone`

## Rules that fire (from `TestRolePipeline_MSSQL`)
- `EXEC xp_cmdshell 'whoami'` → at least one alert (rule 14091 in current set)
- `SELECT * FROM dbo.patient` with `app_zone=cde` → PCI Req 8.7 rule (19131)

## Expected first-alert latency
≤ 30 seconds (SQL audit can be batched).

## Troubleshooting
1. **No MSSQL events**
   - On SQL host: `SELECT * FROM sys.dm_server_audit_status;` — `is_state_enabled=1`?
   - If audit writes to a file path the agent doesn't watch, add it to `sources:` and restart agent.

2. **xp_cmdshell test doesn't fire**
   - Rule 19455 (APT41) matches on `query` containing the string; your audit record may not include the full query text. Enable `Audit Statement Text` in your audit specification.

3. **Verify the rule pipeline without running a query**
   ```
   cd WatchTower && go test -race -v -run TestRolePipeline_MSSQL ./internal/engine/
   ```
