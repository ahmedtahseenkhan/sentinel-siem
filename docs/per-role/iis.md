# Sentinel SIEM — IIS web server

## What you get
Detection on every IIS host for: SQLi, XSS, command injection, path traversal,
suspicious user agents (sqlmap, nikto, nmap), webshell drops, large 5xx
spikes, and authentication abuse. Rules in batches `2600-web_application`,
`3100-web_application_advanced`, `4100-iis_specific`.

## Prerequisites
- Windows Server with IIS installed and at least one site bound.
- IIS extended logging enabled with these fields (Web Site → Logging):
  Date, Time, ClientIP, UserName, ServerIP, Method, UriStem, UriQuery,
  HttpStatus, BytesSent, BytesRecv, TimeTaken, UserAgent, Referer.
- WatchNode agent installed.

## Agent config snippet
```yaml
collectors:
  logs:
    enabled: true
    sources:
      - type: file
        path: C:\inetpub\logs\LogFiles\W3SVC*\u_ex*.log
        tags: [iis, web]
        multiline_pattern: "^\\d{4}-\\d{2}-\\d{2}"
```

## Events that flow
- `log.file` with `source=iis` (set by the rule), tagged `web`
- Fields: `uri`, `method`, `status`, `user_agent`, `app_zone`

## Rules that fire (from `TestRolePipeline_IIS`)
A canonical SQLi attempt in the URI (`/products?id=1' OR 1=1--`) trips at
least one rule. The current harness sees rule 14091 fire; additional
rules in 3100 expected to match as field decoders are tightened.

## Expected first-alert latency
≤ 15 seconds (file tail polls every 5s + engine pipeline).

## Troubleshooting
1. **No `log.file` events from IIS**
   - On the IIS host: is `C:\inetpub\logs\LogFiles\W3SVCx\` being written? Check `dir /OD` for fresh files.
   - Some installs route to `%SystemDrive%\inetpub\logs\LogFiles\`; verify the path the agent is watching matches.
   - Agent log: look for `tailer started path=...` lines.

2. **Events flow but no alerts on SQLi tests**
   - In dashboard Discover: do you see your test URI in the `uri` field?
   - Some rules in 3100 require `source=iis` set explicitly — if your events arrive without a `source` field, the rule won't match. Either add `source: iis` to the agent tag config OR loosen the rule.

3. **Verify rule firing without sending a real request**
   ```
   cd WatchTower && go test -race -v -run TestRolePipeline_IIS ./internal/engine/
   ```
