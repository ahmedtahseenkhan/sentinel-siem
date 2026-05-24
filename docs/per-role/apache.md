# Sentinel SIEM — Apache HTTPD

## What you get
Detection on every Apache host for: directory traversal, SQLi/XSS in URIs,
suspicious user agents, large 4xx/5xx spikes per source, ModSecurity
blocks. Rules in `2600-web_application`, `3300-apache_nginx_tomcat`.

## Prerequisites
- Apache 2.4+ on Linux with combined log format enabled (default).
- Default log paths: `/var/log/apache2/*` (Debian/Ubuntu) or
  `/var/log/httpd/*` (RHEL/CentOS).
- WatchNode agent installed.

## Agent config snippet
```yaml
collectors:
  logs:
    enabled: true
    sources:
      - type: file
        path: /var/log/apache2/*.log     # Debian/Ubuntu
        tags: [apache, web]
      - type: file
        path: /var/log/httpd/*log        # RHEL/CentOS
        tags: [apache, web]
```

## Events that flow
- `log.file` with `source=apache` (rules check the tag), `uri`, `method`,
  `status`, `user_agent`, `client_ip`

## Rules that fire (from `TestRolePipeline_Apache`)
- `/cgi-bin/<script>alert(1)>` with status 403 → at least one alert
  (rule 14091 in current set, plus XSS rules in 2600+)
- `/../../../etc/passwd` with status 200 → directory traversal rules

## Expected first-alert latency
≤ 10 seconds.

## Troubleshooting
1. **Agent not reading Apache logs**
   - Check the agent runs as a user with read access to `/var/log/apache2/`.
     On many distros these are 640 owned by root:adm. Either run agent as
     root (default) or add the agent's user to the `adm` group.
   - Verify with: `ls -l /var/log/apache2/access.log`

2. **Events flow but no XSS / traversal alerts**
   - Some rules look at the decoded `path` field, not the raw `uri`. The
     Apache decoder is in `WatchTower/internal/engine/decoder/`. If you
     get raw events but no decoded ones, the decoder may need its
     pattern updated for your log format.

3. **Verify pipeline without sending a request**
   ```
   cd WatchTower && go test -race -v -run TestRolePipeline_Apache ./internal/engine/
   ```
