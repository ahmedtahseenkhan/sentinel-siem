# Sentinel SIEM — Postfix mail server

## What you get
Detection for: open-relay abuse, TLS downgrade, spam relay (10k+ messages
in 10 min), BEC indicators in the queue, RBL hits, and authentication
brute force. Rules in `3900-postfix_exim_mail`, plus email-deep rules in
batch 8800 (some apply to gateway-side events).

## Prerequisites
- Postfix configured to log to syslog (`maillog` or systemd-journald).
- WatchNode agent on the Postfix host.

## Agent config snippet
```yaml
collectors:
  logs:
    enabled: true
    journal:
      enabled: true
      units: [postfix.service, dovecot.service]
    # Or, if your system writes to /var/log/maillog directly:
    sources:
      - type: file
        path: /var/log/maillog
        tags: [postfix, mail]
      - type: file
        path: /var/log/mail.log
        tags: [postfix, mail]
```

## Events that flow
- `log.journal` with `unit=postfix.service` (systemd hosts)
- `logs.syslog` with `program=postfix/smtpd`, `postfix/cleanup`, `postfix/smtp`
- Fields: `program`, `message`, `from`, `to`, `client_ip`, `tls_status`

## Rules that fire (from `TestRolePipeline_Postfix`)
- `NOQUEUE: reject: RCPT from unknown[...]` → relay-denied rules
- `TLS handshake failed` → TLS downgrade alert

> **Note**: `TestRolePipeline_Postfix` currently produces 0 alerts on the
> two-event fixture because rule patterns are coarse. This is a known gap
> tracked in the test output. To improve, tighten the field-match in
> batch 3900 rules to look at `message` substring rather than message
> shape.

## Expected first-alert latency
≤ 5 seconds for journald, ≤ 15 seconds for file tail.

## Troubleshooting
1. **No mail events flowing**
   - On the host: `journalctl -u postfix --since '5 min ago'` shows events?
   - Confirm agent's `journal.enabled: true` and `units: [postfix.service]`.

2. **Events flow but no alerts**
   - The 3900 rule batch matches on specific substrings. If your Postfix
     uses non-English locale messages (e.g. German "Verbindung abgelehnt")
     the English substring matchers won't fire. Either lock Postfix locale
     to en_US.UTF-8 or extend the rule patterns.

3. **Verify pipeline**
   ```
   cd WatchTower && go test -race -v -run TestRolePipeline_Postfix ./internal/engine/
   ```
