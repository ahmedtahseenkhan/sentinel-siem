"""
notifier.py — Email and Slack notifications for Sentinel SIEM critical alerts.
"""
import os
import smtplib
import json
import threading
import time
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# ── Configuration (all from .env / environment) ──────────────────────────────
SMTP_HOST     = os.getenv("SMTP_HOST", "")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER     = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM     = os.getenv("SMTP_FROM", "sentinel@localhost")
SMTP_TLS      = os.getenv("SMTP_TLS", "true").lower() in ("true", "1", "yes")
ALERT_TO      = os.getenv("ALERT_EMAIL_TO", "")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL", "")
THROTTLE_MIN  = int(os.getenv("ALERT_THROTTLE_MINUTES", "30"))

# ── Throttle: prevents flood of emails for the same alert ───────────────────
_throttle_lock = threading.Lock()
_last_sent: dict[str, float] = {}   # key → last send epoch


def _throttle_key(alert: dict) -> str:
    return f"{alert.get('rule_id','?')}:{alert.get('agent_id','?')}"


def _should_send(alert: dict) -> bool:
    if THROTTLE_MIN <= 0:
        return True
    key = _throttle_key(alert)
    now = time.monotonic()
    with _throttle_lock:
        last = _last_sent.get(key, 0)
        if now - last < THROTTLE_MIN * 60:
            return False
        _last_sent[key] = now
    return True


# ── Email ────────────────────────────────────────────────────────────────────
def send_email(subject: str, html_body: str, to: Optional[str] = None) -> bool:
    recipient = to or ALERT_TO
    if not SMTP_HOST or not recipient:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_FROM
        msg["To"]      = recipient
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
            if SMTP_TLS:
                s.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                s.login(SMTP_USER, SMTP_PASSWORD)
            s.sendmail(SMTP_FROM, [recipient], msg.as_string())
        logger.info("Email sent to %s: %s", recipient, subject)
        return True
    except Exception as e:
        logger.error("Email send failed: %s", e)
        return False


def _alert_email_html(alert: dict) -> str:
    level     = alert.get("rule_level", 0)
    sev_color = "#d32f2f" if level >= 12 else "#e65100" if level >= 8 else "#f9a825" if level >= 4 else "#388e3c"
    sev_label = "CRITICAL" if level >= 12 else "HIGH" if level >= 8 else "MEDIUM" if level >= 4 else "LOW"
    ts        = alert.get("timestamp", "")
    if ts:
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z","+00:00"))
            ts = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            pass
    return f"""
<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:20px;">
  <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)">
    <div style="background:{sev_color};color:#fff;padding:16px 24px;">
      <h2 style="margin:0">&#9888; Sentinel SIEM Alert &mdash; {sev_label}</h2>
    </div>
    <div style="padding:24px;">
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:8px;font-weight:bold;color:#555;width:140px">Severity</td>
            <td style="padding:8px"><span style="background:{sev_color};color:#fff;padding:3px 10px;border-radius:12px;font-size:12px">{sev_label} (Level {level})</span></td></tr>
        <tr style="background:#fafafa"><td style="padding:8px;font-weight:bold;color:#555">Description</td>
            <td style="padding:8px">{alert.get("rule_description","&mdash;")}</td></tr>
        <tr><td style="padding:8px;font-weight:bold;color:#555">Agent</td>
            <td style="padding:8px">{alert.get("agent_name") or alert.get("agent_id","&mdash;")}</td></tr>
        <tr style="background:#fafafa"><td style="padding:8px;font-weight:bold;color:#555">Rule ID</td>
            <td style="padding:8px">{alert.get("rule_id","&mdash;")}</td></tr>
        <tr><td style="padding:8px;font-weight:bold;color:#555">Groups</td>
            <td style="padding:8px">{", ".join(alert.get("rule_groups",[]) or [])}</td></tr>
        <tr style="background:#fafafa"><td style="padding:8px;font-weight:bold;color:#555">Source IP</td>
            <td style="padding:8px">{alert.get("srcip") or (alert.get("event_data") or {}).get("srcip","&mdash;")}</td></tr>
        <tr><td style="padding:8px;font-weight:bold;color:#555">Time</td>
            <td style="padding:8px">{ts}</td></tr>
      </table>
      <p style="margin-top:24px;font-size:12px;color:#888">
        Sent by Sentinel SIEM &middot; <a href="http://localhost:5050" style="color:#1565c0">Open Dashboard</a>
      </p>
    </div>
  </div>
</body>
</html>"""


# ── Slack ─────────────────────────────────────────────────────────────────────
def send_slack(alert: dict) -> bool:
    if not SLACK_WEBHOOK:
        return False
    import urllib.request
    level     = alert.get("rule_level", 0)
    sev_label = "🔴 CRITICAL" if level >= 12 else "🟠 HIGH" if level >= 8 else "🟡 MEDIUM" if level >= 4 else "🟢 LOW"
    color     = "#d32f2f" if level >= 12 else "#e65100" if level >= 8 else "#f9a825" if level >= 4 else "#388e3c"
    payload = {
        "attachments": [{
            "color": color,
            "title": f"{sev_label} — {alert.get('rule_description','Alert')}",
            "fields": [
                {"title": "Agent",   "value": alert.get("agent_name") or alert.get("agent_id","—"), "short": True},
                {"title": "Level",   "value": str(level),                                            "short": True},
                {"title": "Rule ID", "value": str(alert.get("rule_id","—")),                         "short": True},
                {"title": "Groups",  "value": ", ".join(alert.get("rule_groups",[]) or []),          "short": True},
            ],
            "footer": "Sentinel SIEM",
            "ts": int(time.time()),
        }]
    }
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(SLACK_WEBHOOK, data=data,
                                      headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
        return True
    except Exception as e:
        logger.error("Slack send failed: %s", e)
        return False


# ── Public entry point called by the alert watcher ───────────────────────────
def notify_alert(alert: dict) -> None:
    """Send email + Slack for a single alert if it passes throttle."""
    if not _should_send(alert):
        return
    level = int(alert.get("rule_level") or 0)
    if level < 8:
        return   # only HIGH / CRITICAL
    desc  = alert.get("rule_description", "Security Alert")
    subj  = f"[Sentinel SIEM] {'CRITICAL' if level >= 12 else 'HIGH'} Alert: {desc}"
    # Fire and forget — don't block the watcher thread.
    threading.Thread(target=send_email, args=(subj, _alert_email_html(alert)), daemon=True).start()
    threading.Thread(target=send_slack, args=(alert,), daemon=True).start()


# ── Background alert watcher ─────────────────────────────────────────────────
class AlertWatcher:
    """Polls OpenSearch every 60 s for new HIGH/CRITICAL alerts and notifies."""

    def __init__(self, os_search_fn, index_prefix: str):
        self._search  = os_search_fn
        self._prefix  = index_prefix
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_ts: Optional[str] = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("AlertWatcher started (email=%s, slack=%s)",
                    bool(SMTP_HOST and ALERT_TO), bool(SLACK_WEBHOOK))

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        # Seed the last_ts so we don't flood on startup.
        self._last_ts = datetime.now(timezone.utc).isoformat()
        while self._running:
            try:
                self._check()
            except Exception as e:
                logger.debug("AlertWatcher check error: %s", e)
            time.sleep(60)

    def _check(self) -> None:
        body = {
            "size": 20,
            "sort": [{"timestamp": {"order": "asc"}}],
            "query": {"bool": {"must": [
                {"range": {"rule_level": {"gte": 8}}},
                {"range": {"timestamp": {"gt": self._last_ts}}},
            ]}},
        }
        res   = self._search(f"{self._prefix}-alerts-*", body)
        hits  = (res.get("hits") or {}).get("hits", [])
        if hits:
            self._last_ts = hits[-1]["_source"].get("timestamp", self._last_ts)
        for h in hits:
            src = h.get("_source", {})
            alert = {
                "rule_id":          src.get("rule_id"),
                "rule_description": src.get("rule_description"),
                "rule_level":       src.get("rule_level"),
                "rule_groups":      src.get("rule_groups", []),
                "agent_id":         src.get("agent_id"),
                "agent_name":       src.get("agent_name"),
                "timestamp":        src.get("timestamp"),
                "srcip":            (src.get("event_data") or {}).get("srcip"),
                "event_data":       src.get("event_data", {}),
            }
            notify_alert(alert)
