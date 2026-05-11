"""
Scheduled report delivery for Sentinel SIEM dashboard.
Uses APScheduler to run jobs in-process alongside Gunicorn.
Schedules are persisted in a JSON file so they survive restarts.
"""
import os
import json
import logging
import smtplib
import threading
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)

SCHEDULES_FILE = os.getenv("SCHEDULES_FILE", "/tmp/sentinel_schedules.json")

_scheduler = BackgroundScheduler(timezone="UTC")
_lock = threading.Lock()


# ── Persistence ───────────────────────────────────────────────────────────────

def _load_schedules():
    try:
        with open(SCHEDULES_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save_schedules(schedules):
    Path(SCHEDULES_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(SCHEDULES_FILE, "w") as f:
        json.dump(schedules, f, indent=2)


# ── Email delivery ────────────────────────────────────────────────────────────

def _send_report_email(recipients: list, subject: str, html_body: str):
    smtp_host = os.getenv("SMTP_HOST", "")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_pass = os.getenv("SMTP_PASSWORD", "")
    from_addr = os.getenv("SMTP_FROM", smtp_user)

    if not smtp_host or not recipients:
        logger.warning("Scheduled report: SMTP not configured or no recipients")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_addr
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            if os.getenv("SMTP_TLS", "true").lower() in ("true", "1"):
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, recipients, msg.as_string())
        logger.info("Scheduled report sent to %s", recipients)
    except Exception as e:
        logger.error("Failed to send scheduled report: %s", e)


# ── Report generators ─────────────────────────────────────────────────────────

def _build_overview_html():
    """Fetch live data and render a compact HTML overview report."""
    try:
        from watchtower_client import get_recent_alerts, get_agents_summary, get_alerts_by_severity
        alerts_res  = get_recent_alerts(20)
        agents_res  = get_agents_summary()
        sev_res     = get_alerts_by_severity()

        total_alerts = (alerts_res.get("hits") or {}).get("total", {}).get("value", 0)
        agents_info  = agents_res or {}
        total_agents = agents_info.get("total", 0)
        active       = agents_info.get("active", 0)

        sev_buckets = (sev_res.get("aggregations") or {}).get("by_severity", {}).get("buckets", [])
        sev_rows = "".join(
            f"<tr><td>{b.get('key','—')}</td><td>{b.get('doc_count',0)}</td></tr>"
            for b in sev_buckets
        )

        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        return f"""
<html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:24px">
<h2 style="color:#58a6ff">🛡 Sentinel SIEM — Daily Overview Report</h2>
<p style="color:#8b949e">Generated: {now}</p>
<table style="border-collapse:collapse;margin:16px 0">
  <tr><td style="padding:8px 16px 8px 0;color:#8b949e">Total Agents</td><td style="font-size:20px;font-weight:bold">{total_agents}</td></tr>
  <tr><td style="padding:8px 16px 8px 0;color:#8b949e">Active Agents</td><td style="font-size:20px;font-weight:bold;color:#3fb950">{active}</td></tr>
  <tr><td style="padding:8px 16px 8px 0;color:#8b949e">Alerts (last 24h)</td><td style="font-size:20px;font-weight:bold;color:#f85149">{total_alerts}</td></tr>
</table>
<h3 style="color:#58a6ff">Alert Severity Breakdown</h3>
<table style="border-collapse:collapse;min-width:200px">
  <tr style="background:#161b22"><th style="padding:8px 16px;text-align:left">Severity</th><th style="padding:8px 16px;text-align:left">Count</th></tr>
  {sev_rows}
</table>
<p style="margin-top:24px;color:#8b949e;font-size:12px">
  View full dashboard at your Sentinel SIEM URL.
</p>
</body></html>"""
    except Exception as e:
        return f"<html><body><p>Report generation failed: {e}</p></body></html>"


REPORT_BUILDERS = {
    "overview":     _build_overview_html,
    "daily":        _build_overview_html,
}


# ── Job executor ──────────────────────────────────────────────────────────────

def _run_report_job(schedule_id: str):
    schedules = _load_schedules()
    sched = next((s for s in schedules if s["id"] == schedule_id), None)
    if not sched:
        return

    report_type = sched.get("report_type", "overview")
    builder     = REPORT_BUILDERS.get(report_type, _build_overview_html)
    html        = builder()
    subject     = f"[Sentinel SIEM] {sched.get('name', 'Scheduled Report')} — {datetime.utcnow().strftime('%Y-%m-%d')}"
    recipients  = sched.get("recipients", [])

    _send_report_email(recipients, subject, html)

    # Update last_run timestamp
    for s in schedules:
        if s["id"] == schedule_id:
            s["last_run"] = datetime.utcnow().isoformat()
    _save_schedules(schedules)


# ── Public API ────────────────────────────────────────────────────────────────

def list_schedules():
    return _load_schedules()


def get_schedule(schedule_id: str):
    return next((s for s in _load_schedules() if s["id"] == schedule_id), None)


def create_schedule(name: str, report_type: str, frequency: str,
                    recipients: list, hour: int = 8, minute: int = 0,
                    day_of_week: str = "mon") -> dict:
    """
    frequency: "daily" | "weekly" | "monthly"
    day_of_week: mon, tue, wed, thu, fri, sat, sun (for weekly)
    hour/minute: UTC time to send
    """
    import uuid as _uuid
    schedule_id = str(_uuid.uuid4())[:8]
    sched = {
        "id":          schedule_id,
        "name":        name,
        "report_type": report_type,
        "frequency":   frequency,
        "recipients":  recipients,
        "hour":        hour,
        "minute":      minute,
        "day_of_week": day_of_week,
        "enabled":     True,
        "created_at":  datetime.utcnow().isoformat(),
        "last_run":    None,
    }

    with _lock:
        schedules = _load_schedules()
        schedules.append(sched)
        _save_schedules(schedules)
        _register_job(sched)

    return sched


def delete_schedule(schedule_id: str) -> bool:
    with _lock:
        schedules = _load_schedules()
        new = [s for s in schedules if s["id"] != schedule_id]
        if len(new) == len(schedules):
            return False
        _save_schedules(new)
        try:
            _scheduler.remove_job(f"report_{schedule_id}")
        except Exception:
            pass
    return True


def run_now(schedule_id: str):
    """Trigger a scheduled report immediately (for testing)."""
    threading.Thread(target=_run_report_job, args=(schedule_id,), daemon=True).start()


# ── Scheduler lifecycle ───────────────────────────────────────────────────────

def _register_job(sched: dict):
    job_id = f"report_{sched['id']}"
    try:
        _scheduler.remove_job(job_id)
    except Exception:
        pass

    freq = sched.get("frequency", "daily")
    h    = sched.get("hour", 8)
    m    = sched.get("minute", 0)
    dow  = sched.get("day_of_week", "mon")

    if freq == "daily":
        trigger = CronTrigger(hour=h, minute=m)
    elif freq == "weekly":
        trigger = CronTrigger(day_of_week=dow, hour=h, minute=m)
    elif freq == "monthly":
        trigger = CronTrigger(day=1, hour=h, minute=m)
    else:
        trigger = CronTrigger(hour=h, minute=m)

    _scheduler.add_job(
        _run_report_job,
        trigger=trigger,
        id=job_id,
        args=[sched["id"]],
        replace_existing=True,
    )


def init_scheduler():
    """Call once at app startup to restore all saved schedules and start the scheduler."""
    for sched in _load_schedules():
        if sched.get("enabled", True):
            try:
                _register_job(sched)
            except Exception as e:
                logger.warning("Failed to register schedule %s: %s", sched["id"], e)

    _scheduler.start()
    logger.info("Report scheduler started with %d job(s)", len(_scheduler.get_jobs()))
