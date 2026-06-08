"""
AI Alert Summarizer for Sentinel SIEM.
Uses the Anthropic Claude API to generate:
  - Executive summary (2-3 plain-English sentences)
  - Technical analysis (what happened technically)
  - Recommended actions (what the analyst should do)
  - MITRE ATT&CK context

Config: set ANTHROPIC_API_KEY environment variable.
Model: claude-haiku-4-5 (fast, cost-effective for high-volume alert triage).
"""
import json
import logging
import os
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

# Simple file-based cache so the same alert isn't summarized twice.
_CACHE_FILE = os.getenv("AI_SUMMARY_CACHE", "/tmp/sentinel_ai_summaries.json")
_lock = threading.Lock()
_cache: dict = {}


def _load_cache():
    global _cache
    try:
        with open(_CACHE_FILE) as f:
            _cache = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        _cache = {}


def _save_cache():
    Path(_CACHE_FILE).parent.mkdir(parents=True, exist_ok=True)
    with open(_CACHE_FILE, "w") as f:
        json.dump(_cache, f, indent=2)


_load_cache()


def is_configured() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def get_cached_summary(alert_id: str) -> dict | None:
    with _lock:
        return _cache.get(str(alert_id))


def _cache_summary(alert_id: str, summary: dict):
    with _lock:
        _cache[str(alert_id)] = summary
        _save_cache()


def summarize_alert(alert: dict, related_alerts: list = None) -> dict:
    """
    Generate an AI summary for a single alert.

    alert dict expected keys:
        id, rule_id, rule_level, title, description, agent_id,
        timestamp, event_data (JSON string), rule_groups (list)

    Returns dict with keys:
        executive_summary, technical_analysis, recommended_actions,
        mitre_context, severity_explanation, model, cached
    """
    alert_id = str(alert.get("id", "unknown"))

    # Return cached result if available.
    cached = get_cached_summary(alert_id)
    if cached:
        cached["cached"] = True
        return cached

    if not is_configured():
        return _fallback_summary(alert)

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        # Build context from event_data.
        event_data = {}
        raw_event = alert.get("event_data", "{}")
        if isinstance(raw_event, str):
            try:
                event_data = json.loads(raw_event)
            except json.JSONDecodeError:
                event_data = {"raw": raw_event[:500]}
        elif isinstance(raw_event, dict):
            event_data = raw_event

        # Truncate event_data to avoid huge prompts.
        event_summary = json.dumps(event_data, indent=2)[:1500]

        # Related alerts context.
        related_ctx = ""
        if related_alerts:
            related_ctx = "\n\nRecent related alerts on same agent:\n" + "\n".join(
                f"- [{r.get('rule_level', '?')}] {r.get('title', 'Unknown')}"
                for r in (related_alerts or [])[:5]
            )

        prompt = f"""You are a senior SOC analyst at a Security Operations Center. Analyze this security alert and provide a structured assessment.

ALERT DETAILS:
- Title: {alert.get('title', 'Unknown')}
- Severity Level: {alert.get('rule_level', 0)}/15
- Rule Groups: {', '.join(alert.get('rule_groups') or [])}
- Agent/Host: {alert.get('agent_id', 'Unknown')}
- Description: {alert.get('description', 'No description')}
- Event Data:
{event_summary}{related_ctx}

Provide your analysis in the following JSON format (respond with ONLY the JSON, no markdown):
{{
  "executive_summary": "2-3 plain English sentences suitable for a manager. What happened, why it matters.",
  "technical_analysis": "2-4 sentences for the SOC analyst. Technical details of the attack vector, what systems are affected, and indicators of compromise.",
  "recommended_actions": ["Action 1: specific step", "Action 2: specific step", "Action 3: specific step"],
  "mitre_context": "Explain which MITRE ATT&CK tactic/technique this maps to and why it matters in the kill chain.",
  "severity_explanation": "Why this alert has severity level {alert.get('rule_level', 0)}/15 and whether it should be escalated.",
  "false_positive_likelihood": "low|medium|high",
  "false_positive_reason": "Brief reason for the likelihood assessment."
}}"""

        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )

        text = response.content[0].text.strip()
        # Strip markdown code blocks if present.
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        text = text.strip().rstrip("```").strip()

        result = json.loads(text)
        result["model"]  = "claude-haiku-4-5"
        result["cached"] = False

        _cache_summary(alert_id, result)
        return result

    except Exception as e:
        logger.error("AI summarizer error: %s", e)
        return _fallback_summary(alert, error=str(e))


def _fallback_summary(alert: dict, error: str = None) -> dict:
    """Rule-based fallback when API is unavailable."""
    level = int(alert.get("rule_level", 0))
    title = alert.get("title", "Security Alert")

    if level >= 13:
        severity_text = "CRITICAL severity — immediate escalation required."
        fp_likelihood = "low"
    elif level >= 10:
        severity_text = "HIGH severity — investigate within 15 minutes."
        fp_likelihood = "low"
    elif level >= 6:
        severity_text = "MEDIUM severity — investigate within 1 hour."
        fp_likelihood = "medium"
    else:
        severity_text = "LOW severity — investigate during business hours."
        fp_likelihood = "medium"

    return {
        "executive_summary": (
            f"Security alert '{title}' detected on host {alert.get('agent_id', 'unknown')}. "
            f"{severity_text} "
            "Review the event details and take appropriate action per your incident response playbook."
        ),
        "technical_analysis": (
            f"Alert triggered by rule level {level}/15. "
            f"Event source: {alert.get('agent_id', 'unknown')}. "
            "Detailed technical analysis requires AI API configuration — set ANTHROPIC_API_KEY."
        ),
        "recommended_actions": [
            "Review the full alert details and event data below.",
            "Check if other alerts exist for the same host in the last 24 hours.",
            "Escalate per severity level if warranted by your IR policy.",
        ],
        "mitre_context": "MITRE ATT&CK mapping available in alert rule groups. Configure ANTHROPIC_API_KEY for detailed context.",
        "severity_explanation": severity_text,
        "false_positive_likelihood": fp_likelihood,
        "false_positive_reason": "Rule-based assessment — configure AI API for accurate analysis.",
        "model": "fallback",
        "cached": False,
        "error": error,
    }


def batch_summarize_critical(alerts: list) -> dict:
    """
    Auto-summarize a list of critical alerts (level >= 10).
    Returns dict: alert_id → summary.
    """
    results = {}
    for alert in alerts:
        if int(alert.get("rule_level", 0)) >= 10:
            alert_id = str(alert.get("id", ""))
            if alert_id and not get_cached_summary(alert_id):
                results[alert_id] = summarize_alert(alert)
    return results
