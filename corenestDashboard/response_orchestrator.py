"""
response_orchestrator.py — turn an XDR incident into a cross-domain containment
bundle and (optionally) execute it.

An incident names an *entity* (user/host). Containment means acting on every
asset that entity touches, across domains, using the response actions WatchTower
already ships. This module:

  * bundle_for(incident)  -> the recommended [actions]  (no side effects)
  * execute(actions)      -> fire them via the WatchTower active-response API
  * should_auto_respond(incident) -> tiered policy gate

Tiered policy (plan): critical incidents auto-contain ONLY when the operator
opts in (XDR_AUTO_RESPONSE=true); everything else is recommend + one-click.
Auto-response is OFF by default — the blast radius of isolate/disable is high,
so each client turns it on deliberately. WatchTower enforces its own safelist,
dedup and audit on every action.
"""
from __future__ import annotations

import os
from typing import Any

import entities

_SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _ar(agent_id: str, action: str, parameters: dict | None = None) -> Any:
    """Send one active-response command via the existing WatchTower API."""
    from watchtower_client import watchtower_request
    payload = {"agent_id": agent_id, "action": action, "parameters": parameters or {}}
    return watchtower_request("/api/v1/active-response", method="POST", json_body=payload)


def bundle_for(incident: dict, *, os_search=None) -> list[dict]:
    """Recommended response actions for an incident (does NOT execute).

    Each action: {action, agent_id, parameters, desc}. Only actions with a
    resolvable agent target are returned."""
    detector = incident.get("detector") or ""
    entity = incident.get("entity") or ""
    etype = incident.get("entity_type") or "user"
    evidence = incident.get("evidence") or {}
    reason = f"XDR incident #{incident.get('id')} ({detector})"

    # Resolve the entity to agent IDs a host action can target.
    if etype == "host":
        aid = entities.agent_for_host(entity)
        agents = [aid] if aid else []
    else:
        agents = entities.hosts_for_user(entity, os_search=os_search)

    actions: list[dict] = []

    def isolate_all():
        for aid in agents:
            actions.append({"action": "isolate-host", "agent_id": aid,
                            "parameters": {"reason": reason},
                            "desc": f"Isolate host (agent {aid})"})

    def disable_user():
        for aid in agents:
            actions.append({"action": "disable-account", "agent_id": aid,
                            "parameters": {"username": entity},
                            "desc": f"Disable account {entity}"})

    def block_ips(ips):
        for ip in ips[:10]:
            actions.append({"action": "firewall-drop", "agent_id": (agents[0] if agents else ""),
                            "parameters": {"ip": ip}, "desc": f"Block IP {ip}"})

    if detector == "compromised_identity":
        disable_user(); isolate_all()
    elif detector == "multi_location_logon":   # impossible travel / risky auth
        disable_user()
        block_ips(evidence.get("distinct_ips", []))
    elif detector == "lateral_movement":
        isolate_all()
    elif detector == "data_exfiltration":
        isolate_all()
        block_ips(evidence.get("egress_ips", []))

    # Drop any action we couldn't target (no agent resolved).
    return [a for a in actions if a.get("agent_id")]


def execute(actions: list[dict]) -> list[dict]:
    """Fire each action via the WatchTower AR API; never raises. Returns
    per-action results for the audit trail / UI."""
    results: list[dict] = []
    for a in actions:
        try:
            res = _ar(a["agent_id"], a["action"], a.get("parameters"))
            results.append({**a, "ok": True, "response": res})
        except Exception as e:  # noqa: BLE001 — surface, don't crash the sweep
            results.append({**a, "ok": False, "error": str(e)})
    return results


def should_auto_respond(incident: dict) -> bool:
    """Tiered gate: only auto-contain when the operator opted in AND the
    incident meets the minimum severity (default critical)."""
    if os.getenv("XDR_AUTO_RESPONSE", "false").lower() not in ("true", "1", "yes"):
        return False
    min_sev = os.getenv("XDR_AUTO_RESPONSE_MIN_SEVERITY", "critical").lower()
    return _SEV_RANK.get(incident.get("severity", "low"), 0) >= _SEV_RANK.get(min_sev, 4)
