"""
system_logs.py — Read recent stdout/stderr lines from the SIEM's own services.

Lets operators triage "is WatchTower OK?" without SSHing. Three resolution
paths, tried in order, so this works in dev (files), containerized prod
(docker socket), and standalone deployments:

    1. SYSTEM_LOG_SOURCES env var — explicit ``name:path`` overrides. Wins
       over everything else.
    2. ``docker logs --tail N <container>`` via subprocess. Requires the
       dashboard container to have the docker CLI + socket mounted. Standard
       for docker-compose deployments.
    3. Built-in fallback paths — Docker's per-container JSON-file logs at
       ``/var/lib/docker/containers/<id>/<id>-json.log``. Rarely accessible
       from inside another container but useful for host-mode runs.

A small registry maps friendly service names → container names. Edit the
mapping if your compose file uses different names.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Iterable

# Friendly name → container name used in docker-compose.full.yaml.
SERVICES = {
    "watchtower":  "watchtower",
    "watchvault":  "watchvault",
    "opensearch":  "opensearch",
    "dashboard":   "sentinel-dashboard",
}

# Parses "name:/path" pairs from SYSTEM_LOG_SOURCES env var.
def _env_sources() -> dict[str, str]:
    raw = os.getenv("SYSTEM_LOG_SOURCES", "").strip()
    if not raw:
        return {}
    out: dict[str, str] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        name, path = part.split(":", 1)
        if name.strip() and path.strip():
            out[name.strip()] = path.strip()
    return out


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


def list_services() -> list[dict]:
    """Return services the UI can read, with the source it'll pull from."""
    env = _env_sources()
    out = []
    for name, container in SERVICES.items():
        if name in env:
            source = f"file:{env[name]}"
        else:
            source = f"docker:{container}"
        out.append({"name": name, "container": container, "source": source})
    return out


def _read_file_tail(path: str, lines: int) -> tuple[list[str], str | None]:
    try:
        with open(path, "rb") as f:
            # Read last ~1 MB which is usually enough for `lines` lines.
            try:
                f.seek(-1024 * 1024, os.SEEK_END)
            except OSError:
                f.seek(0)
            data = f.read().decode("utf-8", errors="replace")
        return data.splitlines()[-lines:], None
    except FileNotFoundError:
        return [], f"file not found: {path}"
    except Exception as e:
        return [], f"file read failed: {e}"


def _read_docker_tail(container: str, lines: int) -> tuple[list[str], str | None]:
    """Shell out to `docker logs --tail N --timestamps <container>`."""
    try:
        cmd = ["docker", "logs", "--tail", str(int(lines)), "--timestamps", container]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            err = proc.stderr.strip().splitlines()[-1] if proc.stderr else "non-zero exit"
            return [], f"docker logs failed: {err}"
        # docker writes container stderr to our stderr and stdout to stdout —
        # merge so the analyst sees both interleaved.
        combined = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        out = [_strip_ansi(l) for l in combined.splitlines()]
        return out[-lines:], None
    except FileNotFoundError:
        return [], "docker CLI not available in this environment"
    except subprocess.TimeoutExpired:
        return [], "docker logs timed out after 10s"
    except Exception as e:
        return [], f"docker logs error: {e}"


def read_logs(service: str, lines: int = 200) -> dict:
    """Return {"service", "source", "lines": [...], "error": ...}."""
    if service not in SERVICES:
        return {"error": f"unknown service '{service}'",
                "valid": list(SERVICES.keys())}
    lines = max(1, min(int(lines), 2000))

    # 1) explicit file path from env
    env_paths = _env_sources()
    if service in env_paths:
        ls, err = _read_file_tail(env_paths[service], lines)
        return {"service": service, "source": f"file:{env_paths[service]}",
                "lines": ls, "error": err}

    # 2) docker logs
    container = SERVICES[service]
    ls, err = _read_docker_tail(container, lines)
    if not err:
        return {"service": service, "source": f"docker:{container}",
                "lines": ls, "error": None}

    # 3) hint to operator
    return {
        "service": service,
        "source": f"docker:{container}",
        "lines": [],
        "error": err,
        "hint": (
            "Set SYSTEM_LOG_SOURCES=watchtower:/var/log/watchtower.log,"
            "watchvault:/var/log/watchvault.log on the dashboard container "
            "to read from log files instead. Or mount /var/run/docker.sock "
            "and install the docker CLI in the dashboard image to use "
            "`docker logs`."
        ),
    }
