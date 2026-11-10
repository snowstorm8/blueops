"""Builders for validation-framework tests: scenario dicts, pack files, telemetry record specs."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from shared.rules.loader import RuleSet, load_rule_set

HUNT_RULES = load_rule_set().only(lambda r: any(s.startswith("telemetry") for s in r.sources))


def rs(*ids: str) -> RuleSet:
    """The shipped telemetry rules, restricted to ``ids`` (all of them when empty)."""
    return HUNT_RULES.only(lambda r: not ids or r.id in ids)


def tr(category: str, key: str, attrs: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"category": category, "key": key, "attributes": attrs, **extra}


def proc(
    pid: int,
    ppid: int,
    name: str,
    exe: str | None = None,
    user: str = "root",
    cmd: str | None = None,
) -> dict[str, Any]:
    return tr(
        "process",
        f"pid:{pid}",
        {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "exe": exe or f"/usr/bin/{name}",
            "user": user,
            "cmdline": cmd or name,
        },
    )


def conn(pid: int, remote: str, port: int = 4444, state: str = "established") -> dict[str, Any]:
    return tr(
        "network_connection",
        f"c:{pid}:{remote}",
        {
            "protocol": "tcp",
            "state": state,
            "local_address": "10.0.0.5",
            "local_port": 40000 + pid,
            "remote_address": remote,
            "remote_port": port,
            "pid": pid,
            "process": "bash",
        },
    )


def ev(
    t: str | None, action: str, result: str, user: str, src: str = "", n: int = 0
) -> dict[str, Any]:
    attrs = {
        "action": action,
        "result": result,
        "user": user,
        "source_address": src or None,
        "service": "sshd",
    }
    return tr("auth_event", f"e{n}|{t}|{action}|{user}|{src}", attrs, event_time=t)


SHELL_UNDER_NGINX = [
    proc(100, 1, "nginx", user="www-data"),
    proc(200, 100, "bash", user="www-data"),
]

BASE_SCENARIO: dict[str, Any] = {
    "id": "SCN-LNX-PRC-001",
    "title": "Shell under nginx",
    "description": "A shell is a direct child of a web server.",
    "objective": "HPRC-001 detects it.",
    "kind": "positive",
    "platforms": ["linux"],
    "dataset": {"platform": "linux", "records": SHELL_UNDER_NGINX},
    "expect": {"detections": [{"rule": "DR-ANY-HPRC-001"}]},
    "limitations": ["synthetic"],
}


def scn(**over: Any) -> dict[str, Any]:
    s = copy.deepcopy(BASE_SCENARIO)
    for k, v in over.items():
        if v is None:
            s.pop(k, None)
        else:
            s[k] = v
    return s


def pack(scenarios: list[dict[str, Any]], name: str = "test-pack") -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "kind": "scenario-pack",
        "pack": {"name": name, "version": "1.0.0", "description": "test"},
        "scenarios": scenarios,
    }


def write_pack(tmp: Path, scenarios: list[dict[str, Any]], name: str = "pk") -> Path:
    path = tmp / f"{name}.json"
    path.write_text(json.dumps(pack(scenarios, name=name.replace("_", "-"))), encoding="utf-8")
    return path
