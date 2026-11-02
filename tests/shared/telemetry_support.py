"""Synthetic telemetry builders shared by the telemetry tests. Nothing here touches a host."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT_FOR_REPO = Path(__file__).resolve().parents[2]
STARTED = "2026-03-01T10:00:00Z"
ENDED = "2026-03-01T10:05:00Z"


def rec(
    category: str,
    key: str,
    attrs: dict[str, Any],
    *,
    event_time: str | None = None,
    scope: str = "",
    unknown: tuple[str, ...] = (),
    source: tuple[str, str] = ("file", "/synthetic"),
    observed_at: str = STARTED,
    **extra: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "record", "category": category, "key": key, "attributes": attrs,
        "observed_at": observed_at, "source": {"type": source[0], "ref": source[1]},
        "method": "synthetic", "unknown_attributes": list(unknown),
    }  # fmt: skip
    if event_time:
        out["event_time"] = event_time
    if scope:
        out["scope"] = scope
    out.update(extra)
    return out


def proc(
    pid: int, ppid: int, name: str, *, exe: str = "", user: str = "root", cmdline: str = ""
) -> dict[str, Any]:
    return rec(
        "process", f"pid:{pid}:100",
        {"pid": pid, "ppid": ppid, "name": name, "exe": exe or f"/usr/bin/{name}", "user": user, "cmdline": cmdline or name},
        source=("proc", f"/proc/{pid}"),
    )  # fmt: skip


def auth(
    when: str | None, action: str, result: str, user: str, src: str = "", key: str = ""
) -> dict[str, Any]:
    return rec(
        "auth_event", key or f"{when}|{action}|{user}|{src}",
        {"action": action, "result": result, "user": user, "source_address": src or None, "service": "sshd"},
        event_time=when, source=("file", "/var/log/auth.log"),
    )  # fmt: skip


def coverage(
    categories: list[str], status: str = "complete", reason: str = ""
) -> list[dict[str, Any]]:
    return [
        {
            "type": "coverage",
            "category": c,
            "status": status,
            **({"reason": reason} if reason else {}),
        }
        for c in categories
    ]


ALL_CATEGORIES = [
    "process", "user", "group", "session", "service", "scheduled_task", "network_connection",
    "listener", "auth_event", "security_event", "config_change", "system_config", "integrity",
    "persistence",
]  # fmt: skip


def stream(
    records: list[dict[str, Any]],
    cov: list[dict[str, Any]] | None = None,
    *,
    host: str = "host01",
    family: str = "linux",
    end: bool = True,
    started: str = STARTED,
    ended: str = ENDED,
    cid: str = "tel-synthetic",
    errors: list[dict[str, Any]] | None = None,
    count: int | None = None,
) -> bytes:
    lines: list[dict[str, Any]] = [
        {
            "type": "header", "schema_version": "1.0.0", "collector": {"name": "synthetic", "version": "1.0.0"},
            "host": {"hostname": host, "os": {"family": family, "name": "Synthetic", "version": "1"}, "arch": "x86_64"},
            "collection": {"id": cid, "started_at": started, "elevated": True},
        }
    ]  # fmt: skip
    lines += cov if cov is not None else coverage(sorted({r["category"] for r in records}))
    lines += records
    lines += errors or []
    if end:
        lines.append(
            {"type": "end", "ended_at": ended, "records": len(records) if count is None else count}
        )
    return ("\n".join(json.dumps(x) for x in lines) + "\n").encode()
