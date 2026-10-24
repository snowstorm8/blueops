"""Builders for synthetic audit reports used by the baseline-diff tests (no real host data)."""

from __future__ import annotations

import copy
from typing import Any

from shared.reporting.contracts import INVENTORY_DOMAINS

LATER = {"run": "run-2", "start": "2026-01-02T10:00:00Z", "end": "2026-01-02T10:05:00Z"}


def rec(  # noqa: PLR0913, PLR0917 - mirrors the record shape
    domain: str,
    key: str,
    attrs: dict[str, Any] | None = None,
    volatile: dict[str, Any] | None = None,
    evidence: list[tuple[str, str]] | None = None,
    scope: str = "",
) -> dict[str, Any]:
    out: dict[str, Any] = {"domain": domain, "key": key, "attrs": attrs or {}}
    if scope:
        out["scope"] = scope
    if volatile:
        out["volatile"] = volatile
    if evidence:
        out["evidence"] = [{"type": t, "ref": r} for t, r in evidence]
    return out


def cov(domain: str, status: str = "complete", reason: str = "", scope: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {"domain": domain, "status": status}
    if scope:
        out["scope"] = scope
    if reason:
        out["reason"] = reason
    return out


def finding(
    fid: str,
    severity: str = "medium",
    evidence: list[tuple[str, str]] | None = None,
    description: str = "synthetic",
) -> dict[str, Any]:
    f: dict[str, Any] = {
        "id": fid,
        "title": f"Finding {fid}",
        "severity": severity,
        "category": "test",
        "description": description,
    }
    if evidence:
        f["evidence"] = [{"type": t, "ref": r} for t, r in evidence]
    return f


def report(  # noqa: PLR0913 - a flat builder keeps the tests readable
    records: list[dict[str, Any]] | None = None,
    *,
    coverage: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    errors: list[dict[str, Any]] | None = None,
    host: str = "web01",
    family: str = "linux",
    run: str = "run-1",
    start: str = "2026-01-01T10:00:00Z",
    end: str = "2026-01-01T10:05:00Z",
    elevated: bool = True,
    inventory: bool = True,
    version: str = "0.2.0",
) -> dict[str, Any]:
    recs = records or []
    out: dict[str, Any] = {
        "schema_version": version,
        "tool": {"name": "synthetic-audit", "version": "0.0.0", "category": "audit"},
        "run": {
            "id": run,
            "started_at": start,
            "finished_at": end,
            "mode": "read-only",
            "dry_run": False,
            "exit_code": 0,
        },
        "host": {
            "hostname": host,
            "os": {"family": family, "name": "Synthetic", "version": "1"},
            "arch": "x86_64",
            "elevated": elevated,
        },
        "findings": findings or [],
        "errors": errors or [],
        "summary": {
            "total": len(findings or []),
            "by_severity": {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0},
        },
    }
    if inventory:
        if coverage is None:
            seen = sorted(
                {
                    (r["domain"], r.get("scope", ""))
                    for r in recs
                    if r["domain"] in INVENTORY_DOMAINS
                },
                key=lambda k: (INVENTORY_DOMAINS.index(k[0]), k[1]),
            )
            coverage = [cov(d, scope=sc) for d, sc in seen]
        out["inventory"] = {"coverage": coverage, "records": copy.deepcopy(recs)}
    return out


def pair(
    base_records: list[dict[str, Any]],
    cur_records: list[dict[str, Any]],
    **kw: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """A baseline and a later current report for the same host."""
    base = report(base_records, **kw)
    return base, report(cur_records, **{**kw, **LATER})


def standard_baseline() -> list[dict[str, Any]]:
    """A small, realistic Linux host used by the golden tests."""
    return [
        rec("users", "user:root", {"uid": "0", "shell": "/bin/bash", "home": "/root"}),
        rec("users", "user:alice", {"uid": "1000", "shell": "/bin/bash", "home": "/home/alice"}),
        rec(
            "users", "user:bob", {"uid": "1001", "shell": "/usr/sbin/nologin", "home": "/home/bob"}
        ),
        rec("groups", "group:sudo", {"gid": "27", "members": ["alice"]}),
        rec("services", "service:ssh.service", {"enabled": "enabled", "active": "running"}),
        rec("services", "service:nginx.service", {"enabled": "enabled", "active": "running"}),
        rec(
            "processes",
            "process:root:sshd",
            {"user": "root", "comm": "sshd", "exe": "/usr/sbin/sshd"},
            {"pid": "812"},
        ),
        rec(
            "listeners",
            "listener:tcp/0.0.0.0/22",
            {"proto": "tcp", "bind": "0.0.0.0", "port": "22", "process": "sshd"},
            {"pid": "812"},
        ),
        rec(
            "listeners",
            "listener:tcp/0.0.0.0/80",
            {"proto": "tcp", "bind": "0.0.0.0", "port": "80", "process": "nginx"},
        ),
        rec(
            "scheduled_tasks",
            "cron:/etc/cron.d/backup",
            {"schedule": "0 2 * * *", "user": "root", "command": "/usr/local/bin/backup.sh"},
            evidence=[("file", "/etc/cron.d/backup")],
        ),
        rec(
            "persistence",
            "persist:file:/etc/rc.local",
            {"sha256": "a" * 64, "mode": "755"},
            evidence=[("file", "/etc/rc.local")],
        ),
        rec("config", "config:sysctl:net.ipv4.ip_forward", {"value": "0"}),
    ]
