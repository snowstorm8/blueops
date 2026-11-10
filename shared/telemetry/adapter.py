"""Assessment -> telemetry: the existing inventory becomes telemetry records.

The assessment engine already collects state (processes, users, services, listeners, tasks,
persistence, configuration). This adapter re-expresses that inventory in the telemetry model so
that one hunting layer covers both sources and nothing is collected twice. Event-like categories
(authentication, security events) are not in the inventory; they come only from the telemetry
collectors.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from shared.engine.loader import LoadError, load_assessment
from shared.engine.provenance import entries
from shared.findings.model import clean
from shared.telemetry.ingest import IngestError, RawInput

_NAME = re.compile(r"[^a-z0-9_]+")
_DOMAIN_CATEGORY = {
    "processes": "process", "users": "user", "groups": "group", "services": "service",
    "listeners": "listener", "scheduled_tasks": "scheduled_task", "persistence": "persistence",
    "config": "system_config",
}  # fmt: skip
COLLECTOR = {"name": "assessment-adapter", "version": "1.0.0"}


def _attr_name(name: str) -> str:
    n = _NAME.sub("_", str(name).lower()).strip("_")
    return n if n and n[0].isalpha() else f"a_{n}"[:64]


def _flat(attrs: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in attrs.items():
        name = _attr_name(k)[:64]
        if isinstance(v, (list, tuple)):
            out[name] = [
                x if isinstance(x, (str, int, float, bool)) or x is None else str(x) for x in v
            ][:200]
        elif isinstance(v, (str, int, float, bool)) or v is None:
            out[name] = v
        else:
            out[name] = str(v)
    return out


def _strip(key: str, prefix: str) -> str:
    return key[len(prefix) :] if key.startswith(prefix) else key


def _record(r: dict[str, Any]) -> list[dict[str, Any]]:  # noqa: PLR0912 - one branch per domain
    domain, scope, key = r["domain"], r.get("scope", ""), r["key"]
    category = _DOMAIN_CATEGORY.get(domain)
    if category is None:
        return []
    attrs = _flat(r.get("attrs", {}))
    vol = _flat(r.get("volatile", {}))
    unknown: list[str] = []
    ev = [e.get("ref", "") for e in r.get("evidence", []) if isinstance(e, dict)]
    out: dict[str, Any] = {
        "category": category,
        "key": f"{domain}:{scope}:{key}" if scope else f"{domain}:{key}",
        "scope": scope,
        "source": {"type": "assessment", "ref": ev[0] if ev else key},
        "method": "assessment-inventory",
    }
    if category == "process":
        attrs = {
            "name": attrs.pop("comm", None) or key.rsplit(":", 1)[-1],
            "pid": vol.get("pid"),
            "ppid": vol.get("ppid"),
            "cmdline": vol.get("cmdline"),
            **attrs,
        }
        unknown += [n for n in ("pid", "ppid") if attrs.get(n) is None]
    elif category == "user":
        attrs = {
            "name": _strip(key, "user:"),
            "password_state": attrs.pop("password", None),
            **attrs,
        }
    elif category == "group":
        attrs = {"name": _strip(key, "group:"), **attrs}
    elif category == "service":
        attrs = {
            "name": _strip(key, "service:"),
            "state": attrs.pop("active", None),
            "start_mode": attrs.pop("enabled", None),
            **attrs,
        }
    elif category == "listener":
        attrs = {
            "protocol": attrs.pop("proto", None),
            "local_address": attrs.pop("bind", None),
            "local_port": _port(attrs.pop("port", None)),
            **attrs,
        }
    elif category == "scheduled_task":
        attrs = {"name": key, "command": attrs.pop("entry", None), **attrs}
    elif category == "persistence":
        attrs = {"mechanism": scope or "unknown", "location": attrs.get("file") or key, **attrs}
    else:  # system_config
        attrs = {"setting": key, **attrs}
    out["attributes"] = attrs
    out["unknown_attributes"] = unknown
    results = [out]
    if "sha256" in attrs and isinstance(attrs["sha256"], str):
        path = str(attrs.get("file") or (key.split(":", 2)[-1] if key.count(":") >= 2 else key))
        results.append(
            {
                "category": "integrity", "key": f"integrity:{path}", "scope": scope,
                "source": {"type": "assessment", "ref": ev[0] if ev else key}, "method": "assessment-inventory",
                "attributes": {"path": path, "sha256": attrs["sha256"], "mode": attrs.get("mode")}, "unknown_attributes": [],
            }
        )  # fmt: skip
    return results


def _port(v: Any) -> Any:
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


def _coverage(c: dict[str, Any]) -> dict[str, Any] | None:
    category = _DOMAIN_CATEGORY.get(c["domain"])
    if category is None:
        return None
    status = {"degraded": "partial"}.get(c["status"], c["status"])
    out = {"type": "coverage", "category": category, "status": status, "scope": c.get("scope", "")}
    if c.get("reason"):
        out["reason"] = c["reason"]
    elif c["status"] == "degraded":
        out["reason"] = "all records collected, some attributes unknown"
    return out


def raw_from_assessment(path: Path, data: bytes, verify: bool = True) -> RawInput:
    try:
        doc = load_assessment(path, verify=verify)
    except LoadError as exc:
        raise IngestError(str(exc)) from None
    raw = raw_from_assessment_doc(
        doc, name=path.name, sha256=hashlib.sha256(data).hexdigest(), size=len(data)
    )
    raw.provenance = entries("assessment", doc, source=str(path))
    return raw


def raw_from_assessment_doc(
    doc: dict[str, Any], *, name: str = "assessment", sha256: str = "", size: int = 0
) -> RawInput:
    a, h = doc["assessment"], doc["host"]
    raw = RawInput(
        name=name,
        fmt="assessment",
        sha256=sha256 or hashlib.sha256(repr(a["id"]).encode()).hexdigest(),
        size=size,
    )
    raw.collector = dict(COLLECTOR)
    raw.header = {
        "host": {
            "hostname": h["hostname"],
            "os": h["os"],
            **({"arch": h["arch"]} if h.get("arch") else {}),
        },
        "collection": {
            "id": a["id"],
            "started_at": a["started_at"],
            "ended_at": a["finished_at"],
            "elevated": h.get("elevated"),
        },
        "_ended_at": a["finished_at"],
    }
    unmapped: set[str] = set()
    for i, r in enumerate(doc["inventory"]["records"]):
        recs = _record(r)
        if not recs:
            unmapped.add(r["domain"])
        for rec in recs:
            rec["observed_at"] = a["finished_at"]
            raw.records.append((f"{name}#inventory[{i}]", dict(rec, type="record")))
    for c in doc["inventory"]["coverage"]:
        cov = _coverage(c)
        if cov:
            raw.coverage.append(cov)
        else:
            unmapped.add(c["domain"])
    if any(r["category"] == "integrity" for _o, r in raw.records):
        # Integrity observations are by-products of configuration and persistence records.
        src = [
            c["status"] for c in raw.coverage if c["category"] in ("system_config", "persistence")
        ]
        order = ("complete", "partial", "unavailable")
        worst = max(src, key=lambda s: order.index(s) if s in order else 0, default="partial")
        raw.coverage.append(
            {
                "type": "coverage",
                "category": "integrity",
                "status": worst,
                "reason": "derived from configuration and persistence inventory",
            }
        )
    for dom in sorted(unmapped):
        raw.errors.append(
            {
                "code": "UNMAPPED_DOMAIN",
                "message": clean(
                    f"assessment inventory domain {dom!r} has no telemetry category; not imported",
                    300,
                ),
            }
        )
    return raw
