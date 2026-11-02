"""Subjects: the flat, typed views of assessment data that rule conditions read.

Each *source* names one kind of subject. ``FIELDS`` is the authoritative catalog of the field
names a condition may use per source; rule validation rejects anything else, so a typo is an
error at load time and not a silently-false condition at run time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from shared.findings.model import clean
from shared.rules.history import HistoryView

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SOURCES = (
    "findings", "inventory", "new_findings", "resolved_findings", "persistent_findings",
    "severity_increased", "config_changes", "snapshot",
)  # fmt: skip
CURRENT_SOURCES = ("findings", "inventory")
COMPARISON_SOURCES = tuple(s for s in SOURCES if s not in CURRENT_SOURCES)

_FINDING_FIELDS = (
    "id", "check_id", "title", "description", "severity", "severity_rank", "confidence",
    "category", "component", "priority", "evidence.refs", "evidence.types", "evidence.excerpts",
    "evidence.count", "evidence.paths", "standards.ids", "sources.modules", "occurrences",
)  # fmt: skip
_HISTORY_FIELDS = (
    "history.snapshots_present", "history.consecutive", "history.known_snapshots",
    "history.first_seen", "history.reappeared",
)  # fmt: skip

FIELDS: dict[str, tuple[str, ...]] = {
    "findings": (*_FINDING_FIELDS, *_HISTORY_FIELDS),
    "new_findings": _FINDING_FIELDS,
    "resolved_findings": _FINDING_FIELDS,
    "persistent_findings": (*_FINDING_FIELDS, "baseline_severity", "baseline_severity_rank",
                            "evidence.added", "evidence.removed", *_HISTORY_FIELDS),
    "severity_increased": (*_FINDING_FIELDS, "baseline_severity", "baseline_severity_rank",
                           "evidence.added", "evidence.removed", *_HISTORY_FIELDS),
    "inventory": ("domain", "scope", "key", "evidence.refs", "evidence.count"),
    "config_changes": ("change", "domain", "scope", "key", "priority", "transient",
                       "attributes.names", "evidence.refs", "history.before_stable_snapshots"),
    "snapshot": (
        "previous.exists", "previous.finding_count", "previous.max_severity_rank",
        "previous.complete", "previous.clean", "new.count", "new.count_ge_medium",
        "new.max_severity_rank", "new.categories", "resolved.count", "severity_increased.count",
        "config.changes", "coverage.module_changes", "coverage.modules_degraded", "coverage.modules_removed", "comparison.complete", "history.snapshots",
    ),
}  # fmt: skip
# Open-ended families: ``attrs.<name>`` and ``attr.<name>.before|after``.
_FAMILIES = {
    "inventory": (re.compile(r"^attrs\.[A-Za-z0-9_.-]+$"),),
    "config_changes": (
        re.compile(r"^attrs\.[A-Za-z0-9_.-]+$"),
        re.compile(r"^attr\.[A-Za-z0-9_.-]+\.(before|after)$"),
    ),
}

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_POSIX_PATH = re.compile(r"(?<![\w:/.-])/(?:[\w.@+-]+/)+[\w.@+-]+")
_WIN_PATH = re.compile(r"[A-Za-z]:\\(?:[^\s\"'<>|*?]+)")


def extract_paths(texts: list[str], limit: int = 50) -> list[str]:
    """File-system paths mentioned in evidence references and excerpts (for joining findings)."""
    out: list[str] = []
    for t in texts:
        for rx in (_POSIX_PATH, _WIN_PATH):
            for m in rx.finditer(t):
                p = m.group(0).rstrip(".,;:)")
                if p not in out:
                    out.append(p)
                if len(out) >= limit:
                    return out
    return out


def field_known(source: str, name: str) -> bool:
    if name in FIELDS.get(source, ()):
        return True
    return any(rx.match(name) for rx in _FAMILIES.get(source, ()))


@dataclass
class Subject:
    """One matchable thing, with the information needed to trace a detection back to it."""

    source: str
    ref: dict[str, str]  # {"type": "finding"|"inventory"|"change"|"snapshot", ...ids}
    label: str  # short human description
    fields: dict[str, Any]
    severity: str = ""
    component: str = ""
    evidence_ids: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def uid(self) -> str:
        return "|".join(f"{k}={v}" for k, v in sorted(self.ref.items()))


def _scalar(v: Any) -> Any:
    if isinstance(v, str):
        return _CONTROL.sub("?", v)[:4096]
    return v


def _value(v: Any) -> Any:
    if isinstance(v, (list, tuple)):
        return [_scalar(x) for x in v][:200]
    return _scalar(v)


def finding_subject(
    source: str,
    f: dict[str, Any],
    evidence: dict[str, dict[str, Any]],
    hist: HistoryView | None = None,
    extra: dict[str, Any] | None = None,
) -> Subject:
    ev = [evidence[e] for e in f.get("evidence", []) if e in evidence]
    fields: dict[str, Any] = {
        "id": f["id"],
        "check_id": f["check_id"],
        "title": _scalar(f["title"]),
        "description": _scalar(f["description"]),
        "severity": f["severity"],
        "severity_rank": SEVERITY_RANK[f["severity"]],
        "confidence": f["confidence"],
        "category": f["category"],
        "component": f["component"],
        "priority": f["remediation"]["priority"],
        "evidence.refs": [_scalar(e["ref"]) for e in ev],
        "evidence.types": sorted({e["type"] for e in ev}),
        "evidence.excerpts": [_scalar(x) for e in ev for x in e.get("excerpts", [])][:200],
        "evidence.count": len(f.get("evidence", [])),
        "evidence.paths": extract_paths(
            [e["ref"] for e in ev] + [x for e in ev for x in e.get("excerpts", [])]
        ),
        "standards.ids": [s["id"] for s in f.get("standards", [])],
        "sources.modules": sorted({s["module"] for s in f.get("sources", [])}),
        "occurrences": f.get("occurrences", 1),
    }
    if extra:
        fields.update(extra)
    if hist is not None and source in ("findings", "persistent_findings", "severity_increased"):
        for k, v in hist.finding_history(f).items():
            fields[f"history.{k}"] = v
    return Subject(
        source=source,
        ref={"type": "finding", "id": f["id"], "check_id": f["check_id"]},
        label=f"{f['check_id']}: {f['title']}",
        fields=fields,
        severity=f["severity"],
        component=f["component"],
        evidence_ids=list(f.get("evidence", [])),
    )


def inventory_subject(rec: dict[str, Any]) -> Subject:
    fields: dict[str, Any] = {
        "domain": rec["domain"],
        "scope": rec.get("scope", ""),
        "key": _scalar(rec["key"]),
        "evidence.refs": [_scalar(e["ref"]) for e in rec.get("evidence", []) if "ref" in e],
        "evidence.count": len(rec.get("evidence", [])),
    }
    for k, v in rec.get("attrs", {}).items():
        fields[f"attrs.{k}"] = _value(v)
    return Subject(
        source="inventory",
        ref={
            "type": "inventory",
            "domain": rec["domain"],
            "scope": rec.get("scope", ""),
            "key": _scalar(rec["key"]),
        },
        label=f"{rec['domain']}/{rec['key']}",
        fields=fields,
        component=rec["domain"],
    )


def change_subject(ch: dict[str, Any], hist: HistoryView | None) -> Subject:
    fields: dict[str, Any] = {
        "change": ch["change"],
        "domain": ch["domain"],
        "scope": ch.get("scope", ""),
        "key": _scalar(ch["key"]),
        "priority": ch.get("priority", ""),
        "transient": bool(ch.get("transient", False)),
        "attributes.names": [a["name"] for a in ch.get("attributes", [])],
        "evidence.refs": [],
    }
    side = ch.get("current") or ch.get("baseline") or {}
    for k, v in (side.get("attrs") or {}).items():
        fields[f"attrs.{k}"] = _value(v)
    for a in ch.get("attributes", []):
        fields[f"attr.{a['name']}.before"] = _value(a.get("before"))
        fields[f"attr.{a['name']}.after"] = _value(a.get("after"))
    for side_name in ("current", "baseline"):
        for e in (ch.get(side_name) or {}).get("evidence", []) or []:
            if isinstance(e, dict) and "ref" in e:
                fields["evidence.refs"].append(_scalar(e["ref"]))
    if hist is not None:
        fields["history.before_stable_snapshots"] = hist.record_stability(
            ch["domain"], ch.get("scope", ""), ch["key"]
        )
    detail = {
        "attributes": [
            {"name": a["name"], "before": _value(a.get("before")), "after": _value(a.get("after"))}
            for a in ch.get("attributes", [])[:8]
        ]
    }
    return Subject(
        source="config_changes",
        ref={
            "type": "change",
            "change": ch["change"],
            "domain": ch["domain"],
            "scope": ch.get("scope", ""),
            "key": _scalar(ch["key"]),
        },
        label=f"{ch['change']} {ch['domain']}/{ch['key']}",
        fields=fields,
        component=ch["domain"],
        detail=detail,
    )


def snapshot_subject(
    comparison: dict[str, Any] | None, hist: HistoryView | None, current: dict[str, Any]
) -> Subject:
    fields: dict[str, Any] = {"history.snapshots": hist.count if hist else 0}
    prev = hist.previous_state() if hist else {"exists": False}
    fields["previous.exists"] = bool(prev.get("exists"))
    for k in ("finding_count", "max_severity_rank", "complete", "clean"):
        if k in prev:
            fields[f"previous.{k}"] = prev[k]
    if comparison is not None:
        f = comparison["findings"]
        new = f["new"]
        fields["new.count"] = len(new)
        fields["new.count_ge_medium"] = sum(1 for x in new if SEVERITY_RANK[x["severity"]] >= 2)
        fields["new.max_severity_rank"] = max(
            (SEVERITY_RANK[x["severity"]] for x in new), default=0
        )
        fields["new.categories"] = sorted({x["category"] for x in new})
        fields["resolved.count"] = len(f["resolved"])
        fields["severity_increased.count"] = comparison["summary"]["severity_increased"]
        fields["config.changes"] = comparison["summary"]["configuration_changes"]
        fields["coverage.module_changes"] = comparison["summary"]["coverage_changes"]
        mods = comparison["coverage"]["modules"]
        fields["coverage.modules_degraded"] = sum(
            1 for m in mods["changed"] if m["baseline"] == "ok" and m["current"] != "ok"
        )
        fields["coverage.modules_removed"] = len(mods["removed"])
        fields["comparison.complete"] = (
            not f["indeterminate"] and not comparison["summary"]["coverage_changes"]
        )
    return Subject(
        source="snapshot",
        ref={"type": "snapshot", "id": current["assessment"]["id"]},
        label=f"snapshot {current['assessment']['started_at']}",
        fields=fields,
        component="snapshot",
    )


def sanitize(text: Any, limit: int = 300) -> str:
    return clean(text, limit)
