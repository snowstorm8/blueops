"""Subjects built from telemetry documents (``telemetry`` and ``telemetry_changes`` sources)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from shared.rules.subjects import Subject, _scalar, _value

_MAX_DEPTH = 16
_DETAIL_ATTRS = 8


class ProcessIndex:
    """Parent/child relationships among the process records of one telemetry document."""

    def __init__(self, records: list[dict[str, Any]]) -> None:
        self.by_pid: dict[Any, dict[str, Any]] = {}
        self.children: dict[Any, int] = {}
        for r in records:
            if r["category"] != "process":
                continue
            pid = r["attributes"].get("pid")
            if pid is not None:
                self.by_pid.setdefault(pid, r)
            ppid = r["attributes"].get("ppid")
            if ppid is not None:
                self.children[ppid] = self.children.get(ppid, 0) + 1

    def chain(self, rec: dict[str, Any]) -> list[dict[str, Any]]:
        """Ancestors, nearest first; stops at an unknown parent, a cycle, or the depth cap."""
        out: list[dict[str, Any]] = []
        seen = {rec["attributes"].get("pid")}
        cur = rec
        for _ in range(_MAX_DEPTH):
            ppid = cur["attributes"].get("ppid")
            parent = self.by_pid.get(ppid) if ppid is not None else None
            pid = parent["attributes"].get("pid") if parent else None
            if parent is None or pid in seen:
                break
            out.append(parent)
            seen.add(pid)
            cur = parent
        return out

    def fields(self, rec: dict[str, Any]) -> dict[str, Any]:
        a = rec["attributes"]
        chain = self.chain(rec)
        ppid = a.get("ppid")
        parent = chain[0] if chain else None
        out: dict[str, Any] = {
            "process.ancestors": [_scalar(c["attributes"].get("name")) for c in chain],
            "process.depth": len(chain),
            "process.children": self.children.get(a.get("pid"), 0),
            # Orphan only when a parent id is known but absent from the snapshot; pid 0/1 roots
            # and records without a ppid are not orphans.
            "process.orphan": ppid not in (None, 0) and parent is None and ppid != a.get("pid"),
        }
        if parent:
            pa = parent["attributes"]
            out["process.parent_name"] = _scalar(pa.get("name"))
            out["process.parent_exe"] = _scalar(pa.get("exe"))
            out["process.parent_user"] = _scalar(pa.get("user"))
        return out


def _label(rec: dict[str, Any]) -> str:
    a = rec["attributes"]
    for k in ("name", "setting", "path", "location", "event_id", "user", "object", "grouping"):
        if a.get(k) not in (None, ""):
            return f"{rec['category']} {_scalar(a[k])}"
    return f"{rec['category']} {rec['key'][:80]}"


def _detail(rec: dict[str, Any]) -> dict[str, Any]:
    attrs = {k: _value(v) for k, v in list(rec["attributes"].items())[:_DETAIL_ATTRS]}
    return {
        "record_id": rec["record_id"],
        "source": f"{rec['source']['type']}:{rec['source']['ref']}"[:300],
        "observed_at": rec["observed_at"],
        **({"event_time": rec["event_time"]} if rec.get("event_time") else {}),
        "attributes": attrs,
        **({"limitations": rec["limitations"][:3]} if rec["limitations"] else {}),
    }


def telemetry_subject(rec: dict[str, Any], index: ProcessIndex) -> Subject:
    f: dict[str, Any] = {
        "record_id": rec["record_id"], "category": rec["category"], "scope": rec.get("scope", ""),
        "key": _scalar(rec["key"]), "identity": _scalar(rec["identity"]), "status": rec["status"],
        "partial": rec["status"] == "partial", "occurrences": rec["occurrences"],
        "observed_at": rec["observed_at"], "event_time": rec.get("event_time", ""),
        "first_seen": rec["first_seen"], "last_seen": rec["last_seen"],
        "source.type": rec["source"]["type"], "source.ref": _scalar(rec["source"]["ref"]),
        "method": rec["method"], "collector": rec["collector"]["name"],
        "limitations": [_scalar(x) for x in rec["limitations"]],
        "unknown_attributes": list(rec["unknown_attributes"]),
        "derived": rec["source"]["type"] == "derived", "os_family": rec["os_family"],
    }  # fmt: skip
    if rec.get("event_time"):
        try:
            dt = datetime.strptime(rec["event_time"][:19], "%Y-%m-%dT%H:%M:%S")
            f["hour_utc"], f["weekday"] = dt.hour, dt.weekday()
        except ValueError:
            pass
    for k, v in rec["attributes"].items():
        f[f"attrs.{k}"] = _value(v)
    if rec["category"] == "process":
        f.update(index.fields(rec))
    return Subject(
        source="telemetry",
        ref={"type": "telemetry", "id": rec["record_id"], "category": rec["category"]},
        label=_label(rec),
        fields=f,
        component=rec["category"],
        detail=_detail(rec),
    )


def telemetry_change_subjects(
    base: dict[str, Any], cur: dict[str, Any], comparison: dict[str, Any]
) -> list[Subject]:
    out: list[Subject] = []
    b_by = {r["record_id"]: r for r in base["records"]}
    c_by = {r["record_id"]: r for r in cur["records"]}
    for cat, block in sorted(comparison["categories"].items()):
        for kind, items in (
            ("added", block["added"]),
            ("removed", block["removed"]),
            ("changed", block["changed"]),
        ):
            for it in items:
                rec = c_by.get(it["record_id"]) if kind != "removed" else b_by.get(it["record_id"])
                if rec is None:
                    continue
                f: dict[str, Any] = {
                    "record_id": rec["record_id"], "change": kind, "category": cat, "identity": _scalar(it["identity"]),
                    "summary": _scalar(it.get("summary") or _label(rec)), "determinate": block["determinate"],
                    "attributes.names": [a["name"] for a in it.get("attributes", [])],
                }  # fmt: skip
                for k, v in rec["attributes"].items():
                    f[f"attrs.{k}"] = _value(v)
                for a in it.get("attributes", []):
                    f[f"attr.{a['name']}.before"] = _value(a.get("before"))
                    f[f"attr.{a['name']}.after"] = _value(a.get("after"))
                out.append(
                    Subject(
                        source="telemetry_changes",
                        ref={
                            "type": "telemetry",
                            "id": rec["record_id"],
                            "category": cat,
                            "change": kind,
                        },
                        label=f"{kind} {_label(rec)}",
                        fields=f,
                        component=cat,
                        detail=_detail(rec),
                    )
                )
    return out
