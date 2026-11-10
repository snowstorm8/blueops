"""Detections across several snapshots (oldest to newest), without a database.

Each snapshot is evaluated with the snapshots before it as history, so history-aware rules see
exactly what an analyst would have seen at that time. A detection is only *resolved* when its
rule was actually evaluated in the later snapshot; if the rule was indeterminate there the state
is ``unverified`` (never "gone").
"""

from __future__ import annotations

from typing import Any

from shared.findings.model import host_id
from shared.rules import RULES_ENGINE_NAME, RULES_ENGINE_VERSION, RULES_SCHEMA_VERSION
from shared.rules.engine import detect
from shared.rules.history import Snap
from shared.rules.loader import RuleSet


class TimelineError(ValueError):
    """The snapshots cannot be placed on one timeline."""


def _brief(d: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": d["id"],
        "rule_id": d["rule"]["id"],
        "title": d["title"],
        "severity": d["severity"],
        "confidence": d["confidence"],
    }


def compare_detections(snaps: list[Snap], rule_set: RuleSet, generated_at: str) -> dict[str, Any]:  # noqa: PLR0912
    if len(snaps) < 2:
        raise TimelineError("need at least two snapshots")
    snaps = sorted(snaps, key=lambda s: (s.started_at, s.source))
    first = snaps[0].doc["host"]
    for s in snaps[1:]:
        h = s.doc.get("host")
        if (
            not h
            or h["os"]["family"] != first["os"]["family"]
            or h["hostname"].casefold() != first["hostname"].casefold()
        ):
            raise TimelineError(
                f"{s.source} is from a different host or OS family than {snaps[0].source}"
            )
    results = [
        detect(s.doc, rule_set, previous=snaps[:i], generated_at=generated_at)
        for i, s in enumerate(snaps)
    ]
    present = [{d["id"]: d for d in r["detections"]} for r in results]
    unknown = [
        {i["rule"]["id"] for i in r["indeterminate"]} | {e["rule"] for e in r["rule_errors"]}
        for r in results
    ]
    all_ids = sorted({i for p in present for i in p})
    rule_of: dict[str, str] = {i: p[i]["rule"]["id"] for p in present for i in p}
    transitions = []
    for j in range(1, len(snaps)):
        a, b = present[j - 1], present[j]
        new, resolved, persistent, unverified, changed = [], [], [], [], []
        for did in sorted(set(a) | set(b)):
            if did in b and did not in a:
                new.append(_brief(b[did]))
            elif did in a and did in b:
                persistent.append(_brief(b[did]))
                if a[did]["severity"] != b[did]["severity"]:
                    changed.append(
                        {**_brief(b[did]), "from": a[did]["severity"], "to": b[did]["severity"]}
                    )
            elif rule_of[did] in unknown[j]:
                unverified.append(_brief(a[did]))
            else:
                resolved.append(_brief(a[did]))
        transitions.append({
            "from": snaps[j - 1].doc["assessment"]["id"], "to": snaps[j].doc["assessment"]["id"],
            "new": new, "resolved": resolved, "persistent": persistent, "severity_changed": changed, "unverified": unverified,
        })  # fmt: skip
    rows = []
    for did in all_ids:
        seq: list[bool | None] = []
        for j in range(len(snaps)):
            if did in present[j]:
                seq.append(True)
            elif rule_of[did] in unknown[j]:
                seq.append(None)
            else:
                seq.append(False)
        seen_idx = [j for j, v in enumerate(seq) if v]
        last = seq[-1]
        if last is None:
            state = "unverified"
        elif last and len(seen_idx) == 1:
            state = "new"
        elif last and any(v is False for v in seq[seen_idx[0] :]):
            state = "intermittent"
        elif last:
            state = "persistent"
        else:
            state = "resolved"
        latest = present[seen_idx[-1]][did]
        rows.append({
            "id": did, "rule_id": rule_of[did], "title": latest["title"], "severity": latest["severity"],
            "first_seen": snaps[seen_idx[0]].started_at, "last_seen": snaps[seen_idx[-1]].started_at,
            "present": seq, "state": state,
        })  # fmt: skip
    states: dict[str, int] = {}
    for r in rows:
        states[r["state"]] = states.get(r["state"], 0) + 1
    return {
        "schema_version": RULES_SCHEMA_VERSION,
        "kind": "detection-comparison",
        "generated_at": generated_at,
        "engine": {"name": RULES_ENGINE_NAME, "version": RULES_ENGINE_VERSION},
        "host": {"hostname": first["hostname"], "host_id": host_id(first["hostname"], first["os"]["family"]), "os_family": first["os"]["family"]},
        "snapshots": [
            {"id": s.doc["assessment"]["id"], "started_at": s.started_at, "source": s.source, "detections": len(results[i]["detections"]), "indeterminate": len(results[i]["indeterminate"])}
            for i, s in enumerate(snaps)
        ],
        "transitions": transitions,
        "detections": rows,
        "summary": {"detections_total": len(rows), "states": dict(sorted(states.items())), "snapshots": len(snaps)},
    }  # fmt: skip
