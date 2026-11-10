"""Telemetry snapshot comparison, coverage-aware.

Rules that keep the result honest:

* A removal or attribute change is claimed only for a category collected ``complete`` in both
  snapshots. Otherwise the category is listed under ``indeterminate`` and only additions (which
  cannot be an artifact of missing data) are reported.
* Event categories are logs: new events are reported; events missing from the later snapshot are
  not "removed" (different collection windows legitimately show different events).
* Records are matched by ``identity`` (what makes two observations the same thing across
  snapshots), not by ``record_id`` of the volatile key.
"""

from __future__ import annotations

from typing import Any

from shared.reporting.schema_lite import validate
from shared.telemetry.model import EVENT_CATEGORIES, TELEMETRY_SCHEMA_VERSION, utc_now

IGNORED_ATTRS = ("pid", "ppid", "start_time", "age_seconds", "inode", "cmdline_hash")  # volatile


class CompareError(ValueError):
    """The two documents cannot be compared (different hosts, wrong kind)."""


def _status(doc: dict[str, Any], category: str) -> tuple[str, str]:
    """Worst coverage status of a category (a missing entry is 'unavailable')."""
    rank = {"complete": 0, "not_applicable": 0, "partial": 1, "unavailable": 2}
    entries = [c for c in doc["coverage"] if c["category"] == category]
    if not entries:
        return "unavailable", "no coverage declared"
    worst = max(entries, key=lambda c: rank[c["status"]])
    return worst["status"], worst.get("reason", "")


def _label(rec: dict[str, Any]) -> str:
    a = rec["attributes"]
    for k in ("name", "setting", "path", "location", "event_id", "user", "object"):
        if a.get(k):
            return f"{rec['category']} {a[k]}"
    return f"{rec['category']} {rec['key']}"


def _index(doc: dict[str, Any], category: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in doc["records"]:
        if r["category"] == category:
            out.setdefault(r["identity"], r)
    return out


def compare_telemetry(
    base: dict[str, Any], cur: dict[str, Any], *, generated_at: str | None = None
) -> dict[str, Any]:
    if base["host"]["host_id"] != cur["host"]["host_id"]:
        raise CompareError("the snapshots describe different hosts")
    cats = sorted(
        {r["category"] for r in base["records"]} | {r["category"] for r in cur["records"]}
    )
    out: dict[str, Any] = {}
    indeterminate: list[dict[str, str]] = []
    totals = {"added": 0, "removed": 0, "changed": 0}
    for cat in cats:
        b, c = _index(base, cat), _index(cur, cat)
        events = cat in EVENT_CATEGORIES
        sb, rb = _status(base, cat)
        sc, rc = _status(cur, cat)
        ok = events or (sb == "complete" and sc == "complete")
        if not ok:
            why = []
            if sb != "complete":
                why.append(f"baseline {sb}" + (f" ({rb})" if rb else ""))
            if sc != "complete":
                why.append(f"current {sc}" + (f" ({rc})" if rc else ""))
            indeterminate.append({"category": cat, "reason": "; ".join(why)})
        added = [
            {"identity": i, "record_id": c[i]["record_id"], "summary": _label(c[i])}
            for i in sorted(set(c) - set(b))
        ]
        removed, changed = [], []
        if ok and not events:
            removed = [
                {"identity": i, "record_id": b[i]["record_id"], "summary": _label(b[i])}
                for i in sorted(set(b) - set(c))
            ]
        if not events:
            for i in sorted(set(b) & set(c)):
                if not (ok):
                    break
                ba, ca = b[i]["attributes"], c[i]["attributes"]
                diffs = [
                    {"name": n, "before": ba.get(n), "after": ca.get(n)}
                    for n in sorted(set(ba) | set(ca))
                    if n not in IGNORED_ATTRS and ba.get(n) != ca.get(n)
                    and n not in b[i]["unknown_attributes"] and n not in c[i]["unknown_attributes"]
                ]  # fmt: skip
                if diffs:
                    changed.append(
                        {"identity": i, "record_id": c[i]["record_id"], "attributes": diffs[:50]}
                    )
        if added or removed or changed or not ok:
            out[cat] = {"determinate": ok, "added": added, "removed": removed, "changed": changed}
        totals["added"] += len(added)
        totals["removed"] += len(removed)
        totals["changed"] += len(changed)
    doc = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "kind": "telemetry-comparison",
        "generated_at": generated_at or utc_now(),
        "host": {"host_id": cur["host"]["host_id"], "hostname": cur["host"]["hostname"]},
        "baseline": {
            "id": base["collection"]["id"],
            "started_at": base["collection"]["started_at"],
        },
        "current": {"id": cur["collection"]["id"], "started_at": cur["collection"]["started_at"]},
        "categories": out,
        "indeterminate": indeterminate,
        "summary": {**totals, "indeterminate_categories": len(indeterminate)},
    }
    problems = validate(doc, "telemetry-comparison.schema.json", limit=5)
    if problems:
        raise CompareError("internal error: comparison violates its schema: " + "; ".join(problems))
    return doc
