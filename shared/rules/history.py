"""History of earlier assessments, without a database.

A *history* is just a set of assessments the caller points at: a directory holding assessment
directories / ``assessment.json`` files (or older audit reports), or an explicit list of paths.
Everything is read-only and loaded on demand; nothing is indexed on disk.

Rules never see "absent" when the truth is "unknown": for each earlier snapshot a finding is
``present``, ``absent`` (the module that would have reported it ran cleanly) or ``unknown``
(that module failed, timed out or was not run; same test as the snapshot comparison).
Unknown states stop streak counting instead of being guessed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.engine.loader import LoadError, load_assessment
from shared.reporting.snapshot_compare import finding_coverage

MAX_SNAPSHOTS = 200


class HistoryError(ValueError):
    """The history location is unusable."""


@dataclass
class Snap:
    doc: dict[str, Any]
    source: str
    _records: dict[tuple[str, str, str], dict[str, Any]] | None = field(default=None, repr=False)

    @property
    def started_at(self) -> str:
        return str(self.doc["assessment"]["started_at"])

    def record(self, domain: str, scope: str, key: str) -> dict[str, Any] | None:
        if self._records is None:
            self._records = {
                (r["domain"], r.get("scope", ""), r["key"]): r
                for r in self.doc["inventory"]["records"]
            }
        return self._records.get((domain, scope, key))

    def partition_status(self, domain: str, scope: str) -> str | None:
        for c in self.doc["inventory"]["coverage"]:
            if c["domain"] == domain and c.get("scope", "") == scope:
                return str(c["status"])
        return None

    def finding_ids(self) -> set[str]:
        return {f["id"] for f in self.doc["findings"]}

    def all_modules_ok(self) -> bool:
        return all(m["status"] == "ok" for m in self.doc["modules"])


def _same_host(a: dict[str, Any], b: dict[str, Any]) -> bool:
    ha, hb = a.get("host"), b.get("host")
    return bool(
        ha
        and hb
        and ha["os"]["family"] == hb["os"]["family"]
        and ha["hostname"].casefold() == hb["hostname"].casefold()
    )


class HistoryStore:
    """Earlier snapshots of one host, oldest first, plus what was skipped and why."""

    def __init__(self, snaps: list[Snap], skipped: list[dict[str, str]] | None = None) -> None:
        self.snaps = sorted(snaps, key=lambda s: (s.started_at, s.source))
        self.skipped = skipped or []

    @classmethod
    def from_paths(cls, paths: list[str | Path]) -> HistoryStore:
        snaps: list[Snap] = []
        for p in paths:
            try:
                snaps.append(Snap(load_assessment(p), str(p)))
            except LoadError as exc:
                raise HistoryError(str(exc)) from None
        return cls(snaps)

    @classmethod
    def scan(cls, directory: str | Path) -> HistoryStore:
        """Load every readable assessment directly inside ``directory``; report the rest."""
        root = Path(directory)
        if not root.is_dir():
            raise HistoryError(f"history directory not found: {root}")
        snaps: list[Snap] = []
        skipped: list[dict[str, str]] = []
        children = sorted(root.iterdir())
        if len(children) > MAX_SNAPSHOTS * 4:
            raise HistoryError(f"{root}: too many entries to scan")
        for child in children:
            is_candidate = child.is_dir() or child.suffix == ".json"
            if not is_candidate:
                continue
            try:
                snaps.append(Snap(load_assessment(child), str(child)))
            except LoadError as exc:
                skipped.append({"source": str(child), "reason": str(exc)[:300]})
        if len(snaps) > MAX_SNAPSHOTS:
            raise HistoryError(f"{root}: more than {MAX_SNAPSHOTS} snapshots")
        return cls(snaps, skipped)

    def before(self, current: dict[str, Any]) -> tuple[list[Snap], list[dict[str, str]]]:
        """Snapshots of the same host strictly earlier than ``current`` (and the ones excluded)."""
        out: list[Snap] = []
        notes = list(self.skipped)
        cur_id = current["assessment"]["id"]
        for s in self.snaps:
            if s.doc["assessment"]["id"] == cur_id:
                continue
            if not _same_host(s.doc, current):
                notes.append({"source": s.source, "reason": "different host or OS family"})
            elif s.started_at < current["assessment"]["started_at"]:
                out.append(s)
            else:
                notes.append(
                    {"source": s.source, "reason": "not earlier than the current snapshot"}
                )
        return out, notes


class HistoryView:
    """What rules may ask about the past of one current assessment."""

    def __init__(self, current: dict[str, Any], previous: list[Snap]) -> None:
        self.current = current
        self.previous = previous

    @property
    def count(self) -> int:
        return len(self.previous)

    def finding_states(self, finding: dict[str, Any]) -> list[str]:
        """``present`` / ``absent`` / ``unknown`` per earlier snapshot (oldest first)."""
        states = []
        for s in self.previous:
            if finding["id"] in s.finding_ids():
                states.append("present")
            elif finding_coverage(s.doc, finding)[0]:
                states.append("absent")
            else:
                states.append("unknown")
        return states

    def finding_history(self, finding: dict[str, Any]) -> dict[str, Any]:
        states = self.finding_states(finding)
        streak = 1  # the current snapshot
        for st in reversed(states):
            if st != "present":
                break
            streak += 1
        first = next(
            (s.started_at for s, st in zip(self.previous, states) if st == "present"),
            self.current["assessment"]["started_at"],
        )
        seen_present = False
        reappeared = False
        for st in states:
            if st == "present":
                seen_present = True
            elif st == "absent" and seen_present:
                reappeared = True
        return {
            "snapshots_present": 1 + states.count("present"),
            "consecutive": streak,
            "known_snapshots": 1 + sum(1 for st in states if st != "unknown"),
            "first_seen": first,
            "reappeared": reappeared,
        }

    def record_stability(self, domain: str, scope: str, key: str) -> int:
        """How many of the most recent earlier snapshots held the same attributes for this
        record as the newest earlier one (0 when there is none or it is unknown)."""
        if not self.previous:
            return 0
        newest = self.previous[-1].record(domain, scope, key)
        if newest is None:
            return 0
        want = json.dumps(newest["attrs"], sort_keys=True)
        n = 0
        for s in reversed(self.previous):
            rec = s.record(domain, scope, key)
            if rec is None or json.dumps(rec["attrs"], sort_keys=True) != want:
                break
            if s.partition_status(domain, scope) not in ("complete", "degraded", None):
                break
            n += 1
        return n

    def previous_state(self) -> dict[str, Any]:
        """Facts about the newest earlier snapshot."""
        if not self.previous:
            return {"exists": False}
        s = self.previous[-1]
        rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        worst = max((rank[f["severity"]] for f in s.doc["findings"]), default=0)
        complete = s.all_modules_ok()
        return {
            "exists": True,
            "finding_count": len(s.doc["findings"]),
            "max_severity_rank": worst,
            "complete": complete,
            "clean": complete and worst < rank["medium"],
            "started_at": s.started_at,
        }
