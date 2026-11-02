"""Investigation workflow: analyst state kept apart from immutable assessment evidence.

State lives in one append-only JSON-lines file (``cases.jsonl``) in a directory the analyst
names. Nothing else is needed: no database, no server, easy to copy, diff and archive.

* **Append-only and tamper-evident.** Every event carries its sequence number and the SHA-256 of
  the previous line, so edits, deletions and reordering are detected when the file is read (the
  hash chain is evidence of *accidental or casual* change, not protection against an attacker who
  can rewrite the whole file; keep copies off-host for that).
* **Keyed by detection id.** Detection ids are stable hashes, so a case follows the same
  situation from one assessment to the next. A detection that was resolved or dismissed and is
  observed again is flagged ``reappeared``; the analyst's decision is not silently reverted.
* **Explained decisions.** Resolving or dismissing requires a note.
* Never stores evidence content, only references (detection ids), titles and analyst text.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.rules import RULES_SCHEMA_VERSION

STATUSES = ("new", "acknowledged", "investigating", "resolved", "dismissed")
TRANSITIONS = {
    "new": ("acknowledged", "investigating", "resolved", "dismissed"),
    "acknowledged": ("investigating", "resolved", "dismissed"),
    "investigating": ("acknowledged", "resolved", "dismissed"),
    "resolved": ("investigating",),
    "dismissed": ("investigating",),
}
NOTE_REQUIRED = ("resolved", "dismissed")
ACTIONS = ("observed", "status", "note", "link", "reappeared")
FILE_NAME = "cases.jsonl"
LOCK_NAME = "cases.lock"
GENESIS = "0" * 64
MAX_LINE = 16 * 1024
MAX_EVENTS = 200_000
MAX_NOTE = 2000
_DT = re.compile(r"^DT-[a-f0-9]{16}$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class CaseStoreError(ValueError):
    """The case file is damaged, locked, or a requested change is not allowed."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean(text: Any, limit: int) -> str:
    return _CONTROL.sub("?", str(text)).strip()[:limit]


@dataclass
class Case:
    id: str
    rule_id: str = ""
    title: str = ""
    severity: str = ""
    confidence: str = ""
    hostname: str = ""
    status: str = "new"
    first_seen: str = ""
    last_seen: str = ""
    assessments: list[str] = field(default_factory=list)
    status_history: list[dict[str, str]] = field(default_factory=list)
    notes: list[dict[str, str]] = field(default_factory=list)
    linked: list[str] = field(default_factory=list)
    reappeared: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id, "rule_id": self.rule_id, "title": self.title, "severity": self.severity,
            "confidence": self.confidence, "hostname": self.hostname, "status": self.status,
            "first_seen": self.first_seen, "last_seen": self.last_seen, "assessments": list(self.assessments),
            "status_history": list(self.status_history), "notes": list(self.notes),
            "linked": list(self.linked), "reappeared": self.reappeared,
        }  # fmt: skip


@contextmanager
def _locked(directory: Path) -> Iterator[None]:
    lock = directory / LOCK_NAME
    deadline = time.monotonic() + 5
    while True:
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            break
        except FileExistsError:
            if time.monotonic() > deadline:
                raise CaseStoreError(
                    f"{lock} exists: another writer is active, or a crashed run left it behind "
                    "(remove it only after confirming no other process is using the case store)"
                ) from None
            time.sleep(0.05)
    try:
        yield
    finally:
        with contextlib.suppress(FileNotFoundError):
            lock.unlink()


class CaseStore:
    def __init__(self, directory: str | Path, actor: str | None = None) -> None:
        self.dir = Path(directory)
        self.path = self.dir / FILE_NAME
        who = actor or os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"
        self.actor = _clean(who, 64) or "unknown"

    # ------------------------------------------------------------------------- reading

    def events(self) -> list[dict[str, Any]]:
        """All events, with the hash chain, sequence and field rules verified."""
        if not self.path.exists():
            return []
        try:
            data = self.path.read_bytes()
        except OSError as exc:
            raise CaseStoreError(f"cannot read {self.path}: {exc.strerror or exc}") from None
        out: list[dict[str, Any]] = []
        prev = GENESIS
        for n, raw in enumerate(data.split(b"\n"), 1):
            if not raw:
                continue
            if len(raw) > MAX_LINE or len(out) >= MAX_EVENTS:
                raise CaseStoreError(f"{self.path}:{n}: line too long or too many events")
            try:
                ev = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise CaseStoreError(f"{self.path}:{n}: not valid JSON (file damaged?)") from None
            problem = self._check_event(ev, len(out) + 1, prev)
            if problem:
                raise CaseStoreError(f"{self.path}:{n}: {problem}")
            prev = hashlib.sha256(raw).hexdigest()
            out.append(ev)
        return out

    @staticmethod
    def _check_event(ev: Any, seq: int, prev: str) -> str:  # noqa: PLR0911
        if not isinstance(ev, dict):
            return "event is not an object"
        if ev.get("seq") != seq:
            return (
                f"sequence {ev.get('seq')!r} where {seq} was expected (event removed or reordered?)"
            )
        if ev.get("prev") != prev:
            return "hash chain broken (an earlier line was changed, removed or inserted)"
        if not isinstance(ev.get("ts"), str) or not _TS.match(ev["ts"]):
            return "bad timestamp"
        if ev.get("action") not in ACTIONS:
            return f"unknown action {ev.get('action')!r}"
        if not isinstance(ev.get("detection"), str) or not _DT.match(ev["detection"]):
            return "bad detection id"
        if not isinstance(ev.get("data"), dict) or not isinstance(ev.get("actor"), str):
            return "missing data or actor"
        return ""

    def cases(self) -> dict[str, Case]:
        out: dict[str, Case] = {}
        for ev in self.events():
            c = out.setdefault(ev["detection"], Case(id=ev["detection"]))
            d = ev["data"]
            a = ev["action"]
            if a == "observed":
                c.rule_id, c.title = d.get("rule_id", ""), d.get("title", "")
                c.severity, c.confidence = d.get("severity", ""), d.get("confidence", "")
                c.hostname = d.get("hostname", "")
                c.first_seen = c.first_seen or ev["ts"]
                c.last_seen = ev["ts"]
                if d.get("assessment_id") and d["assessment_id"] not in c.assessments:
                    c.assessments.append(d["assessment_id"])
            elif a == "reappeared":
                c.reappeared = True
                c.last_seen = ev["ts"]
            elif a == "status":
                c.status = d["to"]
                c.reappeared = False
                c.status_history.append(
                    {
                        "ts": ev["ts"],
                        "actor": ev["actor"],
                        "from": d["from"],
                        "to": d["to"],
                        "note": d.get("note", ""),
                    }
                )
            elif a == "note":
                c.notes.append({"ts": ev["ts"], "actor": ev["actor"], "text": d["text"]})
            elif a == "link" and d["related"] not in c.linked:
                c.linked.append(d["related"])
        return out

    # ------------------------------------------------------------------------- writing

    def _append(self, events: list[tuple[str, str, dict[str, Any]]]) -> None:
        """Append ``(action, detection, data)`` events under the lock, extending the chain."""
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        with _locked(self.dir):
            existing = self.events()  # also verifies the file we are about to extend
            prev = GENESIS
            if existing:
                last = self.path.read_bytes().rstrip(b"\n").split(b"\n")[-1]
                prev = hashlib.sha256(last).hexdigest()
            lines = []
            for i, (action, det, data) in enumerate(events, len(existing) + 1):
                ev = {
                    "seq": i,
                    "prev": prev,
                    "ts": _now(),
                    "actor": self.actor,
                    "action": action,
                    "detection": det,
                    "data": data,
                    "schema_version": RULES_SCHEMA_VERSION,
                }
                raw = json.dumps(ev, sort_keys=True, separators=(",", ":")).encode("utf-8")
                if len(raw) > MAX_LINE:
                    raise CaseStoreError("event too large")
                lines.append(raw)
                prev = hashlib.sha256(raw).hexdigest()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "ab") as fh:
                fh.write(b"\n".join(lines) + b"\n")
                fh.flush()
                os.fsync(fh.fileno())

    def observe(self, results: dict[str, Any]) -> dict[str, list[str]]:
        """Register the detections of a run. Returns ``{"new": [...], "reappeared": [...]}``."""
        known = self.cases()
        batch: list[tuple[str, str, dict[str, Any]]] = []
        new: list[str] = []
        back: list[str] = []
        for d in results["detections"]:
            did = d["id"]
            batch.append(("observed", did, {
                "rule_id": d["rule"]["id"], "title": _clean(d["title"], 200), "severity": d["severity"],
                "confidence": d["confidence"], "hostname": _clean(d["host"]["hostname"], 120),
                "assessment_id": _clean(results["assessment"]["id"], 120),
            }))  # fmt: skip
            c = known.get(did)
            if c is None:
                new.append(did)
            elif c.status in ("resolved", "dismissed") and not c.reappeared:
                back.append(did)
                batch.append(
                    (
                        "reappeared",
                        did,
                        {
                            "assessment_id": _clean(results["assessment"]["id"], 120),
                            "was": c.status,
                        },
                    )
                )
        if batch:
            self._append(batch)
        return {"new": new, "reappeared": back}

    def _require(self, det: str) -> Case:
        if not _DT.match(det):
            raise CaseStoreError(f"not a detection id: {det!r}")
        c = self.cases().get(det)
        if c is None:
            raise CaseStoreError(
                f"no case for {det}: run 'detect run --state-dir' first so it is registered"
            )
        return c

    def resolve_id(self, prefix: str) -> str:
        """Expand a unique prefix of a detection id."""
        ids = [i for i in self.cases() if i.startswith(prefix)]
        if len(ids) != 1:
            raise CaseStoreError(
                f"{prefix!r} matches {len(ids)} cases" + (": " + ", ".join(ids[:5]) if ids else "")
            )
        return ids[0]

    def set_status(self, det: str, to: str, note: str = "") -> Case:
        if to not in STATUSES:
            raise CaseStoreError(f"unknown status {to!r} (one of {', '.join(STATUSES)})")
        c = self._require(det)
        if to not in TRANSITIONS[c.status]:
            allowed = ", ".join(TRANSITIONS[c.status])
            raise CaseStoreError(f"cannot move {det} from {c.status} to {to} (allowed: {allowed})")
        text = _clean(note, MAX_NOTE)
        if to in NOTE_REQUIRED and not text:
            raise CaseStoreError(f"a note is required to mark a case {to} (say why)")
        self._append(
            [("status", det, {"from": c.status, "to": to, **({"note": text} if text else {})})]
        )
        return self._require(det)

    def add_note(self, det: str, text: str) -> Case:
        clean = _clean(text, MAX_NOTE)
        if not clean:
            raise CaseStoreError("a note must not be empty")
        self._require(det)
        self._append([("note", det, {"text": clean})])
        return self._require(det)

    def link(self, det: str, other: str) -> Case:
        self._require(det)
        self._require(other)
        if det == other:
            raise CaseStoreError("a case cannot be linked to itself")
        self._append([("link", det, {"related": other}), ("link", other, {"related": det})])
        return self._require(det)


def compute_related(results: dict[str, Any]) -> dict[str, list[str]]:
    """Detections of one run that share a contributing item or an evidence id."""
    by_item: dict[str, set[str]] = {}
    for d in results["detections"]:
        keys = {
            "|".join(f"{k}={c[k]}" for k in ("type", "id", "domain", "scope", "key") if k in c)
            for c in d["contributing"]
            if c["type"] != "snapshot"
        }
        keys |= {f"ev={e}" for e in d["evidence"]}
        for k in keys:
            by_item.setdefault(k, set()).add(d["id"])
    related: dict[str, set[str]] = {d["id"]: set() for d in results["detections"]}
    for ids in by_item.values():
        if len(ids) > 1:
            for i in ids:
                related[i] |= ids - {i}
    return {k: sorted(v) for k, v in related.items()}


def case_summaries(store: CaseStore | None, results: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per detection: investigation status and bookkeeping for reports (read-only)."""
    related = compute_related(results)
    cases = store.cases() if store else {}
    out: dict[str, dict[str, Any]] = {}
    for d in results["detections"]:
        c = cases.get(d["id"])
        out[d["id"]] = {
            "status": c.status if c else "new",
            "tracked": c is not None,
            "reappeared": bool(c and c.reappeared),
            "notes": len(c.notes) if c else 0,
            "last_note": c.notes[-1]["text"][:300] if c and c.notes else "",
            "updated": (
                c.status_history[-1]["ts"] if c and c.status_history else (c.last_seen if c else "")
            ),
            "related": sorted(set(related.get(d["id"], [])) | set(c.linked if c else [])),
        }
    return out
