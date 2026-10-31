"""Accepted-change allowlist: explicit, scoped, expiring, auditable suppression of detections.

An entry names ONE subject (domain + key, optionally scope/change/current attribute values) and
the rules it accepts. A detection is moved to ``accepted`` only when every condition holds:

* the subject matches exactly (no wildcards);
* every reason on the detection comes from a rule the entry lists;
* the detection's severity is at most the entry's ``max_severity`` (never above ``high``);
* the entry has not expired at the run's ``generated_at``;
* if ``current`` is given, the current record carries exactly those attribute values (so a
  later, different change to the same subject - for example another file hash - is reported).

The detection itself is never edited or dropped: it moves unchanged into ``accepted`` with an
``acceptance`` block naming the entry, and the document carries an audit of every entry (matched,
unused or expired). Malformed allowlists are errors, never silently ignored.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.reporting.contracts import Severity
from shared.reporting.inventory import parse_timestamp
from shared.reporting.jsonio import JsonInputError, load_json_strict

SCHEMA_VERSION = "0.1.0"
MAX_BYTES = 1024 * 1024
MAX_ENTRIES = 1000
MAX_TEXT = 500
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RULE = re.compile(r"^BO-[A-Z]+-\d{3}$")
_FIELDS = frozenset(
    {
        "id",
        "rules",
        "domain",
        "key",
        "scope",
        "change",
        "current",
        "max_severity",
        "reason",
        "approved_by",
        "approved_at",
        "expires",
    }
)
_REQUIRED = ("id", "rules", "domain", "key", "max_severity", "reason", "approved_by", "approved_at")
_REQUIRED += ("expires",)
# Critical detections can never be accepted: they need a human decision on every run.
_MAX_ACCEPTABLE = Severity.HIGH


class AllowlistError(ValueError):
    """The allowlist file is unreadable or invalid."""


@dataclass(frozen=True)
class Entry:
    id: str
    rules: frozenset[str]
    domain: str
    key: str
    scope: str | None
    change: str | None
    current: dict[str, list[str]] | None
    max_severity: Severity
    reason: str
    approved_by: str
    approved_at: str
    expires: str


@dataclass(frozen=True)
class Allowlist:
    entries: tuple[Entry, ...]
    sha256: str
    source: str


def _text(entry: dict[str, Any], name: str, where: str) -> str:
    v = entry.get(name)
    if not isinstance(v, str) or not v.strip() or len(v) > MAX_TEXT:
        raise AllowlistError(f"{where}: '{name}' must be a non-empty string (max {MAX_TEXT})")
    return v


def _values(v: Any) -> list[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return sorted(v)
    raise AllowlistError("'current' values must be strings or lists of strings")


def _check_choice(raw: dict[str, Any], where: str) -> None:
    for name in ("scope", "change"):
        if name in raw and not isinstance(raw[name], str):
            raise AllowlistError(f"{where}: '{name}' must be a string")
    if raw.get("change") not in (None, "added", "removed", "modified"):
        raise AllowlistError(f"{where}: 'change' must be added, removed or modified")


def _max_severity(raw: dict[str, Any], where: str) -> Severity:
    try:
        sev = Severity.parse(raw["max_severity"])
    except (ValueError, AttributeError, TypeError):
        raise AllowlistError(f"{where}: 'max_severity' is not a severity") from None
    if sev > _MAX_ACCEPTABLE:
        raise AllowlistError(f"{where}: critical detections cannot be accepted")
    return sev


def _entry(raw: Any, index: int, known_rules: frozenset[str]) -> Entry:
    where = f"entry {index + 1}"
    if not isinstance(raw, dict):
        raise AllowlistError(f"{where}: must be an object")
    where = f"entry {index + 1} ({raw.get('id')!s:.64})"
    extra = sorted(set(raw) - _FIELDS)
    if extra:
        raise AllowlistError(f"{where}: unknown field(s): {', '.join(map(str, extra))[:200]}")
    missing = [f for f in _REQUIRED if f not in raw]
    if missing:
        raise AllowlistError(f"{where}: missing field(s): {', '.join(missing)}")
    if not isinstance(raw["id"], str) or not _ID.match(raw["id"]):
        raise AllowlistError(f"{where}: 'id' must match {_ID.pattern}")
    rules = raw["rules"]
    if (
        not isinstance(rules, list)
        or not rules
        or not all(isinstance(r, str) and _RULE.match(r) for r in rules)
    ):
        raise AllowlistError(f"{where}: 'rules' must be a non-empty list of rule ids")
    unknown = sorted(set(rules) - known_rules)
    if unknown:
        raise AllowlistError(f"{where}: unknown rule(s): {', '.join(unknown)}")
    for name in ("domain", "key", "reason", "approved_by"):
        _text(raw, name, where)
    _check_choice(raw, where)
    current = raw.get("current")
    if current is not None:
        if not isinstance(current, dict) or not current:
            raise AllowlistError(f"{where}: 'current' must be a non-empty object")
        current = {str(k): _values(v) for k, v in current.items()}
    try:
        approved = parse_timestamp(raw["approved_at"])
        expires = parse_timestamp(raw["expires"])
    except Exception:  # noqa: BLE001 - any parse failure is a bad entry
        raise AllowlistError(f"{where}: 'approved_at'/'expires' must be UTC timestamps") from None
    if expires <= approved:
        raise AllowlistError(f"{where}: 'expires' must be after 'approved_at'")
    return Entry(
        id=raw["id"],
        rules=frozenset(rules),
        domain=raw["domain"],
        key=raw["key"],
        scope=raw.get("scope"),
        change=raw.get("change"),
        current=current,
        max_severity=_max_severity(raw, where),
        reason=raw["reason"],
        approved_by=raw["approved_by"],
        approved_at=raw["approved_at"],
        expires=raw["expires"],
    )


def load(path: str, known_rules: frozenset[str]) -> Allowlist:
    """Read and strictly validate an allowlist file."""
    try:
        doc, data = load_json_strict(path, MAX_BYTES, "allowlist")
    except JsonInputError as exc:
        raise AllowlistError(str(exc)) from None
    if not isinstance(doc, dict) or doc.get("kind") != "accepted-changes":
        raise AllowlistError("allowlist must be an object with kind 'accepted-changes'")
    extra = sorted(set(doc) - {"schema_version", "kind", "entries"})
    if extra:
        raise AllowlistError(f"allowlist has unknown field(s): {', '.join(extra)[:200]}")
    if not re.match(r"^0\.\d+\.\d+$", str(doc.get("schema_version", ""))):
        raise AllowlistError("allowlist needs a 0.x schema_version")
    raw = doc.get("entries")
    if not isinstance(raw, list) or len(raw) > MAX_ENTRIES:
        raise AllowlistError(f"'entries' must be a list of at most {MAX_ENTRIES}")
    entries = tuple(_entry(e, i, known_rules) for i, e in enumerate(raw))
    ids = [e.id for e in entries]
    dup = sorted({i for i in ids if ids.count(i) > 1})
    if dup:
        raise AllowlistError(f"duplicate entry id(s): {', '.join(dup)}")
    return Allowlist(entries, hashlib.sha256(data).hexdigest(), Path(path).name)


def _subject_matches(e: Entry, d: dict[str, Any]) -> bool:
    s = d["subject"]
    if e.domain != s["domain"] or e.key != s["key"]:
        return False
    if e.scope is not None and e.scope != s["scope"]:
        return False
    if e.change is not None and e.change != s["change"]:
        return False
    if e.current is not None:
        after = d.get("after") or {}
        for name, want in e.current.items():
            have = after.get(name)
            got = [] if have is None else [have] if isinstance(have, str) else sorted(have)
            if got != want:
                return False
    return True


def apply(
    detections: list[dict[str, Any]], allow: Allowlist, now: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Split ``detections`` into (kept, accepted) and build the audit block.

    ``detections`` must be the complete list (not limited by --min-severity) so that the audit is
    the same whatever the display filter is.
    """
    sev = {s.label: s for s in Severity}
    now_ts = parse_timestamp(now)
    kept: list[dict[str, Any]] = []
    accepted: list[dict[str, Any]] = []
    used: dict[str, list[str]] = {e.id: [] for e in allow.entries}
    blocked: dict[str, list[dict[str, str]]] = {e.id: [] for e in allow.entries}
    for d in detections:
        verdict: Entry | None = None
        for e in allow.entries:
            if not _subject_matches(e, d):
                continue
            expired = parse_timestamp(e.expires) <= now_ts
            if expired:
                blocked[e.id].append({"detection": d["id"], "why": "expired"})
            elif {r["rule"] for r in d["reasons"]} - e.rules:
                blocked[e.id].append({"detection": d["id"], "why": "other rules also fired"})
            elif sev[d["severity"]] > e.max_severity:
                blocked[e.id].append({"detection": d["id"], "why": "severity above max_severity"})
            elif verdict is None:
                verdict = e
        if verdict is None:
            kept.append(d)
            continue
        used[verdict.id].append(d["id"])
        accepted.append(
            {
                **d,
                "acceptance": {
                    "entry": verdict.id,
                    "reason": verdict.reason,
                    "approved_by": verdict.approved_by,
                    "approved_at": verdict.approved_at,
                    "expires": verdict.expires,
                },
            }
        )
    audit = {
        "source": allow.source,
        "sha256": allow.sha256,
        "entries": [
            {
                "id": e.id,
                "status": (
                    "expired"
                    if parse_timestamp(e.expires) <= now_ts
                    else "matched"
                    if used[e.id]
                    else "unused"
                ),
                "expires": e.expires,
                "matched": used[e.id],
                "not_applied": blocked[e.id],
            }
            for e in allow.entries
        ],
    }
    return kept, accepted, audit
