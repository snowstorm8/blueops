"""Telemetry vocabulary, record identity and per-record validation/normalization.

Everything a collector emits is untrusted input (it may come from a compromised host), so a
record is never copied through: ``normalise_record`` builds a new record from validated parts and
returns the reasons a record was refused instead of raising or dropping it silently.
"""

from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from shared.findings.model import clean

TELEMETRY_SCHEMA_VERSION = "1.1.0"  # 1.1.0: optional provenance (inputs_verified, inputs)
TELEMETRY_VERSION = "1.0.0"  # version of the ingestion/normalization logic
COLLECTION_MODES = ("live", "import", "assessment")

# category -> attribute names that must be present (possibly null + listed as unknown).
CATEGORIES: dict[str, tuple[str, ...]] = {
    "process": ("pid", "name"),
    "user": ("name",),
    "group": ("name",),
    "session": ("user",),
    "service": ("name",),
    "scheduled_task": ("name",),
    "network_connection": ("protocol", "local_port"),
    "listener": ("protocol", "local_port"),
    "auth_event": ("action", "result"),
    "security_event": ("event_id",),
    "config_change": ("object", "change"),
    "system_config": ("setting",),
    "integrity": ("path",),
    "persistence": ("mechanism", "location"),
    "auth_summary": ("grouping",),
}
# Append-only logs: a different collection window legitimately shows different events, so a
# comparison reports new events but never "removed" ones.
EVENT_CATEGORIES = ("auth_event", "security_event", "config_change", "auth_summary")
SOURCE_TYPES = ("proc", "file", "command", "api", "eventlog", "registry", "assessment", "derived")
COVERAGE_STATUSES = ("complete", "partial", "unavailable", "not_applicable")
RECORD_STATUSES = ("ok", "partial")
OS_FAMILIES = ("linux", "windows")

# Closed vocabularies for the attributes the built-in rules read.
AUTH_ACTIONS = (
    "login_success", "login_failure", "logoff", "privilege_use", "sudo", "su", "account_change",
    "group_change", "lockout", "credential_use", "other",
)  # fmt: skip
AUTH_RESULTS = ("success", "failure", "unknown")

MAX_ATTR_VALUE = 4096
MAX_LIST = 200
MAX_ATTRS = 64
_ATTR_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_TS = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)
_CAT_ORDER = {c: i for i, c in enumerate(CATEGORIES)}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: Any) -> str | None:
    """Normalize an ISO 8601 timestamp to ``YYYY-MM-DDTHH:MM:SS[.fff]Z`` (UTC), or ``None``.

    A timestamp with no zone is *refused*, not assumed to be UTC: guessing the zone of a log line
    silently shifts every ordering the hunting rules rely on.
    """
    if not isinstance(value, str):
        return None
    m = _TS.match(value.strip())
    if not m or m.group(8) is None:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    try:
        dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
    except ValueError:
        return None
    zone = m.group(8)
    if zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        dt -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    out = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if m.group(7):
        frac = m.group(7).rstrip("0")
        if frac:
            out += "." + frac[:6]
    return out + "Z"


def record_id(host_id: str, category: str, key: str) -> str:
    """Stable id: the same entity on the same host gets the same id in every collection."""
    raw = "\x1f".join((host_id, category, key)).encode("utf-8", "replace")
    return "TEL-" + hashlib.sha256(raw).hexdigest()[:16]


def category_rank(category: str) -> int:
    return _CAT_ORDER.get(category, len(_CAT_ORDER))


def _scalar(v: Any) -> tuple[Any, bool]:
    """``(value, ok)``; strings are stripped of control characters and capped."""
    if v is None or isinstance(v, bool):
        return v, True
    if isinstance(v, (int, float)):
        if isinstance(v, float) and not math.isfinite(v):
            return None, False
        return v, True
    if isinstance(v, str):
        return _CTRL.sub("?", v)[:MAX_ATTR_VALUE], True
    return None, False


def normalise_attributes(raw: Any) -> tuple[dict[str, Any], list[str]]:
    """Validate attribute names and values; returns ``(attributes, problems)``."""
    problems: list[str] = []
    out: dict[str, Any] = {}
    if not isinstance(raw, dict):
        return out, ["attributes must be an object"]
    for name, val in raw.items():
        if len(out) >= MAX_ATTRS:
            problems.append(f"more than {MAX_ATTRS} attributes; the rest were dropped")
            break
        if not isinstance(name, str) or not _ATTR_NAME.match(name):
            problems.append(f"invalid attribute name {clean(str(name), 40)!r}")
            continue
        if isinstance(val, (list, tuple)):
            items = []
            for item in list(val)[:MAX_LIST]:
                v, ok = _scalar(item)
                if not ok:
                    problems.append(f"attribute {name}: non-scalar list element")
                    break
                items.append(v)
            else:
                out[name] = items
                if len(val) > MAX_LIST:
                    problems.append(f"attribute {name}: list truncated to {MAX_LIST}")
            continue
        v, ok = _scalar(val)
        if not ok:
            problems.append(f"attribute {name}: unsupported value type {type(val).__name__}")
            continue
        out[name] = v
    return out, problems


def default_identity(category: str, key: str, attrs: dict[str, Any]) -> str:
    """The comparison identity: what makes two observations "the same thing" across snapshots."""
    if category == "process":
        # pid and start time change on every run; the program, its owner and name do not.
        return f"process:{attrs.get('user') or '?'}:{attrs.get('exe') or attrs.get('name')}"
    if category == "network_connection":
        return (
            f"conn:{attrs.get('protocol')}:{attrs.get('local_port')}>"
            f"{attrs.get('remote_address')}:{attrs.get('remote_port')}:{attrs.get('process') or '?'}"
        )
    return key


def normalise_record(  # noqa: PLR0911, PLR0912, PLR0915 - one linear validation pass
    raw: Any,
    *,
    host_id: str,
    os_family: str,
    observed_default: str,
    collector: dict[str, str],
    origin: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Build a normalized record from untrusted input.

    Returns ``(record, notes)``. ``record`` is ``None`` when the input cannot be used; ``notes``
    then lists why (it becomes a ``rejected`` entry). When a record is kept with imperfections
    (for example an unparsable event time), the notes are returned too and the record is marked
    ``partial`` with the notes as limitations, so the weakness stays visible.
    """
    if not isinstance(raw, dict):
        return None, ["record must be an object"]
    notes: list[str] = []
    category = raw.get("category")
    if category not in CATEGORIES:
        return None, [f"unknown category {clean(str(category), 40)!r}"]
    key = raw.get("key")
    if not isinstance(key, str) or not key.strip():
        return None, ["key is required (a stable string identifying the observed entity)"]
    key = clean(key, 512)
    attrs, problems = normalise_attributes(raw.get("attributes"))
    if "attributes" not in raw:
        return None, ["attributes is required"]
    fatal = [p for p in problems if p == "attributes must be an object"]
    if fatal:
        return None, fatal
    notes.extend(problems)

    unknown_raw = raw.get("unknown_attributes", [])
    unknown: list[str] = []
    if isinstance(unknown_raw, list):
        unknown = [str(u) for u in unknown_raw if isinstance(u, str) and _ATTR_NAME.match(u)][:64]
    elif unknown_raw not in (None, ""):
        notes.append("unknown_attributes must be a list")
    # Required attributes: present, or explicitly declared unknown (null). A required attribute
    # that is simply missing means the record is unusable for rules that read it.
    for name in CATEGORIES[category]:
        if name not in attrs:
            return None, [f"missing required attribute {name!r} for category {category}"]
        if attrs[name] is None and name not in unknown:
            unknown.append(name)
    unknown = sorted(set(unknown) | {n for n, v in attrs.items() if v is None and n in unknown})

    if category in ("auth_event",):
        if attrs.get("action") not in AUTH_ACTIONS:
            notes.append(f"unrecognised auth action {clean(str(attrs.get('action')), 30)!r}")
            attrs["action"] = "other"
        if attrs.get("result") not in AUTH_RESULTS:
            notes.append(f"unrecognised auth result {clean(str(attrs.get('result')), 30)!r}")
            attrs["result"] = "unknown"

    observed = parse_time(raw.get("observed_at")) or observed_default
    if raw.get("observed_at") is not None and parse_time(raw.get("observed_at")) is None:
        notes.append("observed_at unparsable; the collection start time was used")
    event_time = None
    if raw.get("event_time") not in (None, ""):
        event_time = parse_time(raw.get("event_time"))
        if event_time is None:
            notes.append("event_time unparsable or without a time zone; ordering is unknown")
    if category in EVENT_CATEGORIES and event_time is None and category != "auth_summary":
        notes.append("no usable event time; time-based correlation cannot use this record")

    src = raw.get("source") if isinstance(raw.get("source"), dict) else {}
    stype = src.get("type") if src.get("type") in SOURCE_TYPES else "unknown"
    if stype == "unknown" and src.get("type") is not None:
        notes.append("unrecognised source type")
    sref = clean(str(src.get("ref", "")), 512)
    method = clean(str(raw.get("method") or "unspecified"), 120) or "unspecified"

    limitations = raw.get("limitations", [])
    lims = (
        [clean(str(x), 300) for x in limitations if isinstance(x, str)][:10]
        if isinstance(limitations, list)
        else []
    )
    # Notes that imply degraded data become limitations.
    degrade = [
        n for n in notes if "unparsable" in n or "no usable event time" in n or "truncated" in n
    ]
    for n in degrade:
        if n not in lims and len(lims) < 10:
            lims.append(n)
    status = "partial" if (raw.get("status") == "partial" or unknown or degrade) else "ok"

    identity = raw.get("identity")
    identity = (
        clean(identity, 512)
        if isinstance(identity, str) and identity.strip()
        else default_identity(category, key, attrs)
    )

    rec: dict[str, Any] = {
        "record_id": record_id(host_id, category, key),
        "host_id": host_id,
        "category": category,
        "key": key,
        "identity": identity,
        "observed_at": observed,
        "os_family": os_family,
        "collector": dict(collector),
        "source": {"type": stype, "ref": sref},
        "method": method,
        "attributes": attrs,
        "unknown_attributes": unknown,
        "status": status,
        "limitations": lims,
        "occurrences": 1,
        "first_seen": event_time or observed,
        "last_seen": event_time or observed,
        "origin": clean(origin, 200),
    }
    if isinstance(raw.get("scope"), str) and raw["scope"].strip():
        rec["scope"] = clean(raw["scope"], 120)
    if event_time:
        rec["event_time"] = event_time
    if isinstance(raw.get("derived_from"), list):
        rec["derived_from"] = [str(x)[:40] for x in raw["derived_from"][:200] if isinstance(x, str)]
    if isinstance(raw.get("record_id"), str):
        rec["source_record_id"] = clean(raw["record_id"], 80)
    return rec, notes
