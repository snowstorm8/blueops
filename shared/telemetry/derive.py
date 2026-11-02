"""Derived telemetry: aggregates computed from collected records, always labelled as derived.

A derived record carries ``source.type = "derived"`` and ``derived_from`` (the ids it summarizes),
so a rule match on an aggregate can always be traced back to the individual events.
"""

from __future__ import annotations

from typing import Any

from shared.telemetry.model import record_id

COLLECTOR = {"name": "blueops-derive", "version": "1.0.0"}
MAX_LISTED = 50


def _ts_ok(rec: dict[str, Any]) -> str | None:
    return rec.get("event_time")


def _summary_record(  # noqa: PLR0913, PLR0917
    hid: str,
    family: str,
    ts: str,
    grouping: str,
    key: str,
    attrs: dict[str, Any],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    first = min((e["first_seen"] for e in events), default=ts)
    last = max((e["last_seen"] for e in events), default=ts)
    ordering_known = all(_ts_ok(e) for e in events)
    return {
        "record_id": record_id(hid, "auth_summary", key),
        "host_id": hid,
        "category": "auth_summary",
        "key": key,
        "identity": key,
        "observed_at": ts,
        "os_family": family,
        "collector": dict(COLLECTOR),
        "source": {"type": "derived", "ref": "auth_event"},
        "method": "aggregate:auth_event",
        "attributes": {"grouping": grouping, "ordering_known": ordering_known, **attrs},
        "unknown_attributes": [] if ordering_known else ["success_after_failure"],
        "status": "ok" if ordering_known else "partial",
        "limitations": []
        if ordering_known
        else ["some events have no usable time; ordering-based fields are unknown"],
        "occurrences": 1,
        "first_seen": first,
        "last_seen": last,
        "derived_from": [e["record_id"] for e in events][:200],
        "origin": "derived",
    }


def _after(events: list[dict[str, Any]]) -> bool | None:
    """True if a successful login happened after a failure; ``None`` if times are missing."""
    fails = [_ts_ok(e) for e in events if e["attributes"].get("result") == "failure"]
    wins = [_ts_ok(e) for e in events if e["attributes"].get("result") == "success"]
    if not fails or not wins:
        return False
    if any(t is None for t in fails) or any(t is None for t in wins):
        return None
    return max(wins) > min(fails)  # type: ignore[type-var]


def _count(events: list[dict[str, Any]], result: str) -> int:
    return sum(e.get("occurrences", 1) for e in events if e["attributes"].get("result") == result)


def derive_auth_summaries(
    records: list[dict[str, Any]], hid: str, family: str, ts: str
) -> list[dict[str, Any]]:
    logins = [
        r for r in records
        if r["category"] == "auth_event" and r["attributes"].get("action") in ("login_success", "login_failure", "lockout", "sudo", "su")
    ]  # fmt: skip
    out: list[dict[str, Any]] = []
    by_src: dict[str, list[dict[str, Any]]] = {}
    by_user: dict[str, list[dict[str, Any]]] = {}
    for r in logins:
        a = r["attributes"]
        if a.get("action") not in ("login_success", "login_failure"):
            continue
        src, user = a.get("source_address"), a.get("user")
        if isinstance(src, str) and src and src not in ("-", "::1", "127.0.0.1", "localhost"):
            by_src.setdefault(src, []).append(r)
        if isinstance(user, str) and user:
            by_user.setdefault(user, []).append(r)
    for src, ev in sorted(by_src.items()):
        fails = _count(ev, "failure")
        users = sorted(
            {str(e["attributes"].get("user")) for e in ev if e["attributes"].get("user")}
        )
        if fails == 0:
            continue
        out.append(
            _summary_record(
                hid, family, ts, "source", f"source:{src}",
                {
                    "source_address": src, "failures": fails, "successes": _count(ev, "success"),
                    "users_targeted": len(users), "target_users": users[:MAX_LISTED],
                    "success_after_failure": _after(ev),
                },
                ev,
            )
        )  # fmt: skip
    for user, ev in sorted(by_user.items()):
        fails = _count(ev, "failure")
        srcs = sorted(
            {
                str(e["attributes"].get("source_address"))
                for e in ev
                if e["attributes"].get("source_address")
            }
        )
        if fails == 0:
            continue
        out.append(
            _summary_record(
                hid, family, ts, "user", f"user:{user}",
                {
                    "user": user, "failures": fails, "successes": _count(ev, "success"),
                    "distinct_sources": len(srcs), "sources": srcs[:MAX_LISTED],
                    "success_after_failure": _after(ev),
                },
                ev,
            )
        )  # fmt: skip
    return out
