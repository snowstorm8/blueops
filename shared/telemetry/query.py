"""Constrained telemetry queries: filters, a JSON condition, process trees. No code evaluation.

A query is a JSON object (or the equivalent command-line flags)::

    {"category": ["process", "network_connection"],
     "since": "2026-03-01T00:00:00Z", "until": "2026-03-02T00:00:00Z",
     "where": {"all": [{"field": "attrs.name", "op": "eq", "value": "nc"}]},
     "sort": "time", "limit": 100}

``where`` uses the same condition language as detection rules (``shared/rules/conditions.py``)
over the fields of the ``telemetry`` source; unknown fields are rejected before anything runs.
"""

from __future__ import annotations

from typing import Any

from shared.findings.model import clean
from shared.rules.conditions import ConditionError, compile_condition
from shared.rules.subjects import FIELDS, field_known
from shared.rules.telemetry_subjects import ProcessIndex, telemetry_subject
from shared.telemetry.model import CATEGORIES, parse_time

MAX_LIMIT = 10_000
QUERY_KEYS = ("category", "host", "since", "until", "where", "sort", "limit", "scope")


class QueryError(ValueError):
    """The query is malformed; the message says which part."""


def parse_query(raw: Any) -> dict[str, Any]:  # noqa: PLR0912 - one check per query key
    """Validate a query object and return a normalized copy."""
    if not isinstance(raw, dict):
        raise QueryError("a query must be a JSON object")
    unknown = sorted(set(raw) - set(QUERY_KEYS))
    if unknown:
        raise QueryError(
            f"unknown query key(s): {', '.join(unknown)} (allowed: {', '.join(QUERY_KEYS)})"
        )
    q: dict[str, Any] = {}
    cats = raw.get("category", [])
    cats = [cats] if isinstance(cats, str) else cats
    if not isinstance(cats, list) or any(c not in CATEGORIES for c in cats):
        raise QueryError(f"category must be one or more of: {', '.join(CATEGORIES)}")
    q["category"] = list(cats)
    for key in ("since", "until"):
        if raw.get(key) is not None:
            t = parse_time(raw[key])
            if t is None:
                raise QueryError(
                    f"{key}: expected an ISO 8601 UTC timestamp with a zone, e.g. 2026-03-01T00:00:00Z"
                )
            q[key] = t
    if raw.get("host") is not None:
        if not isinstance(raw["host"], str):
            raise QueryError("host must be a string")
        q["host"] = raw["host"]
    if raw.get("scope") is not None:
        q["scope"] = str(raw["scope"])
    sort = raw.get("sort", "time")
    if sort not in ("time", "key", "category"):
        raise QueryError("sort must be one of: time, key, category")
    q["sort"] = sort
    limit = raw.get("limit", 100)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise QueryError(f"limit must be an integer between 1 and {MAX_LIMIT}")
    q["limit"] = limit
    if raw.get("where") is not None:
        try:
            node = compile_condition(raw["where"], "where")
        except ConditionError as exc:
            raise QueryError(str(exc)) from None
        bad = sorted(f for f in node.fields if not field_known("telemetry", f))
        if bad:
            raise QueryError(
                f"unknown field(s) in where: {', '.join(bad)}. Known fields: {', '.join(FIELDS['telemetry'])}, attrs.<name>"
            )
        q["where"] = raw["where"]
    return q


def _when(rec: dict[str, Any]) -> str:
    return str(rec.get("event_time") or rec["observed_at"])


def select(doc: dict[str, Any], query: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    """``(records, total_matches)``; ``records`` is capped at ``limit``."""
    q = parse_query(query)
    if q.get("host") and q["host"].casefold() not in (
        doc["host"]["hostname"].casefold(),
        doc["host"]["host_id"].casefold(),
    ):
        return [], 0
    node = compile_condition(q["where"], "where") if "where" in q else None
    index = ProcessIndex(doc["records"])
    out: list[dict[str, Any]] = []
    for rec in doc["records"]:
        if q["category"] and rec["category"] not in q["category"]:
            continue
        if "scope" in q and rec.get("scope", "") != q["scope"]:
            continue
        when = _when(rec)
        if ("since" in q and when < q["since"]) or ("until" in q and when > q["until"]):
            continue
        if node is not None and not node.run(telemetry_subject(rec, index).fields, None):
            continue
        out.append(rec)
    key = {
        "time": lambda r: (_when(r), r["key"]),
        "key": lambda r: r["key"],
        "category": lambda r: (r["category"], r["key"]),
    }[q["sort"]]
    out.sort(key=key)
    return out[: q["limit"]], len(out)


def attribute_filters(eq: list[str], contains: list[str]) -> dict[str, Any]:
    """Build a ``where`` from ``KEY=VALUE`` (exact) and ``KEY~TEXT`` (substring) flags."""
    leaves: list[dict[str, Any]] = []
    for item in eq:
        k, sep, v = item.partition("=")
        if not sep or not k:
            raise QueryError(f"--attr expects NAME=VALUE, got {clean(item, 60)!r}")
        leaves.append({"field": k if "." in k else f"attrs.{k}", "op": "ieq", "value": v})
    for item in contains:
        k, sep, v = item.partition("~")
        if not sep or not k:
            raise QueryError(f"--contains expects NAME~TEXT, got {clean(item, 60)!r}")
        leaves.append({"field": k if "." in k else f"attrs.{k}", "op": "icontains", "value": v})
    return {"all": leaves} if leaves else {}


# ------------------------------------------------------------------------- process trees


def process_tree(
    doc: dict[str, Any],
    *,
    pid: int | None = None,
    name: str | None = None,
    depth: int = 6,
    max_lines: int = 200,
) -> list[str]:
    """Ancestors and descendants of the matching processes, one text line per process."""
    procs = [r for r in doc["records"] if r["category"] == "process"]
    index = ProcessIndex(procs)
    kids: dict[Any, list[dict[str, Any]]] = {}
    for r in procs:
        kids.setdefault(r["attributes"].get("ppid"), []).append(r)
    roots = [
        r for r in procs
        if (pid is not None and r["attributes"].get("pid") == pid)
        or (name is not None and str(r["attributes"].get("name", "")).casefold() == name.casefold())
    ]  # fmt: skip
    lines: list[str] = []

    def label(r: dict[str, Any]) -> str:
        a = r["attributes"]
        return clean(
            f"{a.get('name')} (pid {a.get('pid')}, user {a.get('user') or '?'}) {a.get('exe') or ''}",
            200,
        )

    def down(r: dict[str, Any], level: int, seen: set[Any]) -> None:
        if len(lines) >= max_lines:
            return
        for child in sorted(
            kids.get(r["attributes"].get("pid"), []), key=lambda c: c["attributes"].get("pid") or 0
        ):
            cp = child["attributes"].get("pid")
            if cp in seen:
                continue
            lines.append("  " * level + "└─ " + label(child))
            if level < depth:
                down(child, level + 1, seen | {cp})

    for r in roots:
        chain = list(reversed(index.chain(r)))
        for i, anc in enumerate(chain):
            lines.append("  " * i + label(anc))
        base = len(chain)
        lines.append("  " * base + "* " + label(r))
        down(r, base + 1, {r["attributes"].get("pid")})
        if len(lines) >= max_lines:
            lines.append("... output truncated")
            break
    return lines
