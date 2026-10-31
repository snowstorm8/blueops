"""Attribute differences between two host-state snapshots to the audit or to the host itself.

The live audit test must stay strict: the audit may not change host state. But Windows changes
some services by itself. Measured on fresh GitHub runners, BITS demotes itself from automatic
(delayed) to demand start about one to three minutes after it was started, with nothing else
running, and logs a System event 7040 ("changed from auto start to demand start"). A difference
is therefore tolerated only for that exact transition, only when the host logged it inside
the snapshot window and only if the service ended up stopped (every observed demotion stops
the service). Anything else, including the opposite transition that starting BITS would
cause, is reported as caused by the audit.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

# Service name -> (state before, state after, text the host logs for that change).
SELF_CHANGES = {
    "BITS": (
        "Auto",
        "Manual",
        "Background Intelligent Transfer Service service was changed from auto start to demand",
    ),
}


def _parse(ts: str) -> datetime:
    head, _, frac = ts.rstrip("Z").partition(".")
    return datetime.fromisoformat(f"{head}.{frac[:6].ljust(6, '0')}" if frac else head)


def _service(entry: str) -> tuple[str, str, str]:
    name, _, rest = entry.partition("|")
    mode, _, path = rest.partition("|")
    return name, mode, path


def _logged(before: dict[str, Any], after: dict[str, Any], text: str) -> bool:
    start = _parse(before["diag"]["at"])
    end = _parse(after["diag"]["at"])
    return any(
        text in c["message"] and start <= _parse(c["at"]) <= end
        for c in after["diag"].get("start_type_changes", [])
    )


def host_changes(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Differences between two snapshots (the ``diag`` key is never compared)."""
    changed: dict[str, Any] = {}
    for key, old in before.items():
        new = after[key]
        if key == "diag" or old == new:
            continue
        if isinstance(old, list) and isinstance(new, list):
            changed[key] = {
                "removed": [x for x in old if x not in new],
                "added": [x for x in new if x not in old],
            }
        else:
            changed[key] = "differs"
    return changed


def explained_by_host(
    changed: dict[str, Any], before: dict[str, Any], after: dict[str, Any]
) -> list[str]:
    """Remove host-initiated service changes from ``changed``; return what was removed."""
    svc = changed.get("services")
    if not isinstance(svc, dict):
        return []
    explained: list[str] = []
    for gone in list(svc["removed"]):
        name, mode, path = _service(gone)
        rule = SELF_CHANGES.get(name)
        if not rule or mode != rule[0]:
            continue
        twin = f"{name}|{rule[1]}|{path}"
        stopped = after["diag"].get("bits_status") == "Stopped"
        if twin in svc["added"] and stopped and _logged(before, after, rule[2]):
            svc["removed"].remove(gone)
            svc["added"].remove(twin)
            explained.append(f"{name}: {rule[0]} -> {rule[1]} logged by the host (event 7040)")
    if not svc["removed"] and not svc["added"]:
        del changed["services"]
    return explained


# Value names whose data is never printed, whatever the snapshot contained (defence in depth: the
# snapshot script already withholds them). Only the type, length and a short digest remain.
_SENSITIVE_NAME = re.compile(r"(?i)pass|secret|credential|token|key|pwd")
_MAX_DATA = 120


def _show(entry: dict[str, Any] | None, name: str) -> str:
    if entry is None:
        return "absent"
    data = entry.get("data")
    if isinstance(data, str) and not _SENSITIVE_NAME.search(name) and entry.get("type") != "Binary":
        shown = data if len(data) <= _MAX_DATA else data[:_MAX_DATA] + "..."
        return f"{entry.get('type')} {shown!r}"
    return f"{entry.get('type')} len={entry.get('length')} sha256={entry.get('sha256')}"


def registry_differences(
    changed: dict[str, Any], before: dict[str, Any], after: dict[str, Any]
) -> list[str]:
    """Value-level description of every registry key in ``changed``.

    Reads the ``diag.registry`` detail the snapshot script records (never compared by
    ``host_changes``). Says so when the detail is missing instead of guessing.
    """
    lines: list[str] = []
    for key in changed:
        if not key.upper().startswith(("HKLM:", "HKCU:")):
            continue
        old = (before.get("diag", {}).get("registry") or {}).get(key)
        new = (after.get("diag", {}).get("registry") or {}).get(key)
        if not isinstance(old, dict) or not isinstance(new, dict):
            lines.append(f"{key}: changed, but no value-level detail was recorded")
            continue
        lines.append(f"{key}: last_write {old.get('last_write')} -> {new.get('last_write')}")
        old_vals = old.get("values") or {}
        new_vals = new.get("values") or {}
        diffs = 0
        for name in sorted(set(old_vals) | set(new_vals)):
            a, b = old_vals.get(name), new_vals.get(name)
            if a == b:
                continue
            diffs += 1
            lines.append(f"  value {name!r}: {_show(a, name)} -> {_show(b, name)}")
        if not diffs:
            lines.append("  no per-value difference found (value names, types and digests equal)")
    return lines


def failure_message(changed: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> str:
    """Text for the assertion that the audit changed host state."""
    parts = [f"audit changed host state: {changed}"]
    parts += registry_differences(changed, before, after)
    parts.append(
        f"before={before.get('diag', {}).get('at')} after={after.get('diag', {}).get('at')}"
    )
    for label, snap in (("before", before), ("after", after)):
        events = snap.get("diag", {}).get("start_type_changes", [])
        parts.append(f"{label} 7040 events: {events}")
    return "\n".join(parts)
