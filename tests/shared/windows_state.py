"""Attribute differences between two host-state snapshots to the audit or to the host itself.

The live audit test must stay strict: the audit may not change host state. But Windows changes
some services by itself. Measured on fresh GitHub runners, BITS demotes itself from automatic
(delayed) to demand start about one to three minutes after it was started, with nothing else
running, and logs a System event 7040 ("changed from auto start to demand start"). A difference
is therefore tolerated only for that exact transition and only when the host logged it inside
the snapshot window. Anything else, including the opposite transition that starting BITS would
cause, is reported as caused by the audit.
"""

from __future__ import annotations

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
        if twin in svc["added"] and _logged(before, after, rule[2]):
            svc["removed"].remove(gone)
            svc["added"].remove(twin)
            explained.append(f"{name}: {rule[0]} -> {rule[1]} logged by the host (event 7040)")
    if not svc["removed"] and not svc["added"]:
        del changed["services"]
    return explained
