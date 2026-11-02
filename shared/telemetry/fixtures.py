"""Build small synthetic telemetry documents from compact specs (rule examples, tests, docs).

    {"records": [{"category": "process", "key": "p1", "attributes": {"pid": 7, "name": "nc"}}],
     "coverage": {"auth_event": "unavailable"}}

Categories that have records default to ``complete`` coverage; ``coverage`` overrides per category
and may declare categories that have no records (an observed absence, or ``unavailable``). The
result goes through the real ingestion path, so an example exercises exactly what a collected
stream would.
"""

from __future__ import annotations

import json
from typing import Any

from shared.telemetry.ingest import build_document, read_stream
from shared.telemetry.model import CATEGORIES

DEFAULT_STARTED = "2026-03-01T10:00:00Z"
DEFAULT_ENDED = "2026-03-01T10:05:00Z"


def build_telemetry(
    spec: dict[str, Any],
    *,
    platform: str = "linux",
    hostname: str = "host01",
    cid: str = "example-telemetry",
) -> dict[str, Any]:
    started = spec.get("started_at", DEFAULT_STARTED)
    lines: list[dict[str, Any]] = [
        {
            "type": "header",
            "collector": {"name": "synthetic", "version": "1.0.0"},
            "host": {"hostname": spec.get("host", hostname), "os": {"family": platform, "name": "Synthetic", "version": "1"}},
            "collection": {"id": cid, "started_at": started, "elevated": spec.get("elevated", True)},
        }
    ]  # fmt: skip
    records = spec.get("records", [])
    declared = dict(spec.get("coverage", {}))
    for cat in sorted({r["category"] for r in records if r.get("category") in CATEGORIES}):
        declared.setdefault(cat, "complete")
    for cat, status in sorted(declared.items()):
        lines.append(
            {
                "type": "coverage",
                "category": cat,
                "status": status,
                **({"reason": "synthetic"} if status != "complete" else {}),
            }
        )
    for r in records:
        lines.append(
            {"type": "record", "observed_at": started, "source": {"type": "file", "ref": "/synthetic"}, "method": "synthetic", "unknown_attributes": [], **r}
        )  # fmt: skip
    lines.append(
        {"type": "end", "ended_at": spec.get("ended_at", DEFAULT_ENDED), "records": len(records)}
    )
    data = ("\n".join(json.dumps(x) for x in lines) + "\n").encode()
    return build_document(
        [read_stream("example", data)],
        mode="import",
        generated_at=spec.get("generated_at", DEFAULT_ENDED),
    )
