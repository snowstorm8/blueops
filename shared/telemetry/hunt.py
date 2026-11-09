"""Hunting: telemetry rules run through the detection engine, so results are ordinary detections.

There is deliberately no second rule engine. This module only prepares inputs: when there is no
assessment, a minimal empty one is built from the telemetry so the engine has a host to attach
detections to (it carries no findings, and its modules list is empty).
"""

from __future__ import annotations

from typing import Any

from shared.engine.assessment import assessment_from_report
from shared.engine.provenance import entries, mark, merge_into
from shared.reporting.contracts import SCHEMA_VERSION

NATURE_CLASS = {
    "observation": "unusual",
    "indicator": "suspicious",
    "correlated": "suspicious",
    "hypothesis": "lead",
}
CLASS_TEXT = {
    "unusual": "A factual difference from what is expected; no wrongdoing is implied.",
    "suspicious": "Matches a pattern associated with malicious activity; benign causes are common. Not proof.",
    "lead": "An unverified hypothesis to follow up.",
}


def classification(nature: str) -> str:
    """How a rule's ``nature`` is presented to hunters. BlueOps never reports 'confirmed': only an
    analyst can confirm, and does so by resolving a case with a note."""
    return NATURE_CLASS.get(nature, "lead")


def shell_assessment(tel: dict[str, Any]) -> dict[str, Any]:
    h, c = tel["host"], tel["collection"]
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "blueops-telemetry", "version": "1.0.0", "category": "audit"},
        "run": {"id": c["id"], "started_at": c["started_at"], "finished_at": c["ended_at"], "mode": "read-only", "dry_run": False, "exit_code": 0},
        "host": {
            "hostname": h["hostname"],
            "os": {"family": h["os"]["family"], "name": h["os"].get("name", h["os"]["family"].title()), "version": h["os"].get("version", "unknown")},
            "arch": h.get("arch", "unknown"),
            "elevated": bool(c.get("elevated")),
        },
        "findings": [],
        "errors": [],
        "inventory": {"coverage": [], "records": []},
        "summary": {"total": 0, "by_severity": dict.fromkeys(("info", "low", "medium", "high", "critical"), 0)},
    }  # fmt: skip
    doc = assessment_from_report(report)
    doc["assessment"]["profile"] = "telemetry"
    doc["assessment"]["id"] = c["id"]
    doc["assessment"]["modules"] = []
    doc["modules"] = []
    doc["assessment"]["status"] = "complete" if tel["summary"]["complete"] else "partial"
    # The shell is derived entirely from `tel`, so it inherits exactly tel's provenance.
    merge_into(doc, entries("telemetry", tel))
    own_verified = bool(getattr(tel, "load_verified", False))
    return mark(doc, verified=own_verified, source=getattr(tel, "load_source", "") or "(telemetry)")
