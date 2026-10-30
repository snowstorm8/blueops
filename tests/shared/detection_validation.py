"""Helpers shared by the controlled detection-validation tests (Linux and Windows).

Not a framework: a diff + detect wrapper that checks the invariants every run must satisfy, and
three small assertion helpers. Scenarios themselves live in the test modules.
"""

from __future__ import annotations

import copy
import fnmatch
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from shared.reporting.accepted import load
from shared.reporting.baseline import compare
from shared.reporting.detection import RULES, detect, exit_code_for
from shared.reporting.inventory import Options, build_snapshot

ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-02-01T00:00:00Z"
SCHEMA = json.loads((ROOT / "shared/schemas/detections.schema.json").read_text("utf-8"))
RULE_IDS = frozenset(r.rule_id for r in RULES)
SEVERITIES = ["info", "low", "medium", "high", "critical"]


def diff_reports(base: dict[str, Any], cur: dict[str, Any]) -> dict[str, Any]:
    o = Options()
    return compare(build_snapshot(base, o), build_snapshot(cur, o), o, NOW)


def evaluate(base: dict[str, Any], cur: dict[str, Any], allow: str | None = None) -> dict[str, Any]:
    """detect() over the two reports, plus the invariants that must hold for every run."""
    diff = diff_reports(base, cur)
    allowlist = load(allow, RULE_IDS) if allow else None
    doc = detect(diff, NOW, allow=allowlist)
    Draft202012Validator(SCHEMA).validate(doc)
    again = detect(copy.deepcopy(diff), NOW, allow=allowlist)
    assert json.dumps(doc, sort_keys=True) == json.dumps(again, sort_keys=True), "not deterministic"
    code = exit_code_for(doc)
    if code == 0:  # a clean exit needs nothing found AND whole coverage
        assert doc["summary"]["total"] == 0 and doc["coverage"]["complete"]
    if not doc["coverage"]["complete"]:
        assert code != 0, "incomplete coverage must never exit 0"
    return doc


def find(doc: dict[str, Any], pattern: str) -> list[dict[str, Any]]:
    """Detections whose key matches the glob (case-insensitive: Windows keys are lower-cased)."""
    pat = pattern.casefold()
    return [
        d for d in doc["detections"] if fnmatch.fnmatchcase(d["subject"]["key"].casefold(), pat)
    ]


def keys(doc: dict[str, Any]) -> set[str]:
    return {d["subject"]["key"] for d in doc["detections"]}


def expect(
    doc: dict[str, Any], pattern: str, rules: set[str], severity: str, basis: str
) -> dict[str, Any]:
    """Exactly one detection matches ``pattern`` with these rules, severity and basis."""
    found = find(doc, pattern)
    assert len(found) == 1, (pattern, sorted(keys(doc)))
    d = found[0]
    assert rules <= {r["rule"] for r in d["reasons"]}, (pattern, d["reasons"])
    assert (d["severity"], d["basis"]) == (severity, basis), (pattern, d["severity"], d["basis"])
    return d


def ceiling(doc: dict[str, Any], limit: str) -> None:
    """No detection is above ``limit``."""
    over = [
        d["subject"]["key"]
        for d in doc["detections"]
        if SEVERITIES.index(d["severity"]) > SEVERITIES.index(limit)
    ]
    assert not over, f"above {limit}: {over}"
