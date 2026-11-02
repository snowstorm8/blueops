"""Golden-file regression tests for the comparison and report output.

``tests/fixtures/engine/`` holds two assessments, the comparison computed from them and the
Markdown report rendered from the second. Any change in these outputs fails the test; if the
change is intended, regenerate with ``BO_UPDATE_GOLDEN=1`` set (pytest on this file) and review the
diff like any other code change.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from shared.engine.loader import load_assessment
from shared.reporting.render_html import render_html
from shared.reporting.render_markdown import render_markdown
from shared.reporting.schema_lite import validate
from shared.reporting.snapshot_compare import compare_snapshots, comparison_exit_code

GOLD = Path(__file__).resolve().parents[1] / "fixtures" / "engine"
STAMP = "2026-03-09T00:00:00Z"
UPDATE = os.environ.get("BO_UPDATE_GOLDEN") == "1"


def _check(name: str, text: str) -> None:
    path = GOLD / name
    if UPDATE:
        path.write_text(text, encoding="utf-8", newline="\n")
    assert text == path.read_text("utf-8"), f"{name} changed; see the module docstring"


@pytest.fixture(scope="module")
def snapshots() -> tuple[dict[str, Any], dict[str, Any]]:
    return load_assessment(GOLD / "baseline.assessment.json"), load_assessment(
        GOLD / "current.assessment.json"
    )


def test_stored_assessments_are_valid(snapshots: tuple[dict[str, Any], dict[str, Any]]) -> None:
    for doc in snapshots:
        assert validate(doc, "assessment.schema.json") == []


def test_comparison_matches_the_golden_file(
    snapshots: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    cmp_doc = compare_snapshots(*snapshots, generated_at=STAMP)
    assert validate(cmp_doc, "snapshot-comparison.schema.json") == []
    _check("expected-comparison.json", json.dumps(cmp_doc, indent=2) + "\n")


def test_golden_comparison_says_what_a_reviewer_expects(
    snapshots: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    """Independent of the golden text: the facts the fixtures were built to contain."""
    c = compare_snapshots(*snapshots, generated_at=STAMP)
    f = c["findings"]
    assert [x["check_id"] for x in f["new"]] == ["USR-NEW-001"]
    assert sorted(x["check_id"] for x in f["resolved"]) == ["NET-LISTEN-001", "USR-PWD-001"]
    assert [x["check_id"] for x in f["severity_changed"]] == ["USR-UID0-001"]
    assert f["severity_changed"][0]["direction"] == "increased"
    assert f["severity_changed"][0]["evidence"]["added"]
    changes = {(x["change"], x["key"]) for x in c["configuration"]["changes"]}
    assert changes == {
        ("modified", "user:alice"),
        ("added", "user:eve"),
        ("removed", "user:bob"),
        ("removed", "listener:tcp/0.0.0.0/23"),
    }
    # fewer weighted points but a new finding and a worse one: the trend must still be "worse"
    assert c["summary"]["weighted_index"]["delta"] < 0 and c["summary"]["trend"] == "worse"
    assert comparison_exit_code(c) == 4


def test_markdown_report_matches_the_golden_file(
    snapshots: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    cmp_doc = compare_snapshots(*snapshots, generated_at=STAMP)
    _check("expected-report.md", render_markdown(snapshots[1], [cmp_doc], STAMP))


def test_html_report_is_stable_and_shows_the_changed_evidence(
    snapshots: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    cmp_doc = compare_snapshots(*snapshots, generated_at=STAMP)
    html = render_html(snapshots[1], [cmp_doc], STAMP)
    assert html == render_html(snapshots[1], [cmp_doc], STAMP)
    assert "Persistent findings with changed evidence (1)" in html
    assert "New findings (1)" in html and "Resolved findings (2)" in html
