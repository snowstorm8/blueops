"""Detections in the JSON / Markdown / HTML reports: content, escaping, offline behaviour."""

from __future__ import annotations

import base64
import hashlib
import re
from html import unescape
from typing import Any

import pytest
from rules_support import STAMP, doc, finding, linux_compromised, make_rule, record, rule_set
from test_render import _check_html

from shared.reporting.render_detections import DET_JS, NATURE_LABEL, render_detections_markdown
from shared.reporting.render_html import JS, render_html
from shared.reporting.render_markdown import render_markdown
from shared.rules.engine import detect
from shared.rules.investigation import case_summaries
from shared.rules.loader import load_rule_set

RS = load_rule_set()


@pytest.fixture(scope="module")
def host() -> tuple[dict[str, Any], dict[str, Any]]:
    current = doc(linux_compromised(), aid="rep")
    return current, detect(current, RS, generated_at=STAMP)


def test_html_has_a_complete_detections_section(
    host: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    current, results = host
    cases = case_summaries(None, results)
    html = render_html(current, None, STAMP, results, cases)
    p = _check_html(html)
    assert p.scripts == 1 and p.external == []
    assert '<section id="detections">' in html and 'href="#detections"' in html
    for needle in (
        "Severity",
        "Confidence",
        "Nature",
        "Categories",
        "Affected host",
        "Contributing findings and items",
        "Evidence references",
        "Why it was flagged",
        "How it matched",
        "Recommended investigation",
        "Recommended action",
        "Framework references",
        "Investigation",
        "Filter detections",
        'id="dsort"',
        "Rules that could not reach a conclusion",
    ):
        assert needle in html, needle
    assert html.count('<details class="det"') == len(results["detections"])
    for d in results["detections"]:
        assert f'id="{d["id"]}"' in html and d["rule"]["id"] in html


def test_filters_sorting_and_ids_are_wired_in_the_markup(
    host: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    current, results = host
    html = render_html(current, None, STAMP, results, case_summaries(None, results))
    for key in ("sev", "conf", "nature", "status"):
        assert f'data-dk="{key}"' in html
    for attr in (
        "data-sev=",
        "data-conf=",
        "data-status=",
        "data-nature=",
        "data-rule=",
        "data-title=",
        "data-text=",
    ):
        assert attr in html
    assert all(
        f'<option value="{v}">' in html
        for v in ("severity", "confidence", "rule", "status", "title")
    )
    assert 'id="dq"' in html and 'id="dshown"' in html


def test_csp_still_pins_exactly_the_one_script_and_includes_the_detection_code(
    host: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    current, results = host
    html = render_html(current, None, STAMP, results, None)
    policy = unescape(
        re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1)
    )  # type: ignore[union-attr]
    digest = base64.b64encode(hashlib.sha256(JS.encode()).digest()).decode()
    assert (
        f"'sha256-{digest}'" in policy
        and DET_JS.strip()[:40] in JS
        and f"<script>{JS}</script>" in html
    )
    assert "unsafe-eval" not in policy and "default-src 'none'" in policy


def test_findings_are_linked_from_detections_by_anchor(
    host: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    current, results = host
    html = render_html(current, None, STAMP, results, None)
    for d in results["detections"]:
        for c in d["contributing"]:
            if c["type"] == "finding":
                assert f'id="{c["id"]}"' in html and f'href="#{c["id"]}"' in html
    for e in {i for d in results["detections"] for i in d["evidence"]}:
        assert f'id="{e}"' in html  # the evidence index defines every anchor a detection links to


def test_investigation_status_and_notes_are_shown() -> None:
    current = doc(linux_compromised(), aid="rep2")
    results = detect(current, RS, generated_at=STAMP)
    d0 = results["detections"][0]["id"]
    cases = case_summaries(None, results)
    cases[d0] = {
        **cases[d0],
        "status": "investigating",
        "tracked": True,
        "notes": 2,
        "last_note": "asked the owner <script>alert(1)</script>",
        "reappeared": True,
        "related": [results["detections"][1]["id"]],
    }
    html = render_html(current, None, STAMP, results, cases)
    assert (
        'data-status="investigating"' in html
        and "2 note(s)" in html
        and "observed again after being closed" in html
    )
    assert (
        "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    )
    assert f'href="#{results["detections"][1]["id"]}"' in html
    md = render_detections_markdown(results, cases)
    assert (
        "status **investigating**" in md
        and "observed again after being closed" in md
        and "<script>" not in md
    )


def test_hostile_values_cannot_inject_markup() -> None:
    evil = '"><img src=x onerror=alert(1)><script>alert(2)</script>'
    f = {**finding("TST-AAA-001", "high", "users", "/srv/x", excerpt=evil), "title": evil}
    rule = make_rule(
        title="Hit {a.title}",
        name="Rule <b>name</b>",
        rationale="Because <i>reasons</i> are given here.",
        remediation="Do <u>this</u> now please.",
    )
    current = doc(
        {"findings": [f], "inventory": [record("users", evil, {"uid": "5"})]}, host="h" + evil
    )
    results = detect(current, rule_set(rule), generated_at=STAMP)
    html = render_html(current, None, STAMP, results, None)
    p = _check_html(html)
    assert (
        p.scripts == 1
        and "<img" not in html
        and "onerror=alert(1)>" not in html.replace("onerror=alert(1)&gt;", "")
    )
    md = render_markdown(current, None, STAMP, results, None)
    body = "\n".join(line for line in md.splitlines() if not line.startswith("> "))
    assert not re.search(r"(?<!\\)<(script|img|b|i|u)\b", body)


def test_markdown_report_contains_a_detections_section_and_standalone_report_works(
    host: tuple[dict[str, Any], dict[str, Any]],
) -> None:
    current, results = host
    md = render_markdown(current, None, STAMP, results, None)
    assert "## Detections" in md and "### HIGH" in md.replace("#### ", "### ") or "HIGH ·" in md
    assert md.index("## Detections") < md.index("## Errors and warnings")
    standalone = render_detections_markdown(results)
    assert (
        standalone.startswith("# BlueOps detection report")
        and "## Overview" in standalone
        and "## Detections" in standalone
    )
    assert "A detection is a lead for investigation, not a verdict." in standalone
    for label in NATURE_LABEL.values():
        assert label in standalone or label not in {
            NATURE_LABEL[d["nature"]] for d in results["detections"]
        }
    assert standalone.endswith("\n") and "\n\n\n" not in standalone.replace("\n\n\n\n", "")


def test_reports_without_detections_are_unchanged() -> None:
    current = doc({"findings": [finding("TST-AAA-001")]})
    plain = render_html(current, None, STAMP)
    assert 'id="detections"' not in plain and "Detections" not in plain
    assert render_markdown(current, None, STAMP) == render_markdown(
        current, None, STAMP, None, None
    )


def test_empty_detection_set_renders_cleanly() -> None:
    current = doc({"findings": [finding("TST-AAA-001")]})
    results = detect(
        current,
        rule_set(
            make_rule(
                id="DR-TST-NON-001",
                clauses=[
                    {
                        "id": "a",
                        "source": "findings",
                        "description": "d",
                        "where": {"field": "check_id", "op": "eq", "value": "NOPE-NOPE-001"},
                    }
                ],
            )
        ),
        generated_at=STAMP,
    )
    html = render_html(current, None, STAMP, results, None)
    _check_html(html)
    assert "No detections." in html
    assert "No detections." in render_detections_markdown(results)


def test_rule_errors_and_indeterminate_rules_are_visible() -> None:
    from shared.rules.loader import RuleSet
    from shared.rules.validate import Diagnostic

    current = doc({"findings": [finding("TST-ZZZ-001", "low", "network")]})
    rs = rule_set(make_rule(requires_coverage=["module:users"]))
    rs.diagnostics.append(Diagnostic("error", "rules[3]", "broken", "DR-TST-BRK-001"))
    results = detect(current, rs, generated_at=STAMP)
    html = render_html(current, None, STAMP, results, None)
    assert "Rule errors (1)" in html and "Rules that could not reach a conclusion (1)" in html
    assert "Not evaluated is not the same as clean" in html and isinstance(rs, RuleSet)
    md = render_detections_markdown(results)
    assert "## Rule errors" in md and "## Rules that could not reach a conclusion" in md
