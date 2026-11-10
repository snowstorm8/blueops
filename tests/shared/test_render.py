"""Markdown and HTML reports: structure, escaping of hostile data, self-containment."""

from __future__ import annotations

import base64
import hashlib
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from engine_support import fake_assessment, fnd, make_report

from shared.engine.runner import ExecResult
from shared.reporting.render_common import (
    RenderError,
    check_assessment,
    coverage_caveats,
    executive_summary,
    findings_by_category,
    posture,
    remediation_plan,
)
from shared.reporting.render_html import CSS, JS, render_html
from shared.reporting.render_markdown import code, esc, render_comparison_markdown, render_markdown
from shared.reporting.snapshot_compare import compare_snapshots

XSS = "<script>alert(1)</script><img src=x onerror=alert(2)>\"'&"
VOID = {"meta", "br", "input", "img", "link", "hr"}


class _Balanced(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.errors: list[str] = []
        self.scripts = 0
        self.external: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "script":
            self.scripts += 1
        for k, v in attrs:
            if k in ("src", "srcset", "data") or (k == "href" and tag == "link"):
                self.external.append(f"{tag}[{k}]={v}")
            if k.startswith("on"):
                self.errors.append(f"inline handler {k} on <{tag}>")
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unbalanced </{tag}> (open: {self.stack[-3:]})")
        else:
            self.stack.pop()


def _check_html(html: str) -> _Balanced:
    p = _Balanced()
    p.feed(html)
    assert p.errors == [] and p.stack == [], (p.errors, p.stack)
    return p


@pytest.fixture
def doc(tmp_path: Path) -> dict[str, Any]:
    reports = {
        "linux.users": make_report(
            [
                fnd("USR-AAA-001", "critical", evidence=[("file", "/etc/passwd")]),
                fnd("USR-BBB-001", "low"),
            ]
        ),
        "linux.net": make_report([fnd("NET-CCC-001", "info", category="network")], run="r2"),
    }
    return fake_assessment(tmp_path, reports).document


@pytest.fixture
def hostile(tmp_path: Path) -> dict[str, Any]:
    f = fnd("USR-AAA-001", "high", evidence=[("file", XSS)])
    f["title"] = XSS
    f["description"] = XSS
    f["remediation"] = XSS
    rep = make_report([f], host="host" + XSS)
    return fake_assessment(tmp_path, {"linux.users": rep}).document


# ------------------------------------------------------------------------------- HTML


def test_html_is_well_formed_and_complete(doc: dict[str, Any]) -> None:
    html = render_html(doc, generated_at="2026-03-01T12:00:00Z")
    _check_html(html)
    assert html.startswith("<!DOCTYPE html>") and '<html lang="en">' in html
    for section in (
        "summary",
        "metadata",
        "modules",
        "priorities",
        "findings",
        "evidence",
        "history",
        "problems",
    ):
        assert f'id="{section}"' in html and f'href="#{section}"' in html
    for needle in (
        "Executive summary",
        "Severity distribution",
        "Remediation priorities",
        "Evidence index",
        "Historical comparison",
        "web01",
        "USR-AAA-001",
        "/etc/passwd",
        "viewport",
    ):
        assert needle in html


def test_html_has_no_external_resources_and_one_pinned_script(doc: dict[str, Any]) -> None:
    html = render_html(doc)
    p = _check_html(html)
    assert p.external == [] and p.scripts == 1
    assert not re.search(
        r"""(?:src|href)=["']https?://""", html.replace("https://attack.mitre.org", "")
    )
    assert "@import" not in CSS and "url(" not in CSS
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html)
    assert csp
    policy = unescape(csp.group(1))
    assert (
        "default-src 'none'" in policy
        and "unsafe-eval" not in policy
        and "script-src 'unsafe-inline'" not in policy
    )
    digest = base64.b64encode(hashlib.sha256(JS.encode()).digest()).decode()
    assert f"'sha256-{digest}'" in policy
    assert f"<script>{JS}</script>" in html  # the hash covers exactly the emitted script


def test_html_escapes_hostile_values(hostile: dict[str, Any]) -> None:
    html = render_html(hostile)
    p = _check_html(html)
    assert p.scripts == 1  # only ours
    assert "<script>alert" not in html and "onerror=alert" not in html.replace(
        "onerror=alert(2)&gt;", ""
    )
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img" not in html


def test_html_attribute_injection_in_data_text(hostile: dict[str, Any]) -> None:
    html = render_html(hostile)
    m = re.search(r'data-text="([^"]*)"', html)
    assert m and "<" not in m.group(1) and '"' not in m.group(1)


def test_html_is_deterministic(doc: dict[str, Any]) -> None:
    assert render_html(doc, generated_at="t") == render_html(doc, generated_at="t")


def test_html_responsive_and_accessible_basics(doc: dict[str, Any]) -> None:
    html = render_html(doc)
    assert "@media (max-width:560px)" in html and "prefers-color-scheme:dark" in html
    assert 'aria-label="Filter findings"' in html and 'role="img"' in html
    assert re.search(
        r'class="sev critical">critical</span>', html
    )  # severity is text, not colour alone


def test_html_with_no_findings_and_no_host(tmp_path: Path) -> None:
    ok = fake_assessment(tmp_path / "a", {"linux.a": make_report([])}).document
    html = render_html(ok)
    _check_html(html)
    assert "No actionable findings" in html and "No findings." in html
    dead = fake_assessment(
        tmp_path / "b", {"linux.a": lambda: ExecResult(None, error="cannot start: x")}
    ).document
    html = render_html(dead)
    _check_html(html)
    assert "unidentified host" in html and "unavailable" in html


def test_html_shows_failed_modules_and_caveats(tmp_path: Path) -> None:
    d = fake_assessment(
        tmp_path,
        {
            "linux.a": make_report([fnd("USR-AAA-001")]),
            "linux.b": lambda: ExecResult(None, timed_out=True),
        },
    ).document
    html = render_html(d)
    _check_html(html)
    assert (
        "Coverage caveats" in html
        and "linux.b finished as timeout" in html
        and "status timeout" in html
    )


def test_html_includes_history_when_comparisons_are_given(tmp_path: Path) -> None:
    a = fake_assessment(
        tmp_path / "a", {"linux.users": make_report([fnd("USR-AAA-001", "high")])}
    ).document
    b = fake_assessment(
        tmp_path / "b",
        {
            "linux.users": make_report(
                [fnd("USR-BBB-001", "low")],
                run="r2",
                start="2026-03-02T10:00:00Z",
                end="2026-03-02T10:05:00Z",
            )
        },
        clock_start="2026-03-02T10:00:00Z",
    ).document
    cmp_doc = compare_snapshots(a, b, generated_at="2026-03-03T00:00:00Z")
    html = render_html(b, [cmp_doc])
    _check_html(html)
    assert (
        "New findings (1)" in html
        and "Resolved findings (1)" in html
        and "No earlier snapshot" not in html
    )
    md = render_markdown(b, [cmp_doc])
    assert "## Historical comparison" in md and "Resolved" in md
    assert "Compared with the previous snapshot" in md


# ---------------------------------------------------------------------------- Markdown


def test_markdown_structure(doc: dict[str, Any]) -> None:
    md = render_markdown(doc, generated_at="2026-03-01T12:00:00Z")
    for heading in (
        "# BlueOps assessment report",
        "## Executive summary",
        "## Assessment metadata",
        "## Host",
        "## Severity distribution",
        "## Module results",
        "## Remediation priorities",
        "## Findings",
        "## Evidence index",
        "## Errors and warnings",
    ):
        assert heading in md
    assert (
        "### P1 - " in md and "USR\\-AAA\\-001" not in md
    )  # check ids are code spans, not escaped text
    assert md.endswith("\n") and not md.endswith("\n\n")


def test_markdown_neutralises_hostile_values(hostile: dict[str, Any]) -> None:
    md = render_markdown(hostile)
    body = "\n".join(line for line in md.splitlines() if not line.startswith("> "))  # our own quote
    assert not re.search(r"(?<!\\)[<>]", body)  # no unescaped angle bracket from report data
    assert "\\<script\\>" in md
    for line in md.splitlines():  # no value may start a new heading or table row of its own
        if "alert(1)" in line:
            assert not line.startswith("#") or line.startswith("####"), line


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a|b", "a\\|b"),
        ("*bold* _it_", "\\*bold\\* \\_it\\_"),
        ("[x](http://e.invalid)", "\\[x\\]\\(http://e.invalid\\)"),
        ("line1\nline2\r\n# h", "line1 line2 \\# h"),
        (None, ""),
    ],
)
def test_esc(raw: Any, expected: str) -> None:
    assert esc(raw) == expected


def test_esc_caps_length_and_code_handles_backticks() -> None:
    assert len(esc("x" * 1000)) == 300
    assert code("a`b") == "``a`b``"
    assert code("`edge`") == "`` `edge` ``"
    assert "|" not in code("a|b")


def test_comparison_markdown(tmp_path: Path) -> None:
    a = fake_assessment(
        tmp_path / "a", {"linux.users": make_report([fnd("USR-AAA-001", "high")])}
    ).document
    b = fake_assessment(
        tmp_path / "b",
        {
            "linux.users": make_report(
                [], run="r2", start="2026-03-02T10:00:00Z", end="2026-03-02T10:05:00Z"
            )
        },
        clock_start="2026-03-02T10:00:00Z",
    ).document
    md = render_comparison_markdown(compare_snapshots(a, b))
    assert (
        "## Resolved findings" in md
        and "Trend: **better**" in md
        and "## Coverage differences" in md
    )


# ------------------------------------------------------------------------- shared logic


def test_posture_follows_the_worst_severity() -> None:
    base = {"by_severity": dict.fromkeys(("info", "low", "medium", "high", "critical"), 0)}
    assert posture(base)[1] == "info"
    for sev, key in (
        ("low", "low"),
        ("medium", "medium"),
        ("high", "high"),
        ("critical", "critical"),
    ):
        s = {"by_severity": {**base["by_severity"], sev: 1}}
        assert posture(s)[1] == key


def test_remediation_plan_orders_by_priority_then_severity(doc: dict[str, Any]) -> None:
    plan = remediation_plan(doc)
    assert [f["check_id"] for f in plan["P1"]] == ["USR-AAA-001"]
    assert all(f["remediation"]["summary"] for items in plan.values() for f in items)


def test_findings_grouped_with_worst_category_first(doc: dict[str, Any]) -> None:
    groups = findings_by_category(doc)
    assert [g for g, _ in groups][0] == "users"
    assert [f["severity"] for f in groups[0][1]] == ["critical", "low"]


def test_executive_summary_and_caveats(doc: dict[str, Any]) -> None:
    s = executive_summary(doc)
    assert s["headline"] == "Immediate attention required" and "3 finding(s)" in s["bullets"][0]
    assert coverage_caveats(doc) == []
    doc = {**doc, "host": {**doc["host"], "elevated": False}}
    assert any("without administrator" in c for c in coverage_caveats(doc))


def test_wrong_document_kind_is_refused() -> None:
    with pytest.raises(RenderError):
        check_assessment({"kind": "snapshot-comparison"})
    with pytest.raises(RenderError):
        check_assessment([])
