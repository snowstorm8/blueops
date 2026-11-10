"""`python -m shared.engine validate ...`: CLI behavior, exit codes, reports and rendering."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from validation_support import make_store, proc, scn, tr, write_pack

from shared.engine.cli import main
from shared.reporting.schema_lite import validate
from shared.validation import render
from shared.validation.calibrate import recommend
from shared.validation.model import load_scenarios
from shared.validation.runner import run_scenarios, telemetry_rule_set

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / "shared" / "rules" / "library" / "telemetry-hunting.json"


def call(capsys, *argv):
    capsys.readouterr()
    try:
        rc = main([str(a) for a in argv])
    except SystemExit as exc:
        rc = int(exc.code)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


@pytest.fixture(scope="module")
def library_results():
    ss = load_scenarios()
    return run_scenarios(ss.ordered(), ss, telemetry_rule_set(), recommend=recommend)


# ------------------------------------------------------------------ list / show


def test_list_filters_and_formats(capsys):
    rc, out, _ = call(capsys, "validate", "list", "--platform", "windows", "--kind", "coverage")
    assert rc == 0 and "SCN-WIN-AUT-005" in out and "SCN-LNX" not in out
    rc, out, _ = call(capsys, "validate", "list", "--tag", "known-issue", "--format", "json")
    assert {s["id"] for s in json.loads(out)["scenarios"]} == {"SCN-LNX-PRC-004", "SCN-LNX-PRC-006"}


def test_show_prints_expectations_limitations_and_known_issues(capsys):
    rc, out, _ = call(capsys, "validate", "show", "SCN-LNX-PRC-004")
    assert (
        rc == 0
        and "KNOWN ISSUE" in out
        and "expects no detection: DR-ANY-HPRC-001" in out
        and "limitation:" in out
    )
    rc, out, _ = call(capsys, "validate", "show", "SCN-LNX-AUT-010", "--format", "json")
    assert json.loads(out)["scenario"]["kind"] == "coverage"
    assert call(capsys, "validate", "show", "SCN-NOPE-XXX-999")[0] == 3


# ------------------------------------------------------------------ run / evaluate / dry-run


def test_run_all_exits_zero_with_known_issues_and_prints_a_summary(capsys):
    rc, out, _ = call(capsys, "validate", "run")
    assert (
        rc == 0
        and "scenarios: 84" in out
        and "known_issue=2" in out
        and "synthetic data only" in out
    )
    assert "[known issue] SCN-LNX-PRC-004" in out


def test_run_json_output_is_schema_valid_and_selection_filters_apply(capsys, tmp_path):
    rc, out, _ = call(
        capsys, "validate", "run", "--platform", "linux", "--kind", "negative", "--format", "json"
    )
    doc = json.loads(out)
    assert rc == 0 and validate(doc, "validation-results.schema.json") == []
    assert all(s["kind"] == "negative" and "linux" in s["platforms"] for s in doc["scenarios"])
    rc, out, _ = call(
        capsys, "validate", "run", "--scenario", "SCN-LNX-PRC-001", "--format", "json"
    )
    assert [s["id"] for s in json.loads(out)["scenarios"]] == ["SCN-LNX-PRC-001"]
    assert call(capsys, "validate", "run", "--scenario", "SCN-NOPE-XXX-999")[0] == 3


def test_dry_run_builds_datasets_and_executes_nothing(capsys, tmp_path):
    rc, out, _ = call(
        capsys,
        "validate",
        "run",
        "--dry-run",
        "--history-dir",
        tmp_path / "h",
        "--results-out",
        tmp_path / "r.json",
    )
    assert (
        rc == 0
        and "DRY RUN" in out
        and "nothing on this host is modified" in out
        and "84 scenario(s)" in out
    )
    assert not (tmp_path / "h").exists() and not (tmp_path / "r.json").exists()
    rc, out, _ = call(
        capsys, "validate", "run", "--dry-run", "--format", "json", "--scenario", "SCN-LNX-PRC-001"
    )
    d = json.loads(out)
    assert d["executes_nothing"] is True and d["scenarios"][0]["modifies_host"] is False


def test_dry_run_reports_unbuildable_datasets(capsys, tmp_path):
    bad = write_pack(
        tmp_path,
        [
            scn(
                dataset={
                    "platform": "linux",
                    "records": [{"category": "nonsense", "key": "k", "attributes": {}}],
                }
            )
        ],
    )
    rc, out, _ = call(capsys, "validate", "evaluate", bad, "--dry-run")
    assert rc == 3 and "PROBLEM" in out and "rejected" in out


def test_evaluate_custom_packs_only_and_failures_exit_four(capsys, tmp_path):
    ok = write_pack(tmp_path, [scn()])
    rc, out, _ = call(capsys, "validate", "evaluate", ok, "--format", "json")
    doc = json.loads(out)
    assert rc == 0 and [s["id"] for s in doc["scenarios"]] == ["SCN-LNX-PRC-001"], (
        "the library is not loaded unless asked"
    )
    miss = write_pack(
        tmp_path,
        [
            scn(
                dataset={
                    "platform": "linux",
                    "records": [proc(100, 1, "nginx"), proc(200, 100, "cat")],
                }
            )
        ],
        name="miss",
    )
    rc, out, _ = call(capsys, "validate", "evaluate", miss)
    assert rc == 4 and "fail" in out


def test_inconclusive_and_error_runs_exit_six(capsys, tmp_path, monkeypatch):
    inc = write_pack(
        tmp_path,
        [
            scn(
                kind="negative",
                expect={"absent": ["DR-ANY-HPRC-001"]},
                dataset={
                    "platform": "linux",
                    "records": [proc(1, 0, "x")],
                    "coverage": {"process": "unavailable"},
                },
            )
        ],
    )
    assert call(capsys, "validate", "evaluate", inc)[0] == 6
    from shared.rules import engine

    real = engine.evaluate_rule
    monkeypatch.setattr(
        engine,
        "evaluate_rule",
        lambda r, c, s: (
            (_ for _ in ()).throw(RuntimeError("boom"))
            if r.id == "DR-ANY-HPRC-001"
            else real(r, c, s)
        ),
    )
    ok = write_pack(tmp_path, [scn()], name="okk")
    rc, out, _ = call(capsys, "validate", "evaluate", ok)
    assert rc == 6 and "error" in out


def test_invalid_packs_and_unknown_rules_are_refused_with_diagnostics(capsys, tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    rc, _, err = call(capsys, "validate", "evaluate", p)
    assert rc == 3 and "scenario problem" in err
    typo = write_pack(
        tmp_path, [scn(expect={"detections": [{"rule": "DR-ANY-HPRC-999"}]})], name="typo"
    )
    rc, _, err = call(capsys, "validate", "evaluate", typo)
    assert rc == 3 and "unknown rule DR-ANY-HPRC-999" in err


def test_outputs_are_written_exclusively(capsys, tmp_path):
    target = tmp_path / "r.html"
    assert (
        call(
            capsys,
            "validate",
            "run",
            "--scenario",
            "SCN-LNX-PRC-001",
            "--format",
            "html",
            "--output",
            target,
        )[0]
        == 0
    )
    assert "<!doctype html>" in target.read_text()
    rc, _, err = call(
        capsys,
        "validate",
        "run",
        "--scenario",
        "SCN-LNX-PRC-001",
        "--format",
        "html",
        "--output",
        target,
    )
    assert rc == 3 and "refusing to overwrite" in err


# ------------------------------------------------------------------ history and regressions through the CLI


def relaxed_rules(tmp_path):
    doc = json.loads(LIB.read_text())
    for rule in doc["rules"]:
        if rule["id"] == "DR-ANY-HPRC-002":
            rule["clauses"][0]["where"] = {"field": "category", "op": "eq", "value": "process"}
    path = tmp_path / "rules" / "hunting.json"
    path.parent.mkdir()
    path.write_text(json.dumps(doc))
    return path


def test_history_compare_latest_detects_a_rule_regression(capsys, tmp_path):
    hist = tmp_path / "hist"
    assert call(capsys, "validate", "run", "--history-dir", hist, "--format", "text")[0] == 0
    rc, out, _ = call(
        capsys,
        "validate",
        "run",
        "--history-dir",
        hist,
        "--compare-latest",
        "--no-rule-library",
        "--rules-dir",
        relaxed_rules(tmp_path),
        "--format",
        "markdown",
    )
    assert rc == 4 and "## Regression findings" in out and "DR-ANY-HPRC-002" in out
    assert len(list(hist.glob("validation-run-*.json"))) == 2


def test_compare_two_saved_runs_and_report_them(capsys, tmp_path):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    assert call(capsys, "validate", "run", "--format", "json", "--output", a)[0] == 0
    assert (
        call(
            capsys,
            "validate",
            "run",
            "--no-rule-library",
            "--rules-dir",
            relaxed_rules(tmp_path),
            "--format",
            "json",
            "--output",
            b,
        )[0]
        == 4
    )
    rc, out, _ = call(capsys, "validate", "compare", a, b)
    cmp = json.loads(out)
    assert (
        rc == 4
        and validate(cmp, "validation-comparison.schema.json") == []
        and cmp["summary"]["regressions"] > 0
    )
    assert call(capsys, "validate", "compare", a, a, "--format", "text")[0] == 0
    rc, out, _ = call(capsys, "validate", "compare", a, b, "--format", "markdown")
    assert "# Validation comparison" in out and "precision_decreased" not in out
    cmp_file = tmp_path / "cmp.json"
    cmp_file.write_text(json.dumps(cmp))
    rc, out, _ = call(
        capsys, "validate", "report", b, "--comparison", cmp_file, "--format", "markdown"
    )
    assert rc == 0 and "Regression findings" in out


def test_report_formats_and_calibrate(capsys, tmp_path, library_results):
    res = tmp_path / "res.json"
    res.write_text(json.dumps(library_results))
    for fmt, needle in (
        ("markdown", "# BlueOps validation report"),
        ("html", "<svg"),
        ("text", "Validation run"),
        ("json", '"kind": "validation-results"'),
    ):
        rc, out, _ = call(capsys, "validate", "report", res, "--format", fmt)
        assert rc == 0 and needle in out, fmt
    rc, out, _ = call(capsys, "validate", "calibrate", res)
    assert (
        rc == 0
        and "nothing is changed" in out
        and "REC-DR-ANY-HPRC-001-reduce_false_positives" in out
    )
    assert call(capsys, "validate", "report", tmp_path / "missing.json")[0] == 3
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert call(capsys, "validate", "report", bad)[0] == 3


def test_the_legacy_schema_validate_command_still_works(capsys):
    doc = ROOT / "tests" / "fixtures" / "rules" / "linux-compromised.assessment.json"
    rc, out, _ = call(capsys, "validate", doc)
    assert rc == 0 and "valid" in out.lower()
    assert call(capsys, "validate", "run", "--help")[0] == 0


# ------------------------------------------------------------------ baseline commands


def test_baseline_capture_check_diff_workflow(capsys, tmp_path):
    base = make_store(tmp_path, [tr("service", "s", {"name": "a", "path": "/x"})], name="b")
    cur_ok = make_store(
        tmp_path,
        [tr("service", "s", {"name": "a", "path": "/x"})],
        started="2026-03-08T10:00:00Z",
        cid="c1",
        name="c1",
    )
    cur_new = make_store(
        tmp_path,
        [
            tr("service", "s", {"name": "a", "path": "/x"}),
            tr("service", "s2", {"name": "b", "path": "/y"}),
        ],
        started="2026-03-08T10:00:00Z",
        cid="c2",
        name="c2",
    )
    allow = tmp_path / "allow.json"
    allow.write_text(
        json.dumps(
            [
                {
                    "category": "service",
                    "change": "added",
                    "identity_pattern": "^service:nothing$",
                    "reason": "n/a",
                }
            ]
        )
    )
    rc, out, _ = call(
        capsys,
        "validate",
        "baseline",
        "capture",
        base,
        "--name",
        "kg",
        "--output-dir",
        tmp_path / "bl",
        "--expected-changes",
        allow,
        "--purpose",
        "lab",
    )
    assert rc == 0 and "baseline stored in" in out
    bl = tmp_path / "bl" / "kg"
    rc, out, _ = call(capsys, "validate", "baseline", "show", bl)
    assert rc == 0 and "kg:" in out
    rc, out, _ = call(capsys, "validate", "baseline", "check", bl, "--against", cur_ok)
    assert rc == 0 and "NOT_LAB_ATTESTED" in out
    assert call(capsys, "validate", "baseline", "diff", bl, cur_ok)[0] == 0
    rc, out, _ = call(capsys, "validate", "baseline", "diff", bl, cur_new)
    d = json.loads(out)
    assert (
        rc == 4
        and d["summary"]["unexpected"] == 1
        and validate(d, "validation-baseline-diff.schema.json") == []
    )
    rc, out, _ = call(capsys, "validate", "compare", bl, cur_new, "--format", "markdown")
    assert rc == 4 and "A difference is not a finding" in out and "why it matters" in out
    rc, out, _ = call(capsys, "validate", "baseline", "diff", bl, cur_new, "--format", "text")
    assert "unexpected" in out
    assert (
        call(
            capsys,
            "validate",
            "baseline",
            "capture",
            base,
            "--name",
            "kg",
            "--output-dir",
            tmp_path / "bl",
        )[0]
        == 3
    )


def test_baseline_check_exit_codes_for_incompatible_and_stale(capsys, tmp_path):
    base = make_store(tmp_path, [tr("service", "s", {"name": "a"})], name="b")
    other = make_store(tmp_path, [tr("service", "s", {"name": "a"})], host="other", name="o")
    from shared.validation.baseline import capture_baseline

    old = capture_baseline(base, tmp_path / "bl", "old", captured_at="2020-01-01T00:00:00Z")
    rc, out, _ = call(capsys, "validate", "baseline", "check", old)
    assert rc == 6 and "STALE" in out
    rc, out, _ = call(capsys, "validate", "baseline", "check", old, "--against", other)
    assert rc == 3 and "HOST_MISMATCH" in out
    assert call(capsys, "validate", "baseline", "diff", old, other)[0] == 3


# ------------------------------------------------------------------ rendering


HOSTILE = '<script>alert(1)</script> & "quotes" `ticks` | pipe'


def hostile_results(tmp_path):
    s = scn(
        title="Hostile " + HOSTILE,
        description=HOSTILE,
        dataset={"platform": "linux", "records": [proc(100, 1, "nginx"), proc(200, 100, "cat")]},
        limitations=[HOSTILE],
    )
    ss = load_scenarios([write_pack(tmp_path, [s])], include_library=False)
    return run_scenarios(ss.ordered(), ss, telemetry_rule_set(), recommend=recommend)


def test_html_is_self_contained_escaped_and_has_charts(tmp_path, library_results):
    page = render.render_html(library_results)
    assert (
        "Content-Security-Policy" in page
        and "<script" not in page.lower()
        and "http://" not in page
        and "https://" not in page.replace("https://json-schema", "")
    )
    assert (
        page.count("<svg") == 2 and "Per-rule performance" in page and "Scenario outcomes" in page
    )
    for section in (
        "Per platform",
        "False-positive analysis",
        "False-negative analysis",
        "Coverage gaps",
        "Calibration recommendations",
        "Reproducibility",
        "Metric definitions",
    ):
        assert section in page, section


def test_hostile_text_is_escaped_in_every_format(tmp_path):
    res = hostile_results(tmp_path)
    res["scenarios"][0]["reason"] = HOSTILE
    for out in (render.render_html(res), render.render_markdown(res), render.render_text(res)):
        assert "<script>" not in out
    assert "&lt;script&gt;" in render.render_html(res)


def test_undefined_metrics_render_as_na_never_zero_or_perfect(tmp_path):
    ss = load_scenarios(
        [
            write_pack(
                tmp_path,
                [
                    scn(
                        kind="negative",
                        expect={"absent": ["DR-ANY-HPRC-001"]},
                        dataset={"platform": "linux", "records": [proc(1, 0, "systemd")]},
                    )
                ],
            )
        ],
        include_library=False,
    )
    res = run_scenarios(ss.ordered(), ss, telemetry_rule_set(), recommend=recommend)
    g = res["metrics"]["global"]
    assert g["precision"]["value"] is None and g["recall"]["value"] is None
    text = render.render_text(res)
    assert (
        "precision n/a" in text
        and "recall    n/a" in text
        and "precision 0" not in text
        and "precision 1" not in text
    )
    page = render.render_html(res)
    assert "n/a (undefined)" in page or "n/a" in page
    md = render.render_markdown(res)
    assert re.search(r"\| precision \| n/a", md)


def test_failures_are_listed_not_hidden_behind_the_aggregate(tmp_path, library_results):
    md = render.render_markdown(library_results)
    assert "[known issue]" in render.render_text(library_results)
    assert (
        "(known issue)" in md
        and "SCN-LNX-PRC-004" in md.split("## False-positive analysis")[1].split("##")[0]
    )
    bad = hostile_results(tmp_path)
    assert bad["summary"]["exit_status"] == "failures"
    assert "## False-negative analysis" in render.render_markdown(
        bad
    ) and "fail" in render.render_text(bad)


def test_reports_contain_reproducibility_metadata(library_results):
    md = render.render_markdown(library_results)
    assert library_results["reproducibility"]["digest"] in md and "Scenario packs" in md
