"""Detection CLI: commands, exit codes, malformed input, export safety."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest
from rules_support import doc, finding, make_rule, record

from shared.engine.cli import main
from shared.reporting.schema_lite import validate

UID0 = {
    "inventory": [
        record("users", "user:root", {"uid": "0"}),
        record("users", "user:toor", {"uid": "0"}),
    ]
}
TWO_HITS = {
    "inventory": [
        *UID0["inventory"],
        record(
            "listeners",
            "listener:tcp/0.0.0.0/23",
            {"proto": "tcp", "bind": "0.0.0.0", "port": "23", "process": "telnetd"},
        ),
    ]
}
CLEAN = {
    "inventory": [record("users", "user:root", {"uid": "0"})],
    "findings": [finding("SYS-INFO-001", "info", "system")],
}


def call(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    rc = main(list(argv))
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def save(tmp_path: Path, name: str, spec: dict[str, Any], **kw: Any) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(doc(spec, **kw)), encoding="utf-8")
    return p


@pytest.fixture
def current(tmp_path: Path) -> Path:
    return save(tmp_path, "cur.json", TWO_HITS, aid="cur", started="2026-03-01T10:00:00Z")


# ---------------------------------------------------------------------------------- rules


def test_rules_list_filters_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, _ = call(capsys, "rules", "list")
    assert (
        rc == 0
        and "DR-LNX-ACC-001" in out
        and "DR-WIN-SVC-001" in out
        and out.strip().endswith("rule(s)")
    )
    rc, out, _ = call(capsys, "rules", "list", "--platform", "windows", "--json")
    rows = json.loads(out)
    assert rc == 0 and rows and all("windows" in r["platforms"] for r in rows)
    rc, out, _ = call(
        capsys, "rules", "list", "--nature", "correlated", "--min-severity", "high", "--json"
    )
    assert all(
        r["nature"] == "correlated" and r["severity"] in ("high", "critical")
        for r in json.loads(out)
    )
    rc, out, _ = call(capsys, "rules", "list", "--disable", "DR-LNX-ACC-001")
    assert "DR-LNX-ACC-001" in out and "(disabled)" in out


def test_rules_show_and_unknown_rule(capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, _ = call(capsys, "rules", "show", "DR-LNX-ACC-001")
    assert rc == 0 and "Non-root account with UID 0" in out and "T1136.001" in out
    rc, out, _ = call(capsys, "rules", "show", "DR-LNX-ACC-001", "--json")
    assert json.loads(out)["id"] == "DR-LNX-ACC-001"
    rc, _, err = call(capsys, "rules", "show", "DR-NOP-NOPE-001")
    assert rc == 2 and "unknown rule" in err


def test_rules_validate_good_and_bad_packs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = tmp_path / "good.json"
    good.write_text(
        json.dumps(
            {
                "schema_version": "0.1.0",
                "kind": "rule-pack",
                "pack": {"name": "mine", "version": "1.0.0"},
                "rules": [
                    make_rule(
                        id="DR-TST-OK-001",
                        examples=[
                            {
                                "name": "y",
                                "expect": "match",
                                "current": {"findings": [finding("TST-AAA-001")]},
                            },
                            {"name": "n", "expect": "no_match", "current": {}},
                        ],
                    )
                ],
            }
        ),
        encoding="utf-8",
    )
    rc, out, _ = call(capsys, "rules", "validate", str(good), "--examples")
    assert rc == 0 and "1 rule(s) valid, 0 error(s), 0 failing example(s)" in out
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "schema_version": "0.1.0",
                "kind": "rule-pack",
                "pack": {"name": "mine", "version": "1.0.0"},
                "rules": [
                    make_rule(id="DR-TST-BAD-001", severity="urgent"),
                    make_rule(
                        id="DR-TST-ALT-001",
                        clauses=[
                            {
                                "id": "a",
                                "source": "findings",
                                "description": "d",
                                "where": {"field": "nope", "op": "eq", "value": 1},
                            }
                        ],
                    ),
                ],
            }
        ),
        encoding="utf-8",
    )
    rc, out, err = call(capsys, "rules", "validate", str(bad))
    assert (
        rc == 3
        and "DR-TST-BAD-001" in err
        and "field 'nope' does not exist" in err
        and "0 rule(s) valid, 2 error(s)" in out
    )
    rc, out, _ = call(capsys, "rules", "validate", str(bad), "--json")
    assert rc == 3 and len(json.loads(out)["diagnostics"]) >= 2
    notjson = tmp_path / "x.json"
    notjson.write_text("{", encoding="utf-8")
    assert call(capsys, "rules", "validate", str(notjson))[0] == 3
    assert call(capsys, "rules", "validate", str(tmp_path / "missing.json"))[0] == 3


def test_rules_validate_with_examples_reports_failing_examples(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wrong = make_rule(
        id="DR-TST-WRG-001",
        examples=[
            {"name": "claims a match", "expect": "match", "current": {}},
            {"name": "n", "expect": "no_match", "current": {}},
        ],
    )
    p = tmp_path / "wrong.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "0.1.0",
                "kind": "rule-pack",
                "pack": {"name": "mine", "version": "1.0.0"},
                "rules": [wrong],
            }
        ),
        encoding="utf-8",
    )
    rc, out, err = call(capsys, "rules", "validate", str(p), "--examples")
    assert rc == 3 and "claims a match" in err and "1 failing example" in out


def test_rules_test_and_docs(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    rc, out, _ = call(capsys, "rules", "test")
    assert rc == 0 and "example(s) passed" in out
    rc, out, _ = call(capsys, "rules", "test", "--rule", "DR-LNX-ACC-001")
    assert rc == 0 and out.startswith("4 of 4")
    target = tmp_path / "lib.md"
    assert call(capsys, "rules", "docs", "--output", str(target))[0] == 0
    assert target.read_text("utf-8").startswith("# Detection rule library")
    assert call(capsys, "rules", "docs", "--output", str(target))[0] == 3  # never overwrites


# --------------------------------------------------------------------------------- detect


def test_detect_run_json_and_exit_codes(current: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc, out, err = call(
        capsys, "detect", "run", str(current), "--generated-at", "2026-03-02T00:00:00Z"
    )
    res = json.loads(out)
    assert rc == 4 and validate(res, "detection-results.schema.json") == []
    assert (
        any(d["rule"]["id"] == "DR-LNX-ACC-001" for d in res["detections"])
        and "detection(s)" in err
    )
    rc, _, _ = call(capsys, "detect", "run", str(current), "--fail-on", "critical", "--quiet")
    assert rc == 6  # nothing reached critical, but other rules were indeterminate (no history)


def test_detect_run_clean_host(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    clean = save(
        tmp_path,
        "clean.json",
        {
            **CLEAN,
            "modules": {
                "system": "ok",
                "network": "ok",
                "users": "ok",
                "persistence": "ok",
                "filesystem": "ok",
                "pam": "ok",
                "sysconfig": "ok",
                "auth": "ok",
                "services": "ok",
            },
        },
    )
    rc, out, _ = call(capsys, "detect", "run", str(clean), "--quiet")
    res = json.loads(out)
    assert res["detections"] == [] and rc in (0, 6)


def test_detect_run_formats(
    current: Path, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    rc, out, _ = call(capsys, "detect", "run", str(current), "--format", "text", "--quiet")
    assert "DR-LNX-ACC-001" in out and "[HIGH" in out.upper()
    rc, out, _ = call(capsys, "detect", "run", str(current), "--format", "markdown", "--quiet")
    assert out.startswith("# BlueOps detection report") and "Account user:toor has UID 0" in out
    rc, out, _ = call(capsys, "detect", "run", str(current), "--format", "html", "--quiet")
    assert '<section id="detections">' in out and "Content-Security-Policy" in out
    target = tmp_path / "out.json"
    assert call(capsys, "detect", "run", str(current), "--output", str(target), "--quiet")[0] == 4
    assert json.loads(target.read_text("utf-8"))["kind"] == "detection-results"
    assert call(capsys, "detect", "run", str(current), "--output", str(target), "--quiet")[0] == 3


def test_detect_run_min_severity_and_rule_overrides(
    current: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, out, _ = call(
        capsys, "detect", "run", str(current), "--min-severity", "critical", "--quiet"
    )
    res = json.loads(out)
    assert (
        res["detections"] == [] and res["summary"]["total"] == 0
    )  # view filtered, exit reflects all
    assert rc == 4
    rc, out, _ = call(
        capsys, "detect", "run", str(current), "--disable", "DR-LNX-ACC-001", "--quiet"
    )
    assert all(d["rule"]["id"] != "DR-LNX-ACC-001" for d in json.loads(out)["detections"])
    rc, out, _ = call(
        capsys, "detect", "run", str(current), "--disable", "DR-NOP-NOPE-001", "--quiet"
    )
    errors = json.loads(out)["rule_errors"]  # an unknown override is a rule error, never ignored
    assert rc == 4 and any(
        e["code"] == "RULE_INVALID" and "unknown rule id" in e["message"] for e in errors
    )
    rc, out, _ = call(
        capsys,
        "detect",
        "run",
        str(current),
        "--disable",
        "DR-NOP-NOPE-001",
        "--min-severity",
        "critical",
        "--fail-on",
        "critical",
        "--quiet",
    )
    assert rc == 6


def test_detect_run_with_history_directory_and_previous(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    hist = tmp_path / "hist"
    hist.mkdir()
    save(hist, "a.json", CLEAN, aid="a", started="2026-02-01T10:00:00Z")
    save(hist, "b.json", CLEAN, aid="b", started="2026-02-02T10:00:00Z")
    cur = save(tmp_path, "cur.json", UID0, aid="cur", started="2026-03-01T10:00:00Z")
    rc, out, _ = call(capsys, "detect", "run", str(cur), "--history", str(hist), "--quiet")
    res = json.loads(out)
    assert res["history"]["snapshots"] == 2 and res["history"]["compared_with"] == "b"
    explicit = save(tmp_path, "p.json", CLEAN, aid="p", started="2026-02-15T10:00:00Z")
    rc, out, _ = call(capsys, "detect", "run", str(cur), "--previous", str(explicit), "--quiet")
    assert json.loads(out)["history"]["compared_with"] == "p"


def test_detect_run_rejects_bad_inputs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for bad in ("{", "[]", '{"kind": "mystery"}'):
        p = tmp_path / "bad.json"
        p.write_text(bad, encoding="utf-8")
        rc, _, err = call(capsys, "detect", "run", str(p))
        assert rc == 3 and "Traceback" not in err
    assert call(capsys, "detect", "run", str(tmp_path / "missing.json"))[0] == 3
    assert call(capsys, "detect", "run", str(tmp_path), "--history", str(tmp_path / "nope"))[0] == 3


def test_detect_compare_across_snapshots(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a = save(tmp_path, "a.json", CLEAN, aid="a", started="2026-02-01T10:00:00Z")
    b = save(tmp_path, "b.json", UID0, aid="b", started="2026-02-02T10:00:00Z")
    c = save(tmp_path, "c.json", CLEAN, aid="c", started="2026-02-03T10:00:00Z")
    rc, out, _ = call(capsys, "detect", "compare", str(a), str(b), str(c))
    cmp = json.loads(out)
    assert rc == 4 and validate(cmp, "detection-comparison.schema.json") == []
    states = {r["rule_id"]: r["state"] for r in cmp["detections"]}
    assert states["DR-LNX-ACC-001"] == "resolved"
    rc, out, _ = call(capsys, "detect", "compare", str(a), str(b), "--format", "text")
    assert "2 new" in out  # the account detection and the coverage change
    assert call(capsys, "detect", "compare", str(a))[0] == 3
    other = save(tmp_path, "o.json", CLEAN, aid="o", host="other")
    assert call(capsys, "detect", "compare", str(a), str(other))[0] == 3


def test_detect_show_report_export(
    current: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results = tmp_path / "results.json"
    call(capsys, "detect", "run", str(current), "--output", str(results), "--quiet")
    res = json.loads(results.read_text("utf-8"))
    did = next(d["id"] for d in res["detections"] if d["rule"]["id"] == "DR-LNX-ACC-001")
    rc, out, _ = call(capsys, "detect", "show", str(results), did[:10])
    assert (
        rc == 0
        and "Why flagged:" in out
        and "Matched conditions:" in out
        and "T1136.001 (possible)" in out
    )
    rc, out, _ = call(capsys, "detect", "show", str(results), did, "--json")
    assert json.loads(out)["investigation"]["status"] == "new"
    assert call(capsys, "detect", "show", str(results), "DT-zzzz")[0] == 2
    rc, out, _ = call(capsys, "detect", "report", str(results))
    assert out.startswith("# BlueOps detection report")
    assert call(capsys, "detect", "report", str(results), "--format", "html")[0] == 2
    rc, out, _ = call(
        capsys, "detect", "report", str(results), "--format", "html", "--assessment", str(current)
    )
    assert rc == 0 and 'id="detections"' in out and f'id="{did}"' in out
    rc, out, _ = call(capsys, "detect", "export", str(results), "--format", "jsonl")
    assert len(out.splitlines()) == len(res["detections"]) and json.loads(out.splitlines()[0])["id"]
    rc, out, _ = call(capsys, "detect", "export", str(results), "--format", "csv")
    rows = list(csv.reader(io.StringIO(out)))
    assert rows[0][0] == "detection_id" and len(rows) == len(res["detections"]) + 1
    rc, out, _ = call(capsys, "detect", "export", str(results), "--format", "json")
    assert "investigation" in json.loads(out)


def test_csv_export_neutralises_formula_injection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from rules_support import STAMP, rule_set

    from shared.rules.engine import detect
    from shared.rules.export import csv_safe, to_csv

    assert csv_safe("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert (
        csv_safe("+1") == "'+1"
        and csv_safe("@x") == "'@x"
        and csv_safe("-2") == "'-2"
        and csv_safe("ok") == "ok"
    )
    assert csv_safe("a\nb") == "a b"
    f = {**finding("TST-AAA-001"), "title": '=HYPERLINK("http://evil.invalid")'}
    res = detect(doc({"findings": [f]}), rule_set(make_rule(title="{a.title}")), generated_at=STAMP)
    row = list(csv.reader(io.StringIO(to_csv(res))))[1]
    assert row[2].startswith("'=")


def test_help_texts_exist() -> None:
    for argv in (
        ["rules", "--help"],
        ["detect", "--help"],
        ["case", "--help"],
        ["detect", "run", "--help"],
    ):
        with pytest.raises(SystemExit) as exc:
            main(argv)
        assert exc.value.code == 0


@pytest.mark.parametrize(
    "argv",
    [
        ["rules"],
        ["detect"],
        ["case"],
        ["detect", "run"],
        ["case", "status", "--state-dir", "x", "DT-1"],
        ["rules", "list", "--platform", "macos"],
    ],
)
def test_usage_errors_exit_2(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


# ------------------------------------------------------------------------------------ case


def test_case_workflow_through_the_cli(
    current: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = str(tmp_path / "state")
    rc, _, err = call(
        capsys, "detect", "run", str(current), "--state-dir", state, "--actor", "alice", "--quiet"
    )
    assert rc == 4
    rc, out, _ = call(capsys, "case", "list", "--state-dir", state, "--json")
    cases = json.loads(out)
    assert rc == 0 and cases and {c["status"] for c in cases} == {"new"}
    did = cases[0]["id"]
    assert (
        call(
            capsys,
            "case",
            "status",
            "--state-dir",
            state,
            "--actor",
            "alice",
            did[:12],
            "investigating",
        )[0]
        == 0
    )
    assert (
        call(
            capsys,
            "case",
            "note",
            "--state-dir",
            state,
            "--actor",
            "alice",
            did,
            "checked auth logs",
        )[0]
        == 0
    )
    rc, _, err = call(capsys, "case", "status", "--state-dir", state, did, "resolved")
    assert rc == 3 and "note is required" in err
    assert (
        call(
            capsys,
            "case",
            "status",
            "--state-dir",
            state,
            did,
            "resolved",
            "--note",
            "approved change",
        )[0]
        == 0
    )
    rc, out, _ = call(capsys, "case", "show", "--state-dir", state, did)
    assert (
        "resolved" in out
        and "checked auth logs" in out
        and "approved change" in out
        and "alice" in out
    )
    rc, out, _ = call(capsys, "case", "list", "--state-dir", state, "--status", "resolved")
    assert out.strip().splitlines()[-1] == "1 case(s)"
    other = cases[1]["id"]
    assert call(capsys, "case", "link", "--state-dir", state, did, other)[0] == 0
    # the next run shows the analyst state in every format and flags the closed one that came back
    rc, out, _ = call(
        capsys, "detect", "run", str(current), "--state-dir", state, "--format", "text"
    )
    assert "resolved" in out
    rc, out, _ = call(capsys, "case", "show", "--state-dir", state, did, "--json")
    assert json.loads(out)["reappeared"] is True
    rc, out, _ = call(
        capsys, "detect", "run", str(current), "--state-dir", state, "--format", "html", "--quiet"
    )
    assert "observed again after being closed" in out


def test_case_commands_on_missing_or_damaged_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        call(capsys, "case", "list", "--state-dir", str(tmp_path / "none"))[1].strip()
        == "0 case(s)"
    )
    rc, _, err = call(
        capsys, "case", "show", "--state-dir", str(tmp_path / "none"), "DT-0000000000000000"
    )
    assert rc == 3 and "matches 0 cases" in err
    (tmp_path / "cases.jsonl").write_text("garbage\n", encoding="utf-8")
    rc, _, err = call(capsys, "case", "list", "--state-dir", str(tmp_path))
    assert rc == 3 and "cases.jsonl:1" in err


# --------------------------------------------------------------------------- engine run


def test_engine_run_with_detect_writes_results_reports_and_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from engine_support import ROOT, collector_env, linux_fixture_root

    root = linux_fixture_root(tmp_path / "root")
    for k, v in collector_env(root).items():
        monkeypatch.setenv(k, v)
    out = tmp_path / "out"
    rc, _, err = call(
        capsys,
        "run",
        "--platform",
        "linux",
        "--output-dir",
        str(out),
        "--detect",
        "--state-dir",
        str(tmp_path / "state"),
        "--quiet",
    )
    assert rc == 4, err
    (d,) = out.glob("blueops-assessment-*")
    res = json.loads((d / "detections.json").read_text("utf-8"))
    assert validate(res, "detection-results.schema.json") == [] and res["summary"]["total"] >= 5
    html = (d / "report.html").read_text("utf-8")
    assert 'id="detections"' in html and "DR-LNX-ACC-001" in html
    assert "## Detections" in (d / "report.md").read_text("utf-8")
    assert call(capsys, "verify", str(d))[0] == 0
    assert (
        call(capsys, "case", "list", "--state-dir", str(tmp_path / "state"))[1]
        .strip()
        .endswith("case(s)")
    )
    assert ROOT.is_dir()


def test_validate_command_knows_the_detection_document_kinds(
    current: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    results = tmp_path / "r.json"
    call(capsys, "detect", "run", str(current), "--output", str(results), "--quiet")
    rc, out, _ = call(capsys, "validate", str(results))
    assert rc == 0 and "detection-results.schema.json" in out
    pack = Path(__file__).resolve().parents[2] / "shared" / "rules" / "library" / "linux-core.json"
    assert call(capsys, "validate", str(pack))[0] == 0
    cmp_path = tmp_path / "c.json"
    a = save(tmp_path, "a.json", CLEAN, aid="a", started="2026-02-01T10:00:00Z")
    b = save(tmp_path, "b.json", UID0, aid="b", started="2026-02-02T10:00:00Z")
    call(capsys, "detect", "compare", str(a), str(b), "--output", str(cmp_path))
    assert call(capsys, "validate", str(cmp_path))[0] == 0
