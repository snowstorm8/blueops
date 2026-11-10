"""Snapshot comparison: new / resolved / persistent / severity / configuration / coverage."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
from engine_support import fake_assessment, fnd, make_report, rec
from jsonschema import Draft202012Validator

from shared.engine.assessment import assessment_from_report
from shared.engine.runner import ExecResult
from shared.reporting.contracts import ExitCode
from shared.reporting.schema_lite import SCHEMA_DIR, load_schema, validate
from shared.reporting.snapshot_compare import (
    ComparisonError,
    compare_snapshots,
    comparison_exit_code,
    weighted_index,
)

LATER = {"run": "run-2", "start": "2026-03-02T10:00:00Z", "end": "2026-03-02T10:05:00Z"}
CLOCK_LATER = "2026-03-02T10:00:00Z"


def _base(findings: list[dict[str, Any]], **kw: Any) -> dict[str, Any]:
    return fake_assessment(kw.pop("tmp"), {"linux.users": make_report(findings, **kw)}).document


def _cur(findings: list[dict[str, Any]], **kw: Any) -> dict[str, Any]:
    tmp = kw.pop("tmp")
    return fake_assessment(
        tmp, {"linux.users": make_report(findings, **{**LATER, **kw})}, clock_start=CLOCK_LATER
    ).document


def _cmp(base: dict[str, Any], cur: dict[str, Any], **kw: Any) -> dict[str, Any]:
    c = compare_snapshots(base, cur, generated_at="2026-03-03T00:00:00Z", **kw)
    assert validate(c, "snapshot-comparison.schema.json") == []
    assert Draft202012Validator(load_schema("snapshot-comparison.schema.json")).is_valid(c)
    return c


def ids(c: dict[str, Any], key: str) -> list[str]:
    return sorted(f["check_id"] for f in c["findings"][key])


@pytest.fixture
def t1(tmp_path: Path) -> Path:
    return tmp_path / "a"


@pytest.fixture
def t2(tmp_path: Path) -> Path:
    return tmp_path / "b"


def test_new_resolved_persistent(t1: Path, t2: Path) -> None:
    base = _base([fnd("USR-AAA-001", "high"), fnd("USR-BBB-001", "low")], tmp=t1)
    cur = _cur([fnd("USR-BBB-001", "low"), fnd("USR-CCC-001", "medium")], tmp=t2)
    c = _cmp(base, cur)
    assert ids(c, "new") == ["USR-CCC-001"]
    assert ids(c, "resolved") == ["USR-AAA-001"]
    assert ids(c, "persistent") == ["USR-BBB-001"]
    assert c["summary"]["trend"] == "worse"
    assert comparison_exit_code(c) == ExitCode.FINDINGS


def test_severity_changes_are_persistent_findings_with_a_direction(t1: Path, t2: Path) -> None:
    base = _base([fnd("USR-AAA-001", "low"), fnd("USR-BBB-001", "critical")], tmp=t1)
    cur = _cur([fnd("USR-AAA-001", "high"), fnd("USR-BBB-001", "medium")], tmp=t2)
    c = _cmp(base, cur)
    assert ids(c, "new") == [] and ids(c, "resolved") == []
    changed = {
        f["check_id"]: (f["baseline_severity"], f["severity"], f["direction"])
        for f in c["findings"]["severity_changed"]
    }
    assert changed == {
        "USR-AAA-001": ("low", "high", "increased"),
        "USR-BBB-001": ("critical", "medium", "decreased"),
    }
    assert c["summary"]["severity_increased"] == 1 and c["summary"]["severity_decreased"] == 1
    assert len(c["findings"]["persistent"]) == 2
    assert c["summary"]["trend"] == "worse"  # any increase makes the trend worse


def test_only_improvements_is_better(t1: Path, t2: Path) -> None:
    base = _base([fnd("USR-AAA-001", "high"), fnd("USR-BBB-001", "low")], tmp=t1)
    cur = _cur([fnd("USR-BBB-001", "info")], tmp=t2)
    c = _cmp(base, cur)
    assert c["summary"]["trend"] == "better" and c["summary"]["weighted_index"]["delta"] < 0


def test_identical_snapshots_are_unchanged_with_exit_ok(t1: Path, t2: Path) -> None:
    f = [fnd("USR-AAA-001", "high", evidence=[("file", "/a")])]
    c = _cmp(_base(f, tmp=t1), _cur(f, tmp=t2))
    assert c["summary"]["trend"] == "unchanged"
    assert (
        c["summary"]["new"],
        c["summary"]["resolved"],
        c["summary"]["configuration_changes"],
    ) == (0, 0, 0)
    assert comparison_exit_code(c) == ExitCode.OK


def test_evidence_delta_on_a_persistent_finding(t1: Path, t2: Path) -> None:
    base = _base([fnd("USR-AAA-001", evidence=[("file", "/a"), ("file", "/b")])], tmp=t1)
    cur = _cur([fnd("USR-AAA-001", evidence=[("file", "/b"), ("file", "/c")])], tmp=t2)
    (p,) = _cmp(base, cur)["findings"]["persistent"]
    assert (
        len(p["evidence"]["added"]),
        len(p["evidence"]["removed"]),
        p["evidence"]["unchanged"],
    ) == (1, 1, 1)


def test_truncated_findings_flag_unreliable_evidence_delta(t1: Path, t2: Path) -> None:
    f = fnd("USR-AAA-001", description="many [90 items; only the first 50 are listed]")
    (p,) = _cmp(_base([f], tmp=t1), _cur([f], tmp=t2))["findings"]["persistent"]
    assert p["evidence"]["truncated"] is True


# ------------------------------------------------------------- coverage-aware conclusions


def test_a_failed_module_never_resolves_findings(tmp_path: Path) -> None:
    ok = {
        "linux.users": make_report([fnd("USR-AAA-001", "high")]),
        "linux.net": make_report([fnd("NET-BBB-001", category="network")], run="r2"),
    }
    base = fake_assessment(tmp_path / "a", ok).document
    cur = fake_assessment(
        tmp_path / "b",
        {
            "linux.users": make_report([], **LATER),
            "linux.net": lambda: ExecResult(None, timed_out=True),
        },
        clock_start=CLOCK_LATER,
    ).document
    c = _cmp(base, cur)
    assert ids(c, "resolved") == ["USR-AAA-001"]  # users ran cleanly and no longer reports it
    (ind,) = c["findings"]["indeterminate"]
    assert (
        ind["check_id"] == "NET-BBB-001"
        and ind["side"] == "baseline"
        and "timeout" in ind["reason"]
    )
    assert c["summary"]["trend"] == "better"
    assert c["coverage"]["modules"]["changed"] == [
        {"id": "linux.net", "baseline": "ok", "current": "timeout"}
    ]


def test_a_partial_baseline_module_cannot_prove_a_finding_is_new(tmp_path: Path) -> None:
    base = fake_assessment(
        tmp_path / "a", {"linux.users": make_report([])}, exit_codes={"linux.users": 6}
    ).document
    cur = fake_assessment(
        tmp_path / "b",
        {"linux.users": make_report([fnd("USR-AAA-001")], **LATER)},
        clock_start=CLOCK_LATER,
    ).document
    c = _cmp(base, cur)
    assert ids(c, "new") == [] and ids(c, "indeterminate") == ["USR-AAA-001"]
    assert c["findings"]["indeterminate"][0]["side"] == "current"
    assert comparison_exit_code(c) in (ExitCode.PARTIAL, ExitCode.FINDINGS)


def test_a_module_that_was_not_run_is_indeterminate(tmp_path: Path) -> None:
    both = {
        "linux.users": make_report([fnd("USR-AAA-001")]),
        "linux.net": make_report([fnd("NET-BBB-001", category="network")], run="r2"),
    }
    base = fake_assessment(tmp_path / "a", both).document
    cur = fake_assessment(
        tmp_path / "b",
        {"linux.users": make_report([fnd("USR-AAA-001")], **LATER)},
        clock_start=CLOCK_LATER,
    ).document
    c = _cmp(base, cur)
    assert ids(c, "resolved") == []
    assert "was not run" in c["findings"]["indeterminate"][0]["reason"]
    assert c["coverage"]["modules"]["removed"] == ["linux.net"]


def test_imported_report_baseline_is_judged_as_a_whole(tmp_path: Path) -> None:
    legacy = assessment_from_report(make_report([fnd("USR-AAA-001", "high")]))
    cur = fake_assessment(
        tmp_path, {"linux.users": make_report([], **LATER)}, clock_start=CLOCK_LATER
    ).document
    c = _cmp(legacy, cur)
    assert ids(c, "resolved") == ["USR-AAA-001"]
    partial_cur = fake_assessment(
        tmp_path / "p",
        {"linux.users": make_report([], **LATER)},
        exit_codes={"linux.users": 6},
        clock_start=CLOCK_LATER,
    ).document
    assert ids(_cmp(legacy, partial_cur), "resolved") == [] and ids(
        _cmp(legacy, partial_cur), "indeterminate"
    ) == ["USR-AAA-001"]


def test_imported_report_with_gaps_cannot_show_absence() -> None:
    base = assessment_from_report(make_report([fnd("USR-AAA-001")]))
    gappy = make_report([], **LATER)
    gappy["run"]["exit_code"] = 6
    c = _cmp(base, assessment_from_report(gappy))
    assert ids(c, "resolved") == [] and ids(c, "indeterminate") == ["USR-AAA-001"]
    # and the mirror image: a gappy baseline cannot prove a finding is new
    gappy_base = make_report([])
    gappy_base["run"]["exit_code"] = 6
    c = _cmp(
        assessment_from_report(gappy_base),
        assessment_from_report(make_report([fnd("USR-AAA-001")], **LATER)),
    )
    assert ids(c, "new") == [] and ids(c, "indeterminate") == ["USR-AAA-001"]


# ------------------------------------------------------------------------ configuration


def test_configuration_changes_come_from_the_inventory(t1: Path, t2: Path) -> None:
    base = _base(
        [], tmp=t1, records=[rec("users", "user:alice", {"uid": "1000", "shell": "/bin/bash"})]
    )
    cur = _cur(
        [],
        tmp=t2,
        records=[
            rec("users", "user:alice", {"uid": "1000", "shell": "/bin/sh"}),
            rec("users", "user:evil", {"uid": "0"}),
        ],
    )
    c = _cmp(base, cur)
    cfg = c["configuration"]
    assert cfg["available"] and cfg["summary"]["added"] == 1 and cfg["summary"]["modified"] == 1
    assert {(x["change"], x["key"]) for x in cfg["changes"]} == {
        ("added", "user:evil"),
        ("modified", "user:alice"),
    }
    assert (
        c["summary"]["configuration_changes"] == 2 and comparison_exit_code(c) == ExitCode.FINDINGS
    )


def test_inventory_coverage_loss_is_not_reported_as_removal(tmp_path: Path) -> None:
    base = fake_assessment(tmp_path / "a", {"linux.users": make_report([])}).document
    cur = fake_assessment(
        tmp_path / "b",
        {"linux.users": make_report([], **LATER, records=[])},
        clock_start=CLOCK_LATER,
    ).document
    cur["inventory"]["coverage"] = [
        {"domain": "users", "status": "unavailable", "reason": "not collected"}
    ]
    c = _cmp(base, cur)
    assert c["configuration"]["summary"]["removed"] == 0
    assert c["coverage"]["inventory_partitions"] == [
        {"domain": "users", "scope": "", "baseline": "complete", "current": "unavailable"}
    ]


def test_snapshot_without_inventory_degrades_to_findings_only(t1: Path, t2: Path) -> None:
    base = assessment_from_report(make_report([fnd("USR-AAA-001")], inventory=False, records=[]))
    cur = assessment_from_report(make_report([], inventory=False, records=[], **LATER))
    c = _cmp(base, cur)
    assert c["configuration"]["available"] is False and "inventory" in c["configuration"]["reason"]
    assert ids(c, "resolved") == ["USR-AAA-001"]


# ----------------------------------------------------------------------- compatibility


def test_different_os_families_are_refused(tmp_path: Path) -> None:
    a = assessment_from_report(make_report([]))
    b = assessment_from_report(make_report([], family="windows", **LATER))
    with pytest.raises(ComparisonError, match="OS families"):
        compare_snapshots(a, b)


def test_host_mismatch_needs_an_explicit_override() -> None:
    a = assessment_from_report(make_report([fnd("USR-AAA-001")]))
    b = assessment_from_report(make_report([fnd("USR-AAA-001")], host="db01", **LATER))
    with pytest.raises(ComparisonError, match="allow-host-mismatch"):
        compare_snapshots(a, b)
    c = _cmp(a, b, allow_host_mismatch=True)
    assert {w["code"] for w in c["warnings"]} >= {"HOST_MISMATCH", "IDENTITY_MISMATCH"}
    assert ids(c, "persistent") == []  # ids embed the host: nothing matches across hosts
    assert ids(c, "new") == ["USR-AAA-001"] and ids(c, "resolved") == ["USR-AAA-001"]


def test_hostname_case_does_not_matter() -> None:
    a = assessment_from_report(make_report([fnd("USR-AAA-001")], host="WEB01"))
    b = assessment_from_report(make_report([fnd("USR-AAA-001")], host="web01", **LATER))
    assert ids(_cmp(a, b), "persistent") == ["USR-AAA-001"]


def test_warnings_for_same_run_reversed_order_and_privilege() -> None:
    r = make_report([fnd("USR-AAA-001")])
    same = _cmp(assessment_from_report(r), assessment_from_report(r))
    assert "SAME_RUN" in {w["code"] for w in same["warnings"]}
    older = assessment_from_report(make_report([], **LATER, elevated=False))
    newer = assessment_from_report(make_report([]))
    codes = {w["code"] for w in _cmp(older, newer)["warnings"]}
    assert {"REVERSED_ORDER", "PRIVILEGE_DIFFERS"} <= codes


def test_no_host_means_no_comparison(tmp_path: Path) -> None:
    dead = fake_assessment(
        tmp_path, {"linux.a": lambda: ExecResult(None, error="cannot start: x")}
    ).document
    with pytest.raises(ComparisonError, match="need a host"):
        compare_snapshots(dead, dead)


def test_comparison_is_deterministic_and_does_not_mutate_inputs(t1: Path, t2: Path) -> None:
    base = _base([fnd("USR-AAA-001", "high"), fnd("USR-BBB-001")], tmp=t1)
    cur = _cur([fnd("USR-BBB-001", "high")], tmp=t2)
    snap = (copy.deepcopy(base), copy.deepcopy(cur))
    assert _cmp(base, cur) == _cmp(base, cur)
    assert (base, cur) == snap


def test_weighted_index_weights() -> None:
    doc = {"findings": [{"severity": s} for s in ("info", "low", "medium", "high", "critical")]}
    assert weighted_index(doc) == 0 + 1 + 3 + 7 + 15


def test_comparison_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(load_schema("snapshot-comparison.schema.json"))
    assert (SCHEMA_DIR / "snapshot-comparison.schema.json").is_file()
