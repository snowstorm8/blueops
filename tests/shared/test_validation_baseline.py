"""Baselines: capture, integrity, staleness/compatibility checks and classified differences."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest
from validation_support import make_store, tr

from shared.reporting.schema_lite import validate
from shared.validation.baseline import (
    BaselineError,
    capture_baseline,
    check_baseline,
    diff_baseline,
    load_baseline,
)


def svc(name, path="/usr/bin/x", **extra):
    return tr("service", f"service:{name}", {"name": name, "path": path, **extra})


def lis(port, proc="sshd"):
    return tr(
        "listener",
        f"l:{port}",
        {"protocol": "tcp", "local_address": "0.0.0.0", "local_port": port, "process": proc},
    )


def baseline(tmp_path, records=None, **kw):
    store = make_store(tmp_path, records or [svc("ssh.service"), lis(22)], name="s1")
    return capture_baseline(store, tmp_path / "bl", kw.pop("name", "lab-known-good"), **kw)


NOW = datetime(2026, 3, 10, tzinfo=timezone.utc)


def issues(meta, tel, current=None, **kw):
    return {i["code"]: i for i in check_baseline(meta, tel, current, now=NOW, **kw)}


# ------------------------------------------------------------------ capture and integrity


def test_capture_writes_a_verified_private_baseline_with_metadata(tmp_path):
    root = baseline(
        tmp_path, purpose="clean lab image", lab_attested=True, captured_at="2026-03-01T10:00:00Z"
    )
    assert {p.name for p in root.iterdir()} == {"baseline.json", "telemetry.json", "manifest.json"}
    assert os.name != "posix" or (root.stat().st_mode & 0o777) == 0o700
    meta, tel = load_baseline(root)
    assert validate(meta, "validation-baseline.schema.json") == []
    assert (
        meta["purpose"] == "clean lab image"
        and meta["lab_attested"] is True
        and meta["source"]["records"] == tel["summary"]["records"]
    )
    assert (
        meta["source"]["coverage"]["service"] == "complete"
        and meta["host"]["host_id"] == tel["host"]["host_id"]
    )


def test_a_baseline_is_never_overwritten_and_names_are_validated(tmp_path):
    store = make_store(tmp_path, [svc("a")], name="s1")
    capture_baseline(store, tmp_path / "bl", "one")
    with pytest.raises(BaselineError, match="never overwritten"):
        capture_baseline(store, tmp_path / "bl", "one")
    with pytest.raises(BaselineError):
        capture_baseline(store, tmp_path / "bl", "../escape")


def test_capture_refuses_an_unverifiable_source(tmp_path):
    store = make_store(tmp_path, [svc("a")], name="s1")
    (store / "telemetry.json").write_text(
        (store / "telemetry.json").read_text().replace("a", "b", 1)
    )
    with pytest.raises(BaselineError, match="manifest"):
        capture_baseline(store, tmp_path / "bl", "x")
    with pytest.raises(BaselineError):
        capture_baseline(tmp_path / "missing", tmp_path / "bl", "y")


@pytest.mark.parametrize("target", ["telemetry.json", "baseline.json"])
def test_tampering_with_any_baseline_file_is_detected(tmp_path, target):
    root = baseline(tmp_path)
    p = root / target
    p.write_text(
        p.read_text().replace('"', "'", 1)
        if target == "baseline.json"
        else p.read_text().replace("sshd", "evil")
    )
    with pytest.raises(BaselineError):
        load_baseline(root)


def test_metadata_and_telemetry_must_describe_the_same_host(tmp_path):
    root = baseline(tmp_path)
    meta = json.loads((root / "baseline.json").read_text())
    meta["host"]["host_id"] = "H-000000000000"
    (root / "baseline.json").write_text(json.dumps(meta))
    from shared.engine.manifest import write_manifest

    (root / "manifest.json").unlink()
    write_manifest(
        root,
        {
            "assessment": {
                "id": "x",
                "started_at": "2026-03-01T10:00:00Z",
                "finished_at": "2026-03-01T10:00:00Z",
                "exit_code": 0,
            }
        },
    )
    with pytest.raises(BaselineError, match="different hosts"):
        load_baseline(root)


@pytest.mark.parametrize("pattern", ["(a+)+$", "(x*)*y"])
def test_dangerous_allowance_patterns_are_refused(tmp_path, pattern):
    store = make_store(tmp_path, [svc("a")], name="s1")
    with pytest.raises(BaselineError):
        capture_baseline(
            store,
            tmp_path / "bl",
            "z",
            expected_changes=[{"category": "service", "identity_pattern": pattern, "reason": "x"}],
        )


# ------------------------------------------------------------------ staleness and compatibility


def test_a_fresh_complete_baseline_has_only_the_attestation_note(tmp_path):
    meta, tel = load_baseline(baseline(tmp_path, captured_at="2026-03-05T10:00:00Z"))
    assert set(issues(meta, tel)) == {"NOT_LAB_ATTESTED"}


def test_stale_baselines_are_flagged_with_their_age(tmp_path):
    meta, tel = load_baseline(
        baseline(tmp_path, captured_at="2025-12-01T00:00:00Z", max_age_days=30)
    )
    assert "99 days old (limit 30)" in issues(meta, tel)["STALE"]["message"]
    assert "STALE" not in issues(meta, tel, max_age_days=365)


def test_incomplete_and_fixture_baselines_are_called_out(tmp_path):
    store = make_store(
        tmp_path, [svc("a")], coverage={"listener": "unavailable", "service": "partial"}, name="s2"
    )
    meta, tel = load_baseline(
        capture_baseline(store, tmp_path / "bl", "inc", captured_at="2026-03-05T10:00:00Z")
    )
    msg = issues(meta, tel)["BASELINE_INCOMPLETE"]["message"]
    assert "listener" in msg and "not conclusive" in msg
    meta["source"]["errors"] = ["TEST_MODE"]
    assert "TEST_MODE" in issues(meta, tel)


def test_incompatible_schema_versions_are_errors(tmp_path):
    meta, tel = load_baseline(baseline(tmp_path, captured_at="2026-03-05T10:00:00Z"))
    meta["source"]["telemetry_schema"] = "2.0.0"
    assert issues(meta, tel)["SCHEMA_INCOMPATIBLE"]["severity"] == "error"


def test_capture_compatibility_host_os_collector_and_coverage(tmp_path):
    meta, tel = load_baseline(baseline(tmp_path, captured_at="2026-03-05T10:00:00Z"))
    other_host = json.loads(json.dumps(tel))
    other_host["host"]["host_id"] = "H-ffffffffffff"
    assert issues(meta, tel, other_host)["HOST_MISMATCH"]["severity"] == "error"
    newer = json.loads(json.dumps(tel))
    newer["host"]["os"]["version"] = "2"
    newer["collection"]["collectors"] = [
        {"name": c["name"], "version": "9.0.0"} for c in tel["collection"]["collectors"]
    ]
    newer["coverage"] = [
        {**c, "status": "unavailable"} if c["category"] == "listener" else c
        for c in newer["coverage"]
    ]
    got = issues(meta, tel, newer)
    assert {"OS_VERSION_DIFFERS", "COLLECTOR_MAJOR_DIFFERS", "COVERAGE_REGRESSION"} <= set(got)
    assert "listener" in got["COVERAGE_REGRESSION"]["message"]


# ------------------------------------------------------------------ differences


def diff(tmp_path, base_records, cur_records, *, expected=None, **kw):
    store = make_store(tmp_path, base_records, name="b")
    root = capture_baseline(
        store,
        tmp_path / "bl",
        "kg",
        expected_changes=expected or [],
        captured_at="2026-03-05T10:00:00Z",
    )
    meta, tel = load_baseline(root)
    cur = load_current(tmp_path, cur_records, **kw)
    return diff_baseline(meta, tel, cur, now=NOW)


def load_current(tmp_path, records, **kw):
    from shared.telemetry.ingest import load_telemetry

    return load_telemetry(
        make_store(tmp_path, records, started="2026-03-08T10:00:00Z", cid="cur", name="c", **kw)
    )


def test_identical_environment_has_no_differences(tmp_path):
    d = diff(tmp_path, [svc("a"), lis(22)], [svc("a"), lis(22)])
    assert d["summary"] == {
        "total": 0,
        "expected": 0,
        "unexpected": 0,
        "indeterminate_categories": 0,
        "exit_status": "ok",
    }
    assert validate(d, "validation-baseline-diff.schema.json") == []


def test_unexpected_differences_carry_an_explanation_and_never_a_verdict(tmp_path):
    d = diff(
        tmp_path, [svc("a"), lis(22)], [svc("a", "/opt/new"), svc("b"), lis(22), lis(9001, "x")]
    )
    assert (
        d["summary"]["unexpected"] == 3 and d["summary"]["exit_status"] == "unexpected_differences"
    )
    for x in d["differences"]:
        assert x["classification"] == "unexpected" and x["why_it_matters"] and x["how_to_review"]
    text = json.dumps(d).lower()
    assert "malicious" not in text and "compromise" not in text
    changed = next(x for x in d["differences"] if x["change"] == "changed")
    assert (
        changed["attributes"][0]["name"] == "path"
        and changed["attributes"][0]["after"] == "/opt/new"
    )


def test_declared_allowances_make_a_difference_expected_with_the_reason(tmp_path):
    allow = [
        {
            "category": "service",
            "change": "added",
            "identity_pattern": "^service:metrics",
            "reason": "metrics agent rollout CHG-1042",
        },
        {
            "category": "service",
            "change": "changed",
            "attributes": ["path"],
            "reason": "package upgrade moved binaries",
        },
    ]
    d = diff(
        tmp_path,
        [svc("a")],
        [svc("a", "/usr/local/bin/x"), svc("metrics-agent"), svc("other")],
        expected=allow,
    )
    by = {x["identity"]: x for x in d["differences"]}
    assert (
        by["service:metrics-agent"]["classification"] == "expected"
        and "CHG-1042" in by["service:metrics-agent"]["expected_by"]
    )
    assert by["service:a"]["classification"] == "expected"
    assert by["service:other"]["classification"] == "unexpected"
    assert d["summary"] == {
        "total": 3,
        "expected": 2,
        "unexpected": 1,
        "indeterminate_categories": 0,
        "exit_status": "unexpected_differences",
    }


def test_an_allowance_does_not_cover_other_attributes_or_changes(tmp_path):
    allow = [
        {"category": "service", "change": "changed", "attributes": ["path"], "reason": "upgrade"}
    ]
    d = diff(
        tmp_path,
        [svc("a", "/x", state="running")],
        [svc("a", "/y", state="stopped")],
        expected=allow,
    )
    assert d["differences"][0]["classification"] == "unexpected", (
        "state also changed, which the allowance does not cover"
    )


def test_removals_and_changes_are_not_claimed_for_incomplete_categories(tmp_path):
    d = diff(tmp_path, [svc("a"), svc("b")], [svc("a")], coverage={"service": "partial"})
    assert d["differences"] == [] and d["indeterminate"][0]["category"] == "service"
    assert d["summary"]["exit_status"] == "incomplete"


def test_incompatible_captures_produce_no_differences_at_all(tmp_path):
    d = diff(tmp_path, [svc("a")], [svc("a"), svc("b")], host="another-host")
    assert d["summary"]["exit_status"] == "incompatible" and d["differences"] == []
    assert any(c["code"] == "HOST_MISMATCH" for c in d["compatibility"])


def test_cross_platform_comparison_is_coverage_parity_not_identity_diff(tmp_path):
    d = diff(
        tmp_path,
        [svc("a"), lis(22)],
        [tr("service", "s", {"name": "Spooler", "path": "C:\\x.exe"})],
        platform="windows",
        host="win-host",
    )
    assert (
        d["mode"] == "cross_platform"
        and d["differences"] == []
        and d["summary"]["exit_status"] == "incomplete"
    )
    par = {p["category"]: p for p in d["parity"]}
    assert (
        par["service"]["baseline"]["records"] == 1
        and par["listener"]["current"]["status"] == "absent"
    )
    assert any(c["code"] == "CROSS_PLATFORM" for c in d["compatibility"])


def test_stale_baselines_still_compare_but_say_so(tmp_path):
    store = make_store(tmp_path, [svc("a")], name="b")
    meta, tel = load_baseline(
        capture_baseline(store, tmp_path / "bl", "old", captured_at="2025-01-01T00:00:00Z")
    )
    d = diff_baseline(meta, tel, load_current(tmp_path, [svc("a")]), now=NOW)
    assert (
        any(c["code"] == "STALE" for c in d["compatibility"])
        and d["summary"]["exit_status"] == "ok"
    )
