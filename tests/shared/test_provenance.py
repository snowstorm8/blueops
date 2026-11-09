"""Input provenance: an output records which inputs it was derived from and whether each one
was verified, and that record cannot silently disappear.

The invariants under test (``shared/engine/provenance.py``):

* verification status is per input, and the summary ``inputs_verified`` is true only if all are;
* an input of *unknown* provenance (a plain dict, a hand-built document) counts as unverified,
  so copying or rebuilding a document can only lose "verified", never invent it;
* a document that passes its schema is not thereby verified;
* the status survives conversions (assessment <-> audit report), saving to disk and a later
  verified load, and every renderer shows it.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from engine_support import fnd, make_report
from test_engine_cli import _assessment_dir, _plugin_dir, _two_runs
from test_engine_integrity import build

from shared.engine.assessment import assessment_from_report, assessment_to_report
from shared.engine.cli import main
from shared.engine.loader import LoadError, load_assessment
from shared.engine.manifest import MANIFEST_NAME, write_manifest
from shared.engine.provenance import Loaded, banner, entries, gather, produced_here, stamp
from shared.reporting import render_provenance
from shared.reporting.render_html import render_html
from shared.reporting.render_markdown import render_comparison_markdown, render_markdown
from shared.reporting.schema_lite import validate
from shared.reporting.snapshot_compare import compare_snapshots
from shared.rules.loader import load_rule_set
from shared.telemetry import ingest

STAMP = "2026-03-09T00:00:00Z"
RS = load_rule_set()


def _rewrite(d: Path, doc: dict[str, Any]) -> None:
    """Replace ``assessment.json`` and write a fresh manifest (manifests are create-exclusive)."""
    (d / MANIFEST_NAME).unlink()
    (d / "assessment.json").write_text(json.dumps(doc), encoding="utf-8")
    write_manifest(d, doc)


def _two(tmp_path: Path) -> tuple[Path, Path]:
    """Two verified assessment directories of one host (different run ids and findings)."""
    out = []
    for n in range(2):
        d, _, doc = build(tmp_path / f"d{n}")
        doc["assessment"]["id"] = f"run-{n}"
        doc["assessment"]["started_at"] = f"2026-03-0{n + 1}T10:00:00Z"
        doc["assessment"]["finished_at"] = f"2026-03-0{n + 1}T10:05:00Z"
        doc["findings"] = []
        _rewrite(d, doc)
        out.append(d)
    return out[0], out[1]


def _noverify(d: Path) -> Loaded:
    """Load ``d`` with the opt-out from a copy whose manifest is gone, so it cannot verify."""
    copy_dir = d.with_name(d.name + "-nomanifest")
    if not copy_dir.exists():
        _unverifiable_copy(d, copy_dir)
    return load_assessment(copy_dir, verify=False)


def _statuses(doc: dict[str, Any]) -> dict[str, bool]:
    return {e["role"]: e["verified"] for e in doc["inputs"] if "via" not in e}


# ----------------------------------------------------------------------- the loader


def test_a_verified_load_is_verified_and_an_unverified_one_says_so_in_the_document(
    tmp_path: Path,
) -> None:
    d, _, _ = build(tmp_path)
    ok = load_assessment(d)
    assert isinstance(ok, Loaded) and ok.load_verified is True
    assert "inputs_verified" not in ok  # nothing to record: nothing unverified was used
    bad = _noverify(d)
    assert bad.load_verified is False
    assert bad["inputs_verified"] is False
    assert [e["verified"] for e in bad["inputs"]] == [False]
    assert validate(bad, "assessment.schema.json") == []


def test_the_opt_out_still_tries_to_verify_and_records_what_happened(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    assert load_assessment(d, verify=False).load_verified is True  # it verifies: say so
    (d / "assessment.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(LoadError):  # malformed data is never overridable
        load_assessment(d, verify=False)


def test_unverified_status_is_data_so_a_plain_copy_cannot_launder_it(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    bad = _noverify(d)
    for clone in (dict(bad), copy.deepcopy(bad), json.loads(json.dumps(bad))):
        assert clone["inputs_verified"] is False
        cmp_doc = compare_snapshots(clone, clone, generated_at=STAMP, allow_host_mismatch=True)
        assert cmp_doc["inputs_verified"] is False


def test_unknown_provenance_counts_as_unverified_not_verified(tmp_path: Path) -> None:
    """A verified document copied into a plain dict loses the *claim*, never gains one."""
    d, _, _ = build(tmp_path)
    ok = load_assessment(d)
    assert compare_snapshots(ok, ok, generated_at=STAMP)["inputs_verified"] is True
    plain = dict(ok)  # the Loaded attribute is gone
    out = compare_snapshots(plain, plain, generated_at=STAMP)
    assert out["inputs_verified"] is False
    assert {e["reason"] for e in out["inputs"]} == {
        "provenance unknown (verification status was not carried)"
    }


def test_schema_validity_alone_never_marks_a_document_verified(tmp_path: Path) -> None:
    d, _, doc = build(tmp_path)
    assert validate(doc, "assessment.schema.json") == []
    out = compare_snapshots(doc, doc, generated_at=STAMP)
    assert out["inputs_verified"] is False
    assert validate(out, "snapshot-comparison.schema.json") == []


def test_only_this_run_or_a_manifest_check_can_produce_a_verified_entry(tmp_path: Path) -> None:
    d, _, doc = build(tmp_path)
    assert entries("x", doc)[0]["verified"] is False
    assert entries("x", produced_here(doc))[0]["verified"] is True
    assert entries("x", load_assessment(d))[0]["verified"] is True
    assert entries("x", _noverify(d))[0]["verified"] is False


# ------------------------------------------------------------- comparisons: mixed inputs


def test_a_comparison_keeps_per_input_status_for_mixed_inputs(tmp_path: Path) -> None:
    a, b = _two(tmp_path)
    cmp_doc = compare_snapshots(load_assessment(a), _noverify(b))
    assert cmp_doc["inputs_verified"] is False
    assert _statuses(cmp_doc) == {"baseline": True, "current": False}
    assert validate(cmp_doc, "snapshot-comparison.schema.json") == []
    both = compare_snapshots(load_assessment(a), load_assessment(b))
    assert both["inputs_verified"] is True and _statuses(both) == {
        "baseline": True,
        "current": True,
    }


def test_derived_from_unverified_survives_save_and_a_later_verified_load(tmp_path: Path) -> None:
    """A manifest verifies *this* file; it does not launder what the file was built from."""
    a, b = _two(tmp_path)
    rebuilt = dict(_noverify(b))
    for entry in rebuilt["inputs"]:  # as if the file had been saved by a run with the opt-out
        assert entry["verified"] is False
    saved, _, _ = build(tmp_path / "saved")
    _rewrite(saved, rebuilt)
    again = load_assessment(saved)  # verifies cleanly
    assert again.load_verified is True
    out = compare_snapshots(load_assessment(a), again, generated_at=STAMP)
    assert out["inputs_verified"] is False
    assert any(e["verified"] is False and e.get("via") for e in out["inputs"])
    assert _statuses(out)["current"] is True  # the file itself verified; its ancestry did not


# ------------------------------------------------------------------------ conversions


def test_provenance_survives_conversion_between_report_and_assessment(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    bad = _noverify(d)
    report = assessment_to_report(bad)
    assert report["inputs_verified"] is False and report["inputs"] == bad["inputs"]
    assert validate(report, "audit-report.schema.json") == []
    back = assessment_from_report(report)
    assert back["inputs_verified"] is False and back["inputs"] == bad["inputs"]
    assert validate(back, "assessment.schema.json") == []


def test_a_collector_report_loaded_without_verification_is_marked(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "report.json").write_text(json.dumps(make_report([fnd("USR-AAA-001", "high")])))
    doc = load_assessment(run, verify=False)
    assert doc["inputs_verified"] is False and doc["inputs"][0]["path"] == str(run)
    with pytest.raises(LoadError, match="cannot be verified"):
        load_assessment(run)


# --------------------------------------------------------------------- detection results


# ------------------------------------------------------------------------- rendering


def test_markdown_and_html_distinguish_verified_from_unverified(tmp_path: Path) -> None:
    a, b = _two(tmp_path)
    ok_a, ok_b = load_assessment(a), load_assessment(b)
    bad_a = _noverify(a)
    good_cmp = compare_snapshots(ok_a, ok_b, generated_at=STAMP)
    bad_cmp = compare_snapshots(bad_a, ok_b, generated_at=STAMP)

    md_ok = render_markdown(ok_b, [good_cmp], STAMP)
    assert "## Input provenance" in md_ok and "WARNING" not in md_ok and "UNVERIFIED" not in md_ok
    md_bad = render_markdown(ok_b, [bad_cmp], STAMP)
    assert md_bad.index("WARNING") < md_bad.index("Executive summary")  # the warning comes first
    assert "**UNVERIFIED**" in md_bad and "verified |" in md_bad  # per input, both kinds listed

    html_ok = render_html(ok_b, [good_cmp], STAMP)
    html_bad = render_html(ok_b, [bad_cmp], STAMP)
    assert 'role="alert"' not in html_ok and 'id="provenance"' in html_ok
    assert (
        'role="alert"' in html_bad and "UNVERIFIED" in html_bad and 'class="prov-bad"' in html_bad
    )

    assert "UNVERIFIED" in render_comparison_markdown(bad_cmp)
    assert "UNVERIFIED" not in render_comparison_markdown(good_cmp)


def test_a_document_with_no_provenance_record_claims_nothing(tmp_path: Path) -> None:
    d, _, doc = build(tmp_path)
    assert doc.get("inputs_verified") is None
    assert render_provenance.markdown(("assessment", doc)) == []
    assert render_provenance.html(("assessment", doc)) == ("", "")
    assert banner(doc) == ""


def test_hostile_input_paths_are_escaped_in_every_format(tmp_path: Path) -> None:
    d, _, doc = build(tmp_path)
    evil = "</td><script>alert(1)</script>|[x](http://e)"
    bad = _noverify(d)
    bad["inputs"][0]["path"] = evil
    md = render_markdown(bad, None, STAMP)
    html = render_html(bad, None, STAMP)
    assert "<script>alert(1)" not in html and "&lt;script&gt;alert(1)" in html
    assert "<script>" not in md  # angle brackets never reach the Markdown raw
    assert "\u2039script\u203a" in md and "`" in md  # shown literally, inside a code span


def test_overall_verdict_is_false_if_any_document_in_a_report_is_unverified() -> None:
    ok = stamp({}, [{"role": "a", "path": "p", "verified": True}])
    bad = stamp({}, [{"role": "a", "path": "q", "verified": False, "reason": "r"}])
    assert gather(("x", ok))[0] is True
    assert gather(("x", ok), ("y", bad))[0] is False
    assert gather(("x", {}))[0] is None
    # a document that says "unverified" without itemising still shows up as a row
    overall, rows = gather(("z", {"inputs_verified": False, "inputs": []}))
    assert overall is False and rows[0]["verified"] is False


# --------------------------------------------------------------------------- telemetry


def _store(tmp_path: Path, name: str, **kw: Any) -> Path:
    from telemetry_support import proc, stream  # noqa: PLC0415 - shared helper, test-only

    src = tmp_path / f"{name}.jsonl"
    src.write_bytes(stream([proc(1, "init", "/sbin/init")], **kw))
    doc = ingest.ingest_paths([src], allow_unverified=True)
    return ingest.write_store(doc, tmp_path / f"{name}-stores", [(src.name, src.read_bytes())])


# ------------------------------------------------------------------------- engine run


def _run_main(*argv: str) -> int:
    return main(list(argv))


def _unverifiable_copy(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst)
    (dst / MANIFEST_NAME).unlink()
    return dst


def _run_args(tmp_path: Path, n: int, *extra: str) -> list[str]:
    plugins = _plugin_dir(
        tmp_path / f"pp{n}",
        make_report([], run=f"run-{n}", start="2026-03-09T10:00:00Z", end="2026-03-09T10:05:00Z"),
    )
    return [
        "run", "--platform", "linux", "--plugin-dir", str(plugins), "--modules", "linux.demo",
        "--quiet", "--output-dir", str(tmp_path / f"out{n}"), *extra,
    ]  # fmt: skip


def test_run_rejects_an_unverifiable_compare_input_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, _ = _two_runs(tmp_path, capsys)
    bad = _unverifiable_copy(a, tmp_path / "unverifiable")
    rc = _run_main(*_run_args(tmp_path, 1, "--compare", str(bad)))
    err = capsys.readouterr().err
    assert rc == 6 and "comparison skipped" in err and "--allow-unverified" in err
    d = _assessment_dir(tmp_path / "out1")
    doc = json.loads((d / "assessment.json").read_text("utf-8"))
    assert doc["inputs_verified"] is True and doc["inputs"] == []  # nothing was consulted
    assert not (d / "comparison-1.json").exists()


def test_run_with_allow_unverified_uses_the_input_and_records_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, _ = _two_runs(tmp_path, capsys)
    bad = _unverifiable_copy(a, tmp_path / "unverifiable")
    rc = _run_main(*_run_args(tmp_path, 2, "--compare", str(bad), "--allow-unverified"))
    err = capsys.readouterr().err
    assert rc in (0, 4), err
    d = _assessment_dir(tmp_path / "out2")
    doc = json.loads((d / "assessment.json").read_text("utf-8"))
    cmp_doc = json.loads((d / "comparison-1.json").read_text("utf-8"))
    assert doc["inputs_verified"] is False and cmp_doc["inputs_verified"] is False
    assert [e["role"] for e in doc["inputs"] if not e["verified"]] == ["compare"]
    assert validate(doc, "assessment.schema.json") == []
    for name in ("report.md", "report.html"):
        assert "UNVERIFIED" in (d / name).read_text("utf-8"), name
    assert main(["verify", str(d)]) == 0  # the manifest covers the new fields


def test_run_with_mixed_verified_and_unverified_compare_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = _two_runs(tmp_path, capsys)
    bad = _unverifiable_copy(a, tmp_path / "unverifiable")
    args = _run_args(tmp_path, 3, "--compare", str(b), "--compare", str(bad))
    assert _run_main(*args) == 6  # the second is refused; the first is not used either
    capsys.readouterr()
    args = _run_args(tmp_path, 4, "--compare", str(b), "--compare", str(bad), "--allow-unverified")
    rc = _run_main(*args)
    assert rc in (0, 4), capsys.readouterr().err
    doc = json.loads((_assessment_dir(tmp_path / "out4") / "assessment.json").read_text("utf-8"))
    by_path = {e["path"]: e["verified"] for e in doc["inputs"] if e["role"] == "compare"}
    assert by_path == {str(b): True, str(bad): False}
    assert doc["inputs_verified"] is False


def test_run_with_a_verified_compare_input_stays_verified(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Existing behaviour is unchanged for inputs that verify."""
    a, _ = _two_runs(tmp_path, capsys)
    rc = _run_main(*_run_args(tmp_path, 5, "--compare", str(a)))
    assert rc in (0, 4), capsys.readouterr().err
    d = _assessment_dir(tmp_path / "out5")
    doc = json.loads((d / "assessment.json").read_text("utf-8"))
    assert doc["inputs_verified"] is True
    assert [(e["role"], e["verified"]) for e in doc["inputs"]] == [("compare", True)]
    assert "WARNING" not in (d / "report.md").read_text("utf-8")


def test_a_stored_comparison_file_is_a_bare_file_and_needs_the_opt_in(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = _two_runs(tmp_path, capsys)
    cmp_file = tmp_path / "cmp.json"
    assert main(["compare", str(a), str(b), "--output", str(cmp_file)]) in (0, 4)
    capsys.readouterr()
    assert _run_main(*_run_args(tmp_path, 6, "--compare", str(cmp_file))) == 6
    assert "bare file" in capsys.readouterr().err
    rc = _run_main(*_run_args(tmp_path, 7, "--compare", str(cmp_file), "--allow-unverified"))
    assert rc in (0, 4)
    d = _assessment_dir(tmp_path / "out7")
    doc = json.loads((d / "comparison-1.json").read_text("utf-8"))
    assert doc["inputs_verified"] is False
    assert any("no manifest" in e.get("reason", "") for e in doc["inputs"])
