"""Verified / unverified / invalid are three different outcomes.

* verified: a manifest exists and matched;
* unverified: there is nothing to verify against (no manifest, or a bare file), and the caller
  explicitly accepted that with ``--allow-unverified`` / ``verify=False``;
* invalid: a manifest exists and verification was attempted and **failed** (hash mismatch,
  malformed manifest, missing or unlisted file, symlink, wrong digest). Nothing accepts this.

The opt-out must never turn an integrity failure into an accepted document, in any command that
loads assessments, comparisons, detection results or telemetry.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest
from engine_support import fnd, make_report
from telemetry_support import proc, stream
from test_engine_cli import _assessment_dir, _plugin_dir, _two_runs
from test_engine_integrity import build
from test_provenance import _rewrite, _unverifiable_copy

from shared.engine.cli import main
from shared.engine.loader import (
    InvalidIntegrityError,
    LoadError,
    UnverifiableError,
    load_assessment,
    stored_file_status,
)
from shared.engine.manifest import MANIFEST_NAME
from shared.engine.provenance import status
from shared.reporting.inventory import ReportError, load_snapshot
from shared.rules.cli import _load_results
from shared.rules.export import to_csv, to_jsonl
from shared.telemetry import ingest

STAMP = "2026-03-09T00:00:00Z"


# --------------------------------------------------------------- ways to make a dir invalid


def _tamper(d: Path) -> None:
    doc = json.loads((d / "assessment.json").read_text("utf-8"))
    (d / "assessment.json").write_text(json.dumps({**doc, "findings": []}), encoding="utf-8")


def _unlisted_file(d: Path) -> None:
    (d / "extra.txt").write_text("not in the manifest", encoding="utf-8")


def _missing_listed_file(d: Path) -> None:
    next(p for p in (d / "modules").rglob("*") if p.is_file()).unlink()


def _malformed_manifest(d: Path) -> None:
    (d / MANIFEST_NAME).write_text("{not json", encoding="utf-8")


def _wrong_kind_manifest(d: Path) -> None:
    (d / MANIFEST_NAME).write_text('{"kind": "something-else"}', encoding="utf-8")


def _symlinked_manifest(d: Path) -> None:
    real = d.parent / "elsewhere.json"
    real.write_text((d / MANIFEST_NAME).read_text("utf-8"), encoding="utf-8")
    (d / MANIFEST_NAME).unlink()
    (d / MANIFEST_NAME).symlink_to(real)


def _dangling_manifest(d: Path) -> None:
    (d / MANIFEST_NAME).unlink()
    (d / MANIFEST_NAME).symlink_to(d.parent / "does-not-exist.json")


def _symlinked_member(d: Path) -> None:
    real = d.parent / "real-assessment.json"
    real.write_text((d / "assessment.json").read_text("utf-8"), encoding="utf-8")
    (d / "assessment.json").unlink()
    (d / "assessment.json").symlink_to(real)


BREAKERS: list[Callable[[Path], None]] = [
    _tamper,
    _unlisted_file,
    _missing_listed_file,
    _malformed_manifest,
    _wrong_kind_manifest,
    _symlinked_manifest,
    _dangling_manifest,
    _symlinked_member,
]
IDS = [f.__name__.strip("_") for f in BREAKERS]


@pytest.fixture(params=BREAKERS, ids=IDS)
def invalid_dir(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    d, _, _ = build(tmp_path)
    request.param(d)
    return d


# ---------------------------------------------------------------------- 1. the loader


def test_every_failed_verification_is_invalid_with_and_without_the_opt_out(
    invalid_dir: Path,
) -> None:
    for verify in (True, False):
        with pytest.raises(InvalidIntegrityError):
            load_assessment(invalid_dir, verify=verify)
        with pytest.raises(LoadError):  # addressed as a file: also refused (a symlink, or invalid)
            load_assessment(invalid_dir / "assessment.json", verify=verify)


def test_absent_manifest_is_unverifiable_and_only_then_does_the_opt_out_accept(
    tmp_path: Path,
) -> None:
    d, _, _ = build(tmp_path)
    (d / MANIFEST_NAME).unlink()
    with pytest.raises(UnverifiableError, match="cannot be verified"):
        load_assessment(d)
    doc = load_assessment(d, verify=False)
    assert doc.load_verified is False and doc["inputs_verified"] is False
    assert "no manifest.json" in doc["inputs"][0]["reason"]


def test_bare_file_in_a_directory_whose_manifest_fails_is_invalid_not_unverified(
    tmp_path: Path,
) -> None:
    """Addressing a file directly must not sidestep the directory's failed check."""
    d, _, doc = build(tmp_path)
    other = d / "renamed-copy.json"
    other.write_text(json.dumps(doc), encoding="utf-8")  # unlisted: the directory now fails
    with pytest.raises(InvalidIntegrityError):
        load_assessment(other, verify=False)
    bare = tmp_path / "plain" / "x.json"
    bare.parent.mkdir()
    bare.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(UnverifiableError):
        load_assessment(bare)
    assert load_assessment(bare, verify=False).load_verified is False


def test_a_collector_run_with_a_failing_manifest_is_invalid(tmp_path: Path) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "report.json").write_text(json.dumps(make_report([fnd("USR-AAA-001", "high")])))
    (run / MANIFEST_NAME).write_text('{"kind": "run-manifest", "files": []}', encoding="utf-8")
    for verify in (True, False):
        with pytest.raises(InvalidIntegrityError):
            load_assessment(run, verify=verify)
    (run / MANIFEST_NAME).unlink()
    assert load_assessment(run, verify=False).load_verified is False  # unverifiable: accepted


def test_the_opt_out_cannot_be_combined_with_an_expected_digest(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    with pytest.raises(LoadError, match="expected manifest digest"):
        load_assessment(d, verify=False, expected_sha256="0" * 64)
    with pytest.raises(InvalidIntegrityError, match="expected digest"):
        load_assessment(d, expected_sha256="0" * 64)


def test_legacy_baseline_loader_does_not_treat_a_dangling_manifest_as_no_manifest(
    tmp_path: Path,
) -> None:
    run = tmp_path / "run"
    run.mkdir()
    (run / "report.json").write_text(json.dumps(make_report([])), encoding="utf-8")
    (run / MANIFEST_NAME).symlink_to(tmp_path / "gone.json")
    with pytest.raises(ReportError, match="manifest verification"):
        load_snapshot(run)


# ------------------------------------------------------------------------- 2. commands


@pytest.mark.parametrize("cmd", ["report", "compare", "detect"])
def test_cli_rejects_an_invalid_directory_even_with_the_opt_out(
    invalid_dir: Path, tmp_path: Path, cmd: str, capsys: pytest.CaptureFixture[str]
) -> None:
    good, _, _ = build(tmp_path / "good")
    argv = {
        "report": ["report", str(invalid_dir), "--allow-unverified"],
        "compare": ["compare", str(good), str(invalid_dir), "--allow-unverified"],
        "detect": ["detect", "run", str(invalid_dir), "--allow-unverified", "--quiet"],
    }[cmd]
    rc = main(argv)
    err = capsys.readouterr().err
    assert rc == 3, err
    assert "failed manifest verification" in err or "manifest" in err


def test_run_never_uses_an_invalid_compare_input_and_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, _ = _two_runs(tmp_path, capsys)
    bad = tmp_path / "tampered"
    shutil.copytree(a, bad)
    _tamper(bad)
    plugins = _plugin_dir(tmp_path / "pp", make_report([]))
    args = [
        "run", "--platform", "linux", "--plugin-dir", str(plugins), "--modules", "linux.demo",
        "--quiet", "--output-dir", str(tmp_path / "out"), "--compare", str(bad),
        "--allow-unverified",
    ]  # fmt: skip
    assert main(args) == 6
    assert "failed manifest verification" in capsys.readouterr().err
    d = _assessment_dir(tmp_path / "out")
    doc = json.loads((d / "assessment.json").read_text("utf-8"))
    assert not (d / "comparison-1.json").exists()
    assert doc["inputs"] == [] and doc["inputs_verified"] is True  # nothing was consulted


def test_run_history_excludes_an_invalid_snapshot_and_records_why(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import time  # noqa: PLC0415 - one-second resolution of started_at

    a, b = _two_runs(tmp_path, capsys)
    time.sleep(1.1)
    hist = tmp_path / "hist"
    hist.mkdir()
    shutil.copytree(a, hist / "ok")
    shutil.copytree(b, hist / "tampered")
    _tamper(hist / "tampered")
    plugins = _plugin_dir(tmp_path / "pp", make_report([]))
    args = [
        "run", "--platform", "linux", "--plugin-dir", str(plugins), "--modules", "linux.demo",
        "--quiet", "--output-dir", str(tmp_path / "out"), "--detect", "--history", str(hist),
        "--allow-unverified",
    ]  # fmt: skip
    assert main(args) in (0, 4, 6)
    res = json.loads((_assessment_dir(tmp_path / "out") / "detections.json").read_text("utf-8"))
    assert res["history"]["snapshots"] == 1
    assert any("failed manifest verification" in x["reason"] for x in res["history"]["excluded"])
    assert all("tampered" not in e["path"] for e in res["inputs"])


def test_a_stored_comparison_in_a_directory_that_fails_its_manifest_is_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = _two_runs(tmp_path, capsys)
    # a finished run directory holds comparison files its manifest covers; alter the directory
    cmp_file = a / "comparison-1.json"
    args = ["compare", str(a), str(b), "--allow-unverified", "--output", str(cmp_file)]
    assert main(args) in (0, 4)
    capsys.readouterr()
    plugins = _plugin_dir(tmp_path / "pp", make_report([]))
    args = [
        "run", "--platform", "linux", "--plugin-dir", str(plugins), "--modules", "linux.demo",
        "--quiet", "--output-dir", str(tmp_path / "out"), "--compare", str(cmp_file),
        "--allow-unverified",
    ]  # fmt: skip
    assert main(args) == 6  # the file is unlisted in a manifest-bearing directory: invalid
    assert "manifest verification" in capsys.readouterr().err


# ----------------------------------------------------------------- 3. detection results


def _results_file(tmp_path: Path) -> Path:
    d, _, _ = build(tmp_path / "src")
    out = tmp_path / "res.json"
    args = ["detect", "run", str(d), "--quiet", "--output", str(out), "--allow-unverified"]
    assert main(args) in (0, 4, 6)
    return out


def test_a_stored_results_file_cannot_vouch_for_itself(tmp_path: Path) -> None:
    res = _results_file(tmp_path)
    doc = json.loads(res.read_text("utf-8"))
    doc["inputs_verified"], doc["inputs"] = True, []  # a hand-edited claim of "verified"
    res.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(LoadError, match="--allow-unverified|bare"):
        _load_results(str(res))  # unverifiable and no opt-in: refused
    loaded = _load_results(
        str(res), True
    )  # the loader every detect show/export/report goes through
    ok, inputs = status(loaded)
    assert ok is False and any(not i["verified"] and i["role"] == "source" for i in inputs)
    row = {  # the exporters need one detection to write a row
        "id": "d1", "rule": {"id": "R"}, "title": "t", "severity": "low", "confidence": "low",
        "nature": "observation", "category": "c", "host": {"hostname": "h"},
        "references": {"attack": [], "nist": []}, "contributing": [], "evidence": [],
        "remediation": "r",
    }  # fmt: skip
    loaded["detections"] = [row]
    assert to_csv(loaded).splitlines()[1].endswith(",false")
    assert json.loads(to_jsonl(loaded))["inputs_verified"] is False


def test_stored_file_status_distinguishes_all_three_states(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    assert stored_file_status(d / "assessment.json") == (True, "")
    _unlisted_file(d)
    with pytest.raises(InvalidIntegrityError):
        stored_file_status(d / "assessment.json")
    bare = tmp_path / "bare" / "x.json"
    bare.parent.mkdir()
    bare.write_text("{}", encoding="utf-8")
    verified, why = stored_file_status(bare)
    assert verified is False and "no manifest" in why


# ---------------------------------------------------------------------- 4. telemetry


def _store(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    src = tmp_path / "s.jsonl"
    src.write_bytes(stream([proc(1, "init", "/sbin/init")]))
    return ingest.write_store(
        ingest.ingest_paths([src], allow_unverified=True),
        tmp_path / "stores",
        [(src.name, src.read_bytes())],
    )


def test_telemetry_stores_are_invalid_when_altered_and_there_is_no_opt_out(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    (store / "telemetry.json").write_text(
        (store / "telemetry.json").read_text("utf-8").replace("init", "evil"), encoding="utf-8"
    )
    for fn in (ingest.load_telemetry, ingest.read_path):
        with pytest.raises(ingest.IngestError, match="manifest verification"):
            fn(store)


def test_telemetry_import_of_assessments_follows_the_same_three_states(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ok, _, _ = build(tmp_path / "ok")
    plain = _unverifiable_copy(ok, tmp_path / "plain")
    bad = tmp_path / "bad"
    shutil.copytree(ok, bad)
    _tamper(bad)
    out = ["--output-dir", str(tmp_path / "st"), "--quiet"]
    f = "assessment.json"  # a directory would be read as a telemetry store
    assert main(["telemetry", "import", str(plain / f), *out]) == 3  # unverifiable: refused
    capsys.readouterr()
    assert main(["telemetry", "import", str(plain / f), *out, "--allow-unverified"]) in (0, 6)
    capsys.readouterr()
    assert main(["telemetry", "import", str(bad / f), *out, "--allow-unverified"]) == 3  # invalid
    assert "manifest verification" in capsys.readouterr().err
    assert main(["telemetry", "import", str(ok / f), *out]) in (0, 6)  # verified


# ----------------------------------------------------------- 5. tampered provenance claims


def test_a_document_cannot_claim_verified_next_to_an_unverified_entry() -> None:
    doc = {
        "inputs_verified": True,
        "inputs": [{"role": "a", "path": "p", "verified": False, "reason": "x"}],
    }
    assert status(doc)[0] is False
    assert status({"inputs_verified": True, "inputs": [{"role": "a", "path": "p"}]})[0] is False
    assert status({"inputs_verified": "yes", "inputs": []})[0] is False
    assert status({})[0] is None  # no record: no claim either way


def test_provenance_a_file_claims_is_overridden_by_how_it_was_actually_loaded(
    tmp_path: Path,
) -> None:
    d, _, doc = build(tmp_path)
    claim = {**doc, "inputs_verified": True, "inputs": []}
    _rewrite(d, claim)
    (d / MANIFEST_NAME).unlink()  # now nothing backs the claim
    loaded = load_assessment(d, verify=False)
    assert loaded["inputs_verified"] is False  # the claim in the file does not survive
    assert status(loaded)[0] is False
