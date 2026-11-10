"""Assessment loading must verify integrity by default and must never fail open.

The contract (``shared/engine/loader.py``): with verification on, a missing, malformed or
non-matching ``manifest.json`` is an error; ``assessment.json`` addressed as a file is verified
through its directory; a bare file that has no manifest cannot be verified and is refused;
``verify=False`` / ``--allow-unverified`` is the only way around, and it cannot be combined with
an expected digest.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from engine_support import fake_assessment, fnd, make_report
from telemetry_support import proc, stream

from shared.engine.cli import main
from shared.engine.loader import LoadError, load_assessment
from shared.engine.manifest import MANIFEST_NAME, verify_directory, write_manifest
from shared.reporting.contracts import ExitCode
from shared.telemetry import ingest

REPORT = make_report([fnd("USR-AAA-001", "high", evidence=[("file", "/etc/passwd")])])
MODULE_REPORT = Path("modules/linux.users/output/blueops-run-20260301T100000Z-fake/report.json")


def build(tmp_path: Path) -> tuple[Path, str, dict[str, Any]]:
    """A complete assessment directory with a manifest; returns (dir, manifest sha256, doc)."""
    a = fake_assessment(tmp_path, {"linux.users": REPORT})
    (a.directory / "assessment.json").write_text(json.dumps(a.document), encoding="utf-8")
    _, digest = write_manifest(a.directory, a.document)
    return a.directory, digest, a.document


def manifest_of(d: Path) -> dict[str, Any]:
    return json.loads((d / MANIFEST_NAME).read_text("utf-8"))  # type: ignore[no-any-return]


# 1 ----------------------------------------------------------------------- valid + valid


def test_valid_assessment_and_manifest_load_by_directory_and_by_file(tmp_path: Path) -> None:
    d, digest, doc = build(tmp_path)
    assert load_assessment(d)["assessment"]["id"] == doc["assessment"]["id"]
    assert load_assessment(d / "assessment.json")["kind"] == "assessment"
    assert load_assessment(d, expected_sha256=digest)["kind"] == "assessment"
    assert verify_directory(d, digest) == []


# 2 ------------------------------------------------------------------- missing manifest


def test_missing_manifest_is_a_failure_not_a_pass(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    (d / MANIFEST_NAME).unlink()
    for target in (d, d / "assessment.json"):
        with pytest.raises(LoadError, match="no manifest.json.*cannot be verified"):
            load_assessment(target)


def test_tampered_assessment_with_deleted_manifest_is_refused(tmp_path: Path) -> None:
    """The original bypass: edit the data, delete the manifest, load without complaint."""
    d, _, doc = build(tmp_path)
    (d / "assessment.json").write_text(json.dumps({**doc, "findings": []}), encoding="utf-8")
    (d / MANIFEST_NAME).unlink()
    with pytest.raises(LoadError, match="cannot be verified"):
        load_assessment(d)


def test_cli_exits_nonzero_with_a_clear_message_and_opt_in_works(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d, _, _ = build(tmp_path)
    (d / MANIFEST_NAME).unlink()
    out = tmp_path / "r.md"
    rc = main(["report", str(d), "--format", "markdown", "--output", str(out)])
    err = capsys.readouterr().err
    assert rc == int(ExitCode.PRECONDITION) and "no manifest.json" in err
    assert not out.exists()
    rc = main(
        ["report", str(d), "--format", "markdown", "--output", str(out), "--allow-unverified"]
    )
    assert rc == int(ExitCode.OK) and out.is_file()


def test_cli_compare_refuses_unverifiable_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    d, _, _ = build(tmp_path)
    bare = tmp_path / "bare.json"
    bare.write_text((d / "assessment.json").read_text("utf-8"), encoding="utf-8")
    rc = main(["compare", str(d), str(bare)])
    assert rc == int(ExitCode.PRECONDITION) and "cannot be verified" in capsys.readouterr().err


# 3 -------------------------------------------------------- modified after manifest creation


def test_assessment_modified_after_the_manifest_is_refused(tmp_path: Path) -> None:
    d, _, doc = build(tmp_path)
    (d / "assessment.json").write_text(json.dumps({**doc, "findings": []}), encoding="utf-8")
    with pytest.raises(LoadError, match="assessment.json: content differs"):
        load_assessment(d)
    with pytest.raises(LoadError, match="content differs"):
        load_assessment(d / "assessment.json")


def test_module_report_modified_after_the_manifest_is_refused(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    target = d / MODULE_REPORT
    target.write_text(target.read_text("utf-8").replace("web01", "web02"), encoding="utf-8")
    with pytest.raises(LoadError, match="content differs"):
        load_assessment(d)


# 4 --------------------------------------------------------------------- modified manifest


def test_manifest_with_an_altered_hash_is_refused(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    m = manifest_of(d)
    m["files"][0]["sha256"] = "0" * 64
    (d / MANIFEST_NAME).write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(LoadError, match="content differs"):
        load_assessment(d)


def test_manifest_rewritten_together_with_the_data_needs_the_expected_digest(
    tmp_path: Path,
) -> None:
    """Without an off-host digest a consistent rewrite is undetectable; with one it is caught."""
    d, original_digest, doc = build(tmp_path)
    (d / "assessment.json").write_text(json.dumps({**doc, "findings": []}), encoding="utf-8")
    (d / MANIFEST_NAME).unlink()
    write_manifest(d, doc)  # the attacker re-hashes everything
    assert (
        load_assessment(d)["findings"] == []
    )  # documented limit: a manifest cannot vouch for itself
    with pytest.raises(LoadError, match="expected digest"):
        load_assessment(d, expected_sha256=original_digest)


def test_expected_digest_must_be_checked_or_rejected_never_ignored(tmp_path: Path) -> None:
    d, digest, _ = build(tmp_path)
    with pytest.raises(LoadError, match="expected digest"):
        load_assessment(d, expected_sha256="f" * 64)
    with pytest.raises(LoadError, match="verification off"):
        load_assessment(d, verify=False, expected_sha256=digest)


# 5 -------------------------------------------------------------------- malformed manifest


@pytest.mark.parametrize(
    "payload",
    [
        "{",
        "[]",
        "null",
        '{"kind": "assessment-manifest"}',
        '{"kind": "run-manifest", "files": []}',
        '{"a": 1, "a": 2}',
    ],
)
def test_malformed_manifest_is_refused(tmp_path: Path, payload: str) -> None:
    d, _, _ = build(tmp_path)
    (d / MANIFEST_NAME).write_text(payload, encoding="utf-8")
    with pytest.raises(LoadError):
        load_assessment(d)


def test_manifest_with_unsafe_paths_is_refused(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    m = manifest_of(d)
    m["files"].append({"path": "../outside", "sha256": "0" * 64, "size": 1})
    (d / MANIFEST_NAME).write_text(json.dumps(m), encoding="utf-8")
    with pytest.raises(LoadError, match="unsafe path"):
        load_assessment(d)


@pytest.mark.skipif(os.name != "posix", reason="needs symbolic links")
def test_symlinked_manifest_is_refused(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    real = tmp_path / "elsewhere.json"
    real.write_text((d / MANIFEST_NAME).read_text("utf-8"), encoding="utf-8")
    (d / MANIFEST_NAME).unlink()
    (d / MANIFEST_NAME).symlink_to(real)
    with pytest.raises(LoadError, match="symbolic link"):
        load_assessment(d)
    with pytest.raises(LoadError, match="symbolic link"):  # invalid, so not overridable either
        load_assessment(d, verify=False)


# 6 ------------------------------------------------------------------- missing files


def test_missing_assessment_file_is_refused(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    (d / "assessment.json").unlink()
    with pytest.raises(LoadError, match="no assessment.json or report.json"):
        load_assessment(d)
    assert any("missing" in p for p in verify_directory(d))


def test_missing_module_file_listed_in_the_manifest_is_refused(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    (d / MODULE_REPORT).unlink()
    with pytest.raises(LoadError, match="missing or not a regular file"):
        load_assessment(d)


# 7 --------------------------------------------------------------- unexpected extra files


def test_files_the_manifest_does_not_list_are_refused(tmp_path: Path) -> None:
    """Contract: the manifest is complete for the directory; an unlisted file is a failure."""
    d, _, _ = build(tmp_path)
    (d / "extra.txt").write_text("x", encoding="utf-8")
    with pytest.raises(LoadError, match="not listed in the manifest"):
        load_assessment(d)


@pytest.mark.skipif(os.name != "posix", reason="needs symbolic links")
def test_symlinks_inside_the_directory_are_refused(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    (d / "link").symlink_to(tmp_path)
    with pytest.raises(LoadError, match="symbolic link"):
        load_assessment(d)


# 8 ---------------------------------------------------------------------- direct files


def test_a_bare_file_cannot_bypass_verification(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    copy = tmp_path / "copy.json"
    copy.write_text((d / "assessment.json").read_text("utf-8"), encoding="utf-8")
    with pytest.raises(LoadError, match="bare file has no manifest"):
        load_assessment(copy)
    # Same bytes, in a directory with no manifest, under the canonical name:
    lone = tmp_path / "lone"
    lone.mkdir()
    (lone / "assessment.json").write_text(copy.read_text("utf-8"), encoding="utf-8")
    with pytest.raises(LoadError, match="no manifest.json"):
        load_assessment(lone / "assessment.json")


@pytest.mark.skipif(os.name != "posix", reason="needs symbolic links")
def test_a_symlink_to_a_verified_assessment_is_refused(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    link = tmp_path / "latest"
    link.symlink_to(d)
    with pytest.raises(LoadError, match="symbolic link"):
        load_assessment(link)


def test_collector_report_directories_need_their_run_manifest(tmp_path: Path) -> None:
    d, _, _ = build(tmp_path)
    run = (d / MODULE_REPORT).parent
    assert not (run / MANIFEST_NAME).exists()  # the fake executor writes no run manifest
    with pytest.raises(LoadError, match="no manifest.json"):
        load_assessment(run)
    with pytest.raises(LoadError, match="no manifest.json"):
        load_assessment(run / "report.json")


# 9 ----------------------------------------------------------------- explicit unverified


def test_explicit_unverified_loading_still_validates_the_document(tmp_path: Path) -> None:
    d, _, doc = build(tmp_path)
    (d / MANIFEST_NAME).unlink()
    assert load_assessment(d, verify=False)["assessment"]["id"] == doc["assessment"]["id"]
    assert load_assessment(d / "assessment.json", verify=False)["kind"] == "assessment"
    (d / "assessment.json").write_text('{"kind": "assessment"}', encoding="utf-8")
    with pytest.raises(LoadError, match="not a valid assessment"):
        load_assessment(d, verify=False)


def test_the_opt_out_never_accepts_a_directory_whose_verification_failed(tmp_path: Path) -> None:
    """`--allow-unverified` covers "nothing to verify against", not "verification failed": a
    manifest that exists and does not match is invalid data under every option."""
    d, _, doc = build(tmp_path)
    (d / "assessment.json").write_text(json.dumps({**doc, "findings": []}), encoding="utf-8")
    for verify in (True, False):
        with pytest.raises(LoadError, match="content differs"):
            load_assessment(d, verify=verify)


# telemetry stores share the contract -------------------------------------------------------


def test_telemetry_store_without_a_manifest_is_refused(tmp_path: Path) -> None:
    src = tmp_path / "s.jsonl"
    src.write_bytes(stream([proc(1, 0, "init")]))
    store = ingest.write_store(
        ingest.ingest_paths([src], allow_unverified=True),
        tmp_path / "out",
        [("s.jsonl", src.read_bytes())],
    )
    assert ingest.load_telemetry(store)["kind"] == "telemetry"
    (store / MANIFEST_NAME).unlink()
    with pytest.raises(ingest.IngestError, match="no manifest.json"):
        ingest.load_telemetry(store)
    with pytest.raises(ingest.IngestError, match="no manifest.json"):
        ingest.read_path(store)
