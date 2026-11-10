"""``blueops-diff`` / ``blueops-detect`` keep their documented output but never look trusted.

Their JSON/text output is independent of the input form by contract, so the standing of the
inputs cannot be added to it. It is reported on **stderr** instead, and only for inputs that
were not verified (a bare report, a run directory without a manifest, a saved ``--from-diff``).
A manifest that exists and does not match is refused outright, as before.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from baseline_builders import pair, standard_baseline

from shared.reporting import detect as detect_cli
from shared.reporting import diff as diff_cli

NOW = "2026-01-02T12:00:00Z"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _run_dir(root: Path, name: str, report: dict[str, Any], *, manifest: bool) -> Path:
    d = root / name
    d.mkdir(parents=True)
    rep = d / "report.json"
    rep.write_text(json.dumps(report), encoding="utf-8")
    if manifest:
        (d / "manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": "0.2.0",
                    "kind": "run-manifest",
                    "hash_algorithm": "sha256",
                    "complete": True,
                    "run": {"id": report["run"]["id"]},
                    "files": [
                        {"path": "report.json", "sha256": _sha(rep), "size": rep.stat().st_size}
                    ],
                }
            ),
            encoding="utf-8",
        )
    return d


def _tool(mod: Any, capsys: pytest.CaptureFixture[str], *argv: Any) -> tuple[int, str, str]:
    code = mod.main([str(a) for a in argv])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


@pytest.fixture
def reports(tmp_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    return pair(standard_baseline(), standard_baseline())


@pytest.mark.parametrize("mod", [diff_cli, detect_cli])
def test_bare_reports_warn_on_stderr_and_stdout_is_unchanged(
    mod: Any, tmp_path: Path, reports: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = reports
    plain = [
        _run_dir(tmp_path / "plain", "a", a, manifest=False),
        _run_dir(tmp_path / "plain", "b", b, manifest=False),
    ]
    good = [
        _run_dir(tmp_path / "good", "a", a, manifest=True),
        _run_dir(tmp_path / "good", "b", b, manifest=True),
    ]
    args = ["--json", "--generated-at", NOW]
    c1, out_plain, err_plain = _tool(mod, capsys, *plain, *args)
    c2, out_good, err_good = _tool(mod, capsys, *good, *args)
    assert (c1, out_plain) == (c2, out_good)  # the documented output does not depend on this
    json.loads(out_plain)  # still pure JSON: the warning is not in stdout
    assert "WARNING" not in out_plain and "UNVERIFIED" not in out_plain
    assert err_plain.count("UNVERIFIED") == 2  # one per input
    assert "UNVERIFIED" not in err_good  # verified inputs: nothing to warn about


@pytest.mark.parametrize("mod", [diff_cli, detect_cli])
def test_the_warning_survives_quiet_and_does_not_reach_an_output_file(
    mod: Any, tmp_path: Path, reports: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = reports
    pa = tmp_path / "a.json"
    pb = tmp_path / "b.json"
    pa.write_text(json.dumps(a), encoding="utf-8")
    pb.write_text(json.dumps(b), encoding="utf-8")
    out = tmp_path / "out.json"
    _, stdout, err = _tool(mod, capsys, pa, pb, "--json", "--quiet", "--output", out)
    assert stdout == "" and err.count("UNVERIFIED") == 2
    ref = tmp_path / "ref.json"
    _tool(mod, capsys, pa, pb, "--json", "--quiet", "--output", ref)
    assert out.read_text("utf-8") == ref.read_text("utf-8")
    assert "UNVERIFIED" not in out.read_text("utf-8")


def test_a_failed_manifest_is_still_refused_not_downgraded(
    tmp_path: Path, reports: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = reports
    da = _run_dir(tmp_path, "a", a, manifest=True)
    db = _run_dir(tmp_path, "b", b, manifest=True)
    (db / "report.json").write_text((db / "report.json").read_text("utf-8") + " ", "utf-8")
    code, out, err = _tool(diff_cli, capsys, da, db, "--json")
    assert code == 3 and out == "" and "manifest verification" in err
    shutil.rmtree(da)  # a dangling/absent input is an error, not a silent downgrade
    code, out, _ = _tool(diff_cli, capsys, da, db, "--json")
    assert code == 3 and out == ""


def test_from_diff_warns_that_its_origin_cannot_be_checked(
    tmp_path: Path, reports: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = reports
    pa, pb = tmp_path / "a.json", tmp_path / "b.json"
    pa.write_text(json.dumps(a), encoding="utf-8")
    pb.write_text(json.dumps(b), encoding="utf-8")
    saved = tmp_path / "d.json"
    diff_cli.main(
        [str(pa), str(pb), "--json", "--quiet", "--generated-at", NOW, "--output", str(saved)]
    )
    capsys.readouterr()
    code, out, err = _tool(
        detect_cli, capsys, "--from-diff", saved, "--json", "--generated-at", NOW
    )
    assert "saved diff with no provenance" in err and "UNVERIFIED" in err
    json.loads(out)
    assert "UNVERIFIED" not in out
    assert code in (0, 4, 6)
