"""Run the Windows audit against the *real* host (no fixture) and validate the result.

Only meaningful on Windows (the CI runner); skipped elsewhere. Checks that each shell
(Windows PowerShell 5.1 and PowerShell 7) produces a schema-valid report, that no module
crashed, and that the audit left a snapshot of host state unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import warnings
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from shared.reporting.manifest import verify_run_dir
from tests.shared.windows_state import explained_by_host, host_changes

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "shared" / "schemas" / "audit-report.schema.json").read_text("utf-8"))
MANIFEST_SCHEMA = json.loads(
    (ROOT / "shared" / "schemas" / "run-manifest.schema.json").read_text("utf-8")
)
SHELLS = [s for s in ("powershell", "pwsh") if shutil.which(s)]
AUDIT = ROOT / "windows" / "audit" / "Invoke-WindowsAudit.ps1"
PERSIST = ROOT / "windows" / "persistence" / "Find-Persistence.ps1"

pytestmark = [
    pytest.mark.skipif(sys.platform != "win32", reason="live audit needs a Windows host"),
    pytest.mark.skipif(not SHELLS, reason="requires PowerShell"),
]

# Host state the audit must never change. Hashes of listings, not contents, keep it cheap.
SNAPSHOT = ROOT / "tests" / "shared" / "windows-state-snapshot.ps1"


def _run(shell: str, args: list[str]) -> subprocess.CompletedProcess[str]:
    cmd = [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", *args]
    env = {k: v for k, v in os.environ.items() if not k.startswith("BO_")}
    return subprocess.run(  # noqa: S603
        cmd, capture_output=True, text=True, timeout=1500, env=env, cwd=ROOT, check=False
    )


def _snapshot(shell: str) -> dict:
    res = _run(shell, ["-File", str(SNAPSHOT)])
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


def _tree(path: Path) -> set[tuple[str, int]]:
    return {(str(p.relative_to(path)), p.stat().st_size) for p in path.rglob("*") if p.is_file()}


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("script", [AUDIT, PERSIST], ids=["audit", "persistence"])
def test_live_audit_is_valid_and_read_only(shell: str, script: Path) -> None:
    before = _snapshot(shell)
    repo_before = _tree(ROOT / "windows")

    res = _run(shell, ["-File", str(script), "-Json", "-Quiet"])
    assert res.returncode in (0, 4, 6), (res.returncode, res.stderr[-2000:])

    # stdout is the machine-readable report, and only that.
    report = json.loads(res.stdout)
    errors = sorted(Draft202012Validator(SCHEMA).iter_errors(report), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors[:5]]
    assert report["run"]["mode"] == "read-only"
    assert report["run"]["exit_code"] == res.returncode
    assert report["tool"]["category"] == ("audit" if script == AUDIT else "persistence")

    ids = [f["id"] for f in report["findings"]]
    assert len(ids) == len(set(ids))
    for fid in ids:
        assert re.fullmatch(r"[A-Z]{2,6}-[A-Z0-9]+-\d{3,}", fid), fid
    # Every module must have contributed on a real host and none may have crashed.
    assert not [e for e in report["errors"] if e["code"] == "MODULE_FAILED"], report["errors"]
    if script == AUDIT:
        for prefix in ("SYS", "USR", "PRC", "NET", "SVC", "TSK", "AUT", "FW", "SEC", "FS"):
            assert any(i.startswith(prefix + "-") for i in ids), prefix

    # No secret-looking material in the output.
    assert not re.search(r"(?i)(password|passwd|secret|token)\s*=\s*[^\s<*]{4,}", res.stdout)

    after = _snapshot(shell)
    changed = host_changes(before, after)
    for note in explained_by_host(changed, before, after):
        warnings.warn(f"host changed itself during the audit: {note}", stacklevel=1)
    assert not changed, (
        f"audit changed host state: {changed} (before={before['diag']}, after={after['diag']})"
    )
    assert _tree(ROOT / "windows") == repo_before


@pytest.mark.parametrize("shell", SHELLS)
def test_live_output_dir_holds_report_text_and_log(shell: str, tmp_path: Path) -> None:
    out = tmp_path / "out"
    res = _run(shell, ["-File", str(AUDIT), "-Modules", "system,users", "-OutputDir", str(out)])
    assert res.returncode in (0, 4, 6), (res.returncode, res.stderr[-2000:])
    runs = list(out.glob("blueops-run-*"))
    assert len(runs) == 1
    assert {p.name for p in runs[0].iterdir()} == {
        "report.json",
        "report.txt",
        "run.log",
        "manifest.json",
    }
    report = json.loads((runs[0] / "report.json").read_text("utf-8-sig"))
    assert not list(Draft202012Validator(SCHEMA).iter_errors(report))
    assert report["run"]["exit_code"] == res.returncode
    # The manifest the Windows collector wrote is valid, verifies, and its digest was printed.
    manifest_path = runs[0] / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8-sig"))
    assert not list(Draft202012Validator(MANIFEST_SCHEMA).iter_errors(manifest))
    assert manifest["run"]["id"] == report["run"]["id"] and manifest["complete"] is True
    assert verify_run_dir(runs[0]) == []
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert f"Manifest SHA-256: {digest}" in res.stderr
    assert verify_run_dir(runs[0], digest) == []
    (runs[0] / "run.log").write_bytes(b"tampered")
    assert any("run.log" in problem for problem in verify_run_dir(runs[0]))


@pytest.mark.parametrize("shell", SHELLS)
def test_live_run_directories_are_never_reused(shell: str, tmp_path: Path) -> None:
    """Two runs into the same output directory (possibly within one second) keep both reports."""
    out = tmp_path / "out"
    for _ in range(2):
        res = _run(
            shell, ["-File", str(AUDIT), "-Modules", "system", "-OutputDir", str(out), "-Quiet"]
        )
        assert res.returncode in (0, 4, 6), (res.returncode, res.stderr[-2000:])
    runs = sorted(out.glob("blueops-run-*"))
    assert len(runs) == 2
    assert all(verify_run_dir(r) == [] for r in runs)
    ids = {json.loads((r / "report.json").read_text("utf-8-sig"))["run"]["id"] for r in runs}
    assert len(ids) == 2
