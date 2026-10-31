"""Run the Windows audit tooling against the synthetic host fixture and validate the reports.

Runs on any platform with PowerShell: ``pwsh`` (7+) and, on Windows, Windows PowerShell 5.1.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "windows-host"
SCHEMA = json.loads((ROOT / "shared" / "schemas" / "audit-report.schema.json").read_text("utf-8"))
SHELLS = [s for s in ("pwsh", "powershell") if shutil.which(s)]

pytestmark = pytest.mark.skipif(not SHELLS, reason="requires PowerShell")

SCRIPTS = [
    ("windows/audit/Invoke-WindowsAudit.ps1", []),
    ("windows/audit/Invoke-WindowsAudit.ps1", ["-Modules", "users,network,firewall"]),
    ("windows/persistence/Find-Persistence.ps1", []),
]


def _prepare_fixture(dest: Path) -> None:
    """Mirror tests/windows/TestHelper.ps1: date tokens, *.fixture names, file ages."""
    shutil.copytree(FIXTURE, dest)
    now = datetime.now(timezone.utc)

    def token(match: re.Match[str]) -> str:
        return (now - timedelta(days=int(match.group(1)))).strftime("%Y-%m-%dT%H:%M:%SZ")

    for path in dest.rglob("*.json"):
        text = path.read_text("utf-8")
        path.write_text(re.sub(r"@@AGO:(\d+)@@", token, text), "utf-8")
    fs = dest / "fs"
    for path in list(fs.rglob("*.fixture")):
        path.rename(path.with_suffix(""))
    stamp = time.time()
    for path in fs.rglob("*"):
        if path.is_file():
            os.utime(path, (stamp, stamp))
    ages = json.loads((dest / "data" / "fs-ages.json").read_text("utf-8"))
    for rel, days in ages.items():
        target = fs / rel
        old = stamp - days * 86400
        os.utime(target, (old, old))


@pytest.fixture(scope="module")
def fixture_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    dest = tmp_path_factory.mktemp("bo-win") / "host"
    _prepare_fixture(dest)
    return dest


def _run(shell: str, script: str, args: list[str], fixture: Path) -> dict:
    env = {**os.environ, "BO_TEST_MODE": "1", "BO_FIXTURE_DIR": str(fixture)}
    env.pop("BO_FORCE_MISSING", None)
    proc = subprocess.run(  # noqa: S603
        [
            shutil.which(shell) or shell,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ROOT / script),
            "-Json",
            "-Quiet",
            *args,
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=300,
    )
    assert proc.returncode in (0, 4, 6), proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize(("script", "args"), SCRIPTS)
def test_report_conforms_to_schema(
    shell: str, script: str, args: list[str], fixture_dir: Path
) -> None:
    report = _run(shell, script, args, fixture_dir)
    errors = sorted(Draft202012Validator(SCHEMA).iter_errors(report), key=str)
    assert not errors, errors[0].message
    assert report["run"]["mode"] == "read-only"
    assert report["host"]["os"]["family"] == "windows"
    assert report["summary"]["total"] == len(report["findings"])
    ids = [f["id"] for f in report["findings"]]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("shell", SHELLS)
def test_full_audit_report_has_expected_signals(shell: str, fixture_dir: Path) -> None:
    report = _run(shell, "windows/audit/Invoke-WindowsAudit.ps1", [], fixture_dir)
    ids = {f["id"] for f in report["findings"]}
    assert {
        "USR-HIDDEN-001",
        "PRC-MASQ-001",
        "NET-EXPOSE-001",
        "SVC-UNQUOTED-001",
        "TSK-CMD-001",
        "AUT-CMD-001",
        "PER-WMI-001",
        "FW-RULE-002",
        "SEC-PWD-002",
        "FS-EXE-001",
    } <= ids
    assert report["run"]["exit_code"] == 4
