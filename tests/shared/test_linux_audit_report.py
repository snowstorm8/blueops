"""Run the Linux audit tooling against synthetic fixtures and validate the reports."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
SCHEMA = json.loads((ROOT / "shared" / "schemas" / "audit-report.schema.json").read_text("utf-8"))
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(
    BASH is None or sys.platform.startswith("win"), reason="requires bash on a POSIX host"
)

SCRIPTS = [
    ("linux/audit/audit-linux.sh", []),
    ("linux/audit/audit-system.sh", []),
    ("linux/audit/audit-users.sh", []),
    ("linux/audit/audit-processes.sh", []),
    ("linux/audit/audit-network.sh", []),
    ("linux/audit/audit-services.sh", []),
    ("linux/persistence/check-persistence.sh", []),
    ("linux/audit/audit-filesystem.sh", []),
]


@pytest.fixture(scope="module")
def fixture_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    dest = tmp_path_factory.mktemp("bo") / "root"
    shutil.copytree(FIXTURES / "linux-root", dest, symlinks=True)
    for rel in ("usr/bin/su", "usr/bin/find", "usr/bin/mystery"):
        (dest / rel).chmod(stat.S_ISUID | 0o755)
    return dest


def _run(script: str, args: list[str], root: Path) -> dict:
    env = {
        **os.environ,
        "BO_ROOT": str(root),
        "BO_FORCE_MISSING_TOOLS": "ip route ifconfig netstat systemd-detect-virt",
        "PATH": f"{FIXTURES / 'linux-bin'}{os.pathsep}{os.environ['PATH']}",
    }
    proc = subprocess.run(  # noqa: S603
        [BASH, str(ROOT / script), "--json", "--no-color", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=120,
    )
    assert proc.returncode in (0, 4, 6), proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.parametrize(("script", "args"), SCRIPTS)
def test_report_conforms_to_schema(script: str, args: list[str], fixture_root: Path) -> None:
    report = _run(script, args, fixture_root)
    errors = sorted(Draft202012Validator(SCHEMA).iter_errors(report), key=str)
    assert not errors, errors[0].message
    assert report["run"]["mode"] == "read-only"
    assert report["summary"]["total"] == len(report["findings"])
    ids = [f["id"] for f in report["findings"]]
    assert len(ids) == len(set(ids))


def test_full_audit_report_has_expected_signals(fixture_root: Path) -> None:
    report = _run("linux/audit/audit-linux.sh", [], fixture_root)
    ids = {f["id"] for f in report["findings"]}
    assert {"USR-UID0-001", "PRC-DELETED-001", "NET-EXPOSE-001", "PER-CRON-002"} <= ids
    assert report["run"]["exit_code"] == 4
