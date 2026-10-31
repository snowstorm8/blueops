"""End to end: Linux audit of a synthetic host, the host changes, the audit runs again, diff.

Everything runs offline against tests/fixtures/linux-root; no real host data is touched.
"""

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

from shared.reporting.baseline import compare, exit_code_for
from shared.reporting.contracts import ExitCode
from shared.reporting.inventory import Options, build_snapshot

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
DIFF_SCHEMA = json.loads((ROOT / "shared/schemas/baseline-diff.schema.json").read_text("utf-8"))
BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(
    BASH is None or sys.platform.startswith("win"), reason="requires bash on a POSIX host"
)

NOW = "2026-02-01T00:00:00Z"


def _make_root(dest: Path) -> Path:
    shutil.copytree(FIXTURES / "linux-root", dest, symlinks=True)
    for rel in ("usr/bin/su", "usr/bin/find", "usr/bin/mystery"):
        (dest / rel).chmod(stat.S_ISUID | 0o755)
    (dest / "tmp" / "...").write_text("x\n", encoding="utf-8")
    return dest


def _make_bin(dest: Path, extra_listener: bool) -> Path:
    shutil.copytree(FIXTURES / "linux-bin", dest)
    if extra_listener:
        ss = dest / "ss"
        text = ss.read_text("utf-8").replace(
            "udp   UNCONN",
            "tcp   LISTEN 0      1            0.0.0.0:4444      0.0.0.0:*"
            '     users:(("nc",pid=777,fd=3))\n'
            "udp   UNCONN",
            1,
        )
        ss.write_text(text, "utf-8")
    return dest


def _audit(root: Path, bindir: Path, script: str = "linux/audit/audit-linux.sh") -> dict:
    env = {
        **os.environ,
        "BO_TEST_MODE": "1",
        "BO_ROOT": str(root),
        "BO_FORCE_MISSING_TOOLS": "ip route ifconfig netstat systemd-detect-virt",
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
    }
    proc = subprocess.run(  # noqa: S603
        [BASH, str(ROOT / script), "--json", "--no-color"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=180,
    )
    assert proc.returncode in (0, 4, 6), proc.stderr
    return json.loads(proc.stdout)


def _diff(base: dict, cur: dict) -> dict:
    opts = Options()
    return compare(build_snapshot(base, opts), build_snapshot(cur, opts), opts, NOW)


def _keys(d: dict, kind: str) -> set[tuple[str, str]]:
    return {(c["domain"], c["key"]) for c in d["changes"] if c["change"] == kind}


@pytest.fixture(scope="module")
def scenario(tmp_path_factory: pytest.TempPathFactory) -> dict:
    tmp = tmp_path_factory.mktemp("e2e")
    root = _make_root(tmp / "root")
    base_bin = _make_bin(tmp / "bin-a", extra_listener=False)
    base = _audit(root, base_bin)
    again = _audit(root, base_bin)

    # The host changes: rogue account, cron job, sudo rule, hosts entry, process and listener.
    with (root / "etc/passwd").open("a", encoding="utf-8") as fh:
        fh.write("mallory:x:0:0::/root:/bin/bash\n")
    (root / "etc/cron.d/newjob").write_text("* * * * * root /tmp/x.sh\n", encoding="utf-8")
    with (root / "etc/sudoers.d/90-ops").open("a", encoding="utf-8") as fh:
        fh.write("mallory ALL=(ALL) NOPASSWD: ALL\n")
    with (root / "etc/hosts").open("a", encoding="utf-8") as fh:
        fh.write("198.51.100.7 mirror.example.test\n")
    shutil.copytree(root / "proc/301", root / "proc/400", symlinks=True)
    (root / "proc/400/stat").write_text(
        "400 (miner) S 200 400 400 0 -1 0 1 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n"
    )
    (root / "proc/400/status").write_text("Name:\tminer\nUid:\t0\t0\t0\t0\n")
    cur = _audit(root, _make_bin(tmp / "bin-b", extra_listener=True))
    return {"base": base, "again": again, "cur": cur}


def test_inventory_is_present_and_has_no_transient_identifiers(scenario: dict) -> None:
    inv = scenario["base"]["inventory"]
    assert scenario["base"]["schema_version"] == "0.2.0"
    domains = {r["domain"] for r in inv["records"]}
    assert {"users", "groups", "services", "processes", "listeners"} <= domains
    assert {"scheduled_tasks", "persistence", "config"} <= domains
    for r in inv["records"]:
        if r["domain"] in ("processes", "listeners"):
            assert "pid=" not in r["key"]
        assert r["key"] == r["key"].strip()
    assert any(r["key"] == "user:root" for r in inv["records"])


def test_inventory_never_contains_secrets(scenario: dict) -> None:
    blob = json.dumps(scenario["base"]["inventory"])
    for secret in ("hunter2", "s3cretvalue", "REDACTEDHASHFIXTURE", "FIXTUREONLY", "abc123"):
        assert secret not in blob


def test_repeated_audit_of_unchanged_host_has_no_changes(scenario: dict) -> None:
    d = _diff(scenario["base"], scenario["again"])
    assert d["changes"] == []
    assert d["findings"]["new"] == []
    assert d["findings"]["changed"] == []
    assert exit_code_for(d) in (ExitCode.OK, ExitCode.PARTIAL)


def test_host_changes_are_detected_end_to_end(scenario: dict) -> None:
    d = _diff(scenario["base"], scenario["cur"])
    added = _keys(d, "added")
    assert ("users", "user:mallory") in added
    assert ("scheduled_tasks", "cron:/etc/cron.d/newjob#" + _hash_suffix(d, "newjob")) in added
    assert any(k.startswith("config:sudoers:") for _d, k in added)
    assert any(k.startswith("config:hosts:") for _d, k in added)
    assert ("processes", "process:root:miner") in added
    assert ("listeners", "listener:tcp/0.0.0.0/4444") in added
    assert not _keys(d, "removed")
    assert exit_code_for(d) is ExitCode.FINDINGS
    # Findings are secondary evidence: the new listener and miner also raise new findings.
    assert d["findings"]["new"] or d["findings"]["changed"]


def _hash_suffix(d: dict, name: str) -> str:
    for c in d["changes"]:
        if c["key"].startswith(f"cron:/etc/cron.d/{name}#"):
            return c["key"].split("#", 1)[1]
    return ""


def test_diff_output_matches_its_schema(scenario: dict) -> None:
    d = _diff(scenario["base"], scenario["cur"])
    errors = sorted(Draft202012Validator(DIFF_SCHEMA).iter_errors(d), key=str)
    assert not errors, errors[0].message


def test_each_change_names_its_evidence(scenario: dict) -> None:
    d = _diff(scenario["base"], scenario["cur"])
    by_key = {c["key"]: c for c in d["changes"]}
    assert by_key["user:mallory"]["current"]["evidence"] == [{"type": "file", "ref": "/etc/passwd"}]
    cron = next(c for k, c in by_key.items() if k.startswith("cron:/etc/cron.d/newjob#"))
    assert cron["current"]["attrs"]["file"] == "/etc/cron.d/newjob"
    assert cron["priority"] == "high"
