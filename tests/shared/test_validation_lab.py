"""Lab gating and live execution. Everything except the ``live`` tests runs without spawning a process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from shared.engine.runner import current_platform
from shared.reporting.schema_lite import validate
from shared.validation import lab
from shared.validation.lab import LabError, Probes
from shared.validation.model import load_scenarios
from shared.validation.runner import telemetry_rule_set

ROOT = Path(__file__).resolve().parents[2]
POSIX = os.name == "posix"


def probes(env=None, files=(), cgroup="", platform="linux"):
    def read(p):
        if p == "/proc/1/cgroup":
            return cgroup
        raise OSError(p)

    return Probes(env=env or {}, exists=lambda p: p in files, read=read, platform=platform)


# ------------------------------------------------------------------ isolation


def test_isolation_unverified_without_signal_or_attestation():
    iso = lab.verify_isolation(probes())
    assert not iso["verified"] and not iso["allowed"] and iso["method"] == "none"
    assert iso["problems"]


def test_isolation_attestation_is_never_reported_as_verified():
    iso = lab.verify_isolation(probes(), attest=True)
    assert iso["allowed"] and iso["attested"] and not iso["verified"]
    assert iso["method"] == "attested"


@pytest.mark.parametrize(
    "p",
    [
        probes(files=("/.dockerenv",)),
        probes(files=("/run/.containerenv",)),
        probes(cgroup="12:cpu:/kubepods/pod1"),
        probes(env={"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}),
    ],
)
def test_isolation_recognised_signals_verify(p):
    iso = lab.verify_isolation(p)
    assert iso["verified"] and iso["method"] == "verified" and iso["evidence"]


def test_isolation_self_hosted_runner_is_not_verified():
    p = probes(env={"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"})
    assert not lab.verify_isolation(p)["verified"]


def test_isolation_unreadable_cgroup_fails_closed():
    assert not lab.verify_isolation(probes(cgroup=""))["allowed"]


# ------------------------------------------------------------------ lab directory


def test_unsafe_paths_refused(tmp_path, monkeypatch):
    for bad in (Path("/"), Path.home(), ROOT, ROOT / "x", Path("/etc/lab")):
        assert lab.unsafe_lab_path(bad), bad
    monkeypatch.chdir(tmp_path)
    assert lab.unsafe_lab_path(tmp_path)
    assert lab.unsafe_lab_path(tmp_path / "ok") is None


@pytest.mark.skipif(not POSIX, reason="symlinks need POSIX")
def test_symlink_lab_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    assert "symbolic link" in lab.unsafe_lab_path(link)


def test_init_creates_marker_and_refuses_reuse(tmp_path):
    d = lab.init_lab(tmp_path / "lab")
    m = lab.read_marker(d)
    assert m["kind"] == "blueops-lab" and len(m["token"]) == 32
    with pytest.raises(LabError, match="not empty"):
        lab.init_lab(d)


def test_init_refuses_repo_and_system_paths():
    with pytest.raises(LabError):
        lab.init_lab(ROOT / "lab-here")
    with pytest.raises(LabError):
        lab.init_lab("/etc/blueops-lab")


def test_read_marker_requires_marker(tmp_path):
    with pytest.raises(LabError, match="--lab-dir is required"):
        lab.read_marker(None)
    (tmp_path / "plain").mkdir()
    with pytest.raises(LabError, match="not a lab directory"):
        lab.read_marker(tmp_path / "plain")


def test_read_marker_rejects_forged_content(tmp_path):
    d = lab.init_lab(tmp_path / "lab")
    (d / lab.MARKER).write_text(json.dumps({"kind": "blueops-lab", "token": "short"}))
    with pytest.raises(LabError, match="not a BlueOps lab marker"):
        lab.read_marker(d)
    (d / lab.MARKER).write_text("{not json")
    with pytest.raises(LabError, match="unreadable"):
        lab.read_marker(d)


@pytest.mark.skipif(not POSIX, reason="mode bits need POSIX")
def test_read_marker_rejects_writable_marker(tmp_path):
    d = lab.init_lab(tmp_path / "lab")
    (d / lab.MARKER).chmod(0o666)
    with pytest.raises(LabError, match="writable"):
        lab.read_marker(d)


# ------------------------------------------------------------------ scenarios and preconditions


def live_set():
    ss = load_scenarios()
    ss.scenarios = {k: v for k, v in ss.scenarios.items() if v.live_capable}
    return ss


def test_live_pack_loads_clean_and_is_live_only():
    ss = live_set()
    assert not [d for d in ss.diagnostics if d.level == "error"]
    assert ss.ordered() and all(s.live_capable and s.live_only for s in ss.ordered())


def test_precondition_platform_and_unknown_host():
    s = live_set().ordered()[0]
    assert lab.precondition_failures(s, "plan9", lab_ok=True)


def test_precondition_missing_lab_and_interpreter_in_temp(monkeypatch):
    s = live_set().ordered()[0]
    monkeypatch.setattr(lab.sys, "executable", "/tmp/venv/bin/python")
    why = lab.precondition_failures(s, current_platform(), lab_ok=False)
    assert any("temporary location" in w for w in why)


# ------------------------------------------------------------------ gating of run_live (nothing is spawned)


def run_gated(tmp_path, *, d=None, attest=False, yes=False, tty=False, pr=None, chosen=None):
    ss = live_set()
    return lab.run_live(
        chosen if chosen is not None else ss.ordered(),
        ss,
        telemetry_rule_set(),
        lab_dir=d,
        attest=attest,
        assume_yes=yes,
        command="test",
        probes=pr or probes(),
        stdin_is_tty=tty,
    )


def test_run_live_without_lab_dir_exit_3(tmp_path):
    assert run_gated(tmp_path, attest=True, yes=True) == (None, 3)


def test_run_live_unverified_isolation_exit_3(tmp_path):
    d = lab.init_lab(tmp_path / "lab")
    assert run_gated(tmp_path, d=str(d), yes=True) == (None, 3)
    assert not (d / "runs").exists()


def test_run_live_no_tty_no_yes_exit_5(tmp_path):
    d = lab.init_lab(tmp_path / "lab")
    assert run_gated(tmp_path, d=str(d), attest=True) == (None, 5)
    assert not (d / "runs").exists()


def test_run_live_declined_exit_5(tmp_path, monkeypatch):
    d = lab.init_lab(tmp_path / "lab")
    monkeypatch.setattr("builtins.input", lambda _="": "no")
    assert run_gated(tmp_path, d=str(d), attest=True, tty=True) == (None, 5)


def test_run_live_nothing_live_capable_exit_3(tmp_path):
    d = lab.init_lab(tmp_path / "lab")
    assert run_gated(tmp_path, d=str(d), attest=True, yes=True, chosen=[]) == (None, 3)


def test_plan_describes_actions_without_running(tmp_path):
    d = lab.init_lab(tmp_path / "lab")
    plan = lab.live_plan(live_set().ordered(), lab_dir=str(d), attest=True)
    assert plan and all(
        p["lab"] == "lab directory ok" and p["isolation"] == "attested" for p in plan
    )
    assert all("loopback only" in p["modifies_host"] for p in plan)


def test_plan_reports_missing_lab(tmp_path):
    plan = lab.live_plan(live_set().ordered(), lab_dir=str(tmp_path / "nope"), attest=False)
    assert plan[0]["lab"].startswith("NOT READY") and plan[0]["isolation"] == "none"


# ------------------------------------------------------------------ CLI


def cli(*argv):
    return subprocess.run(  # noqa: S603 - fixed argv for our own CLI
        [sys.executable, "-m", "shared.engine", "validate", *argv],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def test_cli_live_without_lab_refuses_before_running(tmp_path):
    r = cli("run", "--live", "--yes", "--attest-disposable")
    assert r.returncode == 3 and "lab-dir" in r.stderr


def test_cli_live_with_synthetic_scenario_id_is_refused(tmp_path):
    d = lab.init_lab(tmp_path / "lab")
    r = cli(
        "run", "--live", "--lab-dir", str(d), "--attest-disposable", "--yes",
        "--scenario", "SCN-LNX-AUT-001",
    )  # fmt: skip
    assert r.returncode == 3 and "not live scenarios" in r.stderr


def test_synthetic_run_never_selects_live_only(tmp_path):
    out = tmp_path / "r.json"
    r = cli("run", "--format", "json", "--results-out", str(out))
    assert r.returncode in (0, 4, 6), r.stderr
    doc = json.loads(out.read_text())
    assert doc["run"]["mode"] == "synthetic"
    assert not any(
        s["id"].startswith("SCN-ANY-LAB") and s["status"] != "skipped" for s in doc["scenarios"]
    )


# ------------------------------------------------------------------ session cleanup


@pytest.mark.skipif(not POSIX, reason="process groups need POSIX")
def test_session_cleanup_kills_children_and_reports_no_residue(tmp_path):
    s = lab.LabSession(tmp_path)
    s.spawn_sleeper("sleeper", 60)
    pid = s.children[0].pid
    res = s.cleanup()
    assert res == {"ok": True, "terminated": 1, "residual_pids": []}
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.skipif(not POSIX, reason="process groups need POSIX")
def test_session_cleanup_is_idempotent(tmp_path):
    s = lab.LabSession(tmp_path)
    s.spawn_sleeper("sleeper", 60)
    assert s.cleanup()["ok"] and s.cleanup()["ok"]


def test_session_rejects_excessive_duration(tmp_path):
    with pytest.raises((LabError, ValueError)):
        lab.LabSession(tmp_path).spawn_sleeper("x", lab.MAX_SECONDS + 1)


# ------------------------------------------------------------------ real live execution (opt-in)

LIVE = os.environ.get("BLUEOPS_LIVE_LAB") == "1"


@pytest.mark.live
@pytest.mark.skipif(
    not (LIVE and POSIX), reason="set BLUEOPS_LIVE_LAB=1 in a disposable lab (POSIX)"
)
def test_live_run_end_to_end(tmp_path):
    if lab.TEMP_PATH.search(sys.executable):
        pytest.skip("interpreter runs from a temporary location; the lab refuses to start")
    d = lab.init_lab(tmp_path / "lab")
    out = tmp_path / "live.json"
    r = cli(
        "run", "--live", "--lab-dir", str(d), "--attest-disposable", "--yes",
        "--format", "json", "--results-out", str(out),
    )  # fmt: skip
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text())
    assert doc["run"]["mode"] == "live" and doc["run"]["isolation"]["method"] in (
        "attested",
        "verified",
    )
    assert all(s["status"] == "pass" for s in doc["scenarios"]), [
        (s["id"], s["status"]) for s in doc["scenarios"]
    ]
    assert all(s["cleanup"]["ok"] and not s["cleanup"]["residual_pids"] for s in doc["scenarios"])
    schema = json.loads((ROOT / "shared/schemas/validation-results.schema.json").read_text())
    assert validate(doc, schema) == []
    assert list((d / "runs").glob("live-*/results.json"))
