"""Module execution: real subprocesses (timeouts, crashes, hostile output) and canned ones."""

from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest
from engine_support import FIXED_CLOCK, ROOT, fnd, make_report, spec

from shared.engine.module import FAILED, INVALID_OUTPUT, OK, PARTIAL, SKIPPED, TIMEOUT, ModuleSpec
from shared.engine.runner import ExecResult, RunContext, build_command, run_module

PY = sys.executable


def _ctx(tmp_path: Path, **kw: Any) -> RunContext:
    kw.setdefault("platform_name", "linux")
    return RunContext(repo_root=ROOT, out_root=tmp_path, clock=lambda: FIXED_CLOCK, **kw)


def _py(
    tmp_path: Path, body: str, mid: str = "linux.proc", **kw: Any
) -> tuple[ModuleSpec, RunContext]:
    script = tmp_path / "plugin.py"
    script.write_text(textwrap.dedent(body), encoding="utf-8")
    s = spec(mid, argv=(PY, "-I", str(script), "{output_dir}"), **kw)
    return s, _ctx(tmp_path / "run")


def _write_report_script(report: dict[str, Any], code: int = 0) -> str:
    return f"""
        import json, sys, pathlib
        out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
        (out / "report.json").write_text({json.dumps(report)!r})
        sys.exit({code})
    """


@pytest.fixture
def run_root(tmp_path: Path) -> Path:
    (tmp_path / "run").mkdir()
    return tmp_path


def test_successful_module(run_root: Path) -> None:
    rep = make_report([fnd("USR-AAA-001")])
    s, ctx = _py(run_root, _write_report_script(rep))
    res = run_module(s, ctx)
    assert (res.status, res.exit_code, res.findings_count) == (OK, 0, 1)
    assert res.report is not None and len(res.report_sha256) == 64
    assert res.report_path == "modules/linux.proc/output/report.json"
    assert res.started_at == FIXED_CLOCK


def test_exit_4_is_ok_and_exit_6_is_partial(run_root: Path) -> None:
    rep = make_report([fnd("USR-AAA-001")])
    s, ctx = _py(run_root, _write_report_script(rep, 4))
    assert run_module(s, ctx).status == OK
    s, ctx = _py(run_root, _write_report_script(rep, 6), mid="linux.proc2")
    res = run_module(s, ctx)
    assert res.status == PARTIAL and "gaps" in res.reason


@pytest.mark.parametrize("code", [1, 2, 5, 7, 255])
def test_unexpected_exit_codes_fail_even_with_a_report(run_root: Path, code: int) -> None:
    s, ctx = _py(run_root, _write_report_script(make_report(), code))
    res = run_module(s, ctx)
    assert res.status == FAILED and str(code) in res.reason and res.report is None


def test_exit_3_means_skipped(run_root: Path) -> None:
    s, ctx = _py(run_root, "import sys; sys.exit(3)")
    res = run_module(s, ctx)
    assert res.status == SKIPPED and "precondition" in res.reason


def test_timeout_kills_the_whole_process_tree(run_root: Path) -> None:
    pidfile = run_root / "child.pid"
    body = f"""
        import subprocess, sys, time, pathlib
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
        pathlib.Path({str(pidfile)!r}).write_text(str(child.pid))
        time.sleep(120)
    """
    s, ctx = _py(run_root, body, timeout=1)
    t0 = time.monotonic()
    res = run_module(s, ctx)
    assert res.status == TIMEOUT and "1s" in res.reason
    assert time.monotonic() - t0 < 30
    if os.name == "posix":
        pid = int(pidfile.read_text())
        for _ in range(50):
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            pytest.fail("the grandchild process survived the timeout")


def test_timeout_override_beats_the_module_limit(run_root: Path) -> None:
    s, ctx = _py(run_root, "import time; time.sleep(60)", timeout=3000)
    ctx.timeout_override = 1
    assert run_module(s, ctx).status == TIMEOUT


def test_missing_executable_is_a_failure_not_a_crash(tmp_path: Path) -> None:
    s = spec("linux.ghost", argv=(str(tmp_path / "does-not-exist"),))
    res = run_module(s, _ctx(tmp_path))
    assert res.status == FAILED and "cannot start" in res.reason


def test_no_report_written(run_root: Path) -> None:
    s, ctx = _py(run_root, "pass")
    res = run_module(s, ctx)
    assert res.status == INVALID_OUTPUT and "no report.json" in res.reason


@pytest.mark.parametrize(
    ("payload", "why"),
    [
        ("{not json", "not valid JSON"),
        ('{"a": 1, "a": 2}', "duplicate"),
        ('{"v": NaN}', "non-finite"),
        ("[]", "schema"),
        ('{"schema_version": "0.2.0"}', "schema"),
        ("\xff\xfe", "UTF-8"),
        ("", "not valid JSON"),
    ],
)
def test_malformed_reports_are_invalid_output(run_root: Path, payload: str, why: str) -> None:
    body = f"""
        import sys, pathlib
        out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
        (out / "report.json").write_bytes({payload!r}.encode("latin-1"))
    """
    s, ctx = _py(run_root, body)
    res = run_module(s, ctx)
    assert res.status == INVALID_OUTPUT and why in res.reason and res.report is None


def test_schema_violating_report_is_not_trusted(run_root: Path) -> None:
    rep = make_report([fnd("USR-AAA-001")])
    rep["findings"][0]["severity"] = "apocalyptic"
    s, ctx = _py(run_root, _write_report_script(rep))
    res = run_module(s, ctx)
    assert (
        res.status == INVALID_OUTPUT
        and "audit-report schema" in res.reason
        and res.findings_count == 0
    )


def test_deeply_nested_report_is_an_error_not_a_crash(run_root: Path) -> None:
    body = """
        import sys, pathlib
        out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
        (out / "report.json").write_text("[" * 200000 + "]" * 200000)
    """
    s, ctx = _py(run_root, body)
    assert run_module(s, ctx).status == INVALID_OUTPUT


def test_stdout_output_mode(run_root: Path) -> None:
    rep = make_report([fnd("USR-AAA-001")])
    body = f"import sys; sys.stdout.write({json.dumps(rep)!r})"
    s, ctx = _py(run_root, body, output="stdout")
    res = run_module(s, ctx)
    assert res.status == OK and res.report_path == "modules/linux.proc/stdout.txt"


@pytest.mark.skipif(os.name != "posix", reason="symlinks need POSIX")
def test_symlinked_report_is_ignored(run_root: Path) -> None:
    secret = run_root / "secret.json"
    secret.write_text(json.dumps(make_report()), encoding="utf-8")
    body = f"""
        import sys, pathlib
        out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
        (out / "report.json").symlink_to({str(secret)!r})
    """
    s, ctx = _py(run_root, body)
    assert run_module(s, ctx).status == INVALID_OUTPUT


def test_stderr_tail_is_captured_and_sanitised(run_root: Path) -> None:
    body = "import sys; sys.stderr.write('boom\\x1b[31m' + 'x' * 5000); sys.exit(1)"
    s, ctx = _py(run_root, body)
    res = run_module(s, ctx)
    assert (
        res.status == FAILED and 0 < len(res.stderr_tail) <= 2000 and "\x1b" not in res.stderr_tail
    )


def test_platform_mismatch_is_skipped_without_running(tmp_path: Path) -> None:
    s = spec("windows.users", argv=("{powershell}", "x"))
    res = run_module(s, _ctx(tmp_path))
    assert res.status == SKIPPED and "windows" in res.reason and res.command == []


def test_module_directory_is_created_once(run_root: Path) -> None:
    s, ctx = _py(run_root, _write_report_script(make_report()))
    run_module(s, ctx)
    assert run_module(s, ctx).status == FAILED  # evidence directories are never reused


@pytest.mark.skipif(os.name != "posix", reason="POSIX modes")
def test_module_files_are_owner_only(run_root: Path) -> None:
    s, ctx = _py(run_root, _write_report_script(make_report()))
    run_module(s, ctx)
    base = run_root / "run" / "modules"
    for p in (base, base / "linux.proc", base / "linux.proc" / "stdout.txt"):
        assert (p.stat().st_mode & 0o077) == 0, p


# ------------------------------------------------------------------ command building


def test_placeholders_become_single_argv_elements(tmp_path: Path) -> None:
    s = spec("linux.x", argv=("{repo}/a b", "--out={output_dir}", "{module}"))
    argv = build_command(s, _ctx(tmp_path / "with space; rm -rf"), tmp_path / "o u t")
    assert argv == [f"{ROOT}/a b", f"--out={tmp_path / 'o u t'}", "x"]  # builtin: collector name


def test_option_flags_are_applied_only_when_set(tmp_path: Path) -> None:
    s = ModuleSpec(
        **{
            **spec("linux.x").__dict__,
            "option_flags": {"recent_days": ("--recent-days", "{value}"), "pkg": ("--pkg",)},
        }
    )
    base = build_command(s, _ctx(tmp_path, options={}), tmp_path)
    on = build_command(
        s, _ctx(tmp_path, options={"recent_days": 3, "pkg": True, "other": 1}), tmp_path
    )
    off = build_command(s, _ctx(tmp_path, options={"pkg": False}), tmp_path)
    assert on == [*base, "--pkg", "--recent-days", "3"]
    assert off == base


def test_powershell_is_resolved_or_the_module_is_skipped(tmp_path: Path) -> None:
    s = spec("windows.users", argv=("{powershell}", "-File", "x.ps1"))
    ctx = _ctx(
        tmp_path,
        platform_name="windows",
        which=lambda name: "C:/pwsh.exe" if name == "pwsh" else None,
    )
    assert build_command(s, ctx, tmp_path)[0] == "C:/pwsh.exe"
    ctx = _ctx(
        tmp_path,
        platform_name="windows",
        which=lambda name: "C:/ps.exe" if name == "powershell" else None,
    )
    assert build_command(s, ctx, tmp_path)[0] == "C:/ps.exe"
    ctx = _ctx(tmp_path, platform_name="windows", which=lambda name: None)
    res = run_module(s, ctx)
    assert res.status == SKIPPED and "PowerShell" in res.reason


def test_executor_error_and_default_executor_are_used_through_the_context(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, executor=lambda *a: ExecResult(None, error="cannot start: denied"))
    res = run_module(spec("linux.x"), ctx)
    assert res.status == FAILED and "denied" in res.reason
