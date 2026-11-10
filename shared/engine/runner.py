"""Execute one module: build the command, enforce the time limit, validate the output.

The runner is the only place that starts processes. Rules:

* Commands are argv lists; ``shell=True`` is never used and placeholders are substituted into
  single argv elements, so a value can never become a second argument or shell syntax.
* The child gets no stdin, its own process group (POSIX) so a timeout kills the whole tree, and
  stdout/stderr go to files in the module's directory (kept as evidence and hashed in the
  manifest), never into unbounded memory.
* The report is parsed with the strict JSON loader and checked against
  ``audit-report.schema.json`` before any of it is trusted. A report that fails validation is
  ``invalid_output``; its content is not ingested.
"""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess  # noqa: S404 - the engine's job is to run collectors (argv only, no shell)
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.engine.builtin import collector_module_name
from shared.engine.environment import sanitized_environment, trusted_which
from shared.engine.module import (
    FAILED,
    INVALID_OUTPUT,
    OK,
    PARTIAL,
    SKIPPED,
    TIMEOUT,
    ModuleResult,
    ModuleSpec,
)
from shared.engine.trust import plugin_launch_problems
from shared.findings.model import clean
from shared.reporting.contracts import ExitCode
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.schema_lite import validate

MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_STREAM_TAIL = 2000
_SAFE_PLACEHOLDER_VALUE_MAX = 4096


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class ExecResult:
    returncode: int | None
    timed_out: bool = False
    error: str = ""  # could not start (missing file, permission)


Executor = Callable[[list[str], int, dict[str, str], Path, Path], ExecResult]


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:  # pragma: no cover - exercised only on Windows
            subprocess.run(  # noqa: S603
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],  # noqa: S607
                check=False,
                capture_output=True,
                timeout=15,
            )
            proc.kill()
    except (ProcessLookupError, PermissionError, OSError, subprocess.TimeoutExpired):
        proc.kill()


def default_executor(
    argv: list[str], timeout: int, env: dict[str, str], stdout_path: Path, stderr_path: Path
) -> ExecResult:
    """Run ``argv`` with a hard time limit; stdout/stderr go to the given files (mode 0600)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    try:
        out_fd = os.open(stdout_path, flags, 0o600)
        err_fd = os.open(stderr_path, flags, 0o600)
    except OSError as exc:
        return ExecResult(None, error=f"cannot create output files: {exc.strerror or exc}")
    with os.fdopen(out_fd, "wb") as out, os.fdopen(err_fd, "wb") as err:
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv list, no shell
                argv,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                env=env,
                start_new_session=(os.name == "posix"),
            )
        except OSError as exc:
            return ExecResult(None, error=f"cannot start: {exc.strerror or exc}")
        try:
            rc = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_tree(proc)
            proc.wait()
            return ExecResult(None, timed_out=True)
        return ExecResult(rc)


@dataclass
class RunContext:
    """Everything a module run needs that is not part of the module itself."""

    repo_root: Path
    out_root: Path  # the assessment directory; modules write beneath modules/<id>/
    options: dict[str, Any] = field(default_factory=dict)
    timeout_override: int | None = None
    # Children get an allowlisted environment and a trusted PATH, not a copy of the caller's
    # (shared/engine/environment.py). A caller that passes ``env`` explicitly is trusted.
    env: dict[str, str] = field(default_factory=lambda: sanitized_environment()[0])
    executor: Executor = default_executor
    platform_name: str = ""  # "linux" | "windows"; defaults to the running OS
    which: Callable[[str], str | None] = trusted_which
    clock: Callable[[], str] = utc_now

    def __post_init__(self) -> None:
        if not self.platform_name:
            self.platform_name = current_platform()


def current_platform() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    return sys.platform


def _powershell(ctx: RunContext) -> str | None:
    for name in ("pwsh", "powershell"):
        found = ctx.which(name)
        if found:
            return found
    return None


def _expand(arg: str, values: dict[str, str]) -> str:
    out = arg
    for key, val in values.items():
        out = out.replace("{" + key + "}", val)
    return out


def build_command(spec: ModuleSpec, ctx: RunContext, output_dir: Path) -> list[str] | str:
    """The argv for ``spec`` or, when it cannot run here, a human reason (str)."""
    values = {
        "repo": str(ctx.repo_root),
        "plugin_dir": spec.plugin_dir,
        "output_dir": str(output_dir),
        "module": collector_module_name(spec.id) if spec.source == "builtin" else spec.id,
    }
    if any("{powershell}" in a for a in spec.argv):
        ps = _powershell(ctx)
        if ps is None:
            return "PowerShell (pwsh or powershell) not found"
        values["powershell"] = ps
    argv = [_expand(a, values) for a in spec.argv]
    for opt, value in sorted(ctx.options.items()):
        flags = spec.option_flags.get(opt)
        if flags is None or value in (None, False):
            continue
        if value is not True and len(str(value)) > _SAFE_PLACEHOLDER_VALUE_MAX:
            return f"option {opt} is too long"
        argv += [a.replace("{value}", str(value)) for a in flags]
    if os.name == "posix" and not Path(argv[0]).is_absolute():
        argv[0] = ctx.which(argv[0]) or argv[0]
    return argv


def _tail(path: Path) -> str:
    try:
        data = path.read_bytes()[-MAX_STREAM_TAIL:]
    except OSError:
        return ""
    return clean(data.decode("utf-8", "replace").strip(), MAX_STREAM_TAIL)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_report(output_dir: Path) -> Path | None:
    """``report.json`` written directly into ``output_dir`` or into one ``blueops-run-*`` child."""
    direct = output_dir / "report.json"
    if direct.is_file() and not direct.is_symlink():
        return direct
    runs = sorted(p for p in output_dir.glob("blueops-run-*") if p.is_dir() and not p.is_symlink())
    for run in reversed(runs):
        cand = run / "report.json"
        if cand.is_file() and not cand.is_symlink():
            return cand
    return None


def _failure(result: ModuleResult, status: str, reason: str) -> ModuleResult:
    result.status = status
    result.reason = reason
    return result


def run_module(spec: ModuleSpec, ctx: RunContext) -> ModuleResult:
    """Run one module and return its result. Never raises for module-level problems."""
    result = ModuleResult(module=spec.id, status=FAILED, started_at=ctx.clock())
    t0 = time.monotonic()
    try:
        return _run(spec, ctx, result, t0)
    finally:
        result.finished_at = ctx.clock()
        result.duration_seconds = time.monotonic() - t0


def _run(  # noqa: PLR0911, PLR0912 - each early return is one distinct failure status
    spec: ModuleSpec, ctx: RunContext, result: ModuleResult, t0: float
) -> ModuleResult:
    if spec.platform not in ("any", ctx.platform_name):
        return _failure(
            result, SKIPPED, f"module is for {spec.platform}; this host is {ctx.platform_name}"
        )
    mod_dir = ctx.out_root / "modules" / spec.id
    out_dir = mod_dir / "output"
    try:
        # One level at a time: mkdir(parents=True) applies the mode to the leaf only.
        mod_dir.parent.mkdir(mode=0o700, exist_ok=True)
        mod_dir.mkdir(mode=0o700)
        out_dir.mkdir(mode=0o700)
    except OSError as exc:
        return _failure(result, FAILED, f"cannot create module directory: {exc.strerror or exc}")
    built = build_command(spec, ctx, out_dir)
    if isinstance(built, str):
        return _failure(result, SKIPPED, built)
    result.command = built
    if spec.source != "builtin":
        # As late as possible before the exec: the plugin's own files must still be trustworthy.
        untrusted = plugin_launch_problems(built, spec.plugin_dir)
        if untrusted:
            return _failure(result, FAILED, f"plugin files are not trusted: {untrusted[0]}")
    timeout = ctx.timeout_override or spec.timeout_seconds
    stdout_path, stderr_path = mod_dir / "stdout.txt", mod_dir / "stderr.txt"
    ex = ctx.executor(built, timeout, ctx.env, stdout_path, stderr_path)
    result.stderr_tail = _tail(stderr_path)
    if ex.error:
        return _failure(result, FAILED, ex.error)
    if ex.timed_out:
        return _failure(result, TIMEOUT, f"exceeded the {timeout}s time limit and was killed")
    result.exit_code = ex.returncode
    if ex.returncode == int(ExitCode.PRECONDITION):
        return _failure(result, SKIPPED, "collector reported an unmet precondition (exit 3)")
    if ex.returncode not in (int(ExitCode.OK), int(ExitCode.FINDINGS), int(ExitCode.PARTIAL)):
        return _failure(result, FAILED, f"unexpected exit code {ex.returncode}")

    if spec.output == "stdout":
        report_path: Path | None = stdout_path
    else:
        report_path = _find_report(out_dir)
    if report_path is None:
        return _failure(result, INVALID_OUTPUT, "the module produced no report.json")
    result.report_path = report_path.relative_to(ctx.out_root).as_posix()
    try:
        report, raw = load_json_strict(report_path, MAX_REPORT_BYTES, "module report")
    except JsonInputError as exc:
        return _failure(result, INVALID_OUTPUT, str(exc))
    result.report_sha256 = hashlib.sha256(raw).hexdigest()
    problems = validate(report, "audit-report.schema.json", limit=5)
    if problems:
        return _failure(
            result,
            INVALID_OUTPUT,
            "report violates the audit-report schema: " + "; ".join(problems),
        )
    result.report = report
    result.errors = [e for e in report.get("errors", []) if isinstance(e, dict)]
    result.findings_count = len(report["findings"])
    result.status = PARTIAL if ex.returncode == int(ExitCode.PARTIAL) else OK
    if result.status == PARTIAL:
        result.reason = "the collector reported coverage gaps (exit 6); see errors"
    return result
