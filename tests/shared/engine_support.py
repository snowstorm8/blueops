"""Helpers for the assessment-engine tests: synthetic reports and a fake module executor."""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from baseline_builders import finding, rec, report

from shared.engine.assessment import Assessment, make_assessment_dir, run_assessment
from shared.engine.module import ModuleSpec
from shared.engine.registry import Registry
from shared.engine.runner import ExecResult, RunContext

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
POSIX_BASH = shutil.which("bash") is not None and not sys.platform.startswith("win")
FIXED_CLOCK = "2026-03-01T10:00:00Z"


def spec(  # noqa: PLR0913 - a flat test builder
    mid: str = "linux.alpha",
    *,
    requires: tuple[str, ...] = (),
    provides: tuple[str, ...] = (),
    timeout: int = 30,
    output: str = "run-dir",
    argv: tuple[str, ...] = ("/bin/true",),
) -> ModuleSpec:
    platform = mid.split(".", maxsplit=1)[0]
    return ModuleSpec(
        id=mid,
        title=mid,
        platform=platform if platform in ("linux", "windows") else "any",
        category="audit",
        argv=argv,
        requires=requires,
        provides=provides,
        timeout_seconds=timeout,
        output=output,
        privilege="none",
    )


def make_report(findings: list[dict[str, Any]] | None = None, **kw: Any) -> dict[str, Any]:
    """A schema-valid audit report (0.2.0) with the given findings."""
    kw.setdefault("records", [rec("users", "user:alice", {"uid": "1000"})])
    records = kw.pop("records")
    out = report(records, findings=findings or [], **kw)
    out["summary"]["total"] = len(out["findings"])
    for f in out["findings"]:
        out["summary"]["by_severity"][f["severity"]] += 1
    return out


def fnd(
    check_id: str, severity: str = "medium", category: str = "users", **kw: Any
) -> dict[str, Any]:
    f = finding(check_id, severity, **kw)
    f["category"] = category
    f["confidence"] = "high"
    f["remediation"] = f"Review {check_id} and remediate."
    return f


def fake_executor(
    reports: dict[str, dict[str, Any] | Callable[[], ExecResult] | str],
    exit_codes: dict[str, int] | None = None,
) -> Callable[..., ExecResult]:
    """Executor that, instead of starting a process, writes a canned report for the module.

    ``reports`` maps a module id (found through the ``--modules``-less argv marker ``MODULE=<id>``
    in the command) to a report dict, or a raw string to write verbatim, or a callable that
    returns an ``ExecResult`` (to simulate timeouts and start failures).
    """
    codes = exit_codes or {}

    def run(argv: list[str], timeout: int, env: dict[str, str], out: Path, err: Path) -> ExecResult:
        mid = next(a.split("=", 1)[1] for a in argv if a.startswith("MODULE="))
        out.write_text("", encoding="utf-8")
        err.write_text("", encoding="utf-8")
        item = reports[mid]
        if callable(item):
            return item()
        target = Path(next(a for a in argv if a.startswith("OUT=")).split("=", 1)[1])
        text = item if isinstance(item, str) else json.dumps(item)
        run_dir = target / "blueops-run-20260301T100000Z-fake"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "report.json").write_text(text, encoding="utf-8")
        return ExecResult(codes.get(mid, 0))

    return run


def registry_for(ids: list[str], requires: dict[str, tuple[str, ...]] | None = None) -> Registry:
    reg = Registry()
    for mid in ids:
        s = spec(
            mid, requires=(requires or {}).get(mid, ()), argv=(f"MODULE={mid}", "OUT={output_dir}")
        )
        reg.register(s)
    return reg


def fake_assessment(  # noqa: PLR0913 - a flat test builder
    tmp_path: Path,
    reports: dict[str, Any],
    *,
    selected: list[str] | None = None,
    exit_codes: dict[str, int] | None = None,
    requires: dict[str, tuple[str, ...]] | None = None,
    fail_on: str = "medium",
    clock_start: str = FIXED_CLOCK,
) -> Assessment:
    reg = registry_for(list(reports), requires)
    out = make_assessment_dir(tmp_path, "20260301T100000Z", "test")
    ctx = RunContext(
        repo_root=ROOT,
        out_root=out,
        executor=fake_executor(reports, exit_codes),
        platform_name="linux",
        clock=lambda: clock_start,
    )
    return run_assessment(reg, selected or list(reports), ctx, profile_name="test", fail_on=fail_on)


# The fixture host contains a file literally named "..." (a deceptive name the filesystem audit
# must flag: FS-HIDDEN-001). Windows cannot create or check out such a name, so it is generated per
# test on POSIX only, never stored in git. The Linux collector itself only runs on POSIX, so nothing
# that needs the name can run elsewhere; what remains portable (building the tree, the other files,
# the engine and detection logic) must not depend on it.
DECEPTIVE_NAME = "..."
DECEPTIVE_NAME_SUPPORTED = os.name == "posix"


def linux_fixture_root(dest: Path) -> Path:
    """A copy of the synthetic Linux root with what git cannot store: permission bits (SUID) and,
    where the OS allows it, the deceptive file name ``/tmp/...`` (see ``DECEPTIVE_NAME``)."""
    shutil.copytree(FIXTURES / "linux-root", dest, symlinks=True)
    if os.name == "posix":  # chmod bits mean nothing on NTFS
        for rel in ("usr/bin/su", "usr/bin/find", "usr/bin/mystery"):
            (dest / rel).chmod(stat.S_ISUID | 0o755)
    if DECEPTIVE_NAME_SUPPORTED:
        (dest / "tmp" / DECEPTIVE_NAME).write_text("x\n", encoding="utf-8")
    return dest


def collector_env(root: Path) -> dict[str, str]:
    return {
        **os.environ,
        "BO_TEST_MODE": "1",
        "BO_ROOT": str(root),
        "BO_FORCE_MISSING_TOOLS": "ip route ifconfig netstat systemd-detect-virt",
        "PATH": f"{FIXTURES / 'linux-bin'}{os.pathsep}{os.environ['PATH']}",
    }


_LOADS_ASSESSMENTS = {
    ("compare",),
    ("report",),
    ("detect", "run"),
    ("detect", "compare"),
    ("detect", "report"),
    ("telemetry", "hunt"),
    ("telemetry", "import"),
}


def trust_fixtures(argv: list[str]) -> list[str]:
    """Add ``--allow-unverified`` to commands that load assessments.

    The synthetic fixtures these tests use are bare JSON files with no manifest, which the CLIs
    refuse by default (that default is tested in test_engine_integrity.py). Opting in here is
    the explicit, documented way to load data the test itself wrote.
    """
    words = tuple(a for a in argv[:2] if not a.startswith("-"))
    if "--allow-unverified" in argv or not any(words[: len(k)] == k for k in _LOADS_ASSESSMENTS):
        return argv
    return [*argv, "--allow-unverified"]
