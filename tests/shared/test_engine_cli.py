"""Command-line behaviour, exit codes, plugin modules end to end, and cross-platform handling."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from engine_support import POSIX_BASH, ROOT, fnd, make_report, trust_fixtures

from shared.engine.cli import main
from shared.engine.manifest import verify_directory
from shared.engine.registry import Registry
from shared.engine.runner import RunContext, build_command

PY = sys.executable
POSIX = os.name == "posix"
PLUGIN = """
import json, pathlib, sys
out = pathlib.Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
(out / "report.json").write_text(sys.argv[2])
sys.exit(int(sys.argv[3]))
"""


def _plugin_dir(
    tmp_path: Path, report: dict[str, Any], mid: str = "linux.demo", code: int = 0, **extra: Any
) -> Path:
    d = tmp_path / "plugins"
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.py").write_text(PLUGIN, encoding="utf-8")
    manifest = {
        "schema_version": "0.1.0",
        "kind": "module",
        "id": mid,
        "title": "Demo plugin",
        "platform": "linux",
        "category": "audit",
        "privilege": "none",
        "timeout_seconds": 30,
        "command": [
            PY,
            "-I",
            "{plugin_dir}/plugin.py",
            "{output_dir}",
            json.dumps(report),
            str(code),
        ],
        **extra,
    }
    (d / f"{mid}.module.json").write_text(json.dumps(manifest), encoding="utf-8")
    if POSIX:
        d.chmod(0o755)
        (d / f"{mid}.module.json").chmod(0o644)
    return d


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    rc = main(trust_fixtures(list(argv)))
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def _assessment_dir(out: Path) -> Path:
    (d,) = out.glob("blueops-assessment-*")
    return d


# ---------------------------------------------------------------------------- plugins e2e


def test_plugin_module_runs_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plugins = _plugin_dir(
        tmp_path, make_report([fnd("USR-AAA-001", "high", evidence=[("file", "/x")])])
    )
    out = tmp_path / "out"
    rc, _, err = _run(
        capsys,
        "run",
        "--platform",
        "linux",
        "--plugin-dir",
        str(plugins),
        "--modules",
        "linux.demo",
        "--output-dir",
        str(out),
    )
    assert rc == 4, err
    d = _assessment_dir(out)
    doc = json.loads((d / "assessment.json").read_text("utf-8"))
    assert doc["assessment"]["profile"] == "custom" and [m["id"] for m in doc["modules"]] == [
        "linux.demo"
    ]
    assert doc["findings"][0]["check_id"] == "USR-AAA-001"
    assert verify_directory(d) == []
    assert main(["validate", str(d / "assessment.json")]) == 0
    assert main(["verify", str(d)]) == 0


def test_plugin_with_dependency_on_a_builtin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plugins = _plugin_dir(tmp_path, make_report([]), requires=["linux.nonexistent"])
    rc, _, err = _run(capsys, "list", "--platform", "linux", "--plugin-dir", str(plugins))
    assert rc == 3 and "unknown module" in err


def test_list_shows_modules_profiles_and_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc, out, _ = _run(capsys, "list", "--platform", "linux")
    assert rc == 0 and "linux.users" in out and "Profiles:" in out and "windows.users" not in out
    rc, out, _ = _run(capsys, "list", "--platform", "windows", "--json")
    doc = json.loads(out)
    assert (
        rc == 0
        and doc["platform"] == "windows"
        and any(m["id"] == "windows.tasks" for m in doc["modules"])
    )
    assert "quick" in doc["profiles"]


@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_writable_plugin_dir_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plugins = _plugin_dir(tmp_path, make_report([]))
    plugins.chmod(0o777)
    try:
        rc, _, err = _run(capsys, "list", "--platform", "linux", "--plugin-dir", str(plugins))
    finally:
        plugins.chmod(0o755)
    assert rc == 3 and "writable" in err


# ------------------------------------------------------------------------------ usage errors


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "--platform", "linux"],  # --output-dir is required
        ["run", "--platform", "linux", "--output-dir", "x", "--timeout", "0"],
        ["run", "--platform", "linux", "--output-dir", "x", "--report", "pdf"],
        ["run", "--platform", "linux", "--output-dir", "x", "--fail-on", "urgent"],
        ["nonsense"],
        [],
    ],
)
def test_usage_errors_exit_2(
    argv: list[str], capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    argv = [a if a != "x" else str(tmp_path / "x") for a in argv]
    with pytest.raises(SystemExit) as exc:
        rc = main(argv)
        raise SystemExit(rc)
    assert exc.value.code == 2
    capsys.readouterr()
    assert not (tmp_path / "x").exists() or not list((tmp_path / "x").iterdir())


def test_unknown_profile_and_module_selection(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = str(tmp_path / "o")
    rc, _, err = _run(
        capsys, "run", "--platform", "linux", "--profile", "nope", "--output-dir", out
    )
    assert rc == 2 and "no profile" in err
    rc, _, err = _run(
        capsys, "run", "--platform", "linux", "--modules", "bogus", "--output-dir", out
    )
    assert rc in {2, 3}
    assert "unknown module" in err
    rc, _, err = _run(capsys, "run", "--platform", "linux", "--modules", " , ", "--output-dir", out)
    assert rc == 2 and "empty" in err


def test_windows_module_on_linux_is_skipped_not_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Cross-platform guard: a Windows module selected for Linux never starts a process."""
    out = tmp_path / "o"
    rc, _, err = _run(
        capsys, "run", "--platform", "linux", "--modules", "windows.users", "--output-dir", str(out)
    )
    assert rc == 2 and "not a linux module" in err


def test_json_flag_keeps_stdout_machine_readable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plugins = _plugin_dir(tmp_path, make_report([fnd("USR-AAA-001", "low")]))
    rc, out, err = _run(
        capsys,
        "run",
        "--platform",
        "linux",
        "--plugin-dir",
        str(plugins),
        "--modules",
        "linux.demo",
        "--output-dir",
        str(tmp_path / "o"),
        "--json",
        "--report",
        "none",
    )
    assert rc == 0, err
    assert json.loads(out)["kind"] == "assessment"
    assert "manifest sha256" in err and "linux.demo" in err
    assert not list(_assessment_dir(tmp_path / "o").glob("report.*"))


def test_quiet_run_prints_nothing_on_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    plugins = _plugin_dir(tmp_path, make_report([]))
    rc, out, err = _run(
        capsys,
        "run",
        "--platform",
        "linux",
        "--plugin-dir",
        str(plugins),
        "--modules",
        "linux.demo",
        "--output-dir",
        str(tmp_path / "o"),
        "--quiet",
    )
    assert (rc, out, err) == (0, "", "")


def test_failing_plugin_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    for code, expected in ((6, 6), (1, 1), (3, 3)):
        plugins = _plugin_dir(tmp_path / str(code), make_report([]), code=code)
        rc, _, _ = _run(
            capsys,
            "run",
            "--platform",
            "linux",
            "--plugin-dir",
            str(plugins),
            "--modules",
            "linux.demo",
            "--output-dir",
            str(tmp_path / f"o{code}"),
            "--quiet",
        )
        assert rc == expected, code


def test_fail_on_threshold(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plugins = _plugin_dir(tmp_path, make_report([fnd("USR-AAA-001", "low")]))
    base = [
        "run",
        "--platform",
        "linux",
        "--plugin-dir",
        str(plugins),
        "--modules",
        "linux.demo",
        "--quiet",
    ]
    assert _run(capsys, *base, "--output-dir", str(tmp_path / "a"))[0] == 0
    assert _run(capsys, *base, "--output-dir", str(tmp_path / "b"), "--fail-on", "low")[0] == 4


def test_runs_never_share_a_directory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    plugins = _plugin_dir(tmp_path, make_report([]))
    args = [
        "run",
        "--platform",
        "linux",
        "--plugin-dir",
        str(plugins),
        "--modules",
        "linux.demo",
        "--output-dir",
        str(tmp_path / "o"),
        "--quiet",
    ]
    _run(capsys, *args)
    _run(capsys, *args)
    assert len(list((tmp_path / "o").glob("blueops-assessment-*"))) == 2


# ----------------------------------------------------------------- compare / report / validate


def _two_runs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[Path, Path]:
    dirs = []
    for n, findings in enumerate(([fnd("USR-AAA-001", "high")], [fnd("USR-BBB-001", "medium")])):
        rep = make_report(
            findings,
            run=f"run-{n}",
            start=f"2026-03-0{n + 1}T10:00:00Z",
            end=f"2026-03-0{n + 1}T10:05:00Z",
        )
        plugins = _plugin_dir(tmp_path / f"p{n}", rep)
        out = tmp_path / f"o{n}"
        _run(
            capsys,
            "run",
            "--platform",
            "linux",
            "--plugin-dir",
            str(plugins),
            "--modules",
            "linux.demo",
            "--output-dir",
            str(out),
            "--quiet",
        )
        dirs.append(_assessment_dir(out))
    return dirs[0], dirs[1]


def test_compare_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a, b = _two_runs(tmp_path, capsys)
    rc, out, err = _run(capsys, "compare", str(a), str(b))
    cmp_doc = json.loads(out)
    assert rc == 4 and cmp_doc["summary"]["new"] == 1 and cmp_doc["summary"]["resolved"] == 1
    assert "1 new, 1 resolved" in err
    dest = tmp_path / "cmp.json"
    assert _run(capsys, "compare", str(a), str(b), "--output", str(dest))[0] == 4
    assert main(["validate", str(dest)]) == 0
    capsys.readouterr()
    assert _run(capsys, "compare", str(a), str(b), "--output", str(dest))[0] == 3  # never overwrite
    rc, out, _ = _run(capsys, "compare", str(a), str(b), "--format", "markdown")
    assert "# BlueOps snapshot comparison" in out
    assert _run(capsys, "compare", str(b), str(b))[0] == 0  # identical


def test_compare_accepts_audit_reports_and_rejects_garbage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    r1, r2 = tmp_path / "r1.json", tmp_path / "r2.json"
    r1.write_text(json.dumps(make_report([fnd("USR-AAA-001")])), encoding="utf-8")
    r2.write_text(
        json.dumps(
            make_report([], run="r2", start="2026-03-02T10:00:00Z", end="2026-03-02T10:05:00Z")
        ),
        encoding="utf-8",
    )
    rc, out, _ = _run(capsys, "compare", str(r1), str(r2))
    assert rc == 4 and json.loads(out)["summary"]["resolved"] == 1
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    rc, _, err = _run(capsys, "compare", str(r1), str(tmp_path / "bad.json"))
    assert rc == 3 and "not valid JSON" in err
    rc, _, err = _run(capsys, "compare", str(r1), str(tmp_path / "missing.json"))
    assert rc == 3


def test_report_command_formats_and_compare(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, b = _two_runs(tmp_path, capsys)
    rc, html, _ = _run(
        capsys,
        "report",
        str(b),
        "--compare",
        str(a),
        "--format",
        "html",
        "--generated-at",
        "2026-03-05T00:00:00Z",
    )
    assert rc == 0 and "New findings (1)" in html and "generated 2026-03-05T00:00:00Z" in html
    rc, md, _ = _run(capsys, "report", str(b), "--format", "markdown")
    assert rc == 0 and md.startswith("# BlueOps assessment report")
    rc, js, _ = _run(capsys, "report", str(b), "--format", "json")
    assert json.loads(js)["kind"] == "assessment"
    pre = tmp_path / "pre.json"
    _run(capsys, "compare", str(a), str(b), "--output", str(pre))
    rc, html2, _ = _run(capsys, "report", str(b), "--compare", str(pre))
    assert rc == 0 and "Resolved findings (1)" in html2


def test_run_with_compare_embeds_history_and_survives_a_bad_baseline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    a, _ = _two_runs(tmp_path, capsys)
    plugins = _plugin_dir(
        tmp_path / "p9",
        make_report([], run="run-9", start="2026-03-09T10:00:00Z", end="2026-03-09T10:05:00Z"),
    )
    common = [
        "run",
        "--platform",
        "linux",
        "--plugin-dir",
        str(plugins),
        "--modules",
        "linux.demo",
        "--quiet",
    ]
    rc, _, _ = _run(capsys, *common, "--output-dir", str(tmp_path / "o9"), "--compare", str(a))
    d = _assessment_dir(tmp_path / "o9")
    assert (d / "comparison-1.json").is_file() and "Resolved findings (1)" in (
        d / "report.html"
    ).read_text("utf-8")
    assert verify_directory(d) == []
    bad = tmp_path / "bad"
    bad.mkdir()
    rc, _, err = _run(capsys, *common, "--output-dir", str(tmp_path / "o10"), "--compare", str(bad))
    assert rc == 6 and "comparison skipped" in err  # the assessment itself still completed
    assert (_assessment_dir(tmp_path / "o10") / "assessment.json").is_file()


def test_validate_and_verify_failures(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    a, _ = _two_runs(tmp_path, capsys)
    capsys.readouterr()
    doc = json.loads((a / "assessment.json").read_text("utf-8"))
    doc["summary"]["total"] = "many"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc), encoding="utf-8")
    rc, _, err = _run(capsys, "validate", str(bad))
    assert rc == 3 and "total" in err
    bad.write_text(json.dumps({"kind": "mystery"}), encoding="utf-8")
    assert _run(capsys, "validate", str(bad))[0] == 3
    (a / "assessment.json").write_text("{}", encoding="utf-8")
    rc, _, err = _run(capsys, "verify", str(a))
    assert rc == 3 and "differs" in err


def test_validate_audit_reports_and_shipped_examples(capsys: pytest.CaptureFixture[str]) -> None:
    for rel in ("examples/audit-report.example.json", "examples/run-manifest.example.json"):
        assert main(["validate", str(ROOT / rel)]) == 0, rel
    capsys.readouterr()


# --------------------------------------------------------------------- cross-platform data


WIN = ROOT / "tests" / "fixtures" / "baseline-e2e" / "windows"
LIN = ROOT / "tests" / "fixtures" / "baseline-e2e" / "linux"


@pytest.mark.parametrize("family", ["windows", "linux"])
def test_real_shaped_reports_of_both_platforms_compare(
    family: str, capsys: pytest.CaptureFixture[str]
) -> None:
    d = ROOT / "tests" / "fixtures" / "baseline-e2e" / family
    rc, out, err = _run(capsys, "compare", str(d / "baseline.json"), str(d / "changed.json"))
    doc = json.loads(out)
    assert rc == 4, err
    assert doc["baseline"]["os_family"] == family and doc["configuration"]["available"]
    assert doc["summary"]["configuration_changes"] > 0
    rc, out, _ = _run(capsys, "compare", str(d / "baseline.json"), str(d / "identical.json"))
    assert json.loads(out)["summary"]["trend"] in ("unchanged", "indeterminate")


def test_comparing_across_operating_systems_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    rc, _, err = _run(capsys, "compare", str(WIN / "baseline.json"), str(LIN / "baseline.json"))
    assert rc == 3 and "different OS families" in err


@pytest.mark.parametrize("family", ["windows", "linux"])
def test_reports_render_for_both_platforms(family: str, capsys: pytest.CaptureFixture[str]) -> None:
    d = ROOT / "tests" / "fixtures" / "baseline-e2e" / family
    for fmt in ("html", "markdown"):
        rc, out, _ = _run(
            capsys,
            "report",
            str(d / "changed.json"),
            "--compare",
            str(d / "baseline.json"),
            "--format",
            fmt,
        )
        assert rc == 0 and "BlueOps" in out and "\n" in out


@pytest.mark.parametrize(
    "name",
    sorted(p.name for p in (ROOT / "tests" / "fixtures" / "baseline-e2e" / "invalid").iterdir()),
)
def test_malformed_inputs_are_precondition_failures_never_tracebacks(
    name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = ROOT / "tests" / "fixtures" / "baseline-e2e" / "invalid" / name
    rc, _, err = _run(capsys, "report", str(bad))
    assert rc == 3, (name, err)
    assert "Traceback" not in err


@pytest.mark.skipif(not POSIX_BASH, reason="requires bash")
def test_package_integrity_option_reaches_the_collector(tmp_path: Path) -> None:
    reg = Registry.with_builtins()
    ctx = RunContext(
        repo_root=ROOT,
        out_root=tmp_path,
        options={"package_integrity": True, "recent_days": 3},
        platform_name="linux",
    )
    argv = build_command(reg.get("linux.filesystem"), ctx, tmp_path / "o")
    assert (
        isinstance(argv, list)
        and "--package-integrity" in argv
        and argv[argv.index("--recent-days") + 1] == "3"
    )
    assert argv[argv.index("--modules") + 1] == "filesystem" and argv[0].endswith(
        "linux/audit/audit-linux.sh"
    )
