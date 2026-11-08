"""Assessment assembly: ordering, dependencies, failure handling, exit codes, integrity."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from engine_support import (
    POSIX_BASH,
    ROOT,
    collector_env,
    fake_assessment,
    fake_executor,
    fnd,
    linux_fixture_root,
    make_report,
    rec,
    registry_for,
)

from shared.engine.assessment import (
    assessment_from_report,
    assessment_to_report,
    make_assessment_dir,
    run_assessment,
)
from shared.engine.loader import LoadError, load_assessment
from shared.engine.manifest import MANIFEST_NAME, verify_directory, write_manifest
from shared.engine.module import ModuleSpec
from shared.engine.registry import Registry
from shared.engine.runner import ExecResult, RunContext
from shared.reporting.contracts import ExitCode
from shared.reporting.schema_lite import validate

R_USERS = make_report([fnd("USR-AAA-001", "high", evidence=[("file", "/etc/passwd")])])
R_NET = make_report([fnd("NET-BBB-001", "low", category="network")])


def _valid(doc: dict[str, Any]) -> None:
    assert validate(doc, "assessment.schema.json") == []


def test_clean_run(tmp_path: Path) -> None:
    a = fake_assessment(tmp_path, {"linux.users": R_USERS, "linux.net": R_NET})
    doc = a.document
    _valid(doc)
    assert a.exit_code == ExitCode.FINDINGS  # a medium+ finding exists
    assert doc["assessment"]["status"] == "complete"
    assert [m["status"] for m in doc["modules"]] == ["ok", "ok"]
    assert doc["summary"]["total"] == 2 and doc["summary"]["by_severity"]["high"] == 1
    assert doc["host"]["hostname"] == "web01" and doc["host"]["elevated"] is True


def test_exit_code_zero_when_nothing_reaches_the_threshold(tmp_path: Path) -> None:
    a = fake_assessment(tmp_path, {"linux.net": R_NET})
    assert a.exit_code == ExitCode.OK
    a = fake_assessment(tmp_path / "b", {"linux.net": R_NET}, fail_on="low")
    assert a.exit_code == ExitCode.FINDINGS


def test_findings_beat_gaps_and_gaps_beat_ok(tmp_path: Path) -> None:
    broken = lambda: ExecResult(None, timed_out=True)  # noqa: E731
    a = fake_assessment(tmp_path, {"linux.users": R_USERS, "linux.net": broken})
    assert a.exit_code == ExitCode.FINDINGS and a.document["assessment"]["status"] == "partial"
    b = fake_assessment(tmp_path / "b", {"linux.a": R_NET, "linux.net": broken})
    assert b.exit_code == ExitCode.PARTIAL
    codes = {"linux.a": 6}
    c = fake_assessment(tmp_path / "c", {"linux.a": R_NET}, exit_codes=codes)
    assert c.exit_code == ExitCode.PARTIAL and c.document["modules"][0]["status"] == "partial"


def test_all_modules_failing_is_an_error_and_all_skipped_a_precondition(tmp_path: Path) -> None:
    crash = lambda: ExecResult(None, error="cannot start: nope")  # noqa: E731
    a = fake_assessment(tmp_path, {"linux.a": crash})
    assert a.exit_code == ExitCode.ERROR and a.document["assessment"]["status"] == "failed"
    assert "host" not in a.document
    _valid(a.document)
    b = fake_assessment(tmp_path / "b", {"linux.a": R_NET}, exit_codes={"linux.a": 3})
    assert b.exit_code == ExitCode.PRECONDITION


def test_one_failing_module_does_not_stop_the_others(tmp_path: Path) -> None:
    a = fake_assessment(
        tmp_path,
        {"linux.bad": "{not json", "linux.good": R_USERS},
        selected=["linux.bad", "linux.good"],
    )
    st = {m["id"]: m["status"] for m in a.document["modules"]}
    assert st == {"linux.bad": "invalid_output", "linux.good": "ok"}
    assert any(
        e["code"] == "MODULE_INVALID_OUTPUT" and e["module"] == "linux.bad"
        for e in a.document["errors"]
    )
    assert a.document["summary"]["total"] == 1


def test_dependency_failure_skips_dependents_but_not_independent_modules(tmp_path: Path) -> None:
    crash = lambda: ExecResult(None, error="cannot start: nope")  # noqa: E731
    a = fake_assessment(
        tmp_path,
        {"linux.base": crash, "linux.dep": R_NET, "linux.free": R_USERS},
        requires={"linux.dep": ("linux.base",)},
        selected=["linux.dep", "linux.free"],
    )
    st = {m["id"]: (m["status"], m.get("reason", "")) for m in a.document["modules"]}
    assert st["linux.base"][0] == "failed"
    assert st["linux.dep"][0] == "skipped" and "linux.base" in st["linux.dep"][1]
    assert st["linux.free"][0] == "ok"
    assert [m["id"] for m in a.document["modules"]][:2] == ["linux.base", "linux.dep"]


def test_dependencies_are_added_and_run_first(tmp_path: Path) -> None:
    a = fake_assessment(
        tmp_path,
        {"linux.base": R_USERS, "linux.dep": R_NET},
        requires={"linux.dep": ("linux.base",)},
        selected=["linux.dep"],
    )
    assert [m["id"] for m in a.document["modules"]] == ["linux.base", "linux.dep"]


def test_same_finding_from_two_modules_is_deduplicated(tmp_path: Path) -> None:
    same = make_report([fnd("USR-AAA-001", "medium", evidence=[("file", "/etc/passwd")])])
    other = make_report(
        [fnd("USR-AAA-001", "high", evidence=[("file", "/etc/shadow")])], run="run-2"
    )
    a = fake_assessment(tmp_path, {"linux.one": same, "linux.two": other})
    (f,) = a.document["findings"]
    assert f["severity"] == "high" and f["occurrences"] == 2 and len(f["evidence"]) == 2
    assert {s["module"] for s in f["sources"]} == {"linux.one", "linux.two"}
    assert a.document["summary"]["total"] == 1 and a.document["summary"]["evidence_items"] == 2


def test_module_reporting_a_different_host_is_flagged(tmp_path: Path) -> None:
    other = make_report([fnd("NET-BBB-001", category="network")], host="db01", run="r2")
    a = fake_assessment(tmp_path, {"linux.a": R_USERS, "linux.b": other})
    assert any(w["code"] == "HOST_MISMATCH" for w in a.document["warnings"])
    assert a.document["host"]["hostname"] == "web01"


def test_privilege_is_the_weakest_of_the_modules(tmp_path: Path) -> None:
    low = make_report([fnd("NET-BBB-001", category="network")], elevated=False, run="r2")
    a = fake_assessment(tmp_path, {"linux.a": R_USERS, "linux.b": low})
    assert a.document["host"]["elevated"] is False


def test_inventory_is_merged_and_failed_modules_leave_unavailable_coverage(tmp_path: Path) -> None:
    reg = registry_for(["linux.a", "linux.b"])
    reg._modules["linux.b"] = ModuleSpec(
        **{**reg.get("linux.b").__dict__, "provides": ("listeners:", "config:sshd")}
    )
    out = make_assessment_dir(tmp_path, "20260301T100000Z", "t")
    ctx = RunContext(
        repo_root=ROOT,
        out_root=out,
        platform_name="linux",
        executor=fake_executor(
            {"linux.a": R_USERS, "linux.b": lambda: ExecResult(None, timed_out=True)}
        ),
    )
    doc = run_assessment(reg, ["linux.a", "linux.b"], ctx, profile_name="t").document
    cov = {(c["domain"], c.get("scope", "")): c for c in doc["inventory"]["coverage"]}
    assert cov[("users", "")]["status"] == "complete"
    assert (
        cov[("listeners", "")]["status"] == "unavailable"
        and "timeout" in cov[("listeners", "")]["reason"]
    )
    assert cov[("config", "sshd")]["status"] == "unavailable"
    assert [r["key"] for r in doc["inventory"]["records"]] == ["user:alice"]


def test_conflicting_inventory_records_are_reported_once_kept_first(tmp_path: Path) -> None:
    r1 = make_report([], records=[rec("users", "user:alice", {"uid": "1000"})])
    r2 = make_report([], records=[rec("users", "user:alice", {"uid": "0"})], run="r2")
    a = fake_assessment(tmp_path, {"linux.a": r1, "linux.b": r2})
    assert [w["code"] for w in a.document["warnings"]] == ["INVENTORY_CONFLICT"]
    assert a.document["inventory"]["records"][0]["attrs"]["uid"] == "1000"


def test_malformed_finding_in_a_valid_report_is_rejected_but_recorded(tmp_path: Path) -> None:
    rep = make_report([fnd("USR-AAA-001")])
    rep["findings"].append(
        {
            "id": "USR-ZZZ-001",
            "title": "ok",
            "severity": "low",
            "category": "users",
            "description": "d",
            "confidence": "high",
        }
    )
    a = fake_assessment(tmp_path, {"linux.a": rep})
    assert a.document["summary"]["total"] == 2
    bad = make_report([fnd("USR-AAA-001")])
    bad["findings"][0]["id"] = "USR-AAA-001"
    # the schema rejects a malformed id before the engine ingests it
    bad["findings"][0]["id"] = "nonsense"
    a = fake_assessment(tmp_path / "b", {"linux.a": bad})
    assert a.document["modules"][0]["status"] == "invalid_output"


def test_assessment_to_report_round_trips_through_the_audit_schema(tmp_path: Path) -> None:
    a = fake_assessment(tmp_path, {"linux.users": R_USERS})
    rep = assessment_to_report(a.document)
    assert validate(rep, "audit-report.schema.json") == []
    again = assessment_from_report(rep)
    assert [f["id"] for f in again["findings"]] == [f["id"] for f in a.document["findings"]]
    _valid(again)


def test_imported_report_is_a_valid_assessment_with_the_same_finding_ids(tmp_path: Path) -> None:
    a = fake_assessment(tmp_path, {"linux.users": R_USERS})
    imp = assessment_from_report(R_USERS)
    _valid(imp)
    assert (
        imp["assessment"]["profile"] == "imported" and imp["modules"][0]["id"] == "imported.report"
    )
    assert imp["findings"][0]["id"] == a.document["findings"][0]["id"]
    legacy = {k: v for k, v in R_USERS.items() if k != "inventory"}
    assert any(w["code"] == "NO_INVENTORY" for w in assessment_from_report(legacy)["warnings"])


# ------------------------------------------------------------------------- loading / integrity


def _write(tmp_path: Path, doc: dict[str, Any]) -> Path:
    p = tmp_path / "assessment.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_load_accepts_assessment_file_dir_and_audit_report(tmp_path: Path) -> None:
    a = fake_assessment(tmp_path, {"linux.users": R_USERS})
    (a.directory / "assessment.json").write_text(json.dumps(a.document), encoding="utf-8")
    write_manifest(a.directory, a.document)  # verified loading requires a manifest
    assert load_assessment(a.directory / "assessment.json")["kind"] == "assessment"
    assert load_assessment(a.directory)["assessment"]["id"] == a.document["assessment"]["id"]
    rp = tmp_path / "report.json"
    rp.write_text(json.dumps(R_USERS), encoding="utf-8")
    with pytest.raises(LoadError, match="cannot be verified"):  # a bare report has no manifest
        load_assessment(rp)
    assert load_assessment(rp, verify=False)["assessment"]["profile"] == "imported"


@pytest.mark.parametrize(
    "payload",
    [
        "{",
        "[]",
        '{"kind": "mystery"}',
        '{"kind": "assessment"}',
        '{"schema_version": "0.2.0"}',
        '{"a":1,"a":2}',
    ],
)
def test_load_rejects_garbage(tmp_path: Path, payload: str) -> None:
    p = tmp_path / "x.json"
    p.write_text(payload, encoding="utf-8")
    with pytest.raises(LoadError):
        load_assessment(p, verify=False)  # exercise the parser, not the manifest check


def test_load_rejects_unsupported_assessment_version(tmp_path: Path) -> None:
    a = fake_assessment(tmp_path, {"linux.users": R_USERS})
    doc = {**a.document, "schema_version": "0.9.0"}
    with pytest.raises(LoadError, match="unsupported"):
        load_assessment(_write(tmp_path, doc), verify=False)


def test_manifest_detects_tampering_additions_and_removals(tmp_path: Path) -> None:
    a = fake_assessment(tmp_path, {"linux.users": R_USERS})
    (a.directory / "assessment.json").write_text(json.dumps(a.document), encoding="utf-8")
    _, digest = write_manifest(a.directory, a.document)
    assert verify_directory(a.directory, digest) == []
    assert verify_directory(a.directory, "0" * 64)  # rewritten manifest
    target = (
        a.directory
        / "modules"
        / "linux.users"
        / "output"
        / "blueops-run-20260301T100000Z-fake"
        / "report.json"
    )
    original = target.read_text("utf-8")
    target.write_text(original.replace("web01", "web02"), encoding="utf-8")
    assert any("differs" in p for p in verify_directory(a.directory))
    with pytest.raises(LoadError, match="manifest verification"):
        load_assessment(a.directory)
    target.write_text(original, encoding="utf-8")
    (a.directory / "extra.txt").write_text("x", encoding="utf-8")
    assert any("not listed" in p for p in verify_directory(a.directory))
    (a.directory / "extra.txt").unlink()
    (a.directory / "assessment.json").unlink()
    assert any("missing" in p for p in verify_directory(a.directory))


def test_manifest_with_unsafe_paths_is_refused(tmp_path: Path) -> None:
    a = fake_assessment(tmp_path, {"linux.users": R_USERS})
    (a.directory / "assessment.json").write_text("{}", encoding="utf-8")
    write_manifest(a.directory, a.document)
    m = json.loads((a.directory / MANIFEST_NAME).read_text("utf-8"))
    for bad in ("../outside", "/etc/passwd", "a\\b"):
        m["files"][0]["path"] = bad
        (a.directory / MANIFEST_NAME).write_text(json.dumps(m), encoding="utf-8")
        assert any("unsafe" in p for p in verify_directory(a.directory)), bad


def test_manifest_is_not_overwritten(tmp_path: Path) -> None:
    a = fake_assessment(tmp_path, {"linux.users": R_USERS})
    write_manifest(a.directory, a.document)
    with pytest.raises(FileExistsError):
        write_manifest(a.directory, a.document)


def test_windows_modules_go_through_a_resolved_powershell(tmp_path: Path) -> None:
    """The Windows path end to end with a fake PowerShell: argv shape, platform, host family."""
    win_report = json.loads(
        (ROOT / "tests/fixtures/baseline-e2e/windows/baseline.json").read_text("utf-8")
    )
    seen: list[list[str]] = []

    def executor(
        argv: list[str], timeout: int, env: dict[str, str], out: Path, err: Path
    ) -> ExecResult:
        seen.append(argv)
        out.write_text("", encoding="utf-8")
        err.write_text("", encoding="utf-8")
        target = Path(argv[argv.index("-OutputDir") + 1])
        target.mkdir(parents=True, exist_ok=True)
        (target / "report.json").write_text(json.dumps(win_report), encoding="utf-8")
        return ExecResult(0)

    out_dir = make_assessment_dir(tmp_path, "20260301T100000Z", "t")
    ctx = RunContext(
        repo_root=ROOT,
        out_root=out_dir,
        executor=executor,
        platform_name="windows",
        which=lambda name: "C:/pwsh/pwsh.exe" if name == "pwsh" else None,
        options={"recent_days": 5},
    )
    a = run_assessment(
        Registry.with_builtins(), ["windows.users", "windows.security"], ctx, profile_name="t"
    )
    doc = a.document
    _valid(doc)
    assert doc["host"]["os"]["family"] == "windows" and [m["status"] for m in doc["modules"]] == [
        "ok",
        "ok",
    ]
    assert (
        seen[0][0] == "C:/pwsh/pwsh.exe"
        and "-NoProfile" in seen[0]
        and "-NonInteractive" in seen[0]
    )
    assert seen[0][seen[0].index("-Modules") + 1] == "users"
    assert seen[1][seen[1].index("-Modules") + 1] == "security"
    assert seen[0][seen[0].index("-RecentDays") + 1] == "5"
    assert seen[0][seen[0].index("-File") + 1].endswith("windows/audit/Invoke-WindowsAudit.ps1")
    assert "-ExecutionPolicy" not in seen[0]  # the engine never weakens the execution policy


def test_windows_only_selection_on_linux_is_skipped_without_starting_anything(
    tmp_path: Path,
) -> None:
    started: list[Any] = []
    out_dir = make_assessment_dir(tmp_path, "20260301T100000Z", "t")
    ctx = RunContext(
        repo_root=ROOT,
        out_root=out_dir,
        platform_name="linux",
        executor=lambda *a: started.append(a) or ExecResult(0),
    )
    a = run_assessment(Registry.with_builtins(), ["windows.users"], ctx, profile_name="t")
    assert started == [] and a.document["modules"][0]["status"] == "skipped"
    assert a.exit_code == ExitCode.PRECONDITION
    _valid(a.document)


# ----------------------------------------------------------- real collector, synthetic host


BASH = shutil.which("bash") or "bash"
pytestmark_real = pytest.mark.skipif(not POSIX_BASH, reason="requires bash on a POSIX host")


@pytest.fixture(scope="module")
def real_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path, int]:
    base = tmp_path_factory.mktemp("real")
    root = linux_fixture_root(base / "root")
    out = base / "out"
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "shared.engine",
            "run",
            "--platform",
            "linux",
            "--output-dir",
            str(out),
            "--quiet",
        ],
        capture_output=True,
        text=True,
        env=collector_env(root),
        cwd=ROOT,
        check=False,
        timeout=300,
    )
    (run_dir,) = out.glob("blueops-assessment-*")
    return run_dir, root, proc.returncode


@pytestmark_real
def test_real_collectors_through_the_engine(real_run: tuple[Path, Path, int]) -> None:
    run_dir, _, rc = real_run
    doc = json.loads((run_dir / "assessment.json").read_text("utf-8"))
    _valid(doc)
    assert rc == 4
    assert {m["status"] for m in doc["modules"]} == {"ok"} and len(doc["modules"]) >= 8
    assert doc["summary"]["by_severity"]["critical"] >= 1
    assert verify_directory(run_dir) == []
    assert (run_dir / "report.html").is_file() and (run_dir / "report.md").is_file()


@pytestmark_real
def test_engine_finds_exactly_what_the_monolithic_collector_finds(
    real_run: tuple[Path, Path, int],
) -> None:
    run_dir, root, _ = real_run
    doc = json.loads((run_dir / "assessment.json").read_text("utf-8"))
    proc = subprocess.run(  # noqa: S603
        [BASH, str(ROOT / "linux/audit/audit-linux.sh"), "--json", "--no-color"],
        capture_output=True,
        text=True,
        env=collector_env(root),
        cwd=ROOT,
        check=False,
        timeout=300,
    )
    mono = json.loads(proc.stdout)
    assert sorted(f["id"] for f in mono["findings"]) == sorted(
        f["check_id"] for f in doc["findings"]
    )
    sev = lambda items, k: sorted((f[k], f["severity"]) for f in items)  # noqa: E731
    assert sev(mono["findings"], "id") == sev(doc["findings"], "check_id")


@pytestmark_real
def test_every_finding_is_traceable_to_its_module_report(real_run: tuple[Path, Path, int]) -> None:
    run_dir, _, _ = real_run
    doc = json.loads((run_dir / "assessment.json").read_text("utf-8"))
    mods = {m["id"]: m for m in doc["modules"]}
    for f in doc["findings"]:
        for s in f["sources"]:
            m = mods[s["module"]]
            rep = json.loads((run_dir / m["report"]["path"]).read_text("utf-8"))
            assert any(x["id"] == s["check_id"] for x in rep["findings"])
    ev_ids = {e["id"] for e in doc["evidence"]}
    assert all(e in ev_ids for f in doc["findings"] for e in f["evidence"])
    assert all(
        p["report_sha256"] in {m["report"]["sha256"] for m in mods.values()}
        for e in doc["evidence"]
        for p in e["provenance"]
    )
