"""CLI and golden-file tests for the offline baseline comparison (shared.reporting.diff)."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import stat
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from shared.reporting import diff as diff_cli
from tests.shared.baseline_builders import cov, pair, rec, report, standard_baseline

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "fixtures" / "baseline"
GENERATED = "2026-01-02T12:00:00Z"
UPDATE = os.environ.get("BLUEOPS_UPDATE_GOLDEN") == "1"


def _run(capsys: pytest.CaptureFixture[str], *argv: str | Path) -> tuple[int, str, str]:
    code = diff_cli.main([str(a) for a in argv])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def _write(path: Path, data: dict[str, Any]) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def diff_schema() -> dict[str, Any]:
    return json.loads(
        (ROOT / "shared" / "schemas" / "baseline-diff.schema.json").read_text(encoding="utf-8")
    )


@pytest.mark.parametrize("name", ["linux", "windows"])
def test_golden_json_and_text(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    base, cur = GOLDEN / f"{name}-baseline.json", GOLDEN / f"{name}-current.json"
    common = [base, cur, "--generated-at", GENERATED]
    code_j, out_j, _ = _run(capsys, *common, "--json", "--quiet")
    code_t, out_t, _ = _run(capsys, *common)
    assert code_j == code_t == 4
    if UPDATE:
        (GOLDEN / f"expected-{name}-diff.json").write_text(out_j, encoding="utf-8", newline="\n")
        (GOLDEN / f"expected-{name}-diff.txt").write_text(out_t, encoding="utf-8", newline="\n")
    assert out_j == (GOLDEN / f"expected-{name}-diff.json").read_text(encoding="utf-8")
    assert out_t == (GOLDEN / f"expected-{name}-diff.txt").read_text(encoding="utf-8")


@pytest.mark.parametrize("name", ["linux", "windows"])
def test_golden_json_conforms_to_diff_schema(name: str, diff_schema: dict[str, Any]) -> None:
    data = json.loads((GOLDEN / f"expected-{name}-diff.json").read_text(encoding="utf-8"))
    Draft202012Validator(diff_schema).validate(data)


def test_golden_linux_semantics() -> None:
    data = json.loads((GOLDEN / "expected-linux-diff.json").read_text(encoding="utf-8"))
    changes = {(c["key"], c["change"]) for c in data["changes"]}
    assert ("user:mallory", "added") in changes
    assert ("user:bob", "removed") in changes
    assert ("user:alice", "modified") in changes
    # A new pid for an unchanged process or listener is not a change.
    assert not any("sshd" in k or k.endswith("/22") for k, _ in changes)
    # The ephemeral listener collapses to one stable key; the fixed port keeps its own.
    assert ("listener:tcp/0.0.0.0/ephemeral", "added") in changes
    assert ("listener:tcp/0.0.0.0/4444", "added") in changes
    # A partial current suid scan never produces removals.
    assert not [c for c in data["changes"] if c["key"].startswith("config:suid")]
    assert {i["reason"] for i in data["indeterminate"]} == {"RECORD_CONFLICT"}
    # Related findings are linked through shared evidence.
    mallory = next(c for c in data["changes"] if c["key"] == "user:mallory")
    assert mallory["related_findings"] == ["USR-UID0-001"]


def test_golden_windows_semantics() -> None:
    data = json.loads((GOLDEN / "expected-windows-diff.json").read_text(encoding="utf-8"))
    keys = {c["key"] for c in data["changes"]}
    # Windows keys are case-insensitive: SPOOLER == spooler, and the null image path (not
    # elevated) is unknown rather than a modification.
    assert not any("spooler" in k for k in keys)
    assert [i["key"] for i in data["indeterminate"]] == ["service:spooler"]
    assert any(w["code"] == "PRIVILEGE_DIFFERS" for w in data["warnings"])


def test_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base, cur = pair(standard_baseline(), standard_baseline())
    b, c = _write(tmp_path / "b.json", base), _write(tmp_path / "c.json", cur)
    assert _run(capsys, b, c)[0] == 0

    changed = standard_baseline() + [rec("users", "user:eve", {"uid": "1002"})]
    _write(c, pair(standard_baseline(), changed)[1])
    assert _run(capsys, b, c)[0] == 4

    # Nothing differs, but the current users collection was partial: do not report "clean".
    base, cur = pair(standard_baseline(), standard_baseline())
    cur["inventory"]["coverage"] = [
        cov("users", "partial", "unreadable") if x["domain"] == "users" else x
        for x in cur["inventory"]["coverage"]
    ]
    _write(c, cur)
    assert _run(capsys, b, c)[0] == 6

    assert _run(capsys, b, tmp_path / "missing.json")[0] == 3
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    assert _run(capsys, b, tmp_path / "bad.json")[0] == 3


def test_usage_error_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        diff_cli.main(["only-one-argument"])
    assert exc.value.code == 2
    capsys.readouterr()


def test_host_mismatch_refused_unless_allowed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    b = _write(tmp_path / "b.json", report(standard_baseline(), host="web01"))
    c = _write(tmp_path / "c.json", pair(standard_baseline(), standard_baseline(), host="db01")[1])
    code, _, err = _run(capsys, b, c)
    assert code == 3
    assert "host" in err.lower()
    assert _run(capsys, b, c, "--allow-host-mismatch")[0] in (0, 4, 6)


def test_output_file_is_private_and_never_overwritten(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    b = GOLDEN / "linux-baseline.json"
    c = GOLDEN / "linux-current.json"
    out = tmp_path / "diff.json"
    code, stdout, err = _run(capsys, b, c, "--json", "--output", out, "--generated-at", GENERATED)
    assert code == 4
    assert stdout == ""
    assert "added" in err
    if os.name == "posix":
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    before = out.read_bytes()
    code, _, err = _run(capsys, b, c, "--json", "--output", out)
    assert code == 1
    assert "cannot write output" in err
    assert out.read_bytes() == before


def test_json_goes_to_stdout_and_summary_to_stderr(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _run(
        capsys, GOLDEN / "linux-baseline.json", GOLDEN / "linux-current.json", "--json"
    )
    assert code == 4
    assert json.loads(out)["kind"] == "baseline-diff"
    assert "blueops-diff:" in err
    _, _, quiet_err = _run(
        capsys, GOLDEN / "linux-baseline.json", GOLDEN / "linux-current.json", "--json", "--quiet"
    )
    assert quiet_err == ""


def test_run_directory_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    base, cur = pair(standard_baseline(), standard_baseline())
    for name, data in (("run-a", base), ("run-b", cur)):
        (tmp_path / name).mkdir()
        _write(tmp_path / name / "report.json", data)
    assert _run(capsys, tmp_path / "run-a", tmp_path / "run-b")[0] == 0


def test_config_file_and_validation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    b, c = GOLDEN / "linux-baseline.json", GOLDEN / "linux-current.json"
    cfg = _write(tmp_path / "cfg.json", {"ignore": {"users": ["user:mallory"]}})
    code, out, _ = _run(capsys, b, c, "--config", cfg, "--json", "--quiet")
    assert code == 4
    assert "user:mallory" not in {x["key"] for x in json.loads(out)["changes"]}
    assert json.loads(out)["summary"]["ignored"] >= 1

    for bad in ({"ephemeral_from": "high"}, {"bogus": 1}, {"ignore": {"nope": ["*"]}}):
        _write(cfg, bad)
        code, _, err = _run(capsys, b, c, "--config", cfg)
        assert code == 3
        assert err.startswith("blueops-diff:")
    cfg.write_text("{", encoding="utf-8")
    assert _run(capsys, b, c, "--config", cfg)[0] == 3


def test_ephemeral_from_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    def listener(port: str) -> dict[str, Any]:
        attrs = {"proto": "tcp", "bind": "0.0.0.0", "port": port}
        return rec("listeners", f"listener:tcp/0.0.0.0/{port}", attrs)

    base = [listener("22")]
    cur = [listener("22"), listener("40000")]
    # Windows treats ports from 49152 as ephemeral by default, so 40000 is a real listener.
    b = _write(tmp_path / "b.json", pair(base, cur, family="windows")[0])
    c = _write(tmp_path / "c.json", pair(base, cur, family="windows")[1])
    _, out, _ = _run(capsys, b, c, "--json", "--quiet")
    assert [x["key"] for x in json.loads(out)["changes"]] == ["listener:tcp/0.0.0.0/40000"]
    _, out, _ = _run(capsys, b, c, "--json", "--quiet", "--ephemeral-from", "32768")
    assert [x["key"] for x in json.loads(out)["changes"]] == ["listener:tcp/0.0.0.0/ephemeral"]


def test_comparison_is_read_only_and_offline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    b, c = GOLDEN / "linux-baseline.json", GOLDEN / "linux-current.json"
    before = {p: _sha(p) for p in GOLDEN.iterdir()}

    def no_network(*_a: object, **_k: object) -> None:
        raise AssertionError("the comparison must not use the network")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    assert _run(capsys, b, c, "--generated-at", GENERATED)[0] == 4
    assert {p: _sha(p) for p in GOLDEN.iterdir()} == before
    assert sorted(p.name for p in tmp_path.iterdir()) == []


def test_output_is_deterministic(capsys: pytest.CaptureFixture[str]) -> None:
    b, c = GOLDEN / "linux-baseline.json", GOLDEN / "linux-current.json"
    runs = {
        _run(capsys, b, c, "--json", "--quiet", "--generated-at", GENERATED)[1] for _ in range(3)
    }
    assert len(runs) == 1
    assert _run(capsys, b, c, "--generated-at", "not-a-time")[0] == 3
