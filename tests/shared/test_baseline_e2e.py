"""End-to-end regression tests for the offline baseline comparison on sanitized snapshots.

The inputs are complete synthetic audit reports in ``tests/fixtures/baseline-e2e/`` (one Linux
host, one Windows host, each with a baseline and five later runs) driven through the real CLI
(``shared.reporting.diff``). Nothing here touches a real host, the network, or the fixtures.

Scenarios: identical snapshots, added/removed/modified records, transient processes and
ephemeral ports, permission gaps and failed modules, malformed or incompatible input, and
deterministic output.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Callable, NamedTuple

import pytest
from jsonschema import Draft202012Validator

from shared.reporting import diff as diff_cli

ROOT = Path(__file__).resolve().parents[2]
FX = ROOT / "tests" / "fixtures" / "baseline-e2e"
GENERATED = "2026-03-02T00:00:00Z"
PLATFORMS = ("linux", "windows")
VARIANTS = ("identical", "changed", "churn", "unprivileged", "module-failed")
DOM = "s-1-5-21-1004336348-1177238915-682003330"  # Windows keys are case-folded by the engine

AUDIT_SCHEMA = json.loads((ROOT / "shared/schemas/audit-report.schema.json").read_text("utf-8"))
DIFF_SCHEMA = json.loads((ROOT / "shared/schemas/baseline-diff.schema.json").read_text("utf-8"))


class Outcome(NamedTuple):
    code: int
    out: str
    err: str

    @property
    def diff(self) -> dict[str, Any]:
        return json.loads(self.out)


def _cli(capsys: pytest.CaptureFixture[str], *argv: str | Path) -> Outcome:
    code = diff_cli.main([str(a) for a in argv])
    cap = capsys.readouterr()
    return Outcome(code, cap.out, cap.err)


def _fx(platform: str, variant: str) -> Path:
    return FX / platform / f"{variant}.json"


def _compare(
    capsys: pytest.CaptureFixture[str],
    platform: str,
    variant: str,
    *extra: str | Path,
    base: str = "baseline",
) -> Outcome:
    return _cli(
        capsys,
        _fx(platform, base),
        _fx(platform, variant),
        "--json",
        "--quiet",
        "--generated-at",
        GENERATED,
        *extra,
    )


def _load(platform: str, variant: str) -> dict[str, Any]:
    return json.loads(_fx(platform, variant).read_text(encoding="utf-8"))


def _put(path: Path, data: dict[str, Any]) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _derive(
    tmp_path: Path, platform: str, variant: str, edit: Callable[[dict[str, Any]], None]
) -> Path:
    """A copy of a fixture report with one adversarial edit applied."""
    data = _load(platform, variant)
    edit(data)
    return _put(tmp_path / f"{platform}-{variant}-derived.json", data)


def _compare_files(
    capsys: pytest.CaptureFixture[str], base: Path, cur: Path, *extra: str | Path
) -> Outcome:
    return _cli(capsys, base, cur, "--json", "--quiet", "--generated-at", GENERATED, *extra)


def _changes(diff: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {(c["domain"], c["key"], c["change"]) for c in diff["changes"] if not c["transient"]}


def _record(data: dict[str, Any], key: str) -> dict[str, Any]:
    return next(r for r in data["inventory"]["records"] if r["key"] == key)


def _drop_records(data: dict[str, Any], keys: set[str]) -> None:
    data["inventory"]["records"] = [r for r in data["inventory"]["records"] if r["key"] not in keys]


def _warning_codes(diff: dict[str, Any]) -> set[str]:
    return {w["code"] for w in diff["warnings"]}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ------------------------------------------------------------------------------ fixtures


def _valid_snapshots() -> list[Path]:
    return sorted(p for plat in PLATFORMS for p in (FX / plat).glob("*.json"))


@pytest.mark.parametrize("path", _valid_snapshots(), ids=lambda p: f"{p.parent.name}-{p.stem}")
def test_snapshots_conform_to_the_audit_schema(path: Path) -> None:
    Draft202012Validator(AUDIT_SCHEMA).validate(json.loads(path.read_text(encoding="utf-8")))


def test_every_scenario_exists_for_both_platforms() -> None:
    for plat in PLATFORMS:
        for name in ("baseline", *VARIANTS):
            assert _fx(plat, name).is_file(), f"missing fixture {plat}/{name}"


def test_snapshots_are_synthetic_and_secret_free() -> None:
    allowed_hosts = {"web01.example.test", "WIN-SRV01"}
    ip = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    secretish = re.compile(r"(?i)BEGIN [A-Z ]*PRIVATE KEY|ssh-(?:rsa|ed25519) AAAA|password\s*[=:]")
    for path in FX.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert not secretish.search(text), path
        assert set(ip.findall(text)) <= {"0.0.0.0", "127.0.0.1"}, path  # noqa: S104
    for path in _valid_snapshots():
        assert _fx(path.parent.name, "baseline").is_file()
        assert json.loads(path.read_text("utf-8"))["host"]["hostname"] in allowed_hosts


def test_fixture_runs_differ_in_ways_that_make_the_scenarios_meaningful() -> None:
    # If the "identical" snapshots were byte-equal to the baseline, the first scenario below would
    # prove nothing about volatile data, so guard against fixture rot.
    for plat in PLATFORMS:
        base, same = _load(plat, "baseline"), _load(plat, "identical")
        assert base["run"]["id"] != same["run"]["id"]
        assert base["inventory"]["records"] != same["inventory"]["records"]
    assert "service:Spooler" in _fx("windows", "identical").read_text(encoding="utf-8")


# --------------------------------------------------------------------- identical snapshots


@pytest.mark.parametrize("platform", PLATFORMS)
def test_identical_snapshots_produce_no_changes(
    platform: str, capsys: pytest.CaptureFixture[str]
) -> None:
    res = _compare(capsys, platform, "identical")
    d = res.diff
    assert res.code == 0
    assert d["changes"] == [] and d["indeterminate"] == []
    assert d["warnings"] == []
    assert d["summary"]["unchanged"] > 20
    assert d["summary"]["domains_compared"] == len(d["domains"])
    assert all(v == 0 for k, v in d["summary"].items() if k.startswith("findings_"))
    Draft202012Validator(DIFF_SCHEMA).validate(d)


@pytest.mark.parametrize("platform", PLATFORMS)
def test_identical_text_report_says_so(platform: str, capsys: pytest.CaptureFixture[str]) -> None:
    res = _cli(capsys, _fx(platform, "baseline"), _fx(platform, "identical"))
    assert res.code == 0
    assert "0 added, 0 removed, 0 modified; 0 indeterminate" in res.out
    assert "No inventory changes detected" in res.out
    assert "\n  +" not in res.out and "\n  -" not in res.out


@pytest.mark.parametrize("platform", PLATFORMS)
def test_a_report_compared_with_itself_is_clean_and_flagged(
    platform: str, capsys: pytest.CaptureFixture[str]
) -> None:
    res = _cli(capsys, _fx(platform, "baseline"), _fx(platform, "baseline"), "--json", "--quiet")
    assert res.code == 0
    assert res.diff["changes"] == []
    assert _warning_codes(res.diff) == {"SAME_RUN"}


# ------------------------------------------------------------------- added/removed/modified

EXPECTED_LINUX = {
    ("users", "user:mallory", "added"),
    ("users", "user:bob", "removed"),
    ("users", "user:deploy", "modified"),
    ("groups", "group:sudo", "modified"),
    ("services", "service:telnet.service", "added"),
    ("services", "service:rsyslog.service", "removed"),
    ("services", "service:nginx.service", "modified"),
    ("listeners", "listener:tcp/0.0.0.0/4444", "added"),
    ("listeners", "listener:tcp/127.0.0.1/5432", "removed"),
    ("scheduled_tasks", "cron:/etc/cron.d/.hidden#1", "added"),
    ("scheduled_tasks", "cron:/etc/cron.d/backup#1", "modified"),
    ("persistence", "persist:ssh_key:mallory:SHA256:synthetic-mallory-key-0002", "added"),
    ("persistence", "persist:file:/etc/rc.local", "modified"),
    ("config", "config:suid:/usr/bin/find", "added"),
    ("config", "config:sysctl:net.ipv4.ip_forward", "modified"),
}

_RUN = "persist:run:machine:\\software\\microsoft\\windows\\currentversion\\run"
_POL = "hklm\\software\\microsoft\\windows\\currentversion\\policies\\system::enablelua"
EXPECTED_WINDOWS = {
    ("users", f"user:{DOM}-1337", "added"),
    ("users", f"user:{DOM}-1002", "removed"),
    ("users", f"user:{DOM}-501", "modified"),
    ("groups", "group:s-1-5-32-544", "modified"),
    ("services", "service:updatehelper", "added"),
    ("services", "service:w32time", "removed"),
    ("services", "service:spooler", "modified"),
    ("services", "service:winrm", "modified"),
    ("listeners", "listener:tcp/0.0.0.0/4444", "added"),
    ("scheduled_tasks", "task:\\updatecheck", "added"),
    ("scheduled_tasks", "task:\\vendor\\backup", "removed"),
    ("persistence", f"{_RUN}:updater", "added"),
    ("config", "config:firewall:profile:public", "modified"),
    ("config", f"config:security:reg:{_POL}", "modified"),
}


@pytest.mark.parametrize(
    ("platform", "expected"), [("linux", EXPECTED_LINUX), ("windows", EXPECTED_WINDOWS)]
)
def test_added_removed_and_modified_records_are_detected(
    platform: str, expected: set[tuple[str, str, str]], capsys: pytest.CaptureFixture[str]
) -> None:
    res = _compare(capsys, platform, "changed")
    d = res.diff
    assert res.code == 4
    assert _changes(d) == expected
    assert d["indeterminate"] == []
    counts = {k: sum(1 for *_, c in expected if c == k) for k in ("added", "removed", "modified")}
    assert {k: d["summary"][k] for k in counts} == counts
    Draft202012Validator(DIFF_SCHEMA).validate(d)


def test_linux_modifications_report_the_changed_attributes() -> None:
    d = _run_json("linux", "changed")
    by_key = {c["key"]: c for c in d["changes"]}

    def attr(key: str, name: str) -> tuple[Any, Any]:
        a = next(x for x in by_key[key]["attributes"] if x["name"] == name)
        return a["before"], a["after"]

    assert attr("user:deploy", "shell") == ("/usr/sbin/nologin", "/bin/bash")
    assert attr("config:sysctl:net.ipv4.ip_forward", "value") == ("0", "1")
    assert attr("service:nginx.service", "active") == ("running", "dead")
    assert attr("group:sudo", "members") == (["alice"], ["alice", "mallory"])
    # Only the attribute that changed is reported, and unchanged records are absent.
    assert [a["name"] for a in by_key["user:deploy"]["attributes"]] == ["shell"]
    assert "user:alice" not in by_key


def test_windows_modifications_report_the_changed_attributes() -> None:
    d = _run_json("windows", "changed")
    by_key = {c["key"]: c for c in d["changes"]}
    spooler = by_key["service:spooler"]["attributes"]
    assert [(a["name"], a["before"], a["after"]) for a in spooler] == [
        ("start_mode", "Auto", "Disabled")
    ]
    uac = by_key[f"config:security:reg:{_POL}"]["attributes"]
    assert [(a["name"], a["before"], a["after"]) for a in uac] == [("value", "1", "0")]
    admins = next(a for a in by_key["group:s-1-5-32-544"]["attributes"] if a["name"] == "members")
    assert sorted(admins["after"]) == sorted(admins["before"] + [f"{DOM.upper()}-1337"])


@pytest.mark.parametrize("platform", PLATFORMS)
def test_changes_carry_priority_evidence_and_observation_window(platform: str) -> None:
    d = _run_json(platform, "changed")
    base_end = _load(platform, "baseline")["run"]["finished_at"]
    cur_start = _load(platform, "changed")["run"]["started_at"]
    cur_end = _load(platform, "changed")["run"]["finished_at"]
    assert d["window"] == {"from": base_end, "to": cur_start}
    for c in d["changes"]:
        want_base = None if c["change"] == "added" else base_end
        want_cur = None if c["change"] == "removed" else cur_end
        assert c["observed"] == {"baseline_at": want_base, "current_at": want_cur}
        assert c["priority"] in {"info", "low", "medium", "high"}
    assert {c["priority"] for c in d["changes"] if c["change"] == "added"} >= {"high"}


def test_related_findings_link_changes_through_evidence() -> None:
    lin = _run_json("linux", "changed")
    hidden = next(c for c in lin["changes"] if c["key"] == "cron:/etc/cron.d/.hidden#1")
    assert hidden["related_findings"] == ["PER-CRON-002"]
    assert {f["id"] for f in lin["findings"]["new"]} == {"PER-CRON-002", "USR-UID0-001"}
    win = _run_json("windows", "changed")
    assert {f["id"] for f in win["findings"]["new"]} == {"PER-RUN-002"}
    assert [f["id"] for f in win["findings"]["changed"]] == ["SEC-UAC-001"]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_swapping_baseline_and_current_inverts_additions_and_removals(
    platform: str, capsys: pytest.CaptureFixture[str]
) -> None:
    fwd = _compare(capsys, platform, "changed").diff
    rev = _cli(
        capsys,
        _fx(platform, "changed"),
        _fx(platform, "baseline"),
        "--json",
        "--quiet",
        "--generated-at",
        GENERATED,
    ).diff
    flip = {"added": "removed", "removed": "added", "modified": "modified"}
    assert _changes(rev) == {(d, k, flip[c]) for d, k, c in _changes(fwd)}
    assert "REVERSED_ORDER" in _warning_codes(rev)


@pytest.mark.parametrize("platform", PLATFORMS)
def test_text_report_lists_every_change(platform: str, capsys: pytest.CaptureFixture[str]) -> None:
    res = _cli(capsys, _fx(platform, "baseline"), _fx(platform, "changed"))
    assert res.code == 4
    expected = EXPECTED_LINUX if platform == "linux" else EXPECTED_WINDOWS
    mark = {"added": "+", "removed": "-", "modified": "~"}
    for _domain, key, change in expected:
        assert re.search(rf"^  \{mark[change]} {re.escape(key)}  \[", res.out, re.M), key


# ------------------------------------------------------------ transient data and ephemeral


def _run_json(platform: str, variant: str, *extra: str | Path, base: str = "baseline") -> Any:
    argv = [
        _fx(platform, base),
        _fx(platform, variant),
        "--json",
        "--quiet",
        "--generated-at",
        GENERATED,
        *extra,
    ]
    return _stdout_json([str(a) for a in argv])


def _stdout_json(argv: list[str]) -> Any:
    buf = io.StringIO()
    with redirect_stdout(buf):
        diff_cli.main(argv)
    return json.loads(buf.getvalue())


def test_linux_helper_processes_and_ephemeral_ports_raise_no_alert(
    capsys: pytest.CaptureFixture[str],
) -> None:
    res = _compare(capsys, "linux", "churn")
    d = res.diff
    assert res.code == 0
    assert _changes(d) == set()
    assert d["indeterminate"] == []
    # The four helper processes are kept for the analyst but never counted.
    assert d["summary"]["transient"] == 4
    assert {c["key"] for c in d["changes"]} == {
        f"process:root:{n}" for n in ("sleep", "ps", "grep", "awk")
    }
    assert all(c["transient"] for c in d["changes"])
    # No listener change: the metrics agent's port moved from 40111 to 33901 and it opened a
    # second socket, and neither of those is a different listener.
    assert [c for c in d["changes"] if c["domain"] == "listeners"] == []


def test_transient_changes_are_hidden_in_text_unless_requested(
    capsys: pytest.CaptureFixture[str],
) -> None:
    hidden = _cli(capsys, _fx("linux", "baseline"), _fx("linux", "churn"))
    shown = _cli(capsys, _fx("linux", "baseline"), _fx("linux", "churn"), "--show-transient")
    assert hidden.code == shown.code == 0
    assert "4 transient change(s) hidden" in hidden.out
    assert "process:root:sleep" not in hidden.out
    assert "process:root:sleep" in shown.out


@pytest.mark.parametrize("exe", ["/tmp/sleep", "/dev/shm/ps", None])  # noqa: S108
def test_a_helper_name_outside_a_system_directory_is_still_reported(
    exe: str | None, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def disguise(data: dict[str, Any]) -> None:
        name = "sleep" if exe is None or exe.endswith("sleep") else "ps"
        rec = _record(data, f"process:root:{name}")
        if exe is None:
            rec["attrs"].pop("exe")  # exe unknown: the name alone proves nothing
        else:
            rec["attrs"]["exe"] = exe

    cur = _derive(tmp_path, "linux", "churn", disguise)
    res = _compare_files(capsys, _fx("linux", "baseline"), cur)
    assert res.code == 4
    assert res.diff["summary"]["added"] == 1
    assert res.diff["summary"]["transient"] == 3


def test_a_different_process_on_an_ephemeral_port_is_still_a_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def takeover(data: dict[str, Any]) -> None:
        _record(data, "listener:tcp/0.0.0.0/33901")["attrs"]["process"] = "nc"

    res = _compare_files(
        capsys, _fx("linux", "baseline"), _derive(tmp_path, "linux", "churn", takeover)
    )
    assert res.code == 4
    assert _changes(res.diff) == {("listeners", "listener:tcp/0.0.0.0/ephemeral", "modified")}


def test_a_fixed_port_listener_is_never_collapsed_into_the_ephemeral_bucket(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def move(data: dict[str, Any]) -> None:
        rec = _record(data, "listener:tcp/0.0.0.0/80")
        rec["key"], rec["attrs"]["port"] = "listener:tcp/0.0.0.0/8080", "8080"

    res = _compare_files(
        capsys, _fx("linux", "baseline"), _derive(tmp_path, "linux", "identical", move)
    )
    assert _changes(res.diff) == {
        ("listeners", "listener:tcp/0.0.0.0/80", "removed"),
        ("listeners", "listener:tcp/0.0.0.0/8080", "added"),
    }


def test_windows_dynamic_rpc_ports_raise_no_alert(capsys: pytest.CaptureFixture[str]) -> None:
    # churn also moves 49664-49666 to 50210-50212 and hands out new pids.
    d = _compare(capsys, "windows", "churn").diff
    assert [c for c in d["changes"] if c["domain"] == "listeners"] == []
    assert d["indeterminate"] == []


def test_windows_helpers_need_configuration_to_count_as_transient(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Documented limitation: the shipped default list only names Unix helpers.
    default = _compare(capsys, "windows", "churn")
    assert default.code == 4
    assert _changes(default.diff) == {
        ("processes", "process:tasklist.exe", "added"),
        ("processes", "process:wmic.exe", "added"),
    }
    cfg = _put(tmp_path / "cfg.json", {"transient_processes": ["TASKLIST.EXE", "wmic.exe"]})
    tuned = _compare(capsys, "windows", "churn", "--config", cfg)
    assert tuned.code == 0
    assert tuned.diff["summary"]["transient"] == 2
    assert _changes(tuned.diff) == set()


# ----------------------------------------------- permission gaps and incomplete audits

_UNPRIV_REASONS = {"ATTRIBUTE_UNKNOWN", "CURRENT_INCOMPLETE"}


@pytest.mark.parametrize("platform", PLATFORMS)
def test_permission_gaps_never_imply_removals(
    platform: str, capsys: pytest.CaptureFixture[str]
) -> None:
    res = _compare(capsys, platform, "unprivileged")
    d = res.diff
    assert res.code == 6  # not a clean bill of health
    assert d["changes"] == []
    assert d["summary"]["added"] == d["summary"]["removed"] == d["summary"]["modified"] == 0
    assert "PRIVILEGE_DIFFERS" in _warning_codes(d)
    assert d["indeterminate"]
    assert {i["reason"] for i in d["indeterminate"]} == _UNPRIV_REASONS
    Draft202012Validator(DIFF_SCHEMA).validate(d)


@pytest.mark.parametrize("platform", PLATFORMS)
def test_unavailable_partitions_are_not_compared_at_all(
    platform: str, capsys: pytest.CaptureFixture[str]
) -> None:
    d = _compare(capsys, platform, "unprivileged").diff
    skipped = {(x["domain"], x["scope"]) for x in d["domains"] if x["status"] == "not_compared"}
    expected = {
        "linux": {("scheduled_tasks", ""), ("config", "sudoers")},
        "windows": {("scheduled_tasks", ""), ("config", "firewall")},
    }[platform]
    assert skipped == expected
    # Their baseline records must not surface anywhere: not as removals, not as indeterminate.
    mentioned = {(i["domain"], i["scope"]) for i in d["indeterminate"]}
    assert not (skipped & mentioned)
    assert d["summary"]["domains_not_compared"] == len(expected)


def test_partial_partitions_withhold_removals_but_keep_what_was_seen() -> None:
    d = _run_json("linux", "unprivileged")
    partial = {(x["domain"], x["scope"]) for x in d["domains"] if x["status"] == "partial"}
    assert partial == {("processes", ""), ("persistence", "ssh_keys"), ("config", "suid")}
    gone = {i["key"] for i in d["indeterminate"] if i["reason"] == "CURRENT_INCOMPLETE"}
    assert "persist:ssh_key:alice:SHA256:synthetic-alice-key-0001" in gone
    assert "config:suid:/usr/bin/passwd" in gone
    # Records the unprivileged run could still read are compared normally (and are unchanged).
    assert d["summary"]["unchanged"] > 0


def _unknown_attrs(item: dict[str, Any]) -> set[str]:
    """Attributes the record has on both sides but could not be read on one of them."""
    base, cur = item["baseline"]["attrs"], item["current"]["attrs"]
    return {n for n in base.keys() & cur.keys() if (base[n] is None) != (cur[n] is None)}


def test_unreadable_values_are_unknown_not_modified() -> None:
    lin = _run_json("linux", "unprivileged")
    unknown = {
        i["key"]: _unknown_attrs(i)
        for i in lin["indeterminate"]
        if i["reason"] == "ATTRIBUTE_UNKNOWN"
    }
    assert unknown["service:ssh.service"] == {"enabled"}
    assert unknown["listener:tcp/0.0.0.0/22"] == {"process"}
    win = _run_json("windows", "unprivileged")
    reg = [i for i in win["indeterminate"] if i["key"].startswith("config:security:reg:")]
    assert reg
    assert all(_unknown_attrs(i) == {"value"} for i in reg)
    # An unreadable registry value is null, never the comparable string "<unset>".
    assert all(i["current"]["attrs"]["value"] is None for i in reg)
    assert win["changes"] == []


@pytest.mark.parametrize("platform", PLATFORMS)
def test_findings_missing_after_a_privilege_drop_are_unverified_not_resolved(
    platform: str,
) -> None:
    f = _run_json(platform, "unprivileged")["findings"]
    assert f["resolved"] == [] and f["new"] == []
    assert [(x["id"], x["state"]) for x in f["unverified"]] == [
        ("SSH-CFG-004" if platform == "linux" else "SEC-UAC-001", "resolved")
    ]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_a_failed_module_is_never_reported_as_everything_removed(
    platform: str, capsys: pytest.CaptureFixture[str]
) -> None:
    res = _compare(capsys, platform, "module-failed")
    d = res.diff
    assert res.code == 6
    assert d["changes"] == []
    persistence = [x for x in d["domains"] if x["domain"] == "persistence"]
    assert persistence and all(x["status"] == "not_compared" for x in persistence)
    assert d["findings"]["resolved"] == []
    assert len(d["findings"]["unverified"]) == 1
    # Every other domain was still compared, so the run is partly useful rather than rejected.
    assert d["summary"]["domains_compared"] >= 8


@pytest.mark.parametrize("platform", PLATFORMS)
def test_text_report_does_not_claim_a_clean_result_when_incomplete(
    platform: str, capsys: pytest.CaptureFixture[str]
) -> None:
    res = _cli(capsys, _fx(platform, "baseline"), _fx(platform, "unprivileged"))
    assert res.code == 6
    assert "0 added, 0 removed, 0 modified;" in res.out
    assert "indeterminate (no conclusion drawn)" in res.out
    assert "No inventory changes detected" not in res.out or "not_compared" in res.out
    assert "appears resolved but the audit coverage behind that conclusion is incomplete" in res.out


@pytest.mark.parametrize("platform", PLATFORMS)
def test_reverse_comparison_does_not_invent_additions(
    platform: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # An unprivileged baseline lacks records, so a full current run must not look like additions.
    d = _cli(
        capsys,
        _fx(platform, "unprivileged"),
        _fx(platform, "baseline"),
        "--json",
        "--quiet",
        "--generated-at",
        GENERATED,
    ).diff
    assert [c for c in d["changes"] if c["change"] == "added"] == []
    assert d["summary"]["added"] == 0
    assert {i["reason"] for i in d["indeterminate"]} <= {"ATTRIBUTE_UNKNOWN", "BASELINE_INCOMPLETE"}


def test_real_changes_in_complete_domains_survive_an_incomplete_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cur = _derive(tmp_path, "linux", "unprivileged", lambda d: _drop_records(d, {"user:bob"}))
    res = _compare_files(capsys, _fx("linux", "baseline"), cur)
    assert res.code == 4
    assert _changes(res.diff) == {("users", "user:bob", "removed")}
    assert res.diff["indeterminate"]  # the gaps are still reported alongside


@pytest.mark.parametrize("platform", PLATFORMS)
def test_silently_missing_domain_is_not_a_mass_removal(
    platform: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # No coverage entry and no records for a domain, and no error: still no conclusion.
    def drop_listeners(data: dict[str, Any]) -> None:
        inv = data["inventory"]
        inv["records"] = [r for r in inv["records"] if r["domain"] != "listeners"]
        inv["coverage"] = [c for c in inv["coverage"] if c["domain"] != "listeners"]

    cur = _derive(tmp_path, platform, "identical", drop_listeners)
    res = _compare_files(capsys, _fx(platform, "baseline"), cur)
    assert res.code == 6
    assert res.diff["summary"]["removed"] == 0
    lst = [x for x in res.diff["domains"] if x["domain"] == "listeners"]
    assert [x["status"] for x in lst] == ["not_compared"]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_declared_partial_coverage_with_no_records_withholds_removals(
    platform: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def empty_users(data: dict[str, Any]) -> None:
        inv = data["inventory"]
        inv["records"] = [r for r in inv["records"] if r["domain"] != "users"]
        for c in inv["coverage"]:
            if c["domain"] == "users":
                c["status"], c["reason"] = "partial", "enumeration was interrupted"

    cur = _derive(tmp_path, platform, "identical", empty_users)
    d = _compare_files(capsys, _fx(platform, "baseline"), cur).diff
    assert d["summary"]["removed"] == 0
    assert {i["reason"] for i in d["indeterminate"]} == {"CURRENT_INCOMPLETE"}


def test_records_without_a_coverage_declaration_are_treated_as_partial(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def undeclared(data: dict[str, Any]) -> None:
        data["inventory"]["coverage"] = [
            c for c in data["inventory"]["coverage"] if c["domain"] != "users"
        ]
        _drop_records(data, {"user:bob"})

    cur = _derive(tmp_path, "linux", "identical", undeclared)
    d = _compare_files(capsys, _fx("linux", "baseline"), cur).diff
    assert d["summary"]["removed"] == 0
    assert any(i["key"] == "user:bob" for i in d["indeterminate"])


# ------------------------------------------------------ malformed and incompatible input


def _invalid_files() -> list[Path]:
    return sorted((FX / "invalid").iterdir())


@pytest.mark.parametrize("side", ["baseline", "current"])
@pytest.mark.parametrize("path", _invalid_files(), ids=lambda p: p.stem)
def test_malformed_reports_fail_safely_on_either_side(
    path: Path, side: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    good = _fx("linux", "baseline")
    args = (path, good) if side == "baseline" else (good, path)
    out_file = tmp_path / "diff.json"
    res = _cli(capsys, *args, "--json", "--output", out_file)
    assert res.code == 3
    assert res.out == ""
    assert res.err.startswith("blueops-diff:")
    assert "Traceback" not in res.err
    assert not out_file.exists()  # no half-written diff that could be mistaken for a result


@pytest.mark.parametrize("name", ["empty.json", "truncated.json", "not-json.txt", "nan-value.json"])
def test_unparseable_input_names_the_file(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    res = _cli(capsys, FX / "invalid" / name, _fx("linux", "baseline"))
    assert name in res.err


def test_unsupported_schema_versions_are_refused_with_the_supported_list(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in ("future-major.json", "unknown-minor.json"):
        res = _cli(capsys, FX / "invalid" / name, _fx("linux", "baseline"))
        assert res.code == 3
        assert "this tool reads 0.1.x, 0.2.x" in res.err


def test_missing_paths_fail_safely(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    good = _fx("linux", "baseline")
    for bad in (tmp_path / "nope.json", tmp_path):  # a missing file, a directory with no report
        for args in ((bad, good), (good, bad)):
            res = _cli(capsys, *args)
            assert res.code == 3
            assert res.out == ""
            assert "cannot read" in res.err


@pytest.mark.skipif(
    os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs permission checks that apply to this user",
)
def test_unreadable_report_fails_safely(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    locked = tmp_path / "locked.json"
    shutil.copyfile(_fx("linux", "changed"), locked)
    locked.chmod(0)
    try:
        res = _cli(capsys, _fx("linux", "baseline"), locked)
    finally:
        locked.chmod(0o600)
    assert res.code == 3
    assert "cannot read" in res.err


def test_reports_of_different_os_families_are_never_compared(
    capsys: pytest.CaptureFixture[str],
) -> None:
    for extra in ((), ("--allow-host-mismatch",)):
        res = _cli(capsys, _fx("linux", "baseline"), _fx("windows", "changed"), *extra)
        assert res.code == 3
        assert "different OS families" in res.err
        assert res.out == ""


def test_host_mismatch_is_refused_unless_explicitly_allowed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    other = _derive(
        tmp_path, "linux", "identical", lambda d: d["host"].update(hostname="db01.example.test")
    )
    refused = _compare_files(capsys, _fx("linux", "baseline"), other)
    assert refused.code == 3 and refused.out == ""
    allowed = _compare_files(capsys, _fx("linux", "baseline"), other, "--allow-host-mismatch")
    assert allowed.code == 0
    assert "HOST_MISMATCH" in _warning_codes(allowed.diff)


@pytest.mark.parametrize("name", ["legacy-0.1.0.json", "inventory-not-object.json"])
def test_a_baseline_without_inventory_concludes_nothing(
    name: str, capsys: pytest.CaptureFixture[str]
) -> None:
    # Even against the most eventful current run, a report with no usable inventory draws no
    # additions: it has nothing to be "added" relative to.
    base = FX / "no-inventory" / name
    quiet = _cli(capsys, base, _fx("linux", "identical"), "--json", "--quiet")
    assert quiet.code == 6
    assert "NO_INVENTORY" in _warning_codes(quiet.diff)
    assert quiet.diff["summary"]["domains_not_compared"] == 12
    loud = _cli(capsys, base, _fx("linux", "changed"), "--json", "--quiet")
    assert loud.diff["changes"] == []
    assert loud.diff["summary"]["added"] == 0
    assert loud.code == 4  # solely because the findings delta (new findings) is still reported
    assert loud.diff["findings"]["new"]


def test_a_current_without_inventory_never_reports_removals(
    capsys: pytest.CaptureFixture[str],
) -> None:
    res = _cli(
        capsys,
        _fx("linux", "baseline"),
        FX / "no-inventory" / "inventory-not-object.json",
        "--json",
        "--quiet",
    )
    assert res.code == 6
    assert res.diff["changes"] == []


@pytest.mark.parametrize(
    "corrupt",
    [
        {"domain": "users", "key": "user:x", "attrs": ["not", "an", "object"]},
        {"domain": "users", "key": "", "attrs": {}},
        {"domain": "users", "key": "user:\u001b[2Jx", "attrs": {}},
        {"domain": "users", "key": "user:y", "attrs": {"uid": {"nested": "object"}}},
        "not even an object",
    ],
    ids=["attrs-list", "empty-key", "control-key", "nested-value", "bare-string"],
)
def test_a_corrupt_record_degrades_its_domain_instead_of_crashing(
    corrupt: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def poison(data: dict[str, Any]) -> None:
        _drop_records(data, {"user:bob"})
        data["inventory"]["records"].append(corrupt)

    cur = _derive(tmp_path, "linux", "identical", poison)
    res = _compare_files(capsys, _fx("linux", "baseline"), cur)
    # bob is gone, but the domain could not be read in full, so removal is not concluded.
    assert res.code == 6
    assert res.diff["summary"]["removed"] == 0
    assert any(i["key"] == "user:bob" for i in res.diff["indeterminate"])
    assert "Traceback" not in res.err


def test_garbage_coverage_statements_do_not_upgrade_trust(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def garble(data: dict[str, Any]) -> None:
        for c in data["inventory"]["coverage"]:
            if c["domain"] == "users":
                c["status"] = "totally-fine"
        _drop_records(data, {"user:bob"})

    cur = _derive(tmp_path, "linux", "identical", garble)
    res = _compare_files(capsys, _fx("linux", "baseline"), cur)
    assert res.diff["summary"]["removed"] == 0
    assert res.code == 6


def test_conflicting_duplicate_records_are_reported_not_resolved_silently(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def duplicate(data: dict[str, Any]) -> None:
        twin = copy.deepcopy(_record(data, "user:alice"))
        twin["attrs"]["shell"] = "/bin/sh"
        data["inventory"]["records"].append(twin)

    res = _compare_files(
        capsys, _fx("linux", "baseline"), _derive(tmp_path, "linux", "identical", duplicate)
    )
    assert res.code == 6
    assert [(i["key"], i["reason"]) for i in res.diff["indeterminate"]] == [
        ("user:alice", "RECORD_CONFLICT")
    ]
    assert res.diff["changes"] == []


def test_invalid_comparison_config_is_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for bad in ({"ephemeral_from": "high"}, {"unknown": 1}, {"ignore": {"bogus": ["x"]}}):
        res = _compare(capsys, "linux", "identical", "--config", _put(tmp_path / "c.json", bad))
        assert res.code == 3
        assert res.out == ""


def test_attacker_controlled_text_cannot_forge_report_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    payload = "/bin/sh\x1b[2J\x1b[31m\n  + user:root  [high]\n\r- user:alice"

    def hostile(data: dict[str, Any]) -> None:
        _record(data, "user:deploy")["attrs"]["shell"] = payload

    res = _cli(
        capsys,
        _fx("linux", "baseline"),
        _derive(tmp_path, "linux", "identical", hostile),
    )
    assert res.code == 4
    assert "\x1b" not in res.out and "\r" not in res.out
    assert not re.search(r"^  \+ user:root", res.out, re.M)
    assert "\\x1b" in res.out and "\\x0a" in res.out
    # The JSON form keeps the raw value as data and stays parseable.
    d = _compare_files(
        capsys, _fx("linux", "baseline"), _derive(tmp_path, "linux", "identical", hostile)
    ).diff
    assert d["changes"][0]["attributes"][0]["after"] == payload


# ----------------------------------------------------------- offline and read-only


@pytest.mark.parametrize("platform", PLATFORMS)
def test_comparisons_are_offline_and_never_modify_inputs(
    platform: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work = tmp_path / "snapshots"
    shutil.copytree(FX, work)
    files = sorted(p for p in work.rglob("*") if p.is_file())
    for p in files:
        p.chmod(0o444)
    before = {p: (_sha(p), p.stat().st_mtime_ns) for p in files}
    listing = sorted(p.relative_to(work).as_posix() for p in work.rglob("*"))

    def no_network(*_a: object, **_k: object) -> None:
        pytest.fail("the comparison attempted a network operation")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(subprocess, "Popen", no_network)

    for variant in VARIANTS:
        for args in (("--json",), ("--format", "text")):
            _cli(
                capsys,
                work / platform / "baseline.json",
                work / platform / f"{variant}.json",
                *args,
                "--quiet",
            )
    assert {p: (_sha(p), p.stat().st_mtime_ns) for p in files} == before
    assert sorted(p.relative_to(work).as_posix() for p in work.rglob("*")) == listing


# ----------------------------------------------------------------------- determinism


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("platform", PLATFORMS)
def test_repeated_comparisons_are_byte_identical(
    platform: str, variant: str, capsys: pytest.CaptureFixture[str]
) -> None:
    runs_json = {_compare(capsys, platform, variant).out for _ in range(3)}
    runs_text = {
        _cli(
            capsys, _fx(platform, "baseline"), _fx(platform, variant), "--generated-at", GENERATED
        ).out
        for _ in range(3)
    }
    assert len(runs_json) == 1 and len(runs_text) == 1


def _shuffle(data: dict[str, Any]) -> None:
    inv = data["inventory"]
    inv["records"].reverse()
    inv["coverage"].reverse()
    data["findings"].reverse()
    data["errors"].reverse()
    for r in inv["records"]:
        r["attrs"] = dict(reversed(list(r["attrs"].items())))
        if isinstance(r["attrs"].get("members"), list):
            r["attrs"]["members"].reverse()


@pytest.mark.parametrize("variant", ["changed", "unprivileged"])
@pytest.mark.parametrize("platform", PLATFORMS)
def test_input_ordering_does_not_change_the_output(
    platform: str, variant: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = _derive(tmp_path, platform, "baseline", _shuffle)
    cur = _derive(tmp_path, platform, variant, _shuffle)
    shuffled = _compare_files(capsys, base, cur)
    plain = _compare(capsys, platform, variant)
    assert shuffled.out == plain.out
    assert shuffled.code == plain.code


@pytest.mark.parametrize("platform", PLATFORMS)
def test_input_location_and_form_do_not_change_the_output(
    platform: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("baseline", "changed"):
        run = tmp_path / f"run-{name}"
        run.mkdir()
        shutil.copyfile(_fx(platform, name), run / "report.json")
    from_dirs = _compare_files(capsys, tmp_path / "run-baseline", tmp_path / "run-changed")
    assert from_dirs.out == _compare(capsys, platform, "changed").out
    target = tmp_path / "out.json"
    code = _cli(
        capsys,
        _fx(platform, "baseline"),
        _fx(platform, "changed"),
        "--json",
        "--quiet",
        "--generated-at",
        GENERATED,
        "--output",
        target,
    ).code
    assert code == from_dirs.code == 4
    assert target.read_text(encoding="utf-8") == from_dirs.out


def test_only_the_generation_timestamp_varies_between_runs(
    capsys: pytest.CaptureFixture[str],
) -> None:
    a = _cli(capsys, _fx("linux", "baseline"), _fx("linux", "changed"), "--json", "--quiet").diff
    b = _cli(capsys, _fx("linux", "baseline"), _fx("linux", "changed"), "--json", "--quiet").diff
    a.pop("generated_at"), b.pop("generated_at")
    assert a == b


def _subprocess_env(seed: str, tz: str, lang: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONHASHSEED", "TZ", "LC_ALL")}
    env.update(
        PYTHONHASHSEED=seed, TZ=tz, LC_ALL=lang, PYTHONPATH=str(ROOT), PYTHONIOENCODING="utf-8"
    )
    return env


@pytest.mark.parametrize("platform", PLATFORMS)
def test_output_is_independent_of_hash_seed_timezone_and_locale(platform: str) -> None:
    outputs: set[tuple[int, str, str]] = set()
    for seed, tz, lang in (
        ("0", "UTC", "C"),
        ("1", "America/New_York", "C.UTF-8"),
        ("4242", "Asia/Tokyo", "C"),
    ):
        for fmt in ("json", "text"):
            proc = subprocess.run(  # noqa: S603 - fixed interpreter, repo module, fixture paths
                [
                    sys.executable,
                    "-m",
                    "shared.reporting.diff",
                    str(_fx(platform, "baseline")),
                    str(_fx(platform, "unprivileged")),
                    "--format",
                    fmt,
                    "--quiet",
                    "--generated-at",
                    GENERATED,
                ],
                capture_output=True,
                check=False,
                cwd=ROOT,
                env=_subprocess_env(seed, tz, lang),
                timeout=120,
            )
            assert proc.returncode == 6, proc.stderr.decode("utf-8", "replace")
            outputs.add((proc.returncode, fmt, hashlib.sha256(proc.stdout).hexdigest()))
    assert len(outputs) == 2  # one digest per format, however the process was configured
