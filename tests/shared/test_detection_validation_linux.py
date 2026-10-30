"""Controlled detection validation, Linux: real collector -> baseline diff -> detection rules.

Scenarios and expected outcomes are defined in docs/detection-validation.md (Part 1, written
before the first run). Every scenario copies the synthetic ``tests/fixtures/linux-root`` into a
pytest temp directory, changes the copy, audits it with ``linux/audit/audit-linux.sh`` and
discards it; nothing outside the temp directory is read or written.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from detection_validation import RULE_IDS, ceiling, evaluate, expect, find, keys
from test_linux_baseline_e2e import BASH, FIXTURES, ROOT, _make_bin

from shared.reporting.accepted import AllowlistError, load
from shared.reporting.detection import exit_code_for

pytestmark = pytest.mark.skipif(
    BASH is None or sys.platform.startswith("win"), reason="requires bash on a POSIX host"
)

FORCED_MISSING = "ip route ifconfig netstat systemd-detect-virt"
ROOT_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISYNTHETICATTACKERKEY0001 attacker@example.test\n"

# --------------------------------------------------------------------- disposable environments


def _append(root: Path, rel: str, text: str) -> None:
    with (root / rel).open("a", encoding="utf-8") as fh:
        fh.write(text)


def _sudo_group(root: Path, member: str) -> None:
    p = root / "etc/group"
    p.write_text(
        p.read_text("utf-8").replace("sudo:x:27:alice", f"sudo:x:27:alice,{member}"),
        encoding="utf-8",
    )


def _account(root: Path) -> None:
    _append(root, "etc/passwd", "mallory:x:0:0::/root:/bin/bash\n")
    _sudo_group(root, "mallory")


def _sudoers(root: Path) -> None:
    (root / "etc/sudoers.d/91-ops2").write_text("mallory ALL=(ALL) NOPASSWD: ALL\n", "utf-8")


def _cron(root: Path) -> None:
    (root / "etc/cron.d/newjob").write_text("* * * * * root /tmp/x.sh\n", "utf-8")


def _sshkey(root: Path) -> None:
    _append(root, "root/.ssh/authorized_keys", ROOT_KEY)


def _rclocal(root: Path) -> None:
    (root / "etc/rc.local").write_text(
        "#!/bin/sh\n/usr/local/bin/new-startup.sh\nexit 0\n", "utf-8"
    )


def _suid(root: Path) -> None:
    (root / "usr/bin/find").chmod(stat.S_ISUID | 0o755)


def _hosts(root: Path) -> None:
    _append(root, "etc/hosts", "198.51.100.7 mirror.example.test\n")


ATTACK: dict[str, Callable[[Path], None]] = {
    "account": _account,
    "sudoers": _sudoers,
    "cron": _cron,
    "sshkey": _sshkey,
    "rclocal": _rclocal,
    "suid": _suid,
    "hosts": _hosts,
}


def _benign_service_account(root: Path) -> None:
    _append(root, "etc/passwd", "svc-backup:x:995:995::/var/lib/svc-backup:/usr/sbin/nologin\n")


def _benign_cron(root: Path) -> None:
    (root / "etc/cron.d/nightly").write_text("0 2 * * * root /usr/local/bin/backup.sh\n", "utf-8")


def _benign_hosts(root: Path) -> None:
    _append(root, "etc/hosts", "10.0.0.5 internal.example.test\n")


def _benign_group(root: Path) -> None:
    _append(root, "etc/group", "developers:x:2000:alice\n")


def _benign_promotion(root: Path) -> None:
    _sudo_group(root, "bob")


def _benign_sudoers_comment(root: Path) -> None:
    _append(root, "etc/sudoers.d/90-ops", "# reviewed 2026-01\n")


def _benign_sudoers_rule(root: Path) -> None:
    _append(root, "etc/sudoers.d/90-ops", "%ops ALL=(root) /usr/bin/systemctl restart nginx\n")


def _cron_repaired(root: Path) -> None:
    (root / "etc/cron.d/newjob").write_text("* * * * * root /usr/local/bin/x.sh\n", "utf-8")


MUTATIONS: dict[str, Callable[[Path], None]] = {
    **ATTACK,
    "svc-account": _benign_service_account,
    "backup-cron": _benign_cron,
    "internal-host": _benign_hosts,
    "dev-group": _benign_group,
    "promote-bob": _benign_promotion,
    "sudoers-comment": _benign_sudoers_comment,
    "sudoers-rule": _benign_sudoers_rule,
    "cron-repaired": _cron_repaired,
}


ID_SHIM = """#!/bin/sh
case "$1" in
-u) echo 0 ;;
-un) echo root ;;
*) exec /usr/bin/id "$@" ;;
esac
"""


def _bindir(dest: Path, listener: str | None, elevated: bool = True) -> Path:
    """Command shims: ``ss`` with no extra listener or one on 4444 owned by ``listener``, and an
    ``id`` that reports uid 0 (``elevated``) so the collectors run as an operator would."""
    bindir = _make_bin(dest, extra_listener=False)
    if elevated:
        shim = bindir / "id"
        shim.write_text(ID_SHIM, "utf-8")
        shim.chmod(0o755)
    if listener:
        ss = bindir / "ss"
        ss.write_text(
            ss.read_text("utf-8").replace(
                "udp   UNCONN",
                "tcp   LISTEN 0      1            0.0.0.0:4444      0.0.0.0:*"
                f'     users:(("{listener}",pid=777,fd=3))\nudp   UNCONN',
                1,
            ),
            "utf-8",
        )
    return bindir


def _audit(root: Path, bindir: Path, missing: str = FORCED_MISSING) -> dict[str, Any]:
    env = {
        **os.environ,
        "BO_ROOT": str(root),
        "BO_FORCE_MISSING_TOOLS": missing,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
    }
    proc = subprocess.run(  # noqa: S603
        [BASH, str(ROOT / "linux/audit/audit-linux.sh"), "--json", "--no-color"],
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=180,
    )
    assert proc.returncode in (0, 4, 6), proc.stderr
    return json.loads(proc.stdout)  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("validation")


@pytest.fixture(scope="module")
def host(workdir: Path) -> Callable[..., dict[str, Any]]:
    """Audit a fresh copy of the fixture with the given changes; results are cached."""
    counter = iter(range(10_000))

    @cache
    def build(
        changes: tuple[str, ...] = (),
        listener: str | None = None,
        missing: str = FORCED_MISSING,
        elevated: bool = True,
    ) -> str:
        n = next(counter)
        root = workdir / f"root-{n}"
        shutil.copytree(FIXTURES / "linux-root", root, symlinks=True)
        for name in changes:
            MUTATIONS[name](root)
        report = _audit(root, _bindir(workdir / f"bin-{n}", listener, elevated), missing)
        shutil.rmtree(root)  # disposable: gone once audited
        return json.dumps(report)

    def get(
        changes: tuple[str, ...] = (),
        listener: str | None = None,
        missing: str = FORCED_MISSING,
        elevated: bool = True,
    ) -> dict[str, Any]:
        return json.loads(build(tuple(changes), listener, missing, elevated))  # type: ignore[no-any-return]

    return get


# --------------------------------------------------------------------- suspicious changes

SUSPICIOUS = [
    pytest.param(
        ("account",),
        None,
        [
            ("user:mallory", {"BO-USR-001"}, "critical", "observed"),
            ("group:sudo", {"BO-GRP-001"}, "critical", "observed"),
        ],
        id="LS-01-uid0-account-in-sudo",
    ),
    pytest.param(
        ("sudoers",),
        None,
        [("config:sudoers:/etc/sudoers.d/91-ops2*", {"BO-CFG-005"}, "high", "observed")],
        id="LS-02-new-sudoers-dropin",
    ),
    pytest.param(
        ("cron",),
        None,
        [("cron:/etc/cron.d/newjob#*", {"BO-SCH-001", "BO-EXE-001"}, "high", "heuristic")],
        id="LS-03-cron-from-tmp",
    ),
    pytest.param(
        ("sshkey",),
        None,
        [("persist:ssh-authkey:root:*", {"BO-PER-001"}, "critical", "observed")],
        id="LS-04-root-ssh-key",
    ),
    pytest.param(
        (),
        "nc",
        [("listener:tcp/0.0.0.0/4444", {"BO-NET-002", "BO-NET-001"}, "high", "heuristic")],
        id="LS-05-netcat-listener",
    ),
    pytest.param(
        ("rclocal",),
        None,
        [("persist:startup:/etc/rc.local", {"BO-PER-002"}, "high", "observed")],
        id="LS-06-rc-local-rewritten",
    ),
    pytest.param(
        ("suid",),
        None,
        [("config:suid:/usr/bin/find", {"BO-CFG-004", "BO-CFG-003"}, "high", "heuristic")],
        id="LS-07-setuid-find",
        marks=pytest.mark.skipif(
            sys.platform == "darwin", reason="BSD stat does not report the set-ID bit"
        ),
    ),
    pytest.param(
        ("hosts",),
        None,
        [("config:hosts:*", {"BO-CFG-007"}, "medium", "observed")],
        id="LS-08-hosts-entry",
    ),
]


@pytest.mark.parametrize(("changes", "listener", "expected"), SUSPICIOUS)
def test_suspicious_change_triggers_the_expected_rule(
    host: Callable[..., dict[str, Any]],
    changes: tuple[str, ...],
    listener: str | None,
    expected: list[tuple[str, set[str], str, str]],
) -> None:
    doc = evaluate(host(), host(changes, listener))
    for pattern, rules, severity, basis in expected:
        expect(doc, pattern, rules, severity, basis)
    assert exit_code_for(doc) == 4


# --------------------------------------------------------------------- benign administration


def test_lb01_service_account_is_low(host: Callable[..., dict[str, Any]]) -> None:
    doc = evaluate(host(), host(("svc-account",)))
    expect(doc, "user:svc-backup", {"BO-USR-002"}, "low", "observed")
    assert len(doc["detections"]) == 1


def test_lb02_ordinary_cron_job_is_medium_without_path_heuristic(
    host: Callable[..., dict[str, Any]],
) -> None:
    doc = evaluate(host(), host(("backup-cron",)))
    d = expect(doc, "cron:/etc/cron.d/nightly#*", {"BO-SCH-001"}, "medium", "observed")
    assert "BO-EXE-001" not in {r["rule"] for r in d["reasons"]}
    ceiling(doc, "medium")


def test_lb03_internal_hosts_entry_is_at_most_medium(host: Callable[..., dict[str, Any]]) -> None:
    ceiling(evaluate(host(), host(("internal-host",))), "medium")


def test_lb04_unprivileged_group_is_silent(host: Callable[..., dict[str, Any]]) -> None:
    assert evaluate(host(), host(("dev-group",)))["detections"] == []


def test_lb05_promoting_an_existing_user_is_high_not_critical(
    host: Callable[..., dict[str, Any]],
) -> None:
    doc = evaluate(host(), host(("promote-bob",)))
    expect(doc, "group:sudo", {"BO-GRP-001"}, "high", "observed")


def test_lb06_no_change_means_no_detection(host: Callable[..., dict[str, Any]]) -> None:
    doc = evaluate(host(), host())
    assert doc["detections"] == [] and doc["coverage"]["complete"]
    assert exit_code_for(doc) == 0  # the only way to a clean exit: nothing found, coverage whole


def test_lb07_comment_only_sudoers_edit_is_silent(host: Callable[..., dict[str, Any]]) -> None:
    assert evaluate(host(), host(("sudoers-comment",)))["detections"] == []


def test_lb08_benign_sudoers_rule_is_the_documented_false_positive(
    host: Callable[..., dict[str, Any]],
) -> None:
    """FP-1: a narrow, password-protected rule for an ops group is rated like NOPASSWD ALL."""
    doc = evaluate(host(), host(("sudoers-rule",)))
    expect(doc, "config:sudoers:/etc/sudoers.d/90-ops*", {"BO-CFG-005"}, "high", "observed")


# --------------------------------------------------------------------- remediation

ALL_ATTACKS = tuple(ATTACK)


def test_lr01_full_reversal_leaves_only_the_hash_direction_false_positive(
    host: Callable[..., dict[str, Any]],
) -> None:
    doc = evaluate(host(ALL_ATTACKS, "nc"), host())
    assert keys(doc) == {"persist:startup:/etc/rc.local"}
    assert all(d["severity"] != "critical" and d["basis"] == "observed" for d in doc["detections"])


def test_lr02_repairing_a_cron_line_is_a_new_job_not_a_low_remediation(
    host: Callable[..., dict[str, Any]],
) -> None:
    """Cron records are keyed by line content, so an edit is remove + add (limitation FP-3):
    the repaired job is reported at the new-job level (medium), never high."""
    doc = evaluate(host(("cron",)), host(("cron-repaired",)))
    d = expect(doc, "cron:/etc/cron.d/newjob#*", {"BO-SCH-001"}, "medium", "observed")
    assert "BO-EXE-001" not in {r["rule"] for r in d["reasons"]}
    ceiling(doc, "medium")


def test_lr03_listener_leaving_netcat_is_low(host: Callable[..., dict[str, Any]]) -> None:
    doc = evaluate(host((), "nc"), host((), "sshd"))
    d = expect(doc, "listener:tcp/0.0.0.0/4444", {"BO-NET-003"}, "low", "observed")
    assert "remediation" in d["summary"]


def test_lr04_compromise_already_in_the_baseline_is_invisible(
    host: Callable[..., dict[str, Any]],
) -> None:
    base = host()
    assert any(f["severity"] in ("high", "critical") for f in base["findings"]), (
        "the standing-state audit does see the dirty fixture"
    )
    assert evaluate(base, host())["detections"] == []  # FN-1: change-based detection


# --------------------------------------------------------------------- accepted changes


def _allow(tmp: Path, *entries: dict[str, Any]) -> str:
    p = tmp / "accepted.json"
    p.write_text(
        json.dumps(
            {"schema_version": "0.1.0", "kind": "accepted-changes", "entries": list(entries)}
        ),
        encoding="utf-8",
    )
    return str(p)


def _entry(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "AC-1",
        "rules": ["BO-PER-002"],
        "domain": "persistence",
        "key": "persist:startup:/etc/rc.local",
        "max_severity": "high",
        "reason": "Synthetic change ticket CHG-1",
        "approved_by": "validation",
        "approved_at": "2026-01-01T00:00:00Z",
        "expires": "2026-12-31T00:00:00Z",
    }
    base.update(over)
    return base


COMBINED = ("account", "sudoers", "rclocal")


def _rc_hash(cur: dict[str, Any]) -> str:
    rec = next(
        r for r in cur["inventory"]["records"] if r["key"] == "persist:startup:/etc/rc.local"
    )
    return str(rec["attrs"]["sha256"])


def test_la01_hash_pinned_entry_accepts_only_that_change(
    host: Callable[..., dict[str, Any]], workdir: Path
) -> None:
    base, cur = host(), host(COMBINED)
    plain = evaluate(base, cur)
    doc = evaluate(base, cur, _allow(workdir, _entry(current={"sha256": _rc_hash(cur)})))
    assert [d["subject"]["key"] for d in doc["accepted"]] == ["persist:startup:/etc/rc.local"]
    original = next(
        d for d in plain["detections"] if d["subject"]["key"] == "persist:startup:/etc/rc.local"
    )
    moved = copy.deepcopy(doc["accepted"][0])
    moved.pop("acceptance")
    assert moved == original  # evidence is intact
    assert keys(doc) == keys(plain) - {"persist:startup:/etc/rc.local"}
    assert exit_code_for(doc) == 4


@pytest.mark.parametrize(
    ("over", "status"),
    [
        ({"current": {"sha256": "0" * 64}}, "unused"),
        ({"key": "persist:startup:/etc/rc.local.bak"}, "unused"),
        ({"expires": "2026-01-15T00:00:00Z"}, "expired"),
        ({"rules": ["BO-CFG-005"]}, "unused"),
    ],
    ids=["LA-02-wrong-hash", "LA-03-neighbouring-key", "LA-05-expired", "LA-07-wrong-rule"],
)
def test_entries_that_do_not_match_exactly_suppress_nothing(
    host: Callable[..., dict[str, Any]], workdir: Path, over: dict[str, Any], status: str
) -> None:
    base, cur = host(), host(COMBINED)
    plain = evaluate(base, cur)
    doc = evaluate(base, cur, _allow(workdir, _entry(**over)))
    assert doc["accepted"] == [] and keys(doc) == keys(plain)
    assert doc["allowlist"]["entries"][0]["status"] == status


def test_la04_critical_detections_cannot_be_accepted(
    host: Callable[..., dict[str, Any]], workdir: Path
) -> None:
    entry = _entry(
        rules=["BO-USR-001", "BO-USR-002"], domain="users", key="user:mallory", max_severity="high"
    )
    doc = evaluate(host(), host(COMBINED), _allow(workdir, entry))
    assert "user:mallory" in keys(doc) and doc["accepted"] == []
    assert doc["allowlist"]["entries"][0]["not_applied"][0]["why"] == "severity above max_severity"
    with pytest.raises(AllowlistError, match="critical"):
        load(_allow(workdir, {**entry, "max_severity": "critical"}), RULE_IDS)


def test_la06_every_non_critical_detection_can_be_accepted_with_exact_entries(
    host: Callable[..., dict[str, Any]], workdir: Path
) -> None:
    base, cur = host(), host(COMBINED)
    plain = evaluate(base, cur)
    entries = []
    for i, d in enumerate(plain["detections"]):
        if d["severity"] == "critical":
            continue
        s = d["subject"]
        entries.append(
            _entry(
                id=f"AC-{i}",
                rules=sorted({r["rule"] for r in d["reasons"]}),
                domain=s["domain"],
                key=s["key"],
                scope=s["scope"],
                change=s["change"],
            )
        )
    doc = evaluate(base, cur, _allow(workdir, *entries))
    assert {d["subject"]["key"] for d in doc["accepted"]} == {
        d["subject"]["key"] for d in plain["detections"] if d["severity"] != "critical"
    }
    assert keys(doc) == {
        d["subject"]["key"] for d in plain["detections"] if d["severity"] == "critical"
    }
    assert exit_code_for(doc) == 4


# --------------------------------------------------------------------- coverage


def test_lc01_current_run_without_ss_is_never_a_clean_bill_of_health(
    host: Callable[..., dict[str, Any]],
) -> None:
    """Process names vanish when ss is missing: the listener owners become indeterminate."""
    doc = evaluate(host(), host(missing=f"{FORCED_MISSING} ss"))
    assert doc["detections"] == []
    assert doc["coverage"]["complete"] is False and doc["coverage"]["indeterminate"] > 0
    assert exit_code_for(doc) == 6


def test_lc02_incomplete_coverage_does_not_hide_other_detections(
    host: Callable[..., dict[str, Any]],
) -> None:
    doc = evaluate(host(), host(("account",), missing=f"{FORCED_MISSING} ss"))
    expect(doc, "user:mallory", {"BO-USR-001"}, "critical", "observed")
    assert doc["coverage"]["complete"] is False
    assert exit_code_for(doc) == 4


def test_lc03_unprivileged_run_is_partial_and_never_clean(
    host: Callable[..., dict[str, Any]],
) -> None:
    doc = evaluate(host(), host(elevated=False))
    assert doc["detections"] == []
    assert {g["domain"] for g in doc["coverage"]["gaps"]} == {"persistence"}
    assert exit_code_for(doc) == 6


def test_lc04_ssh_key_added_in_a_partial_partition_is_indeterminate_not_clean(
    host: Callable[..., dict[str, Any]],
) -> None:
    """Unprivileged audits cannot read every authorized_keys: the new key is not concluded
    (a false negative the output admits through exit 6), it is not reported as clean."""
    doc = evaluate(host(elevated=False), host(("sshkey",), elevated=False))
    assert find(doc, "persist:ssh-authkey:*") == []
    assert doc["coverage"]["indeterminate"] > 0
    assert exit_code_for(doc) == 6
