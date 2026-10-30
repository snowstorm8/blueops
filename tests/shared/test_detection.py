"""Deterministic regression tests for the detection rules (synthetic data only).

Three layers: per-rule scenarios built from small synthetic reports (including the cases that
must NOT alert), the complete Linux/Windows end-to-end fixtures, and the CLI contract.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from baseline_builders import cov, pair, rec, report
from jsonschema import Draft202012Validator

from shared.reporting import detect as detect_cli
from shared.reporting import detection
from shared.reporting.baseline import compare
from shared.reporting.contracts import INVENTORY_DOMAINS, Severity
from shared.reporting.detection import DiffInputError, detect, exit_code_for
from shared.reporting.inventory import Options, build_snapshot

ROOT = Path(__file__).resolve().parents[2]
FX = ROOT / "tests" / "fixtures" / "baseline-e2e"
NOW = "2026-03-02T00:00:00Z"
SCHEMA = json.loads((ROOT / "shared/schemas/detections.schema.json").read_text("utf-8"))
SID = "S-1-5-21-1-2-3"
UAC_KEY = "hklm\\software\\microsoft\\windows\\currentversion\\policies\\system::enablelua"
DOM = "s-1-5-21-1004336348-1177238915-682003330"  # the engine case-folds Windows keys


def _diff(base: dict[str, Any], cur: dict[str, Any]) -> dict[str, Any]:
    o = Options()
    return compare(build_snapshot(base, o), build_snapshot(cur, o), o, NOW)


BYSTANDERS = {
    "users": rec("users", "user:bystander", {"uid": "1500", "shell": "/bin/bash"}),
    "groups": rec("groups", "group:bystander", {"members": []}),
    "services": rec("services", "service:bystander", {"enabled": "enabled", "active": "running"}),
    "processes": rec("processes", "process:root:bystander", {"comm": "bystander", "exe": "/bin/b"}),
}


def reports(
    base_recs: list[dict[str, Any]], cur_recs: list[dict[str, Any]], **kw: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Two complete reports. Every partition seen on either side is declared complete (the
    engine refuses to conclude "added" without a coverage statement), and a core domain that
    would be empty on one side gets an unchanged bystander (an empty complete users/services
    collection is treated as a collector failure, which is tested in the baseline suite)."""
    base, cur = list(base_recs), list(cur_recs)
    for domain, bystander in BYSTANDERS.items():
        both = [r for r in base + cur if r["domain"] == domain]
        if both:
            base.append(bystander)
            cur.append(bystander)
    parts = sorted({(r["domain"], r.get("scope", "")) for r in base + cur})
    return pair(base, cur, coverage=[cov(d, scope=sc) for d, sc in parts], **kw)


def run(
    base_recs: list[dict[str, Any]], cur_recs: list[dict[str, Any]], **kw: Any
) -> dict[str, Any]:
    doc = detect(_diff(*reports(base_recs, cur_recs, **kw)), NOW)
    Draft202012Validator(SCHEMA).validate(doc)
    return doc


def rules_for(doc: dict[str, Any], key: str) -> set[str]:
    return {
        r["rule"] for d in doc["detections"] if d["subject"]["key"] == key for r in d["reasons"]
    }


def one(doc: dict[str, Any], key: str) -> dict[str, Any]:
    found = [d for d in doc["detections"] if d["subject"]["key"] == key]
    assert len(found) == 1, f"expected exactly one detection for {key}, got {len(found)}"
    return found[0]


def user(name: str, uid: str = "1000", shell: str = "/bin/bash", **extra: str) -> dict[str, Any]:
    return rec("users", f"user:{name}", {"uid": uid, "shell": shell, **extra})


def svc(name: str, **attrs: str) -> dict[str, Any]:
    return rec("services", f"service:{name}", {"enabled": "enabled", "active": "running", **attrs})


def cron(n: int, command: str, user_: str = "root") -> dict[str, Any]:
    return rec(
        "scheduled_tasks",
        f"cron:/etc/cron.d/job#{n}",
        {"command": command, "schedule": "* * * * *", "user": user_},
        scope="cron",
    )


# ------------------------------------------------------------------ rules that must fire

FIRE = [
    pytest.param(
        [user("root", "0")],
        [user("root", "0"), user("mallory", "0")],
        "user:mallory",
        "BO-USR-001",
        "critical",
        "observed",
        id="uid0-added",
    ),
    pytest.param(
        [user("bob", "1001")],
        [user("bob", "0")],
        "user:bob",
        "BO-USR-001",
        "critical",
        "observed",
        id="uid0-by-modification",
    ),
    pytest.param(
        [user("root", "0")],
        [user("root", "0"), user("eve", password="empty")],  # noqa: S106 - password *state*
        "user:eve",
        "BO-USR-002",
        "high",
        "observed",
        id="new-account-empty-password",
    ),
    pytest.param(
        [user("deploy", "998", "/usr/sbin/nologin")],
        [user("deploy", "998", "/bin/bash")],
        "user:deploy",
        "BO-USR-003",
        "high",
        "observed",
        id="nologin-gets-shell",
    ),
    pytest.param(
        [rec("users", f"user:{SID}-501", {"name": "Guest", "enabled": "false"})],
        [rec("users", f"user:{SID}-501", {"name": "Guest", "enabled": "true"})],
        f"user:{SID}-501",
        "BO-USR-004",
        "high",
        "observed",
        id="guest-enabled",
    ),
    pytest.param(
        [rec("users", f"user:{SID}-1001", {"name": "u", "password_required": "true"})],
        [rec("users", f"user:{SID}-1001", {"name": "u", "password_required": "false"})],
        f"user:{SID}-1001",
        "BO-USR-005",
        "high",
        "observed",
        id="password-requirement-removed",
    ),
    pytest.param(
        [rec("groups", "group:sudo", {"members": ["alice"]})],
        [rec("groups", "group:sudo", {"members": ["alice", "bob"]})],
        "group:sudo",
        "BO-GRP-001",
        "high",
        "observed",
        id="sudo-member-added",
    ),
    pytest.param(
        [rec("groups", "group:docker", {"members": []})],
        [rec("groups", "group:docker", {"members": ["bob"]})],
        "group:docker",
        "BO-GRP-001",
        "medium",
        "observed",
        id="docker-member-added",
    ),
    pytest.param(
        [],
        [
            rec(
                "persistence",
                "persist:ssh_key:root:SHA256:k1",
                {"user": "root", "type": "ssh-ed25519"},
                scope="ssh_keys",
            )
        ],
        "persist:ssh_key:root:SHA256:k1",
        "BO-PER-001",
        "critical",
        "observed",
        id="root-ssh-key",
    ),
    pytest.param(
        [],
        [
            rec(
                "persistence",
                "persist:ssh-authkey:root:165a5affa810318b561880f3",
                {"owner": "root", "type": "ssh-ed25519", "file": "/root/.ssh/authorized_keys"},
                scope="ssh-authkeys",
            )
        ],
        "persist:ssh-authkey:root:165a5affa810318b561880f3",
        "BO-PER-001",
        "critical",
        "observed",
        id="root-ssh-key-collector-format",
    ),
    pytest.param(
        [rec("persistence", "persist:file:/etc/rc.local", {"sha256": "a"}, scope="startup")],
        [rec("persistence", "persist:file:/etc/rc.local", {"sha256": "b"}, scope="startup")],
        "persist:file:/etc/rc.local",
        "BO-PER-002",
        "high",
        "observed",
        id="startup-script-modified",
    ),
    pytest.param(
        [],
        [cron(1, "/tmp/payload.sh")],
        "cron:/etc/cron.d/job#1",
        "BO-EXE-001",
        "high",
        "heuristic",
        id="cron-from-tmp",
    ),
    pytest.param(
        [cron(1, "/usr/local/bin/backup.sh")],
        [cron(1, "/usr/local/bin/evil.sh")],
        "cron:/etc/cron.d/job#1",
        "BO-SCH-003",
        "high",
        "observed",
        id="cron-command-rewritten",
    ),
    pytest.param(
        [],
        [rec("scheduled_tasks", "task:\\t", {"hidden": "true", "actions": ["C:\\a.exe"]})],
        "task:\\t",
        "BO-SCH-002",
        "high",
        "heuristic",
        id="hidden-task",
    ),
    pytest.param(
        [],
        [svc("telnet.service")],
        "service:telnet.service",
        "BO-SVC-003",
        "medium",
        "heuristic",
        id="telnet-service",
    ),
    pytest.param(
        [rec("services", "service:winrm", {"image_path": "C:\\Windows\\System32\\svchost.exe"})],
        [rec("services", "service:winrm", {"image_path": "D:\\tools\\w.exe"})],
        "service:winrm",
        "BO-SVC-002",
        "high",
        "observed",
        id="service-binary-replaced",
    ),
    pytest.param(
        [svc("auditd.service")],
        [svc("auditd.service", active="dead")],
        "service:auditd.service",
        "BO-SVC-004",
        "high",
        "observed",
        id="auditd-stopped",
    ),
    pytest.param(
        [svc("rsyslog.service")],
        [],
        "service:rsyslog.service",
        "BO-SVC-004",
        "medium",
        "observed",
        id="rsyslog-removed",
    ),
    pytest.param(
        [],
        [
            rec(
                "listeners",
                "listener:tcp/0.0.0.0/8080",
                {"bind": ["0.0.0.0"], "port": ["8080"], "process": ["java"], "proto": ["tcp"]},
            )
        ],
        "listener:tcp/0.0.0.0/8080",
        "BO-NET-001",
        "medium",
        "observed",
        id="new-exposed-listener",
    ),
    pytest.param(
        [],
        [
            rec(
                "listeners",
                "listener:tcp/0.0.0.0/9000",
                {"bind": ["0.0.0.0"], "port": ["9000"], "process": ["ncat"], "proto": ["tcp"]},
            )
        ],
        "listener:tcp/0.0.0.0/9000",
        "BO-NET-002",
        "high",
        "heuristic",
        id="netcat-listener",
    ),
    pytest.param(
        [
            rec(
                "listeners",
                "listener:tcp/0.0.0.0/22",
                {"bind": ["0.0.0.0"], "port": ["22"], "process": ["sshd"], "proto": ["tcp"]},
            )
        ],
        [
            rec(
                "listeners",
                "listener:tcp/0.0.0.0/22",
                {"bind": ["0.0.0.0"], "port": ["22"], "process": ["python3"], "proto": ["tcp"]},
            )
        ],
        "listener:tcp/0.0.0.0/22",
        "BO-NET-003",
        "high",
        "observed",
        id="port-22-taken-over",
    ),
    pytest.param(
        [
            rec(
                "config",
                "config:firewall:profile:public",
                {"enabled": True, "default_inbound": "Block"},
            )
        ],
        [
            rec(
                "config",
                "config:firewall:profile:public",
                {"enabled": False, "default_inbound": "Block"},
            )
        ],
        "config:firewall:profile:public",
        "BO-CFG-001",
        "high",
        "observed",
        id="firewall-disabled",
    ),
    pytest.param(
        [rec("config", "config:sysctl:kernel.randomize_va_space", {"value": "2"}, scope="sysctl")],
        [rec("config", "config:sysctl:kernel.randomize_va_space", {"value": "0"}, scope="sysctl")],
        "config:sysctl:kernel.randomize_va_space",
        "BO-CFG-002",
        "high",
        "observed",
        id="aslr-off",
    ),
    pytest.param(
        [],
        [
            rec(
                "config",
                "config:suid:/usr/bin/newgrp",
                {"mode": "4755", "owner": "root"},
                scope="suid",
            )
        ],
        "config:suid:/usr/bin/newgrp",
        "BO-CFG-003",
        "medium",
        "observed",
        id="plain-new-suid",
    ),
    pytest.param(
        [],
        [
            rec(
                "config",
                "config:suid:/usr/bin/python3",
                {"mode": "4755", "owner": "root"},
                scope="suid",
            )
        ],
        "config:suid:/usr/bin/python3",
        "BO-CFG-004",
        "high",
        "heuristic",
        id="suid-interpreter",
    ),
    pytest.param(
        [rec("config", "config:sudoers:/etc/sudoers.d/ops", {"sha256": "a"}, scope="sudoers")],
        [rec("config", "config:sudoers:/etc/sudoers.d/ops", {"sha256": "b"}, scope="sudoers")],
        "config:sudoers:/etc/sudoers.d/ops",
        "BO-CFG-005",
        "high",
        "observed",
        id="sudoers-changed",
    ),
    pytest.param(
        [],
        [
            rec(
                "config",
                "config:security:defender-exclusion:path::c:\\x",
                {"path": "C:\\x"},
                scope="security",
            )
        ],
        "config:security:defender-exclusion:path::c:\\x",
        "BO-CFG-006",
        "high",
        "observed",
        id="defender-exclusion",
    ),
    pytest.param(
        [],
        [
            rec(
                "config",
                "config:hosts:10.0.0.1/updates.example.test",
                {"ip": "10.0.0.1"},
                scope="hosts",
            )
        ],
        "config:hosts:10.0.0.1/updates.example.test",
        "BO-CFG-007",
        "medium",
        "observed",
        id="hosts-entry-added",
    ),
]


@pytest.mark.parametrize(("base", "cur", "key", "rule_id", "severity", "basis"), FIRE)
def test_rule_fires_with_expected_severity_and_basis(  # noqa: PLR0913, PLR0917 - table row
    base: list[dict[str, Any]],
    cur: list[dict[str, Any]],
    key: str,
    rule_id: str,
    severity: str,
    basis: str,
) -> None:
    doc = run(base, cur)
    det = one(doc, key)
    assert rule_id in rules_for(doc, key)
    reason = next(r for r in det["reasons"] if r["rule"] == rule_id)
    assert reason["severity"] == severity
    assert reason["basis"] == basis
    assert det["id"].startswith("DET-") and det["investigation"] and det["reasons"]


def test_every_rule_is_exercised_by_a_scenario() -> None:
    # BO-FND-001 reads the diff's findings, not changes: see test_detection_regressions.py
    covered = {p.values[3] for p in FIRE} | {"BO-GRP-001", "BO-SVC-001", "BO-SCH-001", "BO-PER-002"}
    covered |= {"BO-FND-001"}
    assert {r.rule_id for r in detection.RULES} <= covered


# ----------------------------------------------------- false positives: nothing may fire

QUIET = [
    pytest.param(
        [user("root", "0"), user("toor", "0")],
        [user("root", "0"), user("toor", "0")],
        id="preexisting-second-uid0-is-baseline",
    ),
    pytest.param(
        [user("root", "0"), user("backup", "34", "/usr/sbin/nologin")],
        [user("root", "0"), user("backup", "34", "/usr/sbin/nologin")],
        id="unchanged-service-account",
    ),
    pytest.param(
        [user("a", "1000", "/bin/bash")],
        [user("a", "1000", "/bin/zsh")],
        id="login-shell-to-login-shell",
    ),
    pytest.param(
        [user("a", "1000", "/bin/bash")],
        [user("a", "1000", "/usr/sbin/nologin")],
        id="account-locked-down",
    ),
    pytest.param(
        [rec("groups", "group:sudo", {"members": ["alice", "bob"]})],
        [rec("groups", "group:sudo", {"members": ["alice"]})],
        id="privileged-member-removed",
    ),
    pytest.param(
        [rec("groups", "group:staff", {"members": ["alice"]})],
        [rec("groups", "group:staff", {"members": ["alice", "bob"]})],
        id="unprivileged-group-grew",
    ),
    pytest.param(
        [cron(1, "/usr/local/bin/backup.sh")],
        [cron(1, "/usr/local/bin/backup.sh")],
        id="same-cron",
    ),
    pytest.param(
        [svc("auditd.service", active="dead")],
        [svc("auditd.service", active="running")],
        id="security-service-restored",
    ),
    pytest.param(
        [svc("nginx.service")],
        [svc("nginx.service", active="dead")],
        id="non-security-service-stopped",
    ),
    pytest.param(
        [rec("config", "config:sysctl:net.ipv4.ip_forward", {"value": "1"}, scope="sysctl")],
        [rec("config", "config:sysctl:net.ipv4.ip_forward", {"value": "0"}, scope="sysctl")],
        id="forwarding-turned-off",
    ),
    pytest.param(
        [rec("config", "config:firewall:profile:domain", {"enabled": False})],
        [rec("config", "config:firewall:profile:domain", {"enabled": True})],
        id="firewall-enabled",
    ),
    pytest.param(
        [rec("config", "config:suid:/usr/bin/passwd", {"mode": "4755"}, scope="suid")],
        [rec("config", "config:suid:/usr/bin/passwd", {"mode": "4755"}, scope="suid")],
        id="existing-suid-python-style-name-not-realerted",
    ),
    pytest.param(
        [rec("config", "config:suid:/usr/bin/find", {"mode": "4755"}, scope="suid")],
        [rec("config", "config:suid:/usr/bin/find", {"mode": "4755"}, scope="suid")],
        id="existing-risky-suid-stays-baseline",
    ),
    pytest.param(
        [],
        [
            rec(
                "listeners",
                "listener:tcp/127.0.0.1/5432",
                {
                    "bind": ["127.0.0.1"],
                    "port": ["5432"],
                    "process": ["postgres"],
                    "proto": ["tcp"],
                },
            )
        ],
        id="new-loopback-listener",
    ),
]


@pytest.mark.parametrize(("base", "cur"), QUIET)
def test_benign_or_unchanged_state_raises_no_detection(
    base: list[dict[str, Any]], cur: list[dict[str, Any]]
) -> None:
    doc = run(base, cur)
    assert doc["detections"] == []
    assert doc["summary"]["total"] == 0


@pytest.mark.parametrize(
    ("cur", "key"),
    [
        pytest.param(
            cron(1, "/home/alice/tmp/run.sh"),
            "cron:/etc/cron.d/job#1",
            id="tmp-as-a-path-component-is-not-the-tmp-directory",
        ),
        pytest.param(
            rec("persistence", "persist:run:m:app", {"data": "C:\\Program Files\\App\\app.exe"}),
            "persist:run:m:app",
            id="program-files-run-key",
        ),
        pytest.param(
            rec("persistence", "persist:run:m:app", {"data": "/mnt/c/users/public/x"}),
            "persist:run:m:app",
            id="drive-less-windows-fragment-on-unix",
        ),
    ],
)
def test_ordinary_paths_do_not_trigger_the_volatile_location_heuristic(
    cur: dict[str, Any], key: str
) -> None:
    doc = run([], [cur])
    assert "BO-EXE-001" not in rules_for(doc, key)
    assert one(doc, key)["severity"] == "medium"  # still a new entry, just not a suspicious one


def test_loopback_netcat_is_a_heuristic_medium_not_high() -> None:
    doc = run(
        [],
        [
            rec(
                "listeners",
                "listener:tcp/127.0.0.1/4444",
                {"bind": ["127.0.0.1"], "port": ["4444"], "process": ["nc"], "proto": ["tcp"]},
            )
        ],
    )
    det = one(doc, "listener:tcp/127.0.0.1/4444")
    assert (det["severity"], det["basis"]) == ("medium", "heuristic")
    assert "BO-NET-001" not in rules_for(doc, "listener:tcp/127.0.0.1/4444")


def test_nologin_and_disabled_new_accounts_are_low() -> None:
    doc = run(
        [],
        [
            user("daemonx", "990", "/usr/sbin/nologin"),
            rec("users", f"user:{SID}-2001", {"name": "svc", "enabled": "false"}),
        ],
    )
    assert one(doc, "user:daemonx")["severity"] == "low"
    assert one(doc, f"user:{SID}-2001")["severity"] == "low"


def test_ephemeral_listener_churn_is_not_an_alert() -> None:
    def lst(proc: str) -> dict[str, Any]:
        return rec(
            "listeners",
            "listener:tcp/0.0.0.0/ephemeral",
            {"bind": ["0.0.0.0"], "port": ["ephemeral"], "process": [proc], "proto": ["tcp"]},
        )

    assert run([lst("agent")], [lst("agent")])["detections"] == []
    # A different name taking over the bucket is not churn: see test_detection_regressions.py
    # (P0-1) for the high-port listener rules.


# ------------------------------------------------------- confirmed vs heuristic, dedup, links


def test_one_detection_per_subject_with_every_reason_listed() -> None:
    doc = run(
        [],
        [
            rec(
                "scheduled_tasks",
                "task:\\u",
                {"hidden": "true", "actions": ["C:\\Users\\Public\\u.exe"]},
            )
        ],
    )
    keys = [
        (d["subject"]["domain"], d["subject"]["scope"], d["subject"]["key"])
        for d in doc["detections"]
    ]
    assert len(keys) == len(set(keys)) == 1
    det = doc["detections"][0]
    assert {r["rule"] for r in det["reasons"]} == {"BO-SCH-001", "BO-SCH-002", "BO-EXE-001"}
    assert len({r["rule"] for r in det["reasons"]}) == len(det["reasons"])
    assert len(det["investigation"]) == len(set(det["investigation"]))


def test_detection_basis_follows_the_reason_that_sets_the_severity() -> None:
    mixed = run([], [cron(1, "/tmp/x.sh")])
    det = one(mixed, "cron:/etc/cron.d/job#1")
    assert det["severity"] == "high" and det["basis"] == "heuristic"  # medium fact + high guess
    assert {r["basis"] for r in det["reasons"]} == {"observed", "heuristic"}
    fact = run([user("root", "0")], [user("root", "0"), user("m", "0")])
    assert one(fact, "user:m")["basis"] == "observed"


def test_new_account_added_to_admin_group_escalates_to_critical() -> None:
    base = [rec("groups", "group:sudo", {"members": ["alice"]})]
    cur = [rec("groups", "group:sudo", {"members": ["alice", "newbie"]}), user("newbie")]
    assert one(run(base, cur), "group:sudo")["severity"] == "critical"
    existing = run(
        [*base, user("carol")],
        [rec("groups", "group:sudo", {"members": ["alice", "carol"]}), user("carol")],
    )
    assert one(existing, "group:sudo")["severity"] == "high"


def test_windows_new_account_in_administrators_is_matched_by_sid_case_insensitively() -> None:
    base = [rec("groups", "group:S-1-5-32-544", {"members": [f"{SID}-500"]})]
    cur = [
        rec("groups", "group:S-1-5-32-544", {"members": [f"{SID}-500", f"{SID}-1337"]}),
        rec("users", f"user:{SID}-1337", {"name": "svc", "enabled": "true"}),
    ]
    assert one(run(base, cur, family="windows"), "group:s-1-5-32-544")["severity"] == "critical"


def test_detections_sharing_an_artifact_are_linked_not_merged() -> None:
    exe = "C:\\Users\\Public\\upd.exe"
    doc = run(
        [],
        [
            rec("scheduled_tasks", "task:\\upd", {"actions": [exe]}),
            rec("persistence", "persist:run:m:upd", {"data": exe}),
            rec("services", "service:upd", {"image_path": exe}),
            rec(
                "listeners",
                "listener:tcp/0.0.0.0/8443",
                {"bind": ["0.0.0.0"], "port": ["8443"], "process": ["upd.exe"], "proto": ["tcp"]},
            ),
            rec("services", "service:unrelated", {"image_path": "C:\\Other\\x.exe"}),
        ],
        family="windows",
    )
    ids = {d["subject"]["key"]: d for d in doc["detections"]}
    assert len(ids) == 5
    task = ids["task:\\upd"]
    assert {c["id"] for c in task["correlated"]} == {
        ids["persist:run:m:upd"]["id"],
        ids["service:upd"]["id"],
        ids["listener:tcp/0.0.0.0/8443"]["id"],
    }
    assert ids["service:unrelated"]["correlated"] == []
    assert task["id"] not in {c["id"] for c in task["correlated"]}


def test_audit_findings_that_already_cover_a_change_are_referenced() -> None:
    from baseline_builders import finding  # noqa: PLC0415

    ev = [("file", "/etc/cron.d/job")]
    b, c = reports(
        [],
        [cron(1, "/tmp/x.sh") | {"evidence": [{"type": "file", "ref": "/etc/cron.d/job"}]}],
    )
    c["findings"] = [finding("PER-CRON-002", "high", ev)]
    doc = detect(_diff(b, c), NOW)
    assert one(doc, "cron:/etc/cron.d/job#1")["related_findings"] == ["PER-CRON-002"]


def test_min_severity_hides_but_counts() -> None:
    b, c = reports([], [user("daemonx", "990", "/usr/sbin/nologin"), user("m", "0")])
    doc = detect(_diff(b, c), NOW, Severity.HIGH)
    assert [d["subject"]["key"] for d in doc["detections"]] == ["user:m"]
    assert doc["summary"]["suppressed_below_min_severity"] == 1
    assert exit_code_for(doc) == 4
    only_low = detect(
        _diff(*reports([], [user("daemonx", "990", "/usr/sbin/nologin")])), NOW, Severity.HIGH
    )
    assert only_low["summary"]["total"] == 0 and exit_code_for(only_low) == 0


# --------------------------------------------------------- incomplete data is never a verdict


def test_partial_domain_withholds_removals_so_no_removal_based_alert() -> None:
    base = [svc("auditd.service")]
    b, c = pair(base, [], coverage=None)
    c["inventory"]["coverage"] = [cov("services", "partial", "needs root")]
    b["inventory"]["coverage"] = [cov("services")]
    doc = detect(_diff(b, c), NOW)
    assert doc["detections"] == []
    assert doc["coverage"]["complete"] is False
    assert exit_code_for(doc) == 6


@pytest.mark.parametrize("platform", ["linux", "windows"])
@pytest.mark.parametrize("variant", ["unprivileged", "module-failed"])
def test_incomplete_e2e_runs_are_not_a_clean_bill_of_health(platform: str, variant: str) -> None:
    doc = _e2e(platform, variant)
    assert doc["coverage"]["complete"] is False
    assert doc["coverage"]["gaps"] or doc["coverage"]["indeterminate"]
    assert doc["detections"] == []
    assert exit_code_for(doc) == 6


def test_report_without_inventory_is_flagged_not_evaluated() -> None:
    b = report([], inventory=False, version="0.1.0")
    c = report([], inventory=False, version="0.1.0", run="run-2")
    doc = detect(_diff(b, c), NOW)
    assert doc["coverage"]["no_inventory"] is True and exit_code_for(doc) == 6


def test_a_failing_rule_is_reported_and_does_not_hide_other_rules(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(c: dict[str, Any], ctx: detection.Context) -> list[detection.Signal]:
        raise RuntimeError("synthetic")

    monkeypatch.setattr(
        detection,
        "RULES",
        [*detection.RULES, detection.RuleInfo("BO-TST-001", ("users",), "t", boom)],
    )
    doc = run([user("root", "0")], [user("root", "0"), user("m", "0")])
    assert doc["coverage"]["rule_errors"] == [
        {"rule": "BO-TST-001", "key": "user:m", "error": "RuntimeError"}
    ]
    assert doc["coverage"]["complete"] is False
    assert "BO-USR-001" in rules_for(doc, "user:m")


def test_transient_changes_are_ignored() -> None:
    d = _diff(
        *reports(
            [], [rec("processes", "process:root:sleep", {"comm": "sleep", "exe": "/usr/bin/sleep"})]
        )
    )
    assert any(c["transient"] for c in d["changes"])
    assert detect(d, NOW)["detections"] == []


# ------------------------------------------------------------------- end-to-end fixtures


def _e2e(platform: str, variant: str, base: str = "baseline") -> dict[str, Any]:
    o = Options()
    b = build_snapshot(json.loads((FX / platform / f"{base}.json").read_text("utf-8")), o)
    c = build_snapshot(json.loads((FX / platform / f"{variant}.json").read_text("utf-8")), o)
    doc = detect(compare(b, c, o, NOW), NOW)
    Draft202012Validator(SCHEMA).validate(doc)
    return doc


# Pinned on purpose: a change here is a behaviour change of the rules, not a refactor.
EXPECTED_LINUX = {
    "user:mallory": ("critical", "observed", {"BO-USR-001", "BO-USR-002"}),
    "group:sudo": ("critical", "observed", {"BO-GRP-001"}),
    "user:deploy": ("high", "observed", {"BO-USR-003"}),
    "listener:tcp/0.0.0.0/4444": ("high", "heuristic", {"BO-NET-001", "BO-NET-002"}),
    "cron:/etc/cron.d/.hidden#1": ("high", "heuristic", {"BO-EXE-001", "BO-SCH-001"}),
    "cron:/etc/cron.d/backup#1": ("high", "observed", {"BO-EXE-001", "BO-SCH-003"}),
    "persist:ssh_key:mallory:SHA256:synthetic-mallory-key-0002": (
        "high",
        "observed",
        {"BO-PER-001"},
    ),
    "persist:file:/etc/rc.local": ("high", "observed", {"BO-PER-002"}),
    "config:suid:/usr/bin/find": ("high", "heuristic", {"BO-CFG-003", "BO-CFG-004"}),
    "service:telnet.service": ("medium", "observed", {"BO-SVC-001", "BO-SVC-003"}),
    "service:rsyslog.service": ("medium", "observed", {"BO-SVC-004"}),
    "config:sysctl:net.ipv4.ip_forward": ("medium", "observed", {"BO-CFG-002"}),
}
EXPECTED_WINDOWS = {
    "group:s-1-5-32-544": ("critical", "observed", {"BO-GRP-001"}),
    f"user:{DOM}-1337": ("high", "observed", {"BO-USR-002"}),
    f"user:{DOM}-501": ("high", "observed", {"BO-USR-004"}),
    "service:updatehelper": ("high", "heuristic", {"BO-EXE-001", "BO-SVC-001"}),
    "service:winrm": ("high", "observed", {"BO-EXE-001", "BO-SVC-002"}),
    "listener:tcp/0.0.0.0/4444": ("high", "heuristic", {"BO-NET-001", "BO-NET-002"}),
    "task:\\updatecheck": ("high", "heuristic", {"BO-EXE-001", "BO-SCH-001", "BO-SCH-002"}),
    "persist:run:machine:\\software\\microsoft\\windows\\currentversion\\run:updater": (
        "high",
        "heuristic",
        {"BO-EXE-001", "BO-PER-002"},
    ),
    "config:firewall:profile:public": ("high", "observed", {"BO-CFG-001"}),
    f"config:security:reg:{UAC_KEY}": (
        "high",
        "observed",
        {"BO-CFG-002"},
    ),
}


@pytest.mark.parametrize(
    ("platform", "expected"), [("linux", EXPECTED_LINUX), ("windows", EXPECTED_WINDOWS)]
)
def test_changed_fixture_detections_are_pinned(
    platform: str, expected: dict[str, tuple[str, str, set[str]]]
) -> None:
    doc = _e2e(platform, "changed")
    got = {
        d["subject"]["key"]: (d["severity"], d["basis"], {r["rule"] for r in d["reasons"]})
        for d in doc["detections"]
    }
    assert got == expected
    assert exit_code_for(doc) == 4


@pytest.mark.parametrize("platform", ["linux", "windows"])
@pytest.mark.parametrize("variant", ["identical", "churn"])
def test_benign_e2e_runs_raise_nothing(platform: str, variant: str) -> None:
    doc = _e2e(platform, variant)
    assert doc["detections"] == [] and doc["coverage"]["complete"] is True
    assert exit_code_for(doc) == 0


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_reversing_the_comparison_does_not_report_the_attack_again(platform: str) -> None:
    """Remediation looks like a change too: it must not look like a new attack."""
    doc = _e2e(platform, "baseline", base="changed")  # the compromised state is the baseline
    assert not any(d["basis"] == "heuristic" for d in doc["detections"])
    assert not any(d["severity"] in ("critical",) for d in doc["detections"])
    fixed = {d["subject"]["key"]: d["severity"] for d in doc["detections"]}
    for key in ("cron:/etc/cron.d/backup#1", "service:winrm"):
        if key in fixed:
            assert fixed[key] == "low"  # command/binary moved out of /tmp or Users\\Public


def test_detection_ids_are_stable_unique_and_ordered() -> None:
    a, b = _e2e("linux", "changed"), _e2e("linux", "changed")
    assert a == b
    ids = [d["id"] for d in a["detections"]]
    assert len(ids) == len(set(ids))
    sev = [Severity.parse(d["severity"]) for d in a["detections"]]
    assert sev == sorted(sev, reverse=True)


def test_output_is_independent_of_input_ordering() -> None:
    o = Options()
    base = json.loads((FX / "linux" / "baseline.json").read_text("utf-8"))
    cur = json.loads((FX / "linux" / "changed.json").read_text("utf-8"))
    ref = detect(compare(build_snapshot(base, o), build_snapshot(cur, o), o, NOW), NOW)
    shuffled = copy.deepcopy(cur)
    shuffled["inventory"]["records"].reverse()
    shuffled["findings"].reverse()
    again = detect(compare(build_snapshot(base, o), build_snapshot(shuffled, o), o, NOW), NOW)
    assert ref == again


# ------------------------------------------------------------------------------- input safety


@pytest.mark.parametrize(
    "bad",
    [
        [],
        {"kind": "audit-report"},
        {"kind": "baseline-diff", "schema_version": "9.0.0"},
        {"kind": "baseline-diff", "schema_version": "0.2.0", "changes": "x"},
    ],
)
def test_malformed_diff_documents_are_rejected(bad: Any) -> None:
    with pytest.raises(DiffInputError):
        detect(bad, NOW)


def test_malformed_change_entry_is_rejected() -> None:
    d = _diff(*reports([], [user("m", "0")]))
    d["changes"][0]["change"] = "exploded"
    with pytest.raises(DiffInputError):
        detect(d, NOW)


def test_hostile_values_do_not_crash_rules_or_forge_text_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    evil = "x\x1b[31mRED\x1b[0m\nBO-FORGED [critical]"
    doc = run([], [user(evil, "0"), cron(1, "/tmp/" + evil)])
    assert doc["coverage"]["rule_errors"] == []
    text = detect_cli.render_text(doc)
    assert "\x1b" not in text
    assert "\nBO-FORGED" not in text
    assert "\\x1b" in text


# ----------------------------------------------------------------------------------- the CLI


def _cli(capsys: pytest.CaptureFixture[str], *argv: str | Path) -> tuple[int, str, str]:
    code = detect_cli.main([str(a) for a in argv])
    cap = capsys.readouterr()
    return code, cap.out, cap.err


def _pair_args(platform: str, variant: str = "changed") -> list[str]:
    return [str(FX / platform / "baseline.json"), str(FX / platform / f"{variant}.json")]


def test_cli_json_matches_the_library_and_validates(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, err = _cli(capsys, *_pair_args("linux"), "--json", "--generated-at", NOW)
    assert code == 4
    assert json.loads(out) == _e2e("linux", "changed")
    assert "12 detection(s)" in err and "coverage complete" in err


def test_cli_from_diff_equals_from_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from shared.reporting import diff as diff_cli  # noqa: PLC0415

    saved = tmp_path / "diff.json"
    diff_cli.main(
        [*_pair_args("windows"), "--json", "--quiet", "--generated-at", NOW, "--output", str(saved)]
    )
    capsys.readouterr()
    a = _cli(capsys, "--from-diff", saved, "--json", "--quiet", "--generated-at", NOW)
    b = _cli(capsys, *_pair_args("windows"), "--json", "--quiet", "--generated-at", NOW)
    assert a == b and a[0] == 4


def test_cli_text_report_explains_each_detection(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _cli(capsys, *_pair_args("linux"), "--generated-at", NOW)
    assert code == 4
    for needle in (
        "[CRITICAL]",
        "(observed)",
        "(heuristic)",
        "because:",
        "saw:",
        "why:",
        "investigate:",
        "also flagged by audit finding(s): PER-CRON-002",
        "coverage: complete",
    ):
        assert needle in out, needle
    assert max(len(line) for line in out.splitlines()) < 600


def test_cli_text_report_shows_links_between_related_detections(
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = _cli(capsys, *_pair_args("windows"), "--generated-at", NOW)[1]
    assert "linked to: DET-" in out and "task:\\updatecheck" in out


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _cli(capsys, *_pair_args("linux", "identical"), "--quiet")[0] == 0
    assert _cli(capsys, *_pair_args("linux", "unprivileged"), "--quiet")[0] == 6
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code, out, err = _cli(capsys, "--from-diff", bad)
    assert (code, out) == (3, "") and err.startswith("blueops-detect:")
    missing = _cli(capsys, str(tmp_path / "nope.json"), str(tmp_path / "nope2.json"))
    assert missing[0] == 3 and missing[1] == ""


def test_cli_usage_errors(capsys: pytest.CaptureFixture[str]) -> None:
    for argv in ([], ["only-one"], ["a", "b", "--from-diff", "c"]):
        with pytest.raises(SystemExit) as exc:
            detect_cli.main(argv)
        assert exc.value.code == 2
        capsys.readouterr()


def test_cli_output_file_is_private_and_never_overwritten(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "det.json"
    code = _cli(capsys, *_pair_args("linux"), "--json", "--output", target)[0]
    assert code == 4 and target.stat().st_mode & 0o777 == 0o600 or os.name == "nt"
    before = target.read_bytes()
    code, out, err = _cli(capsys, *_pair_args("linux"), "--json", "--output", target)
    assert code == 1 and "cannot write output" in err and target.read_bytes() == before


def test_cli_min_severity_and_list_rules(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = _cli(
        capsys, *_pair_args("linux"), "--json", "--quiet", "--min-severity", "critical"
    )
    doc = json.loads(out)
    assert (
        code == 4
        and doc["summary"]["total"] == 2
        and doc["summary"]["suppressed_below_min_severity"] == 10
    )
    code, out, _ = _cli(capsys, "--list-rules")
    assert code == 0
    assert all(r.rule_id in out for r in detection.RULES)


def test_rule_catalogue_is_well_formed() -> None:
    ids = [r.rule_id for r in detection.RULES]
    assert len(ids) == len(set(ids))
    for r in detection.RULES:
        assert r.rule_id.startswith("BO-") and r.summary and r.domains
        assert set(r.domains) <= set(INVENTORY_DOMAINS) | {"findings"}  # BO-FND-001


def test_inputs_are_not_modified_and_nothing_touches_the_network(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_net(*a: Any, **k: Any) -> None:
        raise AssertionError("network access attempted")

    monkeypatch.setattr(socket, "socket", no_net)
    monkeypatch.setattr(socket, "create_connection", no_net)
    monkeypatch.setattr(subprocess, "Popen", no_net)
    files = [Path(p) for p in _pair_args("windows")]
    before = {f: (hashlib.sha256(f.read_bytes()).hexdigest(), f.stat().st_mtime_ns) for f in files}
    listing = sorted(p.name for p in FX.rglob("*"))
    _cli(capsys, *files, "--json", "--quiet")
    assert before == {
        f: (hashlib.sha256(f.read_bytes()).hexdigest(), f.stat().st_mtime_ns) for f in files
    }
    assert listing == sorted(p.name for p in FX.rglob("*"))


def test_output_is_identical_across_hash_seeds_and_locales() -> None:
    outs = []
    for seed, tz in (("1", "UTC"), ("999", "Asia/Tokyo")):
        env = {**os.environ, "PYTHONHASHSEED": seed, "TZ": tz, "LC_ALL": "C"}
        proc = subprocess.run(  # noqa: S603 - fixed argv, synthetic inputs
            [
                sys.executable,
                "-m",
                "shared.reporting.detect",
                *_pair_args("windows"),
                "--json",
                "--quiet",
                "--generated-at",
                NOW,
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=ROOT,
            check=False,
        )
        assert proc.returncode == 4, proc.stderr
        outs.append(proc.stdout)
    assert outs[0] == outs[1]


def test_every_rule_is_documented_and_documented_rules_exist() -> None:
    text = (ROOT / "docs" / "detection-rules.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"`(BO-[A-Z]+-\d{3})`", text))
    assert documented == {r.rule_id for r in detection.RULES}
    assert "27" in text and len(detection.RULES) == 27
