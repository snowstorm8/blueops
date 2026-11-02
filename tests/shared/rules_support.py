"""Builders for the detection-engine tests: synthetic hosts, rules and snapshots."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from shared.rules.fixtures import build_assessment
from shared.rules.history import Snap
from shared.rules.loader import RuleSet
from shared.rules.validate import compile_rule

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests" / "fixtures" / "rules"
STAMP = "2026-03-05T00:00:00Z"


def finding(
    check_id: str, severity: str = "medium", category: str = "users", *refs: str, **kw: Any
) -> dict[str, Any]:
    """A finding spec; positional ``refs`` become evidence, ``excerpt=`` is attached to each."""
    f: dict[str, Any] = {"check_id": check_id, "severity": severity, "category": category}
    excerpt = kw.pop("excerpt", None)
    if refs:
        f["evidence"] = [{"ref": r, **({"excerpt": excerpt} if excerpt else {})} for r in refs]
    f.update(kw)
    return f


def record(
    domain: str, key: str, attrs: dict[str, Any] | None = None, scope: str | None = None
) -> dict[str, Any]:
    r: dict[str, Any] = {"domain": domain, "key": key, "attrs": attrs or {}}
    if scope:
        r["scope"] = scope
    return r


def doc(
    spec: dict[str, Any] | None = None,
    *,
    platform: str = "linux",
    aid: str = "cur",
    started: str | None = None,
    host: str = "host01",
) -> dict[str, Any]:
    s = copy.deepcopy(spec or {})
    if started:
        s["started_at"] = started
    return build_assessment(s, platform=platform, hostname=host, aid=aid)


def history(*specs: dict[str, Any], platform: str = "linux", host: str = "host01") -> list[Snap]:
    """Earlier snapshots, oldest first, one per spec."""
    return [
        Snap(
            doc(
                s,
                platform=platform,
                aid=f"prev-{i}",
                started=f"2026-02-{10 + i:02d}T10:00:00Z",
                host=host,
            ),
            f"prev-{i}",
        )
        for i, s in enumerate(specs)
    ]


BASE_RULE: dict[str, Any] = {
    "id": "DR-TST-RULE-001",
    "version": "1.0.0",
    "name": "Test rule",
    "description": "A rule used only by the test-suite.",
    "platforms": ["any"],
    "category": "testing",
    "severity": "medium",
    "severity_reason": "Chosen for the test of the rule engine.",
    "confidence": "medium",
    "confidence_reason": "Chosen for the test of the rule engine.",
    "nature": "indicator",
    "clauses": [
        {
            "id": "a",
            "source": "findings",
            "description": "A finding of check TST-AAA-001",
            "where": {"field": "check_id", "op": "eq", "value": "TST-AAA-001"},
        }
    ],
    "title": "Test rule matched {a.title}",
    "rationale": "This rationale exists only so the test rule is complete.",
    "investigation": ["Look at the evidence."],
    "remediation": "Nothing to do for a test.",
    "examples": [
        {"name": "yes", "expect": "match", "current": {}},
        {"name": "no", "expect": "no_match", "current": {}},
    ],
}


def make_rule(**over: Any) -> dict[str, Any]:
    r = copy.deepcopy(BASE_RULE)
    r.update(over)
    return r


def rule_set(*raw_rules: dict[str, Any]) -> RuleSet:
    rs = RuleSet()
    for raw in raw_rules:
        rule, diags = compile_rule(raw, "test")
        assert rule is not None, [str(d) for d in diags]
        rs.rules[rule.id] = rule
    return rs


def where(field: str, op: str, value: Any = None) -> dict[str, Any]:
    d: dict[str, Any] = {"field": field, "op": op}
    if op not in ("missing", "present", "is_true", "is_false"):
        d["value"] = value
    return d


# ---------------------------------------------------------------- realistic synthetic hosts

ALL_LINUX_MODULES = dict.fromkeys(
    (
        "system",
        "users",
        "pam",
        "auth",
        "processes",
        "network",
        "services",
        "persistence",
        "filesystem",
        "sysconfig",
    ),
    "ok",
)
ALL_WINDOWS_MODULES = dict.fromkeys(
    (
        "system",
        "users",
        "processes",
        "network",
        "services",
        "tasks",
        "autoruns",
        "persistence",
        "firewall",
        "security",
        "eventlog",
        "filesystem",
    ),
    "ok",
)


def linux_clean() -> dict[str, Any]:
    """A tidy server: only root has uid 0, ssh listens, restricted mounts, logs persisted."""
    return {
        "modules": dict(ALL_LINUX_MODULES),
        "findings": [
            finding("SYS-INFO-001", "info", "system", "/etc/os-release"),
            finding("USR-INFO-001", "info", "users", "/etc/passwd"),
            finding("NET-LISTEN-001", "info", "network", "tcp 0.0.0.0:22"),
            finding("SVC-INFO-001", "info", "services"),
        ],
        "inventory": [
            record("users", "user:root", {"uid": "0", "shell": "/bin/bash", "password": "locked"}),
            record("users", "user:alice", {"uid": "1000", "shell": "/bin/bash", "password": "set"}),
            record(
                "users",
                "user:www-data",
                {"uid": "33", "shell": "/usr/sbin/nologin", "password": "locked"},
            ),
            record("groups", "group:sudo", {"gid": "27", "members": ["alice"]}),
            record("services", "service:ssh.service", {"active": "running", "enabled": "enabled"}),
            record(
                "listeners",
                "listener:tcp/0.0.0.0/22",
                {"proto": "tcp", "bind": "0.0.0.0", "port": "22", "process": "sshd"},
            ),
            record(
                "config",
                "config:core:core_pattern",
                {"value": "|/usr/lib/systemd/systemd-coredump %P %u %g"},
                "core",
            ),
            record("config", "config:suid:/usr/bin/su", {"mode": "4755", "owner": "root"}, "suid"),
        ],
    }


def linux_compromised() -> dict[str, Any]:
    """Clean host plus: a second uid-0 account, telnet, a reverse-shell cron job, an unsigned-style
    unit running from /tmp that the filesystem checks also flag, a redirected auth log and a PAM bypass."""
    spec = linux_clean()
    spec["findings"] += [
        finding(
            "USR-UID0-001", "critical", "users", "/etc/passwd", excerpt="account 'toor' has UID 0"
        ),
        finding(
            "PAM-PERMIT-001",
            "high",
            "pam",
            "/etc/pam.d/login",
            excerpt="auth sufficient pam_permit.so",
        ),
        finding(
            "PER-CRON-002",
            "high",
            "persistence",
            "/etc/cron.d/backdoor",
            excerpt="bash /dev/tcp redirect (reverse-shell pattern)",
        ),
        finding(
            "PER-SYSTEMD-001",
            "high",
            "persistence",
            "/etc/systemd/system/evil.service",
            excerpt="references world-writable directory: ExecStart=/tmp/.hidden/agent",
        ),
        finding("FS-PERM-003", "high", "filesystem", "/tmp/.hidden/agent"),
        finding(
            "CFG-LOG-001",
            "high",
            "sysconfig",
            "/var/log/auth.log",
            excerpt="is a symbolic link to /dev/null",
        ),
        finding("ATH-LOCKOUT-001", "low", "auth", "/etc/pam.d"),
    ]
    spec["inventory"] += [
        record("users", "user:toor", {"uid": "0", "shell": "/bin/bash", "password": "set"}),
        record("services", "service:telnet.service", {"active": "running", "enabled": "enabled"}),
        record(
            "listeners",
            "listener:tcp/0.0.0.0/23",
            {"proto": "tcp", "bind": "0.0.0.0", "port": "23", "process": "telnetd"},
        ),
    ]
    return spec


def windows_clean() -> dict[str, Any]:
    return {
        "modules": dict(ALL_WINDOWS_MODULES),
        "findings": [
            finding("SYS-INFO-001", "info", "system"),
            finding("USR-INFO-001", "info", "accounts"),
            finding("SVC-INFO-001", "info", "services"),
            finding("FW-LOG-001", "low", "firewall"),
        ],
        "inventory": [
            record(
                "users",
                "user:S-1-5-21-1-500",
                {"name": "Administrator", "enabled": False, "password_required": True},
            ),
            record(
                "users",
                "user:S-1-5-21-1-1001",
                {"name": "alice", "enabled": True, "password_required": True},
            ),
            record(
                "groups",
                "group:S-1-5-32-544",
                {"name": "Administrators", "members": ["S-1-5-21-1-500"]},
            ),
            record(
                "services",
                "service:spooler",
                {
                    "account": "LocalSystem",
                    "image_path": "C:\\Windows\\System32\\spoolsv.exe",
                    "state": "Running",
                },
            ),
            record(
                "scheduled_tasks",
                "task:\\microsoft\\windows\\updateorchestrator\\reboot",
                {
                    "user": "SYSTEM",
                    "run_level": "Highest",
                    "actions": ["C:\\Windows\\System32\\MusNotification.exe"],
                },
                "tasks",
            ),
            record(
                "listeners",
                "listener:tcp/0.0.0.0/135",
                {"proto": "tcp", "bind": "0.0.0.0", "port": "135", "process": "svchost.exe"},
            ),
        ],
    }


def windows_compromised() -> dict[str, Any]:
    spec = windows_clean()
    spec["findings"] += [
        finding("USR-HIDDEN-001", "high", "accounts", "support$"),
        finding(
            "SEC-RDP-002", "high", "security-config", "HKLM\\..\\RDP-Tcp :: UserAuthentication"
        ),
        finding(
            "SEC-LSA-001",
            "high",
            "security-config",
            "HKLM\\..\\WDigest :: UseLogonCredential",
            excerpt="WDigest stores plaintext credentials in memory",
        ),
        finding(
            "SEC-DEF-001", "high", "security-config", "HKLM\\..\\Defender :: DisableAntiSpyware"
        ),
        finding(
            "EVT-SVC-001",
            "high",
            "eventlog",
            "HKLM\\..\\Services\\EventLog :: Start",
            excerpt="disabled",
        ),
        finding("SEC-PS-001", "low", "security-config", "HKLM\\..\\PowerShell\\ScriptBlockLogging"),
        finding("SEC-AUDIT-001", "medium", "security-config", "auditpol"),
        finding(
            "PER-WMI-001",
            "high",
            "persistence",
            "root\\subscription:CommandLineEventConsumer",
            excerpt="powershell -enc AAAA",
        ),
        finding(
            "SVC-PATH-001",
            "medium",
            "services",
            "service evilsvc",
            excerpt="C:\\Users\\Public\\payload.exe",
        ),
        finding(
            "FS-EXE-001",
            "medium",
            "filesystem",
            "C:\\Users\\Public\\payload.exe",
            excerpt="unsigned",
        ),
        finding("FW-PROFILE-001", "high", "firewall", "Public profile"),
    ]
    spec["inventory"] += [
        record(
            "users",
            "user:S-1-5-21-1-1003",
            {"name": "support$", "enabled": True, "password_required": True},
        ),
        record(
            "services",
            "service:evilsvc",
            {
                "account": "LocalSystem",
                "image_path": "C:\\Users\\Public\\payload.exe",
                "state": "Running",
            },
        ),
        record(
            "scheduled_tasks",
            "task:\\updater\\sync",
            {"user": "SYSTEM", "run_level": "Highest", "actions": ["C:\\ProgramData\\x\\sync.exe"]},
            "tasks",
        ),
        record(
            "listeners",
            "listener:tcp/0.0.0.0/3389",
            {"proto": "tcp", "bind": "0.0.0.0", "port": "3389", "process": "svchost.exe"},
        ),
        record(
            "listeners",
            "listener:tcp/0.0.0.0/445",
            {"proto": "tcp", "bind": "0.0.0.0", "port": "445", "process": "System"},
        ),
    ]
    return spec
