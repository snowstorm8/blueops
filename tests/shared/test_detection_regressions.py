"""Regression tests for detection-correctness defects found by the engineering audit.

Each section reproduces one defect with the exact record shapes the real collectors emit, plus
the negative cases that must stay quiet. Synthetic data only.
"""

from __future__ import annotations

from typing import Any

from baseline_builders import rec
from test_detection import one, rules_for, run

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
