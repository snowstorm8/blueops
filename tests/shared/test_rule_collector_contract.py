"""Contract: the keys and attributes the detection rules read are the ones the collectors emit.

A rule that matches a key no collector produces passes every hand-written unit test and never
fires on a real host (BO-PER-001 and the ASLR branch of BO-CFG-002 were exactly that). These
tests run the real Linux collector over a disposable copy of the synthetic root, and check the
PowerShell sources statically (no PowerShell is needed here; CI also runs the real collector).
"""

from __future__ import annotations

import re
import shutil
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from test_linux_baseline_e2e import BASH, FIXTURES, ROOT, _audit, _diff, _make_bin

from shared.reporting.detection import SSH_KEY_PREFIXES, detect

pytestmark = pytest.mark.skipif(
    BASH is None or sys.platform.startswith("win"), reason="requires bash on a POSIX host"
)

NOW = "2026-03-02T00:00:00Z"
# `id` reporting uid 0: unprivileged runs mark persistence partitions partial, which would turn
# every added record into "indeterminate". These tests are about rule/collector agreement.
ID_SHIM = '#!/bin/sh\ncase "$1" in -u) echo 0;; -un) echo root;; *) echo "uid=0(root)";; esac\n'


def _bindir(dest: Path) -> Path:
    bindir = _make_bin(dest, extra_listener=False)
    shim = bindir / "id"
    shim.write_text(ID_SHIM, "utf-8")
    shim.chmod(0o755)
    return bindir


def _root(dest: Path, aslr: str | None = "2") -> Path:
    shutil.copytree(FIXTURES / "linux-root", dest, symlinks=True)
    for rel in ("usr/bin/su", "usr/bin/find", "usr/bin/mystery"):
        (dest / rel).chmod(stat.S_ISUID | 0o755)
    (dest / "tmp" / "...").write_text("x\n", encoding="utf-8")
    if aslr is not None:
        (dest / "proc/sys/kernel/randomize_va_space").write_text(aslr + "\n", encoding="utf-8")
    return dest


@pytest.fixture(scope="module")
def workdir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("contract")


@pytest.fixture(scope="module")
def audit(workdir: Path) -> Callable[..., dict[str, Any]]:
    counter = iter(range(1000))
    bindir = _bindir(workdir / "bin")
    plain: dict[str | None, dict[str, Any]] = {}  # unmutated audits are deterministic: reuse

    def run(mutate: Callable[[Path], None] | None = None, aslr: str | None = "2") -> dict[str, Any]:
        if mutate is None and aslr in plain:
            return plain[aslr]
        root = _root(workdir / f"root-{next(counter)}", aslr)
        if mutate:
            mutate(root)
        rep = _audit(root, bindir)
        if mutate is None:
            plain[aslr] = rep
        return rep

    return run


def _detect(base: dict[str, Any], cur: dict[str, Any]) -> dict[str, Any]:
    return detect(_diff(base, cur), NOW)


def _by_key(doc: dict[str, Any], key: str) -> dict[str, Any] | None:
    return next((d for d in doc["detections"] if d["subject"]["key"] == key), None)


# ------------------------------------------------ rule keys exist in real collector output


def test_linux_collector_emits_every_record_shape_the_rules_read(
    audit: Callable[..., dict[str, Any]],
) -> None:
    recs = audit()["inventory"]["records"]

    def has(prefix: str, *attrs: str) -> bool:
        return any(
            r["key"].startswith(prefix) and all(a in r["attrs"] for a in attrs) for r in recs
        )

    assert has(SSH_KEY_PREFIXES[0], "owner"), "BO-PER-001: SSH key records (key + owner)"
    assert has("user:", "uid", "shell"), "BO-USR-001/002/003"
    assert has("group:sudo", "members"), "BO-GRP-001"
    assert has("config:sudoers:") and has("config:pam:"), "BO-CFG-005"
    assert has("config:suid:", "mode"), "BO-CFG-003/004"
    assert has("config:hosts:") and has("config:dns:"), "BO-CFG-007"
    assert has("config:sysctl:net.ipv4.ip_forward", "value"), "BO-CFG-002 (forwarding)"
    assert has("config:sysctl:kernel.randomize_va_space", "value"), "BO-CFG-002 (ASLR)"
    assert has("listener:", "bind", "port", "process", "proto"), "BO-NET-001/002/003"
    assert has("service:"), "BO-SVC-*"
    assert has("cron:", "entry"), "BO-SCH-001, BO-EXE-001"


def test_absent_aslr_file_is_not_a_coverage_gap(audit: Callable[..., dict[str, Any]]) -> None:
    rep = audit(aslr=None)
    assert not any(r["key"].endswith("randomize_va_space") for r in rep["inventory"]["records"])
    assert not [
        c
        for c in rep["inventory"]["coverage"]
        if c["domain"] == "config" and c.get("scope") == "sysctl" and c["status"] != "complete"
    ]


def test_aslr_value_never_leaks_into_the_forwarding_finding(
    audit: Callable[..., dict[str, Any]],
) -> None:
    """ASLR=1 is a valid value, not "forwarding enabled": it must not feed NET-FWD-001."""
    rep = audit(lambda r: (r / "proc/sys/net/ipv4/ip_forward").write_text("0\n"), aslr="1")
    assert "NET-FWD-001" not in {f["id"] for f in rep["findings"]}


# ---------------------------------------------- real collector -> compare -> detect, end to end


def _ssh_key(root: Path) -> None:
    with (root / "root/.ssh/authorized_keys").open("a", encoding="utf-8") as fh:
        fh.write("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATTACKERSYNTHETICKEY0000000000000000 x@y\n")


def test_new_root_ssh_key_is_critical_through_the_real_collector(
    audit: Callable[..., dict[str, Any]],
) -> None:
    doc = _detect(audit(), audit(_ssh_key))
    hits = [d for d in doc["detections"] if d["subject"]["key"].startswith(SSH_KEY_PREFIXES[0])]
    assert hits, "a new authorized key must be detected"
    assert all(d["severity"] == "critical" for d in hits if ":root:" in d["subject"]["key"])
    assert {r["rule"] for d in hits for r in d["reasons"]} == {"BO-PER-001"}


def test_unchanged_host_has_no_ssh_or_aslr_detection(audit: Callable[..., dict[str, Any]]) -> None:
    doc = _detect(audit(), audit())
    assert doc["detections"] == []


@pytest.mark.parametrize(
    ("before", "after", "severity"),
    [("2", "0", "high"), ("2", "1", "high"), ("1", "0", "high")],
)
def test_aslr_reduced_is_detected_through_the_real_collector(
    audit: Callable[..., dict[str, Any]], before: str, after: str, severity: str
) -> None:
    doc = _detect(audit(aslr=before), audit(aslr=after))
    det = _by_key(doc, "config:sysctl:kernel.randomize_va_space")
    assert det is not None and det["severity"] == severity
    assert {r["rule"] for r in det["reasons"]} == {"BO-CFG-002"}


@pytest.mark.parametrize(("before", "after"), [("0", "2"), ("1", "2"), ("2", "2")])
def test_aslr_raised_or_unchanged_is_quiet(
    audit: Callable[..., dict[str, Any]], before: str, after: str
) -> None:
    doc = _detect(audit(aslr=before), audit(aslr=after))
    assert _by_key(doc, "config:sysctl:kernel.randomize_va_space") is None


# ---------------------------------------- Windows: rule keys exist in the collector sources


def _ps(name: str) -> str:
    return (ROOT / "windows/audit" / name).read_text("utf-8")


def test_windows_collectors_emit_the_shapes_the_rules_read() -> None:
    fw, net, sec = (
        _ps("Get-FirewallAudit.ps1"),
        _ps("Get-NetworkAudit.ps1"),
        _ps("Get-SecurityConfigAudit.ps1"),
    )
    # BO-CFG-001: config:firewall:profile:<name> with enabled + default_inbound
    assert "config:firewall:profile:$(" in fw
    assert re.search(r"enabled\s*=.*default_inbound\s*=", fw)
    # BO-CFG-002 (forwarding): config:ip_forward with a boolean `enabled`
    assert re.search(r"-Key 'config:ip_forward' -Attrs @\{ enabled = ", net)
    # BO-CFG-002 (UAC, anonymous access): config:security:reg:<path>::<name> with `value`
    assert "config:security:reg:$($ss[0].ToLowerInvariant())::$($ss[1].ToLowerInvariant())" in sec
    assert "@{ value = $sv }" in sec
    for setting in ("'EnableLUA'", "'RestrictAnonymous'"):
        assert setting in sec
    # BO-CFG-006: config:security:defender-exclusion:...
    assert "config:security:defender-exclusion:" in sec
