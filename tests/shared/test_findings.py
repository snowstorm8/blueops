"""Finding identity, normalisation, deduplication and evidence provenance."""

from __future__ import annotations

from typing import Any

import pytest
from engine_support import fnd, make_report

from shared.findings.model import (
    Evidence,
    FindingError,
    FindingStore,
    clean,
    evidence_id,
    finding_id,
    host_id,
    normalise_finding,
    remediation_priority,
)
from shared.findings.standards import attack_url, standards_for

TS = "2026-03-01T10:00:00Z"


def _norm(raw: Any, host: str = "web01", family: str = "linux", module: str = "linux.users") -> Any:
    return normalise_finding(raw, host, family, module, "run-1", TS, "tool 1.0")


def test_ids_are_deterministic_and_host_specific() -> None:
    h1, h2 = host_id("web01", "linux"), host_id("web02", "linux")
    assert finding_id(h1, "USR-UID0-001", "users") == finding_id(h1, "USR-UID0-001", "users")
    assert finding_id(h1, "USR-UID0-001", "users") != finding_id(h2, "USR-UID0-001", "users")
    assert finding_id(h1, "USR-UID0-001", "users") != finding_id(h1, "USR-UID0-002", "users")
    assert finding_id(h1, "USR-UID0-001", "users").startswith("BOF-")
    assert len(finding_id(h1, "USR-UID0-001", "users")) == 4 + 16


def test_hostname_comparison_is_case_insensitive_but_os_family_matters() -> None:
    assert host_id("WEB01", "linux") == host_id("web01", "linux")
    assert host_id("web01", "windows") != host_id("web01", "linux")


def test_id_does_not_depend_on_severity_or_evidence() -> None:
    a, _ = _norm(fnd("USR-UID0-001", "high", evidence=[("file", "/etc/passwd")]))
    b, _ = _norm(fnd("USR-UID0-001", "critical", evidence=[("file", "/etc/other")]))
    assert a.id == b.id


def test_evidence_id_ignores_excerpt() -> None:
    assert evidence_id("file", "/etc/passwd") == evidence_id("file", "/etc/passwd")
    assert evidence_id("file", "/etc/passwd") != evidence_id("registry", "/etc/passwd")


@pytest.mark.parametrize(
    ("raw", "why"),
    [
        ("not an object", "not an object"),
        ({"id": "bad id", "title": "t", "severity": "low"}, "malformed"),
        ({"id": "USR-X-001", "title": "t", "severity": "urgent"}, "severity"),
        ({"id": "USR-X-001", "title": "", "severity": "low"}, "title"),
        (
            {"id": "USR-X-001", "title": "t", "severity": "low", "confidence": "certain"},
            "confidence",
        ),
        ({"id": "USR-X-001", "title": "t", "severity": None}, "severity"),
    ],
)
def test_malformed_findings_are_rejected(raw: Any, why: str) -> None:
    with pytest.raises(FindingError, match=why):
        _norm(raw)


def test_store_records_rejected_findings_and_keeps_the_rest() -> None:
    report = make_report([fnd("USR-AAA-001"), fnd("USR-BBB-001")])
    report["findings"].append({"id": "garbage", "title": "x", "severity": "low"})
    store = FindingStore()
    assert store.add_report(report, "linux.users", TS) == 2
    assert [r["reason"] for r in store.rejected] == ["finding id is missing or malformed"]
    assert len(store.findings) == 2


def test_duplicate_findings_merge_highest_severity_and_union_evidence() -> None:
    store = FindingStore()
    store.add_report(
        make_report([fnd("USR-AAA-001", "low", evidence=[("file", "/a")])]), "linux.users", TS
    )
    r2 = make_report([fnd("USR-AAA-001", "high", evidence=[("file", "/b")])], run="run-2")
    store.add_report(r2, "linux.other", "2026-03-01T11:00:00Z")
    (f,) = store.findings.values()
    assert f.severity == "high"
    assert f.occurrences == 2
    assert f.detected_at == TS  # the earliest detection wins
    assert len(f.evidence_ids) == 2
    assert {s["module"] for s in f.sources} == {"linux.users", "linux.other"}


def test_same_evidence_from_two_modules_is_stored_once_with_both_provenances() -> None:
    store = FindingStore()
    for module in ("linux.users", "linux.pam"):
        store.add_report(
            make_report([fnd("USR-AAA-001", evidence=[("file", "/etc/passwd")])]), module, TS
        )
    (ev,) = store.evidence.values()
    assert {p.module for p in ev.provenance} == {"linux.users", "linux.pam"}


def test_evidence_provenance_is_complete() -> None:
    store = FindingStore()
    store.add_report(
        make_report([fnd("USR-AAA-001", evidence=[("file", "/etc/passwd")])]),
        "linux.users",
        TS,
        "a" * 64,
    )
    (ev,) = store.sorted_evidence()
    (p,) = ev.provenance
    assert (p.module, p.check_id, p.collected_at, p.report_sha256) == (
        "linux.users",
        "USR-AAA-001",
        TS,
        "a" * 64,
    )
    assert p.collector.startswith("synthetic-audit")


def test_evidence_not_referenced_by_a_finding_is_not_emitted() -> None:
    store = FindingStore()
    store.add_report(make_report([fnd("USR-AAA-001", evidence=[("file", "/a")])]), "m.x", TS)
    orphan = Evidence(id="EV-" + "0" * 16, type="file", ref="/orphan")
    store.evidence[orphan.id] = orphan
    assert [e.ref for e in store.sorted_evidence()] == ["/a"]


def test_hostile_text_is_neutralised() -> None:
    nasty = "a\x00b\x1b[31mred\x7f"
    assert "\x00" not in clean(nasty) and "\x1b" not in clean(nasty)
    assert clean("x" * 5000, 100).endswith("...") and len(clean("x" * 5000, 100)) == 100
    f, ev = _norm(fnd("USR-AAA-001", evidence=[("file", nasty)]))
    assert "\x00" not in ev[0].ref
    assert clean("tab\tnl\nkept") == "tab\tnl\nkept"


def test_unknown_evidence_type_becomes_other_and_bad_digest_is_dropped() -> None:
    raw = fnd("USR-AAA-001")
    raw["evidence"] = [
        {"type": "telepathy", "ref": "x", "sha256": "nothex"},
        {"type": "file"},
        "str",
    ]
    f, ev = _norm(raw)
    assert [(e.type, e.sha256) for e in ev] == [("other", None)]


def test_priority_downgrades_when_confidence_is_low() -> None:
    assert remediation_priority("critical", "high") == "P1"
    assert remediation_priority("high", "high") == "P1"
    assert remediation_priority("high", "low") == "P2"
    assert remediation_priority("info", "high") == "P4"
    assert remediation_priority("medium", "low") == "P3"


def test_standards_mapping() -> None:
    std = standards_for("users", ["T1136.001", "bogus", "T1136.001"])
    assert [s["id"] for s in std if s["framework"] == "MITRE ATT&CK"] == ["T1136.001"]
    assert std[0]["url"] == "https://attack.mitre.org/techniques/T1136/001/"
    assert any(s["id"] == "AC-2" and s["title"] == "Account Management" for s in std)
    assert standards_for("nonexistent", None) == []
    assert attack_url("T1053") == "https://attack.mitre.org/techniques/T1053/"
    with pytest.raises(ValueError, match="technique"):
        attack_url("../../etc/passwd")


def test_to_json_is_stable_across_input_order() -> None:
    a = FindingStore()
    a.add_report(make_report([fnd("USR-AAA-001", "high"), fnd("USR-BBB-001", "low")]), "m.x", TS)
    b = FindingStore()
    b.add_report(make_report([fnd("USR-BBB-001", "low"), fnd("USR-AAA-001", "high")]), "m.x", TS)
    assert [f.to_json() for f in a.sorted_findings()] == [f.to_json() for f in b.sorted_findings()]
