"""Telemetry snapshot comparison and the assessment adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from telemetry_support import auth, coverage, proc, rec, stream

from shared.reporting.schema_lite import validate
from shared.telemetry import ingest
from shared.telemetry.adapter import raw_from_assessment_doc
from shared.telemetry.compare import CompareError, compare_telemetry

ROOT = Path(__file__).resolve().parents[2]


def build(tmp_path, name, records, cov=None, **kw):
    p = tmp_path / name
    p.write_bytes(stream(records, cov, **kw))
    return ingest.ingest_paths([p], generated_at="2026-03-01T11:00:00Z")


def svc(name, state="running", path="/usr/bin/x"):
    return rec("service", f"svc:{name}", {"name": name, "state": state, "path": path})


def test_added_removed_changed_with_complete_coverage(tmp_path):
    a = build(tmp_path, "a.jsonl", [svc("a"), svc("b"), svc("c", "running")])
    b = build(
        tmp_path,
        "b.jsonl",
        [svc("a"), svc("c", "stopped"), svc("d")],
        started="2026-03-02T10:00:00Z",
    )
    c = compare_telemetry(a, b, generated_at="2026-03-02T11:00:00Z")
    assert validate(c, "telemetry-comparison.schema.json") == []
    s = c["categories"]["service"]
    assert [x["identity"] for x in s["added"]] == ["svc:d"] and [
        x["identity"] for x in s["removed"]
    ] == ["svc:b"]
    assert s["changed"][0]["attributes"] == [
        {"name": "state", "before": "running", "after": "stopped"}
    ]
    assert c["summary"] == {"added": 1, "removed": 1, "changed": 1, "indeterminate_categories": 0}


def test_removal_is_not_claimed_when_coverage_was_incomplete(tmp_path):
    a = build(tmp_path, "a.jsonl", [svc("a"), svc("b")])
    b = build(
        tmp_path, "b.jsonl", [svc("a")], coverage(["service"], "unavailable", "systemctl denied")
    )
    c = compare_telemetry(a, b)
    assert (
        c["categories"]["service"]["removed"] == []
        and c["categories"]["service"]["determinate"] is False
    )
    assert (
        c["indeterminate"][0]["category"] == "service"
        and "systemctl denied" in c["indeterminate"][0]["reason"]
    )


def test_additions_are_still_reported_when_indeterminate(tmp_path):
    a = build(tmp_path, "a.jsonl", [svc("a")], coverage(["service"], "partial", "x"))
    b = build(tmp_path, "b.jsonl", [svc("a"), svc("new")], coverage(["service"], "partial", "x"))
    c = compare_telemetry(a, b)
    assert [x["identity"] for x in c["categories"]["service"]["added"]] == ["svc:new"]


def test_events_are_logs_so_absent_events_are_not_removals(tmp_path):
    e1 = auth("2026-03-01T09:00:00Z", "login_failure", "failure", "root", "203.0.113.5")
    e2 = auth("2026-03-02T09:00:00Z", "login_failure", "failure", "root", "203.0.113.6")
    a = build(tmp_path, "a.jsonl", [e1])
    b = build(tmp_path, "b.jsonl", [e2])
    c = compare_telemetry(a, b)["categories"]["auth_event"]
    assert len(c["added"]) == 1 and c["removed"] == [] and c["determinate"] is True


def test_volatile_process_attributes_do_not_register_as_changes(tmp_path):
    a = build(tmp_path, "a.jsonl", [proc(10, 1, "sshd")])
    b = build(tmp_path, "b.jsonl", [proc(99, 1, "sshd")])
    c = compare_telemetry(a, b)
    assert "process" not in c["categories"] or not (
        c["categories"]["process"]["added"] or c["categories"]["process"]["changed"]
    )


def test_new_executable_is_an_added_process(tmp_path):
    a = build(tmp_path, "a.jsonl", [proc(10, 1, "sshd")])
    b = build(
        tmp_path,
        "b.jsonl",
        [proc(10, 1, "sshd"), proc(55, 10, "nc", exe="/tmp/.x/nc", user="www-data")],
    )
    added = compare_telemetry(a, b)["categories"]["process"]["added"]
    assert [x["identity"] for x in added] == ["process:www-data:/tmp/.x/nc"]


def test_unknown_attributes_do_not_produce_phantom_changes(tmp_path):
    a = build(tmp_path, "a.jsonl", [rec("service", "svc:a", {"name": "a", "path": "/x"})])
    b = build(
        tmp_path,
        "b.jsonl",
        [rec("service", "svc:a", {"name": "a", "path": None}, unknown=("path",))],
    )
    c = compare_telemetry(a, b)
    assert "service" not in c["categories"] or c["categories"]["service"]["changed"] == []


def test_different_hosts_cannot_be_compared(tmp_path):
    a = build(tmp_path, "a.jsonl", [svc("a")], host="h1")
    b = build(tmp_path, "b.jsonl", [svc("a")], host="h2")
    with pytest.raises(CompareError):
        compare_telemetry(a, b)


# ------------------------------------------------------------------ assessment adapter


def test_assessment_inventory_becomes_telemetry():
    doc = json.loads((ROOT / "tests/fixtures/rules/linux-compromised.assessment.json").read_text())
    t = ingest.build_document([raw_from_assessment_doc(doc)], mode="assessment")
    assert validate(t, "telemetry.schema.json") == []
    cats = t["summary"]["by_category"]
    for c in (
        "process",
        "user",
        "group",
        "service",
        "listener",
        "scheduled_task",
        "persistence",
        "system_config",
        "integrity",
    ):
        assert cats.get(c, 0) > 0, c
    assert t["collection"]["mode"] == "assessment" and t["errors"] == [] and t["rejected"] == []
    redis = next(
        r
        for r in t["records"]
        if r["category"] == "listener" and r["attributes"]["process"] == "redis-server"
    )
    assert redis["attributes"]["local_port"] == 6379 and redis["source"]["type"] == "assessment"
    from shared.findings.model import host_id

    assert t["host"]["host_id"] == host_id(doc["host"]["hostname"], doc["host"]["os"]["family"])


def test_unavailable_assessment_coverage_stays_unavailable():
    doc = json.loads((ROOT / "tests/fixtures/rules/linux-compromised.assessment.json").read_text())
    for c in doc["inventory"]["coverage"]:
        if c["domain"] == "services":
            c["status"], c["reason"] = "unavailable", "module failed"
    doc["inventory"]["records"] = [
        r for r in doc["inventory"]["records"] if r["domain"] != "services"
    ]
    t = ingest.build_document([raw_from_assessment_doc(doc)], mode="assessment")
    svc_cov = next(c for c in t["coverage"] if c["category"] == "service")
    assert (
        svc_cov["status"] == "unavailable"
        and svc_cov["records"] == 0
        and "module failed" in svc_cov["reason"]
    )


def test_unmapped_inventory_domain_is_reported_not_ignored():
    doc = json.loads((ROOT / "tests/fixtures/rules/linux-compromised.assessment.json").read_text())
    doc["inventory"]["records"].append({"domain": "mystery", "key": "m:1", "attrs": {}})
    t = ingest.build_document([raw_from_assessment_doc(doc)], mode="assessment")
    assert any(e["code"] == "UNMAPPED_DOMAIN" and "mystery" in e["message"] for e in t["errors"])


def test_assessment_file_is_importable_by_path(tmp_path):
    t = ingest.ingest_paths(
        [ROOT / "tests/fixtures/rules/linux-compromised.assessment.json"], mode="assessment"
    )
    assert t["collection"]["imported_from"][0]["format"] == "assessment"
