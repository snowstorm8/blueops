"""History, snapshot reasoning and detection timelines (no external database)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from rules_support import STAMP, doc, finding, history, record

from shared.reporting.schema_lite import validate
from shared.rules.history import HistoryError, HistoryStore, HistoryView, Snap
from shared.rules.loader import load_rule_set
from shared.rules.timeline import TimelineError, compare_detections

OK = {"modules": {"users": "ok"}}
A = finding("USR-SUDO-002", "medium", "users")


def view(current: dict[str, Any], *specs: dict[str, Any]) -> HistoryView:
    return HistoryView(current, history(*specs))


def f_of(d: dict[str, Any]) -> dict[str, Any]:
    return d["findings"][0]


def test_finding_history_counts_streaks_and_first_seen() -> None:
    cur = doc({"findings": [A], **OK})
    h = view(cur, {"findings": [A], **OK}, {"findings": [A], **OK}).finding_history(f_of(cur))
    assert h["consecutive"] == 3 and h["snapshots_present"] == 3 and h["reappeared"] is False
    assert h["first_seen"].startswith("2026-02-10") and h["known_snapshots"] == 3


def test_absence_in_a_clean_earlier_snapshot_is_reappearance() -> None:
    cur = doc({"findings": [A], **OK})
    h = view(
        cur, {"findings": [A], **OK}, {"findings": [finding("XXX-YYY-001")], **OK}
    ).finding_history(f_of(cur))
    assert h["reappeared"] is True and h["consecutive"] == 1 and h["snapshots_present"] == 2


def test_unknown_states_stop_a_streak_and_are_never_reappearance() -> None:
    cur = doc({"findings": [A], **OK})
    unknown = {"findings": [finding("XXX-YYY-001")], "modules": {"users": "failed"}}
    h = view(cur, {"findings": [A], **OK}, unknown, {"findings": [A], **OK}).finding_history(
        f_of(cur)
    )
    assert h["consecutive"] == 2  # current + the latest earlier one
    h = view(cur, {"findings": [A], **OK}, unknown).finding_history(f_of(cur))
    assert (
        h["reappeared"] is False and h["known_snapshots"] == 2
    )  # unknown snapshot not counted as known
    assert view(cur, {"findings": [A], **OK}, unknown).finding_states(f_of(cur)) == [
        "present",
        "unknown",
    ]


def test_record_stability_counts_unchanged_earlier_snapshots() -> None:
    rec = lambda v: record("config", "config:sshd:permitrootlogin", {"value": v}, "sshd")  # noqa: E731
    cur = doc({"inventory": [rec("yes")]})
    spec = lambda v: {"inventory": [rec(v)]}  # noqa: E731
    v = view(cur, spec("no"), spec("no"), spec("no"))
    assert v.record_stability("config", "sshd", "config:sshd:permitrootlogin") == 3
    assert (
        view(cur, spec("yes"), spec("no"), spec("no")).record_stability(
            "config", "sshd", "config:sshd:permitrootlogin"
        )
        == 2
    )
    assert (
        view(cur, spec("no"), spec("yes"), spec("no")).record_stability(
            "config", "sshd", "config:sshd:permitrootlogin"
        )
        == 1
    )
    assert view(cur).record_stability("config", "sshd", "config:sshd:permitrootlogin") == 0
    assert v.record_stability("config", "sshd", "config:sshd:other") == 0


def test_previous_state_clean_requires_complete_coverage_and_no_medium_findings() -> None:
    cur = doc({})
    assert (
        view(cur, {"findings": [finding("AAA-BBB-001", "low")], **OK}).previous_state()["clean"]
        is True
    )
    assert (
        view(cur, {"findings": [finding("AAA-BBB-001", "medium")], **OK}).previous_state()["clean"]
        is False
    )
    assert (
        view(cur, {"findings": [], "modules": {"users": "partial"}}).previous_state()["clean"]
        is False
    )
    assert view(cur).previous_state() == {"exists": False}


# ------------------------------------------------------------------------------ the store


def write(tmp_path: Path, name: str, d: dict[str, Any]) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(d), encoding="utf-8")
    return p


def test_scan_loads_files_and_reports_what_it_skipped(tmp_path: Path) -> None:
    write(tmp_path, "a.json", doc({"findings": [A]}, aid="a", started="2026-02-01T10:00:00Z"))
    write(tmp_path, "b.json", doc({"findings": [A]}, aid="b", started="2026-02-02T10:00:00Z"))
    (tmp_path / "garbage.json").write_text("{", encoding="utf-8")
    (tmp_path / "readme.txt").write_text("ignored")
    store = HistoryStore.scan(tmp_path, verify=False)  # bare synthetic files
    assert [s.doc["assessment"]["id"] for s in store.snaps] == ["a", "b"]
    assert len(store.skipped) == 1 and "garbage.json" in store.skipped[0]["source"]


def test_before_filters_by_host_time_and_identity(tmp_path: Path) -> None:
    cur = doc({"findings": [A]}, aid="now", started="2026-03-01T10:00:00Z")
    write(tmp_path, "old.json", doc({}, aid="old", started="2026-02-01T10:00:00Z"))
    write(
        tmp_path,
        "other.json",
        doc({}, aid="other", started="2026-02-02T10:00:00Z", host="elsewhere"),
    )
    write(tmp_path, "future.json", doc({}, aid="future", started="2026-04-01T10:00:00Z"))
    write(tmp_path, "self.json", cur)
    write(
        tmp_path, "win.json", doc({}, aid="win", platform="windows", started="2026-02-03T10:00:00Z")
    )
    prev, notes = HistoryStore.scan(tmp_path, verify=False).before(cur)
    assert [s.doc["assessment"]["id"] for s in prev] == ["old"]
    reasons = {Path(n["source"]).name: n["reason"] for n in notes}
    assert "different host" in reasons["other.json"] and "different host" in reasons["win.json"]
    assert "not earlier" in reasons["future.json"] and "self.json" not in reasons


def test_missing_directory_and_bad_paths_are_errors(tmp_path: Path) -> None:
    with pytest.raises(HistoryError, match="not found"):
        HistoryStore.scan(tmp_path / "nope")
    with pytest.raises(HistoryError):
        HistoryStore.from_paths([tmp_path / "nope.json"])


def test_assessment_directories_with_manifests_are_verified(tmp_path: Path) -> None:
    from shared.engine.manifest import write_manifest

    d = tmp_path / "blueops-assessment-x"
    d.mkdir()
    snap = doc({"findings": [A]}, aid="x")
    (d / "assessment.json").write_text(json.dumps(snap), encoding="utf-8")
    write_manifest(d, snap)
    assert len(HistoryStore.scan(tmp_path).snaps) == 1
    (d / "assessment.json").write_text(
        json.dumps({**snap, "warnings": [{"code": "X", "message": "tampered"}]}), encoding="utf-8"
    )
    store = HistoryStore.scan(tmp_path)
    assert store.snaps == [] and "manifest verification" in store.skipped[0]["reason"]


# ----------------------------------------------------------------------------- timelines


def snaps(*specs: dict[str, Any]) -> list[Snap]:
    return history(*specs)


def test_timeline_classifies_new_persistent_resolved_and_intermittent() -> None:
    B = finding("USR-UID0-001", "high", "users")
    C = finding("USR-PWD-001", "high", "users")
    rs = load_rule_set()
    uid0 = {
        "inventory": [
            record("users", "user:root", {"uid": "0"}),
            record("users", "user:toor", {"uid": "0"}),
        ]
    }
    clean = {"inventory": [record("users", "user:root", {"uid": "0"})]}
    s = snaps(
        {**clean, "findings": [A]},
        {**uid0, "findings": [A]},
        {**uid0, "findings": [A]},
        {**clean, "findings": [A]},
        {**uid0, "findings": [A]},
    )
    out = compare_detections(s, rs, STAMP)
    assert validate(out, "detection-comparison.schema.json") == []
    assert len(out["snapshots"]) == 5 and len(out["transitions"]) == 4
    (row,) = [r for r in out["detections"] if r["rule_id"] == "DR-LNX-ACC-001"]
    assert row["present"] == [False, True, True, False, True] and row["state"] == "intermittent"
    t = out["transitions"]
    assert [x["id"] for x in t[0]["new"]] and not t[0]["resolved"]
    assert t[1]["persistent"] and not t[1]["new"]
    assert [x["rule_id"] for x in t[2]["resolved"]] == ["DR-LNX-ACC-001"]
    assert [x["rule_id"] for x in t[3]["new"]] == ["DR-LNX-ACC-001"]
    assert C and B


def test_a_detection_is_unverified_not_resolved_when_its_rule_could_not_be_evaluated() -> None:
    rs = load_rule_set()
    uid0 = {
        "inventory": [
            record("users", "user:root", {"uid": "0"}),
            record("users", "user:toor", {"uid": "0"}),
        ]
    }
    no_users = {"coverage": [{"domain": "users", "status": "unavailable"}], "findings": [A]}
    out = compare_detections(snaps(uid0, no_users), rs, STAMP)
    (row,) = [r for r in out["detections"] if r["rule_id"] == "DR-LNX-ACC-001"]
    assert row["state"] == "unverified" and row["present"] == [True, None]
    assert out["transitions"][0]["unverified"] and not out["transitions"][0]["resolved"]


def test_timeline_validation() -> None:
    rs = load_rule_set()
    with pytest.raises(TimelineError, match="at least two"):
        compare_detections(snaps({}), rs, STAMP)
    mixed = [*snaps({}), *history({}, host="other")]
    with pytest.raises(TimelineError, match="different host"):
        compare_detections(mixed, rs, STAMP)


def test_timeline_orders_by_time_not_by_argument_order() -> None:
    rs = load_rule_set()
    uid0 = {
        "inventory": [
            record("users", "user:root", {"uid": "0"}),
            record("users", "user:toor", {"uid": "0"}),
        ]
    }
    s = snaps({}, uid0)
    forward = compare_detections(s, rs, STAMP)
    backward = compare_detections(list(reversed(s)), rs, STAMP)
    assert json.dumps(forward, sort_keys=True) == json.dumps(backward, sort_keys=True)
