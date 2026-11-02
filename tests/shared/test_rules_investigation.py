"""Investigation workflow: states, notes, history integrity, separation from evidence."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from rules_support import STAMP, doc, finding, make_rule, rule_set

from shared.rules.engine import detect
from shared.rules.investigation import (
    FILE_NAME,
    LOCK_NAME,
    CaseStore,
    CaseStoreError,
    case_summaries,
    compute_related,
)

POSIX = os.name == "posix"


def results(*specs: dict[str, Any], aid: str = "run-1") -> dict[str, Any]:
    rules = [
        make_rule(id="DR-TST-ONE-001", title="One {a.title}"),
        make_rule(
            id="DR-TST-TWO-001",
            title="Two {a.title}",
            clauses=[
                {
                    "id": "a",
                    "source": "findings",
                    "description": "d",
                    "where": {"field": "check_id", "op": "eq", "value": "TST-BBB-001"},
                }
            ],
        ),
    ]
    out = detect(
        doc(specs[0] if specs else {"findings": [finding("TST-AAA-001", "high")]}, aid=aid),
        rule_set(*rules),
        generated_at=STAMP,
    )
    return out


BOTH = {"findings": [finding("TST-AAA-001", "high"), finding("TST-BBB-001", "low")]}


def test_observe_registers_new_cases_with_status_new(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "state", actor="alice")
    res = results(BOTH)
    reg = store.observe(res)
    assert len(reg["new"]) == 2 and reg["reappeared"] == []
    cases = store.cases()
    assert {c.status for c in cases.values()} == {"new"}
    c = cases[res["detections"][0]["id"]]
    assert c.rule_id.startswith("DR-TST") and c.hostname == "host01" and c.assessments == ["run-1"]


def test_observing_the_same_detection_again_adds_an_assessment_not_a_case(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    store.observe(results(BOTH, aid="run-1"))
    reg = store.observe(results(BOTH, aid="run-2"))
    assert reg == {"new": [], "reappeared": []}
    assert len(store.cases()) == 2
    assert all(c.assessments == ["run-1", "run-2"] for c in store.cases().values())


def test_status_workflow_and_history(tmp_path: Path) -> None:
    store = CaseStore(tmp_path, actor="alice")
    det = store.observe(results(BOTH))["new"][0]
    store.set_status(det, "acknowledged")
    store.set_status(det, "investigating", "looking at the cron files")
    store.add_note(det, "found the owner of the job")
    c = store.set_status(det, "resolved", "approved change CHG-1")
    assert c.status == "resolved"
    assert [(h["from"], h["to"], h["actor"]) for h in c.status_history] == [
        ("new", "acknowledged", "alice"),
        ("acknowledged", "investigating", "alice"),
        ("investigating", "resolved", "alice"),
    ]
    assert (
        c.notes[0]["text"] == "found the owner of the job"
        and c.status_history[2]["note"] == "approved change CHG-1"
    )


@pytest.mark.parametrize(
    ("path", "bad"),
    [
        (["resolved"], "acknowledged"),
        (["dismissed"], "resolved"),
        (["resolved"], "new"),
        (["acknowledged"], "new"),
    ],
)
def test_illegal_transitions_are_refused(tmp_path: Path, path: list[str], bad: str) -> None:
    store = CaseStore(tmp_path)
    det = store.observe(results(BOTH))["new"][0]
    for step in path:
        store.set_status(det, step, "reason given")
    with pytest.raises(CaseStoreError, match="cannot move"):
        store.set_status(det, bad, "reason given")


def test_resolve_and_dismiss_need_a_reason(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    det = store.observe(results(BOTH))["new"][0]
    for status in ("resolved", "dismissed"):
        with pytest.raises(CaseStoreError, match="note is required"):
            store.set_status(det, status)
    store.set_status(det, "dismissed", "known lab account")
    assert store.set_status(det, "investigating").status == "investigating"  # reopening needs none


def test_unknown_status_ids_and_unregistered_cases(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    det = store.observe(results(BOTH))["new"][0]
    with pytest.raises(CaseStoreError, match="unknown status"):
        store.set_status(det, "fixed")
    with pytest.raises(CaseStoreError, match="not a detection id"):
        store.set_status("nope", "acknowledged")
    with pytest.raises(CaseStoreError, match="no case for"):
        store.set_status("DT-" + "0" * 16, "acknowledged")
    with pytest.raises(CaseStoreError, match="must not be empty"):
        store.add_note(det, "   ")


def test_a_closed_detection_that_comes_back_is_flagged_not_silently_reopened(
    tmp_path: Path,
) -> None:
    store = CaseStore(tmp_path)
    det = store.observe(results(BOTH, aid="run-1"))["new"][0]
    store.set_status(det, "dismissed", "lab host")
    reg = store.observe(results(BOTH, aid="run-2"))
    assert reg["reappeared"] == [det]
    c = store.cases()[det]
    assert c.status == "dismissed" and c.reappeared is True  # the analyst's decision stands
    assert store.observe(results(BOTH, aid="run-3"))["reappeared"] == []  # flagged once
    store.set_status(det, "investigating")
    assert store.cases()[det].reappeared is False
    assert case_summaries(store, results(BOTH))[det]["status"] == "investigating"


def test_resolve_id_accepts_unique_prefixes(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    ids = store.observe(results(BOTH))["new"]
    assert store.resolve_id(ids[0][:12]) == ids[0]
    with pytest.raises(CaseStoreError, match="matches 2 cases"):
        store.resolve_id("DT-")
    with pytest.raises(CaseStoreError, match="matches 0 cases"):
        store.resolve_id("DT-zzz")


def test_links_are_symmetric_and_validated(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    a, b = store.observe(results(BOTH))["new"]
    store.link(a, b)
    assert store.cases()[a].linked == [b] and store.cases()[b].linked == [a]
    store.link(a, b)  # idempotent in the view
    assert store.cases()[a].linked == [b]
    with pytest.raises(CaseStoreError, match="itself"):
        store.link(a, a)


def test_analyst_text_is_sanitised_and_capped(tmp_path: Path) -> None:
    store = CaseStore(tmp_path, actor="eve\x1b[31m" + "x" * 200)
    det = store.observe(results(BOTH))["new"][0]
    store.add_note(det, "line\x00one\x1b[2Jtwo" + "y" * 5000)
    c = store.cases()[det]
    assert (
        "\x00" not in c.notes[0]["text"]
        and "\x1b" not in c.notes[0]["text"]
        and len(c.notes[0]["text"]) <= 2000
    )
    assert "\x1b" not in c.notes[0]["actor"] and len(c.notes[0]["actor"]) <= 64


# --------------------------------------------------------------------------- integrity


def lines(path: Path) -> list[bytes]:
    return path.read_bytes().rstrip(b"\n").split(b"\n")


def seeded(tmp_path: Path) -> tuple[CaseStore, str]:
    store = CaseStore(tmp_path, actor="a")
    det = store.observe(results(BOTH))["new"][0]
    store.add_note(det, "first")
    store.add_note(det, "second")
    return store, det


def test_the_event_log_detects_edits_deletions_and_reordering(tmp_path: Path) -> None:
    store, _ = seeded(tmp_path)
    p = tmp_path / FILE_NAME
    original = lines(p)
    # edit a line
    edited = list(original)
    edited[2] = edited[2].replace(b"first", b"FIRST")
    assert edited[2] != original[2]
    p.write_bytes(b"\n".join(edited) + b"\n")
    with pytest.raises(CaseStoreError, match="hash chain broken"):
        store.events()
    # delete a line
    p.write_bytes(b"\n".join(original[:2] + original[3:]) + b"\n")
    with pytest.raises(CaseStoreError, match="sequence"):
        store.events()
    # swap two lines
    swapped = list(original)
    swapped[2], swapped[3] = swapped[3], swapped[2]
    p.write_bytes(b"\n".join(swapped) + b"\n")
    with pytest.raises(CaseStoreError):
        store.events()
    # restoring the original makes it valid again
    p.write_bytes(b"\n".join(original) + b"\n")
    assert len(store.events()) == len(original)


def test_truncation_is_not_detectable_by_the_chain_alone_but_new_events_extend_the_survivor(
    tmp_path: Path,
) -> None:
    """Documented limit: the chain protects earlier lines; dropping or editing the *last* line is
    not detectable from the file alone (keep off-host copies for that)."""
    store, det = seeded(tmp_path)
    p = tmp_path / FILE_NAME
    p.write_bytes(b"\n".join(lines(p)[:-1]) + b"\n")
    assert store.cases()[det].notes[-1]["text"] == "first"


@pytest.mark.parametrize("garbage", [b"{not json}\n", b"[]\n", b'{"seq": 1}\n', b"\xff\xfe\n"])
def test_damaged_files_are_errors_with_a_line_number_never_silently_skipped(
    tmp_path: Path, garbage: bytes
) -> None:
    store, _ = seeded(tmp_path)
    with (tmp_path / FILE_NAME).open("ab") as fh:
        fh.write(garbage)
    with pytest.raises(CaseStoreError, match=r"cases\.jsonl:\d+"):
        store.cases()
    with pytest.raises(CaseStoreError):  # writing also verifies the file it would extend
        store.add_note("DT-" + "0" * 16, "x")


def test_oversized_lines_are_refused(tmp_path: Path) -> None:
    store, _ = seeded(tmp_path)
    with (tmp_path / FILE_NAME).open("ab") as fh:
        fh.write(b"x" * (20 * 1024) + b"\n")
    with pytest.raises(CaseStoreError, match="too long"):
        store.events()


def test_a_stale_lock_is_reported_not_overridden(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, det = seeded(tmp_path)
    (tmp_path / LOCK_NAME).write_text("")
    import time as _t

    real = _t.monotonic
    ticks = iter([0.0] + [100.0] * 50)
    monkeypatch.setattr("shared.rules.investigation.time.monotonic", lambda: next(ticks, real()))
    monkeypatch.setattr("shared.rules.investigation.time.sleep", lambda _s: None)
    with pytest.raises(CaseStoreError, match="another writer is active"):
        store.add_note(det, "blocked")
    assert len(store.cases()[det].notes) == 2


@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_state_is_owner_only(tmp_path: Path) -> None:
    store = CaseStore(tmp_path / "state")
    store.observe(results(BOTH))
    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "state" / FILE_NAME).stat().st_mode) == 0o600
    assert not (tmp_path / "state" / LOCK_NAME).exists()


def test_case_store_never_contains_evidence_content(tmp_path: Path) -> None:
    spec = {
        "findings": [
            finding("TST-AAA-001", "high", "users", "/etc/secret/path", excerpt="TOPSECRETEXCERPT")
        ]
    }
    CaseStore(tmp_path).observe(results(spec))
    text = (tmp_path / FILE_NAME).read_text("utf-8")
    assert "TOPSECRETEXCERPT" not in text and "/etc/secret/path" not in text


def test_investigation_state_is_separate_from_the_assessment_and_the_results(
    tmp_path: Path,
) -> None:
    current = doc(BOTH)
    snapshot = json.dumps(current, sort_keys=True)
    res = detect(current, rule_set(make_rule()), generated_at=STAMP)
    before = json.dumps(res, sort_keys=True)
    store = CaseStore(tmp_path)
    det = store.observe(res)["new"][0]
    store.set_status(det, "dismissed", "reason")
    assert (
        json.dumps(current, sort_keys=True) == snapshot
        and json.dumps(res, sort_keys=True) == before
    )
    assert "status" not in res["detections"][0]


def test_related_detections_share_contributing_items_or_evidence() -> None:
    shared = make_rule(
        id="DR-TST-SHR-001",
        title="Shared {a.title}",
        clauses=[
            {
                "id": "a",
                "source": "findings",
                "description": "d",
                "where": {"field": "check_id", "op": "eq", "value": "TST-AAA-001"},
            }
        ],
    )
    other = make_rule(
        id="DR-TST-OTH-001",
        title="Other {a.title}",
        clauses=[
            {
                "id": "a",
                "source": "findings",
                "description": "d",
                "where": {"field": "severity_rank", "op": "gte", "value": 2},
            }
        ],
    )
    lone = make_rule(
        id="DR-TST-LON-001",
        title="Lone {a.title}",
        clauses=[
            {
                "id": "a",
                "source": "findings",
                "description": "d",
                "where": {"field": "check_id", "op": "eq", "value": "TST-BBB-001"},
            }
        ],
    )
    res = detect(
        doc(
            {
                "findings": [
                    finding("TST-AAA-001", "high", "users", "/x/y"),
                    finding("TST-BBB-001", "low"),
                ]
            }
        ),
        rule_set(shared, other, lone),
        generated_at=STAMP,
    )
    rel = compute_related(res)
    by_rule = {d["rule"]["id"]: d["id"] for d in res["detections"]}
    assert rel[by_rule["DR-TST-SHR-001"]] == [by_rule["DR-TST-OTH-001"]]
    assert rel[by_rule["DR-TST-OTH-001"]] == [by_rule["DR-TST-SHR-001"]]
    assert rel[by_rule["DR-TST-LON-001"]] == []


def test_summaries_for_untracked_detections_default_to_new() -> None:
    res = results(BOTH)
    s = case_summaries(None, res)
    assert {v["status"] for v in s.values()} == {"new"} and not any(
        v["tracked"] for v in s.values()
    )
