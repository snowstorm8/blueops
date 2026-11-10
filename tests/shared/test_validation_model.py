"""Scenario schema validation, semantic checks and loading."""

from __future__ import annotations

import json

import pytest
from validation_support import pack, scn, write_pack

from shared.validation.model import (
    SCENARIO_DIR,
    check_against_rules,
    load_pack_file,
    load_scenarios,
)


def load_one(tmp_path, scenario):
    path = write_pack(tmp_path, [scenario])
    return load_pack_file(path)


def errors(tmp_path, scenario):
    scenarios, diags, _ = load_one(tmp_path, scenario)
    return scenarios, [str(d) for d in diags if d.level == "error"]


def test_a_valid_scenario_loads_with_hash_and_rules_under_test(tmp_path):
    scenarios, diags, info = load_one(tmp_path, scn())
    assert diags == [] and len(scenarios) == 1
    s = scenarios[0]
    assert (
        s.rules_under_test == ("DR-ANY-HPRC-001",)
        and len(s.sha256) == 64
        and s.dataset_platform == "linux"
    )
    assert info["scenarios"] == 1 and len(info["sha256"]) == 64


def test_hash_changes_when_the_scenario_changes_and_not_otherwise(tmp_path):
    a = load_one(tmp_path, scn())[0][0].sha256
    assert a == load_one(tmp_path, scn())[0][0].sha256
    assert a != load_one(tmp_path, scn(title="Another title"))[0][0].sha256


@pytest.mark.parametrize(
    "mutation",
    [
        {"id": "bad-id"},
        {"id": "SCN-LNX-PRC-1"},
        {"kind": "maybe"},
        {"platforms": []},
        {"platforms": ["macos"]},
        {"title": None},
        {"expect": None},
        {"limitations": []},
        {"surprise": True},
        {"dataset": {"platform": "linux", "records": [], "bogus": 1}},
        {"expect": {"detections": [{"rule": "not-a-rule"}]}},
        {"expect": {"detections": [{"rule": "DR-ANY-HPRC-001", "severity": {"min": "extreme"}}]}},
        {"lab": {"actions": [{"action": "rm_rf"}]}},
        {"lab": {"actions": [{"action": "spawn_sleeper", "seconds": 100000}]}},
    ],
)
def test_schema_violations_exclude_the_whole_pack_with_a_reason(tmp_path, mutation):
    scenarios, diags, _ = load_one(tmp_path, scn(**mutation))
    assert scenarios == [] and diags and all(d.level == "error" for d in diags)


@pytest.mark.parametrize(
    ("mutation", "needle"),
    [
        ({"id": "SCN-WIN-PRC-001"}, "disagree"),
        ({"id": "SCN-ANY-PRC-001"}, "ANY scenario must list both"),
        ({"dataset": {"platform": "windows", "records": []}}, "not among the scenario platforms"),
        ({"dataset": {"platform": "linux"}}, "needs 'records'"),
        ({"expect": {"detections": []}}, "at least one detection"),
        ({"kind": "negative"}, "list absent rules"),
        (
            {
                "kind": "negative",
                "expect": {
                    "absent": ["DR-ANY-HPRC-001"],
                    "detections": [{"rule": "DR-ANY-HPRC-002"}],
                },
            },
            "cannot expect detections",
        ),
        (
            {"kind": "coverage", "expect": {"absent": ["DR-ANY-HPRC-001"]}},
            "coverage scenario must state",
        ),
        (
            {
                "expect": {
                    "detections": [{"rule": "DR-ANY-HPRC-001"}],
                    "absent": ["DR-ANY-HPRC-001"],
                }
            },
            "both expected and absent",
        ),
        (
            {
                "expect": {
                    "detections": [{"rule": "DR-ANY-HPRC-001"}],
                    "indeterminate": [{"rule": "DR-ANY-HPRC-001"}],
                }
            },
            "both asserted and expected indeterminate",
        ),
        (
            {
                "expect": {
                    "detections": [
                        {"rule": "DR-ANY-HPRC-001", "severity": {"min": "high", "max": "low"}}
                    ]
                }
            },
            "severity min is above max",
        ),
        (
            {
                "expect": {
                    "detections": [
                        {"rule": "DR-ANY-HPRC-001", "confidence": {"min": "high", "max": "low"}}
                    ]
                }
            },
            "confidence min is above max",
        ),
        (
            {
                "expect": {
                    "detections": [{"rule": "DR-ANY-HPRC-001", "count": {"min": 3, "max": 1}}]
                }
            },
            "count min is above max",
        ),
        (
            {
                "expect": {
                    "detections": [{"rule": "DR-ANY-HPRC-001"}],
                    "coverage": {"nonsense": "complete"},
                }
            },
            "unknown category",
        ),
        (
            {
                "expect": {
                    "detections": [{"rule": "DR-ANY-HPRC-001"}],
                    "telemetry": [{"category": "nonsense"}],
                }
            },
            "unknown category",
        ),
        (
            {
                "expect": {
                    "detections": [{"rule": "DR-ANY-HPRC-001"}],
                    "telemetry": [
                        {"category": "process", "where": {"field": "nope", "op": "eq", "value": 1}}
                    ],
                }
            },
            "unknown field",
        ),
        (
            {
                "expect": {
                    "detections": [{"rule": "DR-ANY-HPRC-001"}],
                    "telemetry": [
                        {
                            "category": "process",
                            "where": {"field": "attrs.name", "op": "eval", "value": "x"},
                        }
                    ],
                }
            },
            "operator",
        ),
        ({"lab": {}}, "needs actions or collect_categories"),
    ],
)
def test_semantic_errors_are_specific_and_exclude_only_that_scenario(tmp_path, mutation, needle):
    other = scn(id="SCN-LNX-PRC-002")
    path = write_pack(tmp_path, [scn(**mutation), other])
    scenarios, diags, _ = load_pack_file(path)
    assert [s.id for s in scenarios] == ["SCN-LNX-PRC-002"], "the valid scenario still loads"
    assert any(needle in str(d) for d in diags), [str(d) for d in diags]


def test_duplicate_ids_within_and_across_packs_are_refused(tmp_path):
    a = write_pack(tmp_path, [scn(), scn()], name="aa")
    _, diags, _ = load_pack_file(a)
    assert any("duplicate scenario id" in str(d) for d in diags)
    b = write_pack(tmp_path, [scn()], name="bb")
    c = write_pack(tmp_path, [scn()], name="cc")
    ss = load_scenarios([b, c], include_library=False)
    assert len(ss.scenarios) == 1 and any("already defined" in str(d) for d in ss.errors)


def test_unreadable_missing_and_malformed_inputs_are_diagnostics_not_crashes(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    dup = tmp_path / "dup.json"
    dup.write_text('{"a": 1, "a": 2}', encoding="utf-8")
    ss = load_scenarios([bad, dup, tmp_path / "missing.json"], include_library=False)
    assert ss.scenarios == {} and len(ss.errors) == 3


def test_select_filters(tmp_path):
    other = scn(
        id="SCN-WIN-PRC-001",
        platforms=["windows"],
        dataset={"platform": "windows", "records": []},
        kind="negative",
        expect={"absent": ["DR-ANY-HPRC-001"]},
        tags=["admin"],
    )
    ss = load_scenarios([write_pack(tmp_path, [scn(), other])], include_library=False)
    assert [s.id for s in ss.select(platform="windows")] == ["SCN-WIN-PRC-001"]
    assert [s.id for s in ss.select(kind="positive")] == ["SCN-LNX-PRC-001"]
    assert [s.id for s in ss.select(tag="admin")] == ["SCN-WIN-PRC-001"]
    assert [s.id for s in ss.select(ids=["SCN-LNX-PRC-001"])] == ["SCN-LNX-PRC-001"]


def test_unknown_rules_are_reported_so_a_typo_cannot_assert_about_nothing(tmp_path):
    ss = load_scenarios(
        [write_pack(tmp_path, [scn(expect={"detections": [{"rule": "DR-ANY-HPRC-999"}]})])],
        include_library=False,
    )
    diags = check_against_rules(ss, {"DR-ANY-HPRC-001"})
    assert len(diags) == 1 and "DR-ANY-HPRC-999" in str(diags[0])


def test_the_scenario_schema_accepts_what_the_pack_helper_builds():
    from shared.reporting.schema_lite import validate

    assert validate(pack([scn()]), "validation-scenario.schema.json") == []


def test_the_shipped_library_directory_exists():
    assert SCENARIO_DIR.is_dir()


def test_json_pack_files_are_utf8_and_strict(tmp_path):
    p = tmp_path / "x.json"
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps(pack([scn()])).encode())
    assert load_pack_file(p)[0], "a BOM from Windows PowerShell 5.1 must be tolerated"
