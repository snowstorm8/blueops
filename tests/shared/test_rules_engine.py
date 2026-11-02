"""Rule evaluation and correlation: matching, joins, severity, coverage, traceability, bounds."""

from __future__ import annotations

import copy
import json
import random
import time
from typing import Any

import pytest
from rules_support import STAMP, doc, finding, history, make_rule, record, rule_set, where

from shared.reporting.schema_lite import validate
from shared.rules import engine as eng
from shared.rules.engine import detect, exit_code_for


def cl(cid: str, where_: dict[str, Any], source: str = "findings", **kw: Any) -> dict[str, Any]:
    return {"id": cid, "source": source, "description": f"clause {cid}", "where": where_, **kw}


def chk(check: str) -> dict[str, Any]:
    return where("check_id", "eq", check)


def run(
    spec: dict[str, Any],
    *rules: dict[str, Any],
    prev: list[Any] | None = None,
    platform: str = "linux",
) -> dict[str, Any]:
    out = detect(doc(spec, platform=platform), rule_set(*rules), previous=prev, generated_at=STAMP)
    assert validate(out, "detection-results.schema.json") == [], validate(
        out, "detection-results.schema.json"
    )
    return out


TWO = make_rule(
    id="DR-TST-TWO-001",
    nature="correlated",
    title="Both on {host}",
    clauses=[cl("a", chk("TST-AAA-001")), cl("b", chk("TST-BBB-001"))],
)
F_A, F_B = finding("TST-AAA-001", "low"), finding("TST-BBB-001", "low")


def test_single_clause_rule_matches_and_explains() -> None:
    out = run(
        {"findings": [finding("TST-AAA-001", "high", "users", "/etc/x", excerpt="seen")]},
        make_rule(),
    )
    (d,) = out["detections"]
    assert (
        d["rule"]["id"] == "DR-TST-RULE-001"
        and d["nature"] == "indicator"
        and d["severity"] == "medium"
    )
    assert d["title"].startswith("Test rule matched")
    assert d["matched_conditions"][0]["conditions"] == ["check_id eq 'TST-AAA-001'"]
    assert d["explanation"]["disclaimer"] and d["explanation"]["severity_rationale"].startswith(
        "Severity medium is the rule's base severity"
    )
    assert d["investigation_steps"] and d["remediation"]
    assert out["summary"]["total"] == 1 and out["rules"]["evaluated"] == 1


def test_no_match_gives_no_detection_and_no_indeterminate() -> None:
    out = run({"findings": [finding("TST-ZZZ-001")]}, make_rule())
    assert out["detections"] == [] and out["indeterminate"] == []


def test_correlation_requires_every_required_clause() -> None:
    assert len(run({"findings": [F_A, F_B]}, TWO)["detections"]) == 1
    assert run({"findings": [F_A]}, TWO)["detections"] == []
    assert run({"findings": [F_B]}, TWO)["detections"] == []


def test_correlation_lists_every_contributor_and_says_why() -> None:
    (d,) = run({"findings": [F_A, F_B, finding("TST-ZZZ-001")]}, TWO)["detections"]
    assert {c["check_id"] for c in d["contributing"]} == {"TST-AAA-001", "TST-BBB-001"}
    assert {c["clause"] for c in d["contributing"]} == {"a", "b"}
    assert "a (1 item(s)), b (1 item(s))" in d["explanation"]["why_correlated"]
    assert d["nature"] == "correlated"


def test_severity_is_not_raised_by_the_number_of_matches() -> None:
    one = run({"findings": [F_A, F_B]}, TWO)["detections"][0]
    assert one["severity"] == "medium"
    # many distinct matching items for one clause leave severity untouched
    inv_rule = make_rule(
        id="DR-TST-INV-001",
        title="{a.key}",
        clauses=[cl("a", where("domain", "eq", "users"), "inventory")],
    )
    out = run(
        {"inventory": [record("users", f"user:u{i}", {"uid": str(i)}) for i in range(40)]}, inv_rule
    )
    assert {d["severity"] for d in out["detections"]} == {"medium"}
    (merged,) = out["detections"]  # without a join all 40 records are one detection
    assert len(merged["contributing"]) == 40 and merged["severity"] == "medium"


def test_explicit_severity_and_confidence_rules() -> None:
    rule = make_rule(
        id="DR-TST-SEV-001",
        nature="correlated",
        clauses=[
            cl("a", chk("TST-AAA-001")),
            cl("b", chk("TST-BBB-001")),
            cl("c", chk("TST-CCC-001"), optional=True),
        ],
        require={"all": ["a", "b"]},
        severity_rules=[
            {"when": "c", "value": "high", "reason": "the optional corroboration was seen"}
        ],
        confidence_rules=[{"when": "c", "value": "high", "reason": "corroborated by clause c"}],
        title="xxx",
    )
    plain = run({"findings": [F_A, F_B]}, rule)["detections"][0]
    boosted = run({"findings": [F_A, F_B, finding("TST-CCC-001")]}, rule)["detections"][0]
    assert (plain["severity"], plain["confidence"]) == ("medium", "medium")
    assert (boosted["severity"], boosted["confidence"]) == ("high", "high")
    assert (
        "explicit rule condition: the optional corroboration was seen"
        in boosted["explanation"]["severity_rationale"]
    )
    assert "corroborated by clause c" in boosted["explanation"]["confidence_rationale"]
    assert any(
        "Optional corroboration not observed: clause c" in m
        for m in plain["explanation"]["missing_corroboration"]
    )
    assert not any("clause c" in m for m in boosted["explanation"]["missing_corroboration"])


def test_require_expressions_any_not() -> None:
    rule = make_rule(
        id="DR-TST-EXP-001",
        nature="correlated",
        requires_coverage=["module:users"],
        clauses=[
            cl("a", chk("TST-AAA-001")),
            cl("b", chk("TST-BBB-001")),
            cl("c", chk("TST-CCC-001")),
        ],
        require={"all": [{"any": ["a", "b"]}, {"not": "c"}]},
        title="xxx",
    )
    ok = {"modules": {"users": "ok"}}
    assert len(run({"findings": [F_A], **ok}, rule)["detections"]) == 1
    assert len(run({"findings": [F_B], **ok}, rule)["detections"]) == 1
    assert run({"findings": [F_A, finding("TST-CCC-001")], **ok}, rule)["detections"] == []
    assert run({"findings": [], **ok}, rule)["detections"] == []


def test_min_matches_and_distinct() -> None:
    rule = make_rule(
        id="DR-TST-MIN-001",
        nature="correlated",
        title="xxx",
        clauses=[
            cl("a", where("category", "eq", "users"), distinct={"field": "check_id", "count": 3})
        ],
    )
    three = [finding(f"TST-A{c}A-001", "low") for c in "123"]
    assert len(run({"findings": three}, rule)["detections"]) == 1
    assert run({"findings": three[:2]}, rule)["detections"] == []
    assert (
        run({"findings": [finding("TST-ONE-001")] * 1 + [finding("TST-TWO-001")]}, rule)[
            "detections"
        ]
        == []
    )
    mm = make_rule(
        id="DR-TST-MM-001",
        title="xxx",
        clauses=[cl("a", where("domain", "eq", "users"), "inventory", min_matches=2)],
    )
    one = {"inventory": [record("users", "user:a")]}
    two = {"inventory": [record("users", "user:a"), record("users", "user:b")]}
    assert run(one, mm)["detections"] == []
    assert len(run(two, mm)["detections"]) == 1


def test_join_groups_items_that_share_a_value() -> None:
    rule = make_rule(
        id="DR-TST-JOIN-001",
        nature="correlated",
        title="Shared {a.evidence.paths}",
        join={"on": "evidence.paths"},
        clauses=[cl("a", chk("TST-AAA-001")), cl("b", chk("TST-BBB-001"))],
    )
    same = {
        "findings": [
            finding("TST-AAA-001", "low", "users", "/srv/app/run"),
            finding("TST-BBB-001", "low", "users", "/srv/app/run"),
        ]
    }
    other = {
        "findings": [
            finding("TST-AAA-001", "low", "users", "/srv/app/run"),
            finding("TST-BBB-001", "low", "users", "/srv/other/run"),
        ]
    }
    (d,) = run(same, rule)["detections"]
    assert "share evidence.paths = '/srv/app/run'" in d["explanation"]["why_correlated"]
    assert run(other, rule)["detections"] == []
    # two independent pairs on two paths give two detections with different ids
    f = [
        finding("TST-AAA-001", "low", "users", "/srv/a/x", "/srv/b/y"),
        finding("TST-BBB-001", "low", "users", "/srv/a/x", "/srv/b/y"),
    ]
    assert (
        len(run({"findings": f}, rule)["detections"]) == 1
    )  # identical item sets collapse into one group
    case = {
        "findings": [
            finding("TST-AAA-001", "low", "users", "/Srv/App/Run"),
            finding("TST-BBB-001", "low", "users", "/srv/app/run"),
        ]
    }
    assert len(run(case, rule)["detections"]) == 1  # casefold mode by default


def test_join_mode_equal_is_case_sensitive() -> None:
    rule = make_rule(
        id="DR-TST-JEQ-001",
        nature="correlated",
        title="xxx",
        join={"on": "evidence.paths", "mode": "equal"},
        clauses=[cl("a", chk("TST-AAA-001")), cl("b", chk("TST-BBB-001"))],
    )
    case = {
        "findings": [
            finding("TST-AAA-001", "low", "users", "/Srv/App/Run"),
            finding("TST-BBB-001", "low", "users", "/srv/app/run"),
        ]
    }
    assert run(case, rule)["detections"] == []


def test_per_item_grouping_makes_one_detection_per_item() -> None:
    rule = make_rule(
        id="DR-TST-PER-001",
        title="{a.key}",
        join={"on": "key"},
        clauses=[cl("a", where("domain", "eq", "users"), "inventory")],
    )
    out = run({"inventory": [record("users", f"user:u{i}") for i in range(3)]}, rule)
    assert len(out["detections"]) == 3 and len({d["id"] for d in out["detections"]}) == 3
    assert sorted(d["title"] for d in out["detections"]) == ["user:u0", "user:u1", "user:u2"]


# ------------------------------------------------------------------------------- coverage


def test_unmatched_rule_with_missing_module_is_indeterminate_not_clean() -> None:
    rule = make_rule(requires_coverage=["module:users"])
    out = run(
        {"findings": [finding("TST-ZZZ-001", "low", "network")], "modules": {"network": "ok"}}, rule
    )
    assert out["detections"] == [] and [i["rule"]["id"] for i in out["indeterminate"]] == [
        "DR-TST-RULE-001"
    ]
    assert "module users was not run" in out["indeterminate"][0]["reason"]
    assert out["rules"]["indeterminate"] == 1 and exit_code_for(out).name == "PARTIAL"


def test_failed_module_makes_unmatched_rule_indeterminate() -> None:
    rule = make_rule(requires_coverage=["module:users"])
    out = run(
        {
            "findings": [finding("TST-ZZZ-001", "low", "network")],
            "modules": {"users": "timeout", "network": "ok"},
        },
        rule,
    )
    assert out["indeterminate"] and "finished as timeout" in out["indeterminate"][0]["reason"]


def test_positive_observation_stands_despite_a_partial_module_but_confidence_drops() -> None:
    rule = make_rule(requires_coverage=["module:users"])
    out = run(
        {"findings": [finding("TST-AAA-001", "low", "users")], "modules": {"users": "partial"}},
        rule,
    )
    (d,) = out["detections"]
    assert d["confidence"] == "low"  # medium base, lowered one step
    assert any("Coverage incomplete" in c for c in d["explanation"]["caveats"])
    assert any("lowered one step" in c for c in d["explanation"]["caveats"])


def test_absence_based_rules_do_not_conclude_from_incomplete_coverage() -> None:
    rule = make_rule(
        id="DR-TST-ABS-001",
        nature="correlated",
        title="xxx",
        requires_coverage=["module:users"],
        clauses=[cl("a", chk("TST-AAA-001")), cl("b", chk("TST-BBB-001"))],
        require={"all": ["a", {"not": "b"}]},
    )
    ok = run({"findings": [F_A], "modules": {"users": "ok"}}, rule)
    assert len(ok["detections"]) == 1
    part = run({"findings": [F_A], "modules": {"users": "partial"}}, rule)
    assert (
        part["detections"] == []
        and "absence cannot be concluded" in part["indeterminate"][0]["reason"]
    )


def test_inventory_coverage_requirement() -> None:
    rule = make_rule(requires_coverage=["inventory:users"])
    spec = {
        "findings": [finding("TST-ZZZ-001")],
        "coverage": [{"domain": "users", "status": "partial", "reason": "x"}],
    }
    assert run(spec, rule)["indeterminate"]
    spec["coverage"] = [{"domain": "users", "status": "degraded"}]
    out = run(spec, rule)
    assert out["detections"] == [] and out["indeterminate"] == []
    spec["coverage"] = [{"domain": "config", "status": "complete"}]
    assert run(spec, rule)["indeterminate"]


def test_platform_and_enablement() -> None:
    win = make_rule(id="DR-TST-WIN-001", platforms=["windows"])
    out = run({"findings": [F_A]}, win, platform="linux")
    assert out["rules"]["not_applicable"] == 1 and out["detections"] == []
    assert len(run({"findings": [F_A]}, win, platform="windows")["detections"]) == 1
    off = make_rule(id="DR-TST-OFF-001", enabled=False)
    out = run({"findings": [F_A]}, off)
    assert out["rules"]["disabled"] == 1 and out["detections"] == []
    assert out["rule_results"] == [
        {"rule": "DR-TST-OFF-001", "status": "disabled", "detections": 0}
    ]


# ---------------------------------------------------------------------------- snapshots


NEW_RULE = make_rule(
    id="DR-TST-NEW-001",
    title="New {a.title}",
    requires_coverage=["comparison"],
    clauses=[cl("a", where("severity_rank", "gte", 2), "new_findings")],
)


def test_snapshot_rules_are_indeterminate_without_a_previous_snapshot() -> None:
    out = run({"findings": [F_A]}, NEW_RULE)
    assert out["detections"] == [] and "no earlier snapshot" in out["indeterminate"][0]["reason"]
    assert out["history"] == {
        "snapshots": 0,
        "compared_with": None,
        "comparison_trend": None,
        "excluded": [],
    }


def test_new_findings_are_detected_against_the_previous_snapshot() -> None:
    prev = history({"findings": [finding("TST-OLD-001", "low")]})
    out = run(
        {"findings": [finding("TST-OLD-001", "low"), finding("TST-AAA-001", "high")]},
        NEW_RULE,
        prev=prev,
    )
    (d,) = out["detections"]
    assert d["contributing"][0]["check_id"] == "TST-AAA-001"
    assert out["history"]["compared_with"] == "prev-0" and out["history"]["snapshots"] == 1


def test_comparison_incomplete_coverage_is_indeterminate_when_nothing_matches() -> None:
    prev = history(
        {"findings": [finding("TST-OLD-001", "low", "network")], "modules": {"network": "failed"}}
    )
    out = run(
        {"findings": [finding("TST-ZZZ-001", "low", "network")], "modules": {"network": "ok"}},
        NEW_RULE,
        prev=prev,
    )
    assert out["detections"] == [] and out["indeterminate"]


def test_failed_comparison_is_explained_not_hidden() -> None:
    prev = history({"findings": [F_A]}, host="otherhost")
    out = run({"findings": [F_A]}, NEW_RULE, prev=prev)
    assert out["indeterminate"] and "comparison failed" in out["indeterminate"][0]["reason"]


def test_history_fields_drive_rules() -> None:
    rule = make_rule(
        id="DR-TST-HIS-001",
        title="Back {a.title}",
        requires_coverage=["history:2"],
        clauses=[cl("a", where("history.reappeared", "is_true"))],
    )
    ok = {"modules": {"users": "ok"}}
    prev = history({"findings": [F_A], **ok}, {"findings": [finding("TST-ZZZ-001", "low")], **ok})
    (d,) = run({"findings": [F_A], **ok}, rule, prev=prev)["detections"]
    assert d["contributing"][0]["check_id"] == "TST-AAA-001"
    assert (
        run(
            {"findings": [F_A], **ok},
            rule,
            prev=history({"findings": [F_A], **ok}, {"findings": [F_A], **ok}),
        )["detections"]
        == []
    )
    assert run({"findings": [F_A], **ok}, rule, prev=history({"findings": [F_A], **ok}))[
        "indeterminate"
    ]


# ------------------------------------------------------------------- engine guarantees


def test_a_rule_that_crashes_is_recorded_and_others_still_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good, boom = make_rule(id="DR-TST-OKK-001"), make_rule(id="DR-TST-BOOM-001")
    real = eng.evaluate_rule

    def flaky(rule: Any, ctx: Any, stamp: str) -> Any:
        if rule.id == "DR-TST-BOOM-001":
            raise RuntimeError("synthetic failure")
        return real(rule, ctx, stamp)

    monkeypatch.setattr(eng, "evaluate_rule", flaky)
    out = run({"findings": [F_A]}, good, boom)
    assert [d["rule"]["id"] for d in out["detections"]] == ["DR-TST-OKK-001"]
    assert out["rule_errors"] == [
        {
            "rule": "DR-TST-BOOM-001",
            "code": "RULE_FAILED",
            "message": "RuntimeError: synthetic failure",
        }
    ]
    assert out["rules"]["error"] == 1 and exit_code_for(out, "critical").name == "PARTIAL"


def test_invalid_rules_in_the_set_are_reported_as_rule_errors() -> None:
    from shared.rules.loader import RuleSet
    from shared.rules.validate import Diagnostic

    rs = RuleSet(diagnostics=[Diagnostic("error", "rules[0].severity", "bad", "DR-TST-BAD-001")])
    out = detect(doc({"findings": [F_A]}), rs, generated_at=STAMP)
    assert out["rule_errors"][0]["code"] == "RULE_INVALID" and exit_code_for(out).name == "PARTIAL"


def test_exit_codes() -> None:
    hit = run({"findings": [F_A]}, make_rule(severity="high"))
    assert exit_code_for(hit, "medium").name == "FINDINGS"
    assert exit_code_for(hit, "critical").name == "OK"
    assert exit_code_for(run({"findings": []}, make_rule())).name == "OK"


def test_results_are_deterministic_and_independent_of_input_order() -> None:
    findings = [finding(f"TST-A{c}A-001", "low") for c in "123456"] + [F_A, F_B]
    a = run({"findings": findings}, TWO, make_rule())
    shuffled = copy.deepcopy(findings)
    random.Random(7).shuffle(shuffled)
    b = run({"findings": shuffled}, TWO, make_rule())
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert json.dumps(a, sort_keys=True) == json.dumps(
        run({"findings": findings}, TWO, make_rule()), sort_keys=True
    )


def test_detection_ids_are_stable_and_host_specific() -> None:
    one = run({"findings": [F_A]}, make_rule())["detections"][0]["id"]
    assert one == run({"findings": [F_A]}, make_rule())["detections"][0]["id"]
    other = detect(
        doc({"findings": [F_A]}, host="host02"), rule_set(make_rule()), generated_at=STAMP
    )["detections"][0]["id"]
    assert one != other
    # severity or wording changes do not change identity; a different contributing finding does
    changed = run(
        {"findings": [finding("TST-AAA-001", "critical", "users", "/etc/new")]}, make_rule()
    )["detections"][0]["id"]
    assert changed == one


def test_everything_a_detection_cites_exists_in_the_assessment() -> None:
    current = doc(
        {
            "findings": [finding("TST-AAA-001", "high", "users", "/srv/a/x", excerpt="e"), F_B],
            "inventory": [record("users", "user:a")],
        }
    )
    rule = make_rule(
        id="DR-TST-TRC-001",
        nature="correlated",
        title="xxx",
        clauses=[cl("a", chk("TST-AAA-001")), cl("u", where("domain", "eq", "users"), "inventory")],
    )
    out = detect(current, rule_set(rule), generated_at=STAMP)
    (d,) = out["detections"]
    finding_ids = {f["id"] for f in current["findings"]}
    evidence_ids = {e["id"] for e in current["evidence"]}
    keys = {(r["domain"], r.get("scope", ""), r["key"]) for r in current["inventory"]["records"]}
    for c in d["contributing"]:
        if c["type"] == "finding":
            assert c["id"] in finding_ids
        else:
            assert (c["domain"], c["scope"], c["key"]) in keys
    assert d["evidence"] and set(d["evidence"]) <= evidence_ids


def test_hostile_values_are_sanitised_in_titles_and_labels() -> None:
    evil = "bad\x1b[31m\x00name"
    f = {**finding("TST-AAA-001", "high"), "title": evil}
    (d,) = run({"findings": [f]}, make_rule())["detections"]
    assert "\x1b" not in d["title"] and "\x00" not in d["title"]
    assert all("\x1b" not in c["label"] for c in d["contributing"])


def test_template_with_missing_value_does_not_crash() -> None:
    rule = make_rule(
        title="Missing {a.evidence.refs} and {a.history.first_seen}", requires_coverage=[]
    )
    (d,) = run({"findings": [F_A]}, rule)["detections"]
    assert "(missing)" in d["title"]


def test_bounds_on_matches_and_detections(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(eng, "MAX_ITEMS_PER_CLAUSE", 10)
    monkeypatch.setattr(eng, "MAX_LISTED_PER_CLAUSE", 4)
    rule = make_rule(
        id="DR-TST-BIG-001",
        title="xxx",
        clauses=[cl("a", where("domain", "eq", "users"), "inventory")],
    )
    (d,) = run({"inventory": [record("users", f"user:u{i}") for i in range(50)]}, rule)[
        "detections"
    ]
    assert len(d["contributing"]) == 4
    assert any("matched more than 10 items" in c for c in d["explanation"]["caveats"])
    monkeypatch.setattr(eng, "MAX_DETECTIONS_PER_RULE", 3)
    per = make_rule(
        id="DR-TST-CAP-001",
        title="{a.key}",
        join={"on": "key"},
        clauses=[cl("a", where("domain", "eq", "users"), "inventory")],
    )
    out = run({"inventory": [record("users", f"user:u{i}") for i in range(8)]}, per)
    assert len(out["detections"]) == 3 and any(
        "more than 3 detections" in c for c in out["detections"][0]["explanation"]["caveats"]
    )


def test_scales_to_many_findings_and_rules() -> None:
    findings = [
        finding(f"TST-A{i % 900:03d}-001", "low", "users", f"/srv/p{i}/x") for i in range(3000)
    ]
    rules = [
        make_rule(
            id=f"DR-TST-N{i:03d}-001", clauses=[cl("a", chk(f"TST-A{i:03d}-001"))], title="xxx"
        )
        for i in range(100)
    ]
    current = doc({"findings": findings})
    t0 = time.monotonic()
    out = detect(current, rule_set(*rules), generated_at=STAMP)
    assert time.monotonic() - t0 < 10
    assert out["rules"]["evaluated"] == 100 and len(out["detections"]) == 100
