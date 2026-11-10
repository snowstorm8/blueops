"""The shipped scenario library: integrity, coverage of the rules, and what it does and does not prove."""

from __future__ import annotations

import collections

import pytest

from shared.reporting.schema_lite import validate
from shared.validation.calibrate import recommend
from shared.validation.model import check_against_rules, load_scenarios
from shared.validation.runner import run_scenarios, telemetry_rule_set

SS = load_scenarios()
RULES = telemetry_rule_set()
RESULTS = run_scenarios(SS.ordered(), SS, RULES, recommend=recommend)
KNOWN = {"SCN-LNX-PRC-004": "DR-ANY-HPRC-001", "SCN-LNX-PRC-006": "DR-ANY-HPRC-002"}


def test_the_library_loads_without_diagnostics_and_names_only_real_rules():
    assert SS.diagnostics == [] and len(SS.scenarios) >= 80
    assert check_against_rules(SS, set(RULES.rules)) == []


def test_both_platforms_and_all_three_kinds_are_represented_with_unique_ids():
    kinds = collections.Counter(s.kind for s in SS.ordered())
    plats = collections.Counter(p for s in SS.ordered() for p in s.platforms)
    assert set(kinds) == {"positive", "negative", "coverage"} and min(kinds.values()) >= 8
    assert (
        plats["linux"] >= 30 and plats["windows"] >= 25 and len(SS.scenarios) == sum(kinds.values())
    )


def test_every_hunting_rule_has_an_evaluated_positive_and_negative_scenario():
    cov = RESULTS["coverage"]
    assert cov["without_positive_evaluation"] == [] and cov["without_negative_evaluation"] == []
    assert cov["coverage"]["value"] == 1.0 and cov["rules_in_scope"] == len(RULES.rules) == 24


def test_the_requested_topics_are_covered():
    tags = {t for s in SS.ordered() for t in s.tags}
    assert {
        "process",
        "relationship",
        "executable",
        "persistence",
        "service",
        "scheduled-task",
        "configuration",
        "authentication",
        "network",
        "integrity",
        "coverage",
        "permissions",
        "benign",
        "admin",
        "change",
        "gap",
    } <= tags


def test_some_scenarios_verify_incomplete_coverage_instead_of_a_detection():
    cov = [s for s in RESULTS["scenarios"] if s["kind"] == "coverage"]
    assert len(cov) >= 8
    assert any(o["outcome"] == "expected_inconclusive" for s in cov for o in s["outcomes"])


def test_every_scenario_passes_except_the_documented_known_issues():
    by_id = {s["id"]: s for s in RESULTS["scenarios"]}
    bad = {i: s["status"] for i, s in by_id.items() if s["status"] not in ("pass", "known_issue")}
    assert bad == {}, bad
    assert {i for i, s in by_id.items() if s["status"] == "known_issue"} == set(KNOWN)
    for sid, rule in KNOWN.items():
        assert any(
            o["rule"] == rule and o["outcome"] == "false_positive" for o in by_id[sid]["outcomes"]
        )


def test_known_issues_still_count_in_the_metrics_they_are_not_hidden():
    rule = RESULTS["metrics"]["by_rule"]["DR-ANY-HPRC-001"]
    assert rule["counts"]["false_positive"] == 1 and rule["precision"]["value"] < 1.0
    assert any(f["scenario"] == "SCN-LNX-PRC-004" and f["known"] for f in RESULTS["failures"])


def test_a_known_issue_that_stops_reproducing_fails_the_run():
    s = SS.scenarios["SCN-LNX-PRC-004"]
    fixed = RULES.only(lambda r: r.id != "DR-ANY-HPRC-001")  # rule gone: simulate it going quiet
    from shared.validation.evaluate import evaluate_scenario

    res = evaluate_scenario(s, fixed)
    assert res["status"] != "pass"  # not evaluated, so not silently green
    quiet = type(s)(
        **{
            **s.__dict__,
            "dataset": {
                "platform": "linux",
                "records": [
                    {"category": "process", "key": "p", "attributes": {"pid": 1, "name": "init"}}
                ],
            },
        }
    )
    res = evaluate_scenario(quiet, RULES)
    assert res["status"] == "fail" and "no longer reproduces" in res["reason"]


def test_results_validate_and_state_what_they_do_not_prove():
    assert validate(RESULTS, "validation-results.schema.json") == []
    s = RESULTS["summary"]
    assert (
        s["synthetic_only"] is True
        and "not a measurement of detection accuracy on real endpoints" in s["disclaimer"]
    )
    assert RESULTS["run"]["mode"] == "synthetic" and RESULTS["run"]["dry_run"] is False


def test_the_run_is_deterministic():
    again = run_scenarios(SS.ordered(), SS, RULES)
    assert again["reproducibility"]["digest"] == RESULTS["reproducibility"]["digest"]
    assert again["scenarios"] == RESULTS["scenarios"] and again["metrics"] == RESULTS["metrics"]


def test_reproducibility_metadata_identifies_rules_scenarios_and_versions():
    r = RESULTS["reproducibility"]
    assert len(r["rules"]) == 24 and all(
        len(x["sha256"]) == 64 and x["version"] for x in r["rules"]
    )
    assert {p["name"] for p in r["scenario_packs"]} == {"linux-lab", "windows-lab"}
    assert r["versions"]["validation_schema"] == "1.0.0" and r["versions"]["python"]
    assert "hostname" not in str(RESULTS["run"]["host"]).lower()


def test_recommendations_are_evidence_backed_and_never_applied():
    recs = RESULTS["recommendations"]
    assert recs and all(
        r["applied"] is False and r["tradeoffs"] and r["evidence"] is not None for r in recs
    )
    fp = next(
        r for r in recs if r["rule"] == "DR-ANY-HPRC-001" and r["kind"] == "reduce_false_positives"
    )
    assert "SCN-LNX-PRC-004" in fp["supporting_scenarios"] and "SCN-LNX-PRC-001" in " ".join(
        fp["tradeoffs"]
    )
    assert any("also satisfied in the true positives" in e for e in fp["evidence"]), (
        "the benign case satisfies the same conditions as the malicious one"
    )
    assert fp["priority"] == "medium", "documented known issues are lower priority than new ones"


def test_the_library_detects_a_deliberately_broken_rule():
    """Mutation check: if a rule is made to match everything, the library must notice."""
    import copy

    from shared.rules.conditions import compile_condition
    from shared.rules.model import Rule

    rule = RULES.rules["DR-ANY-HPRC-002"]
    broken_clause = copy.copy(rule.clauses[0])
    object.__setattr__(
        broken_clause,
        "where",
        compile_condition({"field": "category", "op": "eq", "value": "process"}),
    )
    broken = Rule(**{**rule.__dict__, "clauses": (broken_clause,)})
    mutated = RULES.only(lambda r: True)
    mutated.rules["DR-ANY-HPRC-002"] = broken
    res = run_scenarios(SS.ordered(), SS, mutated)
    fp = [
        s["id"]
        for s in res["scenarios"]
        if any(
            o["rule"] == "DR-ANY-HPRC-002" and o["outcome"] == "false_positive"
            for o in s["outcomes"]
        )
    ]
    assert len(fp) >= 5, fp
    assert (
        res["metrics"]["by_rule"]["DR-ANY-HPRC-002"]["precision"]["value"]
        < RESULTS["metrics"]["by_rule"]["DR-ANY-HPRC-002"]["precision"]["value"]
    )
    assert res["summary"]["exit_status"] == "failures"


@pytest.mark.parametrize("sid", sorted(KNOWN))
def test_known_issue_scenarios_name_the_limitation_in_plain_words(sid):
    assert any("KNOWN ISSUE" in lim for lim in SS.scenarios[sid].limitations)
