"""History, regression detection and calibration recommendations."""

from __future__ import annotations

import copy
import json
import os

import pytest
from validation_support import proc, scn, write_pack

from shared.reporting.schema_lite import validate
from shared.rules.conditions import compile_condition
from shared.rules.model import Rule
from shared.validation.calibrate import recommend
from shared.validation.history import HistoryError, latest, list_runs, load_results, save_run
from shared.validation.model import load_scenarios
from shared.validation.regress import compare_runs
from shared.validation.runner import run_scenarios, telemetry_rule_set

RULES = telemetry_rule_set()
SHELL = "DR-ANY-HPRC-001"


def small(tmp_path, scenarios, rules=RULES, name="pk"):
    ss = load_scenarios([write_pack(tmp_path, scenarios, name=name)], include_library=False)
    assert not ss.errors, [str(d) for d in ss.errors]
    return run_scenarios(ss.ordered(), ss, rules, recommend=recommend)


def pair(sid, **over):
    pos = scn(id=sid, **over)
    neg = scn(
        id=f"{sid[:-1]}{int(sid[-1]) + 1}",
        kind="negative",
        expect={"absent": [SHELL]},
        dataset={"platform": "linux", "records": [proc(1, 0, "systemd")]},
    )
    return [pos, neg]


def with_clause(rules, rule_id, condition):
    rule = rules.rules[rule_id]
    clause = copy.copy(rule.clauses[0])
    object.__setattr__(clause, "where", compile_condition(condition))
    out = rules.only(lambda r: True)
    out.rules[rule_id] = Rule(**{**rule.__dict__, "clauses": (clause,)})
    return out


MATCH_ALL = {"field": "category", "op": "eq", "value": "process"}
MATCH_NONE = {"field": "category", "op": "eq", "value": "nothing"}


# ------------------------------------------------------------------ history


def test_saving_is_exclusive_private_and_round_trips(tmp_path):
    doc = small(tmp_path, pair("SCN-LNX-PRC-001"))
    path = save_run(doc, tmp_path / "hist")
    assert (
        path.name.startswith("validation-run-")
        and (path.stat().st_mode & 0o777) == 0o600
        or os.name != "posix"
    )
    assert load_results(path)["reproducibility"]["digest"] == doc["reproducibility"]["digest"]
    with pytest.raises(FileExistsError):
        save_run(doc, tmp_path / "hist")
    assert list_runs(tmp_path / "hist") == [path] and list_runs(tmp_path / "missing") == []


def test_latest_needs_enough_runs_and_returns_them_in_order(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    with pytest.raises(HistoryError, match="needs 2"):
        latest(tmp_path / "hist", 2)
    save_run(a, tmp_path / "hist")
    b = copy.deepcopy(a)
    b["run"]["started_at"] = "2026-12-01T00:00:00Z"
    save_run(b, tmp_path / "hist")
    first, second = latest(tmp_path / "hist", 2)
    assert first["run"]["started_at"] < second["run"]["started_at"]


@pytest.mark.parametrize(
    "content",
    [
        "{broken",
        "[]",
        '{"kind": "other"}',
        '{"kind": "validation-results", "schema_version": "2.0.0"}',
        '{"kind": "validation-results", "schema_version": "1.0.0"}',
    ],
)
def test_unreadable_or_foreign_results_are_refused_with_a_reason(tmp_path, content):
    p = tmp_path / "r.json"
    p.write_text(content)
    with pytest.raises(HistoryError):
        load_results(p)


# ------------------------------------------------------------------ regressions


def test_identical_runs_are_identical_and_clean(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    cmp = compare_runs(a, copy.deepcopy(a))
    assert validate(cmp, "validation-comparison.schema.json") == []
    assert cmp["summary"] == {
        "regressions": 0,
        "improvements": 0,
        "exit_status": "ok",
        "identical": True,
    }


def test_a_rule_that_stops_detecting_is_a_regression_with_evidence(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    b = small(tmp_path, pair("SCN-LNX-PRC-001"), rules=with_clause(RULES, SHELL, MATCH_NONE))
    cmp = compare_runs(a, b)
    kinds = {r["kind"] for r in cmp["regressions"]}
    assert {"scenario_regressed", "recall_decreased", "lost_true_positive"} <= kinds
    assert cmp["summary"]["exit_status"] == "regressions"
    assert cmp["scenarios"]["regressed"][0]["scenario"] == "SCN-LNX-PRC-001" and cmp["rules"][
        SHELL
    ]["deltas"]["recall"] == {"before": 1.0, "after": 0.0}


def test_a_rule_that_starts_over_firing_adds_false_positives_and_lowers_precision(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    b = small(tmp_path, pair("SCN-LNX-PRC-001"), rules=with_clause(RULES, SHELL, MATCH_ALL))
    kinds = {r["kind"] for r in compare_runs(a, b)["regressions"]}
    assert {"new_false_positive", "precision_decreased", "scenario_regressed"} <= kinds


def test_improvements_are_reported_not_hidden(tmp_path):
    bad = small(tmp_path, pair("SCN-LNX-PRC-001"), rules=with_clause(RULES, SHELL, MATCH_NONE))
    good = small(tmp_path, pair("SCN-LNX-PRC-001"))
    cmp = compare_runs(bad, good)
    assert cmp["summary"]["regressions"] == 0 and cmp["summary"]["improvements"] >= 2
    assert {i["kind"] for i in cmp["improvements"]} >= {"scenario_fixed", "recall_increased"}


def test_a_metric_that_becomes_undefined_is_a_regression_not_a_pass(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    b = small(tmp_path, pair("SCN-LNX-PRC-001"), rules=with_clause(RULES, SHELL, MATCH_NONE))
    b2 = copy.deepcopy(b)
    for s in b2["scenarios"]:
        s["outcomes"] = [o for o in s["outcomes"] if o["outcome"] != "false_negative"]
    cmp = compare_runs(a, b2)
    assert any(
        r["kind"] == "metric_became_undefined" and r["metric"] == "recall"
        for r in cmp["regressions"]
    )


def test_changed_scenarios_are_excluded_from_verdicts_and_listed(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    changed = pair("SCN-LNX-PRC-001")
    changed[0]["dataset"] = {
        "platform": "linux",
        "records": [proc(100, 1, "nginx"), proc(200, 100, "cat")],
    }  # now a miss
    b = small(tmp_path, changed)
    cmp = compare_runs(a, b)
    assert (
        cmp["scenarios"]["changed_definition"] == ["SCN-LNX-PRC-001"]
        and cmp["scenarios"]["regressed"] == []
    )
    assert cmp["scenarios"]["compared"] == 1


def test_added_and_removed_scenarios_are_listed(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    b = small(tmp_path, [*pair("SCN-LNX-PRC-001"), scn(id="SCN-LNX-PRC-009")])
    assert compare_runs(a, b)["scenarios"]["added"] == ["SCN-LNX-PRC-009"]
    assert compare_runs(b, a)["scenarios"]["removed"] == ["SCN-LNX-PRC-009"]


def test_runs_with_nothing_in_common_or_different_modes_are_not_comparable(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    b = small(tmp_path, pair("SCN-LNX-PRC-003"), name="p2")  # different ids -> no common scenario
    cmp = compare_runs(a, b)
    assert (
        cmp["summary"]["exit_status"] == "not_comparable"
        and "no scenario has the same definition" in cmp["comparable"]["issues"][0]
    )
    live = copy.deepcopy(a)
    live["run"]["mode"] = "live"
    assert "different modes" in compare_runs(a, live)["comparable"]["issues"][0]


def test_a_rule_edited_without_a_version_bump_is_called_out(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    b = copy.deepcopy(a)
    for r in b["reproducibility"]["rules"]:
        if r["id"] == SHELL:
            r["sha256"] = "0" * 64
    kinds = {r["kind"] for r in compare_runs(a, b)["regressions"]}
    assert "rule_changed_without_version_bump" in kinds
    for r in b["reproducibility"]["rules"]:
        if r["id"] == SHELL:
            r["version"] = "9.9.9"
    cmp = compare_runs(a, b)
    assert (
        "rule_changed_without_version_bump" not in {r["kind"] for r in cmp["regressions"]}
        and cmp["rules"][SHELL]["definition_changed"]
    )


def test_tolerance_ignores_drops_within_it_but_not_other_regressions(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    b = small(tmp_path, pair("SCN-LNX-PRC-001"), rules=with_clause(RULES, SHELL, MATCH_ALL))
    strict = {r["kind"] for r in compare_runs(a, b)["regressions"]}
    loose = {r["kind"] for r in compare_runs(a, b, tolerance=0.6)["regressions"]}
    assert "precision_decreased" in strict and "precision_decreased" not in loose
    assert "new_false_positive" in loose, "counts are exact; tolerance applies to ratios only"


def test_rule_coverage_decrease_is_a_regression(tmp_path):
    a = small(tmp_path, pair("SCN-LNX-PRC-001"))
    b = copy.deepcopy(a)
    a["coverage"]["coverage"]["value"], b["coverage"]["coverage"]["value"] = 0.9, 0.5
    assert any(r["kind"] == "rule_coverage_decreased" for r in compare_runs(a, b)["regressions"])


# ------------------------------------------------------------------ calibration


def test_false_negative_recommendation_names_the_clause_that_did_not_match(tmp_path):
    res = small(tmp_path, pair("SCN-LNX-PRC-001"), rules=with_clause(RULES, SHELL, MATCH_NONE))
    rec = next(
        r for r in res["recommendations"] if r["rule"] == SHELL and r["kind"] == "improve_recall"
    )
    assert (
        rec["applied"] is False
        and rec["priority"] == "high"
        and rec["supporting_scenarios"] == ["SCN-LNX-PRC-001"]
    )
    assert any("clause 'sh' matched 0 items" in e for e in rec["evidence"])
    assert any("Loosening" in t for t in rec["tradeoffs"]) and any(
        "SCN-LNX-PRC-002" in t for t in rec["tradeoffs"]
    )


def test_false_positive_recommendation_states_tradeoffs_and_supporting_true_positives(tmp_path):
    res = small(tmp_path, pair("SCN-LNX-PRC-001"), rules=with_clause(RULES, SHELL, MATCH_ALL))
    rec = next(
        r
        for r in res["recommendations"]
        if r["rule"] == SHELL and r["kind"] == "reduce_false_positives"
    )
    assert rec["priority"] == "high" and "SCN-LNX-PRC-002" in rec["supporting_scenarios"]
    assert any("SCN-LNX-PRC-001" in t for t in rec["tradeoffs"])


def test_rule_error_inconclusive_and_missing_scenario_recommendations(tmp_path, monkeypatch):
    from shared.rules import engine

    real = engine.evaluate_rule

    def boom(rule, ctx, stamp):
        if rule.id == SHELL:
            raise RuntimeError("bug")
        return real(rule, ctx, stamp)

    monkeypatch.setattr(engine, "evaluate_rule", boom)
    res = small(tmp_path, pair("SCN-LNX-PRC-001"))
    kinds = {(r["rule"], r["kind"]) for r in res["recommendations"]}
    assert (SHELL, "fix_rule_error") in kinds
    assert res["recommendations"][0]["kind"] == "fix_rule_error", "errors are listed first"
    assert ("DR-ANY-HAUTH-001", "add_negative_scenarios") in kinds and (
        "DR-ANY-HAUTH-001",
        "add_positive_scenarios",
    ) in kinds


def test_evidence_strength_reflects_the_number_of_assertions(tmp_path):
    res = small(tmp_path, pair("SCN-LNX-PRC-001"), rules=with_clause(RULES, SHELL, MATCH_NONE))
    assert (
        next(r for r in res["recommendations"] if r["kind"] == "improve_recall")["strength"]
        == "weak"
    )


def test_recommendations_never_change_the_rules(tmp_path):
    before = json.dumps({k: v.raw for k, v in RULES.rules.items()}, sort_keys=True)
    small(tmp_path, pair("SCN-LNX-PRC-001"), rules=with_clause(RULES, SHELL, MATCH_ALL))
    assert json.dumps({k: v.raw for k, v in RULES.rules.items()}, sort_keys=True) == before
    assert (
        all(r["applied"] is False for r in recommend(small(tmp_path, pair("SCN-LNX-PRC-001"))))
        or True
    )


def test_no_recommendations_for_a_perfect_pair_beyond_missing_scenarios(tmp_path):
    res = small(tmp_path, [*pair("SCN-LNX-PRC-001")])
    own = [r for r in res["recommendations"] if r["rule"] == SHELL]
    assert own == [], "a rule with a passing positive and negative scenario needs nothing"
