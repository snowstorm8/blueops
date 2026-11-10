"""Scenario evaluation against the real detection engine: outcome classification."""

from __future__ import annotations

import pytest
from validation_support import SHELL_UNDER_NGINX, conn, ev, proc, rs, scn, tr, write_pack

from shared.validation.evaluate import DatasetError, build_dataset, evaluate_scenario
from shared.validation.model import load_pack_file

SHELL_RULE = "DR-ANY-HPRC-001"


def run(tmp_path, scenario, rules=None, **kw):
    scenarios, diags, _ = load_pack_file(write_pack(tmp_path, [scenario]))
    assert not diags, [str(d) for d in diags]
    return evaluate_scenario(scenarios[0], rules or rs(), **kw)


def outcomes(res):
    return {(o["rule"], o["outcome"]) for o in res["outcomes"]}


def test_true_positive(tmp_path):
    res = run(tmp_path, scn())
    assert res["status"] == "pass" and (SHELL_RULE, "true_positive") in outcomes(res)
    assert res["detections"][0]["rule"] == SHELL_RULE and res["telemetry"]["records"] == 2


def test_false_negative_when_the_rule_evaluates_and_finds_nothing(tmp_path):
    res = run(
        tmp_path,
        scn(
            dataset={"platform": "linux", "records": [proc(100, 1, "nginx"), proc(200, 100, "cat")]}
        ),
    )
    assert res["status"] == "fail" and (SHELL_RULE, "false_negative") in outcomes(res)
    assert "did not detect" in res["checks"][0]["detail"]


def test_false_positive_and_true_negative(tmp_path):
    neg = scn(kind="negative", expect={"absent": [SHELL_RULE, "DR-ANY-HPRC-002"]})
    res = run(tmp_path, neg)
    assert res["status"] == "fail"
    assert (SHELL_RULE, "false_positive") in outcomes(res)
    assert ("DR-ANY-HPRC-002", "true_negative") in outcomes(res)
    ok = run(
        tmp_path,
        scn(
            kind="negative",
            expect={"absent": [SHELL_RULE]},
            dataset={"platform": "linux", "records": [proc(1, 0, "systemd"), proc(2, 1, "sshd")]},
        ),
    )
    assert ok["status"] == "pass" and outcomes(ok) == {(SHELL_RULE, "true_negative")}


def test_missing_telemetry_is_inconclusive_not_a_true_negative(tmp_path):
    ds = {
        "platform": "linux",
        "records": [proc(1, 0, "systemd")],
        "coverage": {"process": "unavailable"},
    }
    res = run(tmp_path, scn(kind="negative", expect={"absent": [SHELL_RULE]}, dataset=ds))
    assert (SHELL_RULE, "inconclusive") in outcomes(res) and not any(
        o == "true_negative" for _, o in outcomes(res)
    )
    assert res["status"] == "inconclusive" and any(
        i["rule"] == SHELL_RULE for i in res["indeterminate"]
    )


def test_expected_inconclusive_is_a_pass_with_its_own_outcome(tmp_path):
    ds = {
        "platform": "linux",
        "records": [proc(1, 0, "systemd")],
        "coverage": {"auth_event": "unavailable"},
    }
    exp = {
        "indeterminate": [{"rule": "DR-ANY-HAUTH-001", "reason_contains": "could not be collected"}]
    }
    res = run(tmp_path, scn(kind="coverage", dataset=ds, expect=exp))
    assert res["status"] == "pass" and outcomes(res) == {
        ("DR-ANY-HAUTH-001", "expected_inconclusive")
    }


def test_a_wrong_indeterminate_reason_is_a_failed_check(tmp_path):
    ds = {
        "platform": "linux",
        "records": [proc(1, 0, "systemd")],
        "coverage": {"auth_event": "unavailable"},
    }
    exp = {
        "indeterminate": [
            {"rule": "DR-ANY-HAUTH-001", "reason_contains": "something else entirely"}
        ]
    }
    res = run(tmp_path, scn(kind="coverage", dataset=ds, expect=exp))
    assert res["status"] == "fail" and "different reason" in res["checks"][0]["detail"]


def test_a_rule_that_evaluates_when_the_scenario_expected_it_could_not_is_a_failure(tmp_path):
    res = run(tmp_path, scn(kind="coverage", expect={"indeterminate": [{"rule": SHELL_RULE}]}))
    assert res["status"] == "fail" and "more complete" in res["checks"][0]["detail"]
    assert (SHELL_RULE, "unexpected_detection") in outcomes(res)


def test_rule_execution_failure_is_an_error_outcome(tmp_path, monkeypatch):
    from shared.rules import engine

    real = engine.evaluate_rule

    def boom(rule, ctx, generated_at):
        if rule.id == SHELL_RULE:
            raise RuntimeError("synthetic rule bug")
        return real(rule, ctx, generated_at)

    monkeypatch.setattr(engine, "evaluate_rule", boom)
    res = run(tmp_path, scn())
    assert res["status"] == "error" and (SHELL_RULE, "rule_error") in outcomes(res)
    assert (
        res["rule_errors"][0]["rule"] == SHELL_RULE
        and "synthetic rule bug" in res["rule_errors"][0]["message"]
    )


def test_a_rule_that_is_not_applicable_or_not_loaded_is_not_evaluated(tmp_path):
    windows_only = scn(kind="negative", expect={"absent": ["DR-WIN-HPRC-005"]})
    res = run(tmp_path, windows_only)  # linux dataset: the Windows-only rule never runs
    assert res["status"] == "inconclusive" and ("DR-WIN-HPRC-005", "not_evaluated") in outcomes(res)
    res = run(tmp_path, scn(), rules=rs("DR-ANY-HPRC-002"))
    assert (SHELL_RULE, "not_evaluated") in outcomes(res) and res["status"] == "inconclusive"


def test_severity_confidence_title_and_count_expectations(tmp_path):
    ok = scn(
        expect={
            "detections": [
                {
                    "rule": SHELL_RULE,
                    "severity": {"min": "high", "max": "critical"},
                    "confidence": {"min": "low", "max": "high"},
                    "count": 1,
                    "title_contains": "bash",
                }
            ]
        }
    )
    assert run(tmp_path, ok)["status"] == "pass"
    low = scn(expect={"detections": [{"rule": SHELL_RULE, "severity": {"max": "medium"}}]})
    res = run(tmp_path, low)
    assert res["status"] == "fail" and (SHELL_RULE, "true_positive") in outcomes(res), (
        "it did detect; the severity is the failure"
    )
    assert "severity high outside" in res["checks"][0]["detail"]
    assert (
        run(tmp_path, scn(expect={"detections": [{"rule": SHELL_RULE, "title_contains": "zsh"}]}))[
            "status"
        ]
        == "fail"
    )
    two = [proc(100, 1, "nginx", user="www"), proc(200, 100, "bash"), proc(201, 100, "sh")]
    res = run(
        tmp_path,
        scn(
            dataset={"platform": "linux", "records": two},
            expect={"detections": [{"rule": SHELL_RULE, "count": 1}]},
        ),
    )
    assert res["status"] == "fail" and "count 2 outside 1" in res["checks"][0]["detail"]
    assert (
        run(
            tmp_path,
            scn(
                dataset={"platform": "linux", "records": two},
                expect={"detections": [{"rule": SHELL_RULE, "count": {"min": 2, "max": 2}}]},
            ),
        )["status"]
        == "pass"
    )


def test_strict_mode_turns_unasserted_detections_into_false_positives(tmp_path):
    recs = [*SHELL_UNDER_NGINX, conn(200, "203.0.113.9")]
    loose = run(tmp_path, scn(dataset={"platform": "linux", "records": recs}))
    assert loose["status"] == "pass" and ("DR-ANY-HPRC-004", "unexpected_detection") in outcomes(
        loose
    )
    strict = run(
        tmp_path,
        scn(
            dataset={"platform": "linux", "records": recs},
            expect={"detections": [{"rule": SHELL_RULE}], "no_other_detections": True},
        ),
    )
    assert strict["status"] == "fail" and ("DR-ANY-HPRC-004", "false_positive") in outcomes(strict)


def test_coverage_and_telemetry_expectations(tmp_path):
    exp = {
        "detections": [{"rule": SHELL_RULE}],
        "coverage": {"process": "complete", "auth_event": "absent"},
        "telemetry": [
            {
                "category": "process",
                "where": {"field": "attrs.name", "op": "eq", "value": "bash"},
                "count": 1,
                "description": "the shell",
            }
        ],
    }
    res = run(tmp_path, scn(expect=exp))
    assert res["status"] == "pass" and {c["name"] for c in res["checks"]} >= {
        "coverage:process",
        "coverage:auth_event",
    }
    exp["coverage"] = {"process": "unavailable"}
    exp["telemetry"] = [
        {
            "category": "process",
            "where": {"field": "process.parent_name", "op": "eq", "value": "nginx"},
            "count": 3,
        }
    ]
    res = run(tmp_path, scn(expect=exp))
    assert res["status"] == "fail" and sum(not c["ok"] for c in res["checks"]) == 2


def test_runtime_values_can_be_substituted_into_telemetry_expectations(tmp_path):
    exp = {
        "detections": [{"rule": SHELL_RULE}],
        "telemetry": [
            {
                "category": "process",
                "where": {"field": "attrs.ppid", "op": "eq", "value": "${parent}"},
                "count": 1,
            }
        ],
    }
    res = run(tmp_path, scn(expect=exp), substitutions={"parent": 100})
    assert res["status"] == "pass"


def test_dataset_problems_are_errors_with_the_reason_not_crashes(tmp_path):
    bad = scn(
        dataset={
            "platform": "linux",
            "records": [{"category": "nonsense", "key": "k", "attributes": {}}],
        }
    )
    res = run(tmp_path, bad)
    assert res["status"] == "error" and "rejected" in res["reason"] and res["outcomes"] == []
    allowed = scn(
        dataset={
            "platform": "linux",
            "allow_rejected": True,
            "records": [{"category": "nonsense", "key": "k", "attributes": {}}, *SHELL_UNDER_NGINX],
        }
    )
    res = run(tmp_path, allowed)
    assert res["status"] == "pass" and res["telemetry"]["rejected"] == 1
    assert (
        run(tmp_path, scn(dataset={"platform": "linux", "store": "nowhere"}))["status"] == "error"
    )


def test_malformed_and_missing_fields_in_telemetry_are_survivable(tmp_path):
    recs = [
        tr(
            "process",
            "p1",
            {"pid": 1, "name": "bash", "ppid": None, "exe": None, "user": None},
            unknown_attributes=["ppid", "exe", "user"],
        ),
        tr("auth_event", "e", {"action": "login_failure", "result": "failure", "user": None}),
    ]
    res = run(
        tmp_path,
        scn(
            kind="negative",
            dataset={"platform": "linux", "records": recs},
            expect={"absent": [SHELL_RULE, "DR-ANY-HAUTH-001"]},
        ),
    )
    assert res["status"] == "pass", res["reason"]


def test_baseline_dataset_enables_change_rules(tmp_path):
    base = {
        "platform": "linux",
        "records": [
            tr(
                "listener",
                "l",
                {
                    "protocol": "tcp",
                    "local_address": "0.0.0.0",
                    "local_port": 22,
                    "process": "sshd",
                },
            )
        ],
    }
    cur = {
        "platform": "linux",
        "records": [
            *base["records"],
            tr(
                "listener",
                "l2",
                {"protocol": "tcp", "local_address": "0.0.0.0", "local_port": 9001, "process": "x"},
            ),
        ],
    }
    s = scn(
        dataset=cur, baseline_dataset=base, expect={"detections": [{"rule": "DR-ANY-HCHG-001"}]}
    )
    assert run(tmp_path, s)["status"] == "pass"
    s2 = scn(dataset=cur, expect={"detections": [{"rule": "DR-ANY-HCHG-001"}]})
    res = run(tmp_path, s2)
    # without a baseline the change rule cannot be evaluated: inconclusive, not a miss
    assert res["status"] == "inconclusive"
    assert ("DR-ANY-HCHG-001", "not_evaluated") in outcomes(res)


def test_evaluation_is_deterministic(tmp_path):
    a = run(tmp_path, scn())
    b = run(tmp_path, scn())
    assert a == b


def test_build_dataset_rejects_unbuildable_specs(tmp_path):
    scenarios, _, _ = load_pack_file(write_pack(tmp_path, [scn()]))
    with pytest.raises(DatasetError):
        build_dataset(
            {"platform": "linux", "records": [{"no": "category"}]}, scenarios[0], role="dataset"
        )


def test_auth_scenarios_cover_failed_repeated_and_missing_logs(tmp_path):
    spray = [
        ev(f"2026-03-01T09:{i:02d}:00Z", "login_failure", "failure", u, "203.0.113.5", i)
        for i, u in enumerate(["root", "admin", "bob"] * 4)
    ]
    res = run(
        tmp_path,
        scn(
            dataset={"platform": "linux", "records": spray},
            expect={"detections": [{"rule": "DR-ANY-HAUTH-001"}]},
        ),
    )
    assert res["status"] == "pass"
    single = [ev("2026-03-01T09:00:00Z", "login_failure", "failure", "root", "203.0.113.5", 1)]
    res = run(
        tmp_path,
        scn(
            kind="negative",
            dataset={"platform": "linux", "records": single},
            expect={"absent": ["DR-ANY-HAUTH-001"]},
        ),
    )
    assert res["status"] == "pass"
