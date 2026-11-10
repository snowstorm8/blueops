"""Metric formulas, undefined-value handling and rule coverage."""

from __future__ import annotations

import math

import pytest

from shared.validation import metrics as M


def outs(**counts):
    return [
        {"scenario": f"S{i}", "rule": "R", "platform": "linux", "outcome": k}
        for k, n in counts.items()
        for i in range(n)
    ]


def test_formulas_on_a_known_confusion_matrix():
    m = M.compute(outs(true_positive=8, false_positive=2, false_negative=4, true_negative=6))
    assert m["precision"]["value"] == 0.8 and (
        m["precision"]["numerator"],
        m["precision"]["denominator"],
    ) == (8, 10)
    assert m["recall"]["value"] == round(8 / 12, 4)
    assert m["f1"]["value"] == round(16 / 22, 4)
    assert m["specificity"]["value"] == 0.75 and m["false_positive_rate"]["value"] == 0.25
    assert m["evaluated"] == 20 and m["evaluation_rate"]["value"] == 1.0


def test_f1_is_the_harmonic_mean_of_precision_and_recall():
    m = M.compute(outs(true_positive=5, false_positive=3, false_negative=7))
    p, r = m["precision"]["value"], m["recall"]["value"]
    assert m["f1"]["value"] == pytest.approx(2 * p * r / (p + r), abs=1e-3)


@pytest.mark.parametrize(
    ("counts", "undefined"),
    [
        (
            {},
            ["precision", "recall", "f1", "specificity", "false_positive_rate", "evaluation_rate"],
        ),
        ({"true_negative": 5}, ["precision", "recall", "f1"]),  # nothing fired, nothing expected
        ({"false_negative": 3}, ["precision", "specificity", "false_positive_rate"]),
        ({"true_positive": 4}, ["specificity", "false_positive_rate"]),
        (
            {"inconclusive": 3, "rule_error": 1},
            ["precision", "recall", "f1", "specificity", "false_positive_rate"],
        ),
    ],
)
def test_undefined_metrics_are_null_with_a_reason_never_zero_or_one(counts, undefined):
    m = M.compute(outs(**counts))
    for name in undefined:
        assert m[name]["value"] is None, name
        assert m[name]["reason"] and m[name]["ci95"] is None and m[name]["denominator"] == 0


def test_a_perfect_score_on_few_samples_has_a_wide_interval():
    m = M.compute(outs(true_positive=3, true_negative=3))
    assert m["precision"]["value"] == 1.0 and m["precision"]["ci95"][0] < 0.5
    big = M.compute(outs(true_positive=300))
    assert big["precision"]["ci95"][0] > 0.98


def test_wilson_interval_bounds_and_symmetry():
    lo, hi = M._wilson(5, 10)
    assert 0 < lo < 0.5 < hi < 1 and math.isclose(lo + hi, 1.0, abs_tol=1e-3)
    assert M._wilson(0, 0) is None
    assert M._wilson(0, 10)[0] == 0.0 and M._wilson(10, 10)[1] == 1.0


def test_missing_data_is_not_a_true_negative():
    m = M.compute(outs(inconclusive=5))
    assert m["counts"]["true_negative"] == 0 and m["specificity"]["value"] is None
    assert m["evaluation_rate"]["value"] == 0.0 and m["evaluation_rate"]["denominator"] == 5


def test_expected_inconclusive_is_neither_evaluated_nor_untestable():
    m = M.compute(outs(true_positive=2, expected_inconclusive=4, inconclusive=2))
    assert m["evaluation_rate"]["value"] == 0.5 and m["evaluation_rate"]["denominator"] == 4
    assert m["asserted"] == 8


def test_unexpected_detections_do_not_enter_precision():
    m = M.compute(outs(true_positive=2, unexpected_detection=10))
    assert m["precision"]["value"] == 1.0 and m["counts"]["unexpected_detection"] == 10


def test_rule_errors_and_not_evaluated_lower_the_evaluation_rate_only():
    m = M.compute(outs(true_positive=2, rule_error=1, not_evaluated=1))
    assert m["evaluation_rate"]["value"] == 0.5 and m["precision"]["value"] == 1.0


def test_grouping_by_rule_and_platform():
    data = [
        {"scenario": "a", "rule": "R1", "platform": "linux", "outcome": "true_positive"},
        {"scenario": "b", "rule": "R1", "platform": "windows", "outcome": "false_positive"},
        {"scenario": "c", "rule": "R2", "platform": "linux", "outcome": "true_negative"},
    ]
    by_rule = M.by_key(data, "rule")
    assert (
        by_rule["R1"]["precision"]["value"] == 0.5 and by_rule["R2"]["precision"]["value"] is None
    )
    assert M.by_key(data, "platform")["windows"]["counts"]["false_positive"] == 1


def test_rule_coverage_lists_what_has_no_evaluated_positive_or_negative():
    scenarios = [
        {
            "outcomes": [
                {"rule": "R1", "outcome": "true_positive"},
                {"rule": "R1", "outcome": "true_negative"},
                {"rule": "R2", "outcome": "inconclusive"},
            ]
        },
        {"outcomes": [{"rule": "R3", "outcome": "true_negative"}]},
    ]
    cov = M.rule_coverage(["R1", "R2", "R3", "R4"], scenarios)
    assert cov["with_positive_and_negative"] == 1 and cov["coverage"]["value"] == 0.25
    assert (
        cov["without_positive_evaluation"] == ["R2", "R3", "R4"]
        and "R1" not in cov["without_negative_evaluation"]
    )
    assert M.rule_coverage([], [])["coverage"]["value"] is None


def test_every_metric_has_an_explanation():
    for name in (
        "precision",
        "recall",
        "f1",
        "specificity",
        "false_positive_rate",
        "evaluation_rate",
        "undefined",
        "samples",
    ):
        assert M.EXPLANATIONS[name]
