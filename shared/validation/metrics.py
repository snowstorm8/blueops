"""Detection quality metrics with explicit handling of undefined values.

Unit of evaluation: one *outcome* per (scenario, rule) pair the scenario makes an assertion about.

====================  ===========================================================================
outcome               meaning
====================  ===========================================================================
true_positive         the rule was expected to detect the condition and did (count/severity/
                      confidence/title expectations met)
false_negative        the rule ran, found nothing (or a detection outside the expected ranges)
                      although the scenario expected a detection
false_positive        the rule ran and fired where the scenario said it must not
true_negative         the rule ran, evaluated the data and correctly did not fire
inconclusive          the rule could not evaluate (incomplete telemetry) where the scenario
                      expected a definite answer - **not** a true negative
expected_inconclusive the scenario expected the rule to report that it cannot evaluate, and it did
rule_error            the rule raised an error while executing
not_evaluated         the rule was not applicable / not loaded, so the assertion could not be tested
unexpected_detection  a rule the scenario made no assertion about fired (non-strict scenarios);
                      reported, never counted in precision
====================  ===========================================================================

Formulas (``tp, fp, tn, fn`` counts over evaluated outcomes only):

* precision   = tp / (tp + fp)            undefined when nothing fired
* recall      = tp / (tp + fn)            undefined when nothing was expected
* f1          = 2tp / (2tp + fp + fn)     undefined when the denominator is 0
* specificity = tn / (tn + fp)            undefined when no negative assertion was evaluated
* false_positive_rate = fp / (fp + tn)    same denominator as specificity
* evaluation_rate = evaluated / (evaluated + inconclusive + rule_error + not_evaluated)
  - the share of assertions that could actually be tested; ``expected_inconclusive`` is excluded
  from both sides because the scenario wanted that answer.

An undefined metric is reported as ``value: null`` with a ``reason``; it is never 0 and never 1.
``ci95`` is the Wilson score interval for proportions, shown so that a perfect score on three
scenarios is not mistaken for a measurement of real-world accuracy.
"""

from __future__ import annotations

import math
from typing import Any

TP, FN, FP, TN = "true_positive", "false_negative", "false_positive", "true_negative"
INCONCLUSIVE, EXPECTED_INCONCLUSIVE = "inconclusive", "expected_inconclusive"
RULE_ERROR, NOT_EVALUATED, UNEXPECTED = "rule_error", "not_evaluated", "unexpected_detection"
OUTCOMES = (
    TP,
    FN,
    FP,
    TN,
    INCONCLUSIVE,
    EXPECTED_INCONCLUSIVE,
    RULE_ERROR,
    NOT_EVALUATED,
    UNEXPECTED,
)

EXPLANATIONS = {
    "precision": "true_positive / (true_positive + false_positive): of the times the rule fired in an asserted scenario, how often it was expected to.",
    "recall": "true_positive / (true_positive + false_negative): of the conditions the rule was expected to detect, how many it detected.",
    "f1": "2 * true_positive / (2 * true_positive + false_positive + false_negative): the harmonic mean of precision and recall.",
    "specificity": "true_negative / (true_negative + false_positive): of the benign scenarios where the rule was evaluated, how often it stayed quiet.",
    "false_positive_rate": "false_positive / (false_positive + true_negative): the complement of specificity.",
    "evaluation_rate": "evaluated / (evaluated + inconclusive + rule_error + not_evaluated): the share of assertions that could be tested at all. Scenarios that expect an inconclusive result are excluded.",
    "undefined": "A metric whose denominator is 0 is reported as null with a reason. It is never shown as 0 or as a perfect score.",
    "samples": "All metrics describe the scenario library, which is synthetic and small. They are a regression signal and a measure of rule logic, not of real-world detection accuracy.",
}


def _wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n <= 0:
        return None
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def ratio(num: int, den: int, undefined_reason: str, *, interval: bool = True) -> dict[str, Any]:
    if den <= 0:
        return {
            "value": None,
            "numerator": num,
            "denominator": den,
            "ci95": None,
            "reason": undefined_reason,
        }
    return {
        "value": round(num / den, 4),
        "numerator": num,
        "denominator": den,
        "ci95": _wilson(num, den) if interval else None,
        "reason": "",
    }


def counts_of(outcomes: list[dict[str, Any]]) -> dict[str, int]:
    c = dict.fromkeys(OUTCOMES, 0)
    for o in outcomes:
        c[o["outcome"]] += 1
    return c


def compute(outcomes: list[dict[str, Any]]) -> dict[str, Any]:
    c = counts_of(outcomes)
    tp, fp, tn, fn = c[TP], c[FP], c[TN], c[FN]
    evaluated = tp + fp + tn + fn
    untestable = c[INCONCLUSIVE] + c[RULE_ERROR] + c[NOT_EVALUATED]
    return {
        "counts": c,
        "asserted": evaluated + untestable + c[EXPECTED_INCONCLUSIVE],
        "evaluated": evaluated,
        "precision": ratio(
            tp, tp + fp, "the rule never fired in an asserted scenario, so precision is undefined"
        ),
        "recall": ratio(
            tp,
            tp + fn,
            "no scenario expected this rule to detect anything (or none could be evaluated), so recall is undefined",
        ),
        "f1": ratio(
            2 * tp,
            2 * tp + fp + fn,
            "no true positives, false positives or false negatives were observed",
            interval=False,
        ),
        "specificity": ratio(
            tn, tn + fp, "no negative assertion was evaluated, so specificity is undefined"
        ),
        "false_positive_rate": ratio(
            fp,
            fp + tn,
            "no negative assertion was evaluated, so the false positive rate is undefined",
        ),
        "evaluation_rate": ratio(
            evaluated,
            evaluated + untestable,
            "nothing was asserted, so the share evaluated is undefined",
        ),
    }


def by_key(outcomes: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for o in outcomes:
        groups.setdefault(str(o[key]), []).append(o)
    return {k: compute(v) for k, v in sorted(groups.items())}


def rule_coverage(rules_in_scope: list[str], scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    """Which rules have *any* validation: a positive scenario (can show recall), a negative one
    (can show false positives), and whether either could actually be evaluated."""
    pos: dict[str, int] = {}
    neg: dict[str, int] = {}
    for s in scenarios:
        for o in s.get("outcomes", []):
            r = o["rule"]
            if o["outcome"] in (TP, FN):
                pos[r] = pos.get(r, 0) + 1
            elif o["outcome"] in (TN, FP):
                neg[r] = neg.get(r, 0) + 1
    both = [r for r in rules_in_scope if r in pos and r in neg]
    no_pos = [r for r in rules_in_scope if r not in pos]
    no_neg = [r for r in rules_in_scope if r not in neg]
    n = len(rules_in_scope)
    return {
        "rules_in_scope": n,
        "with_positive_and_negative": len(both),
        "without_positive_evaluation": no_pos,
        "without_negative_evaluation": no_neg,
        "coverage": ratio(len(both), n, "no rules in scope", interval=False),
    }
