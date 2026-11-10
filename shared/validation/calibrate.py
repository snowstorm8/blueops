"""Evidence-backed calibration recommendations.

Recommendations are *advice for a developer to review*. This module never edits a rule, a
threshold or a severity, and every recommendation carries ``applied: false``. Each one names the
rule, what was observed, the scenarios that support it, the evidence and the trade-off of acting
on it. Evidence strength reflects how many assertions exist for the rule: a conclusion drawn from
three scenarios is labelled weak.
"""

from __future__ import annotations

from typing import Any

PRIORITY = {
    "fix_rule_error": 0,
    "reduce_false_positives": 1,
    "improve_recall": 2,
    "resolve_inconclusive": 3,
    "add_negative_scenarios": 4,
    "add_positive_scenarios": 4,
}


def _strength(n: int) -> str:
    return "strong" if n >= 10 else ("moderate" if n >= 4 else "weak")


def _conditions(dets: list[dict[str, Any]]) -> set[str]:
    return {c for d in dets for m in d.get("matched", []) for c in m.get("conditions", [])}


def recommend(results: dict[str, Any]) -> list[dict[str, Any]]:  # noqa: PLR0912, PLR0915
    scenarios = {s["id"]: s for s in results["scenarios"]}
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for s in results["scenarios"]:
        for o in s["outcomes"]:
            by_rule.setdefault(o["rule"], []).append({**o, "known": s["status"] == "known_issue"})
    cov = results["coverage"]
    rules = sorted(
        set(by_rule)
        | set(cov.get("without_positive_evaluation", []))
        | set(cov.get("without_negative_evaluation", []))
    )
    out: list[dict[str, Any]] = []

    def add(
        rule: str,
        kind: str,
        priority: str,
        summary: str,
        observed: dict[str, Any],
        sup: list[str],
        evidence: list[str],
        tradeoffs: list[str],
        n: int,
    ) -> None:
        out.append(
            {
                "id": f"REC-{rule}-{kind}", "rule": rule, "kind": kind, "priority": priority,
                "summary": summary, "observed": observed, "supporting_scenarios": sorted(set(sup)),
                "evidence": evidence[:12], "tradeoffs": tradeoffs, "strength": _strength(n),
                "applied": False,
            }
        )  # fmt: skip

    for rule in rules:
        outs = by_rule.get(rule, [])
        n = sum(
            1
            for o in outs
            if o["outcome"]
            in ("true_positive", "false_negative", "false_positive", "true_negative")
        )
        kinds: dict[str, list[dict[str, Any]]] = {}
        for o in outs:
            kinds.setdefault(o["outcome"], []).append(o)
        counts = {k: len(v) for k, v in kinds.items()}

        if kinds.get("rule_error"):
            errs = kinds["rule_error"]
            add(
                rule,
                "fix_rule_error",
                "high",
                f"{rule} raised an error in {len(errs)} scenario(s); it produced no result there.",
                counts,
                [o["scenario"] for o in errs],
                [f"{o['scenario']}: {o['detail'][:200]}" for o in errs],
                [
                    "Until fixed, the rule's behaviour on this input is unknown and it cannot be counted as quiet."
                ],
                n,
            )

        fps = kinds.get("false_positive", [])
        if fps:
            fp_conds: set[str] = set()
            tp_conds: set[str] = set()
            for o in fps:
                fp_conds |= _conditions(
                    [d for d in scenarios[o["scenario"]]["detections"] if d["rule"] == rule]
                )
            for o in kinds.get("true_positive", []):
                tp_conds |= _conditions(
                    [d for d in scenarios[o["scenario"]]["detections"] if d["rule"] == rule]
                )
            ev = [f"{o['scenario']} fired: {o['detail'][:160]}" for o in fps]
            if fp_conds:
                ev.append(
                    "conditions satisfied in the false positives: "
                    + "; ".join(sorted(fp_conds))[:400]
                )
            if tp_conds and fp_conds and fp_conds <= tp_conds:
                ev.append(
                    "every condition satisfied in the false positives is also satisfied in the true positives: no existing condition separates them, so separating them needs a new attribute or context condition"
                )
            tps = [o["scenario"] for o in kinds.get("true_positive", [])]
            trade = [
                "Tightening the rule (an exclusion or an extra condition) suppresses these benign cases but can also suppress genuine activity that satisfies the same conditions."
            ]
            if tps:
                trade.append(
                    "Scenarios that currently depend on the existing behaviour: "
                    + ", ".join(sorted(tps))
                    + "."
                )
            trade.append(
                "Lowering severity/confidence for the borderline case keeps the lead visible without escalating it."
            )
            known = all(o["known"] for o in fps)
            add(
                rule,
                "reduce_false_positives",
                "medium" if known else "high",
                f"{rule} fired unexpectedly in {len(fps)} scenario(s)"
                + (" (documented known issues)" if known else "")
                + ".",
                counts,
                [o["scenario"] for o in fps],
                ev,
                trade,
                n,
            )

        fns = kinds.get("false_negative", [])
        if fns:
            ev = []
            for o in fns:
                miss = scenarios[o["scenario"]].get("miss_analysis", {}).get(rule, [])
                zero = [c for c in miss if c["matched_items"] == 0 and not c["optional"]]
                ev.append(
                    f"{o['scenario']}: "
                    + (
                        "; ".join(
                            f"clause '{c['clause']}' matched 0 items ({c['condition'][:120]})"
                            for c in zero
                        )
                        if zero
                        else o["detail"][:160]
                    )
                )
            trade = [
                "Loosening the condition that blocked detection raises the chance of firing on benign activity.",
                "Check the negative scenarios first: "
                + (
                    ", ".join(sorted(o["scenario"] for o in kinds.get("true_negative", [])))
                    or "none exist for this rule, so the cost of loosening cannot be measured yet"
                )
                + ".",
            ]
            add(
                rule,
                "improve_recall",
                "high",
                f"{rule} missed the expected condition in {len(fns)} scenario(s).",
                counts,
                [o["scenario"] for o in fns],
                ev,
                trade,
                n,
            )

        bad = kinds.get("inconclusive", []) + kinds.get("not_evaluated", [])
        if bad:
            add(
                rule,
                "resolve_inconclusive",
                "low",
                f"{rule} could not be evaluated in {len(bad)} asserted scenario(s); those are not counted as quiet or as detections.",
                counts,
                [o["scenario"] for o in bad],
                [f"{o['scenario']}: {o['detail'][:200]}" for o in bad],
                [
                    "Either the scenario's telemetry lacks the coverage the rule requires (fix the scenario) or the collector does not provide it (a real coverage gap)."
                ],
                n,
            )

        if rule in cov.get("without_negative_evaluation", []) and not fps:
            add(
                rule,
                "add_negative_scenarios",
                "low",
                f"{rule} has no evaluated negative scenario, so its false-positive behaviour is unmeasured.",
                counts,
                [],
                ["No scenario asserted this rule quiet and was able to evaluate it."],
                ["Precision and specificity stay undefined until a benign scenario exists."],
                n,
            )
        if rule in cov.get("without_positive_evaluation", []) and not fns:
            add(
                rule,
                "add_positive_scenarios",
                "low",
                f"{rule} has no evaluated positive scenario, so its recall is unmeasured.",
                counts,
                [],
                ["No scenario expected this rule to detect something and was able to evaluate it."],
                ["Recall stays undefined until a positive scenario exists."],
                n,
            )

    out.sort(key=lambda r: (PRIORITY[r["kind"]], r["rule"]))
    return out
