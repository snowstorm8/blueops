"""Run the examples embedded in rules (every rule ships positive and negative cases)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from shared.rules.engine import detect
from shared.rules.fixtures import build_assessment
from shared.rules.history import Snap
from shared.rules.loader import RuleSet
from shared.rules.model import Rule

STAMP = "2026-03-02T00:00:00Z"


@dataclass(frozen=True)
class ExampleResult:
    rule: str
    example: str
    ok: bool
    message: str


def run_example(rule: Rule, ex: dict[str, Any]) -> ExampleResult:
    platform = ex.get("platform") or ("windows" if rule.platforms == ("windows",) else "linux")
    cur = build_assessment(ex["current"], platform=platform, aid="example-current")
    prev = [
        Snap(
            build_assessment(
                {"started_at": f"2026-02-{10 + i:02d}T10:00:00Z", **spec},
                platform=platform,
                aid=f"example-prev-{i}",
            ),
            f"example-prev-{i}",
        )
        for i, spec in enumerate(ex.get("previous", []))
    ]
    rs = RuleSet(rules={rule.id: rule})
    res = detect(cur, rs, previous=prev, generated_at=STAMP)
    mine = [d for d in res["detections"] if d["rule"]["id"] == rule.id]
    ind = [i for i in res["indeterminate"] if i["rule"]["id"] == rule.id]
    if res["rule_errors"]:
        return ExampleResult(
            rule.id, ex["name"], False, f"rule error: {res['rule_errors'][0]['message']}"
        )
    expect = ex["expect"]
    if expect == "match":
        if not mine:
            return ExampleResult(
                rule.id,
                ex["name"],
                False,
                "expected a detection, got none"
                + (f" (indeterminate: {ind[0]['reason']})" if ind else ""),
            )
        if "count" in ex and len(mine) != ex["count"]:
            return ExampleResult(
                rule.id, ex["name"], False, f"expected {ex['count']} detection(s), got {len(mine)}"
            )
    elif expect == "no_match":
        if mine:
            return ExampleResult(
                rule.id,
                ex["name"],
                False,
                f"expected no detection, got {len(mine)}: {mine[0]['title']}",
            )
        if ind:
            return ExampleResult(
                rule.id,
                ex["name"],
                False,
                f"expected a definite no-match, got indeterminate: {ind[0]['reason']}",
            )
    elif expect == "indeterminate":
        if mine:
            return ExampleResult(
                rule.id, ex["name"], False, "expected indeterminate, got a detection"
            )
        if not ind:
            return ExampleResult(
                rule.id, ex["name"], False, "expected indeterminate, rule evaluated normally"
            )
    return ExampleResult(rule.id, ex["name"], True, "")


def run_all(rule_set: RuleSet, rule_ids: list[str] | None = None) -> list[ExampleResult]:
    out = []
    for rule in rule_set.ordered():
        if rule_ids and rule.id not in rule_ids:
            continue
        out += [run_example(rule, ex) for ex in rule.examples]
    return out
