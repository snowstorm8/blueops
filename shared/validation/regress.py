"""Compare two validation runs and report regressions with their evidence.

Rules of the comparison:

* Only scenarios whose definition (``sha256``) is identical in both runs are compared; a changed
  scenario is listed under ``changed_definition`` and is excluded from verdicts, because a different
  question was asked.
* A regression is a worse answer to the same question: a scenario that stopped passing, precision /
  recall / evaluation rate that fell (both runs defined), a metric that became undefined (the rule
  can no longer be measured), a new false positive, a lost true positive, a new rule error.
* Rule identity changes are reported separately: a rule whose JSON changed without a version bump,
  or whose version changed (expected, but the metric deltas then carry the explanation).
* Runs in different modes (synthetic vs live) are not comparable.
"""

from __future__ import annotations

from typing import Any

from shared.reporting.schema_lite import validate
from shared.validation.model import VALIDATION_SCHEMA_VERSION
from shared.validation.runner import utc_now

GOOD = "pass"
WATCHED = ("precision", "recall", "f1", "evaluation_rate")


class ComparisonError(ValueError):
    """The two documents cannot be compared at all."""


def _rules_by_id(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["id"]: r for r in doc["reproducibility"]["rules"]}


def compare_runs(  # noqa: PLR0912, PLR0915 - one linear pass per comparison kind
    base: dict[str, Any], cur: dict[str, Any], *, tolerance: float = 0.0
) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    issues: list[str] = []
    if base["run"]["mode"] != cur["run"]["mode"]:
        issues.append(
            f"the runs have different modes ({base['run']['mode']} vs {cur['run']['mode']})"
        )
    b_sc = {s["id"]: s for s in base["scenarios"]}
    c_sc = {s["id"]: s for s in cur["scenarios"]}
    same = sorted(i for i in b_sc if i in c_sc and b_sc[i]["sha256"] == c_sc[i]["sha256"])
    if not same:
        issues.append("no scenario has the same definition in both runs")
    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    regressed, fixed = [], []
    for sid in same:
        b, c = b_sc[sid]["status"], c_sc[sid]["status"]
        if b == c:
            continue
        item = {"scenario": sid, "before": b, "after": c, "reason": c_sc[sid]["reason"][:300]}
        if b == GOOD and c != GOOD:
            regressed.append(item)
            regressions.append(
                {
                    "kind": "scenario_regressed",
                    "rule": ",".join(o["rule"] for o in c_sc[sid]["outcomes"][:3]),
                    "scenario": sid,
                    "message": f"{sid} went from {b} to {c}: {c_sc[sid]['reason'][:200]}",
                }
            )
        elif c == GOOD and b != GOOD:
            fixed.append(item)
            improvements.append(
                {
                    "kind": "scenario_fixed",
                    "scenario": sid,
                    "message": f"{sid} went from {b} to {c}",
                }
            )
    added = sorted(set(c_sc) - set(b_sc))
    removed = sorted(set(b_sc) - set(c_sc))
    changed = sorted(i for i in b_sc if i in c_sc and b_sc[i]["sha256"] != c_sc[i]["sha256"])

    # Per-rule metrics, restricted to the scenarios that are comparable in both runs.
    from shared.validation import metrics as M  # noqa: PLC0415

    def rule_metrics(sc: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        outs = [o for sid in same for o in sc[sid]["outcomes"]]
        return M.by_key(outs, "rule")

    bm, cm = rule_metrics(b_sc), rule_metrics(c_sc)
    br, cr = _rules_by_id(base), _rules_by_id(cur)
    rules: dict[str, Any] = {}
    for rid in sorted(set(bm) | set(cm)):
        b, c = bm.get(rid), cm.get(rid)
        entry: dict[str, Any] = {
            "version_before": br.get(rid, {}).get("version"),
            "version_after": cr.get(rid, {}).get("version"),
            "deltas": {},
        }
        if rid in br and rid in cr and br[rid]["sha256"] != cr[rid]["sha256"]:
            entry["definition_changed"] = True
            if br[rid]["version"] == cr[rid]["version"]:
                regressions.append(
                    {
                        "kind": "rule_changed_without_version_bump",
                        "rule": rid,
                        "message": f"{rid} changed but its version is still {cr[rid]['version']}; results cannot be attributed to a release",
                    }
                )
        if b is None or c is None:
            rules[rid] = entry
            continue
        for name in WATCHED:
            bv, cv = b[name]["value"], c[name]["value"]
            entry["deltas"][name] = {"before": bv, "after": cv}
            if bv is not None and cv is None:
                regressions.append(
                    {
                        "kind": "metric_became_undefined",
                        "rule": rid,
                        "metric": name,
                        "message": f"{rid}: {name} was {bv} and is now undefined ({c[name]['reason'][:120]}): the rule can no longer be measured",
                    }
                )
            elif bv is not None and cv is not None:
                if cv < bv - tolerance:
                    regressions.append(
                        {
                            "kind": f"{name}_decreased",
                            "rule": rid,
                            "metric": name,
                            "message": f"{rid}: {name} fell from {bv} to {cv}",
                        }
                    )
                elif cv > bv + tolerance:
                    improvements.append(
                        {
                            "kind": f"{name}_increased",
                            "rule": rid,
                            "message": f"{rid}: {name} rose from {bv} to {cv}",
                        }
                    )
        for key, kind, text in (
            ("false_positive", "new_false_positive", "false positive(s)"),
            ("rule_error", "new_rule_error", "rule error(s)"),
            ("true_positive", "lost_true_positive", "true positive(s)"),
        ):
            bn, cn = b["counts"][key], c["counts"][key]
            entry["deltas"][key] = {"before": bn, "after": cn}
            if key == "true_positive":
                if cn < bn:
                    regressions.append(
                        {
                            "kind": kind,
                            "rule": rid,
                            "message": f"{rid}: {bn - cn} fewer {text} ({bn} -> {cn})",
                        }
                    )
            elif cn > bn:
                regressions.append(
                    {
                        "kind": kind,
                        "rule": rid,
                        "message": f"{rid}: {cn - bn} more {text} ({bn} -> {cn})",
                    }
                )
        rules[rid] = entry

    bc, cc = base["coverage"]["coverage"]["value"], cur["coverage"]["coverage"]["value"]
    if bc is not None and cc is not None and cc < bc - tolerance:
        regressions.append(
            {
                "kind": "rule_coverage_decreased",
                "rule": "-",
                "message": f"rules with an evaluated positive and negative scenario fell from {bc} to {cc}",
            }
        )

    exit_status = "not_comparable" if issues else ("regressions" if regressions else "ok")
    doc = {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "kind": "validation-comparison",
        "generated_at": utc_now(),
        "baseline": {"run_id": base["run"]["id"], "digest": base["reproducibility"]["digest"], "generated_at": base["generated_at"]},
        "current": {"run_id": cur["run"]["id"], "digest": cur["reproducibility"]["digest"], "generated_at": cur["generated_at"]},
        "comparable": {"ok": not issues, "issues": issues},
        "scenarios": {"regressed": regressed, "fixed": fixed, "added": added, "removed": removed, "changed_definition": changed, "compared": len(same)},
        "rules": rules,
        "regressions": regressions,
        "improvements": improvements,
        "summary": {"regressions": len(regressions), "improvements": len(improvements), "exit_status": exit_status, "identical": base["reproducibility"]["digest"] == cur["reproducibility"]["digest"]},
    }  # fmt: skip
    problems = validate(doc, "validation-comparison.schema.json", limit=5)
    if problems:
        raise ComparisonError(
            "internal error: comparison violates its schema: " + "; ".join(problems)
        )
    return doc
