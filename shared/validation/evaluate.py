"""Evaluate a scenario: build its telemetry, run the real detection engine, compare with the
expectations and classify every assertion into a metrics outcome.

Nothing here touches the host: the dataset is built (or loaded) and handed to the same
``shared.rules.engine.detect`` that ``telemetry hunt`` uses.
"""

from __future__ import annotations

import traceback
from pathlib import Path
from typing import Any

from shared.rules.conditions import compile_condition
from shared.rules.engine import detect
from shared.rules.loader import RuleSet
from shared.rules.telemetry_subjects import ProcessIndex, telemetry_subject
from shared.telemetry.fixtures import build_telemetry
from shared.telemetry.hunt import shell_assessment
from shared.telemetry.ingest import IngestError, load_telemetry
from shared.validation import metrics as M
from shared.validation.model import CONFIDENCE_ORDER, SEVERITY_ORDER, Scenario

COVERAGE_RANK = {"complete": 0, "not_applicable": 0, "partial": 1, "unavailable": 2}
DEFAULT_STAMP = "2026-01-01T00:00:00Z"
STATUS_ORDER = ("error", "fail", "inconclusive", "pass")  # worst first


class DatasetError(ValueError):
    """The scenario's dataset could not be built or loaded."""


def build_dataset(spec: dict[str, Any], scenario: Scenario, *, role: str) -> dict[str, Any]:
    """Telemetry document for a synthetic ``records`` spec or a recorded ``store``."""
    if "store" in spec:
        path = Path(spec["store"])
        if not path.is_absolute():
            path = Path(scenario.source_dir) / path
        try:
            return load_telemetry(path)
        except IngestError as exc:
            raise DatasetError(f"{scenario.id}: {role} store: {exc}") from None
    platform = spec.get("platform") or scenario.platforms[0]
    cid = f"{scenario.id.lower()}-{role}"
    try:
        doc = build_telemetry(
            {k: v for k, v in spec.items() if k not in ("platform", "allow_rejected")},
            platform=platform,
            hostname=spec.get("host", "lab-host"),
            cid=cid,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise DatasetError(f"{scenario.id}: {role} dataset cannot be built: {exc}") from None
    if doc["summary"]["rejected"] and not spec.get("allow_rejected"):
        reasons = "; ".join(r for x in doc["rejected"][:2] for r in x["reasons"])
        raise DatasetError(
            f"{scenario.id}: {role} dataset has {doc['summary']['rejected']} rejected record(s) "
            f"({reasons}); set dataset.allow_rejected if that is the point of the scenario"
        )
    return doc


def _rank(value: str, order: tuple[str, ...]) -> int:
    return order.index(value)


def _within(value: str, rng: dict[str, str], order: tuple[str, ...]) -> bool:
    lo, hi = rng.get("min"), rng.get("max")
    return not (
        (lo and _rank(value, order) < _rank(lo, order))
        or (hi and _rank(value, order) > _rank(hi, order))
    )


def _count_bounds(c: Any, default_min: int = 1) -> tuple[int, int | None]:
    if c is None:
        return default_min, None
    if isinstance(c, int):
        return c, c
    return c.get("min", 0 if "max" in c else default_min), c.get("max")


def _count_ok(n: int, bounds: tuple[int, int | None]) -> bool:
    lo, hi = bounds
    return n >= lo and (hi is None or n <= hi)


def _describe(bounds: tuple[int, int | None]) -> str:
    lo, hi = bounds
    return str(lo) if lo == hi else f"{lo}..{hi if hi is not None else 'n'}"


def observed_coverage(tel: dict[str, Any]) -> dict[str, str]:
    """Worst declared status per category; categories with no entry are simply absent."""
    out: dict[str, str] = {}
    for c in tel["coverage"]:
        cur = out.get(c["category"])
        if cur is None or COVERAGE_RANK[c["status"]] > COVERAGE_RANK[cur]:
            out[c["category"]] = c["status"]
    return out


def _rule_status(results: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["rule"]: r for r in results["rule_results"]}


def _check(
    name: str, ok: bool, expected: Any, actual: Any, detail: str = "", *, untestable: bool = False
) -> dict[str, Any]:
    """``untestable`` marks a check that could not be evaluated (missing data): it is not ``ok``
    and not a wrong answer either, so it makes a scenario inconclusive, not failed."""
    c = {"name": name, "ok": bool(ok), "expected": expected, "actual": actual, "detail": detail}
    if untestable:
        c["untestable"] = True
    return c


def evaluate_scenario(  # noqa: PLR0912, PLR0915 - one linear classification pass
    scenario: Scenario,
    rule_set: RuleSet,
    *,
    generated_at: str = DEFAULT_STAMP,
    substitutions: dict[str, Any] | None = None,
    tel: dict[str, Any] | None = None,
    base: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run one scenario. Never raises: failures become ``status: error`` with the reason."""
    out: dict[str, Any] = {
        "id": scenario.id, "title": scenario.title, "kind": scenario.kind,
        "platforms": list(scenario.platforms), "dataset_platform": scenario.dataset_platform,
        "pack": scenario.pack, "sha256": scenario.sha256, "status": "error", "reason": "",
        "checks": [], "outcomes": [], "detections": [], "indeterminate": [], "rule_errors": [],
        "telemetry": {}, "limitations": list(scenario.limitations),
    }  # fmt: skip
    try:
        if tel is None:
            tel = build_dataset(scenario.dataset, scenario, role="dataset")
        if base is None and scenario.baseline_dataset is not None:
            base = build_dataset(scenario.baseline_dataset, scenario, role="baseline")
        known = set(rule_set.rules)
        sub_rules = rule_set.only(lambda r: r.id in known)
        results = detect(
            shell_assessment(tel), sub_rules, generated_at=generated_at, telemetry=tel,
            telemetry_baseline=base,
        )  # fmt: skip
    except DatasetError as exc:
        out["reason"] = str(exc)
        return out
    except Exception as exc:  # noqa: BLE001 - a broken scenario/engine run is reported, not hidden
        out["reason"] = f"{type(exc).__name__}: {exc}"
        out["traceback"] = traceback.format_exc(limit=6)[-1500:]
        return out

    status = _rule_status(results)
    dets_by_rule: dict[str, list[dict[str, Any]]] = {}
    for d in results["detections"]:
        dets_by_rule.setdefault(d["rule"]["id"], []).append(d)
    ind_by_rule = {i["rule"]["id"]: i["reason"] for i in results["indeterminate"]}
    errs = {e["rule"]: e["message"] for e in results["rule_errors"] if e.get("rule")}
    checks = out["checks"]
    outcomes = out["outcomes"]
    exp = scenario.expect

    def add(rule: str, outcome: str, detail: str = "") -> None:
        outcomes.append({"scenario": scenario.id, "rule": rule, "outcome": outcome,
                         "platform": scenario.dataset_platform, "kind": scenario.kind, "detail": detail})  # fmt: skip

    def untestable(rule: str) -> str | None:
        st = status.get(rule, {}).get("status")
        if rule in errs or st == "error":
            add(rule, M.RULE_ERROR, errs.get(rule, "rule raised an error"))
            checks.append(
                _check(
                    f"execution:{rule}", False, "rule executes", "rule error", errs.get(rule, "")
                )
            )
            return "error"
        if st in (None, "disabled", "not_applicable"):
            why = status.get(rule, {}).get("reason") or (st or "rule is not loaded")
            add(rule, M.NOT_EVALUATED, why)
            checks.append(
                _check(
                    f"evaluation:{rule}",
                    False,
                    "rule evaluated",
                    st or "missing",
                    why,
                    untestable=True,
                )
            )
            return "not_evaluated"
        if st == "indeterminate" or rule in ind_by_rule:
            return "indeterminate"
        return None

    asserted_expect = {d["rule"] for d in exp.get("detections", [])}
    asserted_absent = set(exp.get("absent", []))
    asserted_indet = {i["rule"] for i in exp.get("indeterminate", [])}

    for d in exp.get("detections", []):
        rule = d["rule"]
        bad = untestable(rule)
        if bad in {"error", "not_evaluated"}:
            continue
        if bad == "indeterminate":
            reason = ind_by_rule.get(rule, status.get(rule, {}).get("reason", ""))
            add(rule, M.INCONCLUSIVE, reason)
            checks.append(
                _check(
                    f"detection:{rule}",
                    False,
                    "a detection",
                    "rule could not evaluate",
                    reason,
                    untestable=True,
                )
            )
            continue
        found = dets_by_rule.get(rule, [])
        bounds = _count_bounds(d.get("count"))
        if len(found) < bounds[0]:
            add(rule, M.FN, f"expected {_describe(bounds)} detection(s), got {len(found)}")
            checks.append(
                _check(
                    f"detection:{rule}",
                    False,
                    f">= {bounds[0]} detection(s)",
                    len(found),
                    "the rule evaluated the data and did not detect the condition",
                )
            )
            continue
        problems = []
        if not _count_ok(len(found), bounds):
            problems.append(f"count {len(found)} outside {_describe(bounds)}")
        for f in found:
            if d.get("severity") and not _within(f["severity"], d["severity"], SEVERITY_ORDER):
                problems.append(f"severity {f['severity']} outside {d['severity']}")
            if d.get("confidence") and not _within(
                f["confidence"], d["confidence"], CONFIDENCE_ORDER
            ):
                problems.append(f"confidence {f['confidence']} outside {d['confidence']}")
            if d.get("title_contains") and d["title_contains"] not in f["title"]:
                problems.append(f"title {f['title'][:60]!r} lacks {d['title_contains']!r}")
        add(rule, M.TP, "; ".join(problems))
        checks.append(
            _check(
                f"detection:{rule}",
                not problems,
                d,
                [f"{f['severity']}/{f['confidence']}" for f in found],
                "; ".join(sorted(set(problems))),
            )
        )

    for rule in sorted(asserted_absent):
        bad = untestable(rule)
        if bad in ("error", "not_evaluated"):
            continue
        if bad == "indeterminate":
            reason = ind_by_rule.get(rule, status.get(rule, {}).get("reason", ""))
            add(rule, M.INCONCLUSIVE, reason)
            checks.append(
                _check(
                    f"absent:{rule}",
                    False,
                    "evaluated and quiet",
                    "rule could not evaluate",
                    reason,
                    untestable=True,
                )
            )
            continue
        found = dets_by_rule.get(rule, [])
        if found:
            add(rule, M.FP, "; ".join(f["title"][:80] for f in found[:2]))
            checks.append(
                _check(
                    f"absent:{rule}",
                    False,
                    "no detection",
                    f"{len(found)} detection(s)",
                    found[0]["title"][:120],
                )
            )
        else:
            add(rule, M.TN)
            checks.append(_check(f"absent:{rule}", True, "no detection", 0))

    for i in exp.get("indeterminate", []):
        rule = i["rule"]
        bad = untestable(rule)
        if bad in ("error", "not_evaluated"):
            continue
        reason = ind_by_rule.get(rule, "")
        if bad == "indeterminate":
            want = i.get("reason_contains", "")
            ok = want.lower() in reason.lower()
            add(rule, M.EXPECTED_INCONCLUSIVE if ok else M.INCONCLUSIVE, reason)
            checks.append(
                _check(
                    f"indeterminate:{rule}",
                    ok,
                    f"indeterminate ({want!r})" if want else "indeterminate",
                    reason[:200],
                    "" if ok else "the rule could not evaluate, but for a different reason",
                )
            )
        else:
            n = len(dets_by_rule.get(rule, []))
            checks.append(
                _check(
                    f"indeterminate:{rule}",
                    False,
                    "rule reports it cannot evaluate",
                    f"evaluated, {n} detection(s)",
                    "the telemetry was more complete than the scenario assumed",
                )
            )
            if n:
                add(
                    rule,
                    M.UNEXPECTED,
                    "fired although the scenario expected it to be unable to evaluate",
                )

    asserted_all = asserted_expect | asserted_absent | asserted_indet
    for rule, found in sorted(dets_by_rule.items()):
        if rule in asserted_all:
            continue
        if exp.get("no_other_detections"):
            add(rule, M.FP, found[0]["title"][:80])
            checks.append(
                _check(
                    f"strict:{rule}",
                    False,
                    "no other detections",
                    f"{len(found)} detection(s)",
                    found[0]["title"][:120],
                )
            )
        else:
            add(rule, M.UNEXPECTED, found[0]["title"][:80])

    cov = observed_coverage(tel)
    for cat, want in sorted(exp.get("coverage", {}).items()):
        got = cov.get(cat, "absent")
        checks.append(_check(f"coverage:{cat}", got == want, want, got))

    index = ProcessIndex(tel["records"])
    subjects = [telemetry_subject(r, index) for r in tel["records"]]
    for n, t in enumerate(exp.get("telemetry", [])):
        node = compile_condition(_substitute(t["where"], substitutions)) if t.get("where") else None
        hits = [
            s
            for s in subjects
            if s.fields["category"] == t["category"] and (node is None or node.run(s.fields, None))
        ]
        bounds = _count_bounds(t.get("count"))
        label = t.get("description") or t["category"]
        checks.append(
            _check(
                f"telemetry:{n}:{label}",
                _count_ok(len(hits), bounds),
                f"{_describe(bounds)} record(s)",
                len(hits),
            )
        )

    out["detections"] = [
        {"rule": d["rule"]["id"], "id": d["id"], "severity": d["severity"], "confidence": d["confidence"], "nature": d["nature"], "title": d["title"][:160]}
        for d in results["detections"]
    ]  # fmt: skip
    out["indeterminate"] = [
        {"rule": r, "reason": why[:300]} for r, why in sorted(ind_by_rule.items())
    ]
    out["rule_errors"] = [{"rule": r, "message": m[:300]} for r, m in sorted(errs.items())]
    out["telemetry"] = {
        "records": tel["summary"]["records"], "coverage": cov, "complete": tel["summary"]["complete"],
        "errors": [e["code"] for e in tel["errors"]], "rejected": tel["summary"]["rejected"],
    }  # fmt: skip

    failed = [c for c in checks if not c["ok"] and not c.get("untestable")]
    kinds = {o["outcome"] for o in outcomes}
    if M.RULE_ERROR in kinds:
        out["status"], out["reason"] = "error", "a rule raised an error while executing"
    elif failed:
        out["status"] = "fail"
        out["reason"] = "; ".join(
            f"{c['name']}: expected {c['expected']!r}, got {c['actual']!r}" for c in failed[:3]
        )
    elif M.INCONCLUSIVE in kinds or M.NOT_EVALUATED in kinds:
        out["status"], out["reason"] = "inconclusive", "an asserted rule could not be evaluated"
    else:
        out["status"], out["reason"] = "pass", ""
    return out


def _substitute(node: Any, values: dict[str, Any] | None) -> Any:
    """Replace whole-string ``${name}`` values (live scenarios: runtime pids and ports)."""
    if not values:
        return node
    if isinstance(node, dict):
        return {k: _substitute(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [_substitute(v, values) for v in node]
    if isinstance(node, str) and node.startswith("${") and node.endswith("}"):
        return values.get(node[2:-1], node)
    return node
