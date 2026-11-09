"""Evaluate rules over an assessment (and its history) and build explainable detections.

Pipeline for one rule: applicability -> coverage -> clause matching (conditions) -> grouping
(optional join) -> boolean ``require`` over clause results -> detection with explanation.

Principles (enforced here and tested):

* **Deterministic.** Rules run in id order, subjects keep their document order, ids are hashes.
* **No guessing.** Missing coverage or missing history yields an *indeterminate* entry, never a
  clean result and never a detection built on absence.
* **Severity is explicit.** It is the rule's base value or the result of the rule's own
  ``severity_rules``; the number of matching findings never changes it.
* **Traceable.** Every contributing finding / record / change is listed by id; evidence ids are
  taken from the assessment, never invented.
* **Bounded.** Caps on items per clause, items listed per detection and detections per rule.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from shared.engine.module import OK
from shared.engine.provenance import entries, stamp
from shared.findings.model import clean, host_id
from shared.findings.standards import attack_url
from shared.reporting.contracts import ExitCode, Severity
from shared.reporting.snapshot_compare import ComparisonError, compare_snapshots
from shared.rules import RULES_ENGINE_NAME, RULES_ENGINE_VERSION, RULES_SCHEMA_VERSION
from shared.rules.conditions import evaluate
from shared.rules.history import HistoryView, Snap
from shared.rules.loader import RuleSet
from shared.rules.model import Adjust, Clause, Rule
from shared.rules.subjects import (
    COMPARISON_SOURCES,
    SEVERITY_RANK,
    TELEMETRY_SOURCES,
    Subject,
    change_subject,
    finding_subject,
    inventory_subject,
    snapshot_subject,
)
from shared.rules.telemetry_subjects import (
    ProcessIndex,
    telemetry_change_subjects,
    telemetry_subject,
)
from shared.rules.validate import expr_uses_not
from shared.telemetry.compare import CompareError, compare_telemetry

MAX_ITEMS_PER_CLAUSE = 5000
MAX_LISTED_PER_CLAUSE = 50
MAX_DETECTIONS_PER_RULE = 100
MAX_DETECTIONS = 2000
_TEMPLATE = re.compile(r"\{([a-z][a-z0-9_]*)(?:\.([A-Za-z0-9_.*-]+))?\}")
_CONF = ("low", "medium", "high")

NIST_TITLES = {
    "AC-2": "Account Management", "AC-3": "Access Enforcement", "AC-6": "Least Privilege",
    "AC-7": "Unsuccessful Logon Attempts", "AU-2": "Event Logging",
    "AU-6": "Audit Record Review, Analysis, and Reporting", "AU-9": "Protection of Audit Information",
    "AU-12": "Audit Record Generation", "CM-2": "Baseline Configuration",
    "CM-3": "Configuration Change Control", "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality", "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-5": "Authenticator Management", "SC-7": "Boundary Protection", "SI-2": "Flaw Remediation",
    "SI-3": "Malicious Code Protection", "SI-4": "System Monitoring",
    "SI-7": "Software, Firmware, and Information Integrity",
}  # fmt: skip

DISCLAIMERS = {
    "observation": "This is a configuration observation taken from the assessment data. It does not by itself show malicious activity.",
    "indicator": "This is a suspicious indicator. Benign activity can produce the same observation; it does not prove compromise.",
    "correlated": "These independent indicators were correlated by a rule. Correlation raises a question; it does not prove malicious activity.",
    "hypothesis": "This is an unverified hypothesis built from incomplete information. Treat it as a lead to verify.",
}


@dataclass
class Match:
    subject: Subject
    trace: list[str]


@dataclass
class Context:
    """Everything one evaluation run reads. Subject lists are built once per source."""

    current: dict[str, Any]
    previous: list[Snap]
    comparison: dict[str, Any] | None
    comparison_note: str = ""
    telemetry: dict[str, Any] | None = None
    telemetry_base: dict[str, Any] | None = None
    telemetry_comparison: dict[str, Any] | None = None
    telemetry_note: str = ""
    history: HistoryView = field(init=False)
    _cache: dict[str, list[Subject]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.history = HistoryView(self.current, self.previous)
        self.evidence = {e["id"]: e for e in self.current["evidence"]}
        self.findings = {f["id"]: f for f in self.current["findings"]}
        self.base_doc = self.previous[-1].doc if self.previous else None
        self.base_evidence = (
            {e["id"]: e for e in self.base_doc["evidence"]} if self.base_doc else {}
        )
        self.base_findings = (
            {f["id"]: f for f in self.base_doc["findings"]} if self.base_doc else {}
        )
        self.hist_arg = self.history if self.previous else None

    def subjects(self, source: str) -> list[Subject]:
        if source not in self._cache:
            self._cache[source] = list(self._build(source))
        return self._cache[source]

    def _build(self, source: str) -> Iterable[Subject]:  # noqa: PLR0912
        cur, cmpd = self.current, self.comparison
        if source == "findings":
            for f in cur["findings"]:
                yield finding_subject(source, f, self.evidence, self.hist_arg)
        elif source == "inventory":
            for r in cur["inventory"]["records"]:
                yield inventory_subject(r)
        elif source == "snapshot":
            yield snapshot_subject(cmpd, self.hist_arg, cur)
        elif source == "telemetry":
            if self.telemetry is not None:
                index = ProcessIndex(self.telemetry["records"])
                for rec in self.telemetry["records"]:
                    yield telemetry_subject(rec, index)
        elif source == "telemetry_changes":
            if self.telemetry_comparison is not None and self.telemetry_base is not None:
                yield from telemetry_change_subjects(
                    self.telemetry_base, self.telemetry, self.telemetry_comparison
                )
        elif cmpd is None:
            return
        elif source == "new_findings":
            for b in cmpd["findings"]["new"]:
                if b["id"] in self.findings:
                    yield finding_subject(source, self.findings[b["id"]], self.evidence)
        elif source == "resolved_findings":
            for b in cmpd["findings"]["resolved"]:
                if b["id"] in self.base_findings:
                    yield finding_subject(source, self.base_findings[b["id"]], self.base_evidence)
        elif source in ("persistent_findings", "severity_increased"):
            for p in cmpd["findings"]["persistent"]:
                if source == "severity_increased" and p.get("direction") != "increased":
                    continue
                f = self.findings.get(p["id"])
                if f is None:
                    continue
                extra = {
                    "baseline_severity": p["baseline_severity"],
                    "baseline_severity_rank": SEVERITY_RANK[p["baseline_severity"]],
                    "evidence.added": [self.evidence[e]["ref"] for e in p["evidence"]["added"] if e in self.evidence],
                    "evidence.removed": [self.base_evidence[e]["ref"] for e in p["evidence"]["removed"] if e in self.base_evidence],
                }  # fmt: skip
                yield finding_subject(source, f, self.evidence, self.hist_arg, extra)
        elif source == "config_changes" and cmpd["configuration"]["available"]:
            for ch in cmpd["configuration"]["changes"]:
                yield change_subject(ch, self.hist_arg)


# ------------------------------------------------------------------------------ expressions


def eval_expr(expr: Any, matched: dict[str, bool]) -> bool:
    if isinstance(expr, str):
        return matched.get(expr, False)
    ((k, v),) = expr.items()
    if k == "not":
        return not eval_expr(v, matched)
    if k == "all":
        return all(eval_expr(e, matched) for e in v)
    return any(eval_expr(e, matched) for e in v)


def _adjust(base: str, rules: tuple[Adjust, ...], matched: dict[str, bool]) -> tuple[str, str]:
    for a in rules:
        if eval_expr(a.when, matched):
            return a.value, a.reason
    return base, ""


# ---------------------------------------------------------------------------------- coverage


def _module_ok(doc: dict[str, Any], name: str) -> tuple[bool, str]:
    mods = {m["id"]: m["status"] for m in doc["modules"]}
    if mods.get("imported.report") == OK:
        return True, ""
    for mid, st in mods.items():
        if mid == name or mid.endswith("." + name):
            return (st == OK, "" if st == OK else f"module {mid} finished as {st}")
    return False, f"module {name} was not run"


def _inventory_ok(doc: dict[str, Any], spec: str) -> tuple[bool, str]:
    domain, _, scope = spec.partition(":")
    parts = [
        c
        for c in doc["inventory"]["coverage"]
        if c["domain"] == domain and (not scope or c.get("scope", "") == scope)
    ]
    if not parts:
        return False, f"inventory {spec} was not collected"
    bad = [c for c in parts if c["status"] not in ("complete", "degraded")]
    return (
        not bad,
        "" if not bad else f"inventory {domain}/{bad[0].get('scope', '')} is {bad[0]['status']}",
    )


def _telemetry_ok(ctx: Context, spec: str, hard: list[str]) -> tuple[bool, str]:
    """Coverage of a telemetry category. Never collected is a hard stop (nothing can be
    concluded); partial coverage lets the rule run at lower confidence."""
    tel = ctx.telemetry
    if tel is None:
        hard.append("no telemetry was supplied")
        return True, ""
    cat, _, scope = spec.partition("/")
    parts = [
        c
        for c in tel["coverage"]
        if c["category"] == cat and (not scope or c.get("scope", "") == scope)
    ]
    if not parts:
        hard.append(f"telemetry category {spec} was not collected")
        return True, ""
    if all(c["status"] == "unavailable" for c in parts):
        hard.append(
            f"telemetry category {spec} could not be collected: {parts[0].get('reason', 'unavailable')}"
        )
        return True, ""
    bad = [c for c in parts if c["status"] not in ("complete", "not_applicable")]
    if not bad and ctx.telemetry_base is not None and ctx.telemetry_comparison is not None:
        # A change claim also depends on how completely the baseline saw the category.
        base_parts = [c for c in ctx.telemetry_base["coverage"] if c["category"] == cat]
        bad_base = [c for c in base_parts if c["status"] not in ("complete", "not_applicable")]
        if not base_parts or bad_base:
            why = bad_base[0]["status"] if bad_base else "not collected"
            return (
                False,
                f"the baseline telemetry for {spec} is {why}, so differences are not conclusive",
            )
    return (
        not bad,
        "" if not bad else f"telemetry {spec} is {bad[0]['status']}: {bad[0].get('reason', '')}",
    )


def check_coverage(rule: Rule, ctx: Context) -> tuple[list[str], list[str]]:
    """``(hard, soft)`` problems. Hard: the rule cannot be evaluated at all. Soft: it can, but
    absence cannot be concluded."""
    hard: list[str] = []
    soft: list[str] = []
    if "telemetry_changes" in rule.sources and ctx.telemetry_comparison is None:
        hard.append(ctx.telemetry_note or "no earlier telemetry snapshot to compare with")
    uses_comparison = bool(rule.sources & set(COMPARISON_SOURCES))
    if uses_comparison and ctx.comparison is None:
        hard.append(ctx.comparison_note or "no earlier snapshot to compare with")
    elif (
        "config_changes" in rule.sources
        and ctx.comparison
        and not ctx.comparison["configuration"]["available"]
    ):
        hard.append(
            "configuration comparison unavailable: "
            + ctx.comparison["configuration"].get("reason", "")
        )
    for req in rule.requires_coverage:
        kind, _, arg = req.partition(":")
        if kind == "module":
            ok, why = _module_ok(ctx.current, arg)
        elif kind == "inventory":
            ok, why = _inventory_ok(ctx.current, arg)
        elif kind == "telemetry":
            ok, why = _telemetry_ok(ctx, arg, hard)
        elif kind == "history":
            if ctx.history.count < int(arg):
                hard.append(f"needs {arg} earlier snapshot(s), have {ctx.history.count}")
            continue
        else:  # comparison / comparison:exists
            if ctx.comparison is None or arg == "exists":
                continue  # missing comparison is already reported as hard
            c = ctx.comparison
            ok = not c["findings"]["indeterminate"] and not c["summary"]["coverage_changes"]
            why = "the snapshot comparison has indeterminate findings or changed module coverage"
        if not ok:
            soft.append(why)
    return hard, soft


# --------------------------------------------------------------------------------- grouping


def _norm(value: Any, mode: str) -> list[str]:
    vals = value if isinstance(value, list) else [value]
    out = [str(v) for v in vals if v not in (None, "")]
    return [v.casefold() for v in out] if mode == "casefold" else out


def _clause_matches(clause: Clause, ctx: Context, notes: list[str]) -> list[Match]:
    out: list[Match] = []
    for s in ctx.subjects(clause.source):
        ok, trace = evaluate(clause.where, s.fields, explain=True)
        if ok:
            out.append(Match(s, trace))
            if len(out) >= MAX_ITEMS_PER_CLAUSE:
                notes.append(
                    f"clause {clause.id} matched more than {MAX_ITEMS_PER_CLAUSE} items; only the first were used"
                )
                break
    return out


def _satisfied(clause: Clause, items: list[Match]) -> bool:
    if len(items) < clause.min_matches:
        return False
    if clause.distinct:
        fld, need = clause.distinct
        vals = set()
        for m in items:
            v = m.subject.fields.get(fld)
            vals.update(str(x) for x in (v if isinstance(v, list) else [v]) if x not in (None, ""))
        return len(vals) >= need
    return bool(items)


def _groups(rule: Rule, hits: dict[str, list[Match]]) -> list[tuple[str, dict[str, list[Match]]]]:
    if rule.join_on is None:
        return [("*", hits)]
    keyed: dict[str, dict[str, list[Match]]] = {}
    for clause in rule.clauses:
        fld = clause.join_on or rule.join_on
        for m in hits[clause.id]:
            for v in _norm(m.subject.fields.get(fld), rule.join_mode):
                keyed.setdefault(v, {c.id: [] for c in rule.clauses})[clause.id].append(m)
    out = [(k, g) for k, g in sorted(keyed.items())]
    # An item with several join values appears in several groups; collapse identical groups.
    seen: set[tuple[str, ...]] = set()
    unique = []
    for k, g in out:
        sig = tuple(sorted(m.subject.uid for items in g.values() for m in items))
        if sig not in seen:
            seen.add(sig)
            unique.append((k, g))
    return unique


# ---------------------------------------------------------------------------------- building


def _render(template: str, first: dict[str, Subject | None], host: str) -> str:
    def sub(m: re.Match[str]) -> str:
        cid, fld = m.group(1), m.group(2)
        if cid == "host" and fld is None:
            return host
        s = first.get(cid)
        if s is None or fld is None:
            return "(none)"
        v = s.fields.get(fld)
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v[:3])
        return clean("(missing)" if v in (None, "") else v, 120)

    return clean(_TEMPLATE.sub(sub, template), 300)


def _item_json(clause: Clause, m: Match) -> dict[str, Any]:
    s = m.subject
    out: dict[str, Any] = {"clause": clause.id, **s.ref, "label": clean(s.label, 200)}
    if s.detail:
        out["detail"] = s.detail
    if s.severity:
        out["severity"] = s.severity
    return out


def _lower(conf: str) -> str:
    return _CONF[max(0, _CONF.index(conf) - 1)]


def _build_detection(  # noqa: PLR0912, PLR0915
    rule: Rule,
    key: str,
    group: dict[str, list[Match]],
    ctx: Context,
    soft: list[str],
    generated_at: str,
) -> dict[str, Any]:
    host = ctx.current["host"]
    hid = host_id(host["hostname"], host["os"]["family"])
    matched = {c.id: _satisfied(c, group[c.id]) for c in rule.clauses}
    sev, sev_why = _adjust(rule.severity, rule.severity_rules, matched)
    conf, conf_why = _adjust(rule.confidence, rule.confidence_rules, matched)
    caveats: list[str] = []
    if soft:
        conf = _lower(conf)
        caveats += [f"Coverage incomplete: {w}" for w in soft]
        caveats.append(
            "Confidence was lowered one step because the data behind this rule is incomplete."
        )
    if ctx.comparison and ctx.comparison["warnings"] and (rule.sources & set(COMPARISON_SOURCES)):
        caveats += [
            f"Comparison warning {w['code']}: {w['message']}"
            for w in ctx.comparison["warnings"][:3]
        ]
    uids = sorted(m.subject.uid for c in rule.clauses for m in group[c.id])
    did = (
        "DT-"
        + hashlib.sha256(
            "\0".join(["blueops/detection/v1", rule.id, hid, key, *uids]).encode()
        ).hexdigest()[:16]
    )
    first = {c.id: (group[c.id][0].subject if group[c.id] else None) for c in rule.clauses}
    contributing, evidence_ids, components, matched_conditions = [], [], set(), []
    truncated = 0
    for c in rule.clauses:
        items = group[c.id]
        components.update(m.subject.component for m in items if m.subject.component)
        for m in items[:MAX_LISTED_PER_CLAUSE]:
            contributing.append(_item_json(c, m))
            for e in m.subject.evidence_ids:
                if e in ctx.evidence and e not in evidence_ids:
                    evidence_ids.append(e)
        truncated += max(0, len(items) - MAX_LISTED_PER_CLAUSE)
        if items:
            matched_conditions.append({"clause": c.id, "description": c.description, "optional": c.optional,
                                       "matched_items": len(items), "conditions": items[0].trace[:12]})  # fmt: skip
    present = [c for c in rule.clauses if matched[c.id]]
    why = (
        f"Rule {rule.id} requires: {_require_text(rule)}. Satisfied clauses: "
        + (", ".join(f"{c.id} ({len(group[c.id])} item(s))" for c in present) or "none")
        + "."
    )
    if key != "*" and rule.join_on:
        if len(rule.clauses) == 1 and not rule.clauses[0].join_on:
            why += f" Each matching item is reported separately (grouped by {rule.join_on} = {clean(key, 120)!r})."
        else:
            why += f" The contributing items were grouped because they share {rule.join_on} = {clean(key, 120)!r}."
    missing = [
        f"Optional corroboration not observed: {c.description}"
        for c in rule.clauses
        if c.optional and not matched[c.id]
    ]
    missing += list(rule.confidence_boosters)
    if sev_why:
        sev_text = f"Severity {sev} was set by an explicit rule condition: {sev_why}"
    else:
        sev_text = f"Severity {sev} is the rule's base severity: {rule.severity_reason} The number of matching items did not change it."
    conf_text = f"Confidence {conf}: " + (conf_why or rule.confidence_reason)
    attack = [
        {"id": a["id"], "relationship": a["relationship"], "explanation": a["explanation"], "url": attack_url(a["id"])}
        for a in rule.references.get("attack", [])
    ]  # fmt: skip
    nist = [{"id": n, "title": NIST_TITLES.get(n, "")} for n in rule.references.get("nist", [])]
    if truncated:
        caveats.append(f"{truncated} further matching item(s) are not listed.")
    return {
        "id": did,
        "rule": {"id": rule.id, "name": rule.name, "version": rule.version, "pack": rule.pack},
        "title": _render(rule.title, first, host["hostname"]),
        "description": rule.description,
        "severity": sev,
        "confidence": conf,
        "nature": rule.nature,
        "category": rule.category,
        "detected_at": generated_at,
        "host": {"hostname": host["hostname"], "host_id": hid},
        "components": sorted(components | {rule.category}),
        "contributing": contributing,
        "evidence": evidence_ids,
        "matched_conditions": matched_conditions,
        "explanation": {
            "why_flagged": rule.rationale,
            "why_correlated": why,
            "severity_rationale": sev_text,
            "confidence_rationale": conf_text,
            "missing_corroboration": missing,
            "possible_benign_causes": list(rule.false_positives),
            "caveats": caveats,
            "disclaimer": DISCLAIMERS[rule.nature],
        },
        "investigation_steps": list(rule.investigation),
        "remediation": rule.remediation,
        "references": {"attack": attack, "nist": nist, "other": list(rule.references.get("other", []))},
    }  # fmt: skip


def _require_text(rule: Rule) -> str:
    def t(e: Any) -> str:
        if isinstance(e, str):
            return e
        ((k, v),) = e.items()
        return f"not {t(v)}" if k == "not" else "(" + f" {k} ".join(t(x) for x in v) + ")"

    return t(rule.require)


# ----------------------------------------------------------------------------------- driver


def evaluate_rule(
    rule: Rule, ctx: Context, generated_at: str
) -> tuple[str, list[dict[str, Any]], str]:
    """Returns ``(status, detections, reason)``; status is ``evaluated`` or ``indeterminate``."""
    hard, soft = check_coverage(rule, ctx)
    if hard:
        return "indeterminate", [], "; ".join(hard)
    notes: list[str] = []
    hits = {c.id: _clause_matches(c, ctx, notes) for c in rule.clauses}
    detections = []
    for key, group in _groups(rule, hits):
        matched = {c.id: _satisfied(c, group[c.id]) for c in rule.clauses}
        if eval_expr(rule.require, matched):
            detections.append(_build_detection(rule, key, group, ctx, soft, generated_at))
            if len(detections) >= MAX_DETECTIONS_PER_RULE:
                notes.append(
                    f"rule produced more than {MAX_DETECTIONS_PER_RULE} detections; the rest were dropped"
                )
                break
    if soft and not detections:
        return "indeterminate", [], "; ".join(soft)
    if soft and _uses_not(rule):
        return "indeterminate", [], "absence cannot be concluded: " + "; ".join(soft)
    if notes:
        for d in detections:
            d["explanation"]["caveats"] += notes
    return "evaluated", detections, ""


def _uses_not(rule: Rule) -> bool:
    return expr_uses_not(rule.require)


def detect(  # noqa: PLR0912, PLR0915
    current: dict[str, Any],
    rule_set: RuleSet,
    *,
    previous: list[Snap] | None = None,
    generated_at: str,
    history_notes: list[dict[str, str]] | None = None,
    telemetry: dict[str, Any] | None = None,
    telemetry_baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run every enabled, applicable rule; returns the ``detection-results`` document."""
    host = current["host"]
    prev = list(previous or [])
    comparison = None
    comparison_note = ""
    if prev:
        try:
            comparison = compare_snapshots(prev[-1].doc, current, generated_at=generated_at)
        except ComparisonError as exc:
            comparison_note = f"snapshot comparison failed: {exc}"
    tel_cmp = None
    tel_note = ""
    if telemetry is not None:
        if telemetry["host"]["host_id"] != host_id(host["hostname"], host["os"]["family"]):
            raise ValueError("the telemetry describes a different host than the assessment")
        if telemetry_baseline is not None:
            try:
                tel_cmp = compare_telemetry(
                    telemetry_baseline, telemetry, generated_at=generated_at
                )
            except CompareError as exc:
                tel_note = f"telemetry comparison failed: {exc}"
    ctx = Context(
        current, prev, comparison, comparison_note,
        telemetry=telemetry, telemetry_base=telemetry_baseline,
        telemetry_comparison=tel_cmp, telemetry_note=tel_note,
    )  # fmt: skip
    detections: list[dict[str, Any]] = []
    indeterminate: list[dict[str, Any]] = []
    rule_results: list[dict[str, Any]] = []
    rule_errors: list[dict[str, str]] = [
        {"rule": d.rule or "-", "code": "RULE_INVALID", "message": f"{d.path}: {d.message}"[:400]}
        for d in rule_set.errors
    ]
    family = host["os"]["family"]
    counts = {"evaluated": 0, "disabled": 0, "not_applicable": 0, "indeterminate": 0, "error": 0}
    for rule in rule_set.ordered():
        if not rule.enabled:
            counts["disabled"] += 1
            rule_results.append({"rule": rule.id, "status": "disabled", "detections": 0})
            continue
        if not rule.applies_to(family):
            counts["not_applicable"] += 1
            rule_results.append({"rule": rule.id, "status": "not_applicable", "detections": 0})
            continue
        skip = ""
        if rule.sources & set(TELEMETRY_SOURCES) and telemetry is None:
            skip = "no telemetry supplied"  # hunting was never asked for
        elif "telemetry_changes" in rule.sources and telemetry_baseline is None:
            skip = "no telemetry baseline supplied"
        if skip:
            counts["not_applicable"] += 1
            rule_results.append(
                {"rule": rule.id, "status": "not_applicable", "detections": 0, "reason": skip}
            )
            continue
        try:
            status, found, reason = evaluate_rule(rule, ctx, generated_at)
        except Exception as exc:  # noqa: BLE001 - a rule must never take down the others; recorded below
            counts["error"] += 1
            rule_errors.append(
                {
                    "rule": rule.id,
                    "code": "RULE_FAILED",
                    "message": f"{type(exc).__name__}: {exc}"[:400],
                }
            )
            rule_results.append({"rule": rule.id, "status": "error", "detections": 0})
            continue
        counts[status] += 1
        rule_results.append(
            {
                "rule": rule.id,
                "status": status,
                "detections": len(found),
                **({"reason": reason} if reason else {}),
            }
        )
        if status == "indeterminate":
            indeterminate.append(
                {
                    "rule": {"id": rule.id, "name": rule.name},
                    "reason": reason,
                    "nature": rule.nature,
                    "category": rule.category,
                }
            )
        detections += found
    seen: set[str] = set()
    uniq = []
    for d in detections:
        if d["id"] not in seen:
            seen.add(d["id"])
            uniq.append(d)
    if len(uniq) > MAX_DETECTIONS:
        rule_errors.append(
            {
                "rule": "-",
                "code": "DETECTIONS_TRUNCATED",
                "message": f"more than {MAX_DETECTIONS} detections; the rest were dropped",
            }
        )
        uniq = uniq[:MAX_DETECTIONS]
    uniq.sort(
        key=lambda d: (
            -SEVERITY_RANK[d["severity"]],
            -_CONF.index(d["confidence"]),
            d["rule"]["id"],
            d["id"],
        )
    )
    out = {
        "schema_version": RULES_SCHEMA_VERSION,
        "kind": "detection-results",
        "generated_at": generated_at,
        "engine": {"name": RULES_ENGINE_NAME, "version": RULES_ENGINE_VERSION},
        "host": {"hostname": host["hostname"], "host_id": host_id(host["hostname"], family), "os_family": family},
        "assessment": {"id": current["assessment"]["id"], "started_at": current["assessment"]["started_at"], "finished_at": current["assessment"]["finished_at"], "profile": current["assessment"]["profile"]},
        "history": {
            "snapshots": len(prev),
            "compared_with": prev[-1].doc["assessment"]["id"] if comparison else None,
            "comparison_trend": comparison["summary"]["trend"] if comparison else None,
            "excluded": list(history_notes or [])[:50],
        },
        "rule_packs": rule_set.packs,
        "rules": {"total": len(rule_set.rules), **counts},
        "rule_results": rule_results,
        "detections": uniq,
        "indeterminate": indeterminate,
        "rule_errors": rule_errors,
        "summary": _summary(uniq, indeterminate, rule_errors),
        **({"telemetry": _telemetry_block(telemetry, telemetry_baseline, tel_cmp)} if telemetry else {}),
    }  # fmt: skip
    # Provenance: every input the results were derived from, with its own verification status.
    groups = [entries("assessment", current)]
    groups += [entries("history", s.doc, source=s.source) for s in prev]
    if telemetry is not None:
        groups.append(entries("telemetry", telemetry))
    if telemetry_baseline is not None:
        groups.append(entries("telemetry-baseline", telemetry_baseline))
    return stamp(out, *groups)


def _telemetry_block(
    tel: dict[str, Any], base: dict[str, Any] | None, cmp_: dict[str, Any] | None
) -> dict[str, Any]:
    return {
        "collection_id": tel["collection"]["id"],
        "started_at": tel["collection"]["started_at"],
        "records": tel["summary"]["records"],
        "complete": tel["summary"]["complete"],
        "coverage": tel["summary"]["coverage"],
        "unavailable": sorted(
            {c["category"] for c in tel["coverage"] if c["status"] == "unavailable"}
        ),
        "compared_with": base["collection"]["id"] if cmp_ and base else None,
    }


def _summary(
    dets: list[dict[str, Any]], ind: list[dict[str, Any]], errors: list[dict[str, str]]
) -> dict[str, Any]:
    def tally(key: str, order: Iterable[str] | None = None) -> dict[str, int]:
        out: dict[str, int] = dict.fromkeys(order, 0) if order else {}
        for d in dets:
            out[d[key]] = out.get(d[key], 0) + 1
        return dict(sorted(out.items())) if not order else out

    return {
        "total": len(dets),
        "by_severity": tally("severity", ("info", "low", "medium", "high", "critical")),
        "by_confidence": tally("confidence", _CONF),
        "by_nature": tally("nature", ("observation", "indicator", "correlated", "hypothesis")),
        "by_category": tally("category"),
        "indeterminate": len(ind),
        "rule_errors": len(errors),
    }


def exit_code_for(results: dict[str, Any], fail_on: str = "medium") -> ExitCode:
    """4 when a detection reaches ``fail_on`` (wins), 6 when rules were indeterminate or failed."""
    threshold = Severity.parse(fail_on)
    if any(Severity.parse(d["severity"]) >= threshold for d in results["detections"]):
        return ExitCode.FINDINGS
    if results["indeterminate"] or results["rule_errors"]:
        return ExitCode.PARTIAL
    return ExitCode.OK
