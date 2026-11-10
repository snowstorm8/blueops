"""Rule validation: structure (JSON Schema) and meaning (fields, references, safety).

Validation never raises for a bad rule: it returns diagnostics with a path, so an author sees
every problem at once and the loader can exclude just the broken rule ("fail safely").
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from typing import Any

from shared.reporting.schema_lite import Validator, load_schema, validate
from shared.rules.conditions import ConditionError, Node, compile_condition
from shared.rules.model import Adjust, Clause, Rule
from shared.rules.subjects import COMPARISON_SOURCES, FIELDS, field_known

_TEMPLATE = re.compile(r"\{([a-z][a-z0-9_]*)(?:\.([A-Za-z0-9_.*-]+))?\}")
_HISTORY_NEEDS = "history:"
SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")
MAX_RULES = 2000


@dataclass(frozen=True)
class Diagnostic:
    level: str  # "error" | "warning"
    path: str
    message: str
    rule: str = ""

    def __str__(self) -> str:
        who = f"{self.rule}: " if self.rule else ""
        return f"{self.level}: {who}{self.path}: {self.message}"


_RULE_VALIDATOR: Validator | None = None


def _rule_validator() -> Validator:
    global _RULE_VALIDATOR  # noqa: PLW0603 - cached compiled schema
    if _RULE_VALIDATOR is None:
        schema = load_schema("detection-rule.schema.json")
        _RULE_VALIDATOR = Validator({"$ref": "#/$defs/rule", "$defs": schema["$defs"]})
    return _RULE_VALIDATOR


def _suggest(word: str, options: tuple[str, ...] | list[str]) -> str:
    close = difflib.get_close_matches(word, list(options), n=1)
    return f" (did you mean {close[0]!r}?)" if close else ""


def check_expr(
    expr: Any, ids: set[str], path: str, out: list[Diagnostic], rid: str, depth: int = 0
) -> None:
    """Validate a boolean expression over clause ids."""
    if depth > 8:
        out.append(Diagnostic("error", path, "expression nested too deeply", rid))
        return
    if isinstance(expr, str):
        if expr not in ids:
            out.append(
                Diagnostic(
                    "error", path, f"unknown clause {expr!r}{_suggest(expr, sorted(ids))}", rid
                )
            )
        return
    if isinstance(expr, dict) and len(expr) == 1:
        ((k, v),) = expr.items()
        if k == "not":
            check_expr(v, ids, f"{path}.not", out, rid, depth + 1)
            return
        if k in ("all", "any") and isinstance(v, list) and v:
            for i, e in enumerate(v):
                check_expr(e, ids, f"{path}.{k}[{i}]", out, rid, depth + 1)
            return
    out.append(
        Diagnostic(
            "error",
            path,
            "expected a clause id or one of {all: [...]}, {any: [...]}, {not: e}",
            rid,
        )
    )


def expr_uses_not(expr: Any) -> bool:
    if isinstance(expr, dict):
        return any(k == "not" or expr_uses_not(v) for k, v in expr.items())
    if isinstance(expr, list):
        return any(expr_uses_not(e) for e in expr)
    return False


def _check_template(
    text: str, clause_sources: dict[str, str], path: str, out: list[Diagnostic], rid: str
) -> None:
    for m in _TEMPLATE.finditer(text):
        cid, fld = m.group(1), m.group(2)
        if cid == "host" and fld is None:
            continue
        if cid not in clause_sources or fld is None:
            out.append(
                Diagnostic(
                    "error",
                    path,
                    f"unknown placeholder {m.group(0)!r} (use {{host}} or {{clause.field}})",
                    rid,
                )
            )
        elif not field_known(clause_sources[cid], fld):
            out.append(
                Diagnostic(
                    "error",
                    path,
                    f"placeholder field {fld!r} does not exist for source {clause_sources[cid]!r}",
                    rid,
                )
            )


def _compile_clause(c: dict[str, Any], path: str, out: list[Diagnostic], rid: str) -> Clause | None:
    where = c.get("where")
    if where is None:
        out.append(
            Diagnostic(
                "error",
                f"{path}.where",
                "required: a clause without a condition would match everything",
                rid,
            )
        )
        return None
    try:
        node: Node = compile_condition(where, f"{path}.where")
    except ConditionError as exc:
        text = str(exc)
        p, _, msg = text.partition(": ")
        out.append(Diagnostic("error", p, msg, rid))
        return None
    ok = True
    for fld in sorted(node.fields):
        if not field_known(c["source"], fld):
            hint = _suggest(fld, FIELDS.get(c["source"], ()))
            out.append(
                Diagnostic(
                    "error",
                    f"{path}.where",
                    f"field {fld!r} does not exist for source {c['source']!r}{hint}",
                    rid,
                )
            )
            ok = False
    distinct = c.get("distinct")
    if distinct and not field_known(c["source"], distinct["field"]):
        out.append(
            Diagnostic(
                "error",
                f"{path}.distinct.field",
                f"field {distinct['field']!r} does not exist for source {c['source']!r}",
                rid,
            )
        )
        ok = False
    if c.get("join_on") and not field_known(c["source"], c["join_on"]):
        out.append(
            Diagnostic(
                "error",
                f"{path}.join_on",
                f"field {c['join_on']!r} does not exist for source {c['source']!r}",
                rid,
            )
        )
        ok = False
    if not ok:
        return None
    return Clause(
        id=c["id"], source=c["source"], description=c["description"], where=node, where_json=where,
        optional=bool(c.get("optional", False)), min_matches=int(c.get("min_matches", 1)),
        distinct=(distinct["field"], int(distinct["count"])) if distinct else None,
        join_on=c.get("join_on"),
    )  # fmt: skip


def _adjusts(
    items: list[dict[str, Any]] | None,
    allowed: tuple[str, ...],
    ids: set[str],
    path: str,
    out: list[Diagnostic],
    rid: str,
) -> tuple[Adjust, ...]:
    res = []
    for i, a in enumerate(items or []):
        check_expr(a["when"], ids, f"{path}[{i}].when", out, rid)
        if a["value"] not in allowed:
            out.append(
                Diagnostic(
                    "error", f"{path}[{i}].value", f"must be one of {', '.join(allowed)}", rid
                )
            )
        res.append(Adjust(a["when"], a["value"], a["reason"]))
    return tuple(res)


def compile_rule(raw: dict[str, Any], pack: str = "") -> tuple[Rule | None, list[Diagnostic]]:  # noqa: PLR0912, PLR0915
    """Validate and compile one rule. ``Rule`` is ``None`` when any error was found."""
    rid = str(raw.get("id", "?")) if isinstance(raw, dict) else "?"
    out: list[Diagnostic] = []
    if not isinstance(raw, dict):
        return None, [Diagnostic("error", "rule", "a rule must be an object")]
    for v in _rule_validator().iter_errors(raw):
        out.append(Diagnostic("error", v.path or "rule", v.message, rid))
    if out:
        return None, out
    clauses_raw = raw["clauses"]
    ids = [c["id"] for c in clauses_raw]
    if len(set(ids)) != len(ids):
        out.append(Diagnostic("error", "clauses", "clause ids must be unique", rid))
    id_set = set(ids)
    clauses = [_compile_clause(c, f"clauses[{i}]", out, rid) for i, c in enumerate(clauses_raw)]
    require = raw.get("require")
    if require is None:
        required = [c["id"] for c in clauses_raw if not c.get("optional")]
        require = required[0] if len(required) == 1 else {"all": required}
        if not required:
            out.append(
                Diagnostic("error", "clauses", "at least one clause must not be optional", rid)
            )
    else:
        check_expr(require, id_set, "require", out, rid)
    sev_rules = _adjusts(raw.get("severity_rules"), SEVERITIES, id_set, "severity_rules", out, rid)
    conf_rules = _adjusts(
        raw.get("confidence_rules"), CONFIDENCES, id_set, "confidence_rules", out, rid
    )
    sources = {c["id"]: c["source"] for c in clauses_raw}
    _check_template(raw["title"], sources, "title", out, rid)
    join = raw.get("join")
    if join:
        for i, c in enumerate(clauses_raw):
            fld = c.get("join_on") or join["on"]
            if c["source"] == "snapshot":
                out.append(
                    Diagnostic(
                        "error",
                        f"clauses[{i}]",
                        "a snapshot clause cannot take part in a join",
                        rid,
                    )
                )
            elif not field_known(c["source"], fld):
                out.append(
                    Diagnostic(
                        "error",
                        "join.on",
                        f"field {fld!r} does not exist for source {c['source']!r} (clause {c['id']})",
                        rid,
                    )
                )
    # semantic consistency
    required_ids = [c["id"] for c in clauses_raw if not c.get("optional")]
    multi = len(required_ids) > 1 or any(c.get("distinct") for c in clauses_raw)
    if raw["nature"] == "observation" and multi:
        out.append(
            Diagnostic(
                "error",
                "nature",
                "an 'observation' reports one confirmed fact; a multi-clause rule is 'correlated' or 'hypothesis'",
                rid,
            )
        )
    if raw["nature"] == "correlated" and not multi:
        out.append(
            Diagnostic(
                "error",
                "nature",
                "'correlated' needs at least two required clauses or a distinct-count clause",
                rid,
            )
        )
    coverage = raw.get("requires_coverage", [])
    uses_comparison = bool(set(sources.values()) & set(COMPARISON_SOURCES))
    if uses_comparison and not any(c.startswith("comparison") for c in coverage):
        out.append(
            Diagnostic(
                "error",
                "requires_coverage",
                "rules that read snapshot changes must declare 'comparison'",
                rid,
            )
        )
    uses_history = any(f.startswith("history.") for c in clauses if c for f in c.where.fields)
    if (
        uses_history
        and not any(x.startswith(_HISTORY_NEEDS) for x in coverage)
        and not any(c.startswith("comparison") for c in coverage)
    ):
        out.append(
            Diagnostic(
                "error",
                "requires_coverage",
                "rules that read history fields must declare 'history:N'",
                rid,
            )
        )
    if expr_uses_not(require) and not coverage:
        out.append(
            Diagnostic(
                "error",
                "requires_coverage",
                "a rule that concludes from absence ('not') must declare the coverage it needs",
                rid,
            )
        )
    refs = raw.get("references", {})
    if raw["nature"] in ("hypothesis",) and any(
        a["relationship"] == "direct" for a in refs.get("attack", [])
    ):
        out.append(
            Diagnostic(
                "error",
                "references.attack",
                "a hypothesis cannot claim a direct ATT&CK relationship",
                rid,
            )
        )
    ex = raw["examples"]
    expects = {e["expect"] for e in ex}
    if "match" not in expects and "indeterminate" not in expects:
        out.append(
            Diagnostic("error", "examples", "needs at least one example that expects a match", rid)
        )
    if "no_match" not in expects:
        out.append(
            Diagnostic(
                "error", "examples", "needs at least one negative example (expect: no_match)", rid
            )
        )
    if "any" in raw["platforms"] and len(raw["platforms"]) > 1:
        out.append(
            Diagnostic("error", "platforms", "'any' cannot be combined with a named platform", rid)
        )
    if any(d.level == "error" for d in out) or any(c is None for c in clauses):
        return None, out
    rule = Rule(
        id=raw["id"], version=raw["version"], name=raw["name"], description=raw["description"],
        enabled=bool(raw.get("enabled", True)), platforms=tuple(raw["platforms"]), category=raw["category"],
        severity=raw["severity"], severity_reason=raw["severity_reason"], severity_rules=sev_rules,
        confidence=raw["confidence"], confidence_reason=raw["confidence_reason"], confidence_rules=conf_rules,
        nature=raw["nature"], requires_coverage=tuple(coverage),
        clauses=tuple(c for c in clauses if c is not None), require=require,
        join_on=join["on"] if join else None, join_mode=join.get("mode", "casefold") if join else "casefold",
        title=raw["title"], rationale=raw["rationale"],
        false_positives=tuple(raw.get("false_positives", [])),
        confidence_boosters=tuple(raw.get("confidence_boosters", [])),
        investigation=tuple(raw["investigation"]), remediation=raw["remediation"],
        references=refs, examples=tuple(ex), pack=pack, raw=raw,
    )  # fmt: skip
    return rule, out


def validate_pack(doc: Any, source: str = "") -> tuple[list[Rule], list[Diagnostic]]:
    """Compile every rule of a parsed pack; invalid rules are excluded and reported."""
    diags: list[Diagnostic] = []
    if not isinstance(doc, dict):
        return [], [Diagnostic("error", "pack", f"{source}: top level must be an object")]
    skeleton = {k: v for k, v in doc.items() if k != "rules"}
    skeleton["rules"] = []
    for msg in validate(skeleton, "detection-rule.schema.json", limit=10):
        diags.append(Diagnostic("error", "pack", msg))
    rules_raw = doc.get("rules")
    if diags or not isinstance(rules_raw, list):
        if not isinstance(rules_raw, list):
            diags.append(Diagnostic("error", "rules", "must be a list"))
        return [], diags
    if len(rules_raw) > MAX_RULES:
        return [], [Diagnostic("error", "rules", f"more than {MAX_RULES} rules in one pack")]
    rules: list[Rule] = []
    seen: set[str] = set()
    pack_name = doc["pack"]["name"]
    for i, raw in enumerate(rules_raw):
        rule, d = compile_rule(raw, pack_name)
        diags += [Diagnostic(x.level, f"rules[{i}].{x.path}", x.message, x.rule) for x in d]
        if rule is None:
            continue
        if rule.id in seen:
            diags.append(
                Diagnostic("error", f"rules[{i}].id", "duplicate rule id in pack", rule.id)
            )
            continue
        seen.add(rule.id)
        rules.append(rule)
    return rules, diags
