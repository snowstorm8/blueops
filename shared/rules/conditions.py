"""Condition language: compile once, evaluate many times, explain what matched.

A condition is JSON:

    {"field": "severity", "op": "in", "value": ["high", "critical"]}      # leaf
    {"all": [c1, c2]}  {"any": [c1, c2]}  {"not": c}                       # compound

Leaves read a dotted field of the *subject* (a finding, inventory record, change ...) given as a
flat ``dict``. Semantics that matter for correctness:

* A **missing** field (absent, ``None``, empty string or empty list) makes every comparison false,
  including ``ne`` and ``not_in``. Absence is only ever tested explicitly with ``missing`` /
  ``present``. This prevents "unknown" from being read as "different".
* A **list** field matches if *any* element matches (``len_*`` and ``missing`` look at the list).
* Numbers compare numerically when both sides coerce; strings compare as text.
* Regular expressions use ``re.search`` on inputs capped at ``MAX_TEXT`` characters; patterns are
  length-capped and patterns with nested quantifiers (a common catastrophic-backtracking shape)
  are rejected at validation time. This is a mitigation, not a proof of linear-time matching.

``evaluate`` returns the boolean and, when asked, the list of *leaf conditions that were true* so
a detection can say exactly which conditions matched.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

MAX_TEXT = 4096
MAX_PATTERN = 300
MAX_DEPTH = 12
MAX_NODES = 200
MAX_SET = 500

LEAF_OPS = (
    "eq", "ne", "ieq", "contains", "icontains", "startswith", "endswith", "regex",
    "gt", "gte", "lt", "lte", "in", "not_in", "missing", "present", "is_true", "is_false",
    "len_eq", "len_gte", "len_lte",
)  # fmt: skip
NO_VALUE_OPS = ("missing", "present", "is_true", "is_false")
SET_OPS = ("in", "not_in")
NUMERIC_OPS = ("gt", "gte", "lt", "lte", "len_eq", "len_gte", "len_lte")
STRING_OPS = ("contains", "icontains", "startswith", "endswith", "regex", "ieq")

_NESTED_QUANT = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


class ConditionError(ValueError):
    """A condition is malformed (raised by ``compile_condition`` with a path in the message)."""


def _is_missing(v: Any) -> bool:
    return v is None or v == "" or (isinstance(v, (list, tuple)) and len(v) == 0)


def _items(v: Any) -> list[Any]:
    return list(v) if isinstance(v, (list, tuple)) else [v]


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v.strip())
        except ValueError:
            return None
    return None


def _text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)[:MAX_TEXT]


def _bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"
    return None


def check_pattern(pattern: str) -> str | None:
    """A problem with a regex pattern, or ``None`` when it is acceptable."""
    if len(pattern) > MAX_PATTERN:
        return f"pattern longer than {MAX_PATTERN} characters"
    if _NESTED_QUANT.search(pattern):
        return "nested quantifier (risk of catastrophic backtracking)"
    try:
        re.compile(pattern)
    except re.error as exc:
        return f"invalid regular expression: {exc}"
    return None


def _equal(field: Any, value: Any) -> bool:
    a, b = _num(field), _num(value)
    if a is not None and b is not None and not isinstance(value, str):
        return a == b
    if isinstance(value, bool):
        return _bool(field) is value
    return _text(field) == _text(value)


def _leaf_any(op: str, value: Any, rx: re.Pattern[str] | None) -> Callable[[Any], bool]:  # noqa: PLR0911, PLR0912
    """Predicate over ONE field element (not missing)."""
    if op == "eq":
        return lambda x: _equal(x, value)
    if op == "ne":
        return lambda x: not _equal(x, value)
    if op == "ieq":
        return lambda x: _text(x).casefold() == _text(value).casefold()
    if op == "contains":
        return lambda x: _text(value) in _text(x)
    if op == "icontains":
        return lambda x: _text(value).casefold() in _text(x).casefold()
    if op == "startswith":
        return lambda x: _text(x).startswith(_text(value))
    if op == "endswith":
        return lambda x: _text(x).endswith(_text(value))
    if op == "regex":
        assert rx is not None  # noqa: S101 - compile_condition always supplies it
        return lambda x: rx.search(_text(x)) is not None
    if op in ("gt", "gte", "lt", "lte"):
        limit = float(value)

        def cmp(x: Any) -> bool:
            n = _num(x)
            if n is None:
                return False
            return {"gt": n > limit, "gte": n >= limit, "lt": n < limit, "lte": n <= limit}[op]

        return cmp
    if op == "in":
        allowed = {_text(v).casefold() if isinstance(v, str) else _text(v) for v in value}
        return lambda x: (_text(x).casefold() if isinstance(x, str) else _text(x)) in allowed
    if op == "not_in":
        banned = {_text(v).casefold() if isinstance(v, str) else _text(v) for v in value}
        return lambda x: (_text(x).casefold() if isinstance(x, str) else _text(x)) not in banned
    raise ConditionError(f"unknown operator {op!r}")


@dataclass
class Node:
    """A compiled condition: ``run(subject, trace)`` -> bool; trace collects true leaf texts."""

    run: Callable[[dict[str, Any], list[str] | None], bool]
    text: str
    fields: frozenset[str]


def describe_leaf(field: str, op: str, value: Any) -> str:
    if op in NO_VALUE_OPS:
        return f"{field} {op}"
    shown = value if isinstance(value, (int, float, bool)) else repr(value)
    if isinstance(value, list):
        shown = (
            "[" + ", ".join(repr(v) for v in value[:6]) + (", ..." if len(value) > 6 else "") + "]"
        )
    return f"{field} {op} {shown}"


def compile_condition(  # noqa: PLR0912, PLR0915 - one flat dispatch over the grammar
    cond: Any, path: str = "where", _depth: int = 0, _count: list[int] | None = None
) -> Node:
    """Compile ``cond``; raises ``ConditionError`` naming the offending path."""
    count = _count if _count is not None else [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise ConditionError(f"{path}: condition has more than {MAX_NODES} nodes")
    if _depth > MAX_DEPTH:
        raise ConditionError(f"{path}: nesting deeper than {MAX_DEPTH}")
    if not isinstance(cond, dict) or not cond:
        raise ConditionError(f"{path}: a condition must be a non-empty object")
    keys = set(cond)
    if keys & {"all", "any", "not"}:
        if len(keys) != 1:
            raise ConditionError(f"{path}: use exactly one of all / any / not per object")
        (kind,) = keys
        if kind == "not":
            child = compile_condition(cond["not"], f"{path}.not", _depth + 1, count)
            neg_text = f"not ({child.text})"

            def run_not(s: dict[str, Any], t: list[str] | None) -> bool:
                if child.run(s, None):
                    return False
                if t is not None:
                    t.append(neg_text)
                return True

            return Node(run_not, neg_text, child.fields)
        subs = cond[kind]
        if not isinstance(subs, list) or not subs:
            raise ConditionError(f"{path}.{kind}: expected a non-empty list")
        nodes = [
            compile_condition(c, f"{path}.{kind}[{i}]", _depth + 1, count)
            for i, c in enumerate(subs)
        ]
        fields = frozenset().union(*(n.fields for n in nodes))
        text = f" {kind} ".join(f"({n.text})" for n in nodes)
        if kind == "all":

            def run_all(s: dict[str, Any], t: list[str] | None) -> bool:
                local: list[str] = []
                for n in nodes:
                    if not n.run(s, local):
                        return False
                if t is not None:
                    t.extend(local)
                return True

            return Node(run_all, text, fields)

        def run_any(s: dict[str, Any], t: list[str] | None) -> bool:
            for n in nodes:
                local: list[str] = []
                if n.run(s, local):
                    if t is not None:
                        t.extend(local)
                    return True
            return False

        return Node(run_any, text, fields)

    unknown = keys - {"field", "op", "value"}
    if unknown:
        raise ConditionError(f"{path}: unexpected key(s) {sorted(unknown)} in a leaf condition")
    field, op = cond.get("field"), cond.get("op")
    if not isinstance(field, str) or not field:
        raise ConditionError(f"{path}.field: required, a dotted field name")
    if op not in LEAF_OPS:
        hint = _suggest(str(op), LEAF_OPS)
        raise ConditionError(f"{path}.op: unknown operator {op!r}{hint}")
    value = cond.get("value")
    if op in NO_VALUE_OPS:
        if "value" in cond:
            raise ConditionError(f"{path}.value: operator {op!r} takes no value")
    elif "value" not in cond:
        raise ConditionError(f"{path}.value: operator {op!r} requires a value")
    rx = None
    if op == "regex":
        if not isinstance(value, str):
            raise ConditionError(f"{path}.value: a regex must be a string")
        problem = check_pattern(value)
        if problem:
            raise ConditionError(f"{path}.value: {problem}")
        rx = re.compile(value)
    elif op in SET_OPS:
        if not isinstance(value, list) or not value or len(value) > MAX_SET:
            raise ConditionError(f"{path}.value: expected a list of 1..{MAX_SET} values")
        if any(isinstance(v, (dict, list)) for v in value):
            raise ConditionError(f"{path}.value: set members must be scalars")
    elif op in NUMERIC_OPS:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConditionError(f"{path}.value: operator {op!r} needs a number")
    elif op in STRING_OPS and not isinstance(value, str):
        raise ConditionError(f"{path}.value: operator {op!r} needs a string")
    elif op in ("eq", "ne") and isinstance(value, (dict, list)):
        raise ConditionError(f"{path}.value: eq/ne compare scalars; use 'in' for sets")
    text = describe_leaf(field, op, value)
    pred = None if op in NO_VALUE_OPS or op.startswith("len_") else _leaf_any(op, value, rx)

    def run_leaf(s: dict[str, Any], t: list[str] | None) -> bool:
        v = s.get(field)
        if op == "missing":
            ok = _is_missing(v)
        elif op == "present":
            ok = not _is_missing(v)
        elif _is_missing(v):
            ok = False
        elif op in ("is_true", "is_false"):
            ok = any(_bool(x) is (op == "is_true") for x in _items(v))
        elif op.startswith("len_"):
            n = len(v) if isinstance(v, (list, tuple, str)) else 1
            ok = {"len_eq": n == value, "len_gte": n >= value, "len_lte": n <= value}[op]
        else:
            assert pred is not None  # noqa: S101
            ok = any(pred(x) for x in _items(v))
            if op in ("ne", "not_in"):  # "none of the elements equal / are in the set"
                ok = all(pred(x) for x in _items(v))
        if ok and t is not None:
            t.append(text)
        return ok

    return Node(run_leaf, text, frozenset({field}))


def _suggest(word: str, options: tuple[str, ...]) -> str:
    import difflib  # noqa: PLC0415 - only on the error path

    close = difflib.get_close_matches(word, options, n=1)
    return f" (did you mean {close[0]!r}?)" if close else ""


def evaluate(node: Node, subject: dict[str, Any], explain: bool = False) -> tuple[bool, list[str]]:
    trace: list[str] | None = [] if explain else None
    ok = node.run(subject, trace)
    return ok, (trace or []) if ok else []
