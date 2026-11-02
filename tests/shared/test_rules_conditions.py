"""Condition language: operators, compound expressions, missing-value semantics, safety."""

from __future__ import annotations

from typing import Any

import pytest
from rules_support import where

from shared.rules.conditions import (
    MAX_DEPTH,
    MAX_NODES,
    ConditionError,
    check_pattern,
    compile_condition,
    evaluate,
)


def run(cond: dict[str, Any], subject: dict[str, Any]) -> bool:
    return evaluate(compile_condition(cond), subject)[0]


@pytest.mark.parametrize(
    ("op", "value", "field_value", "expected"),
    [
        ("eq", "high", "high", True),
        ("eq", "high", "High", False),  # eq is case-sensitive
        ("eq", 1000, "1000", True),  # numeric string vs number
        ("eq", "1000", 1000, True),
        ("eq", True, "true", True),
        ("eq", True, False, False),
        ("ne", "a", "b", True),
        ("ne", "a", "a", False),
        ("ieq", "HIGH", "high", True),
        ("contains", "pass", "/etc/passwd", True),
        ("contains", "PASS", "/etc/passwd", False),
        ("icontains", "PASS", "/etc/passwd", True),
        ("startswith", "/tmp/", "/tmp/x", True),
        ("startswith", "/tmp/", "/var/tmp/x", False),
        ("endswith", ".exe", "a.exe", True),
        ("regex", r"^/(tmp|dev/shm)/", "/dev/shm/x", True),
        ("regex", r"^/(tmp|dev/shm)/", "/home/tmp/x", False),
        ("gt", 5, "6", True),
        ("gt", 5, 5, False),
        ("gte", 5, "5", True),
        ("lt", 5, 4.5, True),
        ("lte", 5, "5", True),
        ("gt", 5, "abc", False),  # non-numeric never compares
        ("in", ["a", "b"], "b", True),
        ("in", ["a", "b"], "B", True),  # set membership is case-insensitive for text
        ("in", ["a", "b"], "c", False),
        ("not_in", ["a", "b"], "c", True),
        ("not_in", ["a", "b"], "a", False),
        ("is_true", None, True, True),
        ("is_true", None, "true", True),
        ("is_true", None, "yes", False),
        ("is_false", None, False, True),
        ("is_false", None, "FALSE", True),
        ("len_gte", 2, ["a", "b"], True),
        ("len_eq", 1, ["a"], True),
        ("len_lte", 1, ["a", "b"], False),
    ],
)
def test_leaf_operators(op: str, value: Any, field_value: Any, expected: bool) -> None:
    assert run(where("f", op, value), {"f": field_value}) is expected


@pytest.mark.parametrize("missing", [None, "", [], "absent"])
@pytest.mark.parametrize(
    "op", ["eq", "ne", "contains", "regex", "gt", "in", "not_in", "startswith"]
)
def test_comparisons_on_missing_values_are_false(op: str, missing: Any) -> None:
    """Unknown is never 'different': ne / not_in on a missing field must not match."""
    value: Any = {
        "eq": "x",
        "ne": "x",
        "contains": "x",
        "regex": "x",
        "gt": 1,
        "in": ["x"],
        "not_in": ["x"],
        "startswith": "x",
    }[op]
    subject = {} if missing == "absent" else {"f": missing}
    assert run(where("f", op, value), subject) is False


def test_missing_and_present_are_the_only_tests_for_absence() -> None:
    for v in (None, "", [], "absent"):
        subject = {} if v == "absent" else {"f": v}
        assert run(where("f", "missing"), subject) is True
        assert run(where("f", "present"), subject) is False
    assert run(where("f", "present"), {"f": "x"}) is True
    assert run(where("f", "present"), {"f": 0}) is True  # zero is a value
    assert run(where("f", "missing"), {"f": False}) is False


def test_list_fields_match_if_any_element_matches_except_negations() -> None:
    s = {"refs": ["/etc/passwd", "/tmp/x"]}
    assert run(where("refs", "startswith", "/tmp"), s)
    assert run(where("refs", "regex", r"passwd$"), s)
    assert run(where("refs", "in", ["/tmp/x"]), s)
    # negations are "none of the elements": a list that contains the value does not match
    assert not run(where("refs", "ne", "/tmp/x"), s)
    assert not run(where("refs", "not_in", ["/tmp/x"]), s)
    assert run(where("refs", "not_in", ["/other"]), s)


def test_compound_expressions() -> None:
    a, b = where("x", "eq", 1), where("y", "eq", 2)
    s = {"x": 1, "y": 3}
    assert not run({"all": [a, b]}, s)
    assert run({"any": [a, b]}, s)
    assert run({"not": b}, s)
    assert run({"all": [a, {"not": b}]}, s)
    assert not run({"not": {"any": [a, b]}}, s)
    assert run({"any": [{"all": [a, b]}, {"all": [a, {"not": b}]}]}, s)


def test_not_on_a_missing_field_is_true_only_through_the_inner_false() -> None:
    # not(eq) of a missing field: inner is False (missing), so not(...) is True. Authors who
    # mean "known and different" must say present AND ne; this documents the sharp edge.
    assert run({"not": where("f", "eq", "x")}, {})
    assert not run({"all": [where("f", "present"), where("f", "ne", "x")]}, {})


def test_trace_lists_only_the_true_leaves() -> None:
    cond = {
        "all": [
            where("a", "eq", 1),
            {"any": [where("b", "eq", 9), where("c", "contains", "z")]},
            {"not": where("d", "eq", 5)},
        ]
    }
    ok, trace = evaluate(
        compile_condition(cond), {"a": 1, "b": 0, "c": "xyz", "d": 4}, explain=True
    )
    assert ok
    assert trace == ["a eq 1", "c contains 'z'", "not (d eq 5)"]
    ok, trace = evaluate(compile_condition(cond), {"a": 2}, explain=True)
    assert not ok and trace == []


def test_fields_are_collected_for_validation() -> None:
    node = compile_condition({"all": [where("a", "eq", 1), {"not": where("b", "missing")}]})
    assert node.fields == {"a", "b"}


@pytest.mark.parametrize(
    ("cond", "message"),
    [
        ({}, "non-empty object"),
        ([], "non-empty object"),
        ("x", "non-empty object"),
        ({"all": []}, "non-empty list"),
        ({"all": "x"}, "non-empty list"),
        ({"all": [{"field": "a", "op": "eq", "value": 1}], "any": []}, "exactly one"),
        ({"field": "a", "op": "eqq", "value": 1}, "did you mean 'eq'"),
        ({"field": "a", "op": "zzzz", "value": 1}, "unknown operator"),
        ({"field": "", "op": "eq", "value": 1}, "required"),
        ({"op": "eq", "value": 1}, "required"),
        ({"field": "a", "op": "eq"}, "requires a value"),
        ({"field": "a", "op": "missing", "value": 1}, "takes no value"),
        ({"field": "a", "op": "in", "value": "x"}, "list of 1"),
        ({"field": "a", "op": "in", "value": []}, "list of 1"),
        ({"field": "a", "op": "in", "value": [["x"]]}, "scalars"),
        ({"field": "a", "op": "gt", "value": "5"}, "needs a number"),
        ({"field": "a", "op": "gt", "value": True}, "needs a number"),
        ({"field": "a", "op": "contains", "value": 5}, "needs a string"),
        ({"field": "a", "op": "eq", "value": [1]}, "scalars"),
        ({"field": "a", "op": "regex", "value": 5}, "must be a string"),
        ({"field": "a", "op": "regex", "value": "("}, "invalid regular expression"),
        ({"field": "a", "op": "regex", "value": "(a+)+$"}, "catastrophic"),
        ({"field": "a", "op": "regex", "value": "(.*)*x"}, "catastrophic"),
        ({"field": "a", "op": "regex", "value": "x" * 400}, "longer than"),
        ({"field": "a", "op": "eq", "value": 1, "extra": 1}, "unexpected key"),
    ],
)
def test_malformed_conditions_are_rejected_with_a_path(cond: Any, message: str) -> None:
    with pytest.raises(ConditionError, match=message) as exc:
        compile_condition(cond, "rules[0].where")
    assert str(exc.value).startswith("rules[0].where")


def test_error_paths_point_into_nested_conditions() -> None:
    cond = {
        "all": [
            where("a", "eq", 1),
            {"any": [where("b", "eq", 1), {"field": "c", "op": "bogus", "value": 1}]},
        ]
    }
    with pytest.raises(ConditionError) as exc:
        compile_condition(cond, "w")
    assert str(exc.value).startswith("w.all[1].any[1].op")


def test_depth_and_size_limits() -> None:
    deep: dict[str, Any] = where("a", "eq", 1)
    for _ in range(MAX_DEPTH + 2):
        deep = {"not": deep}
    with pytest.raises(ConditionError, match="nesting deeper"):
        compile_condition(deep)
    wide = {"any": [where("a", "eq", i) for i in range(MAX_NODES + 1)]}
    with pytest.raises(ConditionError, match="more than"):
        compile_condition(wide)


@pytest.mark.parametrize(
    "pattern",
    [r"^/(tmp|dev/shm)/", r"(?i)passwd", r"[a-z]+\.exe$", r"\d{1,3}(\.\d{1,3}){3}", r"(?:ab|cd)x"],
)
def test_ordinary_patterns_are_accepted(pattern: str) -> None:
    assert check_pattern(pattern) is None


def test_regex_input_is_capped_so_long_values_cannot_stall_matching() -> None:
    node = compile_condition(where("f", "regex", r"^a+b$"))
    assert evaluate(node, {"f": "a" * 100_000})[0] is False  # returns promptly, no match


def test_evaluation_never_raises_on_odd_values() -> None:
    node = compile_condition(
        {
            "any": [
                where("f", "contains", "x"),
                where("f", "gt", 1),
                where("f", "regex", "x"),
                where("f", "is_true"),
            ]
        }
    )
    for v in (object(), 1.5, b"bytes", {"k": "v"}, float("nan"), ["a", None, 3]):
        evaluate(node, {"f": v})
