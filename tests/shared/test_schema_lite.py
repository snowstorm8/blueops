"""The dependency-free validator must agree with ``jsonschema`` and refuse what it cannot check."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from shared.reporting.schema_lite import SCHEMA_DIR, SchemaError, Validator, validate

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = sorted(p.name for p in SCHEMA_DIR.glob("*.json"))


def _both(schema: dict[str, Any], instance: Any) -> tuple[bool, bool]:
    return (
        Validator(schema).is_valid(instance),
        Draft202012Validator(schema).is_valid(instance),
    )


@pytest.mark.parametrize("name", SCHEMAS)
def test_every_shipped_schema_is_supported(name: str) -> None:
    """Loading and walking an empty object proves no schema uses an unsupported keyword."""
    schema = json.loads((SCHEMA_DIR / name).read_text("utf-8"))
    Draft202012Validator.check_schema(schema)
    Validator(schema).iter_errors({})


CASES: list[tuple[dict[str, Any], Any]] = [
    ({"type": "string"}, "x"),
    ({"type": "string"}, 1),
    ({"type": "integer"}, 1.0),
    ({"type": "integer"}, True),
    ({"type": "number"}, True),
    ({"type": ["string", "null"]}, None),
    ({"enum": [1, "a"]}, True),  # True must not equal 1
    ({"enum": [1, "a"]}, 1),
    ({"const": True}, 1),
    ({"const": {"a": [1]}}, {"a": [1]}),
    ({"type": "string", "minLength": 2, "maxLength": 3}, "a"),
    ({"type": "string", "minLength": 2, "maxLength": 3}, "abcd"),
    ({"type": "string", "pattern": "^a+$"}, "aab"),
    ({"type": "integer", "minimum": 1, "maximum": 3}, 0),
    ({"type": "integer", "minimum": 1, "maximum": 3}, 4),
    ({"type": "array", "minItems": 1}, []),
    ({"type": "array", "maxItems": 1}, [1, 2]),
    ({"type": "array", "uniqueItems": True}, [1, True]),
    ({"type": "array", "uniqueItems": True}, [1, 1]),
    ({"type": "array", "items": {"type": "integer"}}, [1, "a"]),
    ({"type": "object", "required": ["a"]}, {}),
    ({"type": "object", "additionalProperties": False, "properties": {"a": {}}}, {"b": 1}),
    ({"type": "object", "additionalProperties": {"type": "integer"}}, {"b": "x"}),
    ({"anyOf": [{"type": "string"}, {"type": "integer"}]}, 1.5),
    ({"oneOf": [{"type": "integer"}, {"minimum": 0}]}, 1),
    ({"allOf": [{"type": "integer"}, {"minimum": 3}]}, 2),
]


@pytest.mark.parametrize(("schema", "instance"), CASES)
def test_agrees_with_jsonschema(schema: dict[str, Any], instance: Any) -> None:
    ours, ref = _both(schema, instance)
    assert ours == ref


def test_unknown_keyword_is_refused_not_ignored() -> None:
    with pytest.raises(SchemaError, match="dependentRequired"):
        Validator({"dependentRequired": {"a": ["b"]}}).iter_errors({})


def test_remote_ref_is_refused() -> None:
    with pytest.raises(SchemaError, match="local"):
        Validator({"$ref": "https://example.invalid/x"}).iter_errors(1)


def test_unresolvable_ref_is_refused() -> None:
    with pytest.raises(SchemaError, match="unresolvable"):
        Validator({"$ref": "#/$defs/missing"}).iter_errors(1)


def test_schema_name_cannot_escape_the_schema_directory() -> None:
    with pytest.raises(SchemaError):
        validate({}, "../pyproject.toml")


def test_deeply_nested_instance_is_a_violation_not_a_crash() -> None:
    schema = {
        "$ref": "#/$defs/n",
        "$defs": {"n": {"type": "array", "items": {"$ref": "#/$defs/n"}}},
    }
    inst: Any = []
    for _ in range(200):
        inst = [inst]
    assert any("deep" in str(v) for v in Validator(schema).iter_errors(inst))


def test_example_report_validates_in_both() -> None:
    doc = json.loads((ROOT / "examples" / "audit-report.example.json").read_text("utf-8"))
    assert validate(doc, "audit-report.schema.json") == []
    bad = copy.deepcopy(doc)
    bad["findings"][0]["severity"] = "urgent"
    assert validate(bad, "audit-report.schema.json")
    ref = Draft202012Validator(
        json.loads((SCHEMA_DIR / "audit-report.schema.json").read_text("utf-8"))
    )
    assert not ref.is_valid(bad)


def test_agreement_on_mutated_documents() -> None:
    """Delete or corrupt each top-level key of a valid report: both validators must agree."""
    doc = json.loads((ROOT / "examples" / "audit-report.example.json").read_text("utf-8"))
    schema = json.loads((SCHEMA_DIR / "audit-report.schema.json").read_text("utf-8"))
    ours, ref = Validator(schema), Draft202012Validator(schema)
    for key in list(doc):
        for mutate in ("delete", "null", "string"):
            m = copy.deepcopy(doc)
            if mutate == "delete":
                del m[key]
            else:
                m[key] = None if mutate == "null" else "x"
            assert ours.is_valid(m) == ref.is_valid(m), (key, mutate)
    extra = {**doc, "unexpected": 1}
    assert ours.is_valid(extra) == ref.is_valid(extra) is False
