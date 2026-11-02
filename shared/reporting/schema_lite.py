"""A small, dependency-free JSON Schema validator for the BlueOps schemas.

Runtime code is standard-library only (CLAUDE.md section 7), so the engine cannot rely on the
``jsonschema`` package that the test suite uses. This module implements exactly the subset of
JSON Schema draft 2020-12 that ``shared/schemas/*.json`` use, and it **refuses** any other
keyword instead of silently ignoring it: a validator that skips a constraint it does not
understand would report "valid" for documents the schema forbids.

``tests/shared/test_schema_lite.py`` checks it against ``jsonschema`` on every schema and on
mutated documents, so the two cannot drift apart unnoticed.

Supported: ``$ref`` (local ``#/...`` pointers), ``type``, ``enum``, ``const``, ``required``,
``properties``, ``additionalProperties`` (bool or schema), ``items``, ``minItems``,
``maxItems``, ``uniqueItems``, ``minLength``, ``maxLength``, ``pattern``, ``minimum``,
``maximum``, ``anyOf``, ``oneOf``, ``allOf``. ``format`` is an annotation (not asserted), as in
the default behaviour of the reference validators.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ANNOTATIONS = frozenset(
    {"$schema", "$id", "$comment", "title", "description", "examples", "default", "$defs", "format"}
)
_ASSERTIONS = frozenset(
    {
        "$ref",
        "type",
        "enum",
        "const",
        "required",
        "properties",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minLength",
        "maxLength",
        "pattern",
        "minimum",
        "maximum",
        "anyOf",
        "oneOf",
        "allOf",
    }
)
SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
_MAX_DEPTH = 64


class SchemaError(ValueError):
    """The schema itself uses something this validator does not implement."""


@dataclass(frozen=True)
class Violation:
    path: str
    message: str

    def __str__(self) -> str:
        return f"{self.path or '$'}: {self.message}"


def _type_ok(value: Any, name: str) -> bool:  # noqa: PLR0911 - one return per JSON type
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    if name == "integer":
        return (isinstance(value, int) and not isinstance(value, bool)) or (
            isinstance(value, float) and value.is_integer()
        )
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    raise SchemaError(f"unknown type {name!r}")


def _same(a: Any, b: Any) -> bool:
    """JSON equality: ``true`` is not ``1`` (Python's ``True == 1`` would say otherwise)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return bool(a == b)


class Validator:
    def __init__(self, schema: dict[str, Any]) -> None:
        if not isinstance(schema, dict):
            raise SchemaError("schema must be an object")
        self.root = schema
        self._patterns: dict[str, re.Pattern[str]] = {}

    def _resolve(self, ref: str) -> dict[str, Any]:
        if not ref.startswith("#"):
            raise SchemaError(f"only local $ref is supported: {ref!r}")
        node: Any = self.root
        for raw in [p for p in ref[1:].split("/") if p]:
            part = raw.replace("~1", "/").replace("~0", "~")
            if not isinstance(node, dict) or part not in node:
                raise SchemaError(f"unresolvable $ref {ref!r}")
            node = node[part]
        if not isinstance(node, dict):
            raise SchemaError(f"$ref {ref!r} does not point at a schema object")
        return node

    def _regex(self, pattern: str) -> re.Pattern[str]:
        if pattern not in self._patterns:
            self._patterns[pattern] = re.compile(pattern)
        return self._patterns[pattern]

    def iter_errors(self, instance: Any) -> list[Violation]:
        out: list[Violation] = []
        self._check(instance, self.root, "", out, 0)
        return out

    def is_valid(self, instance: Any) -> bool:
        return not self.iter_errors(instance)

    # ------------------------------------------------------------------ internals

    def _check(  # noqa: PLR0912, PLR0915 - one flat dispatch over the supported keywords
        self, inst: Any, schema: dict[str, Any], path: str, out: list[Violation], depth: int
    ) -> None:
        if depth > _MAX_DEPTH:
            out.append(Violation(path, "nesting too deep"))
            return
        if not isinstance(schema, dict):
            raise SchemaError("a subschema must be an object")
        unknown = set(schema) - _ASSERTIONS - _ANNOTATIONS
        if unknown:
            raise SchemaError(f"unsupported schema keyword(s): {', '.join(sorted(unknown))}")
        if "$ref" in schema:
            self._check(inst, self._resolve(schema["$ref"]), path, out, depth + 1)
        if "type" in schema:
            names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
            if not any(_type_ok(inst, n) for n in names):
                out.append(Violation(path, f"expected {'/'.join(names)}, got {_kind(inst)}"))
                return
        if "const" in schema and not _same(inst, schema["const"]):
            out.append(Violation(path, f"must equal {schema['const']!r}"))
        if "enum" in schema and not any(_same(inst, e) for e in schema["enum"]):
            shown = ", ".join(repr(e) for e in schema["enum"][:8])
            out.append(Violation(path, f"{_short(inst)} is not one of: {shown}"))
        for key in ("anyOf", "oneOf", "allOf"):
            if key in schema:
                self._combine(key, inst, schema[key], path, out, depth)
        if isinstance(inst, str):
            self._check_string(inst, schema, path, out)
        elif isinstance(inst, (int, float)) and not isinstance(inst, bool):
            if "minimum" in schema and inst < schema["minimum"]:
                out.append(Violation(path, f"{inst} is below the minimum {schema['minimum']}"))
            if "maximum" in schema and inst > schema["maximum"]:
                out.append(Violation(path, f"{inst} is above the maximum {schema['maximum']}"))
        elif isinstance(inst, list):
            self._check_array(inst, schema, path, out, depth)
        elif isinstance(inst, dict):
            self._check_object(inst, schema, path, out, depth)

    def _combine(  # noqa: PLR0913, PLR0917 - mirrors _check's visitor arguments
        self,
        key: str,
        inst: Any,
        subs: list[dict[str, Any]],
        path: str,
        out: list[Violation],
        d: int,
    ) -> None:
        results = []
        for sub in subs:
            errs: list[Violation] = []
            self._check(inst, sub, path, errs, d + 1)
            results.append(errs)
        passed = sum(1 for e in results if not e)
        if key == "allOf":
            for errs in results:
                out.extend(errs)
        elif key == "anyOf" and passed == 0:
            out.append(Violation(path, "does not match any allowed shape"))
        elif key == "oneOf" and passed != 1:
            out.append(Violation(path, f"matches {passed} of the alternatives; exactly 1 required"))

    def _check_string(
        self, inst: str, schema: dict[str, Any], path: str, out: list[Violation]
    ) -> None:
        if "minLength" in schema and len(inst) < schema["minLength"]:
            out.append(Violation(path, f"shorter than {schema['minLength']} characters"))
        if "maxLength" in schema and len(inst) > schema["maxLength"]:
            out.append(Violation(path, f"longer than {schema['maxLength']} characters"))
        if "pattern" in schema and not self._regex(schema["pattern"]).search(inst):
            out.append(Violation(path, f"{_short(inst)} does not match {schema['pattern']}"))

    def _check_array(
        self, inst: list[Any], schema: dict[str, Any], path: str, out: list[Violation], d: int
    ) -> None:
        if "minItems" in schema and len(inst) < schema["minItems"]:
            out.append(Violation(path, f"fewer than {schema['minItems']} items"))
        if "maxItems" in schema and len(inst) > schema["maxItems"]:
            out.append(Violation(path, f"more than {schema['maxItems']} items"))
        if schema.get("uniqueItems"):
            for i, a in enumerate(inst):
                if any(_same(a, b) for b in inst[:i]):
                    out.append(Violation(path, f"item {i} duplicates an earlier item"))
                    break
        if "items" in schema:
            for i, item in enumerate(inst):
                self._check(item, schema["items"], f"{path}[{i}]", out, d + 1)

    def _check_object(
        self, inst: dict[str, Any], schema: dict[str, Any], path: str, out: list[Violation], d: int
    ) -> None:
        for name in schema.get("required", []):
            if name not in inst:
                out.append(Violation(path, f"missing required property {name!r}"))
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for name, value in inst.items():
            child = f"{path}.{name}" if path else name
            if name in props:
                self._check(value, props[name], child, out, d + 1)
            elif extra is False:
                out.append(Violation(path, f"unexpected property {name!r}"))
            elif isinstance(extra, dict):
                self._check(value, extra, child, out, d + 1)


def _kind(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    return type(v).__name__


def _short(v: Any) -> str:
    text = repr(v)
    return text if len(text) <= 60 else text[:57] + "..."


_CACHE: dict[str, Validator] = {}


def load_schema(name: str) -> dict[str, Any]:
    """Load ``shared/schemas/<name>`` (a file name such as ``audit-report.schema.json``)."""
    if "/" in name or "\\" in name or not name.endswith(".json"):
        raise SchemaError(f"not a schema file name: {name!r}")
    loaded = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise SchemaError(f"{name} is not a JSON object")
    return loaded


def validator_for(name: str) -> Validator:
    if name not in _CACHE:
        _CACHE[name] = Validator(load_schema(name))
    return _CACHE[name]


def validate(instance: Any, schema_name: str, limit: int = 20) -> list[str]:
    """Return up to ``limit`` human-readable violations of ``schema_name`` (empty = valid)."""
    return [str(v) for v in validator_for(schema_name).iter_errors(instance)][:limit]
