"""Contract tests: schema validity, example/fixture conformance, enum consistency."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from shared.reporting.contracts import SCHEMA_VERSION, ExitCode, Severity

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "shared" / "schemas" / "audit-report.schema.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def schema() -> dict:
    return _load(SCHEMA_PATH)


def test_schema_is_valid(schema: dict) -> None:
    Draft202012Validator.check_schema(schema)


def test_example_report_conforms(schema: dict) -> None:
    report = _load(ROOT / "examples" / "audit-report.example.json")
    Draft202012Validator(schema).validate(report)
    assert report["schema_version"] == SCHEMA_VERSION


def test_invalid_fixture_is_rejected(schema: dict) -> None:
    report = _load(ROOT / "tests" / "fixtures" / "invalid-report-bad-severity.json")
    errors = list(Draft202012Validator(schema).iter_errors(report))
    assert errors, "fixture should violate the schema"


def test_severity_matches_schema(schema: dict) -> None:
    enum_values = schema["$defs"]["finding"]["properties"]["severity"]["enum"]
    assert enum_values == [s.label for s in sorted(Severity)]
    by_sev = schema["properties"]["summary"]["properties"]["by_severity"]["required"]
    assert by_sev == enum_values


def test_exit_codes_match_schema_range(schema: dict) -> None:
    exit_schema = schema["properties"]["run"]["properties"]["exit_code"]
    assert exit_schema["maximum"] == max(ExitCode)
    assert exit_schema["minimum"] == min(ExitCode)


def test_severity_parse() -> None:
    assert Severity.parse(" High ") is Severity.HIGH
    assert Severity.CRITICAL > Severity.LOW
    with pytest.raises(ValueError):
        Severity.parse("nope")
