"""Contract tests: schema validity, example/fixture conformance, enum consistency."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from shared.reporting.contracts import (
    COVERAGE_STATUSES,
    INVENTORY_DOMAINS,
    READABLE_REPORT_VERSIONS,
    SCHEMA_VERSION,
    ExitCode,
    Severity,
)
from shared.reporting.inventory import Options, options_from_config

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


DIFF_SCHEMA_PATH = ROOT / "shared" / "schemas" / "baseline-diff.schema.json"


def test_inventory_enums_match_schema(schema: dict) -> None:
    assert list(INVENTORY_DOMAINS) == schema["$defs"]["inventory_domain"]["enum"]
    cov_props = schema["properties"]["inventory"]["properties"]["coverage"]["items"]["properties"]
    assert list(COVERAGE_STATUSES) == cov_props["status"]["enum"]


def test_diff_schema_is_valid_and_versioned() -> None:
    diff_schema = _load(DIFF_SCHEMA_PATH)
    Draft202012Validator.check_schema(diff_schema)
    assert diff_schema["$id"].endswith(f"/{SCHEMA_VERSION}")
    assert _load(SCHEMA_PATH)["$id"].endswith(f"/{SCHEMA_VERSION}")


def test_diff_schema_reasons_and_coverage_match_code() -> None:
    diff_schema = _load(DIFF_SCHEMA_PATH)
    reasons = diff_schema["$defs"]["indeterminate"]["properties"]["reason"]["enum"]
    assert reasons == [
        "BASELINE_INCOMPLETE",
        "CURRENT_INCOMPLETE",
        "ATTRIBUTE_UNKNOWN",
        "RECORD_CONFLICT",
    ]
    cov = diff_schema["$defs"]["coverage"]["oneOf"][1]["properties"]["status"]["enum"]
    assert cov == list(COVERAGE_STATUSES)


def test_default_diff_config_matches_builtin_defaults() -> None:
    cfg = _load(ROOT / "shared" / "config" / "baseline-diff.default.json")
    opts = options_from_config(cfg)
    assert opts.transient_processes == Options().transient_processes
    assert opts.ephemeral_from is None
    assert not opts.ignore


def test_legacy_schema_0_1_reports_are_still_readable() -> None:
    assert "0.1" in READABLE_REPORT_VERSIONS
    assert SCHEMA_VERSION.rsplit(".", 1)[0] in READABLE_REPORT_VERSIONS
