"""Schema consistency across producers (Bash, PowerShell), consumers (Python) and the examples.

The collectors, the comparison, the detection layer and the manifest all communicate through the
JSON documents described in shared/schemas/. These tests keep the declared versions, the examples
and the allowlist example in step with the code, so a drift fails here rather than on a host.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from shared.reporting import detect as detect_cli
from shared.reporting.accepted import load
from shared.reporting.contracts import SCHEMA_VERSION
from shared.reporting.detection import RULES

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = sorted((ROOT / "shared" / "schemas").glob("*.json"))
FX = ROOT / "tests" / "fixtures" / "baseline-e2e"


def _json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", SCHEMAS, ids=lambda p: p.name)
def test_every_schema_is_a_valid_2020_12_schema(path: Path) -> None:
    Draft202012Validator.check_schema(_json(path))


def test_schema_versions_agree_across_producers_and_consumers() -> None:
    """Bash and PowerShell collectors, the Python contract and the three schema ids declare the
    same report version; the manifest has its own, independent version line."""
    linux = re.search(r'BO_SCHEMA_VERSION="([^"]+)"', (ROOT / "linux/lib/common.sh").read_text())
    windows = re.search(
        r"BoSchemaVersion = '([^']+)'", (ROOT / "windows/lib/Common.ps1").read_text()
    )
    assert linux and windows
    assert linux.group(1) == windows.group(1) == SCHEMA_VERSION
    for name in ("audit-report", "baseline-diff", "detections"):
        schema = _json(ROOT / "shared" / "schemas" / f"{name}.schema.json")
        assert schema["$id"].endswith(f"/{name}/{SCHEMA_VERSION}"), name
    manifest = _json(ROOT / "shared" / "schemas" / "run-manifest.schema.json")
    assert manifest["$id"].endswith("/run-manifest/0.1.0")
    for producer in ("linux/lib/common.sh", "windows/lib/Common.ps1"):
        assert (
            "0.1.0" in (ROOT / producer).read_text()
            and "run-manifest" in (ROOT / producer).read_text()
        )


def test_examples_validate_against_their_schemas() -> None:
    pairs = {
        "audit-report.example.json": "audit-report.schema.json",
        "run-manifest.example.json": "run-manifest.schema.json",
    }
    for example, schema in pairs.items():
        Draft202012Validator(_json(ROOT / "shared/schemas" / schema)).validate(
            _json(ROOT / "examples" / example)
        )


def test_report_schema_allows_exactly_the_documented_host_fields() -> None:
    host = _json(ROOT / "shared/schemas/audit-report.schema.json")["properties"]["host"]
    assert set(host["properties"]) == {"hostname", "os", "arch", "user", "elevated", "test_mode"}
    assert host["additionalProperties"] is False


def test_every_rule_id_is_unique_and_matches_the_detection_schema_pattern() -> None:
    ids = [r.rule_id for r in RULES]
    assert len(ids) == len(set(ids))
    schema = _json(ROOT / "shared/schemas/detections.schema.json")

    def find(node: Any) -> str | None:
        if isinstance(node, dict):
            rule = node.get("rule")
            if isinstance(rule, dict) and "pattern" in rule:
                return str(rule["pattern"])
            return next((p for v in node.values() if (p := find(v))), None)
        if isinstance(node, list):
            return next((p for v in node if (p := find(v))), None)
        return None

    pattern = find(schema)
    assert pattern, "the detections schema must constrain rule ids"
    assert all(re.match(pattern, i) for i in ids), pattern
    assert all(re.fullmatch(r"BO-[A-Z]{3}-\d{3}", i) for i in ids)


# ----------------------------------------------------- the example allowlist, end to end

EXAMPLE = ROOT / "examples" / "accepted-changes.example.json"


def _run(capsys: pytest.CaptureFixture[str], generated: str, host: str = "linux") -> dict[str, Any]:
    code = detect_cli.main(
        [
            str(FX / host / "baseline.json"),
            str(FX / host / "changed.json"),
            "--accepted",
            str(EXAMPLE),
            "--json",
            "--quiet",
            "--generated-at",
            generated,
        ]
    )
    assert code == 4  # other detections remain either way
    return json.loads(capsys.readouterr().out)  # type: ignore[no-any-return]


def test_example_allowlist_is_valid_and_documents_its_own_expiry() -> None:
    allow = load(str(EXAMPLE), frozenset(r.rule_id for r in RULES))
    assert [e.id for e in allow.entries] == ["AC-sysctl-forwarding"]
    assert allow.entries[0].expires > allow.entries[0].approved_at


def test_example_allowlist_accepts_exactly_its_subject_before_it_expires(
    capsys: pytest.CaptureFixture[str],
) -> None:
    doc = _run(capsys, "2026-03-02T00:00:00Z")
    assert doc["summary"]["accepted"] == 1
    assert doc["accepted"][0]["subject"]["key"] == "config:sysctl:net.ipv4.ip_forward"
    assert doc["allowlist"]["entries"][0]["status"] == "matched"


def test_example_allowlist_stops_suppressing_after_its_expiry(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The shipped example expires on 2026-06-01: run after that date it accepts nothing and
    says so, which is why it must be copied and renewed rather than used as-is."""
    doc = _run(capsys, "2026-12-01T00:00:00Z")
    assert doc["summary"]["accepted"] == 0
    assert doc["allowlist"]["entries"][0]["status"] == "expired"
    assert any(
        d["subject"]["key"] == "config:sysctl:net.ipv4.ip_forward" for d in doc["detections"]
    )


def test_example_allowlist_does_not_apply_to_a_different_host_family(
    capsys: pytest.CaptureFixture[str],
) -> None:
    doc = _run(capsys, "2026-03-02T00:00:00Z", host="windows")
    assert doc["summary"]["accepted"] == 0
    assert doc["allowlist"]["entries"][0]["status"] == "unused"
