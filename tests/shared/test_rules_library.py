"""The shipped rule library: every rule is valid, documented and proven by its own examples."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from shared.findings.standards import attack_url
from shared.rules.docgen import render_library
from shared.rules.loader import load_rule_set
from shared.rules.selftest import run_example

ROOT = Path(__file__).resolve().parents[2]
RS = load_rule_set()
RULES = RS.ordered()
CASES = [(r.id, i) for r in RULES for i in range(len(r.examples))]


def test_library_has_a_meaningful_number_of_valid_rules() -> None:
    assert RS.diagnostics == []
    assert len(RULES) >= 20
    assert len({r.id for r in RULES}) == len(RULES)


@pytest.mark.parametrize(("rule_id", "idx"), CASES, ids=[f"{r}-{i}" for r, i in CASES])
def test_every_embedded_example_passes(rule_id: str, idx: int) -> None:
    rule = RS.rules[rule_id]
    ex = rule.examples[idx]
    res = run_example(rule, ex)
    assert res.ok, f"{rule_id} / {ex['name']}: {res.message}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_each_rule_is_documented_and_proven(rule) -> None:  # type: ignore[no-untyped-def]
    expects = {e["expect"] for e in rule.examples}
    assert "no_match" in expects and expects & {"match", "indeterminate"}
    assert rule.investigation and rule.remediation and rule.rationale
    assert rule.severity_reason and rule.confidence_reason
    assert rule.id.split("-")[1] in ("LNX", "WIN", "ANY")
    plat = rule.id.split("-")[1]
    assert (plat == "ANY") == (rule.platforms == ("any",)), "id prefix and platforms must agree"
    if plat != "ANY":
        assert rule.platforms == ({"LNX": "linux", "WIN": "windows"}[plat],)


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_attack_mappings_are_well_formed_and_honest(rule) -> None:  # type: ignore[no-untyped-def]
    for a in rule.references.get("attack", []):
        assert re.fullmatch(r"T\d{4}(\.\d{3})?", a["id"])
        assert attack_url(a["id"]).startswith("https://attack.mitre.org/techniques/")
        assert len(a["explanation"]) >= 30
        # a rule that cannot see an adversary action must not call the relationship direct
        if rule.nature in ("indicator", "correlated", "hypothesis"):
            assert a["relationship"] == "possible", (
                f"{rule.id} {a['id']}: only observations may claim 'direct'"
            )
    for n in rule.references.get("nist", []):
        assert re.fullmatch(r"[A-Z]{2}-\d{1,2}", n)


def test_ids_the_rules_name_exist_in_the_collectors() -> None:
    """Guards against rules that silently never fire because a check id was renamed or mistyped."""
    known: set[str] = set()
    for p in list((ROOT / "linux").rglob("*.sh")):
        known |= set(re.findall(r"\b([A-Z]{2,6}-[A-Z0-9]+-\d{3})\b", p.read_text("utf-8")))
    for p in (ROOT / "windows").rglob("*.ps1"):
        known |= set(re.findall(r"'([A-Z]{2,6}-[A-Z0-9]+-\d{3})'", p.read_text("utf-8")))
    mentioned: set[str] = set()
    for r in RULES:
        text = str(r.raw["clauses"])
        mentioned |= set(re.findall(r"\b([A-Z]{2,6}-[A-Z0-9]+-\d{3})\b", text))
    mentioned = {m for m in mentioned if not m.startswith("DR-")}
    missing = sorted(mentioned - known)
    assert not missing, f"rules refer to check ids no collector emits: {missing}"


def test_library_covers_the_requested_areas() -> None:
    by_platform: dict[str, set[str]] = {"linux": set(), "windows": set()}
    for r in RULES:
        for p in r.platforms:
            by_platform.setdefault(p, set()).add(r.category)
    linux = by_platform["linux"] | by_platform["any"]
    windows = by_platform["windows"] | by_platform["any"]
    # Linux: authentication, privileged accounts, services, filesystem, persistence, network, system config, integrity
    for area in (
        "accounts",
        "authentication",
        "services",
        "filesystem",
        "persistence",
        "network-exposure",
        "system-config",
        "integrity",
    ):
        assert area in linux, area
    # Windows: accounts, services, scheduled tasks, firewall/network, logging, security configuration, persistence
    for area in (
        "accounts",
        "services",
        "scheduled-tasks",
        "network-exposure",
        "defense-evasion",
        "credential-access",
        "persistence",
    ):
        assert area in windows, area
    assert any(r.platforms == ("any",) and r.nature == "correlated" for r in RULES)
    assert {r.nature for r in RULES} >= {"observation", "indicator", "correlated"}


def test_rules_are_not_trivial_variations_of_each_other() -> None:
    sigs = {}
    for r in RULES:
        sig = str([(c.source, c.where_json) for c in r.clauses])
        assert sig not in sigs, f"{r.id} duplicates the conditions of {sigs[sig]}"
        sigs[sig] = r.id


def test_documentation_is_in_sync_with_the_rules() -> None:
    doc = (ROOT / "docs" / "detection-library.md").read_text("utf-8")
    assert doc == render_library(RS), (
        "run: python -m shared.engine rules docs --output <new file> and replace docs/detection-library.md"
    )
