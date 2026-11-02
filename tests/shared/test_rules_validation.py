"""Rule validation and loading: diagnostics, fail-safe behaviour, overrides."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from rules_support import BASE_RULE, make_rule, where

from shared.rules.loader import LIBRARY_DIR, load_pack_file, load_rule_set
from shared.rules.validate import compile_rule, validate_pack


def pack(*rules: dict[str, Any], name: str = "test-pack") -> dict[str, Any]:
    return {
        "schema_version": "0.1.0",
        "kind": "rule-pack",
        "pack": {"name": name, "version": "1.0.0"},
        "rules": list(rules),
    }


def messages(raw: dict[str, Any]) -> list[str]:
    rule, diags = compile_rule(raw)
    assert rule is None, "expected the rule to be rejected"
    return [str(d) for d in diags]


def test_the_base_rule_is_valid() -> None:
    rule, diags = compile_rule(copy.deepcopy(BASE_RULE))
    assert rule is not None and not diags
    assert rule.id == "DR-TST-RULE-001" and rule.enabled is True and rule.sources == {"findings"}


@pytest.mark.parametrize(
    ("change", "needle"),
    [
        ({"id": "BAD-ID"}, "id"),
        ({"id": "DR-TST-RULE-1"}, "id"),
        ({"version": "1.0"}, "version"),
        ({"name": "x"}, "name"),
        ({"severity": "urgent"}, "severity"),
        ({"confidence": "certain"}, "confidence"),
        ({"nature": "proof"}, "nature"),
        ({"platforms": []}, "platforms"),
        ({"platforms": ["macos"]}, "platforms"),
        ({"category": "Bad Category"}, "category"),
        ({"clauses": []}, "clauses"),
        ({"severity_reason": "short"}, "severity_reason"),
        ({"investigation": []}, "investigation"),
        ({"unexpected": 1}, "unexpected"),
        ({"requires_coverage": ["module:Bad Name"]}, "requires_coverage"),
        (
            {
                "references": {
                    "attack": [
                        {"id": "T12", "relationship": "direct", "explanation": "long enough text"}
                    ]
                }
            },
            "attack",
        ),
        (
            {
                "references": {
                    "attack": [
                        {
                            "id": "T1136.001",
                            "relationship": "proven",
                            "explanation": "long enough text",
                        }
                    ]
                }
            },
            "relationship",
        ),
        ({"references": {"nist": ["ac2"]}}, "nist"),
    ],
)
def test_schema_violations_are_reported_with_the_rule_id(
    change: dict[str, Any], needle: str
) -> None:
    out = messages(make_rule(**change))
    assert any(needle in m for m in out), out
    assert all("DR-TST-RULE-001" in m or "BAD-ID" in m or "DR-TST-RULE-1" in m for m in out)


def clause(cid: str, where_: dict[str, Any], **kw: Any) -> dict[str, Any]:
    return {"id": cid, "source": "findings", "description": f"clause {cid}", "where": where_, **kw}


def test_missing_required_property_is_named() -> None:
    raw = make_rule()
    del raw["remediation"]
    assert any("remediation" in m for m in messages(raw))


def test_clause_without_where_is_refused() -> None:
    raw = make_rule(clauses=[{"id": "a", "source": "findings", "description": "no condition"}])
    assert any("would match everything" in m for m in messages(raw))


def test_unknown_field_is_reported_with_a_suggestion() -> None:
    raw = make_rule(clauses=[clause("a", where("check_idd", "eq", "X"))])
    out = messages(raw)
    assert any("check_idd" in m and "does not exist for source 'findings'" in m for m in out)
    raw = make_rule(clauses=[clause("a", where("check_id", "eq", "X"))])
    raw["clauses"][0]["source"] = "inventory"
    assert any("'check_id' does not exist for source 'inventory'" in m for m in messages(raw))


def test_dynamic_field_families_are_accepted() -> None:
    raw = make_rule(
        title="On {host}",
        clauses=[
            {
                "id": "a",
                "source": "inventory",
                "description": "d",
                "where": where("attrs.anything.goes", "eq", "x"),
            }
        ],
    )
    rule, diags = compile_rule(raw)
    assert rule is not None, diags
    raw = make_rule(
        title="On {host}",
        clauses=[
            {
                "id": "a",
                "source": "config_changes",
                "description": "d",
                "where": where("attr.members.after", "present"),
            }
        ],
        requires_coverage=["comparison"],
    )
    assert compile_rule(raw)[0] is not None
    raw["clauses"][0]["where"] = where("attr.members.during", "present")
    assert messages(raw)


def test_bad_operator_and_regex_are_reported_at_their_path() -> None:
    out = messages(make_rule(clauses=[clause("a", where("check_id", "eqq", "X"))]))
    assert any("clauses[0].where.op" in m and "did you mean 'eq'" in m for m in out)
    out = messages(make_rule(clauses=[clause("a", where("title", "regex", "(a+)+$"))]))
    assert any("catastrophic" in m for m in out)


def test_clause_ids_and_references() -> None:
    dup = make_rule(
        clauses=[
            clause("a", where("check_id", "eq", "X")),
            clause("a", where("check_id", "eq", "Y")),
        ]
    )
    assert any("unique" in m for m in messages(dup))
    bad = make_rule(
        clauses=[clause("a", where("check_id", "eq", "X"))], require={"all": ["a", "bee"]}
    )
    out = messages(bad)
    assert any("unknown clause 'bee'" in m for m in out)
    assert any("require.all[1]" in m for m in out)
    assert any("expected a clause id" in m for m in messages(make_rule(require={"xor": ["a"]})))
    assert any("expected a clause id" in m for m in messages(make_rule(require={"all": []})))


def test_all_clauses_optional_needs_an_explicit_require() -> None:
    raw = make_rule(clauses=[clause("a", where("check_id", "eq", "X"), optional=True)])
    assert any("must not be optional" in m for m in messages(raw))
    raw["require"] = "a"
    assert compile_rule(raw)[0] is not None


def test_adjustment_rules_are_validated() -> None:
    raw = make_rule(severity_rules=[{"when": "zzz", "value": "high", "reason": "because it is"}])
    assert any("severity_rules[0].when" in m for m in messages(raw))
    raw = make_rule(severity_rules=[{"when": "a", "value": "urgent", "reason": "because it is"}])
    assert any("severity_rules[0].value" in m for m in messages(raw))
    raw = make_rule(confidence_rules=[{"when": "a", "value": "certain", "reason": "because it is"}])
    assert any("confidence_rules[0].value" in m for m in messages(raw))


def test_template_placeholders_are_checked() -> None:
    assert any("unknown placeholder" in m for m in messages(make_rule(title="Matched {zzz.title}")))
    assert any(
        "does not exist for source" in m for m in messages(make_rule(title="Matched {a.nonsense}"))
    )
    assert any("unknown placeholder" in m for m in messages(make_rule(title="Matched {a}")))
    assert compile_rule(make_rule(title="On {host}: {a.title} ({a.check_id})"))[0] is not None


def test_nature_must_match_the_shape_of_the_rule() -> None:
    two = [clause("a", where("check_id", "eq", "X")), clause("b", where("check_id", "eq", "Y"))]
    assert any("'observation'" in m for m in messages(make_rule(nature="observation", clauses=two)))
    assert any("'correlated' needs" in m for m in messages(make_rule(nature="correlated")))
    assert compile_rule(make_rule(nature="correlated", clauses=two))[0] is not None
    distinct = [
        clause("a", where("severity_rank", "gte", 1), distinct={"field": "check_id", "count": 3})
    ]
    assert compile_rule(make_rule(nature="correlated", clauses=distinct))[0] is not None


def test_hypothesis_cannot_claim_a_direct_attack_relationship() -> None:
    ref = {
        "attack": [
            {"id": "T1078", "relationship": "direct", "explanation": "stated as directly observed"}
        ]
    }
    assert any("hypothesis" in m for m in messages(make_rule(nature="hypothesis", references=ref)))


def test_rules_must_declare_the_coverage_they_depend_on() -> None:
    change = [
        {
            "id": "a",
            "source": "new_findings",
            "description": "d",
            "where": where("severity", "eq", "high"),
        }
    ]
    assert any("declare 'comparison'" in m for m in messages(make_rule(clauses=change)))
    assert compile_rule(make_rule(clauses=change, requires_coverage=["comparison"]))[0] is not None
    assert (
        compile_rule(make_rule(clauses=change, requires_coverage=["comparison:exists"]))[0]
        is not None
    )
    hist = [clause("a", where("history.reappeared", "is_true"))]
    assert any("history:N" in m for m in messages(make_rule(clauses=hist)))
    assert compile_rule(make_rule(clauses=hist, requires_coverage=["history:2"]))[0] is not None
    neg = make_rule(
        clauses=[
            clause("a", where("check_id", "eq", "X")),
            clause("b", where("check_id", "eq", "Y")),
        ],
        nature="correlated",
        require={"all": ["a", {"not": "b"}]},
    )
    assert any("absence" in m for m in messages(neg))
    neg["requires_coverage"] = ["module:users"]
    assert compile_rule(neg)[0] is not None


def test_examples_must_include_a_positive_and_a_negative() -> None:
    only_match = make_rule(
        examples=[
            {"name": "a", "expect": "match", "current": {}},
            {"name": "b", "expect": "match", "current": {}},
        ]
    )
    assert any("negative example" in m for m in messages(only_match))
    only_no = make_rule(
        examples=[
            {"name": "a", "expect": "no_match", "current": {}},
            {"name": "b", "expect": "no_match", "current": {}},
        ]
    )
    assert any("expects a match" in m for m in messages(only_no))
    assert any(
        "at least" in m or "minItems" in m or "fewer" in m
        for m in messages(make_rule(examples=[{"name": "a", "expect": "match", "current": {}}]))
    )


def test_join_field_must_exist_for_every_clause_source() -> None:
    raw = make_rule(
        join={"on": "evidence.paths"},
        clauses=[
            {
                "id": "a",
                "source": "inventory",
                "description": "d",
                "where": where("domain", "eq", "users"),
            }
        ],
    )
    assert any("join.on" in m for m in messages(raw))
    snap = make_rule(
        join={"on": "key"},
        clauses=[
            {
                "id": "a",
                "source": "snapshot",
                "description": "d",
                "where": where("previous.clean", "eq", True),
            }
        ],
        requires_coverage=["comparison"],
    )
    assert any("snapshot clause cannot take part in a join" in m for m in messages(snap))


def test_platform_any_cannot_be_mixed() -> None:
    assert any(
        "'any' cannot be combined" in m for m in messages(make_rule(platforms=["any", "linux"]))
    )


# -------------------------------------------------------------------------------- packs


def test_validate_pack_fails_safely_one_rule_at_a_time() -> None:
    good = make_rule(id="DR-TST-GOOD-001")
    bad = make_rule(id="DR-TST-BAD-001", severity="urgent")
    rules, diags = validate_pack(pack(good, bad))
    assert [r.id for r in rules] == ["DR-TST-GOOD-001"]
    assert any(
        d.level == "error" and d.rule == "DR-TST-BAD-001" and d.path.startswith("rules[1].")
        for d in diags
    )


def test_duplicate_ids_in_a_pack() -> None:
    rules, diags = validate_pack(pack(make_rule(), make_rule()))
    assert len(rules) == 1 and any("duplicate" in d.message for d in diags)


@pytest.mark.parametrize(
    "doc",
    [
        [],
        "x",
        {},
        {"kind": "rule-pack"},
        {**pack(), "kind": "other"},
        {**pack(), "rules": "no"},
        {**pack(), "extra": 1},
    ],
)
def test_malformed_packs_give_diagnostics_not_exceptions(doc: Any) -> None:
    rules, diags = validate_pack(doc)
    assert rules == [] and diags and diags[0].level == "error"


def test_pack_files_are_read_strictly(tmp_path: Path) -> None:
    cases = {
        "notjson.json": "{",
        "dupkeys.json": '{"a": 1, "a": 2}',
        "nan.json": '{"x": NaN}',
        "array.json": "[]",
        "binary.json": None,
    }
    for name, text in cases.items():
        p = tmp_path / name
        if text is None:
            p.write_bytes(b"\xff\xfe\x00")
        else:
            p.write_text(text, encoding="utf-8")
        rules, diags, _ = load_pack_file(p)
        assert rules == [] and diags and all(d.level == "error" for d in diags), name


def test_oversized_pack_is_refused(tmp_path: Path) -> None:
    p = tmp_path / "big.json"
    p.write_text(" " * (1024 * 1024 + 1), encoding="utf-8")
    rules, diags, _ = load_pack_file(p)
    assert rules == [] and "exceed" in diags[0].message


def write_pack(tmp_path: Path, *rules: dict[str, Any], name: str = "p") -> Path:
    p = tmp_path / f"{name}.json"
    p.write_text(json.dumps(pack(*rules, name=name)), encoding="utf-8")
    return p


def test_library_plus_extra_rules(tmp_path: Path) -> None:
    extra = write_pack(tmp_path, make_rule(id="DR-TST-EXTRA-001"))
    rs = load_rule_set([extra])
    assert "DR-TST-EXTRA-001" in rs.rules and "DR-LNX-ACC-001" in rs.rules and not rs.errors
    assert {p["name"] for p in rs.packs} >= {"linux-core", "p"} and all(
        len(p["sha256"]) == 64 for p in rs.packs
    )


def test_a_pack_cannot_replace_a_library_rule(tmp_path: Path) -> None:
    extra = write_pack(tmp_path, make_rule(id="DR-LNX-ACC-001", name="Replacement"))
    rs = load_rule_set([extra])
    assert rs.rules["DR-LNX-ACC-001"].name != "Replacement"
    assert any("already defined" in d.message for d in rs.errors)


def test_directory_and_missing_locations(tmp_path: Path) -> None:
    write_pack(tmp_path, make_rule(id="DR-TST-ONE-001"), name="one")
    write_pack(tmp_path, make_rule(id="DR-TST-TWO-001"), name="two")
    (tmp_path / "notes.txt").write_text("ignored")
    rs = load_rule_set([tmp_path], include_library=False)
    assert sorted(rs.rules) == ["DR-TST-ONE-001", "DR-TST-TWO-001"]
    rs = load_rule_set([tmp_path / "missing"], include_library=False)
    assert rs.errors and "not found" in rs.errors[0].message


def test_enable_and_disable_overrides(tmp_path: Path) -> None:
    rs = load_rule_set(disable=["DR-LNX-ACC-001"])
    assert rs.rules["DR-LNX-ACC-001"].enabled is False
    off = write_pack(tmp_path, make_rule(id="DR-TST-OFF-001", enabled=False))
    rs = load_rule_set([off], enable=["DR-TST-OFF-001"])
    assert rs.rules["DR-TST-OFF-001"].enabled is True
    rs = load_rule_set(disable=["DR-NOPE-NOPE-001"])
    assert any("unknown rule id" in d.message for d in rs.errors)


def test_the_shipped_library_loads_without_diagnostics() -> None:
    rs = load_rule_set()
    assert rs.diagnostics == [] and len(rs.rules) >= 20
    assert LIBRARY_DIR.is_dir()
