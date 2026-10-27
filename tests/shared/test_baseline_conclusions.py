"""Regression tests: input that could be mistaken for evidence must not yield conclusions."""

from __future__ import annotations

from typing import Any

import pytest
from baseline_builders import LATER, cov, finding, rec, report, standard_baseline

from shared.reporting.baseline import compare, exit_code_for
from shared.reporting.contracts import ExitCode
from shared.reporting.inventory import (
    ConfigError,
    Options,
    ReportError,
    build_snapshot,
    options_from_config,
)

NOW = "2026-02-01T00:00:00Z"


def run_diff(base: dict[str, Any], cur: dict[str, Any], **opt: Any) -> dict[str, Any]:
    options = Options(**opt)
    return compare(build_snapshot(base, options), build_snapshot(cur, options), options, NOW)


def kinds(d: dict[str, Any]) -> set[tuple[str, str]]:
    return {(c["key"], c["change"]) for c in d["changes"]}


def listener(port: str, process: str = "agent", bind: str = "0.0.0.0") -> dict[str, Any]:  # noqa: S104
    return rec(
        "listeners",
        f"listener:tcp/{bind}/{port}",
        {"proto": "tcp", "bind": bind, "port": port, "process": process},
    )


# ---------------------------------------------------------------- malformed structure


@pytest.mark.parametrize(
    "damage",
    [
        {"inventory": None},
        {"inventory": []},
        {"inventory": "records"},
        {"findings": {"id": "X"}},
        {"findings": [{"title": "no id"}]},
        {"findings": ["PER-CRON-002"]},
        {"errors": {"code": "MODULE_FAILED"}},
        {"errors": ["MODULE_FAILED"]},
        {"errors": [{"message": "no code"}]},
    ],
    ids=[
        "inv-null",
        "inv-list",
        "inv-str",
        "findings-dict",
        "finding-no-id",
        "finding-str",
        "errors-dict",
        "error-str",
        "error-no-code",
    ],
)
def test_malformed_report_structure_is_rejected_not_ignored(damage: dict[str, Any]) -> None:
    r = report(standard_baseline())
    r.update(damage)
    with pytest.raises(ReportError):
        build_snapshot(r, Options())


def test_coverage_that_is_not_a_list_is_rejected() -> None:
    r = report(standard_baseline())
    r["inventory"]["coverage"] = {"domain": "users", "status": "complete"}
    with pytest.raises(ReportError, match="coverage"):
        build_snapshot(r, Options())


def test_a_report_without_the_inventory_key_still_loads_without_inventory() -> None:
    snap = build_snapshot(report(inventory=False), Options())
    assert snap.has_inventory is False


def test_a_dropped_error_cannot_turn_a_failure_into_a_resolution() -> None:
    # Previously a non-object entry in "errors" was skipped, hiding a MODULE_FAILED marker.
    cur = report(findings=[], inventory=False, **LATER)
    cur["errors"] = ["MODULE_FAILED"]
    with pytest.raises(ReportError):
        build_snapshot(cur, Options())


# ---------------------------------------------------------------- untrusted absence


def _resolved(cur_errors: list[dict[str, Any]], base_errors: list[dict[str, Any]], **cur_kw: Any):
    base = report(findings=[finding("USR-SUDO-003", "high")], errors=base_errors, inventory=False)
    cur = report(findings=[], errors=cur_errors, inventory=False, **{**LATER, **cur_kw})
    return run_diff(base, cur)["findings"]


def test_a_new_error_that_names_no_check_makes_absence_unverified() -> None:
    f = _resolved([{"code": "PASSWD_UNREADABLE", "message": "cannot read /etc/passwd"}], [])
    assert f["resolved"] == []
    assert [(x["id"], x["state"]) for x in f["unverified"]] == [("USR-SUDO-003", "resolved")]


def test_the_same_standing_error_does_not_block_resolutions() -> None:
    standing = [{"code": "UPTIME_UNAVAILABLE", "message": "no uptime"}]
    f = _resolved(standing, standing)
    assert [x["id"] for x in f["resolved"]] == ["USR-SUDO-003"]
    assert f["unverified"] == []


def test_an_error_naming_a_different_check_does_not_block_resolutions() -> None:
    other = [{"code": "PERM_DENIED", "message": "x", "check_id": "FS-SUID-001"}]
    assert [x["id"] for x in _resolved(other, [])["resolved"]] == ["USR-SUDO-003"]


@pytest.mark.parametrize("code", [1, 3, 6])
def test_a_failed_or_partial_current_run_makes_absence_unverified(code: int) -> None:
    base = report(findings=[finding("USR-SUDO-003", "high")], inventory=False)
    cur = report(findings=[], inventory=False, **LATER)
    cur["run"]["exit_code"] = code
    f = run_diff(base, cur)["findings"]
    assert f["resolved"] == [] and len(f["unverified"]) == 1


def test_a_baseline_that_was_equally_partial_does_not_block_resolutions() -> None:
    base = report(findings=[finding("USR-SUDO-003", "high")], inventory=False)
    base["run"]["exit_code"] = 6
    cur = report(findings=[], inventory=False, **LATER)
    cur["run"]["exit_code"] = 6
    assert len(run_diff(base, cur)["findings"]["resolved"]) == 1


@pytest.mark.parametrize("domain", ["users", "groups", "services", "processes"])
def test_a_complete_but_empty_core_domain_is_not_a_mass_removal(domain: str) -> None:
    base_records = standard_baseline()
    assert any(r["domain"] == domain for r in base_records)
    cur_records = [r for r in base_records if r["domain"] != domain]
    base, cur = report(base_records), report(cur_records, coverage=None, **LATER)
    cur["inventory"]["coverage"].append(cov(domain))  # declared complete, yet empty
    d = run_diff(base, cur)
    assert d["summary"]["removed"] == 0
    assert exit_code_for(d) == ExitCode.PARTIAL
    assert any("empty" in x["note"] for x in d["domains"] if x["domain"] == domain)


def test_an_empty_baseline_domain_does_not_make_everything_an_addition() -> None:
    base_records = [r for r in standard_baseline() if r["domain"] != "users"]
    base = report(base_records)
    base["inventory"]["coverage"].append(cov("users"))
    d = run_diff(base, report(standard_baseline(), **LATER))
    assert d["summary"]["added"] == 0
    assert exit_code_for(d) == ExitCode.PARTIAL


def test_a_genuinely_removed_single_user_is_still_reported() -> None:
    cur_records = [r for r in standard_baseline() if r["key"] != "user:bob"]
    d = run_diff(report(standard_baseline()), report(cur_records, **LATER))
    assert kinds(d) == {("user:bob", "removed")}


# ---------------------------------------------------------------- high-port listeners


def test_high_port_listeners_collapse_by_default() -> None:
    d = run_diff(
        report([listener("40111")]), report([listener("41222")], **LATER), ephemeral_from=32768
    )
    assert d["changes"] == []


def test_a_fixed_port_in_the_ephemeral_range_keeps_its_identity() -> None:
    opts = {"ephemeral_from": 32768, "fixed_ports": frozenset({40111})}
    same = run_diff(report([listener("40111")]), report([listener("40111")], **LATER), **opts)
    assert same["changes"] == []
    moved = run_diff(report([listener("40111")]), report([listener("41222")], **LATER), **opts)
    assert kinds(moved) == {
        ("listener:tcp/0.0.0.0/40111", "removed"),
        ("listener:tcp/0.0.0.0/ephemeral", "added"),
    }


def test_a_new_listener_on_a_fixed_high_port_is_an_addition_even_with_a_known_process() -> None:
    # Without fixed_ports this is hidden: the bucket already holds the same process name.
    base = report([listener("50000", "agent")])
    cur = report([listener("50000", "agent"), listener("40111", "agent")], **LATER)
    hidden = run_diff(base, cur, ephemeral_from=32768)
    assert hidden["changes"] == []
    shown = run_diff(
        report([listener("50000", "agent")]),
        report([listener("50000", "agent"), listener("40111", "agent")], **LATER),
        ephemeral_from=32768,
        fixed_ports=frozenset({40111}),
    )
    assert kinds(shown) == {("listener:tcp/0.0.0.0/40111", "added")}


def test_fixed_ports_config_is_validated() -> None:
    assert options_from_config({"fixed_ports": [40111, 50000]}).fixed_ports == {40111, 50000}
    for bad in ("40111", [0], [70000], [True], ["80"]):
        with pytest.raises(ConfigError, match="fixed_ports"):
            options_from_config({"fixed_ports": bad})
