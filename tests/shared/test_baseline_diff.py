"""Deterministic regression tests for the baseline-diff engine (synthetic reports only)."""

from __future__ import annotations

import copy
import json
import random
from pathlib import Path
from typing import Any

import pytest
from baseline_builders import LATER, cov, finding, pair, rec, report, standard_baseline

from shared.reporting.baseline import (
    IncompatibleReportsError,
    compare,
    exit_code_for,
)
from shared.reporting.baseline_render import clean, render_text
from shared.reporting.contracts import ExitCode
from shared.reporting.inventory import (
    ConfigError,
    Options,
    ReportError,
    build_snapshot,
    options_from_config,
    read_report_file,
)

NOW = "2026-02-01T00:00:00Z"


def run_diff(base: dict[str, Any], cur: dict[str, Any], **opt: Any) -> dict[str, Any]:
    options = Options(**opt)
    return compare(build_snapshot(base, options), build_snapshot(cur, options), options, NOW)


def changes(d: dict[str, Any], kind: str | None = None) -> list[tuple[str, str, str]]:
    return [
        (c["domain"], c["key"], c["change"]) for c in d["changes"] if kind in (None, c["change"])
    ]


def reasons(d: dict[str, Any]) -> list[tuple[str, str]]:
    return [(i["key"], i["reason"]) for i in d["indeterminate"]]


def warning_codes(d: dict[str, Any]) -> list[str]:
    return [w["code"] for w in d["warnings"]]


# ----------------------------------------------------------------- basic semantics


def test_identical_inventory_has_no_changes() -> None:
    d = run_diff(*pair(standard_baseline(), standard_baseline()))
    assert d["changes"] == []
    assert d["indeterminate"] == []
    assert d["summary"]["unchanged"] == len(standard_baseline())
    assert exit_code_for(d) is ExitCode.OK


def test_added_removed_modified_users() -> None:
    cur = standard_baseline()
    cur = [r for r in cur if r["key"] != "user:bob"]
    cur.append(rec("users", "user:mallory", {"uid": "0", "shell": "/bin/bash", "home": "/tmp/m"}))
    for r in cur:
        if r["key"] == "user:alice":
            r["attrs"]["shell"] = "/bin/sh"
    d = run_diff(*pair(standard_baseline(), cur))
    assert changes(d) == [
        ("users", "user:alice", "modified"),
        ("users", "user:bob", "removed"),
        ("users", "user:mallory", "added"),
    ]
    alice = d["changes"][0]
    assert alice["attributes"] == [{"name": "shell", "before": "/bin/bash", "after": "/bin/sh"}]
    assert alice["priority"] == "high"
    assert exit_code_for(d) is ExitCode.FINDINGS


def test_change_carries_timestamps_and_window() -> None:
    cur = standard_baseline() + [rec("users", "user:eve", {"uid": "1005"})]
    d = run_diff(*pair(standard_baseline(), cur))
    assert d["window"] == {"from": "2026-01-01T10:05:00Z", "to": "2026-01-02T10:00:00Z"}
    added = d["changes"][0]
    assert added["observed"] == {"baseline_at": None, "current_at": "2026-01-02T10:05:00Z"}
    assert added["baseline"] is None
    assert added["current"]["attrs"] == {"uid": "1005"}


def test_volatile_values_are_never_compared() -> None:
    cur = standard_baseline()
    for r in cur:
        if r["domain"] in ("processes", "listeners"):
            r["volatile"] = {"pid": "99999", "cmdline": "different"}
    d = run_diff(*pair(standard_baseline(), cur))
    assert d["changes"] == []


def test_set_attribute_order_is_irrelevant_and_membership_changes_are_detected() -> None:
    base = [rec("groups", "group:sudo", {"gid": "27", "members": ["a", "b", "c"]})]
    same = [rec("groups", "group:sudo", {"gid": "27", "members": ["c", "a", "b", "a"]})]
    assert run_diff(*pair(base, same))["changes"] == []
    more = [rec("groups", "group:sudo", {"gid": "27", "members": ["a", "b", "c", "evil"]})]
    attr = run_diff(*pair(base, more))["changes"][0]["attributes"][0]
    assert attr["before"] == ["a", "b", "c"]
    assert attr["after"] == ["a", "b", "c", "evil"]


def test_scalar_types_are_normalised_across_producers() -> None:
    base = [rec("config", "config:x", {"enabled": True, "count": 1, "name": "v"})]
    cur = [rec("config", "config:x", {"enabled": "true", "count": "1", "name": "v"})]
    assert run_diff(*pair(base, cur))["changes"] == []


def test_list_with_unknown_member_is_unknown_not_empty() -> None:
    base = [rec("groups", "group:adm", {"members": ["a", "b"]})]
    cur = [rec("groups", "group:adm", {"members": ["a", None]})]
    d = run_diff(*pair(base, cur))
    assert d["changes"] == []
    assert reasons(d) == [("group:adm", "ATTRIBUTE_UNKNOWN")]


# ----------------------------------------------- transient pids / ephemeral ports


def test_ephemeral_listener_port_moving_is_not_a_change() -> None:
    def listener(port: str, pid: str) -> dict[str, Any]:
        return rec(
            "listeners",
            f"listener:tcp/0.0.0.0/{port}",
            {"proto": "tcp", "bind": "0.0.0.0", "port": port, "process": "chrome"},
            {"pid": pid},
        )

    d = run_diff(*pair([listener("40001", "10")], [listener("55123", "99")]))
    assert d["changes"] == []
    assert d["summary"]["unchanged"] == 1


def test_ephemeral_listener_with_new_process_is_a_modification() -> None:
    def listener(port: str, proc: str) -> dict[str, Any]:
        return rec(
            "listeners",
            f"listener:tcp/0.0.0.0/{port}",
            {"proto": "tcp", "bind": "0.0.0.0", "port": port, "process": proc},
        )

    d = run_diff(*pair([listener("40001", "chrome")], [listener("40002", "nc")]))
    assert changes(d) == [("listeners", "listener:tcp/0.0.0.0/ephemeral", "modified")]
    assert d["changes"][0]["attributes"][0]["after"] == ["nc"]


def test_fixed_service_port_change_is_removal_plus_addition() -> None:
    def listener(port: str) -> dict[str, Any]:
        return rec(
            "listeners",
            f"listener:tcp/0.0.0.0/{port}",
            {"proto": "tcp", "bind": "0.0.0.0", "port": port, "process": "app"},
        )

    d = run_diff(*pair([listener("8080")], [listener("8081")]))
    assert changes(d) == [
        ("listeners", "listener:tcp/0.0.0.0/8080", "removed"),
        ("listeners", "listener:tcp/0.0.0.0/8081", "added"),
    ]


def test_ephemeral_threshold_is_per_os_family_and_configurable() -> None:
    def listener(port: str) -> dict[str, Any]:
        return rec(
            "listeners",
            f"listener:tcp/0.0.0.0/{port}",
            {"proto": "tcp", "bind": "0.0.0.0", "port": port, "process": "svc"},
        )

    # 40000 is ephemeral on Linux (>= 32768) but a normal port on Windows (>= 49152).
    base, cur = pair([listener("40000")], [listener("40001")], family="windows")
    assert len(changes(run_diff(base, cur))) == 2
    base, cur = pair([listener("40000")], [listener("40001")], family="linux")
    assert changes(run_diff(base, cur)) == []
    base, cur = pair([listener("40000")], [listener("40001")], family="linux")
    assert len(changes(run_diff(base, cur, ephemeral_from=65536))) == 2


def test_new_ephemeral_listener_bind_is_reported() -> None:
    new = rec(
        "listeners",
        "listener:tcp/0.0.0.0/45000",
        {"proto": "tcp", "bind": "0.0.0.0", "port": "45000", "process": "x"},
    )
    d = run_diff(*pair(standard_baseline(), standard_baseline() + [new]))
    assert changes(d) == [("listeners", "listener:tcp/0.0.0.0/ephemeral", "added")]
    assert d["changes"][0]["current"]["volatile"]["port"] == ["45000"]
    assert d["changes"][0]["priority"] == "high"


def test_loopback_listener_is_low_priority() -> None:
    new = rec(
        "listeners",
        "listener:tcp/127.0.0.1/5432",
        {"proto": "tcp", "bind": "127.0.0.1", "port": "5432", "process": "postgres"},
    )
    d = run_diff(*pair(standard_baseline(), standard_baseline() + [new]))
    assert d["changes"][0]["priority"] == "low"


def test_process_instances_are_aggregated_and_pids_ignored() -> None:
    def procs(pids: list[str], exes: list[str | None]) -> list[dict[str, Any]]:
        return [
            rec(
                "processes",
                "process:www:php-fpm",
                {"user": "www", "comm": "php-fpm", "exe": exe},
                {"pid": pid},
            )
            for pid, exe in zip(pids, exes)
        ]

    base = procs(["1", "2", "3"], ["/usr/sbin/php-fpm"] * 3)
    cur = procs(["70", "71"], ["/usr/sbin/php-fpm"] * 2)
    assert run_diff(*pair(base, cur))["changes"] == []
    swapped = procs(["70"], ["/tmp/php-fpm"])
    d = run_diff(*pair(base, swapped))
    assert changes(d) == [("processes", "process:www:php-fpm", "modified")]
    assert d["changes"][0]["attributes"][0]["after"] == ["/tmp/php-fpm"]


def test_transient_processes_do_not_drive_the_result() -> None:
    cur = standard_baseline() + [
        rec("processes", "process:root:ps", {"user": "root", "comm": "ps", "exe": "/bin/ps"})
    ]
    d = run_diff(*pair(standard_baseline(), cur))
    assert d["changes"][0]["transient"] is True
    assert d["summary"]["added"] == 0
    assert d["summary"]["transient"] == 1
    assert exit_code_for(d) is ExitCode.OK
    assert "process:root:ps" not in render_text(d)
    assert "1 transient change(s) hidden" in render_text(d)
    assert "process:root:ps" in render_text(d, show_transient=True)


def test_non_transient_process_addition_counts() -> None:
    cur = standard_baseline() + [
        rec("processes", "process:root:miner", {"user": "root", "comm": "miner", "exe": "/tmp/m"})
    ]
    d = run_diff(*pair(standard_baseline(), cur))
    assert d["summary"]["added"] == 1
    assert d["changes"][0]["priority"] == "info"


# ------------------------------------------- incomplete audits and permission gaps


def test_unreadable_attribute_is_indeterminate_not_modified() -> None:
    base = [
        rec(
            "processes",
            "process:root:nginx",
            {"user": "root", "comm": "nginx", "exe": "/usr/sbin/nginx"},
        )
    ]
    cur = [rec("processes", "process:root:nginx", {"user": "root", "comm": "nginx", "exe": None})]
    d = run_diff(
        *pair(base, cur, elevated=True),
    )
    assert d["changes"] == []
    assert reasons(d) == [("process:root:nginx", "ATTRIBUTE_UNKNOWN")]
    assert exit_code_for(d) is ExitCode.PARTIAL


def test_privilege_difference_is_flagged() -> None:
    base = report(standard_baseline(), elevated=True)
    cur = report(
        standard_baseline(),
        elevated=False,
        **LATER,
    )
    assert "PRIVILEGE_DIFFERS" in warning_codes(run_diff(base, cur))


def test_partially_unreadable_process_group_is_unknown_not_a_removal_of_exes() -> None:
    base = [
        rec("processes", "process:root:worker", {"user": "root", "comm": "worker", "exe": "/a"}),
        rec("processes", "process:root:worker", {"user": "root", "comm": "worker", "exe": "/b"}),
    ]
    cur = [
        rec("processes", "process:root:worker", {"user": "root", "comm": "worker", "exe": "/a"}),
        rec("processes", "process:root:worker", {"user": "root", "comm": "worker", "exe": None}),
    ]
    d = run_diff(*pair(base, cur))
    assert d["changes"] == []
    assert reasons(d) == [("process:root:worker", "ATTRIBUTE_UNKNOWN")]


def test_partial_current_collection_never_claims_removal() -> None:
    cur = [r for r in standard_baseline() if r["key"] != "user:bob"]
    cov_cur = [cov("users", "partial", "passwd unreadable")] + [
        cov(d)
        for d in (
            "groups",
            "services",
            "processes",
            "listeners",
            "scheduled_tasks",
            "persistence",
            "config",
        )
    ]
    base = report(standard_baseline())
    d = run_diff(
        base,
        report(
            cur,
            coverage=cov_cur,
            **LATER,
        ),
    )
    assert changes(d, "removed") == []
    assert ("user:bob", "CURRENT_INCOMPLETE") in reasons(d)
    users = next(x for x in d["domains"] if x["domain"] == "users")
    assert users["status"] == "partial"
    assert exit_code_for(d) is ExitCode.PARTIAL


def test_partial_current_still_reports_modifications_and_additions() -> None:
    cur = standard_baseline() + [rec("users", "user:eve", {"uid": "5"})]
    cur[0]["attrs"]["shell"] = "/bin/zsh"
    d = run_diff(
        report(standard_baseline()),
        report(
            cur,
            coverage=[cov("users", "partial", "x")],
            **LATER,
        ),
    )
    assert ("users", "user:root", "modified") in changes(d)
    assert ("users", "user:eve", "added") in changes(d)


def test_partial_baseline_never_claims_addition() -> None:
    base = report(
        [r for r in standard_baseline() if r["domain"] == "users"],
        coverage=[cov("users", "partial", "no shadow")],
    )
    cur = report(
        standard_baseline() + [rec("users", "user:eve", {"uid": "5"})],
        **LATER,
    )
    d = run_diff(base, cur)
    assert changes(d, "added") == []
    assert ("user:eve", "BASELINE_INCOMPLETE") in reasons(d)


def test_degraded_collection_still_confirms_absence() -> None:
    cur = [r for r in standard_baseline() if r["key"] != "user:bob"]
    cur_cov = [cov("users", "degraded", "attributes need root")]
    d = run_diff(
        report(standard_baseline()),
        report(
            cur,
            coverage=cur_cov,
            **LATER,
        ),
    )
    assert ("users", "user:bob", "removed") in changes(d)


def test_unavailable_or_one_sided_domain_is_not_compared() -> None:
    base = report(standard_baseline())
    cur_recs = [r for r in standard_baseline() if r["domain"] != "services"]
    cur = report(cur_recs, **LATER)
    d = run_diff(base, cur)
    svc = next(x for x in d["domains"] if x["domain"] == "services")
    assert svc["status"] == "not_compared"
    assert not [c for c in d["changes"] if c["domain"] == "services"]
    cur2 = report(
        cur_recs,
        coverage=[cov("services", "unavailable", "systemctl missing")],
        **LATER,
    )
    svc2 = next(x for x in run_diff(base, cur2)["domains"] if x["domain"] == "services")
    assert svc2["status"] == "not_compared"


def test_domain_with_records_but_no_coverage_is_partial() -> None:
    base = report(standard_baseline())
    cur = report(
        [r for r in standard_baseline() if r["key"] != "user:bob"],
        coverage=[],
        **LATER,
    )
    d = run_diff(base, cur)
    assert changes(d, "removed") == []


def test_invalid_records_degrade_coverage_instead_of_vanishing() -> None:
    bad = rec("users", "user:bob", {"uid": {"nested": "object"}})
    cur_recs = [r for r in standard_baseline() if r["key"] != "user:bob"] + [bad]
    d = run_diff(
        report(standard_baseline()),
        report(cur_recs, **LATER),
    )
    assert changes(d, "removed") == []
    assert ("user:bob", "CURRENT_INCOMPLETE") in reasons(d)
    assert "INVALID_RECORD" in warning_codes(d)


def test_unknown_domain_is_skipped_with_warning() -> None:
    cur = standard_baseline() + [{"domain": "weather", "key": "x", "attrs": {}}]
    d = run_diff(*pair(standard_baseline(), cur))
    assert "UNKNOWN_DOMAIN" in warning_codes(d)
    assert d["changes"] == []


def test_record_limit_marks_every_domain_partial() -> None:
    d = run_diff(*pair(standard_baseline(), standard_baseline()), max_records=3)
    assert "RECORD_LIMIT" in warning_codes(d)
    assert all(x["status"] == "partial" for x in d["domains"])


# ----------------------------------------------------------- duplicates / identity


def test_conflicting_duplicate_keys_are_indeterminate() -> None:
    cur = standard_baseline() + [rec("users", "user:alice", {"uid": "0", "shell": "/bin/bash"})]
    d = run_diff(*pair(standard_baseline(), cur))
    assert ("user:alice", "RECORD_CONFLICT") in reasons(d)
    assert ("users", "user:alice", "modified") not in changes(d)


def test_identical_duplicate_keys_collapse() -> None:
    cur = standard_baseline() + [copy.deepcopy(standard_baseline()[0])]
    assert run_diff(*pair(standard_baseline(), cur))["changes"] == []


def test_windows_identifiers_are_case_insensitive_linux_are_not() -> None:
    svc_a = rec("services", "service:Spooler", {"start_mode": "Auto"})
    svc_b = rec("services", "service:spooler", {"start_mode": "Auto"})
    assert run_diff(*pair([svc_a], [svc_b], family="windows"))["changes"] == []
    assert len(run_diff(*pair([svc_a], [svc_b], family="linux"))["changes"]) == 2


# ------------------------------------------------------- compatibility / ordering


def test_different_os_family_is_refused_even_when_host_mismatch_allowed() -> None:
    linux = report(standard_baseline(), family="linux")
    win = report(standard_baseline(), family="windows", run="r2")
    with pytest.raises(IncompatibleReportsError):
        run_diff(linux, win, allow_host_mismatch=True)


def test_hostname_mismatch_is_refused_unless_allowed() -> None:
    a = report(standard_baseline(), host="web01")
    b = report(standard_baseline(), host="db01", run="r2")
    with pytest.raises(IncompatibleReportsError, match="hostnames differ"):
        run_diff(a, b)
    assert "HOST_MISMATCH" in warning_codes(run_diff(a, b, allow_host_mismatch=True))


def test_hostname_comparison_ignores_case() -> None:
    a = report(standard_baseline(), host="WEB01")
    b = report(standard_baseline(), host="web01", run="r2")
    assert "HOST_MISMATCH" not in warning_codes(run_diff(a, b))


def test_reversed_arguments_and_same_run_are_flagged() -> None:
    base, cur = pair(standard_baseline(), standard_baseline())
    assert "REVERSED_ORDER" in warning_codes(run_diff(cur, base))
    assert "SAME_RUN" in warning_codes(run_diff(base, copy.deepcopy(base)))


def test_diff_is_symmetric_in_additions_and_removals() -> None:
    cur = standard_baseline() + [rec("users", "user:eve", {"uid": "7"})]
    forward = run_diff(*pair(standard_baseline(), cur))
    backward = run_diff(*pair(cur, standard_baseline()))
    assert changes(forward, "added") == [("users", "user:eve", "added")]
    assert changes(backward, "removed") == [("users", "user:eve", "removed")]


# ------------------------------------------------ schema 0.1.0 compatibility (legacy)


def test_legacy_reports_compare_at_findings_level_only() -> None:
    base = report(
        findings=[
            finding("PER-CRON-002", "high", [("file", "/etc/cron.d/a")]),
            finding("USR-SUDO-002", "medium"),
        ],
        inventory=False,
        version="0.1.0",
    )
    cur = report(
        findings=[
            finding("PER-CRON-002", "high", [("file", "/etc/cron.d/a"), ("file", "/etc/cron.d/b")]),
            finding("NET-EXPOSE-001", "high"),
        ],
        inventory=False,
        version="0.1.0",
        **LATER,
    )
    d = run_diff(base, cur)
    assert "NO_INVENTORY" in warning_codes(d)
    assert d["domains"] == []
    assert [f["id"] for f in d["findings"]["new"]] == ["NET-EXPOSE-001"]
    assert [f["id"] for f in d["findings"]["resolved"]] == ["USR-SUDO-002"]
    assert d["findings"]["changed"][0]["evidence_added"] == ["/etc/cron.d/b"]
    assert exit_code_for(d) is ExitCode.FINDINGS


def test_legacy_baseline_with_new_current_does_not_invent_inventory_changes() -> None:
    base = report(inventory=False, version="0.1.0")
    cur = report(standard_baseline(), **LATER)
    d = run_diff(base, cur)
    assert d["changes"] == []
    assert all(x["status"] == "not_compared" for x in d["domains"])
    assert exit_code_for(d) is ExitCode.PARTIAL


def test_identical_legacy_reports_exit_partial_not_clean() -> None:
    a, b = pair([], [], inventory=False, version="0.1.0")
    assert exit_code_for(run_diff(a, b)) is ExitCode.PARTIAL


# --------------------------------------------------------------------- findings


def test_findings_ignore_titles_descriptions_and_process_evidence() -> None:
    base = [finding("PRC-CMD-001", "high", [("process", "pid=10")], "old text")]
    cur = [finding("PRC-CMD-001", "high", [("process", "pid=77")], "completely different text")]
    d = run_diff(
        report(findings=base, inventory=False, version="0.1.0"),
        report(
            findings=cur,
            inventory=False,
            version="0.1.0",
            **LATER,
        ),
    )
    assert d["findings"] == {"new": [], "resolved": [], "changed": [], "unverified": []}


def test_finding_severity_change_is_reported() -> None:
    d = run_diff(
        report(findings=[finding("X-Y-001", "low")], inventory=False),
        report(
            findings=[finding("X-Y-001", "critical")],
            inventory=False,
            **LATER,
        ),
    )
    assert d["findings"]["changed"][0]["before_severity"] == "low"
    assert d["findings"]["changed"][0]["after_severity"] == "critical"


def test_truncated_evidence_lists_are_not_diffed() -> None:
    truncated = "many items [300 items; only the first 100 are listed]"
    base = [finding("A-B-001", "info", [("file", "/a")], truncated)]
    cur = [finding("A-B-001", "info", [("file", "/b")], truncated)]
    d = run_diff(
        report(findings=base, inventory=False),
        report(
            findings=cur,
            inventory=False,
            **LATER,
        ),
    )
    assert d["findings"]["changed"] == []


def test_vanished_finding_with_a_coverage_gap_is_unverified() -> None:
    base = report(findings=[finding("USR-SUDO-003", "high")], inventory=False)
    cur = report(
        findings=[],
        errors=[
            {"code": "PERM_DENIED", "message": "sudoers unreadable", "check_id": "USR-SUDO-003"}
        ],
        inventory=False,
        **LATER,
    )
    d = run_diff(base, cur)
    assert d["findings"]["resolved"] == []
    assert d["findings"]["unverified"][0]["state"] == "resolved"


def test_related_findings_are_linked_through_evidence_refs() -> None:
    cur = standard_baseline()
    cur[9]["attrs"]["command"] = "/tmp/backdoor"
    cur_findings = [finding("PER-CRON-002", "high", [("file", "/etc/cron.d/backup")])]
    d = run_diff(
        report(standard_baseline()),
        report(
            cur,
            findings=cur_findings,
            **LATER,
        ),
    )
    assert d["changes"][0]["related_findings"] == ["PER-CRON-002"]


# ----------------------------------------------------- config, ignore, determinism


def test_ignore_patterns_drop_matching_records_on_both_sides() -> None:
    cur = standard_baseline() + [rec("config", "config:motd:serial", {"value": "7"})]
    cur_noisy = copy.deepcopy(cur)
    cur_noisy[-1]["attrs"]["value"] = "8"
    base, cur_report = pair(cur, cur_noisy)
    assert len(run_diff(base, cur_report)["changes"]) == 1
    d = run_diff(base, cur_report, ignore={"config": ("config:motd:*",)})
    assert d["changes"] == []
    assert d["summary"]["ignored"] == 2


def test_options_from_config_validates_input() -> None:
    assert options_from_config({"ephemeral_from": 50000}).ephemeral_from == 50000
    for bad in (
        [],
        {"unknown": 1},
        {"ephemeral_from": "x"},
        {"ephemeral_from": True},
        {"ephemeral_from": 0},
        {"transient_processes": "ps"},
        {"ignore": {"nope": ["a"]}},
        {"ignore": {"users": "a"}},
    ):
        with pytest.raises(ConfigError):
            options_from_config(bad)


def test_output_is_deterministic_and_independent_of_record_order() -> None:
    cur = standard_baseline() + [rec("users", "user:eve", {"uid": "7"})]
    cur[1]["attrs"]["shell"] = "/bin/sh"
    base_r, cur_r = pair(standard_baseline(), cur)
    first = json.dumps(run_diff(base_r, cur_r))
    shuffled_base, shuffled_cur = copy.deepcopy(base_r), copy.deepcopy(cur_r)
    rng = random.Random(7)  # noqa: S311 - deterministic test shuffle
    rng.shuffle(shuffled_base["inventory"]["records"])
    rng.shuffle(shuffled_cur["inventory"]["records"])
    assert json.dumps(run_diff(shuffled_base, shuffled_cur)) == first
    assert json.dumps(run_diff(base_r, cur_r)) == first


def test_inputs_are_not_mutated() -> None:
    base_r, cur_r = pair(standard_baseline(), standard_baseline() + [rec("users", "user:x", {})])
    before = copy.deepcopy((base_r, cur_r))
    run_diff(base_r, cur_r)
    assert (base_r, cur_r) == before


# ---------------------------------------------------------------- rendering safety


def test_terminal_escapes_are_neutralised_in_text_output() -> None:
    evil = "\x1b[2J\x1b]0;pwned\x07 name\r\n" + chr(0x202E) + "evil"
    cur = standard_baseline() + [
        rec("config", "config:evil", {"value": evil}, evidence=[("file", evil)])
    ]
    text = render_text(run_diff(*pair(standard_baseline(), cur)))
    assert "\x1b" not in text
    assert "\x07" not in text
    assert "\r" not in text
    assert "\\x1b[2J" in text
    assert all(ord(ch) < 127 for ch in text)


def test_control_characters_in_keys_are_rejected() -> None:
    cur = standard_baseline() + [rec("users", "user:bad\nname", {"uid": "1"})]
    d = run_diff(*pair(standard_baseline(), cur))
    assert "INVALID_RECORD" in warning_codes(d)
    assert changes(d) == []


def test_clean_truncates_long_values() -> None:
    assert clean("a" * 1000).endswith("...")
    assert len(clean("a" * 1000)) == 160
    assert clean(["x", None]) == "x, null"


# ----------------------------------------------------------------------- loading


def _write(tmp_path: Path, text: str, name: str = "r.json", encoding: str = "utf-8") -> Path:
    p = tmp_path / name
    p.write_bytes(text.encode(encoding))
    return p


def test_loader_accepts_bom_and_run_directory(tmp_path: Path) -> None:
    text = json.dumps(report(standard_baseline()))
    run_dir = tmp_path / "blueops-run-x"
    run_dir.mkdir()
    _write(run_dir, text, "report.json", "utf-8-sig")
    assert read_report_file(run_dir)["schema_version"] == "0.2.0"


@pytest.mark.parametrize(
    ("text", "match"),
    [
        ("{not json", "not valid JSON"),
        ('{"a": 1, "a": 2}', "duplicate object key"),
        ('{"a": NaN}', "non-finite"),
        ("[1, 2]", "top level"),
        ("[" * 100000, "not valid JSON"),
        ("", "not valid JSON"),
    ],
)
def test_loader_rejects_malformed_json(tmp_path: Path, text: str, match: str) -> None:
    with pytest.raises(ReportError, match=match):
        read_report_file(_write(tmp_path, text))


def test_loader_rejects_missing_and_oversized_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ReportError, match="cannot read"):
        read_report_file(tmp_path / "missing.json")
    monkeypatch.setattr("shared.reporting.inventory.MAX_REPORT_BYTES", 10)
    with pytest.raises(ReportError, match="limit"):
        read_report_file(_write(tmp_path, json.dumps(report())))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda r: r.pop("host"),
        lambda r: r.pop("run"),
        lambda r: r["run"].update(started_at="yesterday"),
        lambda r: r["run"].update(finished_at="2026-13-45T00:00:00Z"),
        lambda r: r["host"]["os"].pop("family"),
        lambda r: r.update(schema_version="1.0.0"),
        lambda r: r.update(schema_version="0.3.0"),
        lambda r: r.update(schema_version="banana"),
        lambda r: r.pop("schema_version"),
        lambda r: r["inventory"].update(records="nope"),
    ],
)
def test_snapshot_rejects_invalid_reports(mutate: Any) -> None:
    r = report(standard_baseline())
    mutate(r)
    with pytest.raises(ReportError):
        build_snapshot(r, Options())


def test_bad_coverage_entries_do_not_crash_and_are_not_trusted() -> None:
    r = report(standard_baseline())
    r["inventory"]["coverage"] = [
        {"domain": "users", "status": "wonderful"},
        {"domain": "users", "status": "complete"},
        "garbage",
        {"domain": "nope", "status": "complete"},
    ]
    snap = build_snapshot(r, Options())
    assert snap.coverage[("users", "")][0] == "partial"
    assert any(w["code"] == "BAD_COVERAGE" for w in snap.warnings)


# ----------------------------------------------------------------- scoped coverage


def test_scopes_are_judged_independently() -> None:
    base_recs = [
        rec("config", "config:sudoers:a", {"rule": "x"}, scope="sudoers"),
        rec("config", "config:dns:resolv", {"ns": ["1.1.1.1"]}, scope="dns"),
    ]
    cur_recs = [rec("config", "config:sudoers:a", {"rule": "x"}, scope="sudoers")]
    d = run_diff(*pair(base_recs, cur_recs))
    # DNS was not collected in the current run: that is a coverage gap, not a removal.
    assert d["changes"] == []
    dns = next(x for x in d["domains"] if x["scope"] == "dns")
    assert dns["status"] == "not_compared"
    sudoers = next(x for x in d["domains"] if x["scope"] == "sudoers")
    assert sudoers["status"] == "compared"


def test_partial_scope_does_not_block_other_scopes() -> None:
    base_recs = [
        rec("persistence", "persist:systemd:/etc/a", {"sha256": "1"}, scope="systemd"),
        rec("persistence", "persist:shell:/etc/b", {"sha256": "2"}, scope="shell"),
    ]
    cov_cur = [
        cov("persistence", "partial", "cannot read /etc/b", scope="shell"),
        cov("persistence", scope="systemd"),
    ]
    d = run_diff(
        report(base_recs),
        report([], coverage=cov_cur, **LATER),
    )
    assert changes(d, "removed") == [("persistence", "persist:systemd:/etc/a", "removed")]
    assert reasons(d) == [("persist:shell:/etc/b", "CURRENT_INCOMPLETE")]


def test_scope_without_coverage_is_partial() -> None:
    recs = [rec("config", "config:x", {"v": "1"}, scope="mystery")]
    snap = build_snapshot(report(recs, coverage=[cov("config", scope="other")]), Options())
    assert snap.coverage[("config", "mystery")][0] == "partial"


def test_invalid_record_taints_every_scope_of_its_domain() -> None:
    recs = [
        rec("config", "config:a", {"v": "1"}, scope="one"),
        rec("config", "config:b", {"v": "1"}, scope="two"),
        rec("config", "config:bad", {"v": {"nested": 1}}, scope="two"),
    ]
    snap = build_snapshot(report(recs), Options())
    assert snap.coverage[("config", "one")][0] == "partial"
    assert snap.coverage[("config", "two")][0] == "partial"
