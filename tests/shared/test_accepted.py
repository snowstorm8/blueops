"""Remediation false positives, hash-only honesty and the accepted-change allowlist.

Synthetic data only; time is fixed so every result is deterministic.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from baseline_builders import rec
from jsonschema import Draft202012Validator
from test_detection import NOW, SCHEMA, _diff, cron, one, reports, run, svc, user

from shared.reporting import detect as detect_cli
from shared.reporting import detection
from shared.reporting.accepted import AllowlistError, load
from shared.reporting.detection import Severity, detect, exit_code_for

RULE_IDS = frozenset(r.rule_id for r in detection.RULES)
RC = "persist:file:/etc/rc.local"
SUDOERS = "config:sudoers:/etc/sudoers.d/ops"


def rc_local(sha: str) -> dict[str, Any]:
    return rec("persistence", RC, {"sha256": sha}, scope="startup")


def sudoers(sha: str) -> dict[str, Any]:
    return rec("config", SUDOERS, {"sha256": sha}, scope="sudoers")


def listener(proc: str) -> dict[str, Any]:
    return rec("listeners", "listener:tcp/0.0.0.0/4444", {"process": proc, "port": "4444"})


# ------------------------------------------------------------ remediation false positives


def keys(doc: dict[str, Any]) -> set[str]:
    return {d["subject"]["key"] for d in doc["detections"]}


def test_security_service_that_was_already_down_is_not_reported_again() -> None:
    doc = run(
        [svc("auditd", active="failed")],
        [svc("auditd", active="inactive")],
    )
    assert "service:auditd" not in keys(doc)


def test_security_service_going_down_still_fires() -> None:
    doc = run([svc("auditd")], [svc("auditd", active="failed")])
    assert "BO-SVC-004" in {r["rule"] for d in doc["detections"] for r in d["reasons"]}


def test_restarting_a_stopped_security_service_is_quiet() -> None:
    doc = run([svc("auditd", active="inactive")], [svc("auditd", active="running")])
    assert "service:auditd" not in keys(doc)


@pytest.mark.parametrize(
    ("before", "after", "fires"),
    [("0", "1", False), ("0", "2", False), ("1", "2", False), ("2", "1", True), ("2", "0", True)],
)
def test_aslr_only_fires_when_the_setting_drops(before: str, after: str, fires: bool) -> None:
    key = "config:sysctl:kernel.randomize_va_space"
    doc = run(
        [rec("config", key, {"value": before}, scope="sysctl")],
        [rec("config", key, {"value": after}, scope="sysctl")],
    )
    assert (key in keys(doc)) is fires


def test_listener_leaving_a_netcat_tool_is_low_but_the_reverse_is_not() -> None:
    fixed = one(run([listener("nc")], [listener("sshd")]), "listener:tcp/0.0.0.0/4444")
    assert fixed["severity"] == "low"
    assert "remediation" in fixed["summary"]
    attack = one(run([listener("sshd")], [listener("nc")]), "listener:tcp/0.0.0.0/4444")
    assert attack["severity"] != "low"


def test_argument_change_on_an_already_temporary_command_is_not_a_new_exposure() -> None:
    doc = run([cron(1, "/tmp/tool.sh --a")], [cron(1, "/tmp/tool.sh --b")])
    assert "BO-EXE-001" not in {r["rule"] for d in doc["detections"] for r in d["reasons"]}


def test_only_the_newly_added_temporary_path_is_reported() -> None:
    doc = run([cron(1, "/tmp/old.sh")], [cron(1, "/tmp/old.sh; /dev/shm/new.sh")])
    d = one(doc, "cron:/etc/cron.d/job#1")
    exe = next(r for r in d["reasons"] if r["rule"] == "BO-EXE-001")
    assert "/dev/shm/new.sh" in exe["observation"]
    assert "/tmp/old.sh" not in exe["observation"]


def test_removing_a_persistence_file_or_sudoers_drop_in_is_silent() -> None:
    doc = run([rc_local("a"), sudoers("a")], [])
    assert doc["detections"] == []


# ------------------------------------------------------------ hash-only honesty


def test_hash_only_persistence_change_says_what_is_unknown() -> None:
    d = one(run([rc_local("aaaaaaaaaaaaaaaa")], [rc_local("bbbbbbbbbbbbbbbb")]), RC)
    assert "only its content hash differs" in d["summary"]
    assert "aaaaaaaaaaaa" in d["summary"] and "bbbbbbbbbbbb" in d["summary"]
    text = " ".join(d["unknown"])
    assert "SHA-256" in text and "restored" in text and "known-good" in text
    assert d["severity"] == "high"  # unknown direction is not a reason to stay quiet


def test_hash_only_sudoers_change_is_explicit_and_added_file_content_is_unknown() -> None:
    changed = one(run([sudoers("a")], [sudoers("b")]), SUDOERS)
    assert any("NOPASSWD" in u and "narrowed" in u for u in changed["unknown"])
    added = one(run([], [sudoers("b")]), SUDOERS)
    assert any("new file contains" in u for u in added["unknown"])


def test_records_with_readable_content_claim_no_unknowns() -> None:
    d = one(run([], [cron(1, "/tmp/p.sh")]), "cron:/etc/cron.d/job#1")
    assert d["unknown"] == []
    reg = rec("persistence", "persist:run:HKLM:Updater", {"value": "C:\\x.exe"}, scope="run")
    assert one(run([], [reg]), "persist:run:HKLM:Updater")["unknown"] == []


def test_text_output_lists_what_is_not_known() -> None:
    doc = run([rc_local("a")], [rc_local("b")])
    assert "not known: What changed inside the file" in detect_cli.render_text(doc)


# ------------------------------------------------------------ the allowlist


def entry(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "AC-1",
        "rules": ["BO-PER-002"],
        "domain": "persistence",
        "key": RC,
        "scope": "startup",
        "change": "modified",
        "current": {"sha256": "b"},
        "max_severity": "high",
        "reason": "Change ticket 123: approved rc.local edit",
        "approved_by": "ops-lead",
        "approved_at": "2026-03-01T00:00:00Z",
        "expires": "2026-04-01T00:00:00Z",
    }
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


def allowfile(tmp_path: Path, *entries: dict[str, Any], **top: Any) -> str:
    doc = {"schema_version": "0.1.0", "kind": "accepted-changes", "entries": list(entries), **top}
    p = tmp_path / "accepted.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def with_allow(tmp_path: Path, base: list, cur: list, *entries: dict[str, Any]) -> dict[str, Any]:
    allow = load(allowfile(tmp_path, *entries), RULE_IDS)
    doc = detect(_diff(*reports(base, cur)), NOW, allow=allow)
    Draft202012Validator(SCHEMA).validate(doc)
    return doc


def test_exact_match_moves_the_detection_without_changing_it(tmp_path: Path) -> None:
    plain = run([rc_local("a")], [rc_local("b")])
    doc = with_allow(tmp_path, [rc_local("a")], [rc_local("b")], entry())
    assert doc["detections"] == []
    assert doc["summary"]["total"] == 0 and doc["summary"]["accepted"] == 1
    kept = copy.deepcopy(doc["accepted"][0])
    acceptance = kept.pop("acceptance")
    assert kept == plain["detections"][0]  # evidence, reasons, attributes, unknowns all intact
    assert acceptance["entry"] == "AC-1" and acceptance["approved_by"] == "ops-lead"
    assert exit_code_for(doc) == 0  # nothing left to investigate and coverage is complete


def test_allowlist_audit_is_in_the_document(tmp_path: Path) -> None:
    path = allowfile(tmp_path, entry(), entry(id="AC-2", key="persist:file:/etc/other"))
    doc = detect(_diff(*reports([rc_local("a")], [rc_local("b")])), NOW, allow=load(path, RULE_IDS))
    audit = doc["allowlist"]
    assert audit["source"] == "accepted.json" and len(audit["sha256"]) == 64
    assert [(e["id"], e["status"]) for e in audit["entries"]] == [
        ("AC-1", "matched"),
        ("AC-2", "unused"),
    ]
    assert audit["entries"][0]["matched"] == [doc["accepted"][0]["id"]]


@pytest.mark.parametrize(
    ("over", "why"),
    [
        ({"key": "persist:file:/etc/rc.local2"}, None),
        ({"key": "persist:file:/etc/*"}, None),  # no wildcards
        ({"domain": "config"}, None),
        ({"scope": "other"}, None),
        ({"change": "added"}, None),
        ({"current": {"sha256": "c"}}, None),  # a different change to the same file
        ({"rules": ["BO-CFG-005"]}, "other rules also fired"),
        ({"max_severity": "medium"}, "severity above max_severity"),
        ({"expires": "2026-03-01T12:00:00Z"}, "expired"),
    ],
)
def test_entries_that_do_not_match_suppress_nothing(
    tmp_path: Path, over: dict[str, Any], why: str | None
) -> None:
    doc = with_allow(tmp_path, [rc_local("a")], [rc_local("b")], entry(**over))
    assert [d["subject"]["key"] for d in doc["detections"]] == [RC]
    assert doc["accepted"] == []
    assert exit_code_for(doc) == 4
    if why:
        assert doc["allowlist"]["entries"][0]["not_applied"][0]["why"] == why
    if over.get("expires"):
        assert doc["allowlist"]["entries"][0]["status"] == "expired"


def test_an_entry_does_not_cover_a_detection_that_has_extra_reasons(tmp_path: Path) -> None:
    job = cron(1, "/tmp/payload.sh")
    e = entry(
        rules=["BO-SCH-001"],
        domain="scheduled_tasks",
        key="cron:/etc/cron.d/job#1",
        scope="cron",
        change="added",
        current=None,
    )
    doc = with_allow(tmp_path, [], [job], e)
    assert len(doc["detections"]) == 1  # the heuristic temp-path reason is not accepted
    both = {**e, "rules": ["BO-SCH-001", "BO-EXE-001"], "id": "AC-2"}
    doc = with_allow(tmp_path, [], [job], both)
    assert doc["detections"] == [] and len(doc["accepted"]) == 1


def test_critical_detections_cannot_be_accepted(tmp_path: Path) -> None:
    with pytest.raises(AllowlistError, match="critical"):
        load(allowfile(tmp_path, entry(max_severity="critical")), RULE_IDS)
    crit = {
        "id": "AC-9",
        "rules": ["BO-USR-001", "BO-USR-002"],
        "domain": "users",
        "key": "user:mallory",
        "max_severity": "high",
    }
    e = entry(**{**crit, "scope": None, "change": None, "current": None})
    doc = with_allow(tmp_path, [user("root", "0")], [user("root", "0"), user("mallory", "0")], e)
    assert any(d["subject"]["key"] == "user:mallory" for d in doc["detections"])
    assert doc["allowlist"]["entries"][0]["not_applied"][0]["why"] == "severity above max_severity"


def test_accepting_one_change_does_not_hide_a_correlated_one(tmp_path: Path) -> None:
    base = [rc_local("a")]
    cur = [rc_local("b"), cron(1, "/tmp/payload.sh")]
    doc = with_allow(tmp_path, base, cur, entry())
    assert [d["subject"]["key"] for d in doc["detections"]] == ["cron:/etc/cron.d/job#1"]
    assert doc["summary"]["accepted"] == 1 and exit_code_for(doc) == 4


def test_min_severity_does_not_change_the_acceptance_audit(tmp_path: Path) -> None:
    allow = load(allowfile(tmp_path, entry()), RULE_IDS)
    diff = _diff(*reports([rc_local("a")], [rc_local("b")]))
    a = detect(diff, NOW, allow=allow)
    b = detect(diff, NOW, Severity.CRITICAL, allow)
    assert a["allowlist"] == b["allowlist"] and a["accepted"] == b["accepted"]


def test_output_is_deterministic(tmp_path: Path) -> None:
    docs = [
        json.dumps(with_allow(tmp_path, [rc_local("a")], [rc_local("b")], entry()), sort_keys=True)
        for _ in range(2)
    ]
    assert docs[0] == docs[1]


# ------------------------------------------------------------ strict loading


@pytest.mark.parametrize(
    ("over", "message"),
    [
        ({"surprise": 1}, "unknown field"),
        ({"reason": None}, "missing field"),
        ({"reason": "  "}, "'reason'"),
        ({"approved_by": None}, "missing field"),
        ({"expires": None}, "missing field"),
        ({"max_severity": None}, "missing field"),
        ({"max_severity": "urgent"}, "not a severity"),
        ({"rules": []}, "'rules'"),
        ({"rules": ["BO-XXX-999"]}, "unknown rule"),
        ({"rules": "BO-PER-002"}, "'rules'"),
        ({"id": "bad id"}, "'id'"),
        ({"expires": "2026-02-01T00:00:00Z"}, "after 'approved_at'"),
        ({"expires": "tomorrow"}, "UTC timestamps"),
        ({"change": "renamed"}, "'change'"),
        ({"current": {}}, "'current'"),
        ({"current": {"sha256": 5}}, "'current' values"),
    ],
)
def test_malformed_entries_are_errors_not_ignored(
    tmp_path: Path, over: dict[str, Any], message: str
) -> None:
    with pytest.raises(AllowlistError, match=message):
        load(allowfile(tmp_path, entry(**over)), RULE_IDS)


def test_malformed_files_are_errors(tmp_path: Path) -> None:
    with pytest.raises(AllowlistError, match="duplicate"):
        load(allowfile(tmp_path, entry(), entry()), RULE_IDS)
    with pytest.raises(AllowlistError, match="unknown field"):
        load(allowfile(tmp_path, entry(), extra=1), RULE_IDS)
    with pytest.raises(AllowlistError, match="kind"):
        load(allowfile(tmp_path, entry(), kind="other"), RULE_IDS)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(AllowlistError, match="cannot read"):
        load(str(bad), RULE_IDS)
    with pytest.raises(AllowlistError, match="cannot read"):
        load(str(tmp_path / "missing.json"), RULE_IDS)


# ------------------------------------------------------------ CLI


def _diff_file(tmp_path: Path) -> str:
    p = tmp_path / "diff.json"
    p.write_text(json.dumps(_diff(*reports([rc_local("a")], [rc_local("b")]))), encoding="utf-8")
    return str(p)


def test_cli_allowlist_end_to_end(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    diff = _diff_file(tmp_path)
    args = ["--from-diff", diff, "--generated-at", NOW, "--quiet"]
    assert detect_cli.main([*args, "--json"]) == 4
    capsys.readouterr()
    allow = allowfile(tmp_path, entry())
    assert detect_cli.main([*args, "--json", "--accepted", allow]) == 0
    doc = json.loads(capsys.readouterr().out)
    Draft202012Validator(SCHEMA).validate(doc)
    assert doc["summary"]["accepted"] == 1
    assert detect_cli.main([*args, "--accepted", allow]) == 0
    out = capsys.readouterr().out
    assert "Accepted changes" in out and "AC-1 by ops-lead" in out and "matched" in out


def test_cli_rejects_a_bad_allowlist_with_exit_3(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    diff = _diff_file(tmp_path)
    allow = allowfile(tmp_path, entry(reason=None))
    code = detect_cli.main(["--from-diff", diff, "--generated-at", NOW, "--accepted", allow])
    assert code == 3
    assert "missing field" in capsys.readouterr().err


def test_hostile_allowlist_text_cannot_forge_terminal_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    diff = _diff_file(tmp_path)
    allow = allowfile(tmp_path, entry(reason="ok\x1b[2J\nFAKE LINE", approved_by="a\x07b"))
    detect_cli.main(["--from-diff", diff, "--generated-at", NOW, "--accepted", allow])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x07" not in out
    assert "\nFAKE LINE" not in out
