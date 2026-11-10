"""The Linux telemetry collector against a synthetic root, and its output through ingestion/hunting.

These tests run the real Bash collector, so they need bash on a POSIX host. They verify the
collector's behaviour against *fixtures*; they say nothing about a particular distribution. A real
host is exercised separately (see test_telemetry_live.py).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from engine_support import POSIX_BASH
from telemetry_linux_support import COLLECTOR, env_for, telemetry_root, tree_digest

from shared.engine.cli import main
from shared.rules.engine import detect
from shared.rules.loader import load_rule_set
from shared.telemetry import ingest
from shared.telemetry.hunt import shell_assessment

pytestmark = pytest.mark.skipif(
    not POSIX_BASH, reason="the Linux collector needs bash on a POSIX host"
)


@pytest.fixture(scope="module")
def stream_text(tmp_path_factory: pytest.TempPathFactory) -> str:
    root = telemetry_root(tmp_path_factory.mktemp("tel") / "root")
    run = subprocess.run(
        [str(COLLECTOR), "--since-hours", "100000"],
        env=env_for(root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode in (0, 6), run.stderr
    return run.stdout


@pytest.fixture(scope="module")
def doc(stream_text: str, tmp_path_factory: pytest.TempPathFactory):
    p = tmp_path_factory.mktemp("in") / "s.jsonl"
    p.write_text(stream_text, encoding="utf-8")
    return ingest.ingest_paths([p], generated_at="2026-03-02T00:00:00Z", allow_unverified=True)


def rows(stream_text: str, kind: str) -> list[dict]:
    return [d for d in (json.loads(x) for x in stream_text.splitlines()) if d["type"] == kind]


def recs(doc, category: str) -> list[dict]:
    return [r for r in doc["records"] if r["category"] == category]


# ------------------------------------------------------------------ stream contract


def test_stream_has_header_end_marker_and_matching_count(stream_text):
    lines = [json.loads(x) for x in stream_text.splitlines()]
    assert lines[0]["type"] == "header" and lines[-1]["type"] == "end"
    assert lines[-1]["records"] == sum(1 for x in lines if x["type"] == "record")
    assert (
        lines[0]["host"]["os"]["family"] == "linux"
        and lines[0]["collector"]["name"] == "blueops-linux-telemetry"
    )


def test_every_stream_line_is_valid_json_and_ingests_without_rejections(doc):
    assert doc["summary"]["rejected"] == 0
    assert {
        "process",
        "user",
        "group",
        "service",
        "scheduled_task",
        "listener",
        "network_connection",
        "auth_event",
        "security_event",
        "system_config",
        "integrity",
        "persistence",
    } <= set(doc["summary"]["by_category"])


def test_fixture_hooks_are_reported_so_a_fixture_run_is_never_mistaken_for_a_host(doc):
    assert (
        any(e["code"] == "TEST_MODE" for e in doc["errors"]) and doc["summary"]["complete"] is False
    )


def test_unavailable_sources_are_reported_not_hidden(doc):
    cov = {c["category"]: c for c in doc["coverage"]}
    assert cov["session"]["status"] in ("complete", "unavailable")
    assert cov["network_connection"]["status"] in ("complete", "partial")


# ------------------------------------------------------------------ processes


def test_process_parentage_exe_and_deleted_flag(doc):
    by_pid = {r["attributes"]["pid"]: r["attributes"] for r in recs(doc, "process")}
    assert (
        by_pid[401]["ppid"] == 400
        and by_pid[400]["ppid"] == 1
        and by_pid[401]["user"] == "www-data"
    )
    assert by_pid[402]["exe_deleted"] is True and by_pid[402]["exe"] == "/dev/shm/.x/agent"
    assert by_pid[400]["exe_deleted"] is False


def test_command_lines_are_redacted(stream_text):
    assert "hunter2" not in stream_text and "password=<redacted>" in stream_text


def test_process_key_includes_start_time_so_a_reused_pid_is_not_a_duplicate(doc):
    assert any(r["key"] == "pid:401:5100" for r in recs(doc, "process"))


# ------------------------------------------------------------------ accounts: no secrets


def test_password_hashes_are_never_in_the_stream(stream_text):
    assert not re.search(r"\$[156y]\$", stream_text), "a crypt hash leaked into the stream"


def test_password_state_is_a_classification_only(doc):
    states = {
        r["attributes"]["name"]: r["attributes"].get("password_state") for r in recs(doc, "user")
    }
    assert set(states.values()) <= {"locked", "set", "empty", "unknown", None}
    assert any(v in ("set", "locked", "empty") for v in states.values())


# ------------------------------------------------------------------ network


def test_sockets_are_decoded_and_owned(doc):
    conns = {r["attributes"]["inode"]: r["attributes"] for r in recs(doc, "network_connection")}
    c = conns[777001]
    assert (c["remote_address"], c["remote_port"], c["state"], c["pid"], c["process"]) == (
        "203.0.113.9",
        4444,
        "established",
        401,
        "bash",
    )
    lst = {r["attributes"]["inode"]: r["attributes"] for r in recs(doc, "listener")}
    assert (
        lst[777002]["local_port"] == 8081
        and lst[777002]["local_address"] == "0.0.0.0"
        and lst[777002]["process"] == "agent"
    )


def test_ipv6_is_canonical_and_ipv4_mapped_is_unwrapped(doc):
    addrs = {
        r["attributes"]["inode"]: r["attributes"]["local_address"] for r in recs(doc, "listener")
    }
    assert addrs[9] == "::1" and addrs[10] == "127.0.0.1"


def test_unowned_sockets_are_unknown_not_empty(doc):
    c = next(r for r in recs(doc, "network_connection") if r["attributes"]["inode"] == 3)
    assert (
        c["attributes"]["pid"] is None
        and {"pid", "process"} <= set(c["unknown_attributes"])
        and c["status"] == "partial"
    )


# ------------------------------------------------------------------ authentication


def test_auth_events_cover_the_log(doc):
    ev = recs(doc, "auth_event")
    acts = {(e["attributes"]["action"], e["attributes"]["result"]) for e in ev}
    assert {
        ("login_failure", "failure"),
        ("login_success", "success"),
        ("sudo", "success"),
        ("sudo", "failure"),
        ("su", "success"),
        ("su", "failure"),
        ("account_change", "success"),
        ("group_change", "success"),
    } <= acts
    assert sum(e["occurrences"] for e in ev if e["attributes"]["action"] == "login_failure") == 12


def test_invalid_user_failures_are_attributed_to_the_name_tried(doc):
    users = {
        e["attributes"]["user"]
        for e in recs(doc, "auth_event")
        if e["attributes"]["action"] == "login_failure"
    }
    assert {"root", "admin", "alice"} <= users


def test_account_creation_and_group_change_are_decoded(doc):
    ev = {
        (e["attributes"].get("change"), e["attributes"]["user"], e["attributes"].get("group"))
        for e in recs(doc, "auth_event")
    }
    assert ("created", "backdoor", None) in ev and ("member_added", "backdoor", "sudo") in ev


def test_auth_summary_is_derived(doc):
    s = next(r for r in recs(doc, "auth_summary") if r["key"] == "source:198.51.100.4")
    assert (
        s["attributes"]["failures"] == 12
        and s["attributes"]["users_targeted"] == 3
        and s["attributes"]["success_after_failure"] is True
    )


def test_audit_log_events_and_config_changes(doc):
    sec = {r["attributes"]["event_id"] for r in recs(doc, "security_event")}
    assert {"ADD_USER", "USER_AUTH", "CONFIG_CHANGE"} <= sec and "SYSCALL" not in sec
    cc = {
        (r["attributes"]["object"], r["attributes"]["change"]) for r in recs(doc, "config_change")
    }
    assert ("user", "added") in cc and ("audit_rules", "modified") in cc
    ev = next(r for r in recs(doc, "security_event") if r["attributes"]["event_id"] == "ADD_USER")
    assert ev["event_time"] == "2026-03-01T09:20:00Z"


def test_traditional_syslog_lines_have_no_guessed_time(tmp_path):
    root = telemetry_root(tmp_path / "root")
    (root / "var/log/auth.log").write_text(
        "Mar  1 09:00:01 web01 sshd[100]: Failed password for root from 198.51.100.4 port 1 ssh2\n",
        encoding="utf-8",
    )
    run = subprocess.run(
        [str(COLLECTOR), "--since-hours", "100000"],
        env=env_for(root),
        capture_output=True,
        text=True,
        check=False,
    )
    p = tmp_path / "s.jsonl"
    p.write_text(run.stdout, encoding="utf-8")
    d = ingest.ingest_paths([p], allow_unverified=True)
    ev = next(r for r in d["records"] if r["category"] == "auth_event")
    assert "event_time" not in ev and ev["status"] == "partial"
    cov = next(c for c in d["coverage"] if c["category"] == "auth_event")
    assert cov["status"] == "partial" and "no usable time" in cov["reason"]


def test_missing_auth_sources_are_unavailable_not_empty(tmp_path):
    root = telemetry_root(tmp_path / "root")
    (root / "var/log/auth.log").unlink()
    run = subprocess.run(
        [str(COLLECTOR), "--since-hours", "100000", "--categories", "auth_event"],
        env=env_for(root),
        capture_output=True,
        text=True,
        check=False,
    )
    cov = [json.loads(x) for x in run.stdout.splitlines() if '"coverage"' in x]
    assert (
        cov[0]["category"] == "auth_event"
        and cov[0]["status"] == "unavailable"
        and run.returncode == 6
    )


# ------------------------------------------------------------------ configuration, integrity, persistence


def test_sshd_settings_stop_at_match_blocks(doc):
    cfg = {r["attributes"]["setting"]: r["attributes"]["value"] for r in recs(doc, "system_config")}
    assert cfg["sshd.permitrootlogin"] == "yes" and cfg["sshd.passwordauthentication"] == "yes"


def test_integrity_hashes_are_sha256_and_exclude_secrets(doc):
    paths = {r["attributes"]["path"] for r in recs(doc, "integrity")}
    assert "/etc/passwd" in paths and not any("shadow" in p or "id_rsa" in p for p in paths)
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", r["attributes"]["sha256"])
        for r in recs(doc, "integrity")
        if r["attributes"]["sha256"]
    )


def test_ld_preload_and_authorized_keys_persistence_without_key_material(doc, stream_text):
    mech = {r["attributes"]["mechanism"] for r in recs(doc, "persistence")}
    assert "ld_preload" in mech
    assert not re.search(r"ssh-(rsa|ed25519) AAAA", stream_text)


# ------------------------------------------------------------------ behaviour and safety


def test_collection_does_not_modify_the_root(tmp_path):
    root = telemetry_root(tmp_path / "root")
    before = tree_digest(root)
    subprocess.run(
        [str(COLLECTOR), "--since-hours", "100000"],
        env=env_for(root),
        capture_output=True,
        text=True,
        check=False,
    )
    assert tree_digest(root) == before


def test_script_has_no_network_or_write_commands():
    text = COLLECTOR.read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    # a command word: at the start of a line or right after a pipe, ;, &&, ( or a keyword
    commands = r"(?:^|[|;&(]|\bthen\b|\bdo\b|\$\()\s*(curl|wget|nc|ncat|netcat|ssh|scp|rsync|ftp|telnet|sudo|eval|tee)\s"
    assert re.findall(commands, code, flags=re.MULTILINE) == []
    for banned in ("rm -rf /", "chmod 777", "> /etc", ">> /etc"):
        assert banned not in code, banned


@pytest.mark.parametrize(
    "argv",
    [
        ["--bogus"],
        ["--since-hours", "0"],
        ["--max-events", "x"],
        ["--categories", "nope"],
        ["--since-hours"],
    ],
)
def test_usage_errors_exit_2(argv):
    run = subprocess.run([str(COLLECTOR), *argv], capture_output=True, text=True, check=False)
    assert run.returncode == 2 and run.stdout == ""


def test_categories_limit_what_is_collected(tmp_path):
    root = telemetry_root(tmp_path / "root")
    run = subprocess.run(
        [str(COLLECTOR), "--categories", "group,user"],
        env=env_for(root),
        capture_output=True,
        text=True,
        check=False,
    )
    cats = {json.loads(x).get("category") for x in run.stdout.splitlines() if '"record"' in x}
    assert cats == {"group", "user"}


def test_max_events_caps_events_and_says_so(tmp_path):
    root = telemetry_root(tmp_path / "root")
    run = subprocess.run(
        [
            str(COLLECTOR),
            "--since-hours",
            "100000",
            "--max-events",
            "3",
            "--categories",
            "auth_event",
        ],
        env=env_for(root),
        capture_output=True,
        text=True,
        check=False,
    )
    errs = [json.loads(x) for x in run.stdout.splitlines() if '"error"' in x]
    assert any(e["code"] == "EVENT_LIMIT" for e in errs)
    assert sum(1 for x in run.stdout.splitlines() if '"record"' in x) == 3


def test_log_injection_cannot_forge_a_stream_line(tmp_path):
    root = telemetry_root(tmp_path / "root")
    evil = '2026-03-01T09:00:01+00:00 web01 sshd[1]: Failed password for root"}\n{"type":"record","category":"user" from 198.51.100.4 port 1 ssh2\n'
    (root / "var/log/auth.log").write_text(evil, encoding="utf-8")
    run = subprocess.run(
        [str(COLLECTOR), "--since-hours", "100000", "--categories", "auth_event"],
        env=env_for(root),
        capture_output=True,
        text=True,
        check=False,
    )
    for line in run.stdout.splitlines():
        json.loads(line)  # every line is a well-formed object
    assert '"category":"user"' not in run.stdout.replace('"category":"auth_event"', "")


# ------------------------------------------------------------------ end to end


def test_cli_collect_import_hunt_report_workflow(tmp_path, monkeypatch, capsys):
    root = telemetry_root(tmp_path / "root")
    for k, v in env_for(root).items():
        monkeypatch.setenv(k, v)
    # The CLI's own window limit (<= 2160h) is below the age of the fixture logs, so the event
    # sources are empty here: this test checks the workflow and the store, not the event content.
    monkeypatch.setattr("shared.telemetry.cli.REPO_ROOT", COLLECTOR.parents[2])
    rc = main(
        [
            "telemetry",
            "collect",
            "--output-dir",
            str(tmp_path / "out"),
            "--since-hours",
            "2160",
            "--format",
            "json",
        ]
    )
    out = capsys.readouterr().out
    assert rc in (0, 6), out
    store = next((tmp_path / "out").glob("blueops-telemetry-*"))
    assert (
        (store / "telemetry.json").is_file()
        and (store / "manifest.json").is_file()
        and list((store / "sources").iterdir())
    )
    assert main(["telemetry", "show", str(store)]) == 0
    assert main(["telemetry", "tree", str(store), "--pid", "401"]) == 0
    tree = capsys.readouterr().out
    assert "nginx" in tree and "bash" in tree


def test_hunting_finds_the_planted_activity_and_explains_it(doc):
    rs = load_rule_set()
    res = detect(
        shell_assessment(doc),
        rs.only(lambda r: "telemetry" in {s.split("_")[0] for s in r.sources}),
        generated_at="2026-03-02T00:00:00Z",
        telemetry=doc,
    )
    hits = {d["rule"]["id"] for d in res["detections"]}
    for d in res["detections"]:
        e = d["explanation"]
        assert (
            d["contributing"]
            and e["why_flagged"]
            and e["disclaimer"]
            and e["possible_benign_causes"]
        )
        assert d["nature"] in ("observation", "indicator", "correlated", "hypothesis")
    assert {
        "DR-ANY-HPRC-001",
        "DR-ANY-HPRC-004",
        "DR-ANY-HNET-001",
        "DR-LNX-HPRC-003",
        "DR-ANY-HAUTH-001",
        "DR-ANY-HAUTH-002",
        "DR-ANY-HAUTH-003",
        "DR-ANY-HAUTH-004",
    } <= hits


# ------------------------------------------------------------------ permissions


def _unprivileged(argv: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run as a non-root user: directly when the tests are not root, through setpriv otherwise."""
    if os.geteuid() == 0:
        argv = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", *argv]
    return subprocess.run(argv, env=env, capture_output=True, text=True, check=False)


@pytest.mark.skipif(
    os.name != "posix" or (os.geteuid() == 0 and shutil.which("setpriv") is None),
    reason="needs a non-root user (or setpriv to drop root)",
)
def test_unreadable_sources_become_visible_gaps_not_silence(tmp_path):
    # pytest's own tmp directories are private to the owner, so an unprivileged user could not
    # even reach the root: build it in a world-traversable directory that is removed afterwards.
    base = Path(tempfile.mkdtemp(prefix="bo-tel-"))
    try:
        base.chmod(0o755)
        root = telemetry_root(base / "root")
        for p in [root, *[x for x in root.rglob("*") if x.is_dir() and not x.is_symlink()]]:
            p.chmod(0o755)
        for rel in ("etc/shadow", "var/log/audit/audit.log", "var/log/auth.log", "etc/sudoers"):
            (root / rel).chmod(0o000)
        (root / "proc/401/fd").chmod(0o000)
        _assert_gaps_are_visible(root, tmp_path)
    finally:
        for p in sorted(base.rglob("*"), reverse=True):
            if p.is_dir() and not p.is_symlink():
                p.chmod(0o755)
        shutil.rmtree(base, ignore_errors=True)


def _assert_gaps_are_visible(root, tmp_path):
    run = _unprivileged([str(COLLECTOR), "--since-hours", "100000"], env_for(root))
    assert run.returncode == 6, run.stderr
    d = ingest_text(run.stdout, tmp_path)
    cov = {c["category"]: c for c in d["coverage"]}
    assert cov["user"]["status"] == "partial" and "shadow" in cov["user"]["reason"]
    assert cov["auth_event"]["status"] == "unavailable"
    assert (
        cov["security_event"]["status"] == "unavailable"
        and "not readable" in cov["security_event"]["reason"]
    )
    assert (
        any(e["code"] == "NOT_PRIVILEGED" for e in d["errors"])
        and d["collection"]["elevated"] is False
    )
    states = {r["attributes"]["password_state"] for r in d["records"] if r["category"] == "user"}
    assert states == {None}, "an unreadable shadow file must yield unknown password states"


def ingest_text(text, tmp_path):
    p = tmp_path / "unpriv.jsonl"
    p.write_text(text, encoding="utf-8")
    return ingest.ingest_paths([p], allow_unverified=True)
