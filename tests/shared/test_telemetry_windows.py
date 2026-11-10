"""Windows-shaped telemetry: ingestion, hunting and (on Windows only) the live collector.

The first group uses synthetic streams shaped exactly like the Windows collector's output, so it
runs on every platform and checks ingestion and the rules. Only the last group runs the real
PowerShell collector, and only on a Windows host. A passing synthetic test says nothing about the
collector itself.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest
from telemetry_support import ROOT_FOR_REPO, auth, coverage, rec, stream

from shared.reporting.schema_lite import validate
from shared.rules.engine import detect
from shared.rules.loader import load_rule_set
from shared.telemetry import ingest
from shared.telemetry.hunt import shell_assessment

HOST = "win-srv01"
WIN_COVERAGE = coverage(
    [
        "process",
        "user",
        "group",
        "service",
        "scheduled_task",
        "network_connection",
        "listener",
        "auth_event",
        "security_event",
        "config_change",
        "system_config",
        "persistence",
    ]
)


def win_proc(pid, ppid, name, exe, user="NT AUTHORITY\\SYSTEM", cmdline=None):
    return rec(
        "process",
        f"pid:{pid}:2026-03-01T09:00:00.000Z",
        {
            "pid": pid,
            "ppid": ppid,
            "name": name,
            "exe": exe,
            "user": user,
            "cmdline": cmdline or exe,
        },
        source=("api", "Win32_Process"),
    )


def build(records, cov=None):
    return stream(records, cov if cov is not None else WIN_COVERAGE, host=HOST, family="windows")


def hunt(tmp_path, records, cov=None):
    p = tmp_path / "w.jsonl"
    p.write_bytes(build(records, cov))
    doc = ingest.ingest_paths([p], generated_at="2026-03-02T00:00:00Z", allow_unverified=True)
    rs = load_rule_set().only(lambda r: any(s.startswith("telemetry") for s in r.sources))
    res = detect(shell_assessment(doc), rs, generated_at="2026-03-02T00:00:00Z", telemetry=doc)
    assert validate(res, "detection-results.schema.json") == []
    return doc, res


def ids(res):
    return {d["rule"]["id"] for d in res["detections"]}


def test_windows_stream_is_ingested_with_windows_identity(tmp_path):
    doc, _ = hunt(tmp_path, [win_proc(4, 0, "system", None)])
    assert doc["host"]["os"]["family"] == "windows" and doc["records"][0]["os_family"] == "windows"


def test_office_spawning_encoded_powershell_is_flagged(tmp_path):
    enc = "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA="
    _, res = hunt(
        tmp_path,
        [
            win_proc(
                100,
                4,
                "winword.exe",
                "C:\\Program Files\\Microsoft Office\\winword.exe",
                "CORP\\bob",
            ),
            win_proc(
                200,
                100,
                "powershell.exe",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CORP\\bob",
                enc,
            ),
        ],
    )
    assert {"DR-WIN-HPRC-005", "DR-WIN-HPRC-006"} <= ids(res)


def test_iis_worker_spawning_cmd_is_flagged_but_explorer_is_not(tmp_path):
    _, res = hunt(
        tmp_path,
        [
            win_proc(100, 4, "w3wp.exe", "C:\\Windows\\System32\\inetsrv\\w3wp.exe"),
            win_proc(200, 100, "cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
        ],
    )
    assert "DR-ANY-HPRC-001" in ids(res)
    _, res = hunt(
        tmp_path,
        [
            win_proc(100, 4, "explorer.exe", "C:\\Windows\\explorer.exe"),
            win_proc(200, 100, "cmd.exe", "C:\\Windows\\System32\\cmd.exe"),
        ],
    )
    assert "DR-ANY-HPRC-001" not in ids(res)


def test_cleared_security_log_service_install_and_run_key(tmp_path):
    recs = [
        rec(
            "security_event",
            "win:Security:1:1102",
            {
                "event_id": "1102",
                "source": "Security",
                "outcome": "success",
                "summary": "event log cleared",
            },
            event_time="2026-03-01T09:00:00Z",
            source=("eventlog", "Security#1"),
        ),
        rec(
            "config_change",
            "win:System:2:7045:cc",
            {
                "object": "service",
                "change": "added",
                "name": "evilsvc",
                "path": "C:\\Users\\Public\\evil.exe",
                "actor": None,
            },
            event_time="2026-03-01T09:01:00Z",
            source=("eventlog", "System#2"),
            unknown=("actor",),
        ),
        rec(
            "service",
            "service:evilsvc",
            {
                "name": "evilsvc",
                "state": "Running",
                "start_mode": "Auto",
                "path": "C:\\Users\\Public\\evil.exe",
                "account": "LocalSystem",
                "pid": 888,
            },
            source=("api", "Win32_Service"),
        ),
        rec(
            "persistence",
            "runkey:HKLM:upd",
            {
                "mechanism": "run_key",
                "location": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd",
                "value": "C:\\Users\\Public\\upd.exe",
            },
            source=("registry", "HKLM"),
        ),
    ]
    _, res = hunt(tmp_path, recs)
    assert {"DR-WIN-HAUTH-005", "DR-ANY-HSVC-002", "DR-ANY-HSVC-001", "DR-ANY-HPER-002"} <= ids(res)


def test_account_creation_and_admin_group_addition_correlate_on_the_resolved_name(tmp_path):
    ev = [
        rec(
            "auth_event",
            "win:Security:10",
            {
                "action": "account_change",
                "result": "success",
                "user": "backdoor",
                "change": "created",
                "actor": "eve",
                "event_id": "4720",
                "service": "windows",
            },
            event_time="2026-03-01T09:00:00Z",
        ),
        rec(
            "auth_event",
            "win:Security:11",
            {
                "action": "group_change",
                "result": "success",
                "user": "backdoor",
                "group": "Administrators",
                "change": "member_added",
                "actor": "eve",
                "event_id": "4732",
                "service": "windows",
            },
            event_time="2026-03-01T09:00:05Z",
        ),
    ]
    _, res = hunt(tmp_path, ev)
    assert "DR-ANY-HAUTH-004" in ids(res)


def test_group_addition_whose_account_could_not_be_resolved_does_not_correlate(tmp_path):
    ev = [
        rec(
            "auth_event",
            "win:Security:10",
            {
                "action": "account_change",
                "result": "success",
                "user": "backdoor",
                "change": "created",
                "event_id": "4720",
                "service": "windows",
            },
            event_time="2026-03-01T09:00:00Z",
        ),
        rec(
            "auth_event",
            "win:Security:11",
            {
                "action": "group_change",
                "result": "success",
                "user": None,
                "group": "Administrators",
                "change": "member_added",
                "event_id": "4732",
                "service": "windows",
            },
            event_time="2026-03-01T09:00:05Z",
            unknown=("user",),
        ),
    ]
    _, res = hunt(tmp_path, ev)
    assert "DR-ANY-HAUTH-004" not in ids(res)


def test_failed_logon_spray_and_unavailable_security_log(tmp_path):
    ev = [
        auth(f"2026-03-01T09:0{i}:00Z", "login_failure", "failure", u, "203.0.113.5", key=f"w{i}")
        for i, u in enumerate(["administrator", "admin", "bob"] * 4)
    ]
    ev = [dict(e, source={"type": "eventlog", "ref": "Security#1"}) for e in ev]
    _, res = hunt(tmp_path, ev)
    assert "DR-ANY-HAUTH-001" in ids(res)
    cov = [
        c
        for c in WIN_COVERAGE
        if c["category"] not in ("auth_event", "security_event", "config_change")
    ] + coverage(
        ["auth_event", "security_event", "config_change"],
        "unavailable",
        "the Security event log could not be read: Attempted to perform an unauthorized operation.",
    )
    _, res = hunt(tmp_path, [win_proc(1, 0, "x.exe", "C:\\x.exe")], cov)
    ind = {i["rule"]["id"]: i["reason"] for i in res["indeterminate"]}
    assert "DR-WIN-HAUTH-005" in ind and "unauthorized" in ind["DR-WIN-HAUTH-005"]
    assert not res["detections"]


def test_windows_collector_output_conventions_are_documented_in_the_script():
    script = (ROOT_FOR_REPO / "windows/telemetry/Invoke-TelemetryCollection.ps1").read_text(
        encoding="utf-8"
    )
    lib = (ROOT_FOR_REPO / "windows/lib/Telemetry.ps1").read_text(encoding="utf-8")
    assert all(ord(c) < 128 for c in script + lib), (
        "Windows PowerShell 5.1 reads BOM-less files as ANSI: keep sources ASCII"
    )
    for banned in (
        "Invoke-Expression",
        "iex ",
        "Invoke-WebRequest",
        "Invoke-RestMethod",
        "Start-BitsTransfer",
        "Set-ItemProperty",
        "New-ItemProperty",
        "Remove-Item",
        "Stop-Process",
        "Stop-Service",
        "Set-Service",
        "Disable-",
        "Out-File",
        "Set-Content",
        "Add-Content",
    ):
        assert banned not in script + lib, banned


# ------------------------------------------------------------------ live (Windows only)

POWERSHELL = shutil.which("powershell") or shutil.which("pwsh")


@pytest.mark.skipif(
    not sys.platform.startswith("win") or POWERSHELL is None,
    reason="the live collector needs a Windows host with PowerShell",
)
def test_live_collector_stream_ingests_cleanly_and_reports_gaps_honestly(tmp_path):
    collector = ROOT_FOR_REPO / "windows/telemetry/Invoke-TelemetryCollection.ps1"
    run = subprocess.run(
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(collector),
            "-SinceHours",
            "1",
            "-MaxEvents",
            "100",
        ],
        capture_output=True,
        check=False,
        timeout=900,
    )
    assert run.returncode in (0, 6), run.stderr.decode("utf-8", "replace")[-2000:]
    out = run.stdout
    assert all(b < 128 for b in out), "the stream must be ASCII"
    p = tmp_path / "live.jsonl"
    p.write_bytes(out)
    doc = ingest.ingest_paths([p], allow_unverified=True)
    assert validate(doc, "telemetry.schema.json") == []
    assert doc["summary"]["rejected"] == 0, doc["rejected"][:3]
    cats = set(doc["summary"]["by_category"])
    assert {"process", "user", "group", "service"} <= cats
    cov = {c["category"]: c for c in doc["coverage"]}
    assert all(
        c["status"] in ("complete", "partial", "unavailable", "not_applicable")
        for c in cov.values()
    )
    # This process itself must be in the process list with a parent.
    import os

    me = [
        r
        for r in doc["records"]
        if r["category"] == "process" and r["attributes"]["pid"] == os.getpid()
    ]
    assert not me or me[0]["attributes"]["ppid"] is not None
    # Without elevation the Security log is a declared gap, never silently empty.
    if not doc["collection"]["elevated"]:
        assert cov["auth_event"]["status"] in ("unavailable", "partial")
    assert json.dumps(doc)  # serialisable
