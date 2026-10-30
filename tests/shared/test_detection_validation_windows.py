"""Controlled detection validation, Windows: real PowerShell collector -> diff -> detection rules.

Scenarios and expected outcomes are defined in docs/detection-validation.md (Part 1). Each one
changes a *copy* of ``tests/fixtures/windows-host`` (CIM/registry/task data as JSON, read through
the collector's ``BO_FIXTURE_DIR`` seam), audits it with ``Invoke-WindowsAudit.ps1`` and discards
it. The host running the test is never modified. Needs PowerShell (executed on the CI runners).
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from detection_validation import ceiling, evaluate, expect, find, keys
from test_windows_audit_report import SHELLS, _prepare_fixture, _run

from shared.reporting.detection import exit_code_for

pytestmark = pytest.mark.skipif(not SHELLS, reason="requires PowerShell")

AUDIT = "windows/audit/Invoke-WindowsAudit.ps1"
SID = "S-1-5-21-1000-2000-3000"
RUN = "Registry::HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"


def _edit(root: Path, name: str, change: Callable[[Any], None]) -> None:
    p = root / "data" / name
    data = json.loads(p.read_text("utf-8"))
    change(data)
    p.write_text(json.dumps(data), "utf-8")


def _user(name: str, rid: int) -> dict[str, Any]:
    return {
        "Name": name,
        "SID": f"{SID}-{rid}",
        "Disabled": False,
        "PasswordRequired": True,
        "PasswordExpires": True,
        "Description": "",
    }


def _rogue_admin(root: Path) -> None:
    _edit(root, "cim.Win32_UserAccount.json", lambda d: d.append(_user("svc_mallory", 1099)))
    _edit(
        root,
        "group.administrators.json",
        lambda d: d.append(
            {"Name": "FIXTURE-WS01\\svc_mallory", "SID": f"{SID}-1099", "ObjectClass": "User"}
        ),
    )


def _run_key(root: Path) -> None:
    _edit(
        root,
        "registry.json",
        lambda d: d[RUN]["values"].update({"Updater": "C:\\Users\\Public\\upd.exe"}),
    )


def _hidden_task(root: Path) -> None:
    task = {
        "TaskName": "UpdateChecker",
        "TaskPath": "\\",
        "State": "Ready",
        "Author": "",
        "UserId": "SYSTEM",
        "RunLevel": "Highest",
        "Hidden": True,
        "Actions": [{"Execute": "C:\\Users\\Public\\upd.exe", "Arguments": ""}],
        "Triggers": ["MSFT_TaskTimeTrigger"],
    }
    _edit(root, "tasks.scheduled.json", lambda d: d.append(task))


def _vendor_service(root: Path) -> None:
    svc = {
        "Name": "AcmeBackup",
        "DisplayName": "Acme Backup",
        "State": "Running",
        "StartMode": "Auto",
        "PathName": '"C:\\Program Files\\Acme\\backup.exe" --service',
        "StartName": "NT AUTHORITY\\LocalService",
    }
    _edit(root, "cim.Win32_Service.json", lambda d: d.append(svc))


def _ordinary_user(root: Path) -> None:
    _edit(root, "cim.Win32_UserAccount.json", lambda d: d.append(_user("jsmith", 1100)))


STATES = {
    "attacked": (_rogue_admin, _run_key, _hidden_task),
    "benign": (_vendor_service, _ordinary_user),
}


@pytest.fixture(scope="module")
def host(tmp_path_factory: pytest.TempPathFactory) -> Callable[..., dict[str, Any]]:
    """Audit a fresh fixture copy with the named state applied; results are cached."""
    work = tmp_path_factory.mktemp("win-validation")
    shell = SHELLS[0]

    @cache
    def build(state: str | None, modules: tuple[str, ...]) -> str:
        root = work / f"host-{len(list(work.iterdir()))}"
        _prepare_fixture(root)
        for mutate in STATES.get(state or "", ()):
            mutate(root)
        report = _run(shell, AUDIT, ["-Modules", ",".join(modules)] if modules else [], root)
        shutil.rmtree(root)  # disposable
        return json.dumps(report)

    def get(state: str | None = None, modules: tuple[str, ...] = ()) -> dict[str, Any]:
        return json.loads(build(state, modules))  # type: ignore[no-any-return]

    return get


def test_ws01_rogue_local_admin_is_critical(host: Callable[..., dict[str, Any]]) -> None:
    doc = evaluate(host(), host("attacked"))
    expect(doc, "group:S-1-5-32-544", {"BO-GRP-001"}, "critical", "observed")
    expect(doc, f"user:{SID}-1099", {"BO-USR-002"}, "medium", "observed")
    assert exit_code_for(doc) == 4


def test_ws02_run_key_to_public_folder_is_high_heuristic(
    host: Callable[..., dict[str, Any]],
) -> None:
    doc = evaluate(host(), host("attacked"))
    expect(doc, "persist:run:*:updater", {"BO-PER-002", "BO-EXE-001"}, "high", "heuristic")


def test_ws03_hidden_task_from_public_folder_is_high(host: Callable[..., dict[str, Any]]) -> None:
    doc = evaluate(host(), host("attacked"))
    expect(doc, "task:*updatechecker", {"BO-SCH-002", "BO-EXE-001"}, "high", "heuristic")


def test_ws04_ws05_benign_administration_stays_at_or_below_medium(
    host: Callable[..., dict[str, Any]],
) -> None:
    doc = evaluate(host(), host("benign"))
    expect(doc, "service:acmebackup", {"BO-SVC-001"}, "medium", "observed")
    expect(doc, f"user:{SID}-1100", {"BO-USR-002"}, "medium", "observed")
    ceiling(doc, "medium")
    assert not find(doc, "group:*")  # an ordinary user is not in any privileged group


def test_ws06_remediation_leaves_nothing_above_low(host: Callable[..., dict[str, Any]]) -> None:
    doc = evaluate(host("attacked"), host())
    ceiling(doc, "low")
    assert all(d["basis"] == "observed" for d in doc["detections"])
    assert not [k for k in keys(doc) if "mallory" in k.casefold()]


def test_ws07_partial_collection_is_never_a_clean_bill_of_health(
    host: Callable[..., dict[str, Any]],
) -> None:
    doc = evaluate(host(), host(modules=("users",)))
    assert doc["detections"] == []
    assert doc["coverage"]["complete"] is False and doc["coverage"]["gaps"]
    assert exit_code_for(doc) == 6
