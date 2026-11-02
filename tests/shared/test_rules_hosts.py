"""Rules over realistic synthetic hosts: clean hosts stay quiet, compromised ones light up the
right rules, results are stable (golden files) and cross-platform data does not leak between OSes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from engine_support import POSIX_BASH, ROOT, collector_env, linux_fixture_root
from rules_support import (
    FIX,
    STAMP,
    doc,
    history,
    linux_clean,
    linux_compromised,
    record,
    windows_clean,
    windows_compromised,
)

from shared.engine.loader import load_assessment
from shared.reporting.schema_lite import validate
from shared.rules.engine import detect, exit_code_for
from shared.rules.loader import load_rule_set

RS = load_rule_set()
UPDATE = os.environ.get("BO_UPDATE_GOLDEN") == "1"


def fired(res: dict[str, Any]) -> set[str]:
    return {d["rule"]["id"] for d in res["detections"]}


def run(spec: dict[str, Any], platform: str, prev: list[Any] | None = None) -> dict[str, Any]:
    res = detect(doc(spec, platform=platform), RS, previous=prev, generated_at=STAMP)
    assert validate(res, "detection-results.schema.json") == []
    assert res["rule_errors"] == []
    return res


def test_a_clean_linux_host_raises_no_detections_and_no_indeterminate_rules_without_history_needs() -> (
    None
):
    res = run(linux_clean(), "linux")
    assert res["detections"] == [], [d["title"] for d in res["detections"]]
    # only the snapshot-based rules cannot be evaluated (no earlier snapshot): never "clean", always said so
    assert {i["rule"]["id"] for i in res["indeterminate"]} == {
        "DR-ANY-CHG-001", "DR-ANY-CHG-002", "DR-ANY-CHG-003", "DR-ANY-CHG-004", "DR-ANY-CHG-005",
        "DR-ANY-COR-002", "DR-ANY-COR-003", "DR-ANY-PRIV-001",
    }  # fmt: skip
    assert exit_code_for(res).name == "PARTIAL"


def test_a_clean_windows_host_raises_no_detections() -> None:
    res = run(windows_clean(), "windows")
    assert res["detections"] == [], [d["title"] for d in res["detections"]]


def test_clean_host_with_history_is_fully_evaluated_and_exits_zero() -> None:
    prev = history(*[linux_clean() for _ in range(3)])
    res = run(linux_clean(), "linux", prev)
    assert (
        res["detections"] == [] and res["indeterminate"] == [] and exit_code_for(res).name == "OK"
    )
    assert res["rules"]["evaluated"] + res["rules"]["not_applicable"] == res["rules"]["total"]


def test_compromised_linux_host_lights_up_the_expected_rules() -> None:
    res = run(linux_compromised(), "linux")
    assert fired(res) >= {
        "DR-LNX-ACC-001", "DR-LNX-PER-001", "DR-LNX-LOG-001", "DR-LNX-SVC-001", "DR-ANY-NET-001",
        "DR-ANY-PRIV-002", "DR-ANY-COR-001", "DR-ANY-COR-005",
    }  # fmt: skip
    assert not fired(res) & {
        "DR-WIN-ACC-001",
        "DR-WIN-SVC-001",
        "DR-WIN-PER-001",
    }  # platform rules stay on their platform
    by_rule = {d["rule"]["id"]: d for d in res["detections"]}
    cor = by_rule["DR-ANY-COR-001"]
    assert "/tmp/.hidden/agent" in cor["explanation"]["why_correlated"].lower()
    assert {c["check_id"] for c in cor["contributing"]} == {"PER-SYSTEMD-001", "FS-PERM-003"}
    priv = by_rule["DR-ANY-PRIV-002"]
    assert priv["severity"] == "high" and "bypass" in priv["explanation"]["severity_rationale"]


def test_compromised_windows_host_lights_up_the_expected_rules() -> None:
    res = run(windows_compromised(), "windows")
    assert fired(res) >= {
        "DR-WIN-ACC-001", "DR-WIN-SVC-001", "DR-WIN-TSK-001", "DR-WIN-PER-001", "DR-WIN-LOG-001",
        "DR-WIN-CRED-001", "DR-ANY-NET-002", "DR-ANY-COR-001", "DR-ANY-COR-005",
        "DR-ANY-PRIV-002",
    }  # fmt: skip
    assert not any(r.startswith("DR-LNX") for r in fired(res))
    cred = next(d for d in res["detections"] if d["rule"]["id"] == "DR-WIN-CRED-001")
    assert cred["severity"] == "high"  # Defender disabled: the explicit severity rule
    log = next(d for d in res["detections"] if d["rule"]["id"] == "DR-WIN-LOG-001")
    assert log["severity"] == "medium" and len({c["check_id"] for c in log["contributing"]}) >= 3


def test_false_positive_guards() -> None:
    spec = linux_clean()
    spec["inventory"] += [
        record(
            "users", "user:backup", {"uid": "34", "shell": "/usr/sbin/nologin", "password": "empty"}
        ),  # empty password, no shell
        record(
            "listeners",
            "listener:tcp/127.0.0.1/23",
            {"proto": "tcp", "bind": "127.0.0.1", "port": "23", "process": "telnetd"},
        ),
        record(
            "config", "config:suid:/usr/lib/tmp/helper", {"mode": "4755"}, "suid"
        ),  # path contains /tmp-like text only
        record(
            "config",
            "config:core:core_pattern",
            {"value": "|/usr/share/apport/apport -p%p"},
            "core",
        ),
    ]
    spec["inventory"] = [
        r
        for r in spec["inventory"]
        if not (r["key"] == "config:core:core_pattern" and "systemd" in r["attrs"]["value"])
    ]
    res = run(spec, "linux")
    assert res["detections"] == [], [d["title"] for d in res["detections"]]
    win = windows_clean()
    win["inventory"] += [
        record(
            "services",
            "service:vendor",
            {"account": "LocalSystem", "image_path": "C:\\Program Files\\Vendor\\svc.exe"},
        ),
        record(
            "services",
            "service:usersvc",
            {"account": ".\\bob", "image_path": "C:\\Users\\bob\\svc.exe"},
        ),
        record(
            "users",
            "user:S-1-5-21-1-501",
            {"name": "Guest", "enabled": False, "password_required": False},
        ),
    ]
    assert run(win, "windows")["detections"] == []


def test_cross_platform_rules_see_both_operating_systems() -> None:
    for platform, spec in (("linux", linux_compromised()), ("windows", windows_compromised())):
        res = run(spec, platform)
        assert any(r.startswith("DR-ANY-") for r in fired(res)), platform


def test_golden_detections_for_the_synthetic_hosts() -> None:
    for name, platform, spec in (
        ("linux-compromised", "linux", linux_compromised()),
        ("windows-compromised", "windows", windows_compromised()),
    ):
        res = detect(doc(spec, platform=platform, aid=name), RS, generated_at=STAMP)
        for d in res["detections"]:
            d["rule"]["pack"] = d["rule"]["pack"]  # explicit: pack names are part of the contract
        res["rule_packs"] = [{**p, "source": Path(p["source"]).name} for p in res["rule_packs"]]
        text = json.dumps(res, indent=2, sort_keys=True) + "\n"
        path = FIX / f"expected-detections-{name}.json"
        if UPDATE:
            path.write_text(text, encoding="utf-8", newline="\n")
        assert text == path.read_text("utf-8"), (
            f"{path.name} changed; regenerate with BO_UPDATE_GOLDEN=1 and review the diff"
        )


def test_the_stored_collector_output_is_detected_end_to_end() -> None:
    """A real Linux collector run (stored, so the test does not depend on the collector)."""
    cur = load_assessment(FIX / "linux-compromised.assessment.json")
    res = detect(cur, RS, generated_at=STAMP)
    assert validate(res, "detection-results.schema.json") == [] and res["rule_errors"] == []
    assert fired(res) >= {
        "DR-LNX-ACC-001",
        "DR-LNX-ACC-002",
        "DR-LNX-PER-001",
        "DR-ANY-NET-001",
        "DR-LNX-SVC-001",
        "DR-ANY-PRIV-002",
        "DR-ANY-COR-004",
    }
    # traceability to the stored assessment
    fids = {f["id"] for f in cur["findings"]}
    eids = {e["id"] for e in cur["evidence"]}
    keys = {(r["domain"], r.get("scope", ""), r["key"]) for r in cur["inventory"]["records"]}
    for d in res["detections"]:
        assert set(d["evidence"]) <= eids
        for c in d["contributing"]:
            assert (
                c["id"] in fids
                if c["type"] == "finding"
                else (c["domain"], c["scope"], c["key"]) in keys
            )


@pytest.mark.skipif(not POSIX_BASH, reason="requires bash on a POSIX host")
def test_detection_over_a_live_collector_run_matches_the_stored_one(tmp_path: Path) -> None:
    root = linux_fixture_root(tmp_path / "root")
    out = tmp_path / "out"
    proc = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "shared.engine",
            "run",
            "--platform",
            "linux",
            "--output-dir",
            str(out),
            "--quiet",
            "--detect",
            "--report",
            "none",
        ],
        capture_output=True,
        text=True,
        env=collector_env(root),
        cwd=ROOT,
        check=False,
        timeout=300,
    )
    assert proc.returncode == 4, proc.stderr
    (d,) = out.glob("blueops-assessment-*")
    live = json.loads((d / "detections.json").read_text("utf-8"))
    stored = detect(
        load_assessment(FIX / "linux-compromised.assessment.json"), RS, generated_at=STAMP
    )
    assert {x["rule"]["id"] for x in live["detections"]} == fired(stored)


@pytest.mark.parametrize("family", ["linux", "windows"])
def test_existing_report_fixtures_are_processed_without_errors(family: str) -> None:
    base = ROOT / "tests" / "fixtures" / "baseline-e2e" / family
    for name in ("baseline", "changed", "unprivileged", "module-failed", "churn"):
        cur = load_assessment(base / f"{name}.json")
        res = detect(cur, RS, generated_at=STAMP)
        assert validate(res, "detection-results.schema.json") == [] and res["rule_errors"] == [], (
            name
        )
        # an incomplete audit must show up as indeterminate rules, never as silence
        if name == "module-failed":
            assert res["indeterminate"] or res["detections"]
