"""The Linux collector against the *real* host it runs on (no fixtures, no test hooks).

This is what fixture tests cannot show: that the parsers cope with this kernel's /proc, this
distribution's logs and this user's privileges. Assertions are about invariants, never about what
the host happens to be running.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest
from engine_support import POSIX_BASH
from telemetry_linux_support import COLLECTOR

from shared.engine.cli import main
from shared.reporting.schema_lite import validate
from shared.telemetry import ingest

pytestmark = pytest.mark.skipif(
    not (POSIX_BASH and sys.platform.startswith("linux")),
    reason="the live check needs a Linux host with bash",
)


def clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("BO_")}
    env["BO_LIVE"] = "1"
    return env


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    out = tmp_path_factory.mktemp("live")
    run = subprocess.run(
        [str(COLLECTOR), "--since-hours", "1", "--max-events", "200"],
        env=clean_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    assert run.returncode in (0, 6), run.stderr[-2000:]
    p = out / "live.jsonl"
    p.write_text(run.stdout, encoding="utf-8")
    return ingest.ingest_paths([p]), run


def test_live_stream_is_valid_and_has_no_rejections(live):
    doc, _ = live
    assert validate(doc, "telemetry.schema.json") == []
    assert doc["summary"]["rejected"] == 0, doc["rejected"][:3]
    assert not any(e["code"] == "TEST_MODE" for e in doc["errors"])


def test_live_process_list_contains_this_process_with_the_right_parent(live):
    doc, _ = live
    me = [
        r
        for r in doc["records"]
        if r["category"] == "process" and r["attributes"]["pid"] == os.getpid()
    ]
    assert me, "the running test process must be in the process list"
    assert me[0]["attributes"]["ppid"] == os.getppid()
    assert "python" in me[0]["attributes"]["name"].lower()


def test_live_accounts_include_root_and_never_carry_hashes(live):
    doc, run = live
    names = {r["attributes"]["name"] for r in doc["records"] if r["category"] == "user"}
    assert "root" in names
    assert "$6$" not in run.stdout and "$y$" not in run.stdout and "$5$" not in run.stdout


def test_live_gaps_are_declared_when_unprivileged(live):
    doc, _ = live
    if os.geteuid() != 0:
        assert doc["collection"]["elevated"] is False
        assert any(e["code"] == "NOT_PRIVILEGED" for e in doc["errors"])
        assert doc["summary"]["complete"] is False
    cov = {c["category"]: c["status"] for c in doc["coverage"]}
    # Every category the collector knows is accounted for, never silently missing.
    assert {
        "process",
        "user",
        "group",
        "network_connection",
        "listener",
        "auth_event",
        "integrity",
        "persistence",
    } <= set(cov)


def test_live_collection_is_repeatable_and_comparable(live, tmp_path):
    doc, run = live
    again = subprocess.run(
        [str(COLLECTOR), "--since-hours", "1", "--max-events", "200"],
        env=clean_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    p = tmp_path / "again.jsonl"
    p.write_text(again.stdout, encoding="utf-8")
    d2 = ingest.ingest_paths([p])
    # The same host gives the same host id, and users/groups/integrity records keep stable ids.
    assert d2["host"]["host_id"] == doc["host"]["host_id"]
    stable = {"user", "group", "integrity"}
    a = {r["record_id"] for r in doc["records"] if r["category"] in stable}
    b = {r["record_id"] for r in d2["records"] if r["category"] in stable}
    assert a == b


def test_cli_collect_end_to_end_on_this_host(tmp_path, monkeypatch, capsys):
    for k in [k for k in os.environ if k.startswith("BO_")]:
        monkeypatch.delenv(k)
    rc = main(
        [
            "telemetry",
            "collect",
            "--output-dir",
            str(tmp_path / "out"),
            "--since-hours",
            "1",
            "--max-events",
            "100",
            "--quiet",
            "--format",
            "json",
        ]
    )
    assert rc in (0, 6), capsys.readouterr()
    store = next((tmp_path / "out").glob("blueops-telemetry-*"))
    assert main(
        ["telemetry", "hunt", str(store), "--format", "json", "--quiet", "--fail-on", "critical"]
    ) in (0, 4, 6)
    assert (
        main(
            [
                "telemetry",
                "report",
                str(store),
                "--format",
                "html",
                "--output",
                str(tmp_path / "r.html"),
            ]
        )
        == 0
    )
    assert "Content-Security-Policy" in (tmp_path / "r.html").read_text(encoding="utf-8")
