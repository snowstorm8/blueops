"""Shipped examples must stay valid: they are what the documentation tells people to copy."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import pytest
from engine_support import ROOT, linux_fixture_root

from shared.engine.cli import main
from shared.engine.manifest import verify_directory
from shared.engine.registry import load_manifest
from shared.findings.model import finding_id, host_id
from shared.reporting.render_html import render_html
from shared.reporting.render_markdown import render_markdown
from shared.reporting.schema_lite import validate

EXAMPLES = ROOT / "examples"
POSIX = os.name == "posix"


def test_example_assessment_is_valid_and_renders() -> None:
    doc = json.loads((EXAMPLES / "assessment.example.json").read_text("utf-8"))
    assert validate(doc, "assessment.schema.json") == []
    assert doc["summary"]["total"] == len(doc["findings"]) == 3
    assert "web01" in render_html(doc) and "web01" in render_markdown(doc)


def test_example_assessment_ids_are_what_the_engine_would_compute() -> None:
    doc = json.loads((EXAMPLES / "assessment.example.json").read_text("utf-8"))
    hid = host_id(doc["host"]["hostname"], doc["host"]["os"]["family"])
    for f in doc["findings"]:
        assert f["id"] == finding_id(hid, f["check_id"], f["category"])
        assert f["host"]["host_id"] == hid


@pytest.mark.skipif(not POSIX or shutil.which("python3") is None, reason="needs a POSIX python3")
def test_example_plugin_runs_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plugins = tmp_path / "plugins"
    shutil.copytree(EXAMPLES / "plugins", plugins)
    plugins.chmod(0o755)
    for p in plugins.iterdir():
        p.chmod(0o644)
    spec = load_manifest(plugins / "sudoers-nopasswd.module.json")
    assert spec.id == "linux.sudoers-nopasswd" and spec.plugin_dir == str(plugins.resolve())
    root = linux_fixture_root(tmp_path / "root")
    monkeypatch.setenv("BO_TEST_MODE", "1")
    monkeypatch.setenv("BO_ROOT", str(root))
    out = tmp_path / "out"
    rc = main(
        [
            "run",
            "--platform",
            "linux",
            "--plugin-dir",
            str(plugins),
            "--modules",
            "linux.sudoers-nopasswd",
            "--output-dir",
            str(out),
            "--quiet",
        ]
    )
    assert rc == 4
    (d,) = out.glob("blueops-assessment-*")
    doc = json.loads((d / "assessment.json").read_text("utf-8"))
    (f,) = doc["findings"]
    assert f["check_id"] == "USR-NOPASS-001" and f["severity"] == "high"
    assert any("bob ALL=(ALL) NOPASSWD: ALL" in x for e in doc["evidence"] for x in e["excerpts"])
    assert verify_directory(d) == []


def test_plugin_example_manifest_validates() -> None:
    doc = json.loads((EXAMPLES / "plugins" / "sudoers-nopasswd.module.json").read_text("utf-8"))
    assert validate(doc, "module-manifest.schema.json") == []


def test_all_shipped_profiles_validate() -> None:
    for p in sorted((ROOT / "profiles").glob("*/*.json")):
        assert validate(json.loads(p.read_text("utf-8")), "assessment-profile.schema.json") == [], p


def test_example_plugin_reports_an_unreadable_directory_instead_of_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: an unprivileged run cannot list /etc/sudoers.d; that is a gap (exit 6)."""
    # Importing the plugin must not leave bytecode in examples/ (it was once committed that way).
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    spec = importlib.util.spec_from_file_location(
        "sudoers_nopasswd", EXAMPLES / "plugins" / "sudoers_nopasswd.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(sys, "dont_write_bytecode", True)  # never leave __pycache__ in examples/
    root = tmp_path / "root"
    (root / "etc" / "sudoers.d").mkdir(parents=True)
    (root / "etc" / "sudoers").write_text("root ALL=(ALL) ALL\n", encoding="utf-8")
    monkeypatch.setenv("BO_TEST_MODE", "1")
    monkeypatch.setenv("BO_ROOT", str(root))

    def denied(self: Path) -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "iterdir", denied)
    out = tmp_path / "out"
    assert mod.main(["x", str(out)]) == 6
    report = json.loads((out / "report.json").read_text("utf-8"))
    assert report["errors"][0]["code"] == "UNREADABLE" and report["findings"] == []
