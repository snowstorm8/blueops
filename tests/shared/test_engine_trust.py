"""Plugin trust checks (shared/engine/trust.py): what is refused, and why that matters.

Threat model: the operator (often root) runs the engine with ``--plugin-dir``. A plugin is code run
with the operator's privileges, so anyone who can change its manifest, the program or script it
runs, or swap the directory holding them, controls the operator's account. These tests establish
that each of those paths is closed for local users who are neither root nor the operator. They do
not show a trusted plugin is safe, and the check-to-exec gap is documented, not closed.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest
from engine_support import ROOT

from shared.engine.module import FAILED, ModuleSpec
from shared.engine.registry import PluginError, Registry
from shared.engine.runner import ExecResult, RunContext, run_module
from shared.engine.trust import owner_ok, path_problems, plugin_launch_problems

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and modes")


def plugin(tmp_path: Path, script_mode: int = 0o755) -> tuple[Path, Path]:
    d = tmp_path / "plugins"
    d.mkdir(mode=0o755)
    script = d / "probe.sh"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(script_mode)
    manifest = d / "probe.module.json"
    doc: dict[str, Any] = {
        "schema_version": "0.1.0",
        "kind": "module",
        "id": "any.probe",
        "title": "Probe",
        "platform": "any",
        "category": "audit",
        "command": ["{plugin_dir}/probe.sh", "{output_dir}"],
    }
    manifest.write_text(json.dumps(doc), encoding="utf-8")
    manifest.chmod(0o644)
    return d, script


def spec_of(d: Path) -> ModuleSpec:
    reg = Registry()
    (found,) = reg.discover(d)
    return found


class Recorder:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], *_: Any) -> ExecResult:
        self.calls.append(argv)
        return ExecResult(None, error="stopped by the test after the launch decision")


def run(spec: ModuleSpec, tmp_path: Path) -> tuple[Any, Recorder]:
    out = tmp_path / "run"
    out.mkdir(mode=0o700)
    rec = Recorder()
    ctx = RunContext(repo_root=ROOT, out_root=out, executor=rec, platform_name="linux")
    return run_module(spec, ctx), rec


# ---------------------------------------------------------------- the owner rule


def fake_stat(uid: int, mode: int = 0o100644) -> os.stat_result:
    return os.stat_result((mode, 1, 1, 1, uid, 0, 0, 0, 0, 0))


def test_only_root_or_the_current_user_may_own_trusted_files() -> None:
    assert owner_ok(fake_stat(0), euid=1000)
    assert owner_ok(fake_stat(1000), euid=1000)
    assert not owner_ok(fake_stat(1001), euid=1000)  # another local user can rewrite it


# ---------------------------------------------------------------- files and directories


def test_a_private_file_in_a_private_directory_is_trusted(tmp_path: Path) -> None:
    d, script = plugin(tmp_path)
    assert path_problems(script) == [] and path_problems(d, want="dir") == []


@pytest.mark.parametrize("mode", [0o775, 0o757, 0o777, 0o666])
def test_group_or_other_writable_files_are_refused(tmp_path: Path, mode: int) -> None:
    _, script = plugin(tmp_path, script_mode=mode)
    assert any("writable by group/other" in p for p in path_problems(script))


def test_symlinks_are_refused_even_to_a_trusted_target(tmp_path: Path) -> None:
    d, script = plugin(tmp_path)
    link = d / "link.sh"
    link.symlink_to(script)
    assert path_problems(link) == [f"{link}: is a symbolic link"]
    assert path_problems(tmp_path / "missing") != []


def test_a_writable_ancestor_lets_the_plugin_directory_be_swapped(tmp_path: Path) -> None:
    """A private plugin dir inside a directory others can write to can be renamed away and
    replaced; the ancestors must be checked, not only the plugin directory."""
    outer = tmp_path / "outer"
    outer.mkdir()
    d, script = plugin(outer)
    outer.chmod(0o777)
    try:
        assert any(str(outer) in p and "writable" in p for p in path_problems(script))
        with pytest.raises(PluginError, match="not trusted"):
            Registry().discover(d)
    finally:
        outer.chmod(0o755)


def test_a_sticky_world_writable_ancestor_like_tmp_is_accepted(tmp_path: Path) -> None:
    outer = tmp_path / "sticky"
    outer.mkdir()
    d, script = plugin(outer)
    outer.chmod(0o1777)
    try:
        assert [p for p in path_problems(script) if str(outer) in p] == []
    finally:
        outer.chmod(0o755)


# ---------------------------------------------------------------- discovery


def test_discovery_refuses_a_group_writable_manifest_or_directory(tmp_path: Path) -> None:
    d, _ = plugin(tmp_path)
    m = d / "probe.module.json"
    m.chmod(0o664)
    with pytest.raises(PluginError, match="manifest is not trusted"):
        Registry().discover(d)
    m.chmod(0o644)
    d.chmod(0o775)
    try:
        with pytest.raises(PluginError, match="directory is not trusted"):
            Registry().discover(d)
    finally:
        d.chmod(0o755)


# ---------------------------------------------------------------- the program being run


def test_the_manifest_alone_being_trusted_is_not_enough(tmp_path: Path) -> None:
    """The gap before: manifest and directory were checked, but not the script they launch, so a
    group-writable ``probe.sh`` in a 0755 directory ran with the operator's privileges."""
    d, _ = plugin(tmp_path, script_mode=0o666)
    spec = spec_of(d)  # discovery passes: the manifest and the directory are fine
    result, rec = run(spec, tmp_path)
    assert result.status == FAILED and "not trusted" in result.reason
    assert rec.calls == []  # never started


def test_a_trusted_plugin_still_starts(tmp_path: Path) -> None:
    d, script = plugin(tmp_path)
    result, rec = run(spec_of(d), tmp_path)
    assert rec.calls and rec.calls[0][0] == str(script)
    assert "not trusted" not in result.reason


def test_a_script_made_writable_after_discovery_is_caught_at_launch(tmp_path: Path) -> None:
    """Narrows the check-to-use gap: the files are checked again immediately before the exec."""
    d, script = plugin(tmp_path)
    spec = spec_of(d)
    script.chmod(0o777)
    result, rec = run(spec, tmp_path)
    assert result.status == FAILED and rec.calls == []


def test_a_script_replaced_by_a_symlink_after_discovery_is_caught(tmp_path: Path) -> None:
    d, script = plugin(tmp_path)
    spec = spec_of(d)
    script.unlink()
    script.symlink_to("/bin/sh")
    result, rec = run(spec, tmp_path)
    assert result.status == FAILED and "symbolic link" in result.reason and rec.calls == []


def test_interpreted_scripts_are_checked_too(tmp_path: Path) -> None:
    d, script = plugin(tmp_path, script_mode=0o666)
    problems = plugin_launch_problems(["/bin/sh", str(script)], str(d))
    assert any("writable" in p for p in problems)


def test_system_programs_outside_the_plugin_directory_are_not_second_guessed(
    tmp_path: Path,
) -> None:
    d, _ = plugin(tmp_path)
    assert plugin_launch_problems(["/bin/sh", "-c", "true"], str(d)) == []


def test_builtin_modules_are_not_subject_to_plugin_checks(tmp_path: Path) -> None:
    """Built-ins live in the repository; their trust is the deployment's (checksummed checkout)."""
    spec = ModuleSpec(
        id="any.builtin",
        title="b",
        platform="any",
        category="audit",
        argv=(str(tmp_path / "does-not-need-to-exist"),),
        source="builtin",
    )
    result, rec = run(spec, tmp_path)
    assert rec.calls and "not trusted" not in result.reason


def test_mode_bits_used_are_the_documented_ones() -> None:
    assert stat.S_IWGRP | stat.S_IWOTH == 0o022
