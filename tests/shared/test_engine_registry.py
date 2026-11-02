"""Module registry: built-ins stay in sync with the collectors; plugins and dependencies."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest
from engine_support import ROOT, spec

from shared.engine.builtin import builtin_modules, collector_module_name
from shared.engine.module import ModuleError
from shared.engine.profile import (
    PROFILES_DIR,
    ProfileError,
    find_profile,
    list_profiles,
    load_profile_file,
)
from shared.engine.registry import PluginError, Registry, load_manifest

POSIX = not sys.platform.startswith("win")


def _manifest(path: Path, **over: Any) -> Path:
    doc = {
        "schema_version": "0.1.0",
        "kind": "module",
        "id": "linux.example",
        "title": "Example",
        "platform": "linux",
        "category": "audit",
        "command": ["{plugin_dir}/run.sh", "{output_dir}"],
    }
    doc.update(over)
    path.write_text(json.dumps(doc), encoding="utf-8")
    if POSIX:
        path.chmod(0o644)
    return path


# ------------------------------------------------------------- built-ins vs the collectors


def _collector_modules(text: str, pattern: str) -> list[str]:
    m = re.search(pattern, text, re.S)
    assert m, pattern
    return re.findall(r"[a-z]+", m.group(1))


def test_linux_builtins_match_the_bash_collector() -> None:
    text = (ROOT / "linux" / "lib" / "common.sh").read_text("utf-8")
    declared = _collector_modules(text, r'BO_ALL_MODULES="([^"]+)"')
    ours = [collector_module_name(m.id) for m in builtin_modules() if m.platform == "linux"]
    assert sorted(ours) == sorted(declared)


def test_windows_builtins_match_the_powershell_collector() -> None:
    text = (ROOT / "windows" / "lib" / "Common.ps1").read_text("utf-8")
    declared = _collector_modules(text, r"BoAllModules = @\(([^)]*)\)")
    ours = [collector_module_name(m.id) for m in builtin_modules() if m.platform == "windows"]
    assert sorted(ours) == sorted(declared)


def test_builtin_partitions_match_the_linux_collector() -> None:
    text = (ROOT / "linux" / "lib" / "common.sh").read_text("utf-8")
    block = re.search(r"bo_module_partitions\(\) \{(.*?)\n\}", text, re.S)
    assert block
    for name, parts in re.findall(r'^\s+(\w+)\) echo "([^"]*)" ;;', block.group(1), re.M):
        mod = next((m for m in builtin_modules() if m.id == f"linux.{name}"), None)
        assert mod is not None, name
        assert sorted(mod.provides) == sorted(parts.split()), name


def test_builtin_partitions_match_the_windows_collector() -> None:
    text = (ROOT / "windows" / "lib" / "Common.ps1").read_text("utf-8")
    block = re.search(r"BoModulePartitions = @\{(.*?)\n\}", text, re.S)
    assert block
    for name, parts in re.findall(r"^\s+(\w+)\s*=\s*@\(([^)]*)\)", block.group(1), re.M):
        mod = next(m for m in builtin_modules() if m.id == f"windows.{name}")
        assert sorted(mod.provides) == sorted(re.findall(r"'([^']+)'", parts)), name


def test_every_builtin_is_valid_and_registers() -> None:
    reg = Registry.with_builtins()
    assert reg.check_dependencies() == []
    assert len(reg.all("linux")) >= 8 and len(reg.all("windows")) >= 11


def test_platform_filtering() -> None:
    reg = Registry.with_builtins()
    assert all(m.platform in ("linux", "any") for m in reg.all("linux"))
    assert all(m.platform in ("windows", "any") for m in reg.all("windows"))


# ------------------------------------------------------------------------ validation


@pytest.mark.parametrize(
    "bad",
    [
        {"mid": "Linux.users"},
        {"mid": "users"},
        {"mid": "windows.users", "platform": "linux"},
        {"mid": "linux.users", "timeout": 0},
        {"mid": "linux.users", "timeout": 10**7},
        {"mid": "linux.users", "requires": ("linux.users",)},
        {"mid": "linux.users", "requires": ("BAD",)},
        {"mid": "linux.users", "argv": ()},
        {"mid": "linux.users", "argv": ("",)},
    ],
)
def test_invalid_module_definitions_are_rejected(bad: dict[str, Any]) -> None:
    kw = dict(bad)
    mid = kw.pop("mid")
    platform = kw.pop("platform", None)
    s = spec(mid, **{("timeout" if k == "timeout" else k): v for k, v in kw.items()})
    if platform:
        s = type(s)(**{**s.__dict__, "platform": platform})
    with pytest.raises(ModuleError):
        s.validate()


def test_duplicate_ids_are_rejected() -> None:
    reg = Registry()
    reg.register(spec("linux.a"))
    with pytest.raises(ModuleError, match="duplicate"):
        reg.register(spec("linux.a"))


# ---------------------------------------------------------------------- dependency plan


def _reg(deps: dict[str, tuple[str, ...]]) -> Registry:
    reg = Registry()
    for mid, req in deps.items():
        reg.register(spec(mid, requires=req))
    return reg


def test_plan_adds_dependencies_first_and_once() -> None:
    reg = _reg({"linux.a": (), "linux.b": ("linux.a",), "linux.c": ("linux.b", "linux.a")})
    assert [m.id for m in reg.plan(["linux.c"])] == ["linux.a", "linux.b", "linux.c"]
    assert [m.id for m in reg.plan(["linux.c", "linux.a", "linux.b"])] == [
        "linux.a",
        "linux.b",
        "linux.c",
    ]


def test_plan_keeps_requested_order_for_independent_modules() -> None:
    reg = _reg({"linux.a": (), "linux.b": (), "linux.c": ()})
    assert [m.id for m in reg.plan(["linux.c", "linux.a"])] == ["linux.c", "linux.a"]


def test_cycles_are_reported_with_their_path() -> None:
    reg = _reg({"linux.a": ("linux.b",), "linux.b": ("linux.c",), "linux.c": ("linux.a",)})
    with pytest.raises(ModuleError, match=r"linux\.a -> linux\.b -> linux\.c -> linux\.a"):
        reg.plan(["linux.a"])
    assert any("cycle" in p for p in reg.check_dependencies())


def test_unknown_module_and_unknown_dependency() -> None:
    reg = _reg({"linux.a": ("linux.ghost",)})
    with pytest.raises(ModuleError, match="unknown module 'linux.nope'"):
        reg.plan(["linux.nope"])
    with pytest.raises(ModuleError, match="requires unknown module"):
        reg.plan(["linux.a"])
    assert reg.check_dependencies() == ["linux.a requires unknown module linux.ghost"] or any(
        "ghost" in p for p in reg.check_dependencies()
    )


# -------------------------------------------------------------------------------- plugins


def test_plugin_manifest_loads(tmp_path: Path) -> None:
    spec_ = load_manifest(
        _manifest(tmp_path / "x.module.json", requires=["linux.users"], timeout_seconds=5)
    )
    assert (spec_.id, spec_.timeout_seconds, spec_.requires) == (
        "linux.example",
        5,
        ("linux.users",),
    )
    assert spec_.plugin_dir == str(tmp_path.resolve()) and spec_.source.endswith("x.module.json")


def test_discover_registers_plugins_beside_builtins(tmp_path: Path) -> None:
    _manifest(tmp_path / "a.module.json")
    (tmp_path / "ignored.txt").write_text("x")
    reg = Registry.with_builtins()
    found = reg.discover(tmp_path)
    assert [m.id for m in found] == ["linux.example"] and "linux.example" in reg


def test_plugin_cannot_shadow_a_builtin(tmp_path: Path) -> None:
    _manifest(tmp_path / "a.module.json", id="linux.users")
    with pytest.raises(ModuleError, match="duplicate"):
        Registry.with_builtins().discover(tmp_path)


@pytest.mark.parametrize(
    "over",
    [
        {"kind": "profile"},
        {"id": "Bad Id"},
        {"command": []},
        {"command": [""]},
        {"timeout_seconds": 0},
        {"platform": "macos"},
        {"unexpected": True},
        {"provides": ["nodomain"]},
    ],
)
def test_malformed_manifests_are_rejected(tmp_path: Path, over: dict[str, Any]) -> None:
    with pytest.raises(PluginError):
        load_manifest(_manifest(tmp_path / "x.module.json", **over))


def test_manifest_that_is_not_json_or_has_duplicate_keys(tmp_path: Path) -> None:
    p = tmp_path / "x.module.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(PluginError, match="not valid JSON"):
        load_manifest(p)
    p.write_text('{"id": "a", "id": "b"}', encoding="utf-8")
    with pytest.raises(PluginError, match="duplicate"):
        load_manifest(p)


def test_missing_plugin_directory(tmp_path: Path) -> None:
    with pytest.raises(PluginError, match="not found"):
        Registry().discover(tmp_path / "nope")


@pytest.mark.skipif(not POSIX, reason="POSIX permissions")
def test_group_or_world_writable_plugins_are_refused(tmp_path: Path) -> None:
    p = _manifest(tmp_path / "x.module.json")
    p.chmod(0o666)
    with pytest.raises(PluginError, match="writable"):
        load_manifest(p)
    p.chmod(0o644)
    tmp_path.chmod(0o777)
    try:
        with pytest.raises(PluginError, match="writable"):
            Registry().discover(tmp_path)
    finally:
        tmp_path.chmod(0o755)


@pytest.mark.skipif(not POSIX, reason="symlinks need POSIX")
def test_symlinked_manifest_is_refused(tmp_path: Path) -> None:
    real = _manifest(tmp_path / "real.json")
    link = tmp_path / "x.module.json"
    link.symlink_to(real)
    with pytest.raises(PluginError, match="symbolic link"):
        load_manifest(link)


# ------------------------------------------------------------------------------- profiles


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_shipped_profiles_load_and_resolve(platform: str) -> None:
    reg = Registry.with_builtins()
    names = list_profiles(platform)
    assert {"default", "quick", "persistence-hunt"} <= set(names)
    for name in names:
        profile = find_profile(name, platform)
        ids = profile.resolve(reg)
        assert ids and all(i.startswith(platform + ".") for i in ids), name


def test_default_profile_expands_to_every_module() -> None:
    reg = Registry.with_builtins()
    assert find_profile("default", "linux").resolve(reg) == reg.default_selection("linux")


def test_unknown_profile_lists_the_available_ones() -> None:
    with pytest.raises(ProfileError, match="available: .*default"):
        find_profile("nope", "linux")


def test_profile_for_the_wrong_platform_or_with_unknown_modules(tmp_path: Path) -> None:
    with pytest.raises(ProfileError, match="not windows"):
        find_profile(str(PROFILES_DIR / "linux" / "default.json"), "windows")
    p = tmp_path / "p.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "0.1.0",
                "kind": "profile",
                "name": "x",
                "platform": "linux",
                "modules": ["linux.ghost"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProfileError, match="unknown module"):
        load_profile_file(p).resolve(Registry.with_builtins())
    p.write_text(
        json.dumps(
            {
                "schema_version": "0.1.0",
                "kind": "profile",
                "name": "x",
                "platform": "linux",
                "modules": ["windows.users"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProfileError, match="not a linux"):
        load_profile_file(p).resolve(Registry.with_builtins())


@pytest.mark.parametrize(
    "over", [{"fail_on": "urgent"}, {"modules": []}, {"options": {"x": 1}}, {"name": "Bad Name"}]
)
def test_invalid_profiles_are_rejected(tmp_path: Path, over: dict[str, Any]) -> None:
    doc = {
        "schema_version": "0.1.0",
        "kind": "profile",
        "name": "x",
        "platform": "linux",
        "modules": ["all"],
        **over,
    }
    p = tmp_path / "p.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ProfileError, match="invalid profile"):
        load_profile_file(p)
