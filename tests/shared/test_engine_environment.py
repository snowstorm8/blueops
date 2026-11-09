"""The environment modules start with, and what it protects.

Threat model (shared/engine/environment.py): the engine is started, often as root, from an
environment an attacker on a compromised host may have influenced (a planted ``BASH_ENV`` in a
profile, a ``sudo`` ``env_keep`` rule, an automation runner). Several of those variables take
effect before the first line of the collector, so only the launcher can stop them.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from engine_support import POSIX_BASH, ROOT

from shared.engine.environment import (
    HOOK_NAMES,
    SYSTEM_DIRS,
    safe_path,
    sanitized_environment,
    trusted_which,
)
from shared.engine.runner import RunContext, default_executor

POSIX = os.name == "posix"

POISONED = {
    "BASH_ENV": "/tmp/evil.sh",  # noqa: S108 - a name in a synthetic environment, never opened
    "ENV": "/tmp/evil.sh",  # noqa: S108
    "LD_PRELOAD": "/tmp/evil.so",  # noqa: S108
    "LD_LIBRARY_PATH": "/tmp",  # noqa: S108
    "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",  # noqa: S108
    "PYTHONPATH": "/tmp",  # noqa: S108
    "PYTHONSTARTUP": "/tmp/evil.py",  # noqa: S108
    "SHELLOPTS": "xtrace",
    "BASH_FUNC_ls%%": "() { :; }",
    "AWS_SECRET_ACCESS_KEY": "synthetic-not-a-key",  # noqa: S105
    "GITHUB_TOKEN": "synthetic-not-a-token",  # noqa: S105
    "PATH": ".:/tmp/evil:/usr/bin:",  # noqa: S108
    "LANG": "en_US.UTF-8",
    "LC_ALL": "C",
    "HOME": "/root",
    "TERM": "xterm",
}


@pytest.mark.skipif(not POSIX, reason="POSIX policy")
def test_hooks_and_secrets_are_not_passed_and_hooks_are_reported() -> None:
    env, withheld = sanitized_environment(POISONED, posix=True)
    for name in POISONED:
        if name not in ("PATH", "LANG", "LC_ALL", "HOME", "TERM"):
            assert name not in env, name
    assert env["LANG"] == "en_US.UTF-8" and env["LC_ALL"] == "C" and env["HOME"] == "/root"
    # hooks are named so the operator learns about them; plain secrets are dropped silently
    assert {"BASH_ENV", "ENV", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "PYTHONPATH"} <= set(withheld)
    assert "AWS_SECRET_ACCESS_KEY" not in withheld and "GITHUB_TOKEN" not in withheld
    assert "BASH_ENV" in HOOK_NAMES


@pytest.mark.skipif(not POSIX, reason="POSIX policy")
def test_path_is_rebuilt_from_trusted_directories_only() -> None:
    env, _ = sanitized_environment(POISONED, posix=True)
    parts = env["PATH"].split(os.pathsep)
    assert "" not in parts and "." not in parts and "/tmp/evil" not in parts  # noqa: S108
    assert all(os.path.isabs(p) for p in parts)
    system = [d for d in SYSTEM_DIRS if os.path.isdir(d)]
    assert parts[: len(system)] == system  # system directories come first, in order


@pytest.mark.skipif(not POSIX or os.geteuid() == 0, reason="needs a non-root owner")
def test_a_directory_the_current_user_owns_is_not_trusted_on_path(tmp_path: Path) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(mode=0o755)
    path, dropped = safe_path(os.pathsep.join([str(bin_dir), "/usr/bin"]))
    assert str(bin_dir) not in path.split(os.pathsep) and str(bin_dir) in dropped


@pytest.mark.skipif(not POSIX, reason="POSIX policy")
def test_test_mode_keeps_the_callers_path_for_command_shims() -> None:
    env, _ = sanitized_environment(
        {"BO_TEST_MODE": "1", "BO_ROOT": "/x", "PATH": "/some/shims:/usr/bin"}, posix=True
    )
    assert env["PATH"] == "/some/shims:/usr/bin" and env["BO_ROOT"] == "/x"


@pytest.mark.skipif(not POSIX, reason="POSIX policy")
def test_a_planted_tool_earlier_on_path_is_not_the_one_found(tmp_path: Path) -> None:
    fake = tmp_path / "sh"
    fake.write_text("#!/bin/sh\necho planted\n", encoding="utf-8")
    fake.chmod(0o755)
    found = trusted_which("sh", {"PATH": f"{tmp_path}{os.pathsep}/usr/bin{os.pathsep}/bin"})
    assert found is not None and Path(found) != fake


def test_windows_policy_drops_only_known_injection_variables() -> None:
    env, withheld = sanitized_environment(
        {
            "COR_PROFILER": "{x}",
            "DOTNET_STARTUP_HOOKS": "x.dll",
            "SystemRoot": "C:\\Windows",
            "PATH": "C:\\x",
        },
        posix=False,
    )
    assert env == {"SystemRoot": "C:\\Windows", "PATH": "C:\\x"}
    assert withheld == ["COR_PROFILER", "DOTNET_STARTUP_HOOKS"]


def test_windows_denylist_holds_no_invented_names() -> None:
    """Only variables known to exist are listed; a name nobody confirmed must not look protected."""
    env, withheld = sanitized_environment(
        {"PSMODULEPATH_OVERRIDE": "x", "Path": "C:\\x"}, posix=False
    )
    assert "PSMODULEPATH_OVERRIDE" in env and withheld == []


@pytest.mark.skipif(not (POSIX and POSIX_BASH), reason="needs POSIX bash")
def test_bash_env_does_not_run_in_a_module_but_would_in_an_unsanitised_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: the same child, started with the engine's default environment and with a raw
    copy of the caller's. Only the second runs the planted file, which is what this guards."""
    marker = tmp_path / "marker"
    evil = tmp_path / "evil.sh"
    evil.write_text(f"echo ran > '{marker}'\n", encoding="utf-8")
    script = tmp_path / "collector.sh"
    script.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    monkeypatch.setenv("BASH_ENV", str(evil))
    monkeypatch.delenv("BO_TEST_MODE", raising=False)
    argv = [str(Path(os.environ.get("BASH", "/bin/bash"))), str(script)]
    out, err = tmp_path / "out", tmp_path / "err"

    ctx = RunContext(repo_root=ROOT, out_root=tmp_path)  # default: sanitised
    assert "BASH_ENV" not in ctx.env
    assert default_executor(argv, 30, ctx.env, out, err).returncode == 0
    assert not marker.exists()

    raw = dict(os.environ)  # what the engine used to pass
    assert default_executor(argv, 30, raw, out, err).returncode == 0
    assert marker.exists(), (
        "the control run must show the hook is real, or this test proves nothing"
    )


@pytest.mark.skipif(not POSIX, reason="POSIX modes")
def test_sanitised_default_is_what_run_context_uses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")  # noqa: S108
    monkeypatch.setenv("SOME_SECRET", "x")
    ctx = RunContext(repo_root=ROOT, out_root=ROOT)
    assert "LD_PRELOAD" not in ctx.env and "SOME_SECRET" not in ctx.env
    assert stat.S_ISDIR(os.stat("/usr/bin").st_mode)  # sanity: the system dirs exist here
