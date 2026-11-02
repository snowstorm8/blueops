"""Repository hygiene: no generated files in git, and fixture names every OS can check out."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import engine_support
import pytest
from engine_support import (
    DECEPTIVE_NAME,
    DECEPTIVE_NAME_SUPPORTED,
    POSIX_BASH,
    collector_env,
    linux_fixture_root,
)

ROOT = Path(__file__).resolve().parents[2]
GIT = shutil.which("git")
_IN_GIT = GIT is not None and (ROOT / ".git").exists()

# Characters and names Windows cannot create (also rejected by NTFS tools, git checkout, archives).
_WIN_BAD_CHARS = re.compile(r'[<>:"|?*\x00-\x1f]')
_WIN_RESERVED = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$", re.IGNORECASE)


def git(*args: str) -> subprocess.CompletedProcess[str]:
    assert GIT
    return subprocess.run(  # noqa: S603 - fixed git argv, no shell
        [GIT, "-C", str(ROOT), *args], capture_output=True, text=True, check=False
    )


@pytest.mark.skipif(not _IN_GIT, reason="needs a git checkout")
def test_no_bytecode_or_cache_directories_are_tracked() -> None:
    tracked = git("ls-files").stdout.splitlines()
    bad = [
        t
        for t in tracked
        if "__pycache__/" in t
        or re.search(r"\.py[cod]$", t)
        or t.endswith((".egg-info", ".pytest_cache"))
    ]
    assert bad == [], f"generated files are tracked: {bad}"


@pytest.mark.skipif(not _IN_GIT, reason="needs a git checkout")
@pytest.mark.parametrize(
    "path",
    [
        "examples/plugins/__pycache__/sudoers_nopasswd.cpython-313.pyc",
        "examples/plugins/__pycache__/x.cpython-39.pyc",
        "examples/deep/dir/mod.pyc",
        "tests/fixtures/rules/__pycache__/y.cpython-312.pyc",
        "tests/fixtures/linux-root/opt/z.pyo",
        "tests/shared/__pycache__/engine_support.cpython-313.pyc",
        "shared/rules/__pycache__/engine.cpython-313.pyc",
    ],
)
def test_gitignore_still_ignores_bytecode_where_it_re_includes_examples_and_fixtures(
    path: str,
) -> None:
    """Regression: ``!examples/**`` and ``!tests/fixtures/**`` once re-included ``__pycache__``."""
    r = git("check-ignore", "-q", "--no-index", path)
    assert r.returncode == 0, (
        f"{path} is not ignored; keep the bytecode patterns after the negations in .gitignore"
    )


@pytest.mark.skipif(not _IN_GIT, reason="needs a git checkout")
def test_examples_and_fixtures_that_are_meant_to_be_committed_are_not_ignored() -> None:
    for path in (
        "examples/plugins/sudoers_nopasswd.py",
        "examples/assessment.example.json",
        "tests/fixtures/rules/linux-compromised.assessment.json",
    ):
        assert git("check-ignore", "-q", "--no-index", path).returncode == 1, (
            f"{path} must stay tracked"
        )


def test_fixture_names_can_be_checked_out_on_windows() -> None:
    """Everything stored under tests/fixtures must have a name Windows accepts. Names that Windows
    cannot represent (such as ``...``) have to be generated per test, on POSIX only."""
    problems = []
    for p in (ROOT / "tests" / "fixtures").rglob("*"):
        name = p.name
        if (
            _WIN_BAD_CHARS.search(name)
            or _WIN_RESERVED.match(name)
            or name.endswith((" ", "."))
            or len(name) > 255
        ):
            problems.append(str(p.relative_to(ROOT)))
    assert problems == [], f"not representable on Windows: {problems}"


def test_the_fixture_tree_builds_on_every_platform(tmp_path: Path) -> None:
    root = linux_fixture_root(tmp_path / "root")
    assert (root / "etc" / "passwd").is_file()
    assert (root / "tmp" / DECEPTIVE_NAME).exists() == DECEPTIVE_NAME_SUPPORTED


def test_building_the_fixture_does_not_need_the_deceptive_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Simulate a platform that cannot create ``...``: the tree must still build, without it."""
    monkeypatch.setattr(engine_support, "DECEPTIVE_NAME_SUPPORTED", False)
    root = linux_fixture_root(tmp_path / "root")
    assert (root / "etc" / "passwd").is_file() and not (root / "tmp" / DECEPTIVE_NAME).exists()


@pytest.mark.skipif(
    not (POSIX_BASH and DECEPTIVE_NAME_SUPPORTED),
    reason="the Linux collector runs on POSIX with bash",
)
def test_the_generated_deceptive_name_is_what_the_filesystem_audit_flags(tmp_path: Path) -> None:
    """The reason the file exists: the audit must report it (FS-HIDDEN-001), so generating it per
    test instead of storing it in git keeps the Linux coverage."""
    root = linux_fixture_root(tmp_path / "root")
    proc = subprocess.run(  # noqa: S603
        [shutil.which("bash") or "bash", str(ROOT / "linux" / "audit" / "audit-linux.sh"), "--modules", "filesystem", "--json", "--no-color"],
        capture_output=True, text=True, env=collector_env(root), check=False, timeout=120,
    )  # fmt: skip
    findings = {f["id"]: f for f in json.loads(proc.stdout)["findings"]}
    assert "FS-HIDDEN-001" in findings
    assert any(e["ref"] == "/tmp/..." for e in findings["FS-HIDDEN-001"]["evidence"])
