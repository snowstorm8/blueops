"""Guard the documented repository layout."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_FILES = [
    "CLAUDE.md",
    "README.md",
    "LICENSE",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    ".gitignore",
    ".editorconfig",
    ".gitattributes",
    ".github/workflows/ci.yml",
    ".github/workflows/lint.yml",
    ".github/dependabot.yml",
    ".github/pull_request_template.md",
    "docs/architecture.md",
    "docs/development.md",
    "docs/deployment.md",
    "docs/security-model.md",
    "docs/roadmap.md",
    "docs/contracts.md",
]

CATEGORIES = ["audit", "persistence", "incident", "hardening", "lib"]


@pytest.mark.parametrize("rel", REQUIRED_FILES)
def test_required_file_exists(rel: str) -> None:
    assert (ROOT / rel).is_file(), rel


@pytest.mark.parametrize("platform", ["linux", "windows"])
def test_platform_directories_exist(platform: str) -> None:
    for category in CATEGORIES:
        assert (ROOT / platform / category).is_dir()
    assert (ROOT / "profiles" / platform).is_dir()
    assert (ROOT / "tests" / platform).is_dir()


def test_tracked_paths_are_valid_on_windows() -> None:
    """Every contributor and CI runner must be able to check the repo out on Windows."""
    names = subprocess.run(  # noqa: S603
        ["git", "ls-files", "-z"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split("\0")
    bad_char = re.compile(r'[<>:"|?*\x00-\x1f]')
    reserved = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.IGNORECASE)
    for name in filter(None, names):
        for part in name.split("/"):
            assert not bad_char.search(part), name
            assert not part.endswith((".", " ")), name
            assert not reserved.match(part), name
