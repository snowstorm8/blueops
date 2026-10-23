"""Guard the documented repository layout."""

from __future__ import annotations

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
