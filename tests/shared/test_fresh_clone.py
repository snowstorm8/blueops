"""The documented deployment (apt install git, git clone, cd blueops) works from tracked files only.

Every test runs against a copy of exactly the files Git tracks, placed in a temporary directory and
invoked from an unrelated working directory, so nothing depends on the development checkout, local
paths, untracked files or the caller's cwd. No test installs anything: package managers are shims.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash")
FIXTURES = Path("tests") / "fixtures"

pytestmark = pytest.mark.skipif(
    BASH is None or sys.platform.startswith("win") or not (ROOT / ".git").exists(),
    reason="requires bash on a POSIX host and a Git checkout",
)

# Everything the launcher, setup and collectors need, plus dirname/env used by the shims.
REQUIRED_CMDS = (
    ("awk", "cat", "cut", "date", "find", "grep", "head", "id", "mktemp", "sed", "sort"),
    ("stat", "tail", "tr", "uname", "wc", "dirname", "env"),
)
REQUIRED_CMDS = REQUIRED_CMDS[0] + REQUIRED_CMDS[1]


def _git(*args: str) -> str:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def _tracked() -> list[str]:
    return [p for p in _git("ls-files", "-z").split("\0") if p]


@pytest.fixture(scope="module")
def tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A copy of only the Git-tracked files (what `git clone` would deliver)."""
    dest = tmp_path_factory.mktemp("clone") / "blueops"
    for rel in _tracked():
        src = ROOT / rel
        if not src.is_file():
            continue  # tracked but deleted in the working tree: absent from the copy too
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target, follow_symlinks=False)
    return dest


@pytest.fixture()
def elsewhere(tmp_path: Path) -> Path:
    d = tmp_path / "unrelated-cwd"
    d.mkdir()
    return d


def _env(**extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BO_", "PYTHON"))}
    env.update(extra)
    return env


def _run(cmd: list[str], cwd: Path, env: dict[str, str], stdin=subprocess.DEVNULL):
    return subprocess.run(  # noqa: S603
        cmd, cwd=cwd, env=env, capture_output=True, text=True, stdin=stdin, check=False
    )


def _restricted_path(
    base: Path, omit: tuple[str, ...] = (), extra: dict[str, str] | None = None
) -> str:
    """A PATH with only the required commands (symlinks) plus shims; never Python."""
    d = base / "restricted-bin"
    d.mkdir()
    for name in REQUIRED_CMDS:
        if name in omit:
            continue
        real = shutil.which(name)
        assert real, f"test host lacks {name}"
        (d / name).symlink_to(real)
    for name, body in (extra or {}).items():
        shim = d / name
        if shim.is_symlink() or shim.exists():
            shim.unlink()
        shim.write_text(f"#!{BASH}\n{body}\n", encoding="utf-8")
        shim.chmod(0o755)
    return str(d)


# --- the repository itself ------------------------------------------------------------------


def test_required_files_listed_by_doctor_are_tracked() -> None:
    text = (ROOT / "linux/lib/deps.sh").read_text("utf-8")
    block = re.search(r'BO_DEPS_REQUIRED_FILES="(.*?)"', text, re.S)
    assert block
    listed = [line.strip() for line in block.group(1).splitlines() if line.strip()]
    tracked = set(_tracked())
    assert listed
    assert [p for p in listed if p not in tracked] == []


def test_no_runtime_file_is_hidden_by_gitignore() -> None:
    """A file that exists locally but is ignored would be missing from a fresh clone."""
    out = _git(
        "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--",
        "blueops", "linux", "windows", "shared", "scripts", "profiles", "examples",
    )  # fmt: skip
    hidden = [p for p in out.split("\0") if p and "__pycache__" not in p and not p.endswith(".pyc")]
    assert hidden == []


def test_entry_points_are_tracked_executable() -> None:
    modes = {}
    for line in _git("ls-files", "-s", "--", "blueops", "linux", "scripts/setup").splitlines():
        meta, path = line.split("\t", 1)
        modes[path] = meta.split()[0]
    scripts = [p for p in modes if p == "blueops" or (p.endswith(".sh") and "/lib/" not in p)]
    assert "blueops" in scripts and "scripts/setup/setup-linux.sh" in scripts
    assert [p for p in scripts if modes[p] != "100755"] == []


def test_no_development_machine_paths_in_runtime_files() -> None:
    bad = []
    for rel in _tracked():
        if not rel.startswith(("blueops", "linux/", "windows/", "scripts/", "shared/")):
            continue
        text = (ROOT / rel).read_text("utf-8", errors="ignore") if (ROOT / rel).is_file() else ""
        if "/Users/" in text or "Main Files" in text:
            bad.append(rel)
    assert bad == []


def test_readme_quick_start_leads_with_the_exact_deployment_commands() -> None:
    text = (ROOT / "README.md").read_text("utf-8")
    section = text.split("## Quick start", 1)
    assert len(section) == 2, "README needs a '## Quick start' section"
    first_block = re.search(r"```(?:bash)?\n(.*?)```", section[1], re.S)
    assert first_block
    lines = [ln for ln in first_block.group(1).splitlines() if ln.strip()]
    assert lines[:3] == [
        "sudo apt install git",
        "git clone https://github.com/snowstorm8/blueops.git",
        "cd blueops",
    ]
    # Nothing but commands may precede the block inside the section.
    assert section[1].lstrip().startswith("```")


# --- behaviour from a fresh copy of the tracked files ---------------------------------------


def test_doctor_runs_from_any_directory(tree: Path, elsewhere: Path) -> None:
    r = _run([BASH, str(tree / "blueops"), "doctor"], elsewhere, _env())
    assert r.returncode == 0, r.stdout + r.stderr
    assert "all required repository files are present" in r.stdout
    assert not (tree / "shared" / "reporting" / "__pycache__").exists()


def test_launcher_follows_a_symlink(tree: Path, elsewhere: Path) -> None:
    link = elsewhere / "blueops"
    link.symlink_to(tree / "blueops")
    r = _run([BASH, str(link), "doctor"], elsewhere, _env())
    assert r.returncode == 0, r.stdout + r.stderr
    assert str(tree) in r.stdout


def test_audit_through_launcher_is_cwd_independent(tree: Path, elsewhere: Path) -> None:
    env = _env(
        BO_ROOT=str(tree / FIXTURES / "linux-root-min"),
        PATH=f"{tree / FIXTURES / 'linux-bin'}{os.pathsep}{os.environ['PATH']}",
    )
    r = _run(
        [BASH, str(tree / "blueops"), "audit", "--modules", "system", "--json", "--no-color"],
        elsewhere,
        env,
    )
    assert r.returncode in (0, 4, 6), r.stdout + r.stderr
    assert json.loads(r.stdout)["tool"]["name"] == "audit-linux"


@pytest.mark.parametrize("cmd", ["diff", "detect"])
def test_python_commands_work_without_pythonpath_or_cwd(
    tree: Path, elsewhere: Path, cmd: str
) -> None:
    base = tree / FIXTURES / "baseline-e2e" / "linux"
    r = _run(
        [
            BASH,
            str(tree / "blueops"),
            cmd,
            str(base / "baseline.json"),
            str(base / "changed.json"),
            "--quiet",
        ],
        elsewhere,
        _env(),
    )
    assert r.returncode == 4, r.stdout + r.stderr
    assert not list(tree.rglob("__pycache__"))


def test_missing_required_command_is_actionable(
    tree: Path, elsewhere: Path, tmp_path: Path
) -> None:
    env = _env(PATH=_restricted_path(tmp_path, omit=("awk",)))
    doctor = _run([BASH, str(tree / "blueops"), "doctor"], elsewhere, env)
    assert doctor.returncode == 3
    assert "[MISSING] required command: awk" in doctor.stdout
    assert "setup-linux.sh" in doctor.stdout

    audit = _run([BASH, str(tree / "blueops"), "audit", "--json"], elsewhere, env)
    assert audit.returncode == 3
    assert "awk" in audit.stderr and "cannot continue" in audit.stderr

    # Calling the collector directly gets the same early, readable refusal.
    direct = _run(
        [BASH, str(tree / "linux/audit/audit-linux.sh"), "--modules", "system", "--json"],
        elsewhere,
        {**env, "BO_ROOT": str(tree / FIXTURES / "linux-root-min")},
    )
    assert direct.returncode == 3
    assert "required command(s) not found: awk" in direct.stderr
    assert "setup-linux.sh" in direct.stderr


def test_python_commands_explain_a_missing_python(
    tree: Path, elsewhere: Path, tmp_path: Path
) -> None:
    env = _env(PATH=_restricted_path(tmp_path))
    r = _run([BASH, str(tree / "blueops"), "detect", "a", "b"], elsewhere, env)
    assert r.returncode == 3
    assert "Python >= 3.9" in r.stderr and "collectors do not need Python" in r.stderr


def test_incomplete_checkout_is_reported(tree: Path, elsewhere: Path, tmp_path: Path) -> None:
    broken = tmp_path / "broken"
    shutil.copytree(tree, broken, symlinks=True)
    (broken / "linux/audit/audit-pam.sh").unlink()
    (broken / "shared/reporting/detect.py").unlink()
    r = _run([BASH, str(broken / "blueops"), "audit"], elsewhere, _env())
    assert r.returncode == 3
    assert "linux/audit/audit-pam.sh" in r.stderr and "Re-clone" in r.stderr


# --- setup is separate, explicit and never silent ---------------------------------------------


def _setup_env(
    tmp_path: Path, os_release: str, manager: str, uid: str = "0"
) -> tuple[dict[str, str], Path]:
    log = tmp_path / "pkg.log"
    osr = tmp_path / "os-release"
    osr.write_text(os_release, encoding="utf-8")
    shims = {
        "uname": 'if [ "${1:-}" = "-s" ]; then echo Linux; else /usr/bin/uname "$@"; fi',
        "id": f"echo {uid}",
        manager: f'echo "{manager} $*" >> "{log}"',
    }
    path = _restricted_path(tmp_path, omit=("awk", "uname", "id"), extra=shims)
    return _env(PATH=path, BO_DEPS_OS_RELEASE=str(osr)), log


DEBIAN = 'ID=debian\nVERSION_ID="13"\n'
ROCKY8 = 'ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="8.10"\n'


def _setup(tree: Path, cwd: Path, env: dict[str, str], *args: str):
    return _run([BASH, str(tree / "scripts/setup/setup-linux.sh"), *args], cwd, env)


def test_setup_default_reports_and_changes_nothing(
    tree: Path, elsewhere: Path, tmp_path: Path
) -> None:
    env, log = _setup_env(tmp_path, DEBIAN, "apt-get")
    r = _setup(tree, elsewhere, env)
    assert r.returncode == 3  # awk (required) is missing
    assert "Packages that would be installed" in r.stdout and "mawk" in r.stdout
    assert "Nothing was changed" in r.stdout
    assert not log.exists()


def test_setup_dry_run_prints_the_exact_commands(
    tree: Path, elsewhere: Path, tmp_path: Path
) -> None:
    env, log = _setup_env(tmp_path, DEBIAN, "apt-get")
    r = _setup(tree, elsewhere, env, "--install", "--dry-run")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "apt-get update" in r.stdout
    assert "apt-get install -y --no-install-recommends" in r.stdout and "mawk" in r.stdout
    assert "Dry run: nothing was executed" in r.stdout
    assert not log.exists()


def test_setup_without_terminal_or_yes_refuses(tree: Path, elsewhere: Path, tmp_path: Path) -> None:
    env, log = _setup_env(tmp_path, DEBIAN, "apt-get")
    r = _setup(tree, elsewhere, env, "--install")
    assert r.returncode == 5
    assert "--yes" in r.stderr
    assert not log.exists()


def test_setup_requires_root(tree: Path, elsewhere: Path, tmp_path: Path) -> None:
    env, log = _setup_env(tmp_path, DEBIAN, "apt-get", uid="1000")
    r = _setup(tree, elsewhere, env, "--install", "--yes")
    assert r.returncode == 3
    assert "needs root" in r.stderr
    assert not log.exists()


def test_setup_with_yes_runs_only_the_planned_commands(
    tree: Path, elsewhere: Path, tmp_path: Path
) -> None:
    env, log = _setup_env(tmp_path, DEBIAN, "apt-get")
    r = _setup(tree, elsewhere, env, "--install", "--yes")
    calls = log.read_text("utf-8").splitlines()
    assert calls[0] == "apt-get update"
    assert calls[1].startswith("apt-get install -y --no-install-recommends ")
    assert "mawk" in calls[1] and "iproute2" in calls[1] and "systemd" not in calls[1]
    assert len(calls) == 2
    # The shim installs nothing, so the re-check still sees awk missing: reported, not hidden.
    assert r.returncode == 6, r.stdout + r.stderr


def test_setup_rocky8_asks_for_a_modern_python(tree: Path, elsewhere: Path, tmp_path: Path) -> None:
    env, _ = _setup_env(tmp_path, ROCKY8, "dnf")
    r = _setup(tree, elsewhere, env, "--install", "--dry-run")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "dnf install -y" in r.stdout
    assert "python3.11" in r.stdout and "iproute" in r.stdout and "gawk" in r.stdout


def test_setup_minimal_skips_optional_packages(tree: Path, elsewhere: Path, tmp_path: Path) -> None:
    env, _ = _setup_env(tmp_path, DEBIAN, "apt-get")
    r = _setup(tree, elsewhere, env, "--install", "--dry-run", "--minimal")
    assert r.returncode == 0
    assert "mawk" in r.stdout
    assert "python3" not in r.stdout.split("Planned commands", 1)[1]
    assert "iproute2" not in r.stdout.split("Planned commands", 1)[1]
