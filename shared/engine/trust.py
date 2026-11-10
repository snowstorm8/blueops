"""Trust checks for plugin files (POSIX).

Threat model: the operator runs the engine, often as root, on a host that may have local
attackers or compromised service accounts, and points it at a plugin directory. A plugin is a
program the engine will run with the operator's privileges, so whoever can change the manifest,
the program, the script it interprets, or swap the directory that holds them, controls the
operator's account. These checks only *shrink* that to people who already are root or the
operator; they do not make a plugin safe to run, and they say nothing about what a trusted plugin
does.

A path is trusted when, for it and for every ancestor directory up to ``/``:

* it is not a symbolic link (checked for the plugin directory, manifest and command files; the
  ancestors are checked after resolving the path, so a link in the middle is followed once, at
  check time);
* its owner is root or the user running the engine (an owner can always rewrite it, so anything
  else could be rewritten by someone who is not the operator);
* it is not group/other-writable, except that an ancestor directory that is world-writable *and*
  sticky (``/tmp``) is accepted, because the sticky bit stops other users from renaming or
  deleting entries they do not own.

Not covered, by design of what can be done without root-owned installs: the gap between a check
and the exec that follows it (the checks are made as late as possible, immediately before the
module starts, and again on discovery), ACLs, extended attributes, immutable flags, and Windows
(NTFS ACLs are not inspected; protect plugin directories yourself).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

_WRITABLE = stat.S_IWGRP | stat.S_IWOTH


def owner_ok(st: os.stat_result, euid: int | None = None) -> bool:
    me = os.geteuid() if euid is None else euid  # POSIX only: callers return early elsewhere
    return st.st_uid in (0, me)


def _entry_problem(path: Path, st: os.stat_result, *, ancestor: bool) -> str | None:
    if not owner_ok(st):
        return f"{path}: owned by uid {st.st_uid}, which is neither root nor the current user"
    if st.st_mode & _WRITABLE:
        if ancestor and stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX:
            return None
        return f"{path}: writable by group/other"
    return None


def path_problems(  # noqa: PLR0911 - one early return per distinct failure
    path: str | Path, *, want: str = "file"
) -> list[str]:
    """Reasons ``path`` (``want`` = ``"file"`` or ``"dir"``) cannot be trusted; empty = trusted."""
    if os.name != "posix":
        return []
    p = Path(path)
    try:
        st = p.lstat()
    except OSError as exc:
        return [f"{p}: {exc.strerror or exc}"]
    if stat.S_ISLNK(st.st_mode):
        return [f"{p}: is a symbolic link"]
    if want == "file" and not stat.S_ISREG(st.st_mode):
        return [f"{p}: not a regular file"]
    if want == "dir" and not stat.S_ISDIR(st.st_mode):
        return [f"{p}: not a directory"]
    problems = []
    first = _entry_problem(p, st, ancestor=False)
    if first:
        problems.append(first)
    try:
        chain = list(p.resolve().parents)
    except OSError as exc:
        return [*problems, f"{p}: cannot resolve ({exc.strerror or exc})"]
    for parent in chain:
        try:
            pst = parent.stat()
        except OSError as exc:
            problems.append(f"{parent}: {exc.strerror or exc}")
            break
        found = _entry_problem(parent, pst, ancestor=True)
        if found:
            problems.append(found)
    return problems


def plugin_launch_problems(argv: list[str], plugin_dir: str) -> list[str]:
    """Problems with the files a plugin's expanded command line would execute or read as code.

    Every argument that names an existing path inside ``plugin_dir`` is checked as a file; the
    directory itself was checked when the plugin was discovered and is re-checked here.
    """
    if os.name != "posix" or not plugin_dir:
        return []
    root = Path(plugin_dir)
    problems = path_problems(root, want="dir")
    for arg in argv:
        if not os.path.isabs(arg):
            continue
        cand = Path(arg)
        try:
            inside = cand.parent.resolve().is_relative_to(root.resolve())
        except OSError:
            continue
        if inside and (cand.exists() or cand.is_symlink()) and not cand.is_dir():
            problems += path_problems(cand, want="file")
    return problems
