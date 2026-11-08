"""The environment collectors and plugins are started with.

Why this exists: a collector is a program the engine starts, usually as root, in the environment of
whoever started the engine. On a host that may be compromised that environment is not trustworthy:
``BASH_ENV`` makes every non-interactive ``bash`` run an arbitrary file *before the first line of
the collector* (so the collector cannot defend itself), ``LD_PRELOAD``/``DYLD_INSERT_LIBRARIES``
inject code into every child, and ``PATH`` decides which ``ss``/``ps``/``sha256sum`` is run. An
attacker who can plant any of these in root's profile, a ``sudo`` ``env_keep`` rule or an automation
runner's configuration controls, or silently falsifies, the audit. Secrets in the inherited
environment are also handed to every plugin for no reason.

Policy (POSIX): start children from an **allowlist**, not from a copy of the caller's environment.

* kept: a short list of locale/terminal/identity variables, ``LC_*``, ``BLUEOPS_*`` and ``BO_*``
  (the collectors' own, documented variables; the test hooks among them are ignored by the
  collectors unless ``BO_TEST_MODE=1`` and are reported when used);
* ``PATH`` is rebuilt the way ``linux/lib/common.sh`` does it: system directories first, then only
  entries that are absolute, exist, are owned by root and are not group/other-writable. In test
  mode (``BO_TEST_MODE=1``) the caller's ``PATH`` is kept, because the fixtures put command shims
  on it, exactly as the collector's own sanitiser does;
* everything else is dropped, and the names of dropped *loader/interpreter hooks* are reported
  (never their values) because finding ``BASH_ENV`` or ``LD_PRELOAD`` in an operator's environment
  during an incident is information in itself.

Windows: there is no ownership model equivalent to the POSIX one here, so only a small denylist of
variables that inject code into .NET/PowerShell child processes is removed and everything else is
inherited. **This has not been exercised on a Windows host**; see docs/security-model.md.

A caller that builds its own environment (``RunContext(env=...)``) is trusted to have meant it.
"""

from __future__ import annotations

import os
import shutil
import stat
from collections.abc import Mapping

SYSTEM_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
POSIX_KEEP = frozenset(
    {"HOME", "LANG", "LANGUAGE", "TZ", "TERM", "TMPDIR", "USER", "LOGNAME", "NO_COLOR"}
)
POSIX_KEEP_PREFIXES = ("LC_", "BLUEOPS_", "BO_")

# Names whose presence in an operator's environment is worth telling the operator about.
HOOK_NAMES = frozenset(
    {
        "BASH_ENV",
        "ENV",
        "BASH_FUNC",
        "PROMPT_COMMAND",
        "SHELLOPTS",
        "BASHOPTS",
        "CDPATH",
        "GLOBIGNORE",
        "IFS",
        "PS4",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "PYTHONHOME",
        "PERL5OPT",
        "PERL5LIB",
        "RUBYOPT",
        "RUBYLIB",
        "NODE_OPTIONS",
    }
)
HOOK_PREFIXES = ("LD_", "DYLD_", "BASH_FUNC_")

WINDOWS_DROP_PREFIXES = ("COR_", "CORECLR_", "COMPLUS_", "DOTNET_STARTUP", "DOTNET_ADDITIONAL")
WINDOWS_DROP = frozenset({"PSMODULEPATH_OVERRIDE", "__PSLOCKDOWNPOLICY"})


def in_test_mode(env: Mapping[str, str]) -> bool:
    return env.get("BO_TEST_MODE") == "1"


def _trusted_dir(path: str) -> bool:
    """Absolute, existing, a real directory, root-owned and not group/other-writable."""
    if not path or not os.path.isabs(path):
        return False
    try:
        st = os.stat(path)
    except OSError:
        return False
    return (
        stat.S_ISDIR(st.st_mode)
        and st.st_uid == 0
        and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    )


def safe_path(original: str) -> tuple[str, list[str]]:
    """``(PATH, dropped entries)``: system directories, then the trustworthy rest of the input."""
    kept = [d for d in SYSTEM_DIRS if os.path.isdir(d)]
    dropped: list[str] = []
    for entry in original.split(os.pathsep):
        if entry in kept:
            continue
        if _trusted_dir(entry):
            kept.append(entry)
        else:
            dropped.append(entry or "<empty>")
    return os.pathsep.join(kept), dropped


def _is_hook(name: str) -> bool:
    upper = name.upper()
    return upper in HOOK_NAMES or upper.startswith(HOOK_PREFIXES)


def sanitized_environment(
    source: Mapping[str, str] | None = None, *, posix: bool | None = None
) -> tuple[dict[str, str], list[str]]:
    """``(environment for a child, names of hook variables that were withheld)``."""
    src = dict(os.environ if source is None else source)
    on_posix = (os.name == "posix") if posix is None else posix
    if not on_posix:
        out = {
            k: v
            for k, v in src.items()
            if k.upper() not in WINDOWS_DROP and not k.upper().startswith(WINDOWS_DROP_PREFIXES)
        }
        return out, sorted(k for k in src if k not in out)
    out = {k: v for k, v in src.items() if k in POSIX_KEEP or k.startswith(POSIX_KEEP_PREFIXES)}
    if in_test_mode(src):
        if "PATH" in src:
            out["PATH"] = src["PATH"]
    else:
        out["PATH"], _ = safe_path(src.get("PATH", ""))
    withheld = sorted(k for k in src if k not in out and _is_hook(k))
    return out, withheld


def trusted_which(name: str, source: Mapping[str, str] | None = None) -> str | None:
    """Find ``name`` the way a child would, i.e. through the *sanitised* ``PATH``."""
    env, _ = sanitized_environment(source)
    return shutil.which(name, path=env.get("PATH"))
