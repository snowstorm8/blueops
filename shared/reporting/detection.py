"""Explainable detection rules over baseline-diff data (offline, read-only).

The input is the ``baseline-diff`` document produced by ``shared.reporting.baseline.compare``
(or a saved copy of it); the output is a ``detections`` document. Nothing here reads a host,
the network or the original reports: a rule only sees one diff ``change`` plus a small context.

Design rules (see ``docs/detection-rules.md``):

* A rule fires on a *change*, never on standing state, so a baseline that already contained
  something suspicious does not alert again. Indeterminate records and unverified attributes
  are never used.
* Every reason says whether it is an **observed** fact (the data itself shows the condition) or a
  **heuristic** suspicion (a pattern that is usually, but not necessarily, malicious).
* One detection per subject (``domain/scope/key``): several rules firing on the same record are
  merged as reasons. Detections that share an artifact (a path or process name) are linked, not
  merged, so the analyst sees one campaign instead of four unrelated alerts.
* Report content is attacker-influenced: rules treat every value as untrusted text, and a rule
  that raises is recorded as a rule error (coverage incomplete) instead of hiding the others.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from shared.reporting.accepted import Allowlist
from shared.reporting.accepted import apply as apply_allowlist
from shared.reporting.contracts import SCHEMA_VERSION, Severity

TOOL_NAME = "blueops-detect"
TOOL_VERSION = "0.3.0"

OBSERVED = "observed"
HEURISTIC = "heuristic"
READABLE_DIFF_VERSIONS = ("0.2",)

_DOMAIN_ORDER = (
    "users",
    "groups",
    "services",
    "processes",
    "listeners",
    "scheduled_tasks",
    "persistence",
    "config",
)


class DiffInputError(ValueError):
    """The input is not a usable baseline-diff document."""


@dataclass(frozen=True)
class Signal:
    """What one rule concluded about one change."""

    rule: str
    title: str
    severity: Severity
    basis: str
    observation: str
    rationale: str
    investigate: tuple[str, ...]
    techniques: tuple[str, ...] = ()
    tokens: tuple[str, ...] = ()
    unknown: tuple[str, ...] = ()


@dataclass
class Context:
    """Facts about the whole diff that a single change cannot show."""

    os_family: str
    new_accounts: frozenset[str]


Rule = Callable[[dict[str, Any], Context], list[Signal]]


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    domains: tuple[str, ...]
    summary: str
    func: Rule


RULES: list[RuleInfo] = []


def rule(rule_id: str, *domains: str) -> Callable[[Rule], Rule]:
    def register(func: Rule) -> Rule:
        summary = (func.__doc__ or "").strip().splitlines()[0]
        RULES.append(RuleInfo(rule_id, domains, summary, func))
        return func

    return register


# --- helpers over a diff change ------------------------------------------------------------


def _vals(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if x is not None]
    return [str(v)]


def _one(v: Any) -> str:
    vals = _vals(v)
    return vals[0] if vals else ""


def _attrs(rec: Any) -> dict[str, Any]:
    if isinstance(rec, dict) and isinstance(rec.get("attrs"), dict):
        return rec["attrs"]
    return {}


def _now(c: dict[str, Any], name: str) -> Any:
    """Attribute value in the current record (None when absent or unknown)."""
    return _attrs(c.get("current")).get(name)


def _delta(c: dict[str, Any], name: str) -> tuple[list[str], list[str]] | None:
    for a in c.get("attributes") or []:
        if isinstance(a, dict) and a.get("name") == name:
            return _vals(a.get("before")), _vals(a.get("after"))
    return None


def _new_values(c: dict[str, Any]) -> dict[str, list[str]]:
    """Values that appeared with this change: every attribute of an added record, only the
    changed attributes of a modified one, nothing for a removal."""
    if c["change"] == "added":
        return {k: _vals(v) for k, v in _attrs(c.get("current")).items()}
    if c["change"] == "modified":
        return {
            a["name"]: _vals(a.get("after"))
            for a in c.get("attributes") or []
            if isinstance(a, dict) and isinstance(a.get("name"), str)
        }
    return {}


def _name(c: dict[str, Any]) -> str:
    """The part of the key after the domain prefix (``user:alice`` -> ``alice``)."""
    return str(c["key"]).split(":", 1)[-1]


def _acct(c: dict[str, Any]) -> str:
    """Account name for messages: the reported name, else the key (a SID on Windows)."""
    return _one(_now(c, "name")) or _name(c)


def _sig(rule_id: str, title: str, sev: Severity, basis: str, **kw: Any) -> list[Signal]:
    return [Signal(rule=rule_id, title=title, severity=sev, basis=basis, **kw)]


# Records the inventory keeps only as a content digest: the report cannot say what is inside.
_CONTENT_ATTRS = frozenset({"command", "value", "target", "path", "image_path", "actions"})


def _hash_only(c: dict[str, Any]) -> bool:
    """True when the change is known only through a file digest (no readable content)."""
    names = set(_new_values(c))
    return "sha256" in names and not names & _CONTENT_ATTRS


def _digest(c: dict[str, Any]) -> str:
    d = _delta(c, "sha256")
    if d:
        return f" (SHA-256 {_one(d[0])[:12] or 'none'}.. -> {_one(d[1])[:12]}..)"
    return ""


NOLOGIN = ("nologin", "false", "sync", "shutdown", "halt")


def _login_shell(shell: str) -> bool:
    s = shell.strip().lower()
    return bool(s) and s.rsplit("/", 1)[-1] not in NOLOGIN


# --- users and groups ----------------------------------------------------------------------


@rule("BO-USR-001", "users")
def _uid0(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Account other than root with UID 0 appeared."""
    if c["change"] == "added":
        uid = _one(_now(c, "uid"))
    elif c["change"] == "modified" and _delta(c, "uid"):
        uid = _one((_delta(c, "uid") or ([], []))[1])
    else:
        return []
    name = _name(c)
    if uid != "0" or name == "root":
        return []
    return _sig(
        "BO-USR-001",
        "Non-root account with UID 0",
        Severity.CRITICAL,
        OBSERVED,
        observation=f"Account '{name}' has UID 0 and did not before ({c['change']}).",
        rationale="UID 0 is full root authority regardless of the account name; a second "
        "UID 0 account is a classic backdoor and rarely legitimate.",
        investigate=(
            "Review the account entry in /etc/passwd and the last-login records for it.",
            "Check who created it (auth log, shell history of administrators) and when.",
            "Confirm with the system owner; if unauthorised, contain per your incident plan "
            "(lock the account, preserve evidence first).",
        ),
        techniques=("T1136.001", "T1078.003"),
    )


@rule("BO-USR-002", "users")
def _new_account(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """New local account."""
    if c["change"] != "added":
        return []
    sev = Severity.MEDIUM
    notes = []
    shell = _one(_now(c, "shell"))
    if shell and not _login_shell(shell):
        sev = Severity.LOW
        notes.append("it has no interactive login shell")
    if _one(_now(c, "enabled")) == "false":
        sev = Severity.LOW
        notes.append("it is disabled")
    if _one(_now(c, "password")) == "empty" or _one(_now(c, "password_required")) == "false":
        sev = Severity.HIGH
        notes = ["it has no password requirement"]
    extra = f" ({'; '.join(notes)})" if notes else ""
    return _sig(
        "BO-USR-002",
        "New local account",
        sev,
        OBSERVED,
        observation=f"Account '{_acct(c)}' exists now and did not in the baseline{extra}.",
        rationale="Unplanned accounts are a common persistence step. Provisioning and package "
        "installs also create accounts, which is why a locked or no-login account is rated low.",
        investigate=(
            "Match the account against change tickets, package installs and the competition "
            "or build documentation.",
            "Look at when it first appeared (file times of its home directory or profile).",
            "Check group memberships and any scheduled jobs or keys tied to the same name.",
        ),
        techniques=("T1136.001",),
    )


@rule("BO-USR-003", "users")
def _shell_enabled(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Service account given an interactive login shell."""
    d = _delta(c, "shell")
    if c["change"] != "modified" or not d or not d[0] or not d[1]:
        return []
    if _login_shell(d[0][0]) or not _login_shell(d[1][0]):
        return []
    return _sig(
        "BO-USR-003",
        "No-login account can now log in",
        Severity.HIGH,
        OBSERVED,
        observation=f"Shell of '{_acct(c)}' changed from {d[0][0]} to {d[1][0]}.",
        rationale="Service accounts normally have no login shell; enabling one makes the "
        "account usable for interactive access, often with that service's privileges.",
        investigate=(
            "Determine whether the account is supposed to be interactive (administrators "
            "sometimes enable a shell for maintenance).",
            "Check for new SSH keys or password changes on the same account.",
        ),
        techniques=("T1098",),
    )


@rule("BO-USR-004", "users")
def _account_enabled(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Disabled account was enabled."""
    d = _delta(c, "enabled")
    if c["change"] != "modified" or not d or d[0] != ["false"] or d[1] != ["true"]:
        return []
    rid = _name(c).rsplit("-", 1)[-1]
    builtin = rid in ("500", "501")
    return _sig(
        "BO-USR-004",
        "Disabled account re-enabled",
        Severity.HIGH if builtin else Severity.MEDIUM,
        OBSERVED,
        observation=f"Account '{_acct(c)}' changed from disabled to enabled"
        + (" (built-in Administrator/Guest)." if builtin else "."),
        rationale="Built-in Administrator and Guest accounts are disabled by hardening guides; "
        "re-enabling them restores a well-known login target. Other accounts may be "
        "re-enabled legitimately.",
        investigate=(
            "Review the account's recent logons and password-last-set time.",
            "Confirm with the owner; if not authorised, disable it and record who enabled it.",
        ),
        techniques=("T1078.001", "T1098"),
    )


@rule("BO-USR-005", "users")
def _password_removed(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Password requirement removed from an account."""
    if c["change"] != "modified":
        return []
    req = _delta(c, "password_required")
    pw = _delta(c, "password")
    weakened = (req is not None and req[1] == ["false"] and req[0] != ["false"]) or (
        pw is not None and pw[1] == ["empty"] and pw[0] != ["empty"]
    )
    if not weakened:
        return []
    return _sig(
        "BO-USR-005",
        "Account no longer requires a password",
        Severity.HIGH,
        OBSERVED,
        observation=f"Password state of '{_acct(c)}' now allows an empty password.",
        rationale="An account without a password can be used by anyone who can reach a "
        "login path to it.",
        investigate=(
            "Check authentication logs for logons to the account since the baseline.",
            "Set a password or lock the account after preserving evidence.",
        ),
        techniques=("T1098",),
    )


PRIVILEGED_GROUPS: dict[str, tuple[Severity, str]] = {
    "sudo": (Severity.HIGH, "sudo (administrator)"),
    "wheel": (Severity.HIGH, "wheel (administrator)"),
    "admin": (Severity.HIGH, "admin (administrator)"),
    "root": (Severity.HIGH, "root"),
    "docker": (Severity.MEDIUM, "docker (root-equivalent)"),
    "lxd": (Severity.MEDIUM, "lxd (root-equivalent)"),
    "disk": (Severity.MEDIUM, "disk (raw device access)"),
    "shadow": (Severity.MEDIUM, "shadow (password database access)"),
    "s-1-5-32-544": (Severity.HIGH, "Administrators"),
    "s-1-5-32-548": (Severity.MEDIUM, "Account Operators"),
    "s-1-5-32-549": (Severity.MEDIUM, "Server Operators"),
    "s-1-5-32-551": (Severity.MEDIUM, "Backup Operators"),
    "s-1-5-32-555": (Severity.MEDIUM, "Remote Desktop Users"),
}


@rule("BO-GRP-001", "groups")
def _group_member_added(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Member added to a privileged group."""
    gid = _name(c).casefold()
    if gid not in PRIVILEGED_GROUPS or c["change"] not in ("added", "modified"):
        return []
    d = _delta(c, "members") if c["change"] == "modified" else ([], _vals(_now(c, "members")))
    if d is None:
        return []
    before = {m.casefold() for m in d[0]}
    added = sorted({m for m in d[1] if m.casefold() not in before}, key=str.casefold)
    if not added:
        return []
    sev, label = PRIVILEGED_GROUPS[gid]
    fresh = [m for m in added if m.casefold() in ctx.new_accounts]
    why = f"Added to {label}: {', '.join(added)}."
    if fresh:
        sev = Severity.CRITICAL
        why += f" {', '.join(fresh)} was itself created since the baseline."
    return _sig(
        "BO-GRP-001",
        "Privileged group membership grew",
        sev,
        OBSERVED,
        observation=why,
        rationale="Membership of administrator-class groups grants control of the host. A "
        "brand-new account that is immediately privileged is the strongest form of this signal.",
        investigate=(
            "Identify who changed the group (auth/security log events for group changes).",
            "Verify each added member against the approved administrator list.",
            "Review the added accounts' logons and keys since the baseline.",
        ),
        techniques=("T1098", "T1136.001"),
    )


# --- persistence ---------------------------------------------------------------------------

_HASH_UNKNOWN = {
    "added": (
        "What the new file contains: the report records only its SHA-256, not its content.",
        "Which program the file starts.",
    ),
    "modified": (
        "What changed inside the file: the report records only a SHA-256 of its content.",
        "Whether the edit added, removed or restored an entry; reverting to known-good "
        "content looks the same as tampering.",
        "Which program the file now starts.",
    ),
}

HIGH_RISK_MECHANISMS = (
    "winlogon",
    "ifeo",
    "accessibility",
    "appinit",
    "appcertdlls",
    "lsa",
    "netsh",
    "portmonitor",
    "timeprovider",
    "silentprocessexit",
    "wmi",
    "bootexecute",
)


# The Linux collector keys authorized keys as persist:ssh-authkey:<owner>:<id> with an ``owner``
# attribute; persist:ssh_key:<user>:<fingerprint> with ``user`` is the older/synthetic form.
SSH_KEY_PREFIXES = ("persist:ssh-authkey:", "persist:ssh_key:")


@rule("BO-PER-001", "persistence")
def _ssh_key(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """SSH authorized key added."""
    if c["change"] != "added" or not str(c["key"]).startswith(SSH_KEY_PREFIXES):
        return []
    user = _one(_now(c, "owner")) or _one(_now(c, "user")) or "unknown user"
    return _sig(
        "BO-PER-001",
        "New SSH authorized key",
        Severity.CRITICAL if user == "root" else Severity.HIGH,
        OBSERVED,
        observation=f"A new SSH key (fingerprint in the key) can log in as '{user}'.",
        rationale="An authorized key survives password resets and is a quiet, durable way back "
        "into a host. Only fingerprints are recorded; the key material is not in the report.",
        investigate=(
            "Compare the fingerprint with the keys your administrators actually use.",
            "Check authorized_keys modification time and the logins that used the key.",
            "Remove the key only after preserving the file for evidence.",
        ),
        techniques=("T1098.004",),
    )


@rule("BO-PER-002", "persistence")
def _persistence(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Persistence mechanism added or its content changed."""
    key = str(c["key"])
    if c["change"] == "removed" or key.startswith(SSH_KEY_PREFIXES):
        return []
    parts = key.split(":")
    mech = parts[1] if len(parts) > 1 else "unknown"
    risky = mech in HIGH_RISK_MECHANISMS
    sev = Severity.HIGH if (risky or c["change"] == "modified") else Severity.MEDIUM
    verb = "added" if c["change"] == "added" else "changed"
    hashed = _hash_only(c)
    return _sig(
        "BO-PER-002",
        "Persistence entry " + verb,
        sev,
        OBSERVED,
        observation=f"Persistence entry '{key}' ({mech}) was {verb}"
        + (f"; only its content hash differs{_digest(c)}." if hashed else "."),
        unknown=_HASH_UNKNOWN[c["change"]] if hashed else (),
        rationale="Autostart locations run code without a user action. A changed existing "
        "entry or a rarely-used mechanism is more suspicious than a new Run/startup item; "
        "installers also create these, so confirm against software changes.",
        investigate=(
            "Open the referenced file or registry value and identify the program it runs.",
            "Check its signature/package ownership and creation time.",
            "Look for the same program elsewhere in this report (tasks, services, listeners).",
        ),
        techniques=("T1547",),
    )


# --- executables in volatile locations (heuristic) ----------------------------------------

# Patterns matched against report data; the tool never touches these locations. Unix prefixes
# must start the path (so /home/alice/tmp/x is not a hit); Windows fragments need a drive letter.
UNIX_VOLATILE = (
    "/tmp/",  # noqa: S108
    "/var/tmp/",  # noqa: S108
    "/dev/shm/",  # noqa: S108
    "/run/shm/",
    "/run/user/",
)
WINDOWS_VOLATILE = (
    "/users/public/",
    "/appdata/",
    "/windows/temp/",
    "/temp/",
    "/$recycle.bin/",
    "/perflogs/",
)
_DRIVE = re.compile(r"[a-z]:/")
_PATH_TOKEN = re.compile(r"(?:[a-z]:)?/[^\s\"'|<>;&]*")
_EXE_TECHNIQUE = {
    "scheduled_tasks": "T1053",
    "services": "T1543",
    "persistence": "T1547",
    "processes": "T1036",
}
_NON_COMMAND = frozenset({"sha256", "mode", "size", "type", "user", "owner", "name", "uid", "gid"})


def volatile_paths(value: str) -> list[str]:
    """Normalised path tokens in ``value`` that sit in a world-writable or temporary location."""
    norm = value.lower().replace("\\", "/")
    out = []
    for m in _PATH_TOKEN.finditer(norm):
        tok = m.group()
        if tok.startswith(UNIX_VOLATILE) or (
            _DRIVE.match(tok) and any(p in tok for p in WINDOWS_VOLATILE)
        ):
            out.append(tok)
    return out


def leaves_volatile(d: tuple[list[str], list[str]] | None) -> bool:
    """True when a value moved from a temporary location to somewhere else (looks like a fix)."""
    return (
        bool(d)
        and any(volatile_paths(v) for v in d[0])
        and not any(volatile_paths(v) for v in d[1])
    )


@rule("BO-EXE-001", "scheduled_tasks", "services", "persistence", "processes")
def _volatile_exec(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Autostart or process runs from a temporary or world-writable location."""
    domain = c["domain"]
    paths: list[str] = []
    for name, values in _new_values(c).items():
        if name in _NON_COMMAND:
            continue
        for v in values:
            paths += volatile_paths(v)
    if c["change"] == "modified":
        # A path already present before the change is not something this change introduced.
        for a in c.get("attributes") or []:
            if isinstance(a, dict):
                for v in _vals(a.get("before")):
                    paths = [p for p in paths if p not in volatile_paths(v)]
    if not paths:
        return []
    paths = sorted(set(paths))
    tokens = tuple(paths) + tuple("name:" + p.rsplit("/", 1)[-1] for p in paths)
    return _sig(
        "BO-EXE-001",
        "Executes from a temporary or world-writable location",
        Severity.MEDIUM if domain == "processes" else Severity.HIGH,
        HEURISTIC,
        observation=f"New value refers to {', '.join(paths[:3])}.",
        rationale="Legitimate software is installed to protected directories. Staging code in "
        "/tmp, /dev/shm, Users\\Public or AppData and then making it start automatically is "
        "common attacker tradecraft, but portable tools and installers use these paths too.",
        investigate=(
            "Hash and inspect the file (do not execute it); compare with package/vendor data.",
            "Check its owner, creation time and who or what wrote it.",
            "Search this report for other records pointing at the same file.",
        ),
        techniques=(_EXE_TECHNIQUE.get(domain, "T1036"),),
        tokens=tokens,
    )


# --- scheduled tasks and services ---------------------------------------------------------


@rule("BO-SCH-001", "scheduled_tasks")
def _new_task(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """New scheduled job."""
    if c["change"] != "added":
        return []
    return _sig(
        "BO-SCH-001",
        "New scheduled job",
        Severity.MEDIUM,
        OBSERVED,
        observation=f"Scheduled job '{_name(c)}' exists now and did not in the baseline.",
        rationale="Scheduled jobs give recurring, often privileged execution. Administrators "
        "and package installs add them legitimately.",
        investigate=(
            "Read the job's command and the account it runs as.",
            "Check the file or task definition's creation time and writer.",
        ),
        techniques=("T1053.003", "T1053.005"),
    )


@rule("BO-SCH-002", "scheduled_tasks")
def _hidden_task(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """New scheduled task marked hidden."""
    if c["change"] != "added" or _one(_now(c, "hidden")) != "true":
        return []
    return _sig(
        "BO-SCH-002",
        "New hidden scheduled task",
        Severity.HIGH,
        HEURISTIC,
        observation=f"Task '{_name(c)}' is flagged hidden.",
        rationale="The Hidden flag keeps a task out of the default Task Scheduler view. Some "
        "vendors use it, but it is also used to avoid review.",
        investigate=(
            "Dump the task XML and read its actions, triggers and principal.",
            "Compare against software installed in the same window.",
        ),
        techniques=("T1053.005", "T1564"),
    )


@rule("BO-SCH-003", "scheduled_tasks")
def _task_command_changed(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Command of an existing scheduled job changed."""
    if c["change"] != "modified":
        return []
    ds = [d for d in (_delta(c, "command"), _delta(c, "actions")) if d]
    if not ds:
        return []
    before, after = ds[0]
    fix = leaves_volatile(ds[0])
    return _sig(
        "BO-SCH-003",
        "Existing scheduled job now runs something else",
        Severity.LOW if fix else Severity.HIGH,
        OBSERVED,
        observation=f"Command of '{_name(c)}' changed: {'; '.join(before)} -> {'; '.join(after)}.",
        rationale="Rewriting a trusted job is stealthier than adding one: the schedule, name "
        "and owner stay familiar while the payload changes.",
        investigate=(
            "Diff the old and new command and inspect the new target.",
            "Check who modified the job definition and when.",
        ),
        techniques=("T1053",),
    )


@rule("BO-SVC-001", "services")
def _new_service(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """New service."""
    if c["change"] != "added":
        return []
    off = {_one(_now(c, "start_mode")).lower(), _one(_now(c, "enabled")).lower()} & {
        "disabled",
    }
    return _sig(
        "BO-SVC-001",
        "New service",
        Severity.LOW if off else Severity.MEDIUM,
        OBSERVED,
        observation=f"Service '{_name(c)}' exists now and did not in the baseline"
        + (" (disabled)." if off else "."),
        rationale="Services run unattended, often as root/SYSTEM. Software installs add them; "
        "so do attackers establishing persistence.",
        investigate=(
            "Identify the package or installer that owns it and the binary it runs.",
            "Check the account it runs as and whether it listens on the network.",
        ),
        techniques=("T1543.002", "T1543.003"),
    )


def _runs_as_system(acct: tuple[list[str], list[str]] | None) -> bool:
    """True when the account changed to LocalSystem."""
    return bool(acct) and any(
        "localsystem" in a.lower() or a.lower().endswith("\\system") for a in acct[1]
    )


@rule("BO-SVC-002", "services")
def _service_hijack(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Existing service points at a different binary or runs as a more privileged account."""
    if c["change"] != "modified":
        return []
    path = _delta(c, "image_path")
    acct = _delta(c, "account")
    reasons = []
    fix = leaves_volatile(path) and not _runs_as_system(acct)
    if path:
        reasons.append(f"binary changed to {'; '.join(path[1])}")
    if _runs_as_system(acct):
        reasons.append("now runs as LocalSystem")
    if not reasons:
        return []
    return _sig(
        "BO-SVC-002",
        "Existing service modified",
        Severity.LOW if fix else Severity.HIGH,
        OBSERVED,
        observation=f"Service '{_name(c)}': {'; '.join(reasons)}."
        + (
            " It moved away from a temporary location, which looks like remediation." if fix else ""
        ),
        rationale="Replacing the binary of a trusted service, or raising its account, runs "
        "attacker code under a name defenders already ignore.",
        investigate=(
            "Compare the new binary with the vendor's and check its signature.",
            "Review service-control and installation events around the window.",
        ),
        techniques=("T1543", "T1574.010"),
    )


_CLEARTEXT = re.compile(r"^(telnet|rsh|rlogin|rexec|tftp)(d|s)?(\.service|\.socket)?$", re.I)


@rule("BO-SVC-003", "services")
def _cleartext_service(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Cleartext remote-access service installed or started."""
    if c["change"] == "removed" or not _CLEARTEXT.match(_name(c)):
        return []
    if c["change"] == "modified":
        d = _delta(c, "active") or _delta(c, "state")
        if not d or d[1][:1] not in (["running"], ["Running"]):
            return []
    elif _one(_now(c, "active")).lower() not in ("running", "") and _one(
        _now(c, "state")
    ).lower() not in ("running", ""):
        return []
    return _sig(
        "BO-SVC-003",
        "Cleartext remote-access service",
        Severity.MEDIUM,
        HEURISTIC,
        observation=f"Service '{_name(c)}' is present/running and was not before.",
        rationale="Telnet, rsh, rlogin, rexec and TFTP send credentials or data in the clear "
        "and are rarely needed; they are matched by name only.",
        investigate=(
            "Confirm whether the service is required by the scenario/business.",
            "Check which listener it opened and who connected.",
        ),
        techniques=("T1021",),
    )


SECURITY_SERVICES = {
    "auditd": Severity.HIGH,
    "eventlog": Severity.HIGH,
    "sysmon": Severity.HIGH,
    "sysmon64": Severity.HIGH,
    "windefend": Severity.HIGH,
    "mpssvc": Severity.HIGH,
    "rsyslog": Severity.MEDIUM,
    "syslog-ng": Severity.MEDIUM,
    "fail2ban": Severity.MEDIUM,
    "apparmor": Severity.MEDIUM,
    "ufw": Severity.MEDIUM,
    "firewalld": Severity.MEDIUM,
    "wazuh-agent": Severity.MEDIUM,
    "falco": Severity.MEDIUM,
}


@rule("BO-SVC-004", "services")
def _security_service_down(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Logging or security service stopped, disabled or removed."""
    svc = _name(c).casefold()
    svc = svc[: -len(".service")] if svc.endswith(".service") else svc
    if svc not in SECURITY_SERVICES:
        return []
    how = ""
    if c["change"] == "removed":
        how = "is gone"
    elif c["change"] == "modified":
        for attr, bad in (
            ("active", {"dead", "failed", "inactive"}),
            ("state", {"stopped"}),
            ("enabled", {"disabled", "masked"}),
            ("start_mode", {"disabled"}),
        ):
            d = _delta(c, attr)
            if d and d[1] and d[1][0].lower() in bad and not (d[0] and d[0][0].lower() in bad):
                how = f"{attr} is now {d[1][0]}"
                break
    if not how:
        return []
    return _sig(
        "BO-SVC-004",
        "Logging or security service disabled",
        SECURITY_SERVICES[svc],
        OBSERVED,
        observation=f"'{svc}' {how}.",
        rationale="Stopping audit, logging, firewall or endpoint-protection services reduces "
        "what defenders can see. Maintenance restarts and package upgrades also do this "
        "briefly, so check whether it is still down.",
        investigate=(
            "Check the service's current state and the log that explains why it stopped.",
            "Look for a gap in the logs it produces that overlaps the change window.",
        ),
        techniques=("T1562.001", "T1562.002"),
    )


# --- listeners -----------------------------------------------------------------------------

REMOTE_TOOLS = frozenset({"nc", "ncat", "netcat", "socat", "nc.traditional"})
SUSPICIOUS_PORTS = frozenset({"4444", "4445", "1337", "31337", "6666", "12345"})
WELL_KNOWN_PORTS = frozenset({"22", "23", "80", "443", "445", "3389", "5985", "5986"})


def _loopback(binds: list[str]) -> bool:
    return bool(binds) and all(b.startswith(("127.", "::1", "localhost")) for b in binds)


def _tool_name(proc: str) -> str:
    return proc.lower().removesuffix(".exe")


@rule("BO-NET-001", "listeners")
def _new_listener(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """New listener reachable from the network."""
    if c["change"] != "added" or _loopback(_vals(_now(c, "bind"))):
        return []
    proc = _one(_now(c, "process")) or "unknown process"
    return _sig(
        "BO-NET-001",
        "New network listener",
        Severity.MEDIUM,
        OBSERVED,
        observation=f"{proc} listens on {_name(c)} and was not listening in the baseline.",
        rationale="A new reachable port is new attack surface and can be a bind-shell or "
        "tunnel endpoint; new services open ports too.",
        investigate=(
            "Identify the owning process and its executable, and whether it is scored/expected.",
            "Check the firewall: is the port reachable from outside?",
        ),
        techniques=("T1571", "T1205"),
        tokens=tuple("name:" + p.lower() for p in _vals(_now(c, "process"))),
    )


@rule("BO-NET-002", "listeners")
def _suspicious_listener(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Listener owned by a netcat-style tool or on a port favoured by common payloads."""
    if c["change"] != "added":
        return []
    procs = [p.lower().removesuffix(".exe") for p in _vals(_now(c, "process"))]
    ports = _vals(_now(c, "port"))
    tool = [p for p in procs if p in REMOTE_TOOLS]
    port = [p for p in ports if p in SUSPICIOUS_PORTS]
    if not tool and not port:
        return []
    exposed = not _loopback(_vals(_now(c, "bind")))
    what = []
    if tool:
        what.append(f"process {', '.join(tool)} is a general-purpose network tool")
    if port:
        what.append(f"port {', '.join(port)} is a default for common reverse-shell payloads")
    return _sig(
        "BO-NET-002",
        "Listener matches a backdoor pattern",
        Severity.HIGH if exposed else Severity.MEDIUM,
        HEURISTIC,
        observation="; ".join(what).capitalize() + ".",
        rationale="Netcat-style listeners and default payload ports are typical of bind shells. "
        "Both also have legitimate uses (debugging, test servers), so this is a suspicion.",
        investigate=(
            "Inspect the process: executable path, parent, command line and owner.",
            "Capture the connection list for the port before taking any containment action.",
        ),
        techniques=("T1059", "T1571"),
        tokens=tuple("name:" + p for p in procs),
    )


@rule("BO-NET-003", "listeners")
def _listener_owner_changed(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """A different process now owns an existing listener."""
    d = _delta(c, "process")
    if c["change"] != "modified" or not d or _name(c).endswith("/ephemeral"):
        return []
    port = _name(c).rsplit("/", 1)[-1]
    was_tool = any(_tool_name(p) in REMOTE_TOOLS for p in d[0])
    is_tool = any(_tool_name(p) in REMOTE_TOOLS for p in d[1])
    fix = was_tool and not is_tool
    return _sig(
        "BO-NET-003",
        "Listener taken over by another process",
        Severity.LOW if fix else (Severity.HIGH if port in WELL_KNOWN_PORTS else Severity.MEDIUM),
        OBSERVED,
        observation=f"{_name(c)} was served by {', '.join(d[0])}, now by {', '.join(d[1])}."
        + (
            " The previous owner was a netcat-style tool, which looks like remediation."
            if fix
            else ""
        ),
        rationale="A different program answering on an established port can be a service "
        "replacement or hijack; upgrades and renamed binaries do this as well.",
        investigate=(
            "Compare the old and new executables and the service that should own the port.",
            "Check the startup record that launched the new process.",
        ),
        techniques=("T1036", "T1574"),
    )


# --- configuration -------------------------------------------------------------------------


@rule("BO-CFG-001", "config")
def _firewall_weakened(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Host firewall profile disabled or opened."""
    if c["change"] != "modified" or not str(c["key"]).startswith("config:firewall:profile:"):
        return []
    en = _delta(c, "enabled")
    inbound = _delta(c, "default_inbound")
    why = []
    if en and en[1] == ["false"]:
        why.append("profile disabled")
    if inbound and inbound[1] and inbound[1][0].lower() == "allow":
        why.append("default inbound action is Allow")
    if not why:
        return []
    return _sig(
        "BO-CFG-001",
        "Host firewall weakened",
        Severity.HIGH,
        OBSERVED,
        observation=f"{_name(c)}: {', '.join(why)}.",
        rationale="Disabling the host firewall exposes every listening service, and lets "
        "inbound shells and lateral movement through.",
        investigate=(
            "Check firewall policy and security log events for who changed it.",
            "Re-enable only after checking that required (scored) ports stay reachable.",
        ),
        techniques=("T1562.004",),
    )


# (key fragment, values that weaken it, severity, explanation)
WEAKENINGS = (
    ("::enablelua", {"0"}, Severity.HIGH, "User Account Control is turned off"),
    ("::restrictanonymous", {"0"}, Severity.MEDIUM, "anonymous enumeration is allowed"),
    ("kernel.randomize_va_space", {"0", "1"}, Severity.HIGH, "ASLR is reduced or off"),
    ("net.ipv4.ip_forward", {"1"}, Severity.MEDIUM, "the host now forwards IP traffic"),
)


def _lowered(d: tuple[list[str], list[str]], frag: str) -> bool:
    """For graded settings (ASLR 0/1/2) only a drop counts; raising 0 -> 1 is an improvement."""
    if frag != "kernel.randomize_va_space" or not d[0]:
        return True
    try:
        return int(d[1][0]) < int(d[0][0])
    except ValueError:
        return True


@rule("BO-CFG-002", "config")
def _hardening_weakened(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Known hardening setting moved to its weak value."""
    if c["change"] != "modified":
        return []
    d = _delta(c, "value")
    if not d or not d[1]:
        return []
    key = str(c["key"])
    for frag, bad, sev, why in WEAKENINGS:
        if frag in key and d[1][0] in bad and d[0][:1] != d[1][:1] and _lowered(d, frag):
            return _sig(
                "BO-CFG-002",
                "Hardening setting weakened",
                sev,
                OBSERVED,
                observation=f"{key}: {', '.join(d[0])} -> {', '.join(d[1])}; {why}.",
                rationale="This setting is part of common hardening baselines; reverting it "
                "removes a protection. Some changes (IP forwarding for containers/routers) "
                "are deliberate.",
                investigate=(
                    "Check whether the setting is required by a role on this host.",
                    "Find the change in configuration management or admin history.",
                ),
                techniques=("T1562",),
            )
    return []


def _setuid(mode: str) -> bool:
    try:
        return bool(int(mode, 8) & 0o6000)
    except ValueError:
        return False


GTFO_BINARIES = frozenset(
    {
        *("awk", "bash", "cp", "dash", "env", "find", "gdb", "less", "more", "mv", "nano"),
        *("nmap", "node", "perl", "php", "python", "python3", "ruby", "sh", "tar", "vi"),
        *("vim", "zip"),
    }
)


def _new_suid_path(c: dict[str, Any]) -> str | None:
    """Path when the change introduced a set-ID bit, else None."""
    if not str(c["key"]).startswith("config:suid:"):
        return None
    if c["change"] == "added":
        return _name(c).split(":", 1)[-1] if _setuid(_one(_now(c, "mode"))) else None
    d = _delta(c, "mode")
    if (
        c["change"] == "modified"
        and d
        and d[1]
        and _setuid(d[1][0])
        and not (d[0] and _setuid(d[0][0]))
    ):
        return _name(c).split(":", 1)[-1]
    return None


@rule("BO-CFG-003", "config")
def _new_suid(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """New set-UID/set-GID file."""
    path = _new_suid_path(c)
    if path is None:
        return []
    return _sig(
        "BO-CFG-003",
        "New set-UID/set-GID file",
        Severity.MEDIUM,
        OBSERVED,
        observation=f"{path} now has a set-ID bit (mode {_one(_now(c, 'mode'))}).",
        rationale="Set-ID files run with their owner's privileges and are a path to privilege "
        "escalation; package updates add a few legitimately.",
        investigate=(
            "Check which package owns the file (package manager verify) and its hash.",
            "Look at its creation time and who created it.",
        ),
        techniques=("T1548.001",),
    )


@rule("BO-CFG-004", "config")
def _risky_suid(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """New set-ID file is a shell-capable tool or lives in a temporary location."""
    path = _new_suid_path(c)
    if path is None:
        return []
    base = path.rsplit("/", 1)[-1]
    reasons = []
    if base in GTFO_BINARIES:
        reasons.append(f"{base} can spawn a shell or read/write arbitrary files")
    if volatile_paths(path):
        reasons.append("it is in a temporary or world-writable directory")
    if not reasons:
        return []
    return _sig(
        "BO-CFG-004",
        "Set-ID file allows privilege escalation",
        Severity.HIGH,
        HEURISTIC,
        observation=f"{path}: {'; '.join(reasons)}.",
        rationale="A set-ID interpreter, editor or file tool gives any local user root; a "
        "set-ID file in /tmp is almost never packaged software.",
        investigate=(
            "Treat as a probable privilege-escalation backdoor: preserve it and its metadata.",
            "Remove the set-ID bit only after capturing evidence and confirming it is not "
            "required.",
        ),
        techniques=("T1548.001",),
        tokens=tuple(volatile_paths(path)),
    )


@rule("BO-CFG-005", "config")
def _auth_config(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """sudoers or PAM configuration added or changed."""
    key = str(c["key"])
    if c["change"] == "removed" or not key.startswith(("config:sudoers:", "config:pam:")):
        return []
    kind = "sudoers" if key.startswith("config:sudoers:") else "PAM"
    verb = "added" if c["change"] == "added" else "changed"
    hashed = _hash_only(c)
    return _sig(
        "BO-CFG-005",
        f"{kind} configuration {verb}",
        Severity.HIGH,
        OBSERVED,
        observation=f"{key} was {verb}"
        + (f"; only its content hash differs{_digest(c)}." if hashed else "."),
        unknown=_HASH_UNKNOWN[c["change"]][:1]
        + (
            (
                "Whether access was widened (NOPASSWD, wildcard) or narrowed; a restore to a "
                "known-good file looks the same as an attack.",
            )
            if hashed
            else ()
        ),
        rationale="sudoers and PAM define who can become root and how logins are checked; "
        "attackers edit them for passwordless root or authentication bypass.",
        investigate=(
            "Diff the file against the distribution default or configuration management.",
            "Look for NOPASSWD, wildcard, pam_permit or unfamiliar modules.",
        ),
        techniques=("T1548.003", "T1556"),
    )


@rule("BO-CFG-006", "config")
def _defender_exclusion(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Antivirus exclusion added."""
    if c["change"] != "added" or ":defender-exclusion:" not in str(c["key"]):
        return []
    return _sig(
        "BO-CFG-006",
        "Antivirus exclusion added",
        Severity.HIGH,
        OBSERVED,
        observation=f"{c['key']} now exists.",
        rationale="Exclusions let tools run or be stored without scanning; attackers add them "
        "before dropping payloads. Some software requires them.",
        investigate=(
            "Look at what the excluded path/process contains.",
            "Check which administrator or installer added it.",
        ),
        techniques=("T1562.001",),
    )


@rule("BO-CFG-007", "config")
def _name_resolution(c: dict[str, Any], ctx: Context) -> list[Signal]:
    """Hosts-file entry or DNS server added or changed."""
    key = str(c["key"])
    if c["change"] == "removed" or not key.startswith(("config:hosts:", "config:dns:")):
        return []
    return _sig(
        "BO-CFG-007",
        "Name resolution changed",
        Severity.MEDIUM,
        OBSERVED,
        observation=f"{key} was {'added' if c['change'] == 'added' else 'changed'}.",
        rationale="Redirecting names (hosts file, resolver) can send traffic to attacker "
        "systems or block security updates. DHCP and VPN clients also change resolvers.",
        investigate=(
            "Check the entry against your network documentation.",
            "Confirm what manages the resolver configuration on this host.",
        ),
        techniques=("T1565.001",),
    )


# --- engine --------------------------------------------------------------------------------


def validate_diff(diff: Any) -> dict[str, Any]:
    """Reject anything that is not a well-formed baseline-diff (untrusted input)."""
    if not isinstance(diff, dict) or diff.get("kind") != "baseline-diff":
        raise DiffInputError("not a baseline-diff document (kind != 'baseline-diff')")
    ver = diff.get("schema_version")
    if not isinstance(ver, str) or ver.rsplit(".", 1)[0] not in READABLE_DIFF_VERSIONS:
        raise DiffInputError(f"unsupported baseline-diff schema_version: {ver!r}")
    for field_name in ("changes", "indeterminate", "domains", "warnings"):
        if not isinstance(diff.get(field_name), list):
            raise DiffInputError(f"'{field_name}' must be a list")
    for key in ("baseline", "current", "window", "findings", "summary"):
        if not isinstance(diff.get(key), dict):
            raise DiffInputError(f"'{key}' must be an object")
    for c in diff["changes"]:
        ok = (
            isinstance(c, dict)
            and c.get("change") in ("added", "removed", "modified")
            and all(isinstance(c.get(k), str) and c[k] for k in ("domain", "key"))
            and isinstance(c.get("scope", ""), str)
            and isinstance(c.get("attributes", []), list)
            and isinstance(c.get("transient", False), bool)
        )
        if not ok:
            raise DiffInputError("a change entry is malformed")
    return diff


def _detection_id(domain: str, scope: str, key: str) -> str:
    h = hashlib.sha256(f"{domain}\0{scope}\0{key}".encode()).hexdigest()
    return "DET-" + h[:10]


def _context(diff: dict[str, Any]) -> Context:
    fresh: set[str] = set()
    for c in diff["changes"]:
        if c["domain"] == "users" and c["change"] == "added":
            fresh.add(_name(c).casefold())
            n = _one(_now(c, "name"))
            if n:
                fresh.add(n.casefold())
    return Context(str(diff["current"].get("os_family", "")), frozenset(fresh))


@dataclass
class _Group:
    change: dict[str, Any]
    signals: list[Signal] = field(default_factory=list)


def _link(detections: list[dict[str, Any]], tokens: dict[str, set[str]]) -> None:
    """Connect detections that share an artifact (union-find over shared tokens)."""
    parent = {d["id"]: d["id"] for d in detections}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner: dict[str, str] = {}
    for d in detections:
        for t in sorted(tokens.get(d["id"], ())):
            if t in owner:
                parent[find(d["id"])] = find(owner[t])
            else:
                owner[t] = d["id"]
    comps: dict[str, list[str]] = {}
    for d in detections:
        comps.setdefault(find(d["id"]), []).append(d["id"])
    for d in detections:
        d["correlated"] = sorted(i for i in comps[find(d["id"])] if i != d["id"])


def _change_evidence(c: dict[str, Any]) -> list[dict[str, str]]:
    rec = c.get("current") or c.get("baseline") or {}
    out = []
    for e in rec.get("evidence") or []:
        if isinstance(e, dict) and isinstance(e.get("type"), str) and isinstance(e.get("ref"), str):
            out.append({"type": e["type"], "ref": e["ref"]})
    return out


def _state(rec: Any) -> dict[str, Any] | None:
    return dict(_attrs(rec)) if isinstance(rec, dict) else None


def detect(
    diff: dict[str, Any],
    generated_at: str,
    min_severity: Severity = Severity.INFO,
    allow: Allowlist | None = None,
) -> dict[str, Any]:
    """Apply every rule to ``diff`` and return a ``detections`` document.

    ``allow`` moves explicitly accepted detections, unchanged, into ``accepted`` (see
    ``shared.reporting.accepted``); nothing else is suppressed.
    """
    validate_diff(diff)
    ctx = _context(diff)
    groups: dict[tuple[str, str, str], _Group] = {}
    errors: list[dict[str, str]] = []
    for c in diff["changes"]:
        if c.get("transient"):
            continue
        for info in RULES:
            if c["domain"] not in info.domains:
                continue
            try:
                signals = info.func(c, ctx)
            except Exception as exc:  # noqa: BLE001 - one bad record must not hide the rest
                errors.append(
                    {"rule": info.rule_id, "key": str(c["key"]), "error": type(exc).__name__}
                )
                continue
            if signals:
                g = groups.setdefault((c["domain"], c.get("scope", ""), c["key"]), _Group(c))
                g.signals += signals

    detections: list[dict[str, Any]] = []
    tokens: dict[str, set[str]] = {}
    for (domain, scope, key), g in groups.items():
        sigs = sorted(g.signals, key=lambda s: (-int(s.severity), s.basis != OBSERVED, s.rule))
        top = sigs[0]
        c = g.change
        det_id = _detection_id(domain, scope, key)
        tokens[det_id] = {t for s in sigs for t in s.tokens}
        top_basis = (
            OBSERVED
            if any(s.basis == OBSERVED and s.severity == top.severity for s in sigs)
            else HEURISTIC
        )
        detections.append(
            {
                "id": det_id,
                "title": top.title,
                "severity": top.severity.label,
                "basis": top_basis,
                "subject": {
                    "domain": domain,
                    "scope": scope,
                    "key": key,
                    "change": c["change"],
                },
                "summary": top.observation,
                "reasons": [
                    {
                        "rule": s.rule,
                        "title": s.title,
                        "severity": s.severity.label,
                        "basis": s.basis,
                        "observation": s.observation,
                        "rationale": s.rationale,
                    }
                    for s in sigs
                ],
                "before": _state(c.get("baseline")),
                "after": _state(c.get("current")),
                "attributes": [
                    {"name": a["name"], "before": a["before"], "after": a["after"]}
                    for a in c.get("attributes") or []
                    if isinstance(a, dict) and "name" in a
                ],
                "evidence": _change_evidence(c),
                "observed": c.get("observed") or {"baseline_at": None, "current_at": None},
                "related_findings": sorted(
                    x for x in c.get("related_findings") or [] if isinstance(x, str)
                ),
                "artifacts": sorted(t for t in tokens[det_id] if not t.startswith("name:")),
                "techniques": sorted({t for s in sigs for t in s.techniques}),
                "investigation": list(dict.fromkeys(i for s in sigs for i in s.investigate)),
                "unknown": list(dict.fromkeys(u for s in sigs for u in s.unknown)),
                "correlated": [],
            }
        )
    order = {d: i for i, d in enumerate(_DOMAIN_ORDER)}
    sev_rank = {s.label: int(s) for s in Severity}
    detections.sort(
        key=lambda d: (
            -sev_rank[d["severity"]],
            order.get(d["subject"]["domain"], 99),
            d["subject"]["scope"],
            d["subject"]["key"],
        )
    )
    _link(detections, tokens)
    by_id = {d["id"]: d for d in detections}
    for d in detections:
        d["correlated"] = [
            {"id": i, "key": by_id[i]["subject"]["key"], "severity": by_id[i]["severity"]}
            for i in d["correlated"]
        ]
    accepted: list[dict[str, Any]] = []
    audit = None
    if allow is not None:
        detections, accepted, audit = apply_allowlist(detections, allow, generated_at)
    shown = [d for d in detections if sev_rank[d["severity"]] >= int(min_severity)]

    gaps = [
        {
            "domain": d["domain"],
            "scope": d["scope"],
            "status": d["status"],
            "note": d["note"],
        }
        for d in diff["domains"]
        if isinstance(d, dict) and d.get("status") != "compared"
    ]
    no_inventory = any(
        isinstance(w, dict) and w.get("code") == "NO_INVENTORY" for w in diff["warnings"]
    )
    complete = not (gaps or diff["indeterminate"] or errors or no_inventory)
    by_sev = {s.label: 0 for s in sorted(Severity, reverse=True)}
    by_basis = {OBSERVED: 0, HEURISTIC: 0}
    for d in shown:
        by_sev[d["severity"]] += 1
        by_basis[d["basis"]] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "detections",
        "generated_at": generated_at,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "baseline": diff["baseline"],
        "current": diff["current"],
        "window": diff["window"],
        "coverage": {
            "complete": complete,
            "gaps": gaps,
            "indeterminate": len(diff["indeterminate"]),
            "no_inventory": no_inventory,
            "rule_errors": errors,
            "notes": [
                "Detections are triage aids: 'observed' means the report itself shows the "
                "condition, 'heuristic' means a pattern that is often but not always malicious.",
                "Only changes between the two reports are evaluated; anything already present "
                "in the baseline is not re-reported.",
                "A clean result is not proof of integrity if coverage is incomplete or the "
                "host was compromised before the baseline.",
            ],
        },
        "detections": shown,
        "accepted": accepted,
        "allowlist": audit,
        "summary": {
            "total": len(shown),
            "accepted": len(accepted),
            "suppressed_below_min_severity": len(detections) - len(shown),
            "by_severity": by_sev,
            "by_basis": by_basis,
            "changes_evaluated": sum(1 for c in diff["changes"] if not c.get("transient")),
            "changes_without_detection": sum(1 for c in diff["changes"] if not c.get("transient"))
            - len(groups),
            "rules": len(RULES),
        },
    }


def exit_code_for(doc: dict[str, Any]) -> int:
    """4 when anything was detected, 6 when nothing was but coverage is incomplete, else 0."""
    if doc["summary"]["total"]:
        return 4
    return 0 if doc["coverage"]["complete"] else 6
