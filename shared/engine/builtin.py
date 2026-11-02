"""Built-in modules: one per module of the Linux and Windows collectors.

Each module is one invocation of the platform collector with ``--modules <name>``, so a crash or
timeout in one module cannot affect another, and each has its own time limit. The tables below
are checked against ``linux/lib/common.sh`` and ``windows/lib/Common.ps1`` by
``tests/shared/test_engine_registry.py``: adding a collector module without registering it here
fails the test suite.
"""

from __future__ import annotations

from shared.engine.module import ModuleSpec

_LINUX_CMD = (
    "{repo}/linux/audit/audit-linux.sh",
    "--modules",
    "{module}",
    "--json",
    "--quiet",
    "--no-color",
    "--output-dir",
    "{output_dir}",
)
_WIN_CMD = (
    "{powershell}",
    "-NoProfile",
    "-NonInteractive",
    "-File",
    "{repo}/windows/audit/Invoke-WindowsAudit.ps1",
    "-Modules",
    "{module}",
    "-Json",
    "-Quiet",
    "-OutputDir",
    "{output_dir}",
)

# name -> (title, category, inventory partitions it owns, privilege)
_LINUX = {
    "system": ("System", "audit", ("config:kmod",), "recommended"),
    "users": (
        "Users, groups and access",
        "audit",
        ("users:", "groups:", "persistence:ssh-authkeys", "config:sudoers"),
        "recommended",
    ),
    "pam": ("PAM", "audit", ("config:pam",), "recommended"),
    "processes": ("Processes", "audit", ("processes:",), "recommended"),
    "network": (
        "Network",
        "audit",
        (
            "listeners:",
            "config:dns",
            "config:hosts",
            "config:sysctl",
            "config:sshd",
            "config:firewall",
        ),
        "recommended",
    ),
    "services": ("Services", "audit", ("services:",), "recommended"),
    "persistence": (
        "Persistence",
        "persistence",
        (
            "persistence:systemd",
            "persistence:startup",
            "persistence:udev",
            "persistence:apt",
            "persistence:shell",
            "persistence:autostart",
            "persistence:auditd",
            "scheduled_tasks:cron",
            "scheduled_tasks:at",
        ),
        "recommended",
    ),
    "filesystem": ("Filesystem", "audit", ("config:suid",), "recommended"),
}
_WINDOWS = {
    "system": ("System", "audit", (), "recommended"),
    "users": ("Users and groups", "audit", ("users:", "groups:"), "recommended"),
    "processes": ("Processes", "audit", ("processes:",), "recommended"),
    "network": ("Network", "audit", ("listeners:", "config:network"), "recommended"),
    "services": ("Services", "audit", ("services:",), "recommended"),
    "tasks": ("Scheduled tasks", "audit", ("scheduled_tasks:tasks",), "recommended"),
    "autoruns": ("Autoruns", "persistence", ("persistence:autoruns",), "recommended"),
    "persistence": ("Persistence", "persistence", ("persistence:registry",), "recommended"),
    "firewall": ("Windows Firewall", "audit", ("config:firewall",), "recommended"),
    "security": ("Security configuration", "audit", ("config:security",), "recommended"),
    "filesystem": ("Filesystem", "audit", (), "recommended"),
}

# Profile options a collector understands; anything else in a profile is rejected.
LINUX_FLAGS = {
    "package_integrity": ("--package-integrity",),
    "recent_days": ("--recent-days", "{value}"),
}
WINDOWS_FLAGS = {
    "recent_days": ("-RecentDays", "{value}"),
}


def _build(platform: str, table: dict, cmd: tuple[str, ...], flags: dict) -> list[ModuleSpec]:
    specs = []
    for name, (title, category, provides, privilege) in table.items():
        specs.append(
            ModuleSpec(
                id=f"{platform}.{name}",
                title=title,
                description=f"{title} module of the {platform.capitalize()} audit collector.",
                platform=platform,
                category=category,
                argv=cmd,
                provides=provides,
                privilege=privilege,
                option_flags=dict(flags),
            )
        )
    return specs


def builtin_modules() -> list[ModuleSpec]:
    return _build("linux", _LINUX, _LINUX_CMD, LINUX_FLAGS) + _build(
        "windows", _WINDOWS, _WIN_CMD, WINDOWS_FLAGS
    )


def collector_module_name(spec_id: str) -> str:
    """``linux.users`` -> ``users`` (the name the collector's ``--modules`` option takes)."""
    return spec_id.split(".", 1)[1]
