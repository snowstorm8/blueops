"""Module metadata, execution results and status vocabulary."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MODULE_ID_RE = re.compile(r"^[a-z][a-z0-9]*\.[a-z][a-z0-9_-]{0,47}$")
PLATFORMS = ("linux", "windows", "any")
CATEGORIES = ("audit", "persistence")
PRIVILEGES = ("none", "recommended", "required")
OUTPUT_MODES = ("run-dir", "stdout")
DEFAULT_TIMEOUT = 600
MAX_TIMEOUT = 24 * 3600

# Module execution statuses.
OK = "ok"  # exit 0/4 and a valid report
PARTIAL = "partial"  # exit 6 and a valid report: results exist but coverage has gaps
FAILED = "failed"  # no usable result (crash, usage error, unexpected exit code)
TIMEOUT = "timeout"  # killed after the module's time limit
INVALID_OUTPUT = "invalid_output"  # ran, but the report broke the schema or was unreadable
SKIPPED = "skipped"  # not run: wrong platform, missing interpreter, failed dependency
STATUSES = (OK, PARTIAL, FAILED, TIMEOUT, INVALID_OUTPUT, SKIPPED)
USABLE = (OK, PARTIAL)  # statuses whose findings and inventory are ingested


class ModuleError(ValueError):
    """A module definition or selection is invalid."""


@dataclass(frozen=True)
class ModuleSpec:
    """Static description of an assessment module.

    ``argv`` is a template: each element may contain ``{repo}``, ``{plugin_dir}``,
    ``{output_dir}``, ``{powershell}`` and ``{module}``. It is never passed through a shell.
    ``option_flags`` maps a profile option to extra argv elements (``{value}`` is replaced).
    ``provides`` lists the inventory partitions (``domain:scope``) the module owns, so that a
    module that did not run is reported as *unavailable coverage* rather than silently absent.
    """

    id: str
    title: str
    platform: str
    category: str
    argv: tuple[str, ...]
    description: str = ""
    version: str = "1.0.0"
    requires: tuple[str, ...] = ()
    provides: tuple[str, ...] = ()
    timeout_seconds: int = DEFAULT_TIMEOUT
    privilege: str = "recommended"
    output: str = "run-dir"
    option_flags: dict[str, tuple[str, ...]] = field(default_factory=dict)
    source: str = "builtin"
    plugin_dir: str = ""

    def validate(self) -> None:
        if not MODULE_ID_RE.match(self.id):
            raise ModuleError(f"invalid module id {self.id!r} (expected e.g. 'linux.users')")
        if self.platform not in PLATFORMS:
            raise ModuleError(f"{self.id}: platform must be one of {', '.join(PLATFORMS)}")
        if self.platform != "any" and not self.id.startswith(self.platform + "."):
            raise ModuleError(
                f"{self.id}: a {self.platform} module id must start with '{self.platform}.'"
            )
        if self.category not in CATEGORIES:
            raise ModuleError(f"{self.id}: category must be one of {', '.join(CATEGORIES)}")
        if self.privilege not in PRIVILEGES:
            raise ModuleError(f"{self.id}: privilege must be one of {', '.join(PRIVILEGES)}")
        if self.output not in OUTPUT_MODES:
            raise ModuleError(f"{self.id}: output must be one of {', '.join(OUTPUT_MODES)}")
        if not 1 <= self.timeout_seconds <= MAX_TIMEOUT:
            raise ModuleError(f"{self.id}: timeout_seconds must be between 1 and {MAX_TIMEOUT}")
        if not self.argv or not all(isinstance(a, str) and a for a in self.argv):
            raise ModuleError(f"{self.id}: command must be a non-empty list of non-empty strings")
        for dep in self.requires:
            if not MODULE_ID_RE.match(dep):
                raise ModuleError(f"{self.id}: invalid dependency id {dep!r}")
            if dep == self.id:
                raise ModuleError(f"{self.id}: a module cannot require itself")

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "version": self.version,
            "platform": self.platform,
            "category": self.category,
            "requires": list(self.requires),
            "provides": list(self.provides),
            "timeout_seconds": self.timeout_seconds,
            "privilege": self.privilege,
            "source": self.source,
        }


@dataclass
class ModuleResult:
    """Outcome of one module execution. ``report`` is only set for usable statuses."""

    module: str
    status: str
    reason: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0
    exit_code: int | None = None
    command: list[str] = field(default_factory=list)
    report: dict[str, Any] | None = None
    report_path: str = ""  # relative to the assessment directory
    report_sha256: str = ""
    errors: list[dict[str, Any]] = field(default_factory=list)
    findings_count: int = 0
    stderr_tail: str = ""

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.module,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "findings": self.findings_count,
        }
        if self.reason:
            out["reason"] = self.reason
        if self.exit_code is not None:
            out["exit_code"] = self.exit_code
        if self.command:
            out["command"] = list(self.command)
        if self.report_path:
            out["report"] = {"path": self.report_path, "sha256": self.report_sha256}
        if self.errors:
            out["errors"] = list(self.errors)
        if self.stderr_tail:
            out["stderr_tail"] = self.stderr_tail
        return out
