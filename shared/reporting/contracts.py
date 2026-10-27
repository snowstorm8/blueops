"""Shared contracts: schema version, severity levels, exit codes.

These values are mirrored in ``docs/contracts.md``, ``CLAUDE.md`` and the JSON
schema; ``tests/shared/test_contracts.py`` keeps them consistent.
"""

from __future__ import annotations

import enum

SCHEMA_VERSION = "0.2.0"

# Report schema versions (major.minor) that the baseline-diff engine can read.
# 0.1 reports have no ``inventory`` and are compared at findings level only.
READABLE_REPORT_VERSIONS = ("0.1", "0.2")

# Inventory record domains, in report order (see docs/baseline-diff.md).
INVENTORY_DOMAINS = (
    "users",
    "groups",
    "services",
    "processes",
    "listeners",
    "scheduled_tasks",
    "persistence",
    "config",
)

# Per-domain collection coverage, best to worst.
COVERAGE_STATUSES = ("complete", "degraded", "partial", "unavailable")


class Severity(enum.IntEnum):
    """Finding severity, ordered so that comparisons work (``HIGH > LOW``)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None


class ExitCode(enum.IntEnum):
    OK = 0
    ERROR = 1
    USAGE = 2
    PRECONDITION = 3
    FINDINGS = 4
    ABORTED = 5
    PARTIAL = 6
