"""Rule model: parsed, validated and compiled rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from shared.rules.conditions import Node


@dataclass(frozen=True)
class Clause:
    id: str
    source: str
    description: str
    where: Node
    where_json: dict[str, Any]
    optional: bool = False
    min_matches: int = 1
    distinct: tuple[str, int] | None = None
    join_on: str | None = None


@dataclass(frozen=True)
class Adjust:
    when: Any  # expression over clause ids (raw JSON, evaluated by engine.eval_expr)
    value: str
    reason: str


@dataclass(frozen=True)
class Rule:
    id: str
    version: str
    name: str
    description: str
    enabled: bool
    platforms: tuple[str, ...]
    category: str
    severity: str
    severity_reason: str
    severity_rules: tuple[Adjust, ...]
    confidence: str
    confidence_reason: str
    confidence_rules: tuple[Adjust, ...]
    nature: str
    requires_coverage: tuple[str, ...]
    clauses: tuple[Clause, ...]
    require: Any
    join_on: str | None
    join_mode: str
    title: str
    rationale: str
    false_positives: tuple[str, ...]
    confidence_boosters: tuple[str, ...]
    investigation: tuple[str, ...]
    remediation: str
    references: dict[str, Any]
    examples: tuple[dict[str, Any], ...]
    pack: str = ""
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def sources(self) -> frozenset[str]:
        return frozenset(c.source for c in self.clauses)

    def clause(self, cid: str) -> Clause:
        for c in self.clauses:
            if c.id == cid:
                return c
        raise KeyError(cid)

    def applies_to(self, family: str) -> bool:
        return "any" in self.platforms or family in self.platforms

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id, "version": self.version, "name": self.name, "enabled": self.enabled,
            "platforms": list(self.platforms), "category": self.category, "severity": self.severity,
            "confidence": self.confidence, "nature": self.nature, "pack": self.pack,
        }  # fmt: skip
