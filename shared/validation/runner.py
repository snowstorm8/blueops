"""Run scenarios and assemble the ``validation-results`` document.

This module only evaluates datasets (``mode: synthetic`` or ``recorded``): it never touches the
host. Live execution is ``shared.validation.lab`` and is gated separately.
"""

from __future__ import annotations

import platform as _platform
import subprocess  # noqa: S404 - a fixed argv to read the commit id, never a shell
import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.reporting.schema_lite import validate
from shared.rules import RULES_ENGINE_VERSION, RULES_SCHEMA_VERSION
from shared.rules.loader import RuleSet, load_rule_set
from shared.rules.subjects import TELEMETRY_SOURCES
from shared.telemetry.model import TELEMETRY_SCHEMA_VERSION
from shared.validation import metrics as M
from shared.validation.evaluate import DEFAULT_STAMP, evaluate_scenario
from shared.validation.model import (
    VALIDATION_SCHEMA_VERSION,
    Scenario,
    ScenarioSet,
    canonical_sha256,
)

DISCLAIMER = (
    "These results describe how the detection rules behave on the scenario library. The scenarios "
    "are synthetic or lab-generated, small in number and written by the same project; a high score "
    "is a statement about rule logic and a guard against regressions, not a measurement of "
    "detection accuracy on real endpoints."
)


class ValidationError(ValueError):
    """The run cannot be set up (bad rules, schema problems); the message says why."""


def telemetry_rule_set(
    extra: list[str | Path] | None = None, *, include_library: bool = True
) -> RuleSet:
    """Rules that read only telemetry (what a telemetry scenario can exercise)."""
    rs = load_rule_set(extra, include_library=include_library)
    if rs.errors:
        raise ValidationError("rule pack errors: " + "; ".join(str(d) for d in rs.errors[:3]))
    return rs.only(lambda r: bool(r.sources) and r.sources <= set(TELEMETRY_SOURCES))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def host_info() -> dict[str, str]:
    """Where the evaluation ran: no hostname, no user (nothing identifying leaves the host)."""
    family = "windows" if sys.platform.startswith("win") else sys.platform
    return {
        "family": family,
        "system": _platform.system(),
        "release": _platform.release()[:60],
        "machine": _platform.machine(),
        "python": _platform.python_version(),
    }


def _git_commit(root: Path) -> str:
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv
            ["git", "-C", str(root), "rev-parse", "HEAD"],  # noqa: S607 - resolved by PATH, read-only
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    sha = out.stdout.strip()
    return sha if out.returncode == 0 and len(sha) == 40 else ""


def reproducibility(
    ss: ScenarioSet, rule_set: RuleSet, scenarios: list[dict[str, Any]], command: str
) -> dict[str, Any]:
    from shared.engine import ENGINE_VERSION  # noqa: PLC0415 - avoid an import cycle at load

    rules = [
        {"id": r.id, "version": r.version, "sha256": canonical_sha256(r.raw), "pack": r.pack}
        for r in rule_set.ordered()
    ]
    core = {
        "scenarios": [(s["id"], s["sha256"], s["status"], s["outcomes"]) for s in scenarios],
        "rules": [(r["id"], r["version"], r["sha256"]) for r in rules],
    }
    return {
        "digest": canonical_sha256(core),
        "scenario_packs": ss.packs,
        "rule_packs": rule_set.packs,
        "rules": rules,
        "versions": {
            "validation_schema": VALIDATION_SCHEMA_VERSION,
            "telemetry_schema": TELEMETRY_SCHEMA_VERSION,
            "rules_schema": RULES_SCHEMA_VERSION,
            "rules_engine": RULES_ENGINE_VERSION,
            "engine": ENGINE_VERSION,
            "python": _platform.python_version(),
        },
        "git_commit": _git_commit(Path(__file__).resolve().parents[2]),
        "command": command[:1000],
    }


def assemble(
    scenarios: list[dict[str, Any]],
    ss: ScenarioSet,
    rule_set: RuleSet,
    *,
    mode: str,
    started_at: str,
    command: str = "",
    dry_run: bool = False,
    isolation: dict[str, Any] | None = None,
    recommend: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    outcomes = [o for s in scenarios for o in s["outcomes"]]
    in_scope = sorted(rule_set.rules)
    cov = M.rule_coverage(in_scope, scenarios)
    by_status: dict[str, int] = {}
    for s in scenarios:
        by_status[s["status"]] = by_status.get(s["status"], 0) + 1
    failures = [
        {
            "scenario": s["id"],
            "status": s["status"],
            "reason": s["reason"],
            "known": s["status"] == "known_issue",
            "platforms": s["platforms"],
        }
        for s in scenarios
        if s["status"] != "pass"
    ]
    hard = by_status.get("fail", 0)
    soft = (
        by_status.get("error", 0) + by_status.get("inconclusive", 0) + by_status.get("skipped", 0)
    )
    exit_status = "failures" if hard else ("incomplete" if soft else "ok")
    repro = reproducibility(ss, rule_set, scenarios, command)
    doc: dict[str, Any] = {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "kind": "validation-results",
        "generated_at": utc_now(),
        "run": {
            "id": f"run-{started_at.replace('-', '').replace(':', '')}-{repro['digest'][:8]}",
            "mode": mode,
            "dry_run": dry_run,
            "started_at": started_at,
            "finished_at": utc_now(),
            "host": host_info(),
            **({"isolation": isolation} if isolation else {}),
            "command": command[:1000],
        },
        "reproducibility": repro,
        "scenarios": scenarios,
        "metrics": {
            "global": M.compute(outcomes),
            "by_platform": M.by_key(outcomes, "platform"),
            "by_rule": M.by_key(outcomes, "rule"),
            "by_kind": M.by_key(outcomes, "kind"),
            "explanations": M.EXPLANATIONS,
        },
        "coverage": cov,
        "failures": failures,
        "recommendations": [],
        "summary": {
            "scenarios": len(scenarios),
            "by_status": dict(sorted(by_status.items())),
            "exit_status": exit_status,
            "synthetic_only": mode != "live",
            "disclaimer": DISCLAIMER,
        },
    }
    if recommend is not None:
        doc["recommendations"] = recommend(doc)
    problems = validate(doc, "validation-results.schema.json", limit=5)
    if problems:  # a bug here, never the input
        raise ValidationError(
            "internal error: results violate their schema: " + "; ".join(problems)
        )
    return doc


def run_scenarios(
    scenarios: list[Scenario],
    ss: ScenarioSet,
    rule_set: RuleSet,
    *,
    mode: str = "synthetic",
    command: str = "",
    recommend: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None,
    stamp: str = DEFAULT_STAMP,
) -> dict[str, Any]:
    """Evaluate datasets with the real detection engine. Deterministic for fixed inputs."""
    started = utc_now()
    results = [evaluate_scenario(s, rule_set, generated_at=stamp) for s in scenarios]
    return assemble(
        results, ss, rule_set, mode=mode, started_at=started, command=command, recommend=recommend
    )
