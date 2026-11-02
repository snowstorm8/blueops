"""Run a set of modules and assemble the assessment document.

The assessment is a *derived, central view*: it never replaces the per-module reports, which are
kept untouched under ``modules/<id>/`` and hashed in the assessment manifest. Findings are
re-identified (stable ``BOF-`` ids), deduplicated and cross-linked to evidence with provenance.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.engine import ASSESSMENT_SCHEMA_VERSION, ENGINE_NAME, ENGINE_VERSION
from shared.engine.module import (
    FAILED,
    INVALID_OUTPUT,
    OK,
    PARTIAL,
    SKIPPED,
    STATUSES,
    TIMEOUT,
    USABLE,
    ModuleResult,
    ModuleSpec,
)
from shared.engine.registry import Registry
from shared.engine.runner import RunContext, run_module
from shared.findings.model import FindingStore, clean
from shared.reporting.contracts import COVERAGE_STATUSES, SCHEMA_VERSION, ExitCode, Severity

_SEVERITIES = ("info", "low", "medium", "high", "critical")
_MAX_ERRORS = 500


class AssessmentError(ValueError):
    """The assessment could not be set up (bad selection, unwritable output directory)."""


@dataclass
class Assessment:
    document: dict[str, Any]
    directory: Path
    exit_code: ExitCode
    results: list[ModuleResult] = field(default_factory=list)


def make_assessment_dir(parent: Path, stamp: str, profile: str) -> Path:
    """Create ``blueops-assessment-<stamp>-<profile>`` (mode 0700), never reusing a directory."""
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    base = f"blueops-assessment-{stamp}-{profile}"
    for n in range(100):
        path = parent / (base if n == 0 else f"{base}-{n}")
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            continue
        except OSError as exc:
            raise AssessmentError(f"cannot create {path}: {exc.strerror or exc}") from None
        return path
    raise AssessmentError(f"too many assessment directories named {base}")


def _worst(a: str, b: str) -> str:
    return a if COVERAGE_STATUSES.index(a) >= COVERAGE_STATUSES.index(b) else b


def _merge_inventory(  # noqa: PLR0912 - one pass over coverage and records
    results: list[ModuleResult], specs: dict[str, ModuleSpec], warnings: list[dict[str, str]]
) -> dict[str, Any]:
    cov: dict[tuple[str, str], dict[str, Any]] = {}
    records: dict[tuple[str, str, str], dict[str, Any]] = {}
    for res in results:
        if res.status not in USABLE or res.report is None:
            continue
        inv = res.report.get("inventory")
        if not isinstance(inv, dict):
            continue
        for c in inv.get("coverage", []):
            key = (c["domain"], c.get("scope", ""))
            if key in cov:
                cov[key]["status"] = _worst(cov[key]["status"], c["status"])
                if c.get("reason") and c["reason"] not in cov[key].get("reason", ""):
                    cov[key]["reason"] = "; ".join(
                        x for x in (cov[key].get("reason"), c["reason"]) if x
                    )
            else:
                cov[key] = dict(c)
        for r in inv.get("records", []):
            rkey = (r["domain"], r.get("scope", ""), r["key"])
            if rkey in records:
                if records[rkey]["attrs"] != r["attrs"]:
                    warnings.append(
                        {
                            "code": "INVENTORY_CONFLICT",
                            "message": f"two modules reported {r['domain']} record "
                            f"{r['key'][:80]!r} "
                            "with different attributes; the first was kept",
                        }
                    )
                continue
            records[rkey] = r
    # A module that produced nothing leaves its partitions explicitly *unavailable*, so a later
    # comparison can never read their emptiness as "everything was removed".
    for res in results:
        if res.status in USABLE:
            continue
        for part in specs[res.module].provides:
            domain, _, scope = part.partition(":")
            cov.setdefault(
                (domain, scope),
                {
                    "domain": domain,
                    **({"scope": scope} if scope else {}),
                    "status": "unavailable",
                    "reason": clean(f"module {res.module} {res.status}: {res.reason}", 300),
                },
            )
    return {
        "coverage": [cov[k] for k in sorted(cov)],
        "records": [records[k] for k in sorted(records)],
    }


def _host_block(
    results: list[ModuleResult], warnings: list[dict[str, str]]
) -> dict[str, Any] | None:
    host: dict[str, Any] | None = None
    elevated: list[bool] = []
    test_mode = False
    for res in results:
        if res.status not in USABLE or res.report is None:
            continue
        h = res.report["host"]
        if host is None:
            host = {
                "hostname": clean(h["hostname"], 255),
                "os": {k: clean(h["os"][k], 120) for k in ("family", "name", "version")},
                "arch": clean(h.get("arch", ""), 64),
            }
            if "user" in h:
                host["user"] = clean(h["user"], 120)
        elif h["hostname"].casefold() != host["hostname"].casefold():
            warnings.append(
                {
                    "code": "HOST_MISMATCH",
                    "message": f"module {res.module} reported host {clean(h['hostname'], 80)!r}, "
                    f"expected {host['hostname']!r}; its findings are attributed to the first host",
                }
            )
        if isinstance(h.get("elevated"), bool):
            elevated.append(h["elevated"])
        test_mode = test_mode or h.get("test_mode") is True
    if host is None:
        return None
    if elevated:
        host["elevated"] = all(elevated)
    if test_mode:
        host["test_mode"] = True
    return host


def _summary(
    findings: list[dict[str, Any]], evidence_count: int, results: list[ModuleResult]
) -> dict[str, Any]:
    by_sev = dict.fromkeys(_SEVERITIES, 0)
    by_conf = {"low": 0, "medium": 0, "high": 0}
    by_cat: dict[str, int] = {}
    prio = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for f in findings:
        by_sev[f["severity"]] += 1
        by_conf[f["confidence"]] += 1
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
        prio[f["remediation"]["priority"]] += 1
    mods = dict.fromkeys(STATUSES, 0)
    for r in results:
        mods[r.status] += 1
    return {
        "total": len(findings),
        "by_severity": by_sev,
        "by_confidence": by_conf,
        "by_category": dict(sorted(by_cat.items())),
        "by_priority": prio,
        "evidence_items": evidence_count,
        "modules": mods,
    }


def decide_exit_code(
    findings: list[dict[str, Any]], results: list[ModuleResult], fail_on: str
) -> ExitCode:
    """4 beats 6 (``docs/contracts.md``): findings at/above the threshold win over coverage gaps."""
    usable = [r for r in results if r.status in USABLE]
    if not usable:
        if results and all(r.status == SKIPPED for r in results):
            return ExitCode.PRECONDITION
        return ExitCode.ERROR
    threshold = Severity.parse(fail_on)
    if any(Severity.parse(f["severity"]) >= threshold for f in findings):
        return ExitCode.FINDINGS
    if any(r.status != OK for r in results):
        return ExitCode.PARTIAL
    return ExitCode.OK


def run_assessment(  # noqa: PLR0912, PLR0913 - assembling the document is one linear sequence
    registry: Registry,
    selected: list[str],
    ctx: RunContext,
    *,
    profile_name: str,
    fail_on: str = "medium",
    assessment_id: str | None = None,
) -> Assessment:
    """Execute ``selected`` (dependencies added, in order) and build the assessment document.

    ``ctx.out_root`` must already exist (see ``make_assessment_dir``).
    """
    plan = registry.plan(selected)
    specs = {s.id: s for s in plan}
    started = ctx.clock()
    results: list[ModuleResult] = []
    by_id: dict[str, ModuleResult] = {}
    for spec in plan:
        blocked = [d for d in spec.requires if by_id[d].status not in USABLE]
        if blocked:
            res = ModuleResult(
                module=spec.id,
                status=SKIPPED,
                reason=f"dependency not satisfied: {', '.join(blocked)}",
                started_at=ctx.clock(),
                finished_at=ctx.clock(),
            )
        else:
            res = run_module(spec, ctx)
        results.append(res)
        by_id[spec.id] = res

    warnings: list[dict[str, str]] = []
    store = FindingStore()
    errors: list[dict[str, Any]] = []
    for res in results:
        if res.status in USABLE and res.report is not None:
            report_started = res.report["run"]["started_at"]
            res.findings_count = store.add_report(
                res.report, res.module, report_started, res.report_sha256
            )
            for e in res.errors:
                errors.append({"module": res.module, **e})
        elif res.status != OK:
            errors.append(
                {
                    "module": res.module,
                    "code": "MODULE_" + res.status.upper(),
                    "message": clean(res.reason or res.status, 500),
                }
            )
    for rej in store.rejected:
        errors.append(
            {
                "module": "engine",
                "code": "FINDING_REJECTED",
                "message": clean(f"finding {rej['check_id']}: {rej['reason']}", 500),
            }
        )
    host = _host_block(results, warnings)
    findings = [f.to_json() for f in store.sorted_findings()]
    evidence = [e.to_json() for e in store.sorted_evidence()]
    finished = ctx.clock()
    code = decide_exit_code(findings, results, fail_on)
    if len(errors) > _MAX_ERRORS:
        warnings.append(
            {
                "code": "ERRORS_TRUNCATED",
                "message": f"{len(errors)} errors; first {_MAX_ERRORS} kept",
            }
        )
        errors = errors[:_MAX_ERRORS]
    if any(r.status in (FAILED, TIMEOUT, INVALID_OUTPUT) for r in results):
        status = "partial" if any(r.status in USABLE for r in results) else "failed"
    elif any(r.status in (PARTIAL, SKIPPED) for r in results):
        status = "partial"
    else:
        status = "complete"
    doc: dict[str, Any] = {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "kind": "assessment",
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        "assessment": {
            "id": assessment_id or str(uuid.uuid4()),
            "profile": profile_name,
            "platform": ctx.platform_name,
            "started_at": started,
            "finished_at": finished,
            "mode": "read-only",
            "fail_on": fail_on,
            "status": status,
            "exit_code": int(code),
            "modules": [s.id for s in plan],
        },
        "modules": [r.to_json() for r in results],
        "findings": findings,
        "evidence": evidence,
        "inventory": _merge_inventory(results, specs, warnings),
        "errors": errors,
        "warnings": warnings,
        "summary": _summary(findings, len(evidence), results),
    }
    if host is not None:
        doc["host"] = host
    return Assessment(doc, ctx.out_root, code, results)


def assessment_to_report(doc: dict[str, Any]) -> dict[str, Any]:
    """Project an assessment onto the ``audit-report`` shape (schema 0.2.0).

    This lets the existing baseline/detection engines (which read audit reports) work on an
    assessment without modification. Only fields the report schema defines are produced.
    """
    a = doc["assessment"]
    host = doc.get("host")
    if host is None:
        raise AssessmentError("assessment has no host (no module produced a usable report)")
    evidence = {e["id"]: e for e in doc["evidence"]}
    findings = []
    for f in doc["findings"]:
        item: dict[str, Any] = {
            "id": f["check_id"],
            "title": f["title"],
            "severity": f["severity"],
            "confidence": f["confidence"],
            "category": f["category"],
            "description": f["description"],
        }
        ev = []
        for eid in f["evidence"]:
            e = evidence.get(eid)
            if e is None:
                continue
            ent: dict[str, Any] = {"type": e["type"], "ref": e["ref"]}
            if e.get("sha256"):
                ent["sha256"] = e["sha256"]
            if e.get("excerpts"):
                ent["excerpt"] = e["excerpts"][0][:2000]
            ev.append(ent)
        if ev:
            item["evidence"] = ev
        if f["remediation"]["summary"]:
            item["remediation"] = f["remediation"]["summary"]
        mitre = [s["id"] for s in f["standards"] if s["framework"] == "MITRE ATT&CK"]
        if mitre:
            item["mitre_attack"] = mitre
        findings.append(item)
    h: dict[str, Any] = {
        "hostname": host["hostname"],
        "os": dict(host["os"]),
        "arch": host.get("arch", ""),
    }
    for k in ("user", "elevated", "test_mode"):
        if k in host:
            h[k] = host[k]
    errors = [
        {
            "code": e["code"],
            "message": e["message"],
            **({"check_id": e["check_id"]} if "check_id" in e else {}),
        }
        for e in doc["errors"]
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": "blueops-assessment",
            "version": doc["engine"]["version"],
            "category": "audit",
        },
        "run": {
            "id": a["id"],
            "started_at": a["started_at"],
            "finished_at": a["finished_at"],
            "mode": "read-only",
            "dry_run": False,
            "exit_code": a["exit_code"],
        },
        "host": h,
        "findings": findings,
        "errors": errors,
        "inventory": doc["inventory"],
        "summary": {
            "total": len(findings),
            "by_severity": dict(doc["summary"]["by_severity"]),
        },
    }


def assessment_from_report(report: dict[str, Any], report_sha256: str = "") -> dict[str, Any]:
    """Wrap a schema-valid ``audit-report`` (0.1/0.2) as an assessment document.

    Lets older baselines, and reports produced by running a collector by hand, take part in
    snapshot comparison and rendering. The whole report counts as one pseudo-module
    ``imported.report`` (the per-module breakdown is not recoverable from a report), and the
    assessment is marked ``profile: "imported"``.
    """
    host = report["host"]
    run = report["run"]
    store = FindingStore()
    store.add_report(report, "imported.report", run["started_at"], report_sha256 or None)
    findings = [f.to_json() for f in store.sorted_findings()]
    evidence = [e.to_json() for e in store.sorted_evidence()]
    exit_code = int(run["exit_code"])
    status = PARTIAL if exit_code == int(ExitCode.PARTIAL) else OK
    res = ModuleResult(
        module="imported.report",
        status=status,
        started_at=run["started_at"],
        finished_at=run["finished_at"],
        exit_code=exit_code,
        findings_count=len(findings),
        reason="imported from an audit report"
        + ("; the collector reported gaps" if status == PARTIAL else ""),
    )
    if report_sha256:
        res.report_path, res.report_sha256 = "(imported)", report_sha256
    errors = [
        {
            "module": "imported.report",
            **{k: v for k, v in e.items() if k in ("code", "message", "check_id")},
        }
        for e in report.get("errors", [])
    ]
    h: dict[str, Any] = {
        "hostname": clean(host["hostname"], 255),
        "os": {k: clean(host["os"][k], 120) for k in ("family", "name", "version")},
        "arch": clean(host.get("arch", ""), 64),
    }
    for k in ("user", "elevated", "test_mode"):
        if k in host:
            h[k] = host[k]
    inv = report.get("inventory") or {"coverage": [], "records": []}
    doc: dict[str, Any] = {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "kind": "assessment",
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        "assessment": {
            "id": clean(run["id"], 128),
            "profile": "imported",
            "platform": host["os"]["family"],
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "mode": "read-only",
            "fail_on": "medium",
            "status": "partial" if status == PARTIAL else "complete",
            "exit_code": exit_code,
            "modules": ["imported.report"],
        },
        "host": h,
        "modules": [res.to_json()],
        "findings": findings,
        "evidence": evidence,
        "inventory": {
            "coverage": list(inv.get("coverage", [])),
            "records": list(inv.get("records", [])),
        },
        "errors": errors,
        "warnings": [],
        "summary": _summary(findings, len(evidence), [res]),
    }
    if "inventory" not in report:
        doc["warnings"].append(
            {
                "code": "NO_INVENTORY",
                "message": "the imported report has no inventory (schema 0.1.0)",
            }
        )
    return doc
