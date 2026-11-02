"""Compare two assessment snapshots: findings, severity, configuration and coverage.

Output is the ``snapshot-comparison`` document (``shared/schemas/snapshot-comparison.schema.json``).
Findings are matched by their stable ``BOF-`` id. As in the baseline-diff engine, a conclusion
is drawn only from evidence that supports it:

* a finding is **resolved** only if the module that reported it ran to completion in the
  current snapshot; otherwise it is ``indeterminate`` ("not seen" is not "fixed");
* a finding is **new** only if that module ran to completion in the baseline; otherwise it is
  ``indeterminate`` ("not seen before" is not "did not exist");
* configuration changes come from the existing inventory comparison
  (``shared.reporting.baseline``), run on the assessments' merged inventories.

Nothing here reads a host: it compares two documents.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from shared.engine import ASSESSMENT_SCHEMA_VERSION, ENGINE_VERSION
from shared.engine.assessment import AssessmentError, assessment_to_report
from shared.engine.module import OK
from shared.reporting.baseline import IncompatibleReportsError
from shared.reporting.baseline import compare as compare_inventory
from shared.reporting.baseline import exit_code_for as inventory_exit_code
from shared.reporting.contracts import ExitCode, Severity
from shared.reporting.inventory import Options, ReportError, build_snapshot, parse_timestamp

TOOL_NAME = "blueops-compare"
TOOL_VERSION = ENGINE_VERSION
# Relative weights for the trend index. A convenience for "is this better or worse", not a risk
# model: it says nothing about likelihood or impact on a particular environment.
SEVERITY_WEIGHT = {"info": 0, "low": 1, "medium": 3, "high": 7, "critical": 15}
_TRUNCATED_MARK = "only the first"


class ComparisonError(ValueError):
    """The snapshots cannot be compared (different platform or host, malformed input)."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _imported(doc: dict[str, Any]) -> bool:
    return doc["assessment"]["profile"] == "imported"


def _module_status(doc: dict[str, Any]) -> dict[str, str]:
    return {m["id"]: m["status"] for m in doc["modules"]}


def _coverage_of(doc: dict[str, Any], finding: dict[str, Any]) -> tuple[bool, str]:
    """Did the collection that would have reported ``finding`` complete in ``doc``?

    Returns ``(complete, reason)``. For an imported report (no per-module breakdown) the whole
    report is the unit; in a native assessment it is the finding's own module(s).
    """
    status = _module_status(doc)
    if _imported(doc):
        ok = status.get("imported.report") == OK
        return ok, "" if ok else "the imported report has coverage gaps (exit 6)"
    wanted = [s["module"] for s in finding["sources"]]
    if any(w.startswith("imported.") for w in wanted):
        # the finding came from an imported report: which native module owns it is unknown
        bad = [m for m, s in status.items() if s != OK]
        return not bad, "" if not bad else "modules without a clean run: " + ", ".join(
            sorted(bad)[:5]
        )
    for w in wanted:
        st = status.get(w)
        if st is None:
            return False, f"module {w} was not run in this snapshot"
        if st != OK:
            return False, f"module {w} finished as {st}"
    return True, ""


def _brief(f: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f["id"],
        "check_id": f["check_id"],
        "title": f["title"],
        "severity": f["severity"],
        "confidence": f["confidence"],
        "category": f["category"],
        "component": f["component"],
        "priority": f["remediation"]["priority"],
    }


def _truncated(f: dict[str, Any]) -> bool:
    return _TRUNCATED_MARK in f["description"]


def weighted_index(doc: dict[str, Any]) -> int:
    return sum(SEVERITY_WEIGHT[f["severity"]] for f in doc["findings"])


def _check_compat(
    base: dict[str, Any], cur: dict[str, Any], allow_host_mismatch: bool
) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    bh, ch = base.get("host"), cur.get("host")
    if bh is None or ch is None:
        raise ComparisonError(
            "both snapshots need a host (at least one module must have produced a report)"
        )
    if bh["os"]["family"] != ch["os"]["family"]:
        raise ComparisonError(
            "snapshots are from different OS families "
            f"({bh['os']['family']} vs {ch['os']['family']})"
        )
    if bh["hostname"].casefold() != ch["hostname"].casefold():
        msg = f"hostnames differ ({bh['hostname']!r} vs {ch['hostname']!r})"
        if not allow_host_mismatch:
            raise ComparisonError(msg + "; pass --allow-host-mismatch to compare anyway")
        warnings.append(
            {"code": "HOST_MISMATCH", "message": msg + "; compared because it was allowed"}
        )
        warnings.append(
            {
                "code": "IDENTITY_MISMATCH",
                "message": "finding ids embed the host: findings of different hosts never match",
            }
        )
    for side, d in (("baseline", base), ("current", cur)):
        if d["host"].get("test_mode"):
            warnings.append(
                {
                    "code": "TEST_MODE",
                    "message": f"{side} was collected with fixture hooks: "
                    "it does not describe a real host",
                }
            )
    if base["assessment"]["id"] == cur["assessment"]["id"]:
        warnings.append(
            {"code": "SAME_RUN", "message": "baseline and current are the same assessment"}
        )
    if parse_timestamp(base["assessment"]["started_at"]) > parse_timestamp(
        cur["assessment"]["started_at"]
    ):
        warnings.append(
            {
                "code": "REVERSED_ORDER",
                "message": "the baseline started after the current snapshot; check argument order",
            }
        )
    if base["host"].get("elevated") is not cur["host"].get("elevated"):
        warnings.append(
            {
                "code": "PRIVILEGE_DIFFERS",
                "message": "the snapshots were collected with different privilege; some "
                "differences may reflect access, not state",
            }
        )
    return warnings


def _order(f: dict[str, Any]) -> tuple[int, str, str]:
    return (-int(Severity.parse(f["severity"])), f["category"], f["check_id"])


def _compare_findings(base: dict[str, Any], cur: dict[str, Any]) -> dict[str, Any]:
    bmap = {f["id"]: f for f in base["findings"]}
    cmap = {f["id"]: f for f in cur["findings"]}
    out: dict[str, list[dict[str, Any]]] = {
        "new": [],
        "resolved": [],
        "persistent": [],
        "severity_changed": [],
        "indeterminate": [],
    }
    for fid, f in cmap.items():
        if fid in bmap:
            continue
        ok, why = _coverage_of(base, f)
        if ok:
            out["new"].append(_brief(f))
        else:
            out["indeterminate"].append(
                {
                    **_brief(f),
                    "side": "current",
                    "reason": f"not in the baseline, but the baseline cannot show absence: {why}",
                }
            )
    for fid, f in bmap.items():
        if fid in cmap:
            continue
        ok, why = _coverage_of(cur, f)
        if ok:
            out["resolved"].append(_brief(f))
        else:
            out["indeterminate"].append(
                {
                    **_brief(f),
                    "side": "baseline",
                    "reason": f"not in the current snapshot, but it cannot show absence: {why}",
                }
            )
    for fid, cf in cmap.items():
        bf = bmap.get(fid)
        if bf is None:
            continue
        entry = _brief(cf)
        b_ev, c_ev = set(bf["evidence"]), set(cf["evidence"])
        entry["evidence"] = {
            "added": sorted(c_ev - b_ev),
            "removed": sorted(b_ev - c_ev),
            "unchanged": len(b_ev & c_ev),
            "truncated": _truncated(bf) or _truncated(cf),
        }
        bs, cs = Severity.parse(bf["severity"]), Severity.parse(cf["severity"])
        entry["baseline_severity"] = bf["severity"]
        entry["baseline_confidence"] = bf["confidence"]
        if bs != cs:
            entry["direction"] = "increased" if cs > bs else "decreased"
            out["severity_changed"].append(entry)
        out["persistent"].append(entry)
    for items in out.values():
        items.sort(key=_order)
    return out


def _compare_coverage(base: dict[str, Any], cur: dict[str, Any]) -> dict[str, Any]:
    bm, cm = _module_status(base), _module_status(cur)
    changed = [
        {"id": m, "baseline": bm[m], "current": cm[m]}
        for m in sorted(bm.keys() & cm.keys())
        if bm[m] != cm[m]
    ]

    def parts(doc: dict[str, Any]) -> dict[tuple[str, str], str]:
        return {
            (c["domain"], c.get("scope", "")): c["status"] for c in doc["inventory"]["coverage"]
        }

    bp, cp = parts(base), parts(cur)
    inv = [
        {"domain": d, "scope": s, "baseline": bp.get((d, s)), "current": cp.get((d, s))}
        for (d, s) in sorted(bp.keys() | cp.keys())
        if bp.get((d, s)) != cp.get((d, s))
    ]
    return {
        "modules": {
            "added": sorted(cm.keys() - bm.keys()),
            "removed": sorted(bm.keys() - cm.keys()),
            "changed": changed,
            "unchanged": sum(1 for m in bm.keys() & cm.keys() if bm[m] == cm[m]),
        },
        "inventory_partitions": inv,
    }


def _compare_configuration(
    base: dict[str, Any], cur: dict[str, Any], options: Options
) -> dict[str, Any]:
    """Configuration changes via the inventory comparison engine."""
    for side, d in (("baseline", base), ("current", cur)):
        if not d["inventory"]["records"] and not d["inventory"]["coverage"]:
            return {"available": False, "reason": f"the {side} snapshot has no inventory"}
    try:
        b = build_snapshot(assessment_to_report(base), options, source="baseline")
        c = build_snapshot(assessment_to_report(cur), options, source="current")
        diff = compare_inventory(b, c, options, cur["assessment"]["finished_at"])
    except (ReportError, AssessmentError, IncompatibleReportsError) as exc:
        return {"available": False, "reason": str(exc)}
    s = diff["summary"]
    return {
        "available": True,
        "summary": {
            k: s[k]
            for k in (
                "added",
                "removed",
                "modified",
                "indeterminate",
                "domains_partial",
                "domains_not_compared",
            )
        },
        "changes": diff["changes"],
        "indeterminate": diff["indeterminate"],
        "domains": diff["domains"],
        "exit_code": int(inventory_exit_code(diff)),
    }


def _trend(f: dict[str, Any], cfg: dict[str, Any], delta: int) -> str:
    if f["new"] or any(e["direction"] == "increased" for e in f["severity_changed"]):
        return "worse"
    if f["resolved"] or f["severity_changed"]:
        return "better"
    if delta > 0:
        return "worse"
    if delta < 0:
        return "better"
    if f["indeterminate"] or (cfg["available"] and cfg["summary"]["indeterminate"]):
        return "indeterminate"
    return "unchanged"


def compare_snapshots(
    base: dict[str, Any],
    cur: dict[str, Any],
    *,
    generated_at: str | None = None,
    allow_host_mismatch: bool = False,
    options: Options | None = None,
) -> dict[str, Any]:
    """Compare two assessment documents (as returned by ``load_assessment``)."""
    opts = options or Options(allow_host_mismatch=allow_host_mismatch)
    warnings = _check_compat(base, cur, allow_host_mismatch)
    for side, d in (("baseline", base), ("current", cur)):
        if d["host"].get("elevated") is None:
            warnings.append(
                {
                    "code": "PRIVILEGE_UNKNOWN",
                    "message": f"privilege of the {side} collection is unknown",
                }
            )
    findings = _compare_findings(base, cur)
    coverage = _compare_coverage(base, cur)
    config = _compare_configuration(base, cur, opts)
    bi, ci = weighted_index(base), weighted_index(cur)
    cfg_changed = (
        config["summary"]["added"] + config["summary"]["removed"] + config["summary"]["modified"]
        if config["available"]
        else 0
    )
    summary = {
        "findings_baseline": len(base["findings"]),
        "findings_current": len(cur["findings"]),
        "new": len(findings["new"]),
        "resolved": len(findings["resolved"]),
        "persistent": len(findings["persistent"]),
        "severity_increased": sum(
            1 for e in findings["severity_changed"] if e["direction"] == "increased"
        ),
        "severity_decreased": sum(
            1 for e in findings["severity_changed"] if e["direction"] == "decreased"
        ),
        "indeterminate": len(findings["indeterminate"]),
        "configuration_changes": cfg_changed,
        "coverage_changes": len(coverage["modules"]["added"])
        + len(coverage["modules"]["removed"])
        + len(coverage["modules"]["changed"]),
        "weighted_index": {"baseline": bi, "current": ci, "delta": ci - bi},
        "trend": _trend(findings, config, ci - bi),
    }
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "kind": "snapshot-comparison",
        "generated_at": generated_at or _now(),
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "baseline": _meta(base),
        "current": _meta(cur),
        "warnings": warnings,
        "findings": findings,
        "configuration": config,
        "coverage": coverage,
        "summary": summary,
    }


def _meta(doc: dict[str, Any]) -> dict[str, Any]:
    a = doc["assessment"]
    return {
        "assessment_id": a["id"],
        "profile": a["profile"],
        "started_at": a["started_at"],
        "finished_at": a["finished_at"],
        "hostname": doc["host"]["hostname"],
        "os_family": doc["host"]["os"]["family"],
        "status": a["status"],
        "exit_code": a["exit_code"],
        "modules": len(doc["modules"]),
    }


def comparison_exit_code(cmp: dict[str, Any]) -> ExitCode:
    """4 when anything differs (as in ``shared.reporting.diff``), 6 when nothing differs but the
    comparison is incomplete, otherwise 0."""
    s = cmp["summary"]
    if (
        s["new"]
        or s["resolved"]
        or s["severity_increased"]
        or s["severity_decreased"]
        or s["configuration_changes"]
    ):
        return ExitCode.FINDINGS
    cfg = cmp["configuration"]
    incomplete = s["indeterminate"] or s["coverage_changes"] or not cfg["available"]
    if cfg["available"]:
        incomplete = (
            incomplete or cfg["summary"]["indeterminate"] or cfg["summary"]["domains_partial"]
        )
    if incomplete:
        return ExitCode.PARTIAL
    return ExitCode.OK


def finding_coverage(doc: dict[str, Any], finding: dict[str, Any]) -> tuple[bool, str]:
    """Public form of the coverage test used for new/resolved conclusions (see module docs)."""
    return _coverage_of(doc, finding)
