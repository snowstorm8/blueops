"""Offline baseline comparison of two BlueOps audit reports.

``compare`` takes two canonical snapshots (see ``inventory``) and returns the diff report
as plain data. It never touches the network or the hosts the reports describe.

Conclusions are only drawn from evidence that supports them:

* a record is **removed** only if the current collection of its domain was complete;
* a record is **added** only if the baseline collection of its domain was complete;
* an attribute is **modified** only if both sides know its value (``null`` means unknown,
  e.g. an executable path that needs root);
* anything else is reported under ``indeterminate`` with the reason, never as a change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from shared.reporting.contracts import INVENTORY_DOMAINS, SCHEMA_VERSION, ExitCode
from shared.reporting.inventory import (
    Options,
    Record,
    Snapshot,
    Value,
    as_set,
    is_loopback_listener,
    parse_timestamp,
)

TOOL_NAME = "blueops-diff"
TOOL_VERSION = "0.2.0"

_OK_FOR_ABSENCE = ("complete", "degraded")
_TRUNCATED_RE = re.compile(r"only the first \d+ are listed|showing \d+ of \d+")
_STABLE_EVIDENCE = ("file", "registry")


class IncompatibleReportsError(ValueError):
    """The two reports cannot meaningfully be compared (different host or OS family)."""


@dataclass
class _DomainState:
    domain: str
    scope: str
    status: str
    base_cov: tuple[str, str] | None
    cur_cov: tuple[str, str] | None
    note: str
    can_add: bool = False
    can_remove: bool = False

    @property
    def comparable(self) -> bool:
        return self.status in ("compared", "partial")


# ------------------------------------------------------------------------ metadata


def _meta_json(snap: Snapshot) -> dict[str, Any]:
    m = snap.meta
    return {
        "run_id": m.run_id,
        "tool": m.tool,
        "tool_version": m.tool_version,
        "schema_version": m.schema_version,
        "started_at": m.started_at,
        "finished_at": m.finished_at,
        "hostname": m.hostname,
        "os_family": m.os_family,
        "os_name": m.os_name,
        "os_version": m.os_version,
        "elevated": m.elevated,
        "has_inventory": snap.has_inventory,
    }


def _warn(code: str, message: str) -> dict[str, str]:
    return {"code": code, "message": message}


def check_compatibility(base: Snapshot, cur: Snapshot, options: Options) -> list[dict[str, str]]:
    """Return advisory warnings, or raise if the reports must not be compared."""
    b, c = base.meta, cur.meta
    if b.os_family != c.os_family:
        raise IncompatibleReportsError(
            f"reports are from different OS families ({b.os_family} vs {c.os_family}); "
            "identifiers are platform-specific and are not compared across families"
        )
    warnings: list[dict[str, str]] = []
    if b.hostname.casefold() != c.hostname.casefold():
        msg = f"hostnames differ ({b.hostname!r} vs {c.hostname!r})"
        if not options.allow_host_mismatch:
            raise IncompatibleReportsError(msg + "; pass --allow-host-mismatch to compare anyway")
        warnings.append(_warn("HOST_MISMATCH", msg + "; compared because it was allowed"))
    if b.run_id == c.run_id:
        warnings.append(
            _warn("SAME_RUN", "baseline and current have the same run id; no change expected")
        )
    if parse_timestamp(b.started_at) > parse_timestamp(c.started_at):
        warnings.append(
            _warn(
                "REVERSED_ORDER",
                "the baseline started after the current report; check argument order",
            )
        )
    if b.elevated is not c.elevated:
        warnings.append(
            _warn(
                "PRIVILEGE_DIFFERS",
                f"baseline elevated={b.elevated}, current elevated={c.elevated}; "
                "attributes that need privileges may be unknown on one side",
            )
        )
    if not base.has_inventory or not cur.has_inventory:
        warnings.append(
            _warn(
                "NO_INVENTORY",
                "a report has no inventory (schema 0.1.x?); only findings are compared",
            )
        )
    for side, snap in (("baseline", base), ("current", cur)):
        warnings.extend(_warn(w["code"], f"{side}: {w['message']}") for w in snap.warnings)
    return warnings


# --------------------------------------------------------------------- domain plan


# A "complete" collection of these domains that returns nothing is a collector failure, not a
# host with no users, groups, services or processes.
_NEVER_EMPTY = ("users", "groups", "services", "processes")


def _count(snap: Snapshot, domain: str, scope: str) -> int:
    return sum(1 for k in snap.records if k[0] == domain and k[1] == scope)


def _plan_domain(domain: str, scope: str, base: Snapshot, cur: Snapshot) -> _DomainState | None:
    bc, cc = base.coverage.get((domain, scope)), cur.coverage.get((domain, scope))
    if bc is None and cc is None:
        return None

    def state(status: str, note: str, add: bool = False, remove: bool = False) -> _DomainState:
        return _DomainState(domain, scope, status, bc, cc, note, add, remove)

    if not base.has_inventory or not cur.has_inventory:
        return state("not_compared", "a report has no inventory")
    if bc is None or cc is None:
        where = "baseline" if bc is None else "current"
        return state("not_compared", f"not collected in the {where}")
    if "unavailable" in (bc[0], cc[0]):
        return state("not_compared", "collection was unavailable on one side")
    can_add, can_remove = bc[0] in _OK_FOR_ABSENCE, cc[0] in _OK_FOR_ABSENCE
    notes = []
    if domain in _NEVER_EMPTY:
        nb, nc = _count(base, domain, scope), _count(cur, domain, scope)
        if can_remove and nc == 0 < nb:
            can_remove = False
            notes.append("current collection is empty although the baseline was not")
        if can_add and nb == 0 < nc:
            can_add = False
            notes.append("baseline collection is empty although the current one is not")
    if not can_remove:
        notes.append("current collection incomplete: removals cannot be confirmed")
    if not can_add:
        notes.append("baseline collection incomplete: additions cannot be confirmed")
    if "degraded" in (bc[0], cc[0]):
        notes.append("some attributes were unavailable and are not compared")
    status = "compared" if can_add and can_remove else "partial"
    return state(status, "; ".join(notes), can_add, can_remove)


def _cov_json(cov: tuple[str, str] | None) -> dict[str, str] | None:
    return None if cov is None else {"status": cov[0], "reason": cov[1]}


# ---------------------------------------------------------------- record comparison


def _jv(v: Value) -> Any:
    return list(v) if isinstance(v, tuple) else v


def _record_json(rec: Record | None) -> dict[str, Any] | None:
    if rec is None:
        return None
    return {
        "attrs": {k: _jv(v) for k, v in sorted(rec.attrs.items())},
        "volatile": {k: _jv(v) for k, v in sorted(rec.volatile.items())},
        "evidence": [{"type": t, "ref": r} for t, r in rec.evidence],
    }


def _diff_attrs(b: Record, c: Record) -> tuple[list[dict[str, Any]], list[str]]:
    modified: list[dict[str, Any]] = []
    unverified: list[str] = []
    for name in sorted(set(b.attrs) | set(c.attrs)):
        bv, cv = b.attrs.get(name), c.attrs.get(name)
        if bv is None and cv is None:
            continue
        if bv is None or cv is None:
            unverified.append(name)
        elif as_set(bv) != as_set(cv):
            modified.append({"name": name, "before": _jv(bv), "after": _jv(cv)})
    return modified, unverified


_SYSTEM_DIRS = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/lib/",
    "/usr/lib/",
    "/usr/libexec/",
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
)


def _is_transient(recs: list[Record], options: Options, family: str) -> bool:
    """A helper-named process whose executable is *known* to be in a system directory.

    The name alone is attacker-controlled (``/tmp/sleep``), so an unknown or non-system
    executable on either side keeps the change visible and counted.
    """
    if any(r.domain != "processes" for r in recs):
        return False
    fold = str.casefold if family == "windows" else str
    wanted = {fold(n) for n in options.transient_processes}
    for rec in recs:
        names = as_set(rec.attrs.get("comm")) or {rec.key.rsplit(":", 1)[-1]}
        exes = as_set(rec.attrs.get("exe"))
        if not all(fold(n) in wanted for n in names):
            return False
        if not exes or not all(fold(e).startswith(_SYSTEM_DIRS) for e in exes):
            return False
    return True


def _priority(domain: str, change: str, rec: Record) -> str:
    if domain == "processes":
        return "medium" if change == "modified" else "info"
    if domain == "listeners":
        if change == "removed":
            return "low"
        return "low" if is_loopback_listener(rec) else ("high" if change == "added" else "medium")
    if domain in ("persistence", "users", "groups", "scheduled_tasks"):
        return {"added": "high", "modified": "high", "removed": "medium"}[change]
    if domain == "services":
        return "low" if change == "removed" else "medium"
    return "medium"


def _observed(base: Snapshot, cur: Snapshot, in_base: bool, in_cur: bool) -> dict[str, Any]:
    return {
        "baseline_at": base.meta.finished_at if in_base else None,
        "current_at": cur.meta.finished_at if in_cur else None,
    }


def _ref_index(snap: Snapshot) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    fold = snap.meta.os_family == "windows"
    for f in snap.findings:
        for e in f.get("evidence", []) or []:
            if isinstance(e, dict) and isinstance(e.get("ref"), str):
                ref = e["ref"].casefold() if fold else e["ref"]
                index.setdefault(ref, [])
                if f["id"] not in index[ref]:
                    index[ref].append(f["id"])
    return index


def _related(rec_list: list[tuple[Record, dict[str, list[str]], bool]]) -> list[str]:
    ids: set[str] = set()
    for rec, index, fold in rec_list:
        for _t, ref in rec.evidence:
            ids.update(index.get(ref.casefold() if fold else ref, []))
    return sorted(ids)


@dataclass
class _Result:
    states: list[_DomainState]
    changes: list[dict[str, Any]]
    indets: list[dict[str, Any]]
    unchanged: int = 0


@dataclass
class _Ctx:
    base: Snapshot
    cur: Snapshot
    options: Options
    base_refs: dict[str, list[str]]
    cur_refs: dict[str, list[str]]

    @property
    def fold(self) -> bool:
        return self.cur.meta.os_family == "windows"


def _make_change(
    ctx: _Ctx,
    kind: str,
    b: Record | None,
    c: Record | None,
    attr_diff: tuple[list[dict[str, Any]], list[str]] = ([], []),  # noqa: B006 - never mutated
) -> dict[str, Any]:
    modified, unverified = attr_diff
    rec = c or b
    assert rec is not None  # noqa: S101 - callers pass at least one side
    related: list[tuple[Record, dict[str, list[str]], bool]] = []
    if b is not None:
        related.append((b, ctx.base_refs, ctx.fold))
    if c is not None:
        related.append((c, ctx.cur_refs, ctx.fold))
    transient = _is_transient(
        [r for r in (b, c) if r is not None], ctx.options, ctx.cur.meta.os_family
    )
    return {
        "domain": rec.domain,
        "scope": rec.scope,
        "key": rec.key,
        "change": kind,
        "priority": "info" if transient else _priority(rec.domain, kind, rec),
        "transient": transient,
        "attributes": modified,
        "unverified_attributes": unverified,
        "observed": _observed(ctx.base, ctx.cur, b is not None, c is not None),
        "baseline": _record_json(b),
        "current": _record_json(c),
        "related_findings": _related(related),
    }


def _indeterminate(
    ctx: _Ctx, reason: str, detail: str, b: Record | None, c: Record | None
) -> dict[str, Any]:
    rec = c or b
    assert rec is not None  # noqa: S101 - callers pass at least one side
    return {
        "domain": rec.domain,
        "scope": rec.scope,
        "key": rec.key,
        "reason": reason,
        "detail": detail,
        "observed": _observed(ctx.base, ctx.cur, b is not None, c is not None),
        "baseline": _record_json(b),
        "current": _record_json(c),
    }


def _diff_one_sided(
    ctx: _Ctx, state: _DomainState, b: Record | None, c: Record | None
) -> tuple[str, dict[str, Any]]:
    if c is not None:
        if state.can_add:
            return "change", _make_change(ctx, "added", None, c)
        detail = "baseline collection was incomplete; the record may already have existed"
        return "indeterminate", _indeterminate(ctx, "BASELINE_INCOMPLETE", detail, None, c)
    if state.can_remove:
        return "change", _make_change(ctx, "removed", b, None)
    detail = "current collection was incomplete; the record may still exist"
    return "indeterminate", _indeterminate(ctx, "CURRENT_INCOMPLETE", detail, b, None)


def _diff_key(
    ctx: _Ctx, state: _DomainState, b: Record | None, c: Record | None
) -> tuple[str, dict[str, Any] | None]:
    """Classify one key: ``("change"|"indeterminate"|"unchanged", entry)``."""
    conflicted = next((r for r in (b, c) if r is not None and r.conflict), None)
    if conflicted is not None:
        return "indeterminate", _indeterminate(ctx, "RECORD_CONFLICT", conflicted.conflict, b, c)
    if b is None or c is None:
        return _diff_one_sided(ctx, state, b, c)
    modified, unverified = _diff_attrs(b, c)
    if modified:
        return "change", _make_change(ctx, "modified", b, c, (modified, unverified))
    if unverified:
        detail = "attribute(s) unknown on one side (permission gap?): " + ", ".join(unverified)
        return "indeterminate", _indeterminate(ctx, "ATTRIBUTE_UNKNOWN", detail, b, c)
    return "unchanged", None


def _in_partition(snap: Snapshot, state: _DomainState) -> dict[str, Record]:
    return {
        key: rec
        for (dom, scope, key), rec in snap.records.items()
        if dom == state.domain and scope == state.scope
    }


def _diff_domain(
    ctx: _Ctx, state: _DomainState
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    bsel = _in_partition(ctx.base, state)
    csel = _in_partition(ctx.cur, state)
    bkeys, ckeys = set(bsel), set(csel)
    changes: list[dict[str, Any]] = []
    indets: list[dict[str, Any]] = []
    unchanged = 0
    for key in sorted(bkeys | ckeys):
        verdict, entry = _diff_key(ctx, state, bsel.get(key), csel.get(key))
        if verdict == "change" and entry is not None:
            changes.append(entry)
        elif verdict == "indeterminate" and entry is not None:
            indets.append(entry)
        else:
            unchanged += 1
    return changes, indets, unchanged


# ------------------------------------------------------------------ findings delta


def _finding_refs(snap: Snapshot, finding: dict[str, Any]) -> set[str]:
    fold = snap.meta.os_family == "windows"
    refs: set[str] = set()
    for e in finding.get("evidence", []) or []:
        if (
            isinstance(e, dict)
            and e.get("type") in _STABLE_EVIDENCE
            and isinstance(e.get("ref"), str)
        ):
            refs.add(e["ref"].casefold() if fold else e["ref"])
    return refs


def _is_truncated(finding: dict[str, Any]) -> bool:
    return bool(_TRUNCATED_RE.search(str(finding.get("description", ""))))


def _error_checks(snap: Snapshot) -> set[str]:
    return {e["check_id"] for e in snap.errors if isinstance(e.get("check_id"), str)}


def _finding_summary(f: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f["id"],
        "severity": f.get("severity"),
        "category": f.get("category"),
        "title": str(f.get("title", ""))[:200],
    }


def _finding_changed(
    base: Snapshot, cur: Snapshot, bf: dict[str, Any], cf: dict[str, Any]
) -> dict[str, Any] | None:
    sev_changed = bf.get("severity") != cf.get("severity")
    added: list[str] = []
    removed: list[str] = []
    if not (_is_truncated(bf) or _is_truncated(cf)):
        br, cr = _finding_refs(base, bf), _finding_refs(cur, cf)
        added, removed = sorted(cr - br), sorted(br - cr)
    if not (sev_changed or added or removed):
        return None
    out = _finding_summary(cf)
    out.update(
        before_severity=bf.get("severity"),
        after_severity=cf.get("severity"),
        evidence_added=added,
        evidence_removed=removed,
    )
    return out


_RUN_GAP_CODES = ("MODULE_FAILED", "MODULE_MISSING")


def _gap_signatures(snap: Snapshot) -> set[tuple[str, str]]:
    """Errors that do not name a check: they say something was not collected, not what."""
    return {
        (str(e.get("code")), str(e.get("message", "")))
        for e in snap.errors
        if not isinstance(e.get("check_id"), str)
    }


def _absence_untrusted(base: Snapshot, cur: Snapshot) -> bool:
    """True when a finding missing from the current run proves nothing.

    A crashed or missing module, a new collection error that names no check, a run that
    exited partially or with a failure the baseline did not have, or a drop from elevated
    to unprivileged hides findings without any error carrying the finding's own check id.
    """
    if any(e.get("code") in _RUN_GAP_CODES for e in cur.errors):
        return True
    if _gap_signatures(cur) - _gap_signatures(base):
        return True
    failed = (ExitCode.ERROR, ExitCode.PRECONDITION, ExitCode.PARTIAL)
    if cur.meta.exit_code in failed and cur.meta.exit_code != base.meta.exit_code:
        return True
    return base.meta.elevated is True and cur.meta.elevated is not True


def diff_findings(base: Snapshot, cur: Snapshot) -> dict[str, Any]:
    """Compare findings by id, severity and stable (file/registry) evidence refs only."""
    untrusted = _absence_untrusted(base, cur)
    bmap = {f["id"]: f for f in base.findings}
    cmap = {f["id"]: f for f in cur.findings}
    berr, cerr = _error_checks(base), _error_checks(cur)
    new: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unverified: list[dict[str, Any]] = []
    for fid in sorted(set(bmap) | set(cmap)):
        if fid not in bmap or fid not in cmap:
            f = cmap.get(fid) or bmap[fid]
            gap = (fid in berr) if fid in cmap else (untrusted or fid in cerr)
            entry = _finding_summary(f)
            if gap:
                entry["state"] = "new" if fid in cmap else "resolved"
                unverified.append(entry)
            else:
                (new if fid in cmap else resolved).append(entry)
            continue
        delta = _finding_changed(base, cur, bmap[fid], cmap[fid])
        if delta is not None:
            changed.append(delta)
    return {"new": new, "resolved": resolved, "changed": changed, "unverified": unverified}


# --------------------------------------------------------------------------- driver


def _summary(res: _Result, findings: dict[str, Any], ignored: int) -> dict[str, Any]:
    changes, indets, states = res.changes, res.indets, res.states
    unchanged = res.unchanged
    counted = [c for c in changes if not c["transient"]]
    by_domain: dict[str, dict[str, int]] = {}
    for c in counted:
        by_domain.setdefault(c["domain"], {"added": 0, "removed": 0, "modified": 0})[
            c["change"]
        ] += 1
    return {
        "added": sum(1 for c in counted if c["change"] == "added"),
        "removed": sum(1 for c in counted if c["change"] == "removed"),
        "modified": sum(1 for c in counted if c["change"] == "modified"),
        "transient": len(changes) - len(counted),
        "indeterminate": len(indets),
        "unchanged": unchanged,
        "ignored": ignored,
        "by_domain": {d: by_domain[d] for d in INVENTORY_DOMAINS if d in by_domain},
        "domains_compared": sum(1 for s in states if s.status == "compared"),
        "domains_partial": sum(1 for s in states if s.status == "partial"),
        "domains_not_compared": sum(1 for s in states if s.status == "not_compared"),
        "findings_new": len(findings["new"]),
        "findings_resolved": len(findings["resolved"]),
        "findings_changed": len(findings["changed"]),
        "findings_unverified": len(findings["unverified"]),
    }


def compare(base: Snapshot, cur: Snapshot, options: Options, generated_at: str) -> dict[str, Any]:
    """Compare two snapshots and return the diff report (schema ``baseline-diff``)."""
    warnings = check_compatibility(base, cur, options)
    ctx = _Ctx(base, cur, options, _ref_index(base), _ref_index(cur))
    res = _Result([], [], [])
    order = {d: i for i, d in enumerate(INVENTORY_DOMAINS)}
    partitions = sorted(set(base.coverage) | set(cur.coverage), key=lambda k: (order[k[0]], k[1]))
    for domain, scope in partitions:
        state = _plan_domain(domain, scope, base, cur)
        if state is None:
            continue
        res.states.append(state)
        if state.comparable:
            c, i, u = _diff_domain(ctx, state)
            res.changes += c
            res.indets += i
            res.unchanged += u
    findings = diff_findings(base, cur)
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "baseline-diff",
        "generated_at": generated_at,
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "baseline": _meta_json(base),
        "current": _meta_json(cur),
        "window": {"from": base.meta.finished_at, "to": cur.meta.started_at},
        "warnings": warnings,
        "domains": [
            {
                "domain": s.domain,
                "scope": s.scope,
                "status": s.status,
                "baseline_coverage": _cov_json(s.base_cov),
                "current_coverage": _cov_json(s.cur_cov),
                "note": s.note,
            }
            for s in res.states
        ],
        "changes": res.changes,
        "indeterminate": res.indets,
        "findings": findings,
        "summary": _summary(res, findings, base.ignored + cur.ignored),
    }


def exit_code_for(diff: dict[str, Any]) -> ExitCode:
    """FINDINGS (4) when anything changed, PARTIAL (6) when nothing changed but coverage is
    incomplete or conclusions were withheld, otherwise OK (0)."""
    s = diff["summary"]
    changed = s["added"] + s["removed"] + s["modified"]
    changed += s["findings_new"] + s["findings_resolved"] + s["findings_changed"]
    if changed:
        return ExitCode.FINDINGS
    incomplete = s["indeterminate"] + s["domains_partial"] + s["domains_not_compared"]
    incomplete += s["findings_unverified"]
    if incomplete or any(w["code"] == "NO_INVENTORY" for w in diff["warnings"]):
        return ExitCode.PARTIAL
    return ExitCode.OK
