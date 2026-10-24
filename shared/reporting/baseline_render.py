"""Human-readable rendering of a baseline-diff report.

Report content is attacker-influenced, so every value is sanitised before it reaches a
terminal (no escape sequences, no control characters, bounded length).
"""

from __future__ import annotations

import re
from typing import Any

from shared.reporting.contracts import INVENTORY_DOMAINS

_BAD_CHARS = re.compile(r"[^\x20-\x7e]")
_MAX_VALUE = 160
_SYMBOL = {"added": "+", "removed": "-", "modified": "~"}


def clean(value: Any, limit: int = _MAX_VALUE) -> str:
    """Render a value as printable ASCII, escaping anything else."""
    if isinstance(value, (list, tuple)):
        text = ", ".join(clean(v, limit) for v in value)
    else:
        text = "null" if value is None else str(value)
    text = _BAD_CHARS.sub(
        lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 256 else "?", text
    )
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _attrs_line(rec: dict[str, Any] | None) -> str:
    if not rec:
        return ""
    return " ".join(f"{k}={clean(v, 60)}" for k, v in rec["attrs"].items() if v is not None)


def _meta_line(label: str, meta: dict[str, Any]) -> str:
    return (
        f"{label}: {clean(meta['hostname'])}  run {clean(meta['run_id'], 40)}  "
        f"finished {clean(meta['finished_at'])}  "
        f"({clean(meta['os_family'])}, elevated={clean(meta['elevated'])})"
    )


def _change_lines(c: dict[str, Any]) -> list[str]:
    sym = _SYMBOL[c["change"]]
    lines = [f"  {sym} {clean(c['key'])}  [{c['priority']}]"]
    if c["change"] == "modified":
        for a in c["attributes"]:
            lines.append(f"      {clean(a['name'])}: {clean(a['before'])} -> {clean(a['after'])}")
        if c["unverified_attributes"]:
            lines.append(
                f"      not compared (unknown on one side): {clean(c['unverified_attributes'])}"
            )
    else:
        summary = _attrs_line(c["current"] or c["baseline"])
        if summary:
            lines.append(f"      {summary}")
    evidence = (c["current"] or c["baseline"] or {}).get("evidence", [])
    if evidence:
        refs = "; ".join(f"{clean(e['type'])} {clean(e['ref'])}" for e in evidence[:3])
        lines.append(f"      evidence: {refs}")
    if c["related_findings"]:
        lines.append(f"      related findings: {clean(c['related_findings'])}")
    obs = c["observed"]
    lines.append(
        f"      seen: baseline {clean(obs['baseline_at'] or 'absent')}, "
        f"current {clean(obs['current_at'] or 'absent')}"
    )
    return lines


def _domain_section(domain: str, changes: list[dict[str, Any]], show_transient: bool) -> list[str]:
    shown = [c for c in changes if c["domain"] == domain and (show_transient or not c["transient"])]
    hidden = sum(1 for c in changes if c["domain"] == domain and c["transient"]) - (
        sum(1 for c in shown if c["transient"])
    )
    if not shown and not hidden:
        return []
    out = ["", f"== {domain} =="]
    for c in shown:
        out.extend(_change_lines(c))
    if hidden:
        out.append(
            f"  ({hidden} transient change(s) hidden; use --show-transient or --format json)"
        )
    return out


def _coverage_lines(diff: dict[str, Any]) -> list[str]:
    out = ["", "Coverage:"]
    for d in diff["domains"]:
        bc = (d["baseline_coverage"] or {}).get("status", "-")
        cc = (d["current_coverage"] or {}).get("status", "-")
        note = f"  {clean(d['note'], 100)}" if d["note"] else ""
        name = d["domain"] + (f"/{clean(d['scope'], 30)}" if d["scope"] else "")
        out.append(f"  {name:<26} {d['status']:<13} baseline={bc} current={cc}{note}")
    return out


def _summary_line(s: dict[str, Any]) -> str:
    return (
        f"Result: {s['added']} added, {s['removed']} removed, {s['modified']} modified; "
        f"{s['indeterminate']} indeterminate; {s['unchanged']} unchanged"
        + (f"; {s['transient']} transient" if s["transient"] else "")
    )


def _findings_lines(f: dict[str, Any]) -> list[str]:
    if not any(f[k] for k in ("new", "resolved", "changed", "unverified")):
        return []
    out = ["", "== findings (by id, severity and file/registry evidence) =="]
    out += [f"  + {clean(x['id'])} [{clean(x['severity'])}] {clean(x['title'])}" for x in f["new"]]
    out += [
        f"  - {clean(x['id'])} [{clean(x['severity'])}] {clean(x['title'])}" for x in f["resolved"]
    ]
    for x in f["changed"]:
        if x["before_severity"] == x["after_severity"]:
            out.append(f"  ~ {clean(x['id'])} [{clean(x['after_severity'])}] evidence changed")
        else:
            out.append(
                f"  ~ {clean(x['id'])} severity {clean(x['before_severity'])} -> "
                f"{clean(x['after_severity'])}"
            )
        for ref in x["evidence_added"]:
            out.append(f"      + evidence {clean(ref)}")
        for ref in x["evidence_removed"]:
            out.append(f"      - evidence {clean(ref)}")
    for x in f["unverified"]:
        out.append(
            f"  ? {clean(x['id'])} appears {x['state']} but its check reported a coverage gap; "
            "no conclusion drawn"
        )
    return out


def render_text(diff: dict[str, Any], show_transient: bool = False) -> str:
    """Render the diff as a text report (deterministic for a given input)."""
    s = diff["summary"]
    lines = [
        f"BlueOps baseline diff {clean(diff['tool']['version'])} - offline, read-only comparison",
        _meta_line("Baseline", diff["baseline"]),
        _meta_line("Current ", diff["current"]),
        "Changes occurred between "
        f"{clean(diff['window']['from'])} and {clean(diff['window']['to'])}",
        _summary_line(s),
    ]
    for w in diff["warnings"]:
        lines.append(f"! {clean(w['code'])}: {clean(w['message'], 300)}")
    lines += _coverage_lines(diff)
    for domain in INVENTORY_DOMAINS:
        lines += _domain_section(domain, diff["changes"], show_transient)
    if diff["indeterminate"]:
        lines += ["", "== indeterminate (no conclusion drawn) =="]
        for i in diff["indeterminate"]:
            lines.append(f"  ? {clean(i['key'])}  {clean(i['reason'])}: {clean(i['detail'], 200)}")
    lines += _findings_lines(diff["findings"])
    if not (s["added"] + s["removed"] + s["modified"] + s["indeterminate"]):
        lines += ["", "No inventory changes detected in the compared domains."]
    return "\n".join(lines) + "\n"
