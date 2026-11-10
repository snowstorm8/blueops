"""Data preparation shared by the Markdown and HTML report renderers.

Renderers receive an assessment document (and optional snapshot comparisons) and must not change
what the data says, only how it is laid out. Everything derived (posture wording, grouping,
remediation order) lives here so the two formats cannot disagree.
"""

from __future__ import annotations

from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")  # display order, worst first
PRIORITY_LABEL = {
    "P1": "Act now: probable compromise or serious exposure",
    "P2": "Fix soon: material weakness or likely misuse",
    "P3": "Plan: hardening gap or lower-confidence signal",
    "P4": "Routine: context and housekeeping",
}


class RenderError(ValueError):
    """The input cannot be rendered (wrong document kind)."""


def check_assessment(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, dict) or doc.get("kind") != "assessment":
        raise RenderError("expected an assessment document")
    return doc


def posture(summary: dict[str, Any]) -> tuple[str, str]:
    """``(label, css-key)`` for the overall wording. Based on severities present, nothing more."""
    s = summary["by_severity"]
    if s["critical"]:
        return "Immediate attention required", "critical"
    if s["high"]:
        return "Serious findings need attention", "high"
    if s["medium"]:
        return "Weaknesses found", "medium"
    if s["low"]:
        return "Minor hardening gaps", "low"
    return "No actionable findings", "info"


def coverage_caveats(doc: dict[str, Any]) -> list[str]:
    """Plain-language reasons the absence of findings must not be read as 'clean'."""
    out = []
    for m in doc["modules"]:
        if m["status"] != "ok":
            why = f": {m['reason']}" if m.get("reason") else ""
            out.append(f"Module {m['id']} finished as {m['status']}{why}")
    host = doc.get("host", {})
    if host.get("elevated") is False:
        out.append("Collected without administrator/root privileges; some sources were unreadable")
    if host.get("test_mode"):
        out.append("Collected with test fixtures: this report does not describe a real host")
    for part in doc["inventory"]["coverage"]:
        if part["status"] in ("partial", "unavailable"):
            scope = f"/{part['scope']}" if part.get("scope") else ""
            out.append(f"Inventory {part['domain']}{scope} is {part['status']}")
    return out


def executive_summary(
    doc: dict[str, Any], comparisons: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    check_assessment(doc)
    s = doc["summary"]
    label, key = posture(s)
    host = doc.get("host")
    where = (
        f"{host['hostname']} ({host['os']['name']} {host['os']['version']})"
        if host
        else "an unidentified host"
    )
    sev = s["by_severity"]
    counts = ", ".join(f"{sev[k]} {k}" for k in SEVERITIES if sev[k])
    bullets = [
        f"{s['total']} finding(s) on {where}" + (f": {counts}." if counts else "."),
        f"{s['by_priority']['P1']} finding(s) need immediate action (P1) and "
        f"{s['by_priority']['P2']} soon (P2).",
    ]
    m = s["modules"]
    ran = m["ok"] + m["partial"]
    total = sum(m.values())
    bullets.append(
        f"{ran} of {total} module(s) produced results; {total - m['ok']} did not finish cleanly."
    )
    if comparisons:
        c = comparisons[0]["summary"]
        bullets.append(
            f"Compared with the previous snapshot: {c['new']} new, {c['resolved']} resolved, "
            f"{c['persistent']} persistent finding(s); trend: {c['trend']}."
        )
    return {
        "headline": label,
        "key": key,
        "bullets": bullets,
        "caveats": coverage_caveats(doc),
    }


def remediation_plan(doc: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Findings that have a remediation, grouped by priority, worst severity first."""
    plan: dict[str, list[dict[str, Any]]] = {p: [] for p in PRIORITY_LABEL}
    rank = {k: i for i, k in enumerate(SEVERITIES)}
    for f in doc["findings"]:
        if f["remediation"]["summary"]:
            plan[f["remediation"]["priority"]].append(f)
    for items in plan.values():
        items.sort(key=lambda f: (rank[f["severity"]], f["category"], f["check_id"]))
    return plan


def findings_by_category(doc: dict[str, Any]) -> list[tuple[str, list[dict[str, Any]]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in doc["findings"]:
        groups.setdefault(f["category"], []).append(f)
    rank = {k: i for i, k in enumerate(SEVERITIES)}
    ordered = sorted(
        groups.items(),
        key=lambda kv: (min(rank[f["severity"]] for f in kv[1]), kv[0]),
    )
    return [
        (cat, sorted(fs, key=lambda f: (rank[f["severity"]], f["check_id"]))) for cat, fs in ordered
    ]


def evidence_index(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {e["id"]: e for e in doc["evidence"]}


def finding_titles(doc: dict[str, Any]) -> dict[str, str]:
    return {f["id"]: f["title"] for f in doc["findings"]}
