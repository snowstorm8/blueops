"""Markdown report renderer.

Every value from the assessment is attacker-influenced (file names, command lines, account
names). It is escaped for Markdown *and* reduced to a single line, so a hostile value cannot
inject headings, links, images or raw HTML into the report.
"""

from __future__ import annotations

import re
from typing import Any

from shared.reporting.render_common import (
    PRIORITY_LABEL,
    SEVERITIES,
    executive_summary,
    findings_by_category,
    remediation_plan,
)

_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~&])")
_WS = re.compile(r"\s+")
MAX_CELL = 300


def esc(value: Any, limit: int = MAX_CELL) -> str:
    """Escape ``value`` for inline Markdown / a table cell; collapses whitespace, caps length."""
    text = _WS.sub(" ", "" if value is None else str(value)).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return _SPECIAL.sub(r"\\\1", text)


def code(value: Any, limit: int = MAX_CELL) -> str:
    """Inline code span that survives backticks in the value (``<``/``>`` become guillemets)."""
    text = _WS.sub(" ", "" if value is None else str(value)).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    # Angle brackets are shown as single guillemets: a code span is literal in CommonMark, but
    # not every viewer is strict, and the exact value always remains in the JSON report.
    text = text.replace("<", "\u2039").replace(">", "\u203a")
    fence = "`" * (max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text.replace('|', chr(0xFF5C))}{pad}{fence}"


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return out + [""]


def _bar(n: int, total: int, width: int = 20) -> str:
    return "#" * (round(width * n / total) if total else 0)


def render_markdown(  # noqa: PLR0912, PLR0915 - one linear sequence of report sections
    doc: dict[str, Any], comparisons: list[dict[str, Any]] | None = None, generated_at: str = ""
) -> str:
    ex = executive_summary(doc, comparisons)
    a, s = doc["assessment"], doc["summary"]
    host = doc.get("host")
    lines: list[str] = ["# BlueOps assessment report", ""]
    if generated_at:
        lines += [f"_Generated {esc(generated_at)}_", ""]
    lines += [
        "> Read-only assessment. For systems you are authorized to administer. Findings are "
        "leads for investigation, not verdicts.",
        "",
        "## Executive summary",
        "",
        f"**{esc(ex['headline'])}**",
        "",
    ]
    lines += [f"- {esc(b, 500)}" for b in ex["bullets"]] + [""]
    if ex["caveats"]:
        lines += [
            "**Coverage caveats** (absence of findings is not proof of absence of problems):",
            "",
        ]
        lines += [f"- {esc(c, 500)}" for c in ex["caveats"]] + [""]

    lines += ["## Assessment metadata", ""]
    lines += _table(
        ["Field", "Value"],
        [
            ["Assessment id", code(a["id"])],
            ["Profile", esc(a["profile"])],
            ["Started", esc(a["started_at"])],
            ["Finished", esc(a["finished_at"])],
            ["Status", esc(a["status"])],
            ["Exit code", esc(a["exit_code"])],
            ["Fail threshold", esc(a["fail_on"])],
            ["Engine", esc(f"{doc['engine']['name']} {doc['engine']['version']}")],
        ],
    )
    lines += ["## Host", ""]
    if host:
        lines += _table(
            ["Field", "Value"],
            [
                ["Hostname", esc(host["hostname"])],
                [
                    "Operating system",
                    esc(f"{host['os']['name']} {host['os']['version']} ({host['os']['family']})"),
                ],
                ["Architecture", esc(host.get("arch", ""))],
                ["User", esc(host.get("user", "unknown"))],
                [
                    "Privileged",
                    esc({True: "yes", False: "no"}.get(host.get("elevated"), "unknown")),
                ],
            ],
        )
    else:
        lines += ["No module produced a usable report; host details are unavailable.", ""]

    lines += ["## Severity distribution", ""]
    lines += _table(
        ["Severity", "Count", ""],
        [
            [k, str(s["by_severity"][k]), f"`{_bar(s['by_severity'][k], s['total'])}`"]
            for k in SEVERITIES
        ],
    )

    lines += ["## Module results", ""]
    lines += _table(
        ["Module", "Status", "Findings", "Seconds", "Note"],
        [
            [
                code(m["id"]),
                esc(m["status"]),
                str(m["findings"]),
                f"{m['duration_seconds']:.1f}",
                esc(m.get("reason", "")),
            ]
            for m in doc["modules"]
        ],
    )

    lines += ["## Remediation priorities", ""]
    plan = remediation_plan(doc)
    any_plan = False
    for prio, items in plan.items():
        if not items:
            continue
        any_plan = True
        lines += [f"### {prio} - {PRIORITY_LABEL[prio]}", ""]
        lines += [
            f"- **{esc(f['severity'])}** {esc(f['title'], 160)} ({code(f['check_id'])}): "
            f"{esc(f['remediation']['summary'], 400)}"
            for f in items
        ] + [""]
    if not any_plan:
        lines += ["No remediation actions.", ""]

    lines += ["## Findings", ""]
    if not doc["findings"]:
        lines += ["No findings.", ""]
    for cat, items in findings_by_category(doc):
        lines += [f"### {esc(cat)} ({len(items)})", ""]
        for f in items:
            lines += [
                f"#### {esc(f['severity']).upper()} - {esc(f['title'], 200)}",
                "",
                f"- Id: {code(f['id'])}  Check: {code(f['check_id'])}  "
                f"Confidence: {esc(f['confidence'])}  "
                f"Priority: {esc(f['remediation']['priority'])}",
                f"- Component: {esc(f['component'])} on {esc(f['host']['hostname'])}",
                f"- Detected: {esc(f['detected_at'])}",
                f"- Description: {esc(f['description'], 1500)}",
            ]
            if f["remediation"]["summary"]:
                lines.append(f"- Remediation: {esc(f['remediation']['summary'], 800)}")
            if f["standards"]:
                lines.append(
                    "- Standards: "
                    + ", ".join(esc(f"{x['framework']} {x['id']}") for x in f["standards"])
                )
            if f["evidence"]:
                lines.append("- Evidence: " + ", ".join(code(e) for e in f["evidence"][:10]))
                if len(f["evidence"]) > 10:
                    lines.append(f"  ({len(f['evidence']) - 10} more in the evidence index)")
            lines.append("")

    lines += ["## Evidence index", ""]
    rows = []
    for e in doc["evidence"]:
        mods = sorted({p["module"] for p in e["provenance"]})
        rows.append(
            [
                code(e["id"]),
                esc(e["type"]),
                code(e["ref"], 200),
                code(e["sha256"][:16]) if e.get("sha256") else "",
                esc(", ".join(mods)),
            ]
        )
    lines += (
        _table(["Id", "Type", "Reference", "SHA-256 (prefix)", "Collected by"], rows)
        if rows
        else ["No evidence.", ""]
    )

    if comparisons:
        lines += ["## Historical comparison", ""]
        for c in comparisons:
            cs = c["summary"]
            lines += [
                f"### {esc(c['baseline']['started_at'])} -> {esc(c['current']['started_at'])}",
                "",
                f"Trend: **{esc(cs['trend'])}**; "
                f"weighted index {cs['weighted_index']['baseline']} -> "
                f"{cs['weighted_index']['current']} ({cs['weighted_index']['delta']:+d}).",
                "",
            ]
            lines += _table(
                [
                    "New",
                    "Resolved",
                    "Persistent",
                    "Severity up",
                    "Severity down",
                    "Config changes",
                    "Indeterminate",
                ],
                [
                    [
                        str(cs[k])
                        for k in (
                            "new",
                            "resolved",
                            "persistent",
                            "severity_increased",
                            "severity_decreased",
                            "configuration_changes",
                            "indeterminate",
                        )
                    ]
                ],
            )
            for title, key in (
                ("New", "new"),
                ("Resolved", "resolved"),
                ("Severity changed", "severity_changed"),
            ):
                items = c["findings"][key]
                if items:
                    lines += [f"**{title}**", ""]
                    lines += [
                        f"- {esc(i['severity'])}: {esc(i['title'], 160)} ({code(i['check_id'])})"
                        for i in items[:50]
                    ] + [""]
            for w in c["warnings"]:
                lines.append(f"- Warning {esc(w['code'])}: {esc(w['message'], 400)}")
            lines.append("")

    lines += ["## Errors and warnings", ""]
    if doc["errors"] or doc["warnings"]:
        lines += [
            f"- Error {esc(e['code'])} ({esc(e['module'])}): {esc(e['message'], 400)}"
            for e in doc["errors"][:100]
        ]
        lines += [f"- Warning {esc(w['code'])}: {esc(w['message'], 400)}" for w in doc["warnings"]]
        lines.append("")
    else:
        lines += ["None.", ""]
    return "\n".join(lines).rstrip() + "\n"


def render_comparison_markdown(cmp_doc: dict[str, Any]) -> str:
    """Markdown for one snapshot comparison (the same section the full report embeds)."""
    cs = cmp_doc["summary"]
    lines = [
        "# BlueOps snapshot comparison",
        "",
        f"{esc(cmp_doc['baseline']['hostname'])}: {esc(cmp_doc['baseline']['started_at'])} -> "
        f"{esc(cmp_doc['current']['started_at'])}",
        "",
        f"Trend: **{esc(cs['trend'])}**; weighted index {cs['weighted_index']['baseline']} -> "
        f"{cs['weighted_index']['current']} ({cs['weighted_index']['delta']:+d}).",
        "",
    ]
    keys = ("new", "resolved", "persistent", "severity_increased", "severity_decreased")
    keys += ("configuration_changes", "indeterminate", "coverage_changes")
    lines += _table(["Metric", "Count"], [[k.replace("_", " "), str(cs[k])] for k in keys])
    for title, key in (
        ("New findings", "new"),
        ("Resolved findings", "resolved"),
        ("Severity changed", "severity_changed"),
        ("Indeterminate (not enough coverage to conclude)", "indeterminate"),
    ):
        items = cmp_doc["findings"][key]
        if not items:
            continue
        lines += [f"## {title}", ""]
        for i in items[:200]:
            extra = ""
            if key == "severity_changed":
                extra = f" (was {esc(i['baseline_severity'])})"
            elif key == "indeterminate":
                extra = f" - {esc(i['reason'], 300)}"
            lines.append(
                f"- {esc(i['severity'])}: {esc(i['title'], 160)} ({code(i['check_id'])}){extra}"
            )
        lines.append("")
    cfg = cmp_doc["configuration"]
    lines += ["## Configuration changes", ""]
    if not cfg["available"]:
        lines += [f"Unavailable: {esc(cfg.get('reason', ''))}", ""]
    elif not cfg["changes"]:
        lines += ["None.", ""]
    else:
        lines += [
            f"- {esc(c['change'])}: {code(c['domain'] + '/' + c['key'])}"
            for c in cfg["changes"][:200]
        ] + [""]
    cov = cmp_doc["coverage"]["modules"]
    lines += ["## Coverage differences", ""]
    if cov["added"] or cov["removed"] or cov["changed"]:
        lines += [f"- Added: {esc(', '.join(cov['added']) or 'none')}"]
        lines += [f"- Removed: {esc(', '.join(cov['removed']) or 'none')}"]
        lines += [
            f"- Status changed: {esc(c['id'])} {esc(c['baseline'])} -> {esc(c['current'])}"
            for c in cov["changed"]
        ]
        lines.append("")
    else:
        lines += ["None.", ""]
    if cmp_doc["warnings"]:
        lines += ["## Warnings", ""]
        lines += [f"- {esc(w['code'])}: {esc(w['message'], 400)}" for w in cmp_doc["warnings"]] + [
            ""
        ]
    return "\n".join(lines).rstrip() + "\n"
