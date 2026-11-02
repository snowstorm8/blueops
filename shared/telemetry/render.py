"""Text, Markdown and HTML views of telemetry documents (all data is escaped for its context)."""

from __future__ import annotations

import html
from typing import Any

from shared.findings.model import clean
from shared.rules.render_util import md_code, md_text
from shared.telemetry.hunt import CLASS_TEXT, classification

_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
_HEAD_NOTE = (
    "Telemetry is untrusted input collected from the host. Coverage 'complete' with no records is an "
    "observed absence; 'unavailable' means the data could not be collected and says nothing about the host."
)


def summary_lines(doc: dict[str, Any]) -> list[str]:
    h, c, s = doc["host"], doc["collection"], doc["summary"]
    lines = [
        f"{h['hostname']} ({h['os']['family']}) collection {clean(c['id'], 80)}",
        f"  {c['started_at']} .. {c['ended_at']}  mode={c['mode']}  elevated={c['elevated']}",
        f"  {s['records']} record(s); rejected {s['rejected']}, duplicates merged {s['duplicates_merged']}, conflicts {s['conflicts']}",
        f"  complete: {'yes' if s['complete'] else 'NO - see coverage and errors'}",
        "  coverage:",
    ]
    for cov in doc["coverage"]:
        scope = f"/{cov['scope']}" if cov.get("scope") else ""
        why = f"  ({clean(cov['reason'], 100)})" if cov.get("reason") else ""
        lines.append(
            f"    {cov['category'] + scope:<28} {cov['status']:<14} {cov['records']:>6}{why}"
        )
    for e in doc["errors"][:20]:
        lines.append(f"  error {e['code']}: {clean(e['message'], 160)}")
    for r in doc["rejected"][:10]:
        lines.append(f"  rejected {r['origin']}: {clean('; '.join(r['reasons']), 160)}")
    return lines


def record_line(rec: dict[str, Any]) -> str:
    a = rec["attributes"]
    keys = list(a)[:6]
    attrs = " ".join(f"{k}={clean(str(a[k]), 60)}" for k in keys)
    when = rec.get("event_time") or rec["observed_at"]
    mark = " [partial]" if rec["status"] == "partial" else ""
    return f"{when} {rec['category']:<18} {rec['record_id']} {attrs}{mark}"


def _detections_md(results: dict[str, Any]) -> list[str]:
    out = ["## Hunting results", ""]
    dets = results.get("detections", [])
    out.append(
        f"{len(dets)} detection(s); {len(results.get('indeterminate', []))} rule(s) could not be evaluated."
    )
    out.append("")
    for cls in ("suspicious", "unusual", "lead"):
        group = [d for d in dets if classification(d["nature"]) == cls]
        if not group:
            continue
        out += [f"### {cls.capitalize()} ({len(group)})", "", f"_{CLASS_TEXT[cls]}_", ""]
        for d in group:
            e = d["explanation"]
            out.append(
                f"- **{md_text(d['title'])}** — {d['severity']} severity, {d['confidence']} confidence ({md_code(d['rule']['id'])}, {md_code(d['id'])})"
            )
            out.append(f"  - Why: {md_text(e['why_flagged'], 400)}")
            out.append(f"  - Matched: {md_text(e['why_correlated'], 400)}")
            for c in d["contributing"][:5]:
                det = c.get("detail", {})
                out.append(
                    f"  - Evidence: {md_code(c.get('id', ''))} {md_text(c['label'])} {md_text(det.get('source', ''), 120)}"
                )
            if e["caveats"]:
                out.append(f"  - Caveats: {md_text('; '.join(e['caveats']), 400)}")
            if e["possible_benign_causes"]:
                out.append(
                    f"  - Possible benign causes: {md_text('; '.join(e['possible_benign_causes']), 400)}"
                )
    if results.get("indeterminate"):
        out += ["", "### Rules that could not be evaluated", ""]
        out += [
            f"- {md_code(i['rule']['id'])}: {md_text(i['reason'], 300)}"
            for i in results["indeterminate"]
        ]
    return out + [""]


def render_markdown(doc: dict[str, Any], results: dict[str, Any] | None = None) -> str:
    h, c, s = doc["host"], doc["collection"], doc["summary"]
    out = [
        f"# Endpoint telemetry: {md_text(h['hostname'])}",
        "",
        f"_{_HEAD_NOTE}_",
        "",
        f"- Host: {md_text(h['hostname'])} ({h['os']['family']}), id {md_code(h['host_id'])}",
        f"- Collection: {md_code(c['id'])}, {c['started_at']} to {c['ended_at']}, mode {c['mode']}",
        f"- Records: {s['records']}; rejected {s['rejected']}; duplicates merged {s['duplicates_merged']}; conflicts {s['conflicts']}",
        f"- Complete: **{'yes' if s['complete'] else 'no'}**",
        "",
        "## Coverage",
        "",
        "| Category | Scope | Status | Records | Reason |",
        "|---|---|---|---|---|",
    ]
    for cov in doc["coverage"]:
        out.append(
            f"| {cov['category']} | {md_text(cov.get('scope', ''))} | {cov['status']} | {cov['records']} | {md_text(cov.get('reason', ''), 200)} |"
        )
    out.append("")
    if doc["errors"] or doc["rejected"] or doc["conflicts"]:
        out += ["## Collection problems", ""]
        out += [
            f"- error {md_code(e['code'])}: {md_text(e['message'], 300)}"
            for e in doc["errors"][:50]
        ]
        out += [
            f"- rejected {md_code(r['origin'])}: {md_text('; '.join(r['reasons']), 300)}"
            for r in doc["rejected"][:50]
        ]
        out += [
            f"- conflict {md_code(x['record_id'])} ({x['category']}): differs in {md_text(', '.join(x['differing_attributes']))}; kept {x['kept']}"
            for x in doc["conflicts"][:50]
        ]
        out.append("")
    if results is not None:
        out += _detections_md(results)
    return "\n".join(out) + "\n"


def render_html(doc: dict[str, Any], results: dict[str, Any] | None = None) -> str:
    e = html.escape
    h, c, s = doc["host"], doc["collection"], doc["summary"]
    rows = "".join(
        f"<tr><td>{e(cov['category'])}</td><td>{e(cov.get('scope', ''))}</td><td class='{e(cov['status'])}'>{e(cov['status'])}</td><td>{cov['records']}</td><td>{e(clean(cov.get('reason', ''), 200))}</td></tr>"
        for cov in doc["coverage"]
    )
    probs = "".join(
        f"<li>error <code>{e(x['code'])}</code>: {e(clean(x['message'], 300))}</li>"
        for x in doc["errors"][:50]
    )
    probs += "".join(
        f"<li>rejected <code>{e(x['origin'])}</code>: {e(clean('; '.join(x['reasons']), 300))}</li>"
        for x in doc["rejected"][:50]
    )
    det = ""
    if results is not None:
        det = "<h2>Hunting results</h2>"
        for cls in ("suspicious", "unusual", "lead"):
            group = [d for d in results.get("detections", []) if classification(d["nature"]) == cls]
            if not group:
                continue
            det += (
                f"<h3>{e(cls.capitalize())} ({len(group)})</h3><p><em>{e(CLASS_TEXT[cls])}</em></p>"
            )
            for d in group:
                x = d["explanation"]
                ev = "".join(
                    f"<li><code>{e(str(it.get('id', '')))}</code> {e(clean(it['label'], 200))}</li>"
                    for it in d["contributing"][:5]
                )
                det += (
                    f"<details><summary><strong>{e(clean(d['title'], 200))}</strong> — {e(d['severity'])} severity, {e(d['confidence'])} confidence "
                    f"(<code>{e(d['rule']['id'])}</code>)</summary><p>{e(clean(x['why_flagged'], 500))}</p><p>{e(clean(x['why_correlated'], 500))}</p>"
                    f"<ul>{ev}</ul><p>Possible benign causes: {e(clean('; '.join(x['possible_benign_causes']), 500))}</p></details>"
                )
        if results.get("indeterminate"):
            det += (
                "<h3>Rules that could not be evaluated</h3><ul>"
                + "".join(
                    f"<li><code>{e(i['rule']['id'])}</code>: {e(clean(i['reason'], 300))}</li>"
                    for i in results["indeterminate"]
                )
                + "</ul>"
            )
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<meta http-equiv='Content-Security-Policy' content=\"{_CSP}\">"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>Endpoint telemetry {e(h['hostname'])}</title>"
        "<style>body{font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:960px;padding:16px;color:#1b1f24;background:#fff}"
        "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd;padding:4px 8px;text-align:left}"
        ".unavailable{color:#a40000;font-weight:600}.partial{color:#8a5a00;font-weight:600}.complete{color:#1a6b2a}"
        "code{background:#eef;padding:0 3px}details{margin:8px 0;padding:6px;border:1px solid #ccd}"
        "@media (prefers-color-scheme:dark){body{background:#12151a;color:#e6e9ee}td,th,details{border-color:#445}code{background:#223}}</style></head><body>"
        f"<h1>Endpoint telemetry: {e(h['hostname'])}</h1><p><em>{e(_HEAD_NOTE)}</em></p>"
        f"<p>Host <code>{e(h['host_id'])}</code> ({e(h['os']['family'])}); collection <code>{e(clean(c['id'], 80))}</code>, {e(c['started_at'])} to {e(c['ended_at'])}, mode {e(c['mode'])}.<br>"
        f"{s['records']} records; rejected {s['rejected']}; duplicates merged {s['duplicates_merged']}; conflicts {s['conflicts']}. Complete: <strong>{'yes' if s['complete'] else 'no'}</strong></p>"
        f"<h2>Coverage</h2><table><tr><th>Category</th><th>Scope</th><th>Status</th><th>Records</th><th>Reason</th></tr>{rows}</table>"
        + (f"<h2>Collection problems</h2><ul>{probs}</ul>" if probs else "")
        + det
        + "</body></html>\n"
    )
