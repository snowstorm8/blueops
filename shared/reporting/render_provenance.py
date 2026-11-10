"""Render input provenance (``inputs_verified`` / ``inputs``) in text, Markdown and HTML.

An unverified input is shown as a warning **at the top** of the report and again per input in a
table; verified inputs are listed too, so a reader can see what the verdict covers. A document
that records no provenance at all (written before the field existed) shows nothing, because
saying "verified" without a record would be a claim nobody checked.
"""

from __future__ import annotations

from html import escape
from typing import Any

from shared.engine.provenance import gather
from shared.rules.render_util import md_code, md_text

MAX_ROWS = 60
WARNING = (
    "UNVERIFIED INPUTS. At least one input was not checked against a manifest "
    "(--allow-unverified), so its content may have been altered. Treat the results below as "
    "unverified until the inputs are checked another way."
)
OK_LINE = "All recorded inputs were verified against their manifests."


def _rows(named: tuple[tuple[str, Any], ...]) -> tuple[bool | None, list[dict[str, Any]]]:
    overall, rows = gather(*named)
    rows.sort(key=lambda r: bool(r["verified"]))  # unverified first
    return overall, rows


def _state(r: dict[str, Any]) -> str:
    return "verified" if r["verified"] else "UNVERIFIED: " + str(r.get("reason", ""))


def text(*named: tuple[str, Any]) -> list[str]:
    overall, rows = _rows(named)
    if overall is None:
        return []
    out = [("WARNING: " + WARNING) if not overall else OK_LINE]
    for r in rows[:MAX_ROWS]:
        via = f" (via {r['via']})" if r.get("via") else ""
        out.append(f"  [{_state(r)}] {r['document']}/{r['role']}: {r['path']}{via}")
    if len(rows) > MAX_ROWS:
        out.append(f"  ... and {len(rows) - MAX_ROWS} more")
    return out


def markdown(*named: tuple[str, Any]) -> list[str]:
    overall, rows = _rows(named)
    if overall is None:
        return []
    lines = [f"> **WARNING - {md_text(WARNING, 700)}**", ""] if not overall else []
    lines += ["## Input provenance", ""]
    lines += [md_text(OK_LINE) if overall else "**Not all inputs were verified.**", ""]
    if rows:
        lines += ["| Document | Role | Input | Status |", "|---|---|---|---|"]
        for r in rows[:MAX_ROWS]:
            path = md_code(r["path"]) + (f" via {md_code(r['via'])}" if r.get("via") else "")
            status = "verified" if r["verified"] else "**UNVERIFIED** - " + md_text(r.get("reason"))
            lines.append(f"| {md_text(r['document'])} | {md_text(r['role'])} | {path} | {status} |")
        if len(rows) > MAX_ROWS:
            lines.append(f"\n_{len(rows) - MAX_ROWS} more input(s) not shown; see the JSON._")
        lines.append("")
    return lines


def html(*named: tuple[str, Any]) -> tuple[str, str]:
    """``(banner, section)``: the banner goes at the top of the page, the section lower down."""
    overall, rows = _rows(named)
    if overall is None:
        return "", ""
    e = escape
    banner = ""
    if not overall:
        banner = f'<div class="caveat prov-bad" role="alert"><strong>{e(WARNING)}</strong></div>'
    body = "".join(
        '<tr><td>{}</td><td>{}</td><td><code>{}</code>{}</td><td class="{}">{}</td></tr>'.format(
            e(str(r["document"])),
            e(str(r["role"])),
            e(str(r["path"])),
            f" via <code>{e(str(r['via']))}</code>" if r.get("via") else "",
            "prov-ok" if r["verified"] else "prov-bad",
            "verified" if r["verified"] else "UNVERIFIED &mdash; " + e(str(r.get("reason", ""))),
        )
        for r in rows[:MAX_ROWS]
    )
    more = (
        f"<p>{len(rows) - MAX_ROWS} more input(s) not shown; see the JSON.</p>"
        if len(rows) > MAX_ROWS
        else ""
    )
    section = (
        '<section id="provenance"><h2>Input provenance</h2><div class="card">'
        f"<p>{e(OK_LINE) if overall else '<strong>Not all inputs were verified.</strong>'}</p>"
        + (
            "<table><thead><tr><th>Document</th><th>Role</th><th>Input</th><th>Status</th></tr></thead>"
            f"<tbody>{body}</tbody></table>"
            if rows
            else ""
        )
        + more
        + "</div></section>"
    )
    return banner, section
