"""Self-contained HTML report renderer.

One file, no network: styles and a small filtering script are inline, there are no external
fonts, images or scripts. The page carries a Content-Security-Policy that forbids everything
except its own inline style and its own script (pinned by SHA-256), so even a value that
escaped HTML escaping could not load or run anything else.

All dynamic values go through ``html.escape``; the script reads the DOM and never evaluates
report data.
"""

from __future__ import annotations

import base64
import hashlib
from html import escape
from typing import Any

from shared.reporting.render_common import (
    PRIORITY_LABEL,
    SEVERITIES,
    executive_summary,
    findings_by_category,
    remediation_plan,
)

CSS = """
:root{--bg:#f5f6f8;--surface:#fff;--ink:#1b2430;--muted:#5b6675;--line:#d9dee6;--accent:#1d4ed8;
--critical:#9b1c1c;--high:#c2410c;--medium:#a16207;--low:#1d4ed8;--info:#64748b;
--critical-bg:#fde8e8;--high-bg:#ffedd5;--medium-bg:#fef3c7;--low-bg:#dbeafe;--info-bg:#e8ecf1;
--radius:10px;--shadow:0 1px 2px rgba(15,23,42,.08),0 2px 8px rgba(15,23,42,.05)}
@media (prefers-color-scheme:dark){:root{--bg:#0f141b;--surface:#18202b;--ink:#e6ebf2;--muted:#9aa7b8;
--line:#2a3544;--accent:#7aa2ff;--critical:#ff8a8a;--high:#ffb072;--medium:#f3cf6b;--low:#8fb4ff;--info:#a3afbf;
--critical-bg:#3a1b1d;--high-bg:#3a2616;--medium-bg:#352c10;--low-bg:#17284a;--info-bg:#232d3b;--shadow:none}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88em;word-break:break-all}
.wrap{max-width:1120px;margin:0 auto;padding:0 16px 56px}
header.top{background:linear-gradient(135deg,#0f2747,#1d4ed8);color:#fff;padding:28px 0 22px}
header.top .wrap{padding-bottom:0}
header.top h1{margin:0 0 4px;font-size:1.6rem;letter-spacing:-.01em}
header.top p{margin:0;opacity:.85}
nav.toc{position:sticky;top:0;z-index:5;background:var(--surface);border-bottom:1px solid var(--line);overflow-x:auto;white-space:nowrap}
nav.toc .wrap{padding-bottom:0;display:flex;gap:4px}
nav.toc a{display:inline-block;padding:10px 12px;text-decoration:none;color:var(--muted);font-weight:600;font-size:.88rem}
nav.toc a:hover{color:var(--ink)}
section{margin-top:28px}h2{font-size:1.2rem;margin:0 0 12px;scroll-margin-top:56px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:16px}
.posture{border-left:6px solid var(--info);display:flex;flex-direction:column;gap:6px}
.posture.critical{border-left-color:var(--critical)}.posture.high{border-left-color:var(--high)}
.posture.medium{border-left-color:var(--medium)}.posture.low{border-left-color:var(--low)}
.posture h3{margin:0;font-size:1.25rem}.posture ul{margin:4px 0 0;padding-left:20px}
.caveat{margin-top:12px;padding:12px 14px;border-radius:8px;background:var(--medium-bg);color:var(--ink);border:1px solid var(--line)}
.caveat strong{display:block;margin-bottom:4px}.caveat ul{margin:0;padding-left:20px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:14px}
.kpi{padding:14px}.kpi b{display:block;font-size:1.8rem;line-height:1.1}.kpi span{color:var(--muted);font-size:.85rem}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:14px}
dl.meta{margin:0;display:grid;grid-template-columns:max-content 1fr;gap:6px 14px}
dl.meta dt{color:var(--muted)}dl.meta dd{margin:0;overflow-wrap:anywhere}
.dist{display:grid;grid-template-columns:84px 1fr 40px;gap:8px 10px;align-items:center}
.dist .bar{height:14px;background:var(--info-bg);border-radius:7px;overflow:hidden}
.dist .bar i{display:block;height:100%;border-radius:7px}
.dist .n{text-align:right;font-variant-numeric:tabular-nums}
.stack{display:flex;height:16px;border-radius:8px;overflow:hidden;margin-bottom:14px;background:var(--info-bg)}
.stack i{display:block;height:100%}
.sev{display:inline-block;padding:1px 9px;border-radius:99px;font-size:.74rem;font-weight:700;letter-spacing:.03em;text-transform:uppercase;border:1px solid currentColor}
.sev.critical{color:var(--critical);background:var(--critical-bg)}.sev.high{color:var(--high);background:var(--high-bg)}
.sev.medium{color:var(--medium);background:var(--medium-bg)}.sev.low{color:var(--low);background:var(--low-bg)}
.sev.info{color:var(--info);background:var(--info-bg)}
.fill-critical{background:var(--critical)}.fill-high{background:var(--high)}.fill-medium{background:var(--medium)}
.fill-low{background:var(--low)}.fill-info{background:var(--info)}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--radius);background:var(--surface)}
table{border-collapse:collapse;width:100%;min-width:560px}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);background:var(--bg)}tr:last-child td{border-bottom:0}
.status{font-weight:600}.status.ok{color:var(--low)}.status.partial,.status.skipped{color:var(--medium)}
.status.failed,.status.timeout,.status.invalid_output{color:var(--critical)}
.prio{display:grid;gap:12px}.prio h3{margin:0 0 6px;font-size:1rem}.prio h3 small{color:var(--muted);font-weight:400}
.prio ul{margin:0;padding-left:20px}.prio li{margin:4px 0}
.tools{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px;align-items:center}
.tools input[type=search]{flex:1 1 220px;padding:9px 12px;border-radius:8px;border:1px solid var(--line);background:var(--surface);color:var(--ink);font:inherit}
.chip{padding:6px 12px;border-radius:99px;border:1px solid var(--line);background:var(--surface);color:var(--ink);font:inherit;font-size:.85rem;cursor:pointer}
.chip[aria-pressed=true]{background:var(--accent);color:#fff;border-color:var(--accent)}
.chip:focus-visible,input:focus-visible,summary:focus-visible,a:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
details.finding{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);margin:8px 0;box-shadow:var(--shadow)}
details.finding>summary{cursor:pointer;padding:12px 14px;display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;list-style:none}
details.finding>summary::-webkit-details-marker{display:none}
details.finding>summary::before{content:"\\25B8";color:var(--muted)}details.finding[open]>summary::before{content:"\\25BE"}
details.finding .t{font-weight:600;flex:1 1 260px}.finding .body{padding:0 16px 14px;border-top:1px solid var(--line)}
.finding .body h4{margin:12px 0 4px;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.finding .body p{margin:0}.finding ul{margin:0;padding-left:20px}
.pill{font-size:.78rem;color:var(--muted)}.catname{margin:22px 0 4px;font-size:1rem;text-transform:capitalize}
.hide{display:none!important}
.cmp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:10px 0}
.cmp-grid div{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;text-align:center}
.cmp-grid b{display:block;font-size:1.4rem}.cmp-grid span{font-size:.78rem;color:var(--muted)}
.trend{font-weight:700;text-transform:uppercase}.trend.worse{color:var(--critical)}.trend.better{color:var(--low)}
footer{margin-top:36px;color:var(--muted);font-size:.85rem}
@media (max-width:560px){header.top h1{font-size:1.3rem}.dist{grid-template-columns:70px 1fr 32px}dl.meta{grid-template-columns:1fr}dl.meta dt{margin-top:6px}}
@media print{nav.toc,.tools{display:none}body{background:#fff}details.finding{break-inside:avoid}header.top{background:#fff;color:#000}}
"""

JS = """(function(){
var q=document.getElementById('q'),chips=document.querySelectorAll('.chip[data-sev]'),
cards=document.querySelectorAll('details.finding'),cats=document.querySelectorAll('.catgroup'),
count=document.getElementById('shown'),active={};
function apply(){var term=q?q.value.trim().toLowerCase():'',any=Object.keys(active).length,n=0;
cards.forEach(function(c){var ok=(!any||active[c.dataset.sev])&&(!term||c.dataset.text.indexOf(term)>-1);
c.classList.toggle('hide',!ok);if(ok)n++;});
cats.forEach(function(g){g.classList.toggle('hide',!g.querySelector('details.finding:not(.hide)'));});
if(count)count.textContent=n;}
if(q)q.addEventListener('input',apply);
chips.forEach(function(b){b.addEventListener('click',function(){var s=b.dataset.sev;
if(active[s]){delete active[s];b.setAttribute('aria-pressed','false');}else{active[s]=1;b.setAttribute('aria-pressed','true');}apply();});});
var ex=document.getElementById('expand');if(ex)ex.addEventListener('click',function(){var open=ex.dataset.open!=='1';
cards.forEach(function(c){c.open=open;});ex.dataset.open=open?'1':'0';ex.textContent=open?'Collapse all':'Expand all';});
})();"""


def _csp() -> str:
    digest = base64.b64encode(hashlib.sha256(JS.encode("utf-8")).digest()).decode("ascii")
    return (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-" + digest + "'; "
        "img-src data:; base-uri 'none'; form-action 'none'"
    )


def e(value: Any, limit: int = 2000) -> str:
    text = "" if value is None else str(value)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return escape(text, quote=True)


def _sev(sev: str) -> str:
    return f'<span class="sev {e(sev)}">{e(sev)}</span>'


def _table(headers: list[str], rows: list[list[str]], cls: str = "") -> str:
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tablewrap"><table class="{cls}"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _distribution(summary: dict[str, Any]) -> str:
    total = summary["total"]
    sev = summary["by_severity"]
    stack = "".join(
        f'<i class="fill-{k}" style="width:{100 * sev[k] / total:.2f}%" title="{k}: {sev[k]}"></i>'
        for k in SEVERITIES
        if sev[k] and total
    )
    rows = "".join(
        f'<div>{_sev(k)}</div><div class="bar" role="img" aria-label="{k}: {sev[k]} of {total}">'
        f'<i class="fill-{k}" style="width:{(100 * sev[k] / total) if total else 0:.2f}%"></i></div>'
        f'<div class="n">{sev[k]}</div>'
        for k in SEVERITIES
    )
    return f'<div class="stack" aria-hidden="true">{stack}</div><div class="dist">{rows}</div>'


def _finding(f: dict[str, Any], ev: dict[str, dict[str, Any]]) -> str:
    text = " ".join(
        [
            f["title"],
            f["check_id"],
            f["id"],
            f["description"],
            f["category"],
            f["remediation"]["summary"],
        ]
        + [ev[i]["ref"] for i in f["evidence"] if i in ev]
    ).lower()
    parts = [
        f'<details class="finding" data-sev="{e(f["severity"])}" data-text="{e(text, 4000)}">',
        f'<summary>{_sev(f["severity"])}<span class="t">{e(f["title"], 300)}</span>'
        f'<span class="pill mono">{e(f["check_id"])}</span>'
        f'<span class="pill">{e(f["remediation"]["priority"])} &middot; {e(f["confidence"])} confidence</span></summary>',
        '<div class="body">',
        f"<h4>Description</h4><p>{e(f['description'])}</p>",
    ]
    if f["remediation"]["summary"]:
        parts.append(f"<h4>Remediation</h4><p>{e(f['remediation']['summary'])}</p>")
    if f["evidence"]:
        items = []
        for eid in f["evidence"][:15]:
            item = ev.get(eid)
            if item is None:
                continue
            ex = (
                f' <span class="pill">&ndash; {e(item["excerpts"][0], 200)}</span>'
                if item.get("excerpts")
                else ""
            )
            items.append(f'<li><a href="#{e(eid)}"><code>{e(item["ref"], 300)}</code></a>{ex}</li>')
        more = (
            f'<li class="pill">{len(f["evidence"]) - 15} more in the evidence index</li>'
            if len(f["evidence"]) > 15
            else ""
        )
        parts.append(f"<h4>Evidence</h4><ul>{''.join(items)}{more}</ul>")
    if f["standards"]:
        std = []
        for s in f["standards"]:
            label = e(
                f"{s['framework']} {s['id']}" + (f" ({s['title']})" if s.get("title") else "")
            )
            if s.get("url", "").startswith("https://attack.mitre.org/"):
                std.append(
                    f'<li><a href="{e(s["url"])}" rel="noreferrer noopener">{label}</a></li>'
                )
            else:
                std.append(f"<li>{label}</li>")
        parts.append(f"<h4>Standards</h4><ul>{''.join(std)}</ul>")
    srcs = ", ".join(sorted({s["module"] for s in f["sources"]}))
    parts.append(
        f'<h4>Provenance</h4><p class="pill">Id <code>{e(f["id"])}</code> &middot; {e(f["component"])} on '
        f"{e(f['host']['hostname'])} &middot; detected {e(f['detected_at'])} &middot; reported by {e(srcs)}</p>"
    )
    parts.append("</div></details>")
    return "".join(parts)


def _comparison(c: dict[str, Any]) -> str:
    s = c["summary"]
    tiles = "".join(
        f"<div><b>{s[k]}</b><span>{e(label)}</span></div>"
        for k, label in (
            ("new", "New"),
            ("resolved", "Resolved"),
            ("persistent", "Persistent"),
            ("severity_increased", "Severity up"),
            ("severity_decreased", "Severity down"),
            ("configuration_changes", "Config changes"),
            ("indeterminate", "Indeterminate"),
        )
    )
    w = s["weighted_index"]
    out = [
        '<div class="card">',
        f"<p><strong>{e(c['baseline']['started_at'])}</strong> &rarr; <strong>{e(c['current']['started_at'])}</strong>"
        f' &middot; trend <span class="trend {e(s["trend"])}">{e(s["trend"])}</span>'
        f" &middot; weighted index {w['baseline']} &rarr; {w['current']} ({w['delta']:+d})</p>",
        f'<div class="cmp-grid">{tiles}</div>',
    ]
    for title, key in (
        ("New findings", "new"),
        ("Resolved findings", "resolved"),
        ("Severity changed", "severity_changed"),
    ):
        items = c["findings"][key]
        if items:
            lis = "".join(
                f"<li>{_sev(i['severity'])} {e(i['title'], 200)} <span class='pill mono'>{e(i['check_id'])}</span>"
                + (
                    f" <span class='pill'>was {e(i['baseline_severity'])}</span>"
                    if key == "severity_changed"
                    else ""
                )
                + "</li>"
                for i in items[:50]
            )
            out.append(f"<h3>{title} ({len(items)})</h3><ul>{lis}</ul>")
    moved = [
        p for p in c["findings"]["persistent"] if p["evidence"]["added"] or p["evidence"]["removed"]
    ]
    if moved:
        lis = "".join(
            f"<li>{_sev(p['severity'])} {e(p['title'], 200)} "
            f"<span class='pill'>+{len(p['evidence']['added'])} / -{len(p['evidence']['removed'])} "
            "evidence</span></li>"
            for p in moved[:50]
        )
        out.append(
            f"<h3>Persistent findings with changed evidence ({len(moved)})</h3><ul>{lis}</ul>"
        )
    cfg = c["configuration"]
    if cfg["available"] and cfg["changes"]:
        lis = "".join(
            f"<li>{e(ch.get('change', ''))}: <code>{e(ch.get('domain', ''))}/{e(ch.get('key', ''))}</code></li>"
            for ch in cfg["changes"][:50]
        )
        out.append(f"<h3>Configuration changes ({len(cfg['changes'])})</h3><ul>{lis}</ul>")
    elif not cfg["available"]:
        out.append(f"<p class='pill'>Configuration comparison unavailable: {e(cfg['reason'])}</p>")
    for wn in c["warnings"]:
        out.append(f"<p class='pill'>Warning {e(wn['code'])}: {e(wn['message'])}</p>")
    cov = c["coverage"]["modules"]
    if cov["added"] or cov["removed"] or cov["changed"]:
        out.append(
            f"<p class='pill'>Coverage differences: {len(cov['added'])} module(s) added, "
            f"{len(cov['removed'])} removed, {len(cov['changed'])} changed status.</p>"
        )
    out.append("</div>")
    return "".join(out)


def render_html(
    doc: dict[str, Any], comparisons: list[dict[str, Any]] | None = None, generated_at: str = ""
) -> str:
    ex = executive_summary(doc, comparisons)
    a, s = doc["assessment"], doc["summary"]
    host = doc.get("host")
    ev = {x["id"]: x for x in doc["evidence"]}
    sev = s["by_severity"]
    title = f"BlueOps assessment - {host['hostname']}" if host else "BlueOps assessment"

    kpis = "".join(
        f'<div class="card kpi"><b>{v}</b><span>{e(label)}</span></div>'
        for v, label in (
            (s["total"], "Findings"),
            (s["by_priority"]["P1"], "P1 act now"),
            (sev["critical"] + sev["high"], "Critical + high"),
            (f"{s['modules']['ok']}/{sum(s['modules'].values())}", "Modules clean"),
            (s["evidence_items"], "Evidence items"),
        )
    )
    caveat = ""
    if ex["caveats"]:
        lis = "".join(f"<li>{e(c, 500)}</li>" for c in ex["caveats"])
        caveat = (
            '<div class="caveat" role="note"><strong>Coverage caveats &mdash; no finding does not mean no problem</strong>'
            f"<ul>{lis}</ul></div>"
        )
    bullets = "".join(f"<li>{e(b, 500)}</li>" for b in ex["bullets"])

    meta = [
        ("Assessment id", a["id"]),
        ("Profile", a["profile"]),
        ("Started", a["started_at"]),
        ("Finished", a["finished_at"]),
        ("Status", a["status"]),
        ("Exit code", a["exit_code"]),
        ("Fail threshold", a["fail_on"]),
        ("Engine", f"{doc['engine']['name']} {doc['engine']['version']}"),
        ("Mode", a["mode"]),
    ]
    meta_html = "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in meta)
    if host:
        priv = {True: "yes", False: "no"}.get(host.get("elevated"), "unknown")
        host_rows = [
            ("Hostname", host["hostname"]),
            ("Operating system", f"{host['os']['name']} {host['os']['version']}"),
            ("Family", host["os"]["family"]),
            ("Architecture", host.get("arch", "")),
            ("Collected as", host.get("user", "unknown")),
            ("Privileged", priv),
        ]
        host_html = "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in host_rows)
    else:
        host_html = "<dt>Host</dt><dd>unavailable (no module produced a report)</dd>"

    modules = _table(
        ["Module", "Status", "Findings", "Seconds", "Note"],
        [
            [
                f"<code>{e(m['id'])}</code>",
                f'<span class="status {e(m["status"])}">{e(m["status"])}</span>',
                str(m["findings"]),
                f"{m['duration_seconds']:.1f}",
                e(m.get("reason", ""), 300),
            ]
            for m in doc["modules"]
        ],
    )

    prio_html = []
    for prio, items in remediation_plan(doc).items():
        if items:
            lis = "".join(
                f"<li>{_sev(f['severity'])} <strong>{e(f['title'], 200)}</strong> "
                f"<span class='pill mono'>{e(f['check_id'])}</span><br>{e(f['remediation']['summary'], 600)}</li>"
                for f in items
            )
            prio_html.append(
                f'<div class="card"><h3>{e(prio)} <small>{e(PRIORITY_LABEL[prio])} ({len(items)})</small></h3><ul>{lis}</ul></div>'
            )
    prio_block = "".join(prio_html) or '<div class="card">No remediation actions.</div>'

    chips = "".join(
        f'<button class="chip" type="button" data-sev="{k}" aria-pressed="false">{k} ({sev[k]})</button>'
        for k in SEVERITIES
        if sev[k]
    )
    groups = []
    for cat, items in findings_by_category(doc):
        cards = "".join(_finding(f, ev) for f in items)
        groups.append(
            f'<div class="catgroup"><h3 class="catname">{e(cat)} ({len(items)})</h3>{cards}</div>'
        )
    findings_html = "".join(groups) or '<div class="card">No findings.</div>'

    ev_rows = [
        [
            f'<code id="{e(x["id"])}">{e(x["id"])}</code>',
            e(x["type"]),
            f"<code>{e(x['ref'], 400)}</code>",
            f"<code>{e(x['sha256'][:16])}&hellip;</code>" if x.get("sha256") else "",
            e(", ".join(sorted({p["module"] for p in x["provenance"]}))),
            e(x["provenance"][0]["collected_at"]),
        ]
        for x in doc["evidence"]
    ]
    evidence_html = (
        _table(["Id", "Type", "Reference", "SHA-256", "Collected by", "Collected at"], ev_rows)
        if ev_rows
        else '<div class="card">No evidence recorded.</div>'
    )

    history = "".join(_comparison(c) for c in comparisons or []) or (
        '<div class="card">No earlier snapshot supplied. Re-run with <code>--compare</code> '
        "to see new, resolved and persistent findings.</div>"
    )

    problems = [
        f"<li><strong>{e(x['code'])}</strong> ({e(x['module'])}): {e(x['message'], 500)}</li>"
        for x in doc["errors"][:100]
    ]
    problems += [
        f"<li><strong>{e(x['code'])}</strong>: {e(x['message'], 500)}</li>" for x in doc["warnings"]
    ]
    problems_html = f"<ul>{''.join(problems)}</ul>" if problems else "<p>None.</p>"

    nav = "".join(
        f'<a href="#{i}">{t}</a>'
        for i, t in (
            ("summary", "Summary"),
            ("metadata", "Metadata"),
            ("modules", "Modules"),
            ("priorities", "Priorities"),
            ("findings", "Findings"),
            ("evidence", "Evidence"),
            ("history", "History"),
            ("problems", "Problems"),
        )
    )
    stamp = f" &middot; generated {e(generated_at)}" if generated_at else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{e(_csp())}">
<meta name="color-scheme" content="light dark">
<title>{e(title)}</title>
<style>{CSS}</style>
</head>
<body>
<header class="top"><div class="wrap">
<h1>BlueOps assessment report</h1>
<p>{e(host["hostname"]) if host else "unidentified host"} &middot; profile {e(a["profile"])} &middot; read-only{stamp}</p>
</div></header>
<nav class="toc" aria-label="Sections"><div class="wrap">{nav}</div></nav>
<main class="wrap">
<section id="summary"><h2>Executive summary</h2>
<div class="card posture {e(ex["key"])}"><h3>{e(ex["headline"])}</h3><ul>{bullets}</ul></div>
{caveat}
<div class="kpis">{kpis}</div>
<div class="card" style="margin-top:14px"><h2 style="font-size:1rem">Severity distribution</h2>{_distribution(s)}</div>
</section>
<section id="metadata"><h2>Assessment metadata and host</h2>
<div class="grid2"><div class="card"><dl class="meta">{meta_html}</dl></div><div class="card"><dl class="meta">{host_html}</dl></div></div>
</section>
<section id="modules"><h2>Module results</h2>{modules}</section>
<section id="priorities"><h2>Remediation priorities</h2><div class="prio">{prio_block}</div></section>
<section id="findings"><h2>Findings breakdown (<span id="shown">{s["total"]}</span> of {s["total"]} shown)</h2>
<div class="tools"><input id="q" type="search" placeholder="Filter by text, check id or path" aria-label="Filter findings">{chips}
<button class="chip" id="expand" type="button" data-open="0">Expand all</button></div>
{findings_html}</section>
<section id="evidence"><h2>Evidence index</h2>{evidence_html}</section>
<section id="history"><h2>Historical comparison</h2>{history}</section>
<section id="problems"><h2>Errors and warnings</h2><div class="card">{problems_html}</div></section>
<footer>Generated by BlueOps (read-only). Findings are leads for investigation, not verdicts. For systems you are authorized to administer.</footer>
</main>
<script>{JS}</script>
</body>
</html>
"""
