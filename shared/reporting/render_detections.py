"""HTML and Markdown rendering of detection results.

The HTML fragment is embedded in the assessment report by ``render_html`` (same visual language,
same Content-Security-Policy: the extra script below is part of the one pinned script).
Everything dynamic is escaped; the script reads the DOM only.
"""

from __future__ import annotations

from html import escape
from typing import Any

from shared.reporting.render_provenance import markdown as provenance_markdown
from shared.rules.render_util import md_code, md_text

SEV_ORDER = ("critical", "high", "medium", "low", "info")
NATURE_LABEL = {
    "observation": "Configuration observation",
    "indicator": "Suspicious indicator",
    "correlated": "Correlated indicators",
    "hypothesis": "Unverified hypothesis",
}
STATUS_ORDER = ("new", "acknowledged", "investigating", "resolved", "dismissed")

DET_CSS = """
.dgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-top:14px}
.dgrid h3{margin:0 0 8px;font-size:.95rem}
.mini{display:grid;grid-template-columns:96px 1fr 28px;gap:6px 8px;align-items:center;font-size:.85rem}
.mini .bar{height:10px;background:var(--info-bg);border-radius:5px;overflow:hidden}.mini .bar i{display:block;height:100%}
.mini .n{text-align:right;font-variant-numeric:tabular-nums}
.fill-n{background:var(--accent)}
details.det{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);margin:8px 0;box-shadow:var(--shadow)}
details.det>summary{cursor:pointer;padding:12px 14px;display:flex;flex-wrap:wrap;gap:8px 10px;align-items:center;list-style:none}
details.det>summary::-webkit-details-marker{display:none}
details.det>summary::before{content:"\\25B8";color:var(--muted)}details.det[open]>summary::before{content:"\\25BE"}
details.det .t{font-weight:600;flex:1 1 260px}.det .body{padding:0 16px 14px;border-top:1px solid var(--line)}
.det .body h4{margin:12px 0 4px;font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.det .body p{margin:0 0 4px}.det ul,.det ol{margin:0;padding-left:20px}
.nature{font-size:.74rem;padding:1px 8px;border-radius:99px;border:1px dashed var(--muted);color:var(--muted)}
.dstat{font-size:.74rem;font-weight:700;text-transform:uppercase;letter-spacing:.03em}
.dstat.new{color:var(--high)}.dstat.investigating{color:var(--accent)}.dstat.resolved,.dstat.dismissed{color:var(--muted)}
.note{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin:6px 0}
.dtools{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0;align-items:center}
.dtools select,.dtools input{padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--surface);color:var(--ink);font:inherit}
.dtools input{flex:1 1 220px}
"""

DET_JS = """
var dwrap=document.getElementById('detlist');
if(dwrap){var dcards=Array.prototype.slice.call(dwrap.querySelectorAll('details.det')),
dq=document.getElementById('dq'),dsel=document.getElementById('dsort'),dcount=document.getElementById('dshown'),
dact={sev:{},conf:{},status:{},nature:{}},SR={critical:4,high:3,medium:2,low:1,info:0},CR={high:2,medium:1,low:0};
function dapply(){var t=dq.value.trim().toLowerCase(),n=0;
dcards.forEach(function(c){var ok=true;Object.keys(dact).forEach(function(k){if(Object.keys(dact[k]).length&&!dact[k][c.dataset[k]])ok=false;});
if(t&&c.dataset.text.indexOf(t)<0)ok=false;c.classList.toggle('hide',!ok);if(ok)n++;});dcount.textContent=n;}
function dsort(){var k=dsel.value;dcards.slice().sort(function(a,b){var A=a.dataset,B=b.dataset,r=0;
if(k==='severity')r=SR[B.sev]-SR[A.sev];else if(k==='confidence')r=CR[B.conf]-CR[A.conf];
else if(k==='rule')r=A.rule.localeCompare(B.rule);else if(k==='status')r=A.status.localeCompare(B.status);
return r||A.title.localeCompare(B.title)||A.id.localeCompare(B.id);}).forEach(function(c){dwrap.appendChild(c);});}
dq.addEventListener('input',dapply);dsel.addEventListener('change',dsort);
document.querySelectorAll('.chip[data-dk]').forEach(function(b){b.addEventListener('click',function(){var k=b.dataset.dk,v=b.dataset.dv;
if(dact[k][v]){delete dact[k][v];b.setAttribute('aria-pressed','false');}else{dact[k][v]=1;b.setAttribute('aria-pressed','true');}dapply();});});
var dex=document.getElementById('dexpand');if(dex)dex.addEventListener('click',function(){var o=dex.dataset.open!=='1';
dcards.forEach(function(c){c.open=o;});dex.dataset.open=o?'1':'0';dex.textContent=o?'Collapse all':'Expand all';});}
"""


def e(value: Any, limit: int = 2000) -> str:
    text = "" if value is None else str(value)
    return escape(text if len(text) <= limit else text[: limit - 3] + "...", quote=True)


def _sev(s: str) -> str:
    return f'<span class="sev {e(s)}">{e(s)}</span>'


def _bars(counts: dict[str, int], order: tuple[str, ...], cls_of: Any) -> str:
    total = sum(counts.values()) or 1
    rows = "".join(
        f'<div>{cls_of(k)}</div><div class="bar" role="img" aria-label="{e(k)}: {counts.get(k, 0)}">'
        f'<i class="{"fill-" + k if k in SEV_ORDER else "fill-n"}" style="width:{100 * counts.get(k, 0) / total:.1f}%"></i></div>'
        f'<div class="n">{counts.get(k, 0)}</div>'
        for k in order
    )
    return f'<div class="mini">{rows}</div>'


def _plain(k: str) -> str:
    return f"<span>{e(k)}</span>"


def _contrib_item(c: dict[str, Any], finding_ids: set[str]) -> str:
    label = e(c["label"], 300)
    if c["type"] == "finding" and c.get("id") in finding_ids:
        label = f'<a href="#{e(c["id"])}">{label}</a>'
    extra = ""
    for a in (c.get("detail") or {}).get("attributes", [])[:4]:
        extra += f" <span class='pill'>{e(a['name'])}: {e(a.get('before'), 80)} &rarr; {e(a.get('after'), 80)}</span>"
    sev = f"{_sev(c['severity'])} " if c.get("severity") else ""
    return f"<li>{sev}{label} <span class='pill'>clause {e(c['clause'])}, {e(c['type'])}</span>{extra}</li>"


def _card(
    d: dict[str, Any], case: dict[str, Any], finding_ids: set[str], evidence_ids: set[str]
) -> str:
    x = d["explanation"]
    status = case.get("status", "new")
    text = " ".join(
        [
            d["title"],
            d["id"],
            d["rule"]["id"],
            d["rule"]["name"],
            d["category"],
            d["nature"],
            status,
            d["description"],
        ]
    ).lower()
    cond = "".join(
        f"<li><strong>{e(m['clause'])}</strong> ({m['matched_items']} item(s)){' <em>optional</em>' if m['optional'] else ''}: {e(m['description'])}"
        f"<br><span class='pill mono'>{e('; '.join(m['conditions'][:6]), 600)}</span></li>"
        for m in d["matched_conditions"]
    )
    contrib = "".join(_contrib_item(c, finding_ids) for c in d["contributing"])
    ev = (
        "".join(
            f'<li><a href="#{e(i)}"><code>{e(i)}</code></a></li>'
            if i in evidence_ids
            else f"<li><code>{e(i)}</code></li>"
            for i in d["evidence"][:40]
        )
        or "<li>No evidence items are attached to the contributing findings.</li>"
    )
    attack = "".join(
        f'<li><a href="{e(a["url"])}" rel="noreferrer noopener">{e(a["id"])}</a> '
        f'<span class="pill">({e(a["relationship"])})</span> {e(a["explanation"])}</li>'
        for a in d["references"]["attack"]
    )
    nist = ", ".join(f"{e(n['id'])} {e(n['title'])}".strip() for n in d["references"]["nist"])
    refs = (f"<ul>{attack}</ul>" if attack else "") + (
        f"<p class='pill'>NIST SP 800-53 Rev. 5: {nist}</p>" if nist else ""
    )
    related = "".join(
        f'<a href="#{e(r)}"><code>{e(r)}</code></a> ' for r in case.get("related", [])
    )
    notes = f'<div class="note">{e(case["last_note"], 400)}</div>' if case.get("last_note") else ""
    li = lambda items: "".join(f"<li>{e(i, 600)}</li>" for i in items)  # noqa: E731
    boost = list(x["missing_corroboration"])
    return (
        f'<details class="det" id="{e(d["id"])}" data-sev="{e(d["severity"])}" data-conf="{e(d["confidence"])}" data-status="{e(status)}" '
        f'data-nature="{e(d["nature"])}" data-rule="{e(d["rule"]["id"])}" data-title="{e(d["title"].lower(), 200)}" data-id="{e(d["id"])}" data-text="{e(text, 3000)}">'
        f'<summary>{_sev(d["severity"])}<span class="t">{e(d["title"], 300)}</span>'
        f'<span class="pill mono">{e(d["rule"]["id"])}</span><span class="nature">{e(NATURE_LABEL[d["nature"]])}</span>'
        f'<span class="pill">{e(d["confidence"])} confidence</span><span class="dstat {e(status)}">{e(status)}</span></summary>'
        f'<div class="body"><p class="pill">{e(x["disclaimer"])}</p>'
        f"<h4>Why it was flagged</h4><p>{e(x['why_flagged'])}</p>"
        f"<h4>How it matched</h4><p>{e(x['why_correlated'])}</p><ul>{cond}</ul>"
        f"<h4>Severity and confidence</h4><p>{e(x['severity_rationale'])}</p><p>{e(x['confidence_rationale'])}</p>"
        + (f"<h4>Caveats</h4><ul>{li(x['caveats'])}</ul>" if x["caveats"] else "")
        + f"<h4>Contributing findings and items</h4><ul>{contrib}</ul>"
        f"<h4>Evidence references</h4><ul>{ev}</ul>"
        + (f"<h4>What would improve confidence</h4><ul>{li(boost)}</ul>" if boost else "")
        + (
            f"<h4>Possible benign causes</h4><ul>{li(x['possible_benign_causes'])}</ul>"
            if x["possible_benign_causes"]
            else ""
        )
        + f"<h4>Recommended investigation</h4><ol>{li(d['investigation_steps'])}</ol>"
        f"<h4>Recommended action</h4><p>{e(d['remediation'])}</p>"
        f"<h4>Framework references</h4>{refs or '<p class=pill>None.</p>'}"
        f'<h4>Investigation</h4><p><span class="dstat {e(status)}">{e(status)}</span>'
        f"{' &middot; ' + str(case.get('notes', 0)) + ' note(s)' if case.get('notes') else ''}"
        f"{' &middot; <strong>observed again after being closed</strong>' if case.get('reappeared') else ''}"
        f"{' &middot; <strong>case sources UNVERIFIED</strong>' if case.get('verification', 'verified') != 'verified' else ''}</p>{notes}"
        + (f"<p class='pill'>Related detections: {related}</p>" if related else "")
        + f'<p class="pill">Detection <code>{e(d["id"])}</code> &middot; rule {e(d["rule"]["name"])} v{e(d["rule"]["version"])} &middot; {e(d["detected_at"])}</p>'
        "</div></details>"
    )


def detections_section(  # noqa: PLR0912 - assembling the section is one linear sequence
    results: dict[str, Any],
    cases: dict[str, dict[str, Any]] | None,
    finding_ids: set[str],
    evidence_ids: set[str],
) -> str:
    cases = cases or {}
    s = results["summary"]
    dets = results["detections"]
    kpis = "".join(
        f'<div class="card kpi"><b>{v}</b><span>{e(label)}</span></div>'
        for v, label in (
            (s["total"], "Detections"),
            (
                s["by_severity"].get("critical", 0) + s["by_severity"].get("high", 0),
                "Critical + high",
            ),
            (s["by_nature"].get("correlated", 0), "Correlated"),
            (s["indeterminate"], "Rules indeterminate"),
            (s["rule_errors"], "Rule errors"),
        )
    )
    cat_counts = dict(sorted(s["by_category"].items(), key=lambda kv: (-kv[1], kv[0])))
    dist = (
        '<div class="dgrid">'
        f'<div class="card"><h3>Severity</h3>{_bars(s["by_severity"], SEV_ORDER, _sev)}</div>'
        f'<div class="card"><h3>Confidence</h3>{_bars(s["by_confidence"], ("high", "medium", "low"), _plain)}</div>'
        f'<div class="card"><h3>Nature</h3>{_bars(s["by_nature"], tuple(NATURE_LABEL), lambda k: _plain(NATURE_LABEL[k]))}</div>'
        f'<div class="card"><h3>Categories</h3>{_bars(cat_counts, tuple(cat_counts), _plain) if cat_counts else "<p class=pill>None.</p>"}</div>'
        f'<div class="card"><h3>Affected host</h3><p><strong>{e(results["host"]["hostname"])}</strong><br>'
        f'<span class="pill mono">{e(results["host"]["host_id"])}</span><br><span class="pill">{len(dets)} detection(s) across '
        f"{len({c for d in dets for c in d['components']})} component(s)</span></p></div></div>"
    )
    chips = ""
    for key, label, values in (
        ("sev", "severity", [v for v in SEV_ORDER if s["by_severity"].get(v)]),
        ("conf", "confidence", [v for v in ("high", "medium", "low") if s["by_confidence"].get(v)]),
        ("nature", "nature", [v for v in NATURE_LABEL if s["by_nature"].get(v)]),
        (
            "status",
            "status",
            [
                v
                for v in STATUS_ORDER
                if any(cases.get(d["id"], {}).get("status", "new") == v for d in dets)
            ],
        ),
    ):
        chips += "".join(
            f'<button class="chip" type="button" data-dk="{key}" data-dv="{e(v)}" aria-pressed="false">{e(label)}: {e(v)}</button>'
            for v in values
        )
    cards = (
        "".join(_card(d, cases.get(d["id"], {}), finding_ids, evidence_ids) for d in dets)
        or '<div class="card">No detections.</div>'
    )
    tools = (
        '<div class="dtools"><input id="dq" type="search" placeholder="Filter detections by text, rule or id" aria-label="Filter detections">'
        '<label class="pill" for="dsort">Sort by</label><select id="dsort" aria-label="Sort detections">'
        '<option value="severity">Severity</option><option value="confidence">Confidence</option><option value="rule">Rule</option>'
        '<option value="status">Status</option><option value="title">Title</option></select>'
        f'<button class="chip" id="dexpand" type="button" data-open="0">Expand all</button></div><div class="dtools">{chips}</div>'
    )
    ind = ""
    if results["indeterminate"]:
        rows = "".join(
            f"<li><strong>{e(i['rule']['id'])}</strong> {e(i['rule']['name'])}: {e(i['reason'], 400)}</li>"
            for i in results["indeterminate"]
        )
        ind = f'<div class="card" style="margin-top:14px"><h3>Rules that could not reach a conclusion ({len(results["indeterminate"])})</h3><p class="pill">Not evaluated is not the same as clean: the data these rules need was missing or incomplete.</p><ul>{rows}</ul></div>'
    errs = ""
    if results["rule_errors"]:
        rows = "".join(
            f"<li><strong>{e(r['code'])}</strong> {e(r['rule'])}: {e(r['message'], 400)}</li>"
            for r in results["rule_errors"][:50]
        )
        errs = f'<div class="card" style="margin-top:14px"><h3>Rule errors ({len(results["rule_errors"])})</h3><ul>{rows}</ul></div>'
    h = results["history"]
    meta = (
        f'<p class="pill">{results["rules"]["evaluated"]} of {results["rules"]["total"]} rules evaluated; {h["snapshots"]} earlier snapshot(s) available'
        + (f"; compared with {e(h['compared_with'])}" if h["compared_with"] else "")
        + ". A detection is a lead for investigation, not a verdict.</p>"
    )
    return (
        f'<section id="detections"><h2>Detections (<span id="dshown">{len(dets)}</span> of {len(dets)} shown)</h2>{meta}'
        f'<div class="kpis">{kpis}</div>{dist}{tools}<div id="detlist">{cards}</div>{ind}{errs}</section>'
    )


# ----------------------------------------------------------------------------------- Markdown


def render_detections_markdown(  # noqa: PLR0912 - one linear sequence of report sections
    results: dict[str, Any], cases: dict[str, dict[str, Any]] | None = None
) -> str:
    cases = cases or {}
    s = results["summary"]
    h = results["host"]
    prov = provenance_markdown(("detections", results))
    lines = [
        "# BlueOps detection report", "",
        *(prov[:2] if prov and prov[0].startswith("> **WARNING") else []),
        f"_Generated {md_text(results['generated_at'])}_ · host **{md_text(h['hostname'])}** ({md_text(h['os_family'])}) · assessment {md_code(results['assessment']['id'])}", "",
        "> A detection is a lead for investigation, not a verdict. See each detection's *nature* and disclaimer.", "",
        "## Overview", "",
        f"- {s['total']} detection(s): " + ", ".join(f"{s['by_severity'].get(k, 0)} {k}" for k in SEV_ORDER if s["by_severity"].get(k)) + ("" if s["total"] else "none"),
        "- Confidence: " + ", ".join(f"{s['by_confidence'].get(k, 0)} {k}" for k in ("high", "medium", "low")),
        "- Nature: " + ", ".join(f"{s['by_nature'].get(k, 0)} {k}" for k in NATURE_LABEL),
        f"- Rules: {results['rules']['evaluated']} evaluated of {results['rules']['total']}; {results['rules']['indeterminate']} indeterminate, {results['rules']['not_applicable']} not applicable, {results['rules']['disabled']} disabled, {results['rules']['error']} failed",
        f"- History: {results['history']['snapshots']} earlier snapshot(s)" + (f", compared with {md_code(results['history']['compared_with'])}" if results["history"]["compared_with"] else ""),
        "",
    ]  # fmt: skip
    lines += prov[2:] if prov and prov[0].startswith("> **WARNING") else prov
    if s["by_category"]:
        lines += (
            ["| Category | Detections |", "|---|---|"]
            + [f"| {md_text(k)} | {v} |" for k, v in sorted(s["by_category"].items())]
            + [""]
        )
    lines += ["## Detections", ""]
    if not results["detections"]:
        lines += ["No detections.", ""]
    for d in results["detections"]:
        c = cases.get(d["id"], {})
        x = d["explanation"]
        lines += [
            f"### {md_text(d['severity']).upper()} · {md_text(d['title'], 200)}", "",
            f"- Detection {md_code(d['id'])} · rule {md_code(d['rule']['id'])} v{md_text(d['rule']['version'])} · **{md_text(NATURE_LABEL[d['nature']])}**",
            f"- Confidence: {md_text(d['confidence'])} · category {md_text(d['category'])} · status **{md_text(c.get('status', 'new'))}**" + (" · observed again after being closed" if c.get("reappeared") else "")
            + (
                ""
                if c.get("verification", "verified") == "verified"
                else " · **case sources UNVERIFIED**"
            ),
            f"- Why flagged: {md_text(x['why_flagged'], 800)}",
            f"- How it matched: {md_text(x['why_correlated'], 800)}",
            f"- Severity: {md_text(x['severity_rationale'], 600)}",
            f"- Confidence: {md_text(x['confidence_rationale'], 600)}",
            f"- _{md_text(x['disclaimer'])}_",
        ]  # fmt: skip
        if x["caveats"]:
            lines.append("- Caveats: " + "; ".join(md_text(v, 300) for v in x["caveats"]))
        lines += ["", "Matched conditions:", ""]
        lines += [
            f"- `{md_text(m['clause'])}` ({m['matched_items']} item(s)): {md_text(m['description'])}: "
            + md_code("; ".join(m["conditions"][:6]), 500)
            for m in d["matched_conditions"]
        ]
        lines += ["", "Contributing items:", ""]
        for ci in d["contributing"]:
            extra = ""
            for a in (ci.get("detail") or {}).get("attributes", [])[:4]:
                extra += f" ({md_text(a['name'])}: {md_text(a.get('before'), 60)} -> {md_text(a.get('after'), 60)})"
            lines.append(
                f"- {md_text(ci['label'], 200)} [{md_text(ci['type'])}, clause {md_text(ci['clause'])}]{extra}"
                + (f" {md_code(ci['id'])}" if ci.get("id") else "")
            )
        if d["evidence"]:
            lines += ["", "Evidence: " + ", ".join(md_code(i) for i in d["evidence"][:20])]
        if x["missing_corroboration"]:
            lines += ["", "Would improve confidence:", ""] + [
                f"- {md_text(v, 300)}" for v in x["missing_corroboration"]
            ]
        lines += ["", "Investigate:", ""] + [
            f"{i}. {md_text(v, 300)}" for i, v in enumerate(d["investigation_steps"], 1)
        ]
        lines += ["", f"Action: {md_text(d['remediation'], 600)}", ""]
        refs = [
            f"[{a['id']}]({a['url']}) ({a['relationship']}): {md_text(a['explanation'], 250)}"
            for a in d["references"]["attack"]
        ]
        if refs or d["references"]["nist"]:
            lines += ["References:", ""] + [f"- ATT&CK {r}" for r in refs]
            if d["references"]["nist"]:
                lines.append(
                    "- NIST SP 800-53 Rev. 5: "
                    + ", ".join(md_text(n["id"]) for n in d["references"]["nist"])
                )
            lines.append("")
        if c.get("last_note"):
            lines += [f"Latest analyst note: {md_text(c['last_note'], 400)}", ""]
    if results["indeterminate"]:
        lines += [
            "## Rules that could not reach a conclusion",
            "",
            "Not evaluated is not the same as clean.",
            "",
        ]
        lines += [
            f"- {md_code(i['rule']['id'])} {md_text(i['rule']['name'])}: {md_text(i['reason'], 300)}"
            for i in results["indeterminate"]
        ] + [""]
    if results["rule_errors"]:
        lines += (
            ["## Rule errors", ""]
            + [
                f"- {md_text(r['code'])} {md_text(r['rule'])}: {md_text(r['message'], 300)}"
                for r in results["rule_errors"][:50]
            ]
            + [""]
        )
    return "\n".join(lines).rstrip() + "\n"
