"""Text, Markdown and self-contained HTML views of validation documents.

Rules for every view: failures are never hidden behind aggregates, an undefined metric is shown as
"n/a" with its reason (never 0 or 100%), counts accompany every ratio, and all values are escaped
for their medium. The HTML carries a Content-Security-Policy and no script; charts are inline SVG.
"""

from __future__ import annotations

import html
from typing import Any

from shared.findings.model import clean
from shared.rules.render_util import md_code, md_text

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"
STATUS_ORDER = ("pass", "known_issue", "inconclusive", "skipped", "error", "fail")
STATUS_COLOR = {
    "pass": "var(--ok)",
    "known_issue": "var(--known)",
    "inconclusive": "var(--warn)",
    "skipped": "var(--muted)",
    "error": "var(--err)",
    "fail": "var(--bad)",
}
OUTCOME_ORDER = (
    "true_positive",
    "true_negative",
    "expected_inconclusive",
    "unexpected_detection",
    "inconclusive",
    "not_evaluated",
    "rule_error",
    "false_negative",
    "false_positive",
)


def fmt_ratio(r: dict[str, Any], *, ci: bool = True) -> str:
    if r["value"] is None:
        return f"n/a ({r['reason']})"
    text = f"{r['value']:.2f} ({r['numerator']}/{r['denominator']})"
    if ci and r.get("ci95"):
        text += f", 95% CI {r['ci95'][0]:.2f}-{r['ci95'][1]:.2f}"
    return text


def short_ratio(r: dict[str, Any]) -> str:
    return "n/a" if r["value"] is None else f"{r['value']:.2f}"


# ------------------------------------------------------------------------------ text


def render_text(doc: dict[str, Any]) -> str:
    s, g = doc["summary"], doc["metrics"]["global"]
    lines = [
        f"Validation run {doc['run']['id']} ({doc['run']['mode']}{', dry run' if doc['run']['dry_run'] else ''})",
        f"  scenarios: {s['scenarios']}  "
        + "  ".join(f"{k}={v}" for k, v in s["by_status"].items()),
        f"  precision {fmt_ratio(g['precision'])}",
        f"  recall    {fmt_ratio(g['recall'])}",
        f"  f1        {fmt_ratio(g['f1'], ci=False)}",
        f"  specificity {fmt_ratio(g['specificity'])}",
        f"  evaluation rate {fmt_ratio(g['evaluation_rate'], ci=False)}",
        f"  rules with an evaluated positive and negative scenario: {fmt_ratio(doc['coverage']['coverage'], ci=False)}",
        f"  result: {s['exit_status']}   ({'synthetic data only' if s['synthetic_only'] else 'live lab'})",
    ]
    for f in doc["failures"]:
        tag = "known issue" if f["known"] else f["status"]
        lines.append(f"  [{tag}] {f['scenario']}: {clean(f['reason'], 200)}")
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------------------ markdown


def _rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    rules = {r["id"]: r for r in doc["reproducibility"]["rules"]}
    out = []
    for rid, m in doc["metrics"]["by_rule"].items():
        out.append({"rule": rid, "version": rules.get(rid, {}).get("version", "?"), "m": m})
    return out


def render_markdown(doc: dict[str, Any], comparison: dict[str, Any] | None = None) -> str:  # noqa: PLR0915
    s, g = doc["summary"], doc["metrics"]["global"]
    out = [
        "# BlueOps validation report", "",
        f"_{md_text(s['disclaimer'], 800)}_", "",
        f"- Run: {md_code(doc['run']['id'])} ({doc['run']['mode']}{', dry run' if doc['run']['dry_run'] else ''}), {doc['run']['started_at']}",
        f"- Result: **{s['exit_status']}**; {s['scenarios']} scenarios: " + ", ".join(f"{k} {v}" for k, v in s["by_status"].items()),
        "", "## Overall metrics", "",
        "| Metric | Value | Definition |", "|---|---|---|",
    ]  # fmt: skip
    for name in ("precision", "recall", "f1", "specificity", "evaluation_rate"):
        out.append(
            f"| {name} | {md_text(fmt_ratio(g[name], ci=name != 'f1'), 300)} | {md_text(doc['metrics']['explanations'].get(name, ''), 300)} |"
        )
    out += [
        "",
        f"Undefined values: {md_text(doc['metrics']['explanations']['undefined'])}",
        "",
        f"Rules with an evaluated positive and negative scenario: {md_text(fmt_ratio(doc['coverage']['coverage'], ci=False))}",
        "",
    ]
    if (
        doc["coverage"]["without_positive_evaluation"]
        or doc["coverage"]["without_negative_evaluation"]
    ):
        out += ["Coverage gaps:", ""]
        out += [
            f"- {md_code(r)}: no evaluated positive scenario"
            for r in doc["coverage"]["without_positive_evaluation"]
        ]
        out += [
            f"- {md_code(r)}: no evaluated negative scenario"
            for r in doc["coverage"]["without_negative_evaluation"]
        ]
        out.append("")
    out += [
        "## Per platform",
        "",
        "| Platform | Precision | Recall | Specificity | Evaluation rate |",
        "|---|---|---|---|---|",
    ]
    for p, m in doc["metrics"]["by_platform"].items():
        out.append(
            f"| {md_text(p)} | {md_text(short_ratio(m['precision']))} | {md_text(short_ratio(m['recall']))} | {md_text(short_ratio(m['specificity']))} | {md_text(short_ratio(m['evaluation_rate']))} |"
        )
    out += [
        "",
        "## Per rule",
        "",
        "| Rule | Version | TP | FP | TN | FN | Inconclusive | Errors | Precision | Recall |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in _rows(doc):
        c = r["m"]["counts"]
        out.append(
            f"| {md_code(r['rule'])} | {md_text(r['version'])} | {c['true_positive']} | {c['false_positive']} | {c['true_negative']} | {c['false_negative']} | {c['inconclusive'] + c['not_evaluated']} | {c['rule_error']} | {md_text(short_ratio(r['m']['precision']))} | {md_text(short_ratio(r['m']['recall']))} |"
        )
    out += [
        "",
        "## Scenarios",
        "",
        "| Scenario | Kind | Platform | Status | Reason |",
        "|---|---|---|---|---|",
    ]
    for sc in doc["scenarios"]:
        out.append(
            f"| {md_code(sc['id'])} | {sc['kind']} | {'/'.join(sc['platforms'])} | {sc['status']} | {md_text(sc['reason'], 200)} |"
        )
    fps = [
        (sc, o)
        for sc in doc["scenarios"]
        for o in sc["outcomes"]
        if o["outcome"] == "false_positive"
    ]
    fns = [
        (sc, o)
        for sc in doc["scenarios"]
        for o in sc["outcomes"]
        if o["outcome"] == "false_negative"
    ]
    out += ["", "## False-positive analysis", ""] + (
        [
            f"- {md_code(sc['id'])} {md_code(o['rule'])}: {md_text(o['detail'], 240)}"
            + (" (known issue)" if sc["status"] == "known_issue" else "")
            for sc, o in fps
        ]
        or ["None observed in these scenarios."]
    )
    out += ["", "## False-negative analysis", ""] + (
        [
            f"- {md_code(sc['id'])} {md_code(o['rule'])}: {md_text(o['detail'], 240)}"
            for sc, o in fns
        ]
        or ["None observed in these scenarios."]
    )
    inc = [
        (sc, o)
        for sc in doc["scenarios"]
        for o in sc["outcomes"]
        if o["outcome"] in ("inconclusive", "not_evaluated", "rule_error")
    ]
    out += ["", "## Inconclusive results and execution failures", ""] + (
        [
            f"- {md_code(sc['id'])} {md_code(o['rule'])} **{o['outcome']}**: {md_text(o['detail'], 240)}"
            for sc, o in inc
        ]
        or ["None."]
    )
    errs = [f for f in doc["failures"] if f["status"] in ("error", "skipped")]
    out += [""] + [
        f"- {md_code(f['scenario'])} {f['status']}: {md_text(f['reason'], 240)}" for f in errs
    ]
    if comparison:
        out += [
            "",
            "## Regression findings",
            "",
            f"Compared with {md_code(comparison['baseline']['run_id'])}: **{comparison['summary']['exit_status']}**",
        ]
        out += [f"- {md_text(r['message'], 300)}" for r in comparison["regressions"]] or [
            "- No regressions."
        ]
        out += [f"- improvement: {md_text(i['message'], 300)}" for i in comparison["improvements"]]
        out += [f"- not comparable: {md_text(i, 300)}" for i in comparison["comparable"]["issues"]]
    out += [
        "",
        "## Calibration recommendations",
        "",
        "_Advice for a developer to review. Nothing was changed._",
        "",
    ]
    for r in doc["recommendations"]:
        out.append(
            f"- **{md_code(r['id'])}** ({r['priority']}, evidence {r['strength']}): {md_text(r['summary'], 300)}"
        )
        out += [f"  - evidence: {md_text(e, 300)}" for e in r["evidence"][:4]]
        out += [f"  - trade-off: {md_text(t, 300)}" for t in r["tradeoffs"][:3]]
    if not doc["recommendations"]:
        out.append("None.")
    rp = doc["reproducibility"]
    out += [
        "",
        "## Reproducibility",
        "",
        f"- Digest: {md_code(rp['digest'])}",
        "- Scenario packs: "
        + ", ".join(f"{md_code(p['name'])} {p['version']}" for p in rp["scenario_packs"]),
        f"- Rules: {len(rp['rules'])} ({', '.join(sorted({p['name'] + ' ' + p['version'] for p in rp['rule_packs']}))})",
        "- Versions: " + ", ".join(f"{k} {md_text(v)}" for k, v in rp["versions"].items()),
        f"- Git commit: {md_code(rp.get('git_commit') or 'unknown')}",
        f"- Host: {md_text(str(doc['run']['host']))}",
    ]
    return "\n".join(out) + "\n"


def render_comparison_markdown(c: dict[str, Any]) -> str:
    out = [
        "# Validation comparison",
        "",
        f"- Baseline run: {md_code(c['baseline']['run_id'])}",
        f"- Current run: {md_code(c['current']['run_id'])}",
        f"- Result: **{c['summary']['exit_status']}**"
        + (" (identical runs)" if c["summary"]["identical"] else ""),
        f"- Scenarios compared: {c['scenarios']['compared']}",
        "",
    ]
    out += [f"- not comparable: {md_text(i)}" for i in c["comparable"]["issues"]]
    out += ["## Regressions", ""] + (
        [f"- {md_text(r['message'], 300)}" for r in c["regressions"]] or ["None."]
    )
    out += ["", "## Improvements", ""] + (
        [f"- {md_text(r['message'], 300)}" for r in c["improvements"]] or ["None."]
    )
    for key in ("added", "removed", "changed_definition"):
        if c["scenarios"][key]:
            out += ["", f"## Scenarios {key.replace('_', ' ')}", ""] + [
                f"- {md_code(i)}" for i in c["scenarios"][key]
            ]
    return "\n".join(out) + "\n"


def render_baseline_diff_markdown(d: dict[str, Any]) -> str:
    s = d["summary"]
    out = [
        "# Baseline comparison",
        "",
        "_A difference is not a finding. Each one is classified against the baseline's declared allowances and explained so that it can be reviewed; none is labelled by intent._",
        "",
        f"- Baseline: {md_code(d['baseline']['name'])} captured {d['baseline']['captured_at']}",
        f"- Mode: {d['mode']}",
        f"- Result: **{s['exit_status']}** ({s['total']} differences: {s['unexpected']} unexpected, {s['expected']} expected; {s['indeterminate_categories']} categories not conclusive)",
        "",
    ]
    out += ["## Compatibility", ""] + (
        [
            f"- **{c['severity']}** {md_code(c['code'])}: {md_text(c['message'], 300)}"
            for c in d["compatibility"]
        ]
        or ["No issues."]
    )
    for cls in ("unexpected", "expected"):
        items = [x for x in d["differences"] if x["classification"] == cls]
        out += ["", f"## {cls.capitalize()} differences ({len(items)})", ""]
        for x in items:
            out.append(
                f"- {x['change']} {md_code(x['category'])} {md_code(x['identity'][:120])}"
                + (f" (expected: {md_text(x['expected_by'], 120)})" if x.get("expected_by") else "")
            )
            out += [
                f"  - why it matters: {md_text(x['why_it_matters'], 300)}",
                f"  - how to review: {md_text(x['how_to_review'], 300)}",
            ]
            out += [
                f"  - {md_text(a['name'])}: {md_text(a['before'], 80)} -> {md_text(a['after'], 80)}"
                for a in x.get("attributes", [])[:4]
            ]
    if d["indeterminate"]:
        out += ["", "## Categories that cannot be compared conclusively", ""] + [
            f"- {md_code(i['category'])}: {md_text(i['reason'], 300)}" for i in d["indeterminate"]
        ]
    if d["parity"]:
        out += [
            "",
            "## Coverage parity",
            "",
            "| Category | Baseline | Current | Note |",
            "|---|---|---|---|",
        ] + [
            f"| {md_code(p['category'])} | {p['baseline']['status']} ({p['baseline']['records']}) | {p['current']['status']} ({p['current']['records']}) | {md_text(p['note'])} |"
            for p in d["parity"]
        ]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------------ html

STYLE = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#6b7280;--line:#d0d7de;--card:#f6f8fa;--ok:#1a7f4b;--known:#8250df;--warn:#9a6700;--err:#b35900;--bad:#c62828;--p:#1f6feb;--r:#1a7f4b}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9aa4b2;--line:#30363d;--card:#161b22;--ok:#3fb950;--known:#a371f7;--warn:#d29922;--err:#f0883e;--bad:#ff6b6b;--p:#58a6ff;--r:#3fb950}}
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg);margin:0 auto;max-width:1100px;padding:16px}
h1,h2{line-height:1.2}h2{margin-top:32px;border-bottom:1px solid var(--line);padding-bottom:4px}
.note{background:var(--card);border-left:4px solid var(--known);padding:8px 12px;margin:12px 0}
.cards{display:flex;flex-wrap:wrap;gap:10px}.card{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:8px 12px;min-width:140px}
.card b{display:block;font-size:20px}.muted{color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
th{background:var(--card)}code{background:var(--card);padding:0 4px;border-radius:3px}
.s-pass{color:var(--ok)}.s-fail{color:var(--bad);font-weight:600}.s-error{color:var(--err);font-weight:600}.s-known_issue{color:var(--known)}.s-inconclusive,.s-skipped{color:var(--warn)}
.scroll{overflow-x:auto}svg{max-width:100%;height:auto}details{margin:4px 0}
"""


def _esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def _status_chart(by_status: dict[str, int]) -> str:
    total = sum(by_status.values()) or 1
    x, bars, legend = 0.0, [], []
    for i, st in enumerate(k for k in STATUS_ORDER if by_status.get(k)):
        w = 600 * by_status[st] / total
        bars.append(
            f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="26" fill="{STATUS_COLOR[st]}"><title>{_esc(st)}: {by_status[st]}</title></rect>'
        )
        x += w
        legend.append(
            f'<g transform="translate({i * 130},40)"><rect width="12" height="12" fill="{STATUS_COLOR[st]}"/><text x="18" y="11" font-size="12" fill="currentColor">{_esc(st)} {by_status[st]}</text></g>'
        )
    h = 62 + 18 * (len(legend) // 5)
    return f'<svg role="img" aria-label="Scenario outcomes" viewBox="0 0 640 {h}" width="640">{"".join(bars)}{"".join(legend)}</svg>'


def _rule_chart(rows: list[dict[str, Any]]) -> str:
    row_h = 34
    body = []
    for i, r in enumerate(rows):
        y = i * row_h + 20
        m = r["m"]
        body.append(
            f'<text x="0" y="{y + 12}" font-size="12" fill="currentColor">{_esc(r["rule"])}</text>'
        )
        for j, (name, color) in enumerate((("precision", "var(--p)"), ("recall", "var(--r)"))):
            v = m[name]["value"]
            yy = y + j * 11
            body.append(
                f'<rect x="170" y="{yy}" width="300" height="9" fill="none" stroke="var(--line)"/>'
            )
            if v is None:
                body.append(
                    f'<text x="176" y="{yy + 8}" font-size="9" fill="currentColor">{name}: n/a (undefined)</text>'
                )
            else:
                body.append(
                    f'<rect x="170" y="{yy}" width="{300 * v:.1f}" height="9" fill="{color}"><title>{name} {v:.2f}</title></rect>'
                )
                body.append(
                    f'<text x="476" y="{yy + 8}" font-size="9" fill="currentColor">{name} {v:.2f} (n={m[name]["denominator"]})</text>'
                )
    h = len(rows) * row_h + 24
    head = '<text x="170" y="10" font-size="10" fill="currentColor">0</text><text x="460" y="10" font-size="10" fill="currentColor">1</text>'
    return f'<svg role="img" aria-label="Per-rule precision and recall" viewBox="0 0 700 {h}" width="700">{head}{"".join(body)}</svg>'


def render_html(doc: dict[str, Any], comparison: dict[str, Any] | None = None) -> str:  # noqa: PLR0915
    s, g, rp = doc["summary"], doc["metrics"]["global"], doc["reproducibility"]
    e = _esc
    cards = "".join(f'<div class="card"><span class="muted">{e(lbl)}</span><b>{e(val)}</b><span class="muted">{e(sub)}</span></div>' for lbl, val, sub in (
        ("Scenarios", s["scenarios"], ", ".join(f"{k} {v}" for k, v in s["by_status"].items())),
        ("Precision", short_ratio(g["precision"]), fmt_ratio(g["precision"]) if g["precision"]["value"] is None else f"n={g['precision']['denominator']}"),
        ("Recall", short_ratio(g["recall"]), fmt_ratio(g["recall"]) if g["recall"]["value"] is None else f"n={g['recall']['denominator']}"),
        ("F1", short_ratio(g["f1"]), "harmonic mean"),
        ("Specificity", short_ratio(g["specificity"]), "of benign scenarios"),
        ("Evaluation rate", short_ratio(g["evaluation_rate"]), "assertions testable"),
        ("Rule coverage", short_ratio(doc["coverage"]["coverage"]), "rules with positive+negative"),
        ("Result", s["exit_status"], "synthetic only" if s["synthetic_only"] else "live lab"),
    ))  # fmt: skip
    plat = "".join(
        f"<tr><td>{e(p)}</td><td>{e(short_ratio(m['precision']))}</td><td>{e(short_ratio(m['recall']))}</td><td>{e(short_ratio(m['specificity']))}</td><td>{e(short_ratio(m['evaluation_rate']))}</td><td>{m['asserted']}</td></tr>"
        for p, m in doc["metrics"]["by_platform"].items()
    )
    rows = _rows(doc)
    rule_rows = "".join(
        f"<tr><td><code>{e(r['rule'])}</code></td><td>{e(r['version'])}</td>"
        + "".join(
            f"<td>{r['m']['counts'][k]}</td>"
            for k in ("true_positive", "false_positive", "true_negative", "false_negative")
        )
        + f"<td>{r['m']['counts']['inconclusive'] + r['m']['counts']['not_evaluated']}</td><td>{r['m']['counts']['rule_error']}</td><td>{e(short_ratio(r['m']['precision']))}</td><td>{e(short_ratio(r['m']['recall']))}</td></tr>"
        for r in rows
    )
    scen = []
    for sc in doc["scenarios"]:
        checks = "".join(
            f"<li class='{'s-pass' if c['ok'] else 's-fail'}'>{e(c['name'])}: expected {e(str(c['expected'])[:120])}, got {e(str(c['actual'])[:120])} {e(c['detail'][:160])}</li>"
            for c in sc["checks"]
        )
        lim = "".join(f"<li>{e(x)}</li>" for x in sc.get("limitations", []))
        scen.append(
            f"<tr><td><code>{e(sc['id'])}</code></td><td>{e(sc['kind'])}</td><td>{e('/'.join(sc['platforms']))}</td><td class='s-{e(sc['status'])}'>{e(sc['status'])}</td><td>{e(sc['reason'][:200])}<details><summary>checks and limitations</summary><ul>{checks}</ul><p class='muted'>Limitations:</p><ul>{lim}</ul></details></td></tr>"
        )
    fp = "".join(
        f"<li><code>{e(sc['id'])}</code> <code>{e(o['rule'])}</code>: {e(o['detail'][:240])}{' (known issue)' if sc['status'] == 'known_issue' else ''}</li>"
        for sc in doc["scenarios"]
        for o in sc["outcomes"]
        if o["outcome"] == "false_positive"
    )
    fn = "".join(
        f"<li><code>{e(sc['id'])}</code> <code>{e(o['rule'])}</code>: {e(o['detail'][:240])}</li>"
        for sc in doc["scenarios"]
        for o in sc["outcomes"]
        if o["outcome"] == "false_negative"
    )
    inc = "".join(
        f"<li><code>{e(sc['id'])}</code> <code>{e(o['rule'])}</code> <b>{e(o['outcome'])}</b>: {e(o['detail'][:240])}</li>"
        for sc in doc["scenarios"]
        for o in sc["outcomes"]
        if o["outcome"] in ("inconclusive", "not_evaluated", "rule_error")
    )
    gaps = "".join(
        f"<li><code>{e(r)}</code>: no evaluated positive scenario</li>"
        for r in doc["coverage"]["without_positive_evaluation"]
    ) + "".join(
        f"<li><code>{e(r)}</code>: no evaluated negative scenario</li>"
        for r in doc["coverage"]["without_negative_evaluation"]
    )
    fails = "".join(
        f"<li class='s-{e(f['status'])}'><code>{e(f['scenario'])}</code> {e(f['status'])}{' (known issue)' if f['known'] else ''}: {e(f['reason'][:240])}</li>"
        for f in doc["failures"]
    )
    reg = ""
    if comparison:
        reg = (
            f"<h2>Regression findings</h2><p>Compared with <code>{e(comparison['baseline']['run_id'])}</code>: <b>{e(comparison['summary']['exit_status'])}</b></p><ul>"
            + (
                "".join(
                    f"<li class='s-fail'>{e(r['message'][:300])}</li>"
                    for r in comparison["regressions"]
                )
                or "<li>No regressions.</li>"
            )
            + "".join(
                f"<li class='s-pass'>{e(i['message'][:300])}</li>"
                for i in comparison["improvements"]
            )
            + "".join(
                f"<li class='muted'>not comparable: {e(i)}</li>"
                for i in comparison["comparable"]["issues"]
            )
            + "</ul>"
        )
    recs = (
        "".join(
            f"<li><b><code>{e(r['id'])}</code></b> ({e(r['priority'])}, evidence {e(r['strength'])}): {e(r['summary'][:300])}<ul>"
            + "".join(f"<li>evidence: {e(x[:300])}</li>" for x in r["evidence"][:4])
            + "".join(f"<li>trade-off: {e(x[:300])}</li>" for x in r["tradeoffs"][:3])
            + "</ul></li>"
            for r in doc["recommendations"]
        )
        or "<li>None.</li>"
    )
    defs = "".join(
        f"<li><b>{e(k)}</b>: {e(v)}</li>" for k, v in doc["metrics"]["explanations"].items()
    )
    meta = f"<li>Digest <code>{e(rp['digest'])}</code></li><li>Git commit <code>{e(rp.get('git_commit') or 'unknown')}</code></li><li>Scenario packs: {e(', '.join(p['name'] + ' ' + p['version'] for p in rp['scenario_packs']))}</li><li>Rules: {len(rp['rules'])}</li><li>Versions: {e(', '.join(f'{k} {v}' for k, v in rp['versions'].items()))}</li><li>Host: {e(str(doc['run']['host']))}</li>"
    return (
        f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' content=\"{CSP}\"><meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>BlueOps validation report</title><style>{STYLE}</style></head><body><h1>BlueOps validation report</h1>"
        f"<div class='note'>{e(s['disclaimer'])}</div><p class='muted'>Run <code>{e(doc['run']['id'])}</code> ({e(doc['run']['mode'])}{', dry run' if doc['run']['dry_run'] else ''}) started {e(doc['run']['started_at'])}.</p>"
        f"<div class='cards'>{cards}</div><h2>Scenario outcomes</h2>{_status_chart(s['by_status'])}"
        f"<h2>Per platform</h2><table><tr><th>Platform</th><th>Precision</th><th>Recall</th><th>Specificity</th><th>Evaluation rate</th><th>Assertions</th></tr>{plat}</table>"
        f"<h2>Per-rule performance</h2><div class='scroll'>{_rule_chart(rows)}</div><div class='scroll'><table><tr><th>Rule</th><th>Version</th><th>TP</th><th>FP</th><th>TN</th><th>FN</th><th>Inconclusive</th><th>Errors</th><th>Precision</th><th>Recall</th></tr>{rule_rows}</table></div>"
        f"<h2>Scenarios</h2><div class='scroll'><table><tr><th>Scenario</th><th>Kind</th><th>Platform</th><th>Status</th><th>Reason</th></tr>{''.join(scen)}</table></div>"
        f"<h2>False-positive analysis</h2><ul>{fp or '<li>None observed in these scenarios.</li>'}</ul><h2>False-negative analysis</h2><ul>{fn or '<li>None observed in these scenarios.</li>'}</ul>"
        f"<h2>Coverage gaps and inconclusive results</h2><ul>{gaps}{inc or '<li>No inconclusive results.</li>'}</ul><h2>Failures and known issues</h2><ul>{fails or '<li>None.</li>'}</ul>{reg}"
        f"<h2>Calibration recommendations</h2><p class='muted'>Advice for a developer to review. Nothing was changed.</p><ul>{recs}</ul>"
        f"<h2>Reproducibility</h2><ul>{meta}</ul><h2>Metric definitions</h2><ul>{defs}</ul></body></html>\n"
    )
