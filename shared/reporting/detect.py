"""Command line: run explainable detection rules over a baseline comparison (offline, read-only).

    python -m shared.reporting.detect BASELINE CURRENT [--format text|json] [--output FILE]
    python -m shared.reporting.detect --from-diff DIFF.json

BASELINE and CURRENT are audit ``report.json`` files or run directories (compared with the same
engine as ``shared.reporting.diff``); ``--from-diff`` reads a saved ``--json`` diff instead.
Exit codes follow ``docs/contracts.md``: 0 nothing detected and coverage complete, 4 detections,
6 nothing detected but coverage incomplete, 3 unusable input, 2 usage error.
Intended for authorized environments; it reads files and writes one report.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.reporting.accepted import AllowlistError
from shared.reporting.accepted import load as load_allowlist
from shared.reporting.baseline import IncompatibleReportsError, compare
from shared.reporting.baseline_render import clean
from shared.reporting.contracts import ExitCode, Severity
from shared.reporting.detection import (
    RULES,
    TOOL_VERSION,
    DiffInputError,
    detect,
    exit_code_for,
)
from shared.reporting.diff import _options, _write_output
from shared.reporting.inventory import (
    ConfigError,
    ReportError,
    load_snapshot,
    parse_timestamp,
)

MAX_DIFF_BYTES = 64 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m shared.reporting.detect",
        description="Apply explainable detection rules to the changes between two BlueOps audit "
        "reports. Offline and read-only: it reads its inputs and writes one report.",
    )
    p.add_argument(
        "reports", nargs="*", metavar="REPORT", help="BASELINE CURRENT (or none with --from-diff)"
    )
    p.add_argument(
        "--from-diff", metavar="FILE", help="saved baseline-diff JSON instead of reports"
    )
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--json", action="store_const", const="json", dest="format")
    p.add_argument("--output", metavar="FILE", help="write the report here (must not exist; 0600)")
    p.add_argument(
        "--min-severity",
        choices=[s.label for s in Severity],
        default="info",
        help="hide detections below this severity (they are still counted)",
    )
    p.add_argument(
        "--accepted",
        metavar="FILE",
        help="accepted-changes allowlist (docs/detection-rules.md); matches move to 'accepted' "
        "with the evidence intact",
    )
    p.add_argument("--config", metavar="FILE", help="diff comparison config (see baseline-diff.md)")
    p.add_argument("--ephemeral-from", type=int, metavar="PORT")
    p.add_argument("--allow-host-mismatch", action="store_true")
    p.add_argument("--generated-at", metavar="TIMESTAMP", help="timestamp to record (default: now)")
    p.add_argument("--list-rules", action="store_true", help="print the rule catalogue and exit")
    p.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    p.add_argument("--version", action="version", version=f"blueops-detect {TOOL_VERSION}")
    return p


def _load_diff(path: str) -> dict[str, Any]:
    try:
        p = Path(path)
        if p.stat().st_size > MAX_DIFF_BYTES:
            raise DiffInputError("diff file is too large")
        text = p.read_text(encoding="utf-8-sig")
        return json.loads(text)  # type: ignore[no-any-return]
    except (OSError, ValueError) as exc:
        raise DiffInputError(f"cannot read diff {path}: {exc}") from None


def _detection_lines(d: dict[str, Any]) -> list[str]:
    out: list[str] = []
    sub = d["subject"]
    out += [
        "",
        f"[{d['severity'].upper()}] {d['id']}  {clean(d['title'])}  ({d['basis']})",
        f"  subject:  {clean(sub['domain'])} {clean(sub['key'])} ({sub['change']})",
        f"  what:     {clean(d['summary'], 300)}",
        "  because:",
    ]
    for r in d["reasons"]:
        out.append(f"    - {r['rule']} [{r['basis']}, {r['severity']}] {clean(r['title'])}")
        out.append(f"        saw:  {clean(r['observation'], 300)}")
        out.append(f"        why:  {clean(r['rationale'], 400)}")
    for a in d["attributes"]:
        out.append(f"  changed:  {clean(a['name'])}: {clean(a['before'])} -> {clean(a['after'])}")
    for e in d["evidence"][:3]:
        out.append(f"  evidence: {clean(e['type'])} {clean(e['ref'])}")
    if d["related_findings"]:
        out.append(f"  also flagged by audit finding(s): {clean(d['related_findings'])}")
    if d["correlated"]:
        out.append(
            "  linked to: "
            + ", ".join(f"{c['id']} ({clean(c['key'], 60)})" for c in d["correlated"])
        )
    if d["techniques"]:
        out.append(f"  ATT&CK:   {', '.join(d['techniques'])}")
    out += [f"  not known: {clean(u, 300)}" for u in d["unknown"]]
    out.append("  investigate:")
    out += [f"    {n}. {clean(step, 300)}" for n, step in enumerate(d["investigation"], 1)]
    return out


def _allowlist_lines(doc: dict[str, Any]) -> list[str]:
    out: list[str] = []
    if doc["accepted"]:
        out += ["", "Accepted changes (suppressed from the count; evidence is in the JSON):"]
        for d in doc["accepted"]:
            a = d["acceptance"]
            out.append(
                f"  {d['id']} [{d['severity']}] {clean(d['subject']['key'], 120)} "
                f"- {a['entry']} by {clean(a['approved_by'], 60)}, expires {a['expires']}: "
                f"{clean(a['reason'], 200)}"
            )
    al = doc["allowlist"]
    if al:
        out += ["", f"Allowlist {clean(al['source'])} (sha256 {al['sha256'][:16]}..):"]
        for e in al["entries"]:
            line = f"  {clean(e['id'])}: {e['status']}"
            if e["status"] != "matched":
                line += " - nothing was suppressed by it"
            out.append(line)
            out += [f"      not applied to {n['detection']}: {n['why']}" for n in e["not_applied"]]
    return out


def render_text(doc: dict[str, Any]) -> str:
    s = doc["summary"]
    cov = doc["coverage"]
    out = [
        "BlueOps detections (offline analysis of changes since the baseline)",
        f"  host:     {clean(doc['current']['hostname'])} ({clean(doc['current']['os_family'])})",
        f"  window:   {clean(doc['window']['from'])} .. {clean(doc['window']['to'])}",
        f"  result:   {s['total']} detection(s)  "
        + "  ".join(f"{k}={v}" for k, v in s["by_severity"].items() if v)
        + f"  | observed={s['by_basis']['observed']} heuristic={s['by_basis']['heuristic']}",
    ]
    if s["accepted"]:
        out.append(f"  accepted: {s['accepted']} detection(s) allowlisted (listed below)")
    if s["suppressed_below_min_severity"]:
        out.append(f"  hidden:   {s['suppressed_below_min_severity']} below --min-severity")
    out.append(
        "  coverage: "
        + ("complete" if cov["complete"] else "INCOMPLETE - absence of detections is not clean")
    )
    for g in cov["gaps"]:
        scope = f"/{clean(g['scope'])}" if g["scope"] else ""
        out.append(f"      gap: {clean(g['domain'])}{scope} {clean(g['status'])}")
    if cov["indeterminate"]:
        out.append(f"      {cov['indeterminate']} record(s) indeterminate (not evaluated)")
    if cov["no_inventory"]:
        out.append("      a report has no inventory (schema 0.1): nothing could be evaluated")
    for e in cov["rule_errors"]:
        out.append(
            f"      rule error: {clean(e['rule'])} on {clean(e['key'])}: {clean(e['error'])}"
        )
    for d in doc["detections"]:
        out += _detection_lines(d)
    out += _allowlist_lines(doc)
    out += ["", *("note: " + n for n in cov["notes"])]
    return "\n".join(out) + "\n"


def _list_rules() -> str:
    lines = [f"{'RULE':<12} {'DOMAINS':<52} DESCRIPTION"]
    lines += [f"{r.rule_id:<12} {', '.join(r.domains):<52} {r.summary}" for r in RULES]
    return "\n".join(lines) + "\n"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.list_rules:
        sys.stdout.write(_list_rules())
        return int(ExitCode.OK)
    if args.from_diff and args.reports:
        parser.error("give either BASELINE CURRENT or --from-diff, not both")
    if not args.from_diff and len(args.reports) != 2:
        parser.error("BASELINE and CURRENT are required (or use --from-diff)")
    generated = args.generated_at or _now()
    try:
        parse_timestamp(generated)
        if args.from_diff:
            diff = _load_diff(args.from_diff)
        else:
            opts = _options(args)
            diff = compare(
                load_snapshot(args.reports[0], opts),
                load_snapshot(args.reports[1], opts),
                opts,
                generated,
            )
        allow = (
            load_allowlist(args.accepted, frozenset(r.rule_id for r in RULES))
            if args.accepted
            else None
        )
        doc = detect(diff, generated, Severity.parse(args.min_severity), allow)
    except (
        ReportError,
        ConfigError,
        IncompatibleReportsError,
        DiffInputError,
        AllowlistError,
    ) as exc:
        sys.stderr.write(f"blueops-detect: {exc}\n")
        return int(ExitCode.PRECONDITION)
    text = json.dumps(doc, indent=2) + "\n" if args.format == "json" else render_text(doc)
    try:
        if args.output:
            _write_output(args.output, text)
        else:
            sys.stdout.write(text)
    except OSError as exc:
        sys.stderr.write(f"blueops-detect: cannot write output: {exc.strerror or exc}\n")
        return int(ExitCode.ERROR)
    code = exit_code_for(doc)
    if not args.quiet and (args.format == "json" or args.output):
        s = doc["summary"]
        sys.stderr.write(
            f"blueops-detect: {s['total']} detection(s), "
            f"coverage {'complete' if doc['coverage']['complete'] else 'incomplete'} "
            f"(exit {code})\n"
        )
    return code


if __name__ == "__main__":
    sys.exit(main())
