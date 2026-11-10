"""Command line for the detection engine, mounted in ``python -m shared.engine``.

    rules list | validate | show | test | docs
    detect run | compare | show | report | export
    case list | show | status | note | link

Exit codes follow ``docs/contracts.md``: 0 ok / nothing found, 4 detections at or above
``--fail-on``, 6 rules indeterminate or failed (and nothing reached the threshold), 3 bad input
or invalid rules, 2 usage, 1 unexpected failure.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from shared.engine.loader import LoadError, load_assessment
from shared.reporting.contracts import ExitCode, Severity
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.render_detections import render_detections_markdown
from shared.reporting.render_html import render_html
from shared.reporting.schema_lite import validate
from shared.rules.docgen import render_library, rule_section
from shared.rules.engine import detect, exit_code_for
from shared.rules.export import to_csv, to_jsonl
from shared.rules.history import HistoryError, HistoryStore, Snap
from shared.rules.investigation import STATUSES, CaseStore, CaseStoreError, case_summaries
from shared.rules.loader import RuleSet, load_rule_set
from shared.rules.selftest import run_all
from shared.rules.timeline import TimelineError, compare_detections

SEVERITIES = [s.label for s in Severity]
MAX_RESULTS_BYTES = 128 * 1024 * 1024


def _err(msg: str) -> None:
    sys.stderr.write(f"blueops: {msg}\n")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_new(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _emit(text: str, output: str | None) -> None:
    if output:
        _write_new(output, text)
    else:
        sys.stdout.write(text)


def _json(doc: Any) -> str:
    return json.dumps(doc, indent=2) + "\n"


# ----------------------------------------------------------------------------- parsers


def _rule_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument(
        "--rules-dir",
        action="append",
        default=[],
        metavar="PATH",
        help="extra rule pack file or directory (repeatable)",
    )
    sp.add_argument(
        "--no-library", action="store_true", help="do not load the built-in rule library"
    )
    sp.add_argument("--enable", action="append", default=[], metavar="RULE_ID")
    sp.add_argument("--disable", action="append", default=[], metavar="RULE_ID")


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # noqa: SLF001, PLR0915
    rules = sub.add_parser("rules", help="list, validate, show, test and document detection rules")
    rsub = rules.add_subparsers(dest="rules_cmd", required=True)
    p = rsub.add_parser("list", help="list rules")
    _rule_args(p)
    p.add_argument("--platform", choices=("linux", "windows", "any"))
    p.add_argument("--category")
    p.add_argument("--nature", choices=("observation", "indicator", "correlated", "hypothesis"))
    p.add_argument("--min-severity", choices=SEVERITIES)
    p.add_argument("--json", action="store_true")
    p = rsub.add_parser(
        "validate", help="validate rule pack files (structure, fields, references, regex safety)"
    )
    p.add_argument(
        "paths",
        nargs="*",
        metavar="PATH",
        help="pack files or directories (default: the built-in library)",
    )
    p.add_argument("--examples", action="store_true", help="also run each rule's embedded examples")
    p.add_argument("--json", action="store_true")
    p = rsub.add_parser("show", help="show one rule")
    _rule_args(p)
    p.add_argument("rule_id")
    p.add_argument("--json", action="store_true")
    p = rsub.add_parser("test", help="run the examples embedded in the rules")
    _rule_args(p)
    p.add_argument("--rule", action="append", default=[], metavar="RULE_ID")
    p = rsub.add_parser("docs", help="generate the rule library reference (Markdown)")
    _rule_args(p)
    p.add_argument("--output", metavar="FILE")

    det = sub.add_parser(
        "detect", help="run detections, compare them across snapshots, report and export"
    )
    dsub = det.add_subparsers(dest="detect_cmd", required=True)
    p = dsub.add_parser("run", help="evaluate rules over an assessment")
    _rule_args(p)
    p.add_argument("assessment", help="assessment directory/file, or an audit report")
    p.add_argument(
        "--previous",
        action="append",
        default=[],
        metavar="PATH",
        help="an earlier snapshot (repeatable)",
    )
    p.add_argument("--history", metavar="DIR", help="directory of earlier assessments (same host)")
    p.add_argument(
        "--state-dir",
        metavar="DIR",
        help="investigation state; detections are registered as cases here",
    )
    p.add_argument("--actor", metavar="NAME")
    p.add_argument("--format", choices=("json", "text", "markdown", "html"), default="json")
    p.add_argument("--output", metavar="FILE", help="write here (must not exist)")
    p.add_argument("--min-severity", choices=SEVERITIES, help="hide detections below this severity")
    p.add_argument("--fail-on", choices=SEVERITIES, default="medium")
    p.add_argument("--generated-at", metavar="TIMESTAMP")
    p.add_argument("--quiet", action="store_true")
    p = dsub.add_parser("compare", help="compare detections across two or more snapshots")
    _rule_args(p)
    p.add_argument("snapshots", nargs="+", metavar="SNAPSHOT")
    p.add_argument("--format", choices=("json", "text"), default="json")
    p.add_argument("--output", metavar="FILE")
    p.add_argument("--generated-at", metavar="TIMESTAMP")
    p = dsub.add_parser("show", help="show one detection from a results file")
    p.add_argument("results")
    p.add_argument("detection_id", help="DT- id or a unique prefix")
    p.add_argument("--state-dir", metavar="DIR")
    p.add_argument("--json", action="store_true")
    p = dsub.add_parser("report", help="render saved detection results")
    p.add_argument("results")
    p.add_argument(
        "--assessment",
        metavar="PATH",
        help="required for --format html: the report embeds the detections",
    )
    p.add_argument("--format", choices=("markdown", "html"), default="markdown")
    p.add_argument("--state-dir", metavar="DIR")
    p.add_argument("--output", metavar="FILE")
    p.add_argument("--generated-at", metavar="TIMESTAMP")
    p = dsub.add_parser("export", help="export saved detection results")
    p.add_argument("results")
    p.add_argument("--format", choices=("json", "jsonl", "csv"), default="json")
    p.add_argument("--state-dir", metavar="DIR")
    p.add_argument("--output", metavar="FILE")

    case = sub.add_parser("case", help="track investigations (separate from assessment evidence)")
    csub = case.add_subparsers(dest="case_cmd", required=True)

    def state(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--state-dir", required=True, metavar="DIR", help="directory holding cases.jsonl"
        )
        sp.add_argument(
            "--actor", metavar="NAME", help="analyst name recorded in the history (default: $USER)"
        )

    p = csub.add_parser("list", help="list cases")
    state(p)
    p.add_argument("--status", choices=STATUSES)
    p.add_argument("--json", action="store_true")
    p = csub.add_parser("show", help="show a case with its notes and history")
    state(p)
    p.add_argument("detection_id")
    p.add_argument("--json", action="store_true")
    p = csub.add_parser("status", help="change a case's status")
    state(p)
    p.add_argument("detection_id")
    p.add_argument("status", choices=STATUSES)
    p.add_argument("--note", default="", help="required for resolved and dismissed")
    p = csub.add_parser("note", help="add an analyst note")
    state(p)
    p.add_argument("detection_id")
    p.add_argument("text")
    p = csub.add_parser("link", help="link two related cases")
    state(p)
    p.add_argument("detection_id")
    p.add_argument("other_id")


# ------------------------------------------------------------------------------- helpers


def _rule_set(args: argparse.Namespace) -> RuleSet:
    return load_rule_set(
        args.rules_dir,
        include_library=not args.no_library,
        enable=args.enable,
        disable=args.disable,
    )


def _report_diags(rs: RuleSet) -> None:
    for d in rs.diagnostics:
        _err(str(d))


def _load_results(path: str) -> dict[str, Any]:
    try:
        doc, _ = load_json_strict(path, MAX_RESULTS_BYTES, "detection results")
    except JsonInputError as exc:
        raise LoadError(str(exc)) from None
    problems = validate(doc, "detection-results.schema.json", limit=5)
    if problems:
        raise LoadError(f"{path}: not valid detection results: {'; '.join(problems)}")
    return doc  # type: ignore[no-any-return]


def _history(
    args: argparse.Namespace, current: dict[str, Any]
) -> tuple[list[Snap], list[dict[str, str]]]:
    snaps: list[Snap] = []
    store = HistoryStore.scan(args.history) if args.history else HistoryStore([])
    snaps += store.snaps
    if args.previous:
        snaps += HistoryStore.from_paths(args.previous).snaps
    uniq: dict[str, Snap] = {}
    for s in snaps:
        uniq.setdefault(s.doc["assessment"]["id"], s)
    merged = HistoryStore(list(uniq.values()), store.skipped)
    return merged.before(current)


def _filter(results: dict[str, Any], min_sev: str | None) -> dict[str, Any]:
    if not min_sev:
        return results
    keep = [
        d for d in results["detections"] if Severity.parse(d["severity"]) >= Severity.parse(min_sev)
    ]
    return {**results, "detections": keep, "summary": _resummary(results["summary"], keep)}


def _resummary(old: dict[str, Any], dets: list[dict[str, Any]]) -> dict[str, Any]:
    new = {**old, "total": len(dets)}
    for key, field in (
        ("by_severity", "severity"),
        ("by_confidence", "confidence"),
        ("by_nature", "nature"),
        ("by_category", "category"),
    ):
        counts = dict.fromkeys(old[key], 0) if key != "by_category" else {}
        for d in dets:
            counts[d[field]] = counts.get(d[field], 0) + 1
        new[key] = counts
    return new


def render_text(results: dict[str, Any], cases: dict[str, dict[str, Any]] | None = None) -> str:
    s = results["summary"]
    lines = [
        f"BlueOps detections for {results['host']['hostname']} ({results['assessment']['id']})",
        f"{s['total']} detection(s); {s['indeterminate']} rule(s) indeterminate; {s['rule_errors']} rule error(s)",
        "",
    ]
    for d in results["detections"]:
        st = (cases or {}).get(d["id"], {}).get("status", "new")
        lines.append(
            f"[{d['severity'].upper():<8}] {d['id']} {d['rule']['id']} ({d['confidence']} confidence, {d['nature']}, {st})"
        )
        lines.append(f"    {d['title']}")
        lines.append(f"    {d['explanation']['severity_rationale']}")
    for i in results["indeterminate"]:
        lines.append(f"[indeterminate] {i['rule']['id']}: {i['reason']}")
    for r in results["rule_errors"]:
        lines.append(f"[rule error] {r['code']} {r['rule']}: {r['message']}")
    return "\n".join(lines) + "\n"


def render_detection_detail(d: dict[str, Any], case: dict[str, Any] | None = None) -> str:
    x = d["explanation"]
    out = [
        f"{d['id']}  {d['title']}",
        f"rule {d['rule']['id']} v{d['rule']['version']} ({d['rule']['name']})",
        f"severity {d['severity']}, confidence {d['confidence']}, nature {d['nature']}, category {d['category']}",
        f"status: {(case or {}).get('status', 'new')}", "",
        f"Why flagged: {x['why_flagged']}", f"How it matched: {x['why_correlated']}",
        f"Severity: {x['severity_rationale']}", f"Confidence: {x['confidence_rationale']}", x["disclaimer"], "",
        "Matched conditions:",
    ]  # fmt: skip
    for m in d["matched_conditions"]:
        out.append(f"  {m['clause']} ({m['matched_items']}): {m['description']}")
        out += [f"      {c}" for c in m["conditions"][:8]]
    out += ["", "Contributing:"] + [
        f"  [{c['type']}] {c['label']}" + (f" ({c['id']})" if c.get("id") else "")
        for c in d["contributing"]
    ]
    out += ["", "Evidence: " + (", ".join(d["evidence"]) or "none")]
    if x["missing_corroboration"]:
        out += ["", "Would improve confidence:"] + [f"  - {v}" for v in x["missing_corroboration"]]
    if x["possible_benign_causes"]:
        out += ["", "Possible benign causes:"] + [f"  - {v}" for v in x["possible_benign_causes"]]
    if x["caveats"]:
        out += ["", "Caveats:"] + [f"  - {v}" for v in x["caveats"]]
    out += ["", "Investigate:"] + [f"  {i}. {v}" for i, v in enumerate(d["investigation_steps"], 1)]
    out += ["", f"Action: {d['remediation']}", "", "References:"]
    out += [
        f"  ATT&CK {a['id']} ({a['relationship']}): {a['explanation']}"
        for a in d["references"]["attack"]
    ]
    out += [f"  NIST {n['id']} {n['title']}" for n in d["references"]["nist"]]
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------- rules


def _cmd_rules(args: argparse.Namespace) -> int:  # noqa: PLR0911, PLR0912
    cmd = args.rules_cmd
    if cmd == "validate":
        rs = load_rule_set(args.paths, include_library=not args.paths)
        failures = run_all(rs) if args.examples else []
        bad = [f for f in failures if not f.ok]
        if args.json:
            sys.stdout.write(
                _json(
                    {
                        "rules": len(rs.rules),
                        "diagnostics": [str(d) for d in rs.diagnostics],
                        "example_failures": [f"{f.rule}: {f.example}: {f.message}" for f in bad],
                    }
                )
            )
        else:
            _report_diags(rs)
            for f in bad:
                _err(f"error: {f.rule}: example {f.example!r}: {f.message}")
            sys.stdout.write(
                f"{len(rs.rules)} rule(s) valid, {len(rs.errors)} error(s)"
                + (f", {len(bad)} failing example(s)" if args.examples else "")
                + "\n"
            )
        return int(ExitCode.PRECONDITION if rs.errors or bad else ExitCode.OK)
    rs = _rule_set(args)
    if cmd == "docs":
        if rs.errors:
            _report_diags(rs)
            return int(ExitCode.PRECONDITION)
        _emit(render_library(rs), args.output)
        return int(ExitCode.OK)
    if cmd == "test":
        _report_diags(rs)
        results = run_all(rs, args.rule or None)
        bad = [r for r in results if not r.ok]
        for r in bad:
            _err(f"FAIL {r.rule}: {r.example}: {r.message}")
        sys.stdout.write(f"{len(results) - len(bad)} of {len(results)} example(s) passed\n")
        return int(ExitCode.PRECONDITION if bad or rs.errors else ExitCode.OK)
    if cmd == "show":
        rule = rs.rules.get(args.rule_id)
        if rule is None:
            _err(f"unknown rule {args.rule_id!r}")
            return int(ExitCode.USAGE)
        sys.stdout.write(_json(rule.raw) if args.json else "\n".join(rule_section(rule)) + "\n")
        return int(ExitCode.OK)
    # list
    _report_diags(rs)
    rows = [r for r in rs.ordered()
            if (not args.platform or args.platform in r.platforms) and (not args.category or r.category == args.category)
            and (not args.nature or r.nature == args.nature)
            and (not args.min_severity or Severity.parse(r.severity) >= Severity.parse(args.min_severity))]  # fmt: skip
    if args.json:
        sys.stdout.write(_json([r.summary() for r in rows]))
    else:
        for r in rows:
            flag = "" if r.enabled else " (disabled)"
            sys.stdout.write(
                f"{r.id:<16} {','.join(r.platforms):<8} {r.severity:<8} {r.confidence:<6} {r.nature:<11} {r.name}{flag}\n"
            )
        sys.stdout.write(f"{len(rows)} rule(s)\n")
    return int(ExitCode.PRECONDITION if rs.errors else ExitCode.OK)


# ------------------------------------------------------------------------------- detect


def _cases_for(results: dict[str, Any], state_dir: str | None) -> dict[str, dict[str, Any]]:
    return case_summaries(CaseStore(state_dir) if state_dir else None, results)


def run_detection(
    current: dict[str, Any],
    rs: RuleSet,
    previous: list[Snap],
    notes: list[dict[str, str]],
    generated_at: str,
) -> dict[str, Any]:
    return detect(current, rs, previous=previous, generated_at=generated_at, history_notes=notes)


def _cmd_detect(args: argparse.Namespace) -> int:  # noqa: PLR0911, PLR0912, PLR0915
    cmd = args.detect_cmd
    if cmd == "run":
        rs = _rule_set(args)
        current = load_assessment(args.assessment)
        prev, notes = _history(args, current)
        stamp = args.generated_at or _now()
        results = run_detection(current, rs, prev, notes, stamp)
        problems = validate(results, "detection-results.schema.json", limit=5)
        if problems:
            _err("internal error: detection results violate their schema: " + "; ".join(problems))
            return int(ExitCode.ERROR)
        store = CaseStore(args.state_dir, args.actor) if args.state_dir else None
        if store:
            reg = store.observe(results)
            if not args.quiet:
                _err(
                    f"cases: {len(reg['new'])} new, {len(reg['reappeared'])} observed again after being closed"
                )
        view = _filter(results, args.min_severity)
        cases = case_summaries(store, view)
        if args.format == "json":
            text = _json(view)
        elif args.format == "text":
            text = render_text(view, cases)
        elif args.format == "markdown":
            text = render_detections_markdown(view, cases)
        else:
            text = render_html(current, None, stamp, detections=view, cases=cases)
        _emit(text, args.output)
        if not args.quiet:
            s = results["summary"]
            _err(
                f"{s['total']} detection(s), {s['indeterminate']} rule(s) indeterminate, {s['rule_errors']} rule error(s)"
            )
        return int(exit_code_for(results, args.fail_on))
    if cmd == "compare":
        rs = _rule_set(args)
        snaps = [Snap(load_assessment(p), p) for p in args.snapshots]
        doc = compare_detections(snaps, rs, args.generated_at or _now())
        problems = validate(doc, "detection-comparison.schema.json", limit=5)
        if problems:
            _err("internal error: comparison violates its schema: " + "; ".join(problems))
            return int(ExitCode.ERROR)
        if args.format == "json":
            _emit(_json(doc), args.output)
        else:
            lines = [f"{len(doc['snapshots'])} snapshots of {doc['host']['hostname']}"]
            for t in doc["transitions"]:
                lines.append(
                    f"{t['from']} -> {t['to']}: {len(t['new'])} new, {len(t['resolved'])} resolved, {len(t['persistent'])} persistent, {len(t['unverified'])} unverified"
                )
            lines += [
                f"  {r['state']:<12} {r['severity']:<8} {r['id']} {r['title']}"
                for r in doc["detections"]
            ]
            _emit("\n".join(lines) + "\n", args.output)
        st = doc["summary"]["states"]
        changed = (
            st.get("new", 0)
            + st.get("resolved", 0)
            + any(t["severity_changed"] for t in doc["transitions"])
        )
        return int(
            ExitCode.FINDINGS
            if changed
            else (ExitCode.PARTIAL if st.get("unverified") else ExitCode.OK)
        )
    results = _load_results(args.results)
    cases = _cases_for(results, getattr(args, "state_dir", None))
    if cmd == "show":
        matches = [d for d in results["detections"] if d["id"].startswith(args.detection_id)]
        if len(matches) != 1:
            _err(f"{args.detection_id!r} matches {len(matches)} detections")
            return int(ExitCode.USAGE)
        d = matches[0]
        sys.stdout.write(
            _json({**d, "investigation": cases[d["id"]]})
            if args.json
            else render_detection_detail(d, cases[d["id"]])
        )
        return int(ExitCode.OK)
    if cmd == "export":
        text = {
            "json": lambda: _json({**results, "investigation": cases}),
            "jsonl": lambda: to_jsonl(results, cases),
            "csv": lambda: to_csv(results, cases),
        }[args.format]()
        _emit(text, args.output)
        return int(ExitCode.OK)
    # report
    if args.format == "html":
        if not args.assessment:
            _err(
                "--assessment is required for an HTML report (the detections are embedded in the assessment report)"
            )
            return int(ExitCode.USAGE)
        text = render_html(
            load_assessment(args.assessment),
            None,
            args.generated_at or _now(),
            detections=results,
            cases=cases,
        )
    else:
        text = render_detections_markdown(results, cases)
    _emit(text, args.output)
    return int(ExitCode.OK)


# ---------------------------------------------------------------------------------- case


def _case_text(c: Any) -> str:
    out = [
        f"{c.id}  {c.title}",
        f"rule {c.rule_id}  severity {c.severity}  confidence {c.confidence}  host {c.hostname}",
        f"status: {c.status}" + ("  (observed again after being closed)" if c.reappeared else ""),
        f"first seen {c.first_seen}, last seen {c.last_seen}, {len(c.assessments)} assessment(s)",
    ]
    if c.linked:
        out.append("linked: " + ", ".join(c.linked))
    out += ["", "History:"] + [
        f"  {h['ts']} {h['actor']}: {h['from']} -> {h['to']}"
        + (f" ({h['note']})" if h["note"] else "")
        for h in c.status_history
    ]
    out += ["", "Notes:"] + [f"  {n['ts']} {n['actor']}: {n['text']}" for n in c.notes]
    return "\n".join(out) + "\n"


def _cmd_case(args: argparse.Namespace) -> int:
    store = CaseStore(args.state_dir, args.actor)
    cmd = args.case_cmd
    if cmd == "list":
        cases = [c for c in store.cases().values() if not args.status or c.status == args.status]
        if args.json:
            sys.stdout.write(_json([c.to_json() for c in cases]))
        else:
            for c in sorted(cases, key=lambda c: (c.status, c.id)):
                sys.stdout.write(f"{c.id}  {c.status:<13} {c.severity:<8} {c.rule_id}  {c.title}\n")
            sys.stdout.write(f"{len(cases)} case(s)\n")
        return int(ExitCode.OK)
    det = store.resolve_id(args.detection_id)
    if cmd == "show":
        c = store.cases()[det]
        sys.stdout.write(_json(c.to_json()) if args.json else _case_text(c))
    elif cmd == "status":
        c = store.set_status(det, args.status, args.note)
        sys.stdout.write(f"{det}: {c.status}\n")
    elif cmd == "note":
        c = store.add_note(det, args.text)
        sys.stdout.write(f"{det}: {len(c.notes)} note(s)\n")
    else:
        store.link(det, store.resolve_id(args.other_id))
        sys.stdout.write(f"{det} linked\n")
    return int(ExitCode.OK)


def dispatch(args: argparse.Namespace) -> int | None:  # noqa: PLR0911
    """Handle the commands of this module; ``None`` when ``args.cmd`` is not ours."""
    try:
        if args.cmd == "rules":
            return _cmd_rules(args)
        if args.cmd == "detect":
            return _cmd_detect(args)
        if args.cmd == "case":
            return _cmd_case(args)
    except (LoadError, HistoryError, TimelineError) as exc:
        _err(str(exc))
        return int(ExitCode.PRECONDITION)
    except CaseStoreError as exc:
        _err(str(exc))
        return int(ExitCode.PRECONDITION)
    except FileExistsError as exc:
        _err(f"refusing to overwrite {exc.filename}")
        return int(ExitCode.PRECONDITION)
    except OSError as exc:
        _err(f"{exc.strerror or exc}" + (f": {exc.filename}" if exc.filename else ""))
        return int(ExitCode.ERROR)
    return None
