"""Command line for the validation lab, reached as ``python -m shared.engine validate <verb>``.

    list | show | run | evaluate | compare | baseline | report | calibrate | lab

``validate FILE`` (check a document against its schema) keeps working: only the verbs above are
routed here. Exit codes follow ``docs/contracts.md``: 0 all scenarios passed (or no regressions,
no unexpected differences), 4 failures / regressions / unexpected differences, 6 incomplete
(errors, inconclusive, skipped or not-comparable), 3 bad input or an unsafe/unverified environment,
2 usage, 5 confirmation declined.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from shared.reporting.contracts import ExitCode
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.rules.cli import _emit, _err
from shared.validation import render
from shared.validation.baseline import (
    BaselineError,
    capture_baseline,
    check_baseline,
    diff_baseline,
    load_baseline,
)
from shared.validation.calibrate import recommend
from shared.validation.evaluate import DatasetError, build_dataset
from shared.validation.history import HistoryError, latest, load_results, save_run
from shared.validation.model import ScenarioSet, check_against_rules, load_scenarios
from shared.validation.regress import ComparisonError, compare_runs
from shared.validation.runner import ValidationError, run_scenarios, telemetry_rule_set

VERBS = ("list", "show", "run", "evaluate", "compare", "baseline", "report", "calibrate", "lab")
FORMATS = ("text", "json", "markdown", "html")


def _json(doc: Any) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _selection(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--scenarios",
        action="append",
        default=[],
        metavar="PATH",
        help="extra scenario pack file or directory (repeatable)",
    )
    p.add_argument(
        "--no-library", action="store_true", help="do not load the built-in scenario library"
    )
    p.add_argument(
        "--scenario",
        action="append",
        default=[],
        metavar="ID",
        help="only this scenario (repeatable)",
    )
    p.add_argument("--platform", choices=("linux", "windows"))
    p.add_argument("--kind", choices=("positive", "negative", "coverage"))
    p.add_argument("--tag", metavar="TAG")


def _rules(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--rules-dir",
        action="append",
        default=[],
        metavar="PATH",
        help="extra rule pack to evaluate alongside the library (repeatable)",
    )
    p.add_argument(
        "--no-rule-library",
        action="store_true",
        help="evaluate only the packs given with --rules-dir",
    )


def build_parser() -> argparse.ArgumentParser:  # noqa: PLR0915 - one flat list of sub-commands
    ap = argparse.ArgumentParser(
        prog="python -m shared.engine validate",
        description="Validation lab and detection quality framework: scenarios, metrics, regressions, baselines.",
    )
    sub = ap.add_subparsers(dest="verb", required=True)

    p = sub.add_parser("list", help="list scenarios")
    _selection(p)
    p.add_argument("--format", choices=("text", "json"), default="text")

    p = sub.add_parser("show", help="show one scenario (and its result from --results)")
    p.add_argument("scenario_id")
    _selection(p)
    p.add_argument("--results", metavar="FILE")
    p.add_argument("--format", choices=("text", "json"), default="text")

    for name, helptext in (
        ("run", "evaluate scenarios (synthetic by default; --live needs a verified lab)"),
        ("evaluate", "evaluate custom scenario packs (DATASET) against the rules"),
    ):
        p = sub.add_parser(name, help=helptext)
        if name == "evaluate":
            p.add_argument(
                "dataset", nargs="+", metavar="DATASET", help="scenario pack file or directory"
            )
            p.add_argument(
                "--with-library", action="store_true", help="also load the built-in library"
            )
        _selection(p)
        _rules(p)
        p.add_argument("--format", choices=FORMATS, default="text")
        p.add_argument("--output", metavar="FILE", help="write the report here (must not exist)")
        p.add_argument(
            "--results-out",
            metavar="FILE",
            help="also write the JSON results here (must not exist)",
        )
        p.add_argument(
            "--history-dir", metavar="DIR", help="save this run (immutable) in a history directory"
        )
        p.add_argument(
            "--compare-to",
            metavar="RESULTS",
            help="compare with an earlier run and report regressions",
        )
        p.add_argument(
            "--compare-latest",
            action="store_true",
            help="compare with the newest run in --history-dir (before saving)",
        )
        p.add_argument(
            "--dry-run",
            action="store_true",
            help="load and check scenarios, build their datasets, run nothing",
        )
        p.add_argument(
            "--live",
            action="store_true",
            help="execute lab actions and collect real telemetry (disposable lab only)",
        )
        p.add_argument(
            "--lab-dir", metavar="DIR", help="initialised lab directory (see 'validate lab init')"
        )
        p.add_argument(
            "--attest-disposable",
            action="store_true",
            help="you attest this host is disposable when it cannot be verified (recorded as attested, not verified)",
        )
        p.add_argument("--yes", action="store_true", help="confirm live execution without a prompt")

    p = sub.add_parser(
        "compare",
        help="compare two validation runs (regressions) or a baseline and a capture (differences)",
    )
    p.add_argument("first", metavar="BASELINE_OR_RESULTS")
    p.add_argument("second", metavar="CURRENT")
    p.add_argument(
        "--tolerance", type=float, default=0.0, help="ignore ratio drops up to this size"
    )
    p.add_argument("--max-age-days", type=int)
    p.add_argument("--format", choices=("json", "text", "markdown"), default="json")
    p.add_argument("--output", metavar="FILE")

    p = sub.add_parser("baseline", help="capture, inspect and compare known-good baselines")
    bsub = p.add_subparsers(dest="baseline_cmd", required=True)
    c = bsub.add_parser("capture", help="store a verified telemetry store as a named baseline")
    c.add_argument("store")
    c.add_argument("--name", required=True)
    c.add_argument("--output-dir", required=True, metavar="DIR")
    c.add_argument("--purpose", default="")
    c.add_argument("--max-age-days", type=int, default=30)
    c.add_argument(
        "--expected-changes",
        metavar="FILE",
        help="JSON list of declared allowances (category, change, identity_pattern, attributes, reason)",
    )
    c.add_argument(
        "--lab-attested",
        action="store_true",
        help="the capture was made in an attested disposable lab",
    )
    for nm in ("show", "check"):
        s = bsub.add_parser(nm)
        s.add_argument("baseline")
        if nm == "check":
            s.add_argument("--against", metavar="STORE")
            s.add_argument("--max-age-days", type=int)
        s.add_argument("--format", choices=("text", "json"), default="text")
    d = bsub.add_parser("diff", help="compare a capture with a baseline")
    d.add_argument("baseline")
    d.add_argument("current")
    d.add_argument("--max-age-days", type=int)
    d.add_argument("--format", choices=("json", "text", "markdown"), default="json")
    d.add_argument("--output", metavar="FILE")

    p = sub.add_parser("report", help="render saved results")
    p.add_argument("results")
    p.add_argument(
        "--comparison", metavar="FILE", help="a validation-comparison document to include"
    )
    p.add_argument("--format", choices=FORMATS, default="markdown")
    p.add_argument("--output", metavar="FILE")

    p = sub.add_parser("calibrate", help="print calibration recommendations for saved results")
    p.add_argument("results")
    p.add_argument("--format", choices=("text", "json"), default="text")

    p = sub.add_parser("lab", help="prepare and check a disposable lab directory")
    lsub = p.add_subparsers(dest="lab_cmd", required=True)
    li = lsub.add_parser("init", help="create a lab directory and its marker")
    li.add_argument("lab_dir")
    lc = lsub.add_parser(
        "check", help="verify isolation and lab readiness without running anything"
    )
    lc.add_argument("--lab-dir", metavar="DIR")
    lc.add_argument("--attest-disposable", action="store_true")
    lc.add_argument("--format", choices=("text", "json"), default="text")
    return ap


# ------------------------------------------------------------------------------ helpers


def _load(args: argparse.Namespace, *, library: bool = True) -> tuple[ScenarioSet, Any]:
    ss = load_scenarios(args.scenarios, include_library=library and not args.no_library)
    rs = telemetry_rule_set(
        getattr(args, "rules_dir", []), include_library=not getattr(args, "no_rule_library", False)
    )
    diags = ss.errors + check_against_rules(ss, set(rs.rules))
    if diags:
        for d in diags[:20]:
            _err(str(d))
        raise ValidationError(f"{len(diags)} scenario problem(s); fix them or remove the pack")
    return ss, rs


def _select(ss: ScenarioSet, args: argparse.Namespace) -> list[Any]:
    chosen = ss.select(args.scenario or None, args.platform, args.kind, args.tag)
    missing = sorted(set(args.scenario) - set(ss.scenarios))
    if missing:
        raise ValidationError("unknown scenario(s): " + ", ".join(missing))
    return chosen


def _read_json(path: str, what: str) -> Any:
    try:
        return load_json_strict(path, 64 * 1024 * 1024, what)[0]
    except JsonInputError as exc:
        raise ValidationError(str(exc)) from None


def _render(doc: dict[str, Any], fmt: str, comparison: dict[str, Any] | None = None) -> str:
    if fmt == "json":
        return _json(doc)
    if fmt == "markdown":
        return render.render_markdown(doc, comparison)
    if fmt == "html":
        return render.render_html(doc, comparison)
    return render.render_text(doc)


def _exit_for(doc: dict[str, Any], comparison: dict[str, Any] | None) -> int:
    code = {"ok": ExitCode.OK, "failures": ExitCode.FINDINGS, "incomplete": ExitCode.PARTIAL}[
        doc["summary"]["exit_status"]
    ]
    if comparison is not None:
        if comparison["summary"]["exit_status"] == "regressions":
            code = ExitCode.FINDINGS
        elif comparison["summary"]["exit_status"] == "not_comparable" and code == ExitCode.OK:
            code = ExitCode.PARTIAL
    return int(code)


# ------------------------------------------------------------------------------ verbs


def _cmd_list(args: argparse.Namespace) -> int:
    ss = load_scenarios(args.scenarios, include_library=not args.no_library)
    for d in ss.errors:
        _err(str(d))
    rows = [s.summary() for s in _select(ss, args)]
    if args.format == "json":
        sys.stdout.write(
            _json(
                {
                    "scenarios": rows,
                    "diagnostics": [str(d) for d in ss.diagnostics],
                    "packs": ss.packs,
                }
            )
        )
    else:
        for r in rows:
            sys.stdout.write(
                f"{r['id']:<18} {r['kind']:<9} {'/'.join(r['platforms']):<8} {r['title']}"
                + (" [live]" if r["live"] else "")
                + "\n"
            )
        sys.stdout.write(f"{len(rows)} scenario(s)\n")
    return int(ExitCode.PRECONDITION if ss.errors else ExitCode.OK)


def _cmd_show(args: argparse.Namespace) -> int:
    ss = load_scenarios(args.scenarios, include_library=not args.no_library)
    s = ss.scenarios.get(args.scenario_id)
    if s is None:
        _err(f"unknown scenario {args.scenario_id}")
        return int(ExitCode.PRECONDITION)
    result = None
    if args.results:
        result = next((x for x in load_results(args.results)["scenarios"] if x["id"] == s.id), None)
    if args.format == "json":
        sys.stdout.write(_json({"scenario": s.raw, "result": result}))
        return int(ExitCode.OK)
    lines = [
        f"{s.id}  {s.title}",
        f"  kind: {s.kind}   platforms: {', '.join(s.platforms)}   versions: {', '.join(s.supported_versions)}   pack: {s.pack}",
        f"  {s.description}",
        f"  objective: {s.objective}",
    ]
    if s.known_issue:
        lines.append(f"  KNOWN ISSUE: {s.known_issue['description']}")
    for pre in s.preconditions:
        lines.append(
            f"  precondition: {pre['kind']} {pre.get('value', '')} {pre.get('description', '')}".rstrip()
        )
    lines.append(f"  rules under test: {', '.join(s.rules_under_test)}")
    exp = s.expect
    for d in exp.get("detections", []):
        lines.append(
            f"  expects detection {d['rule']} count={d.get('count', '>=1')} severity={d.get('severity', 'any')} confidence={d.get('confidence', 'any')}"
        )
    lines += [f"  expects no detection: {r}" for r in exp.get("absent", [])]
    lines += [
        f"  expects inconclusive: {i['rule']} ({i.get('reason_contains', 'any reason')})"
        for i in exp.get("indeterminate", [])
    ]
    lines += [f"  expects coverage {c}: {st}" for c, st in exp.get("coverage", {}).items()]
    lines += [f"  limitation: {x}" for x in s.limitations]
    lines.append(
        f"  cleanup: {'required - ' if s.cleanup.get('required') else 'none required - '}{s.cleanup.get('description', '')}"
    )
    if s.lab:
        lines.append(
            "  lab actions: "
            + (", ".join(a["action"] for a in s.lab.get("actions", [])) or "none (collection only)")
        )
    if result:
        lines.append(f"  last result: {result['status']} {result['reason']}")
    sys.stdout.write("\n".join(lines) + "\n")
    return int(ExitCode.OK)


def _dry_run(chosen: list[Any], args: argparse.Namespace, rs: Any) -> int:
    plan, bad = [], []
    for s in chosen:
        try:
            tel = build_dataset(s.dataset, s, role="dataset")
            if s.baseline_dataset is not None:
                build_dataset(s.baseline_dataset, s, role="baseline")
            plan.append(
                {
                    "id": s.id,
                    "records": tel["summary"]["records"],
                    "action": "evaluate dataset with the detection engine",
                    "modifies_host": False,
                }
            )
        except DatasetError as exc:
            bad.append(str(exc))
    if args.live:
        from shared.validation import lab  # noqa: PLC0415

        plan = lab.live_plan(chosen, lab_dir=args.lab_dir, attest=args.attest_disposable)
    doc = {
        "dry_run": True,
        "mode": "live" if args.live else "synthetic",
        "scenarios": plan,
        "rules": len(rs.rules),
        "problems": bad,
        "executes_nothing": True,
    }
    if args.format == "json":
        sys.stdout.write(_json(doc))
    else:
        sys.stdout.write(
            f"DRY RUN ({doc['mode']}): nothing is executed and nothing on this host is modified.\n"
        )
        for p in plan:
            sys.stdout.write(f"  would run {p['id']}: {p.get('action', p)}\n")
        for b in bad:
            sys.stdout.write(f"  PROBLEM {b}\n")
        sys.stdout.write(f"{len(plan)} scenario(s), {len(rs.rules)} rule(s)\n")
    return int(ExitCode.PRECONDITION if bad else ExitCode.OK)


def _cmd_run(args: argparse.Namespace) -> int:  # noqa: PLR0911, PLR0912
    library = not (args.verb == "evaluate" and not args.with_library)
    if args.verb == "evaluate":
        args.scenarios = [*args.scenarios, *args.dataset]
    ss, rs = _load(args, library=library)
    chosen = _select(ss, args)
    if not chosen:
        _err("no scenario matches the selection")
        return int(ExitCode.PRECONDITION)
    if args.dry_run:
        return _dry_run(chosen, args, rs)
    command = "validate " + " ".join(sys.argv[2:])[:900]
    if args.live:
        from shared.validation import lab  # noqa: PLC0415

        doc, code = lab.run_live(
            chosen,
            ss,
            rs,
            lab_dir=args.lab_dir,
            attest=args.attest_disposable,
            assume_yes=args.yes,
            command=command,
            recommend=recommend,
        )
        if doc is None:
            return code
    else:
        doc = run_scenarios(chosen, ss, rs, command=command, recommend=recommend)
    comparison = None
    if args.compare_to:
        comparison = compare_runs(load_results(args.compare_to), doc)
    elif args.compare_latest:
        if not args.history_dir:
            _err("--compare-latest needs --history-dir")
            return int(ExitCode.USAGE)
        try:
            comparison = compare_runs(latest(args.history_dir, 1)[0], doc)
        except HistoryError as exc:
            _err(f"no earlier run to compare with: {exc}")
    if args.history_dir:
        path = save_run(doc, args.history_dir)
        _err(f"saved {path}")
    if args.results_out:
        _emit(_json(doc), args.results_out)
    _emit(_render(doc, args.format, comparison), args.output)
    return _exit_for(doc, comparison)


def _is_baseline_dir(p: str) -> bool:
    return Path(p).is_dir() and (Path(p) / "baseline.json").is_file()


def _cmd_compare(args: argparse.Namespace) -> int:
    first_baseline = _is_baseline_dir(args.first)
    if first_baseline:
        return _baseline_diff(args.first, args.second, args)
    a, b = load_results(args.first), load_results(args.second)
    doc = compare_runs(a, b, tolerance=args.tolerance)
    text = _json(doc) if args.format == "json" else render.render_comparison_markdown(doc)
    if args.format == "text":
        text = (
            "\n".join(
                [
                    f"{doc['summary']['exit_status']}: {doc['summary']['regressions']} regression(s), {doc['summary']['improvements']} improvement(s)"
                ]
                + [f"  - {r['message']}" for r in doc["regressions"]]
            )
            + "\n"
        )
    _emit(text, args.output)
    return {
        "ok": int(ExitCode.OK),
        "regressions": int(ExitCode.FINDINGS),
        "not_comparable": int(ExitCode.PARTIAL),
    }[doc["summary"]["exit_status"]]


def _baseline_diff(baseline: str, current: str, args: argparse.Namespace) -> int:
    from shared.telemetry.ingest import IngestError, load_telemetry  # noqa: PLC0415

    meta, tel = load_baseline(baseline)
    try:
        cur = load_baseline(current)[1] if _is_baseline_dir(current) else load_telemetry(current)
    except (IngestError, BaselineError) as exc:
        raise BaselineError(f"{current}: {exc}") from None
    doc = diff_baseline(meta, tel, cur, max_age_days=args.max_age_days)
    if args.format == "json":
        text = _json(doc)
    elif args.format == "markdown":
        text = render.render_baseline_diff_markdown(doc)
    else:
        s = doc["summary"]
        text = (
            f"{s['exit_status']}: {s['total']} difference(s), {s['unexpected']} unexpected, {s['expected']} expected, {s['indeterminate_categories']} categories not conclusive\n"
            + "".join(
                f"  [{c['severity']}] {c['code']}: {c['message']}\n" for c in doc["compatibility"]
            )
            + "".join(
                f"  {d['classification']:<10} {d['change']} {d['category']} {d['identity'][:80]}\n"
                for d in doc["differences"]
            )
        )
    _emit(text, args.output)
    return {
        "ok": int(ExitCode.OK),
        "unexpected_differences": int(ExitCode.FINDINGS),
        "incomplete": int(ExitCode.PARTIAL),
        "incompatible": int(ExitCode.PRECONDITION),
    }[doc["summary"]["exit_status"]]


def _cmd_baseline(args: argparse.Namespace) -> int:
    cmd = args.baseline_cmd
    if cmd == "capture":
        allow = (
            _read_json(args.expected_changes, "expected changes") if args.expected_changes else []
        )
        root = capture_baseline(
            args.store,
            args.output_dir,
            args.name,
            purpose=args.purpose,
            max_age_days=args.max_age_days,
            expected_changes=allow,
            lab_attested=args.lab_attested,
        )
        sys.stdout.write(f"baseline stored in {root}\n")
        return int(ExitCode.OK)
    if cmd == "diff":
        return _baseline_diff(args.baseline, args.current, args)
    meta, tel = load_baseline(args.baseline)
    if cmd == "show":
        sys.stdout.write(
            _json(meta)
            if args.format == "json"
            else f"{meta['name']}: captured {meta['captured_at']} on {meta['host']['hostname']} ({meta['host']['os']['family']}), {meta['source']['records']} records, complete={meta['source']['complete']}, lab_attested={meta['lab_attested']}\n"
        )
        return int(ExitCode.OK)
    from shared.telemetry.ingest import IngestError, load_telemetry  # noqa: PLC0415

    try:
        against = load_telemetry(args.against) if args.against else None
    except IngestError as exc:
        raise BaselineError(str(exc)) from None
    issues = check_baseline(meta, tel, against, max_age_days=args.max_age_days)
    if args.format == "json":
        sys.stdout.write(_json({"baseline": meta["name"], "issues": issues}))
    else:
        sys.stdout.write(
            "".join(f"[{i['severity']}] {i['code']}: {i['message']}\n" for i in issues)
            or "no issues\n"
        )
    if any(i["severity"] == "error" for i in issues):
        return int(ExitCode.PRECONDITION)
    return int(ExitCode.PARTIAL if any(i["severity"] == "warning" for i in issues) else ExitCode.OK)


def _cmd_report(args: argparse.Namespace) -> int:
    doc = load_results(args.results)
    comparison = _read_json(args.comparison, "comparison") if args.comparison else None
    _emit(_render(doc, args.format, comparison), args.output)
    return int(ExitCode.OK)


def _cmd_calibrate(args: argparse.Namespace) -> int:
    doc = load_results(args.results)
    recs = doc["recommendations"] or recommend(doc)
    if args.format == "json":
        sys.stdout.write(_json(recs))
        return int(ExitCode.OK)
    sys.stdout.write(
        "Calibration recommendations are advice for a developer to review; nothing is changed.\n"
    )
    for r in recs:
        sys.stdout.write(
            f"\n[{r['priority']}] {r['id']} (evidence {r['strength']})\n  {r['summary']}\n"
        )
        sys.stdout.writelines(f"    evidence: {e}\n" for e in r["evidence"][:4])
        sys.stdout.writelines(f"    trade-off: {t}\n" for t in r["tradeoffs"][:3])
    return int(ExitCode.OK)


def _cmd_lab(args: argparse.Namespace) -> int:
    from shared.validation import lab  # noqa: PLC0415

    return lab.lab_command(args)


def main(argv: list[str]) -> int:  # noqa: PLR0911 - one return per verb
    args = build_parser().parse_args(argv)
    try:
        if args.verb == "list":
            return _cmd_list(args)
        if args.verb == "show":
            return _cmd_show(args)
        if args.verb in ("run", "evaluate"):
            return _cmd_run(args)
        if args.verb == "compare":
            return _cmd_compare(args)
        if args.verb == "baseline":
            return _cmd_baseline(args)
        if args.verb == "report":
            return _cmd_report(args)
        if args.verb == "calibrate":
            return _cmd_calibrate(args)
        return _cmd_lab(args)
    except (ValidationError, HistoryError, ComparisonError, BaselineError) as exc:
        _err(str(exc))
        return int(ExitCode.PRECONDITION)
    except FileExistsError as exc:
        _err(f"refusing to overwrite {exc.filename}")
        return int(ExitCode.PRECONDITION)
    except OSError as exc:
        _err(f"{exc.strerror or exc}" + (f": {exc.filename}" if exc.filename else ""))
        return int(ExitCode.ERROR)
