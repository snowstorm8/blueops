"""Command line for the assessment engine (``python -m shared.engine``).

    list      show the modules and profiles available on this platform
    run       execute a profile or module list and write an assessment directory
    compare   compare two assessments (or audit reports) and write a snapshot comparison
    report    render an assessment as Markdown / HTML / JSON
    validate  check a document against its schema
    verify    check an assessment directory against its manifest.json

Exit codes follow ``docs/contracts.md``: 0 ok, 1 error, 2 usage, 3 precondition, 4 findings (or
differences), 6 partial. The tool reads and writes only the paths it is given.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from shared.engine import ENGINE_NAME, ENGINE_VERSION
from shared.engine.assessment import AssessmentError, make_assessment_dir, run_assessment
from shared.engine.loader import ALLOW_UNVERIFIED_HELP, LoadError, load_assessment
from shared.engine.manifest import verify_directory, write_manifest
from shared.engine.module import ModuleError
from shared.engine.profile import PROFILES_DIR, Profile, ProfileError, find_profile, list_profiles
from shared.engine.registry import PluginError, Registry
from shared.engine.runner import RunContext, current_platform, utc_now
from shared.reporting.contracts import ExitCode, Severity
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.render_html import render_html
from shared.reporting.render_markdown import render_comparison_markdown, render_markdown
from shared.reporting.schema_lite import validate
from shared.reporting.snapshot_compare import (
    ComparisonError,
    compare_snapshots,
    comparison_exit_code,
)
from shared.rules.cli import dispatch as rules_dispatch
from shared.rules.cli import register as rules_register
from shared.rules.cli import run_detection
from shared.rules.engine import exit_code_for as detection_exit_code
from shared.rules.history import HistoryStore
from shared.rules.investigation import CaseStore, case_summaries
from shared.rules.loader import load_rule_set
from shared.telemetry.cli import dispatch as telemetry_dispatch
from shared.telemetry.cli import register as telemetry_register

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOC_SCHEMAS = {
    "assessment": "assessment.schema.json",
    "snapshot-comparison": "snapshot-comparison.schema.json",
    "assessment-manifest": "assessment-manifest.schema.json",
    "module": "module-manifest.schema.json",
    "profile": "assessment-profile.schema.json",
    "baseline-diff": "baseline-diff.schema.json",
    "detections": "detections.schema.json",
    "run-manifest": "run-manifest.schema.json",
    "detection-results": "detection-results.schema.json",
    "detection-comparison": "detection-comparison.schema.json",
    "rule-pack": "detection-rule.schema.json",
}


def _err(msg: str) -> None:
    sys.stderr.write(f"blueops: {msg}\n")


def _write_new(path: Path, text: str) -> None:
    """Create ``path`` (mode 0600), refusing to overwrite: evidence is append-only."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _emit(text: str, output: str | None) -> None:
    if output:
        _write_new(Path(output), text)
    else:
        sys.stdout.write(text)


def _json(doc: Any) -> str:
    return json.dumps(doc, indent=2) + "\n"


def _registry(plugin_dirs: list[str]) -> Registry:
    reg = Registry.with_builtins()
    for d in plugin_dirs:
        reg.discover(d)
    problems = reg.check_dependencies()
    if problems:
        raise ModuleError("; ".join(problems[:5]))
    return reg


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m shared.engine",
        description="BlueOps assessment engine. Read-only: modules inspect the host; the engine "
        "only writes the output directory you name.",
    )
    p.add_argument("--version", action="version", version=f"{ENGINE_NAME} {ENGINE_VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--platform", choices=("linux", "windows"), help="default: this OS")
        sp.add_argument(
            "--plugin-dir",
            action="append",
            default=[],
            metavar="DIR",
            help="directory of *.module.json plugin manifests (trusted; repeatable)",
        )

    ls = sub.add_parser("list", help="list modules and profiles")
    common(ls)
    ls.add_argument("--json", action="store_true")

    run = sub.add_parser("run", help="run a profile or modules and write an assessment")
    common(run)
    run.add_argument("--profile", default="default", help="profile name or file (default: default)")
    run.add_argument(
        "--modules",
        metavar="LIST",
        help="comma list (ids or short names); overrides the profile's modules",
    )
    run.add_argument(
        "--output-dir",
        required=True,
        metavar="DIR",
        help="parent directory for the assessment directory",
    )
    run.add_argument(
        "--timeout",
        type=int,
        metavar="SECONDS",
        help="per-module time limit (overrides module and profile)",
    )
    run.add_argument(
        "--fail-on", choices=[s.label for s in Severity], help="severity that makes the run exit 4"
    )
    run.add_argument(
        "--report",
        default="html,markdown",
        metavar="LIST",
        help="formats written beside assessment.json: html,markdown or none",
    )
    run.add_argument(
        "--compare",
        action="append",
        default=[],
        metavar="PATH",
        help="earlier assessment/report/comparison (newest first; repeatable)",
    )
    run.add_argument("--allow-host-mismatch", action="store_true")
    run.add_argument(
        "--json",
        action="store_true",
        help="print assessment.json on stdout (human text goes to stderr)",
    )
    run.add_argument("--quiet", action="store_true")
    run.add_argument(
        "--detect",
        action="store_true",
        help="also run the detection rules; writes detections.json and adds a Detections section",
    )
    run.add_argument(
        "--rules-dir",
        action="append",
        default=[],
        metavar="PATH",
        help="extra rule packs (with --detect)",
    )
    run.add_argument(
        "--history",
        metavar="DIR",
        help="earlier assessments of this host for history-aware rules (with --detect)",
    )
    run.add_argument(
        "--state-dir", metavar="DIR", help="register detections as cases here (with --detect)"
    )
    run.add_argument("--actor", metavar="NAME")

    rules_register(sub)
    telemetry_register(sub)
    cmp_ = sub.add_parser("compare", help="compare two assessments or audit reports")
    cmp_.add_argument("baseline")
    cmp_.add_argument("current")
    cmp_.add_argument("--format", choices=("json", "markdown"), default="json")
    cmp_.add_argument("--output", metavar="FILE", help="write here (must not exist)")
    cmp_.add_argument("--allow-host-mismatch", action="store_true")
    cmp_.add_argument("--allow-unverified", action="store_true", help=ALLOW_UNVERIFIED_HELP)
    cmp_.add_argument("--generated-at", metavar="TIMESTAMP")

    rep = sub.add_parser("report", help="render an assessment")
    rep.add_argument("assessment")
    rep.add_argument("--format", choices=("html", "markdown", "json"), default="html")
    rep.add_argument("--output", metavar="FILE", help="write here (must not exist)")
    rep.add_argument("--compare", action="append", default=[], metavar="PATH")
    rep.add_argument("--allow-host-mismatch", action="store_true")
    rep.add_argument("--allow-unverified", action="store_true", help=ALLOW_UNVERIFIED_HELP)
    rep.add_argument("--generated-at", metavar="TIMESTAMP")

    val = sub.add_parser("validate", help="validate a document against its schema")
    val.add_argument("file")

    ver = sub.add_parser("verify", help="verify an assessment directory against its manifest")
    ver.add_argument("directory")
    ver.add_argument("--expect-sha256", metavar="DIGEST")
    return p


# ----------------------------------------------------------------------------- list


def _cmd_list(args: argparse.Namespace) -> int:
    platform = args.platform or current_platform()
    reg = _registry(args.plugin_dir)
    mods = reg.all(platform)
    profiles = list_profiles(platform, PROFILES_DIR)
    if args.json:
        sys.stdout.write(
            _json(
                {"platform": platform, "modules": [m.to_json() for m in mods], "profiles": profiles}
            )
        )
        return int(ExitCode.OK)
    sys.stdout.write(f"Modules for {platform}:\n")
    for m in mods:
        dep = f"  (requires {', '.join(m.requires)})" if m.requires else ""
        sys.stdout.write(f"  {m.id:<24} {m.category:<12} {m.title}{dep}\n")
    sys.stdout.write("Profiles: " + (", ".join(profiles) or "none") + "\n")
    return int(ExitCode.OK)


# ------------------------------------------------------------------------ compare helpers


def _load_comparisons(
    paths: list[str],
    cur: dict[str, Any],
    allow: bool,
    generated_at: str | None = None,
    verify: bool = True,
) -> list[dict[str, Any]]:
    out = []
    for path in paths:
        p = Path(path)
        if p.is_file():
            try:
                raw, _ = load_json_strict(p, 256 * 1024 * 1024, "comparison")
            except JsonInputError:
                raw = None
            if isinstance(raw, dict) and raw.get("kind") == "snapshot-comparison":
                problems = validate(raw, "snapshot-comparison.schema.json", limit=3)
                if problems:
                    raise LoadError(f"{p}: invalid comparison: {'; '.join(problems)}")
                out.append(raw)
                continue
        base = load_assessment(path, verify=verify)
        out.append(
            compare_snapshots(base, cur, allow_host_mismatch=allow, generated_at=generated_at)
        )
    return out


def _cmd_compare(args: argparse.Namespace) -> int:
    base = load_assessment(args.baseline, verify=not args.allow_unverified)
    cur = load_assessment(args.current, verify=not args.allow_unverified)
    cmp_doc = compare_snapshots(
        base, cur, allow_host_mismatch=args.allow_host_mismatch, generated_at=args.generated_at
    )
    problems = validate(cmp_doc, "snapshot-comparison.schema.json", limit=5)
    if problems:
        _err("internal error: the comparison violates its schema: " + "; ".join(problems))
        return int(ExitCode.ERROR)
    _emit(
        _json(cmp_doc) if args.format == "json" else render_comparison_markdown(cmp_doc),
        args.output,
    )
    s = cmp_doc["summary"]
    _err(
        f"{s['new']} new, {s['resolved']} resolved, {s['persistent']} persistent, "
        f"{s['severity_increased']} worse, {s['severity_decreased']} better; trend {s['trend']}"
    )
    return int(comparison_exit_code(cmp_doc))


# ------------------------------------------------------------------------------ report


def _cmd_report(args: argparse.Namespace) -> int:
    doc = load_assessment(args.assessment, verify=not args.allow_unverified)
    comparisons = _load_comparisons(
        args.compare,
        doc,
        args.allow_host_mismatch,
        args.generated_at,
        verify=not args.allow_unverified,
    )
    stamp = args.generated_at or utc_now()
    if args.format == "json":
        text = _json(doc)
    elif args.format == "markdown":
        text = render_markdown(doc, comparisons, stamp)
    else:
        text = render_html(doc, comparisons, stamp)
    _emit(text, args.output)
    return int(ExitCode.OK)


# ------------------------------------------------------------------- validate / verify


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        doc, _ = load_json_strict(args.file, 256 * 1024 * 1024, "document")
    except JsonInputError as exc:
        _err(str(exc))
        return int(ExitCode.PRECONDITION)
    kind = doc.get("kind") if isinstance(doc, dict) else None
    schema = DOC_SCHEMAS.get(kind) if kind else "audit-report.schema.json"
    if schema is None:
        _err(f"unknown document kind {str(kind)[:40]!r}")
        return int(ExitCode.PRECONDITION)
    problems = validate(doc, schema, limit=20)
    for line in problems:
        _err(line)
    if problems:
        return int(ExitCode.PRECONDITION)
    sys.stdout.write(f"{args.file}: valid ({schema})\n")
    return int(ExitCode.OK)


def _cmd_verify(args: argparse.Namespace) -> int:
    problems = verify_directory(args.directory, args.expect_sha256)
    for line in problems:
        _err(line)
    if problems:
        return int(ExitCode.PRECONDITION)
    sys.stdout.write(f"{args.directory} matches its manifest\n")
    return int(ExitCode.OK)


# --------------------------------------------------------------------------------- run


def _select(args: argparse.Namespace, reg: Registry, platform: str) -> tuple[Profile, list[str]]:
    profile = find_profile(args.profile, platform)
    if args.modules:
        ids = []
        for raw in args.modules.split(","):
            name = raw.strip()
            if not name:
                continue
            ids.append(name if "." in name else f"{platform}.{name}")
        if not ids:
            raise ProfileError("--modules is empty")
        profile = Profile(
            name="custom",
            platform=platform,
            modules=ids,
            description="ad-hoc module list",
            fail_on=profile.fail_on,
            timeout_seconds=profile.timeout_seconds,
            options=profile.options,
        )
    return profile, profile.resolve(reg)


def _summary_lines(doc: dict[str, Any], directory: Path) -> list[str]:
    s = doc["summary"]
    sev = s["by_severity"]
    lines = [f"assessment {doc['assessment']['id']} ({doc['assessment']['status']}) -> {directory}"]
    for m in doc["modules"]:
        note = f"  ({m['reason']})" if m.get("reason") else ""
        lines.append(f"  {m['id']:<24} {m['status']:<14} {m['findings']:>3} finding(s){note}")
    lines.append(
        f"  total {s['total']}: "
        + ", ".join(f"{sev[k]} {k}" for k in ("critical", "high", "medium", "low", "info"))
    )
    return lines


def _cmd_run(args: argparse.Namespace) -> int:  # noqa: PLR0912, PLR0915 - setup, run, write
    platform = args.platform or current_platform()
    reg = _registry(args.plugin_dir)
    profile, selected = _select(args, reg, platform)
    fail_on = args.fail_on or profile.fail_on
    formats = (
        [] if args.report == "none" else [f.strip() for f in args.report.split(",") if f.strip()]
    )
    bad = [f for f in formats if f not in ("html", "markdown")]
    if bad:
        _err(f"--report: unsupported format(s): {', '.join(bad)}")
        return int(ExitCode.USAGE)
    if args.timeout is not None and not 1 <= args.timeout <= 86400:
        _err("--timeout must be between 1 and 86400 seconds")
        return int(ExitCode.USAGE)
    stamp = utc_now().replace("-", "").replace(":", "")
    out_dir = make_assessment_dir(Path(args.output_dir), stamp, profile.name)
    ctx = RunContext(
        repo_root=REPO_ROOT,
        out_root=out_dir,
        options=dict(profile.options),
        timeout_override=args.timeout or profile.timeout_seconds,
        platform_name=platform,
    )
    if not args.quiet:
        _err(
            f"running {len(selected)} module(s) of profile {profile.name} on {platform} (read-only)"
        )
    result = run_assessment(reg, selected, ctx, profile_name=profile.name, fail_on=fail_on)
    doc = result.document
    problems = validate(doc, "assessment.schema.json", limit=5)
    if problems:
        _err("internal error: the assessment violates its schema: " + "; ".join(problems))
        _err(f"module reports were kept in {out_dir}")
        return int(ExitCode.ERROR)
    code = result.exit_code
    comparisons: list[dict[str, Any]] = []
    if args.compare:
        try:
            comparisons = _load_comparisons(args.compare, doc, args.allow_host_mismatch)
        except (LoadError, ComparisonError) as exc:
            _err(f"comparison skipped: {exc}")
            if code == ExitCode.OK:
                code = ExitCode.PARTIAL
    _write_new(out_dir / "assessment.json", _json(doc))
    detections: dict[str, Any] | None = None
    cases: dict[str, dict[str, Any]] | None = None
    if args.detect:
        rs = load_rule_set(args.rules_dir)
        prev, notes = HistoryStore.scan(args.history).before(doc) if args.history else ([], [])
        detections = run_detection(doc, rs, prev, notes, doc["assessment"]["finished_at"])
        store = CaseStore(args.state_dir, args.actor) if args.state_dir else None
        if store:
            store.observe(detections)
        cases = case_summaries(store, detections)
        _write_new(out_dir / "detections.json", _json(detections))
        dcode = detection_exit_code(detections, doc["assessment"]["fail_on"])
        if dcode == ExitCode.FINDINGS or (dcode == ExitCode.PARTIAL and code == ExitCode.OK):
            code = dcode
    for n, c in enumerate(comparisons, 1):
        _write_new(out_dir / f"comparison-{n}.json", _json(c))
    stamp_iso = doc["assessment"]["finished_at"]
    if "markdown" in formats:
        _write_new(
            out_dir / "report.md", render_markdown(doc, comparisons, stamp_iso, detections, cases)
        )
    if "html" in formats:
        _write_new(
            out_dir / "report.html", render_html(doc, comparisons, stamp_iso, detections, cases)
        )
    _, digest = write_manifest(out_dir, doc)
    if args.json:
        sys.stdout.write(_json(doc))
    if not args.quiet:
        for line in _summary_lines(doc, out_dir):
            _err(line)
        _err(f"manifest sha256 (record off-host): {digest}")
    return int(code)


_COMMANDS = {
    "list": _cmd_list,
    "run": _cmd_run,
    "compare": _cmd_compare,
    "report": _cmd_report,
    "validate": _cmd_validate,
    "verify": _cmd_verify,
}


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        handled = rules_dispatch(args)
        if handled is None:
            handled = telemetry_dispatch(args)
        if handled is not None:
            return handled
        return _COMMANDS[args.cmd](args)
    except (ModuleError, PluginError, ProfileError) as exc:
        _err(str(exc))
        return int(ExitCode.USAGE if isinstance(exc, ProfileError) else ExitCode.PRECONDITION)
    except (LoadError, ComparisonError, AssessmentError) as exc:
        _err(str(exc))
        return int(ExitCode.PRECONDITION)
    except FileExistsError as exc:
        _err(f"refusing to overwrite {exc.filename}")
        return int(ExitCode.PRECONDITION)
    except OSError as exc:
        _err(f"{exc.strerror or exc}" + (f": {exc.filename}" if exc.filename else ""))
        return int(ExitCode.ERROR)


if __name__ == "__main__":
    sys.exit(main())
