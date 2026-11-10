"""Command line for telemetry, mounted in ``python -m shared.engine``.

    telemetry collect | import | show | query | tree | compare | hunt | report

Exit codes follow ``docs/contracts.md``: 0 ok, 4 hunting detections at or above ``--fail-on`` or
differences found, 6 incomplete coverage (partial), 3 bad input or precondition, 2 usage.
"""

from __future__ import annotations

import argparse
import json
import subprocess  # noqa: S404 - collectors are started as argv lists, never through a shell
import sys
from pathlib import Path
from typing import Any

from shared.engine.environment import sanitized_environment
from shared.engine.loader import ALLOW_UNVERIFIED_HELP, LoadError
from shared.engine.provenance import THIS_RUN, status
from shared.engine.runner import current_platform
from shared.reporting import render_provenance as prov
from shared.reporting.contracts import ExitCode
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.rules.cli import (
    _emit,
    _err,
    _load_results,
    _now,
    _rule_args,
    detect_run_args,
    run_command,
)
from shared.telemetry import render
from shared.telemetry.compare import CompareError, compare_telemetry
from shared.telemetry.ingest import (
    IngestError,
    build_document,
    load_telemetry,
    read_path,
    read_stream,
    write_store,
)
from shared.telemetry.model import CATEGORIES
from shared.telemetry.query import QueryError, attribute_filters, parse_query, process_tree, select

REPO_ROOT = Path(__file__).resolve().parents[2]
MAX_COLLECTOR_BYTES = 512 * 1024 * 1024


def register(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:  # noqa: SLF001, PLR0915
    tel = sub.add_parser("telemetry", help="collect, import, query and hunt endpoint telemetry")
    t = tel.add_subparsers(dest="telemetry_cmd", required=True)

    p = t.add_parser("collect", help="run this host's read-only telemetry collector and ingest it")
    p.add_argument("--platform", choices=("linux", "windows"), help="default: this host's platform")
    p.add_argument(
        "--output-dir",
        required=True,
        metavar="DIR",
        help="parent directory for the telemetry store",
    )
    p.add_argument(
        "--since-hours", type=int, default=24, metavar="N", help="event window (default 24)"
    )
    p.add_argument(
        "--max-events",
        type=int,
        default=5000,
        metavar="N",
        help="cap per event source (default 5000)",
    )
    p.add_argument("--categories", metavar="LIST", help="comma-separated categories (default: all)")
    p.add_argument("--timeout", type=int, default=600, metavar="SECONDS")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--quiet", action="store_true")

    p = t.add_parser("import", help="validate, normalize and store collected telemetry (offline)")
    p.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="collector stream, telemetry document/store, or assessment",
    )
    p.add_argument("--allow-unverified", action="store_true", help=ALLOW_UNVERIFIED_HELP)
    p.add_argument("--output-dir", required=True, metavar="DIR")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--quiet", action="store_true")

    p = t.add_parser("show", help="summary and coverage of a telemetry store")
    p.add_argument("store")
    p.add_argument("--allow-unverified", action="store_true", help=ALLOW_UNVERIFIED_HELP)
    p.add_argument("--format", choices=("text", "json"), default="text")

    p = t.add_parser("query", help="filter telemetry records")
    p.add_argument("store")
    p.add_argument("--allow-unverified", action="store_true", help=ALLOW_UNVERIFIED_HELP)
    p.add_argument(
        "--category", action="append", default=[], choices=CATEGORIES, metavar="CATEGORY"
    )
    p.add_argument("--since", metavar="TIMESTAMP")
    p.add_argument("--until", metavar="TIMESTAMP")
    p.add_argument("--host", metavar="NAME")
    p.add_argument(
        "--attr",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="exact (case-insensitive) match",
    )
    p.add_argument(
        "--contains", action="append", default=[], metavar="NAME~TEXT", help="substring match"
    )
    p.add_argument(
        "--query", metavar="FILE", help="a JSON query file ('-' for stdin); see docs/telemetry.md"
    )
    p.add_argument("--sort", choices=("time", "key", "category"), default="time")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--format", choices=("text", "json"), default="text")

    p = t.add_parser("tree", help="show process ancestors and descendants")
    p.add_argument("store")
    p.add_argument("--allow-unverified", action="store_true", help=ALLOW_UNVERIFIED_HELP)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--pid", type=int)
    g.add_argument("--name")
    p.add_argument("--depth", type=int, default=6)

    p = t.add_parser("compare", help="compare two telemetry snapshots of one host")
    p.add_argument("baseline")
    p.add_argument("current")
    p.add_argument("--allow-unverified", action="store_true", help=ALLOW_UNVERIFIED_HELP)
    p.add_argument("--format", choices=("text", "json"), default="json")
    p.add_argument("--output", metavar="FILE")
    p.add_argument("--generated-at", metavar="TIMESTAMP")

    p = t.add_parser(
        "hunt", help="run the hunting rules over telemetry (alias of 'detect run --telemetry')"
    )
    _rule_args(p)
    p.add_argument("store", metavar="TELEMETRY", help="telemetry store or document")
    p.add_argument(
        "--assessment",
        metavar="PATH",
        help="also read an assessment of the same host (enables joins with findings)",
    )
    detect_run_args(p, telemetry_option=False)

    p = t.add_parser("report", help="render a telemetry store (and optionally hunting results)")
    p.add_argument("store")
    p.add_argument("--allow-unverified", action="store_true", help=ALLOW_UNVERIFIED_HELP)
    p.add_argument(
        "--detections", metavar="RESULTS", help="detection results JSON from 'telemetry hunt'"
    )
    p.add_argument("--format", choices=("markdown", "html"), default="markdown")
    p.add_argument("--output", metavar="FILE")


def _json(doc: Any) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _collector_argv(platform: str, args: argparse.Namespace) -> list[str] | str:
    if platform == "linux":
        argv = [
            str(REPO_ROOT / "linux/telemetry/collect-telemetry.sh"),
            "--since-hours",
            str(args.since_hours),
            "--max-events",
            str(args.max_events),
        ]
        if args.categories:
            argv += ["--categories", args.categories]
        return argv
    import shutil  # noqa: PLC0415 - only needed on the Windows path

    ps = shutil.which("pwsh") or shutil.which("powershell")
    if ps is None:
        return "PowerShell (pwsh or powershell) not found"
    argv = [
        ps,
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(REPO_ROOT / "windows/telemetry/Invoke-TelemetryCollection.ps1"),
        "-SinceHours",
        str(args.since_hours),
        "-MaxEvents",
        str(args.max_events),
    ]
    if args.categories:
        argv += ["-Categories", args.categories]
    return argv


def _cmd_collect(args: argparse.Namespace) -> int:  # noqa: PLR0911 - one early return per precondition
    platform = args.platform or current_platform()
    if platform != current_platform():
        _err(
            f"this host is {current_platform()}; a {platform} collector cannot inspect it. Collect on the target host, then 'telemetry import'."
        )
        return int(ExitCode.PRECONDITION)
    if not (1 <= args.since_hours <= 24 * 90 and 1 <= args.max_events <= 1_000_000):
        _err("--since-hours must be 1..2160 and --max-events 1..1000000")
        return int(ExitCode.USAGE)
    if args.categories and any(c not in CATEGORIES for c in args.categories.split(",")):
        _err(f"--categories must be a comma-separated subset of: {', '.join(CATEGORIES)}")
        return int(ExitCode.USAGE)
    argv = _collector_argv(platform, args)
    if isinstance(argv, str):
        _err(argv)
        return int(ExitCode.PRECONDITION)
    if not Path(argv[0 if platform == "linux" else 4]).is_file():
        _err(f"collector not found: {argv[0 if platform == 'linux' else 4]}")
        return int(ExitCode.PRECONDITION)
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv built from repository paths, no shell
            argv,
            capture_output=True,
            timeout=args.timeout,
            check=False,
            shell=False,
            env=sanitized_environment()[0],
        )
    except subprocess.TimeoutExpired:
        _err(f"the collector did not finish within {args.timeout}s")
        return int(ExitCode.PARTIAL)
    except OSError as exc:
        _err(f"cannot start the collector: {exc.strerror or exc}")
        return int(ExitCode.PRECONDITION)
    if proc.stderr and not args.quiet:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace")[-4000:])
    if len(proc.stdout) > MAX_COLLECTOR_BYTES:
        _err("collector output exceeds the size limit")
        return int(ExitCode.PRECONDITION)
    try:
        raw = read_stream("collector-stream.jsonl", proc.stdout)
    except IngestError as exc:
        _err(f"the collector produced no usable telemetry (exit {proc.returncode}): {exc}")
        return int(ExitCode.PRECONDITION)
    # The stream came from a collector this process just ran: trusted by construction.
    raw.provenance = [{"role": "collector", "path": THIS_RUN, "verified": True}]
    if proc.returncode not in (0, 6):
        raw.errors.append(
            {"code": "COLLECTOR_EXIT", "message": f"collector exited with status {proc.returncode}"}
        )
    doc = build_document([raw], mode="live")
    root = write_store(doc, args.output_dir, [("collector-stream.jsonl", proc.stdout)])
    return _finish_ingest(doc, root, args)


def _provenance_of(doc: dict[str, Any]) -> dict[str, Any]:
    """The provenance fields of ``doc`` (``inputs_verified`` is false if none is recorded)."""
    ok, inputs = status(doc)
    return {"inputs_verified": bool(ok), "inputs": inputs}


def _finish_ingest(doc: dict[str, Any], root: Path, args: argparse.Namespace) -> int:
    if args.format == "json":
        sys.stdout.write(
            _json(
                {
                    "store": str(root),
                    "summary": doc["summary"],
                    "coverage": doc["coverage"],
                    "errors": doc["errors"],
                    "rejected": len(doc["rejected"]),
                    **_provenance_of(doc),
                }
            )
        )
    else:
        sys.stdout.write("\n".join(render.summary_lines(doc)) + f"\nstored in {root}\n")
    return int(ExitCode.OK if doc["summary"]["complete"] else ExitCode.PARTIAL)


def _cmd_import(args: argparse.Namespace) -> int:
    raws = [read_path(p, args.allow_unverified) for p in args.paths]
    doc = build_document(raws, mode="import")
    sources = [(Path(p).name, Path(p).read_bytes()) for p in args.paths if Path(p).is_file()]
    root = write_store(doc, args.output_dir, sources)
    return _finish_ingest(doc, root, args)


def _cmd_query(args: argparse.Namespace) -> int:
    doc = load_telemetry(args.store, args.allow_unverified)
    if args.query:
        try:
            raw = (
                json.load(sys.stdin)
                if args.query == "-"
                else load_json_strict(args.query, 1 << 20, "query")[0]
            )
        except (JsonInputError, ValueError) as exc:
            _err(f"cannot read the query: {exc}")
            return int(ExitCode.PRECONDITION)
    else:
        raw = {}
    where = attribute_filters(args.attr, args.contains)
    if where:
        if "where" in raw:
            raw["where"] = {"all": [raw["where"], where]}
        else:
            raw["where"] = where
    for key in ("since", "until", "host"):
        if getattr(args, key):
            raw[key] = getattr(args, key)
    if args.category:
        raw["category"] = args.category
    raw.setdefault("sort", args.sort)
    raw.setdefault("limit", args.limit)
    recs, total = select(doc, parse_query(raw))
    if args.format == "json":
        sys.stdout.write(
            _json(
                {
                    "total": total,
                    "returned": len(recs),
                    "records": recs,
                    **_provenance_of(doc),
                }
            )
        )
    else:
        for r in recs:
            sys.stdout.write(render.record_line(r) + "\n")
        sys.stdout.write(f"{len(recs)} of {total} matching record(s)\n")
        sys.stdout.write("".join(x + "\n" for x in prov.text(("telemetry", doc))))
    return int(ExitCode.OK)


def _cmd_compare(args: argparse.Namespace) -> int:
    base = load_telemetry(args.baseline, args.allow_unverified)
    cur = load_telemetry(args.current, args.allow_unverified)
    doc = compare_telemetry(base, cur, generated_at=args.generated_at or _now())
    if args.format == "json":
        _emit(_json(doc), args.output)
    else:
        lines = [
            f"{doc['host']['hostname']}: {doc['baseline']['started_at']} -> {doc['current']['started_at']}"
        ]
        for cat, blk in doc["categories"].items():
            tag = "" if blk["determinate"] else "  (indeterminate)"
            lines.append(
                f"  {cat}: +{len(blk['added'])} -{len(blk['removed'])} ~{len(blk['changed'])}{tag}"
            )
            lines += (
                [f"    + {x['summary']}" for x in blk["added"][:20]]
                + [f"    - {x['summary']}" for x in blk["removed"][:20]]
                + [f"    ~ {x['identity']}" for x in blk["changed"][:20]]
            )
        lines += [f"  indeterminate {i['category']}: {i['reason']}" for i in doc["indeterminate"]]
        lines += prov.text(("comparison", doc))
        _emit("\n".join(lines) + "\n", args.output)
    s = doc["summary"]
    if s["added"] or s["removed"] or s["changed"]:
        return int(ExitCode.FINDINGS)
    return int(ExitCode.PARTIAL if s["indeterminate_categories"] else ExitCode.OK)


def _cmd_report(args: argparse.Namespace) -> int:
    doc = load_telemetry(args.store, args.allow_unverified)
    results = None
    if args.detections:
        results = _load_results(args.detections, args.allow_unverified)
    text = (
        render.render_markdown(doc, results)
        if args.format == "markdown"
        else render.render_html(doc, results)
    )
    _emit(text, args.output)
    return int(ExitCode.OK)


def dispatch(args: argparse.Namespace) -> int | None:  # noqa: PLR0911, PLR0912
    if args.cmd != "telemetry":
        return None
    cmd = args.telemetry_cmd
    try:
        if cmd == "collect":
            return _cmd_collect(args)
        if cmd == "import":
            return _cmd_import(args)
        if cmd == "show":
            doc = load_telemetry(args.store, args.allow_unverified)
            sys.stdout.write(
                _json(doc) if args.format == "json" else "\n".join(render.summary_lines(doc)) + "\n"
            )
            return int(ExitCode.OK)
        if cmd == "query":
            return _cmd_query(args)
        if cmd == "tree":
            tel = load_telemetry(args.store, args.allow_unverified)
            lines = process_tree(tel, pid=args.pid, name=args.name, depth=args.depth)
            sys.stdout.write("\n".join(lines) + ("\n" if lines else "no matching process\n"))
            sys.stdout.write("".join(x + "\n" for x in prov.text(("telemetry", tel))))
            return int(ExitCode.OK if lines else ExitCode.PARTIAL)
        if cmd == "compare":
            return _cmd_compare(args)
        if cmd == "hunt":
            args.telemetry = args.store
            return run_command(args)
        if cmd == "report":
            return _cmd_report(args)
    except (IngestError, CompareError, LoadError) as exc:
        _err(str(exc))
        return int(ExitCode.PRECONDITION)
    except QueryError as exc:
        _err(f"query: {exc}")
        return int(ExitCode.USAGE)
    except FileExistsError as exc:
        _err(f"refusing to overwrite {exc.filename}")
        return int(ExitCode.PRECONDITION)
    except OSError as exc:
        _err(f"{exc.strerror or exc}" + (f": {exc.filename}" if exc.filename else ""))
        return int(ExitCode.ERROR)
    return None
