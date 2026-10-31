"""Command line: compare two BlueOps audit reports (offline, read-only).

    python -m shared.reporting.diff BASELINE CURRENT [--format text|json] [--output FILE]

BASELINE and CURRENT are ``report.json`` files or run directories. Exit codes follow
``docs/contracts.md``: 0 no differences, 4 differences found, 6 no differences but the
comparison is incomplete, 3 reports not comparable or unreadable, 2 usage error.
Intended for authorized environments; it reads two files and writes one report.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any

from shared.reporting.baseline import (
    TOOL_VERSION,
    IncompatibleReportsError,
    compare,
    exit_code_for,
)
from shared.reporting.baseline_render import render_text
from shared.reporting.contracts import ExitCode
from shared.reporting.inventory import (
    ConfigError,
    Options,
    ReportError,
    load_snapshot,
    options_from_config,
    parse_timestamp,
)
from shared.reporting.jsonio import JsonInputError, load_json_strict


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m shared.reporting.diff",
        description="Compare two BlueOps audit reports and list additions, removals and "
        "modifications. Offline and read-only: it only reads the two reports (and an optional "
        "config) and writes the diff to stdout or --output.",
    )
    p.add_argument("baseline", help="baseline report.json or run directory")
    p.add_argument("current", help="current report.json or run directory")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--json", action="store_const", const="json", dest="format")
    p.add_argument(
        "--output", metavar="FILE", help="write the diff here (must not exist; mode 0600)"
    )
    p.add_argument(
        "--config", metavar="FILE", help="JSON file: ephemeral_from, transient_processes, ignore"
    )
    p.add_argument(
        "--ephemeral-from",
        type=int,
        metavar="PORT",
        help="treat listeners on ports >= PORT as ephemeral",
    )
    p.add_argument(
        "--allow-host-mismatch",
        action="store_true",
        help="compare reports from different hostnames",
    )
    p.add_argument(
        "--show-transient",
        action="store_true",
        help="list transient process changes in text output",
    )
    p.add_argument(
        "--generated-at", metavar="TIMESTAMP", help="timestamp to record (default: now, UTC)"
    )
    p.add_argument("--quiet", action="store_true", help="suppress the stderr summary")
    p.add_argument("--version", action="version", version=f"blueops-diff {TOOL_VERSION}")
    return p


MAX_CONFIG_BYTES = 1024 * 1024


def _options(args: argparse.Namespace) -> Options:
    opts = Options(allow_host_mismatch=args.allow_host_mismatch)
    if args.config:
        try:
            raw, _ = load_json_strict(args.config, MAX_CONFIG_BYTES, "config")
        except JsonInputError as exc:
            raise ConfigError(str(exc)) from None
        opts = options_from_config(raw, opts)
    if args.ephemeral_from is not None:
        opts = options_from_config({"ephemeral_from": args.ephemeral_from}, opts)
    return opts


def _write_output(path: str, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(args: argparse.Namespace, diff: dict[str, Any]) -> str:
    if args.format == "json":
        return json.dumps(diff, indent=2, sort_keys=False) + "\n"
    return render_text(diff, show_transient=args.show_transient)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    generated = args.generated_at or _now()
    try:
        parse_timestamp(generated)
        opts = _options(args)
        base = load_snapshot(args.baseline, opts)
        cur = load_snapshot(args.current, opts)
        diff = compare(base, cur, opts, generated)
    except (ReportError, ConfigError, IncompatibleReportsError) as exc:
        sys.stderr.write(f"blueops-diff: {exc}\n")
        return int(ExitCode.PRECONDITION)
    text = _emit(args, diff)
    try:
        if args.output:
            _write_output(args.output, text)
        else:
            sys.stdout.write(text)
    except OSError as exc:
        sys.stderr.write(f"blueops-diff: cannot write output: {exc.strerror or exc}\n")
        return int(ExitCode.ERROR)
    code = exit_code_for(diff)
    if not args.quiet and (args.format == "json" or args.output):
        s = diff["summary"]
        sys.stderr.write(
            f"blueops-diff: {s['added']} added, {s['removed']} removed, {s['modified']} modified, "
            f"{s['indeterminate']} indeterminate (exit {int(code)})\n"
        )
    return int(code)


if __name__ == "__main__":
    sys.exit(main())
