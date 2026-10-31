"""Command line: verify a collector run directory against its manifest (offline, read-only).

    python -m shared.reporting.verify RUN_DIR [--expect-sha256 DIGEST]

Exit codes: 0 verified, 3 the directory does not match its manifest (or has none), 2 usage error.
``DIGEST`` is the manifest SHA-256 the collector printed at the end of the run; recording it off
the host is what lets a rewritten manifest be detected.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shared.reporting.contracts import ExitCode
from shared.reporting.manifest import verify_run_dir


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m shared.reporting.verify",
        description="Verify a BlueOps run directory against its manifest.json (offline).",
    )
    p.add_argument("run_dir", metavar="RUN_DIR")
    p.add_argument(
        "--expect-sha256", metavar="DIGEST", help="digest of manifest.json recorded off-host"
    )
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    root = Path(args.run_dir)
    if not root.is_dir():
        sys.stderr.write(f"blueops-verify: {root} is not a directory\n")
        return int(ExitCode.PRECONDITION)
    problems = verify_run_dir(root, args.expect_sha256)
    if problems:
        for line in problems:
            sys.stderr.write(f"blueops-verify: {line}\n")
        return int(ExitCode.PRECONDITION)
    if not args.quiet:
        sys.stdout.write(f"blueops-verify: {root} matches its manifest\n")
    return int(ExitCode.OK)


if __name__ == "__main__":
    sys.exit(main())
