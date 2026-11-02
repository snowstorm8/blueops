"""Example BlueOps plugin module: report sudoers rules granting NOPASSWD: ALL.

A plugin is any program that writes an ``audit-report`` document (shared/schemas/
audit-report.schema.json) to ``<output_dir>/report.json`` and exits 0 (nothing to report),
4 (findings) or 6 (partial: some source was unreadable). This one is read-only: it only
reads /etc/sudoers and /etc/sudoers.d, and never prints rule text beyond the matching rule.

Test hook (same convention as the built-in collectors): with BO_TEST_MODE=1, BO_ROOT is a
prefix for every path read.
"""

from __future__ import annotations

import json
import os
import platform
import re
import socket
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

RULE = re.compile(r"^\s*[^#\s][^=]*\s.*NOPASSWD\s*:\s*ALL\b", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _root() -> Path:
    if os.environ.get("BO_TEST_MODE") == "1" and os.environ.get("BO_ROOT"):
        return Path(os.environ["BO_ROOT"])
    return Path("/")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: sudoers_nopasswd.py OUTPUT_DIR\n")
        return 2
    out = Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)
    started = _now()
    root = _root()
    files = [root / "etc" / "sudoers"]
    drop = root / "etc" / "sudoers.d"
    if drop.is_dir():
        files += sorted(p for p in drop.iterdir() if "." not in p.name and not p.name.endswith("~"))
    evidence, errors = [], []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append({"code": "UNREADABLE", "message": f"{path.name}: {exc.strerror}"})
            continue
        for line in text.splitlines():
            if RULE.match(line):
                ref = "/" + path.relative_to(root).as_posix()
                evidence.append({"type": "file", "ref": ref, "excerpt": line.strip()[:200]})
    findings = []
    if evidence:
        findings.append(
            {
                "id": "USR-NOPASS-001",
                "title": "sudoers rule grants passwordless root",
                "severity": "high",
                "confidence": "high",
                "category": "users",
                "description": "A sudoers rule allows commands as root without a password.",
                "evidence": evidence,
                "remediation": "Require a password, or restrict the rule to named commands.",
                "mitre_attack": ["T1548.003"],
            }
        )
    sev = {"info": 0, "low": 0, "medium": 0, "high": len(findings), "critical": 0}
    code = 4 if findings else (6 if errors else 0)
    report = {
        "schema_version": "0.2.0",
        "tool": {"name": "sudoers-nopasswd", "version": "1.0.0", "category": "audit"},
        "run": {
            "id": str(uuid.uuid4()),
            "started_at": started,
            "finished_at": _now(),
            "mode": "read-only",
            "dry_run": False,
            "exit_code": code,
        },
        "host": {
            "hostname": socket.gethostname() or "unknown",
            "os": {"family": "linux", "name": platform.system(), "version": platform.release()},
            "arch": platform.machine() or "unknown",
        },
        "findings": findings,
        "errors": errors,
        "summary": {"total": len(findings), "by_severity": sev},
    }
    fd = os.open(out / "report.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
