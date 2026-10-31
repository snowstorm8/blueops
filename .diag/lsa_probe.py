"""Throwaway probe: does anything BlueOps runs change HKLM\\...\\Control\\Lsa, or does the runner do it?

For each iteration it takes a state snapshot, runs one phase, takes a second snapshot and reports
what differed (via tests/shared/windows_state.py). Phases: a control that runs no BlueOps code
for the same duration, then the audit and the persistence scripts from the head tree and from the
base tree. Everything printed has already been redacted by the snapshot script.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HEAD = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HEAD))
from tests.shared.windows_state import host_changes, registry_differences  # noqa: E402

SNAPSHOT = HEAD / "tests" / "shared" / "windows-state-snapshot.ps1"
LSA = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def run(shell: str, args: list[str], timeout: int = 1500) -> subprocess.CompletedProcess[str]:
    cmd = [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", *args]
    env = {k: v for k, v in os.environ.items() if not k.startswith("BO_")}
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, check=False)


def snapshot(shell: str) -> dict:
    res = run(shell, ["-File", str(SNAPSHOT)])
    if res.returncode != 0:
        raise SystemExit(f"snapshot failed: {res.stderr[-1500:]}")
    return json.loads(res.stdout)


def lsa_summary(snap: dict) -> str:
    d = (snap.get("diag", {}).get("registry") or {}).get(LSA) or {}
    return f"last_write={d.get('last_write')} values={len(d.get('values') or {})}"


def phase(shell: str, tree: Path, name: str, control_seconds: int) -> float:
    started = time.monotonic()
    if name == "control":
        time.sleep(control_seconds)
    else:
        script = {
            "audit": tree / "windows" / "audit" / "Invoke-WindowsAudit.ps1",
            "persistence": tree / "windows" / "persistence" / "Find-Persistence.ps1",
        }[name]
        res = run(shell, ["-File", str(script), "-Json", "-Quiet"])
        if res.returncode not in (0, 4, 6):
            print(f"  !! {name} exited {res.returncode}: {res.stderr[-400:]}")
    return time.monotonic() - started


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shell", required=True)
    ap.add_argument("--base", required=True, type=Path)
    ap.add_argument("--iterations", type=int, default=6)
    ap.add_argument("--control-seconds", type=int, default=45)
    a = ap.parse_args()

    plan = [("control", "-"), ("audit", "head"), ("persistence", "head"), ("audit", "base"), ("persistence", "base")]
    tally: dict[str, list[int]] = {}
    for i in range(1, a.iterations + 1):
        for name, which in plan:
            tree = a.base if which == "base" else HEAD
            before = snapshot(a.shell)
            t0 = now()
            secs = phase(a.shell, tree, name, a.control_seconds)
            after = snapshot(a.shell)
            changed = host_changes(before, after)
            lsa_changed = LSA in changed
            key = f"{name}/{which}"
            tally.setdefault(key, [0, 0])
            tally[key][0] += 1
            tally[key][1] += int(lsa_changed)
            print(
                f"[{a.shell}] iter {i} {key:18} {t0}Z +{secs:5.1f}s "
                f"changed_keys={sorted(changed)} before:{lsa_summary(before)} after:{lsa_summary(after)}",
                flush=True,
            )
            if changed:
                for line in registry_differences(changed, before, after):
                    print("    " + line)
                for k, v in changed.items():
                    if not k.startswith("HK") and k != "services":
                        print(f"    {k}: {v}")
                if "services" in changed:
                    print(f"    services: {json.dumps(changed['services'])[:600]}")
    print("\nSUMMARY (phase/tree: runs, runs with an Lsa difference)")
    for key, (runs, hits) in tally.items():
        print(f"  {key:18} runs={runs} lsa_differences={hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
