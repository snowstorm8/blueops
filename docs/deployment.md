# Deployment

BlueOps has no installer and requires no network access.

## Philosophy

- **Copy, verify, run.** Transfer the repository (or a release archive, once releases exist) to the host via trusted media; verify a SHA-256 checksum obtained out-of-band.
- **Never fetch-and-execute.** No `curl | sh`, no `iex (iwr ...)`.
- **Least footprint.** Tools write only to a user-specified `--output-dir`; read-only tools change nothing else.
- **Native tooling only.** Bash ≥ 4.2 on Linux; Windows PowerShell 5.1 or PowerShell 7 on Windows. Python is not required on targets.
- **Privileges.** Run unprivileged where possible; tools report reduced coverage when not elevated (exit 6 / `errors[]`) instead of failing silently.

## Recommended procedure (planned)

1. Copy to the host; verify checksum.
2. Run audit/persistence tools first (read-only) and collect output off-host.
3. Review findings; run hardening with `--dry-run`, then with `--yes` for approved changes.
4. Keep the run directory (it contains rollback data) until the exercise/incident ends.

Output directories may contain sensitive data: store them with owner-only permissions and transport them securely.

## Verifying a run (integrity)

Every run directory contains `manifest.json`: the SHA-256 and size of `report.json`, `report.txt` and `run.log`, plus the digests of the collector scripts that produced them. At the end of the run the collector prints the **manifest's own digest** (`Manifest SHA-256: ...`).

1. Record that digest off the host (paper, a separate machine, chat with the operator), *before* the run directory is copied around.
2. On the analyst machine: `python -m shared.reporting.verify RUN_DIR --expect-sha256 DIGEST` (exit 0 = every file matches; exit 3 = something differs or is missing).
3. `python -m shared.reporting.diff` and `detect` verify the manifest automatically when they are given a run directory and **refuse** one that no longer matches.

The manifest proves the files are unchanged since the collector wrote them; it cannot prove the host told the truth, and without the off-host digest an attacker who can rewrite the directory can rewrite the manifest as well. Runs from collectors that predate manifests load unverified.
