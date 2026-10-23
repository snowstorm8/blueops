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
