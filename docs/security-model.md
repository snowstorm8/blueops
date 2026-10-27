# Security model

## Scope and authorization

BlueOps is for defenders operating on systems they own or are explicitly authorized to administer (competition hosts, owned infrastructure, authorized incident response). It contains no offensive functionality.

## Trust assumptions

- The operator is trusted; the host may be **compromised**. Output from a compromised host (command results, file contents, logs) is attacker-influenced: parse defensively, never `eval`, and treat absent findings as "not detected", not "clean".
- Native binaries on a compromised host may be tampered with. Where feasible, document which checks rely on potentially untrusted binaries and note it in report `errors[]`/descriptions.
- The BlueOps files themselves are trusted only after checksum verification.

## Guarantees (design goals)

| Area | Guarantee |
|---|---|
| Default behavior | Read-only; only the run output directory is written |
| State changes | Require confirmation (or `--yes`), support dry-run, record rollback data first |
| Availability | Protected services/ports from profiles are checked before changes |
| Network | No runtime network access; no remote code execution |
| Evidence | Originals untouched; SHA-256 manifest; UTC timestamps; owner-only permissions |
| Secrets | Never printed/logged/committed; never passed as CLI arguments |

## Baseline comparison

`shared.reporting.diff` is offline and read-only: it reads two reports (and an optional config), writes only its result (stdout, or a new file with mode 0600 that is never overwritten), and uses no network. Reports are treated as attacker-influenced input: size and nesting limits, duplicate JSON keys rejected, control characters escaped in text output. Inventories contain no secrets: password state is recorded as `set`/`locked`/`empty`, SSH keys by fingerprint, sensitive command lines and registry data are redacted. `shared.reporting.detect` has the same properties (it only adds rules over the diff, takes the same untrusted input, and validates a supplied `--from-diff` document before use); its text output escapes control characters so a report cannot forge detections, and a rule that fails is reported as incomplete coverage, never as a clean result. A clean diff is not proof of integrity, because a compromised host can alter what its own audit sees; baselines should be taken early and stored off-host.

## Non-goals

Offensive security, exploit development, anti-forensics, or covert operation. Not a replacement for EDR/SIEM.

## Threats considered

Argument/path injection, unsafe temp files and symlink attacks, secret leakage in output, evidence tampering, accidental service disruption, supply-chain compromise (CI actions and dev dependencies are tracked by Dependabot; CI uses least-privilege `contents: read`).

Report vulnerabilities per [SECURITY.md](../SECURITY.md).
