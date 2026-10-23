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

## Non-goals

Offensive security, exploit development, anti-forensics, or covert operation. Not a replacement for EDR/SIEM.

## Threats considered

Argument/path injection, unsafe temp files and symlink attacks, secret leakage in output, evidence tampering, accidental service disruption, supply-chain compromise (CI actions and dev dependencies are tracked by Dependabot; CI uses least-privilege `contents: read`).

Report vulnerabilities per [SECURITY.md](../SECURITY.md).
