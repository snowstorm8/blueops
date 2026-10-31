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
| Evidence | Originals untouched; `manifest.json` with SHA-256 of every output file and collector script (run directories only; verify with `python -m shared.reporting.verify`); UTC timestamps; owner-only permissions; a run directory is never reused |
| Secrets | Never printed/logged/committed; never passed as CLI arguments; command lines are redacted for the forms listed under *Residual risks* |
| Test hooks | Fixture hooks (`BO_ROOT`, `BO_FORCE_MISSING_TOOLS`, `BO_FIXTURE_DIR`, `BO_FORCE_MISSING`) work only with `BO_TEST_MODE=1`; otherwise they are ignored and recorded (`TEST_HOOKS_IGNORED`, exit 6); reports made with them say `host.test_mode` |
| Tool resolution | Linux: `PATH` reduced to system directories plus root-owned, non-writable entries (`PATH_SANITIZED` records what was dropped). Windows: native tools run from `System32` by full path, never through `PATH` |
| Input handling | Reports, diffs, allowlists, configs and manifests are read with one strict loader: size cap, valid UTF-8, no duplicate keys, no `NaN`/infinity, nesting handled; malformed input is exit 3, never a traceback |

## Baseline comparison

`shared.reporting.diff` is offline and read-only: it reads two reports (and an optional config), writes only its result (stdout, or a new file with mode 0600 that is never overwritten), and uses no network. Reports are treated as attacker-influenced input: size and nesting limits, duplicate JSON keys rejected, control characters escaped in text output. Inventories contain no secrets: password state is recorded as `set`/`locked`/`empty`, SSH keys by fingerprint, sensitive command lines and registry data are redacted. `shared.reporting.detect` has the same properties (it only adds rules over the diff, takes the same untrusted input, and validates a supplied `--from-diff` document before use); its text output escapes control characters so a report cannot forge detections, and a rule that fails is reported as incomplete coverage, never as a clean result. A clean diff is not proof of integrity, because a compromised host can alter what its own audit sees; baselines should be taken early and stored off-host.

## Residual risks (known, documented, not fixable in the collectors)

* **A root-level attacker can rewrite file and checksum together.** `--package-integrity` trusts the package database on the same host (dpkg's MD5 lists, the rpm database); the run manifest trusts the directory it sits in unless its digest is recorded off-host.
* **Redaction is pattern-based.** Handled: `name=value` secrets, `--password X`, URL credentials, `Authorization` headers, `curl -u user:pass`, `sshpass -p`, mysql-style `-pSECRET`, and the Windows equivalents. Not detectable: secrets read from stdin or here-strings, in files, or as positional arguments of arbitrary programs. Evidence may therefore still contain sensitive data; its permissions are owner-only.
* **Text is escaped, not decoded.** Non-ASCII bytes appear as `\u00XX` per byte on Linux and `\uXXXX` per UTF-16 unit on Windows, so distinct names stay distinct; a UTF-8 name looks like mojibake in the raw report.
* **`BO_TEST_MODE=1` is an explicit opt-in.** An attacker who controls the audit process environment completely can set it; the report then says `test_mode` and the comparison tools warn (`TEST_MODE`). The gating defeats a stray or planted *hook* variable, not an attacker who owns the whole invocation.
* **The comparison trusts a report's own statements** (coverage, host name). See [baseline-diff.md](baseline-diff.md).
* **Windows signature checks may touch the network.** Authenticode verification is done by Windows and may query revocation endpoints on a connected host; BlueOps does not control it. On an isolated host those lookups time out and are cached.

## Non-goals

Offensive security, exploit development, anti-forensics, or covert operation. Not a replacement for EDR/SIEM.

## Threats considered

Argument/path injection, unsafe temp files and symlink attacks, secret leakage in output, evidence tampering, accidental service disruption, supply-chain compromise (CI actions and dev dependencies are tracked by Dependabot; CI uses least-privilege `contents: read`).

Report vulnerabilities per [SECURITY.md](../SECURITY.md).
