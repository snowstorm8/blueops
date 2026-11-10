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

## Assessment engine

`python -m shared.engine` orchestrates collectors; it never inspects the host itself. It starts programs only as argv lists (no shell), with no stdin, in their own process group so a timeout kills the tree, and only the programs named by built-in modules or by plugin manifests the operator pointed it at. Module reports are untrusted input: strict JSON, schema validation before use, control-character stripping and length caps on every ingested string, and every output format escapes for its medium (the HTML report carries a Content-Security-Policy pinned to its single script). Output directories are created `0700`, files `0600`, exclusively, and never reused; the assessment `manifest.json` lists the SHA-256 of every file (module outputs unchanged), and `verify` refuses unsafe paths and symlinks. **Plugins are the trust boundary:** a plugin is a program you chose to run with the engine's privileges; the engine cannot make it read-only. On POSIX a plugin directory or manifest that group/other can write is refused; on Windows ACLs are not inspected. The engine resolves `pwsh`/`powershell` and any non-absolute plugin command (such as `python3`) through the `PATH` of the process that started it and passes its environment to the module; it does not apply the collectors' `PATH` sanitising. Start it from a trusted shell, or give plugin manifests absolute program paths. A snapshot comparison never concludes "resolved" or "new" from a module that failed, timed out or was not run.

## Detection engine

Rules are JSON data: loading a rule pack cannot run code, and the engine never reads a host. Rule packs, assessments, history snapshots and the case file are all treated as untrusted input: strict JSON (size caps, duplicate keys, `NaN`, nesting), schema validation, condition and regex limits (length caps, nested quantifiers rejected, inputs capped), bounded work per rule, and a rule that raises is recorded as an error without stopping the others. A rule pack is still *policy*: a malicious or sloppy pack can hide a problem (disabled rule, always-false condition) or flood a report; load packs only from sources you trust and review `rules validate --examples`. Output escaping follows the report rules (HTML escaped and CSP-pinned; Markdown escaped; CSV formula-neutralised). Investigation state is written owner-only under a lock as an append-only, hash-chained JSON-lines file (tamper-evident for earlier lines, not tamper-proof; keep copies off-host) and holds no evidence content. Detections are leads: each carries its `nature` and a disclaimer, and none claims proof of malicious activity.

## Telemetry and hunting

Collectors are read-only, have no network code, and write only to stdout/stderr; the Linux collector reads account databases but never password hashes or private keys (only a locked/set/empty classification), redacts command lines and registry values, and records `authorized_keys` as counts. Telemetry can still contain sensitive data (user names, command lines, source addresses): `telemetry import`/`collect` create stores `0700`/`0600` with a SHA-256 manifest, and raw inputs are kept byte for byte under `sources/`. A stream is untrusted input from a possibly compromised host: records are rebuilt, attribute names and sizes are bounded, timestamps without a zone are refused, event XML is parsed without external entities, queries and rules are data (no code evaluation, nested-quantifier regexes rejected), and reports escape for their format. **A compromised host can lie to its own collector** (rootkits, `ld.so.preload`, forged logs): telemetry from a host is evidence of what it reported, not of what happened; hunting rules therefore say "suspicious" or "unusual", never "confirmed". Nothing is transmitted anywhere; collection is local and explicitly started.

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
