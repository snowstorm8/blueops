# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added (fresh-clone deployment)
- `./blueops` launcher (repo root): `doctor`, `audit`, `persistence`, `diff`, `detect`, `version`. Resolves its own location (also through symlinks), so it works from any directory; runs Python tools with `PYTHONPATH` set and `-B` (no bytecode written into the checkout).
- `linux/lib/deps.sh`: read-only dependency detection (required files, required/recommended commands, Python >= 3.9, Bash version, distro family). Collectors now stop early with exit 3 and an actionable message when a required command is missing (`bo_preflight_deps`).
- `scripts/setup/setup-linux.sh`: separate, opt-in setup for Debian/Ubuntu (`apt-get`), RHEL-family incl. Rocky (`dnf`/`yum`) and Arch (`pacman`). Default run changes nothing; `--install` prints the exact commands and asks (`--yes`, `--dry-run`, `--minimal`). Never installs an init system.
- `tests/shared/test_fresh_clone.py`: tracked-files-only copy, run from an unrelated cwd, with restricted `PATH` and package-manager shims; README quick-start guard. CI job `fresh-clone` clones the commit under test and runs the documented flow.
- README `Quick start` leads with the exact clone commands; `docs/deployment.md` documents Debian, Rocky, Windows and offline requirements.
- Lint/format now cover the extensionless `blueops` launcher (`.editorconfig`, `lint.yml`, `check.sh`).

### Added (WCComps 2026 Invitational 2)
- `docs/ccdc-invitational-2.md`: event-specific deployment and operations guide derived from the team packet (machine-to-collector map with full/partial/manual tiers, collect/compare/investigate/verify workflow, report locations, router and scoring-safety rules, known gaps). No code changes.

### Security and integrity (audit remediation, P1-P3)
- **Test hooks need `BO_TEST_MODE=1`** on both platforms (`BO_ROOT`, `BO_FORCE_MISSING_TOOLS`, `BO_FIXTURE_DIR`, `BO_FORCE_MISSING`). Without it they are removed/ignored and the run records `TEST_HOOKS_IGNORED` (material, exit 6); reports made with them carry the new optional `host.test_mode` (report schema 0.2.0, additive). The comparison warns (`TEST_MODE`). Test harnesses (Bats helper, pytest, Pester) now set it explicitly.
- **Trusted `PATH` (Linux):** the system directories first; relative, missing, non-root-owned and group/other-writable entries are dropped and recorded (`PATH_SANITIZED`). **Windows:** `netstat.exe`, `schtasks.exe`, `auditpol.exe` and `net.exe` run from `System32` by full path.
- **Run manifest:** `manifest.json` (new `shared/schemas/run-manifest.schema.json` 0.1.0, example in `examples/`) beside every report with SHA-256 and size of each output file and of the collector scripts, owner-only; the collector prints its digest for off-host recording. New `python -m shared.reporting.verify RUN_DIR [--expect-sha256 DIGEST]`; `diff` and `detect` refuse a run directory that no longer matches its manifest.
- **Windows run directories are never reused** (numeric suffix like Linux) instead of silently overwriting earlier evidence.
- **Secret redaction (Linux)** now covers URL credentials, `Authorization` header values, `curl -u user:pass`, `sshpass -p` and mysql-style `-pSECRET`; Windows gained URL and `curl -u` parity. `NOPASSWD:`/`PASSWD:` sudoers tags are no longer mistaken for secrets (a rule used to read `NOPASSWD: <redacted>`).
- **Text encoding is injective:** non-ASCII bytes become `\u00XX` per byte (Linux) and `\uXXXX` per UTF-16 unit (Windows) instead of `?`, so different names no longer collide.
- **Process/persistence TSV row forgery fixed:** tabs, newlines and carriage returns in command lines, `comm` names, executable paths and file names can no longer add columns or forged records.
- **Strict JSON everywhere untrusted input is read** (`--from-diff`, `--accepted`, `--config`, manifests): size cap, duplicate keys, `NaN`/infinity and deep nesting are clean exit-3 errors (a nested file used to crash with a traceback); saved-diff keys over 1024 characters are rejected.
- **IPv6:** `/proc/net/tcp6` addresses decode to the compressed form `ss` prints (stable keys across tools); loopback is parsed (`::ffff:127.0.0.1` is loopback, `::1f00:1` and `127.evil` are not).

### Added (audit remediation, coverage)
- **Detections:** `BO-EXE-002` (attack patterns in the text of job/service/persistence commands), `BO-CFG-008` (sshd settings), `BO-CFG-009` (new kernel module), `BO-CFG-010` (Linux firewall opened); `BO-GRP-001` also sees primary-group members; `BO-CFG-002` covers `kptr_restrict`, `ptrace_scope`, `dmesg_restrict`, `suid_dumpable` and no longer lets `::restrictanonymous` match `::restrictanonymoussam`; `BO-CFG-005` covers loaded PAM modules; `BO-PER-002` states how many lines were added and removed; the same SSH key under several accounts is linked (`correlated`) instead of reported as unrelated detections. 31 rules.
- **Linux checks:** sudoers `#include`/`@include` targets (followed and flagged), `Defaults` and aliases (`USR-SUDO-004/005`); administrative primary groups (`USR-GROUP-003`); PAM `\` continuation lines and SHA-256 of every referenced PAM module; sshd effective settings (`NET-SSHD-001/002`); kernel hardening sysctls (`NET-SYSCTL-001`); host firewall state (`NET-FW-001/002`); loaded kernel modules with taint (`SYS-KMOD-001`); symlinked and dangling systemd units; `ld.so.conf` search paths (`PER-LDCONF-001`); `cron.allow/deny`, `at.allow/deny`; auditd rules (`PER-AUDITD-001`); line count and line fingerprints on persistence files; `--package-integrity` also supports `rpm -Va` and states the trust limit of both backends.
- Suspicious command patterns (`bo_suspicious_reasons`): `ncat --exec/--sh-exec`, `nc ... | sh`, `sh -i | nc`, `mkfifo` shells, `bash <(curl ...)`, perl/python socket and pty shells, `openssl s_client | sh`.
- Comparison: attributes present in only one report are skipped and reported once (`ATTRIBUTES_NOT_COMPARED`) instead of making every such record indeterminate.
- Tests: `tests/linux/hardening.bats`, `tests/linux/coverage-gaps.bats`, `tests/shared/test_remediation.py`, `test_schemas.py`, `test_windows_sources.py`, `tests/windows/Hardening.Tests.ps1`; manifest and rule/collector contract tests extended.
- `docs/audit-remediation.md`: finding-by-finding status, what was deliberately not changed and why, residual risks.

### Changed (audit remediation)
- A reverse-shell cron line is now `high` on its own (it was `medium`, with the audit finding promoted beside it).
- Collector upgrade: take a new baseline. Records gained attributes (`line_ids`, `primary_members`, ...), sudoers rule text is no longer redacted after `NOPASSWD:`, and `config:kmod:`, `config:sshd:`, `config:firewall:`, `config:pam-module:` records appear.
- The two permission tests that cannot work as uid 0 (`LC-03`, `LC-04`) are skipped when run as root.
- Documentation: security model (residual risks), exit-code precedence, deployment (verifying a run), architecture decisions.

### Fixed (detection correctness, audit P0-1..P0-4)
- `BO-PER-001` now matches the Linux collector's real SSH key records (`persist:ssh-authkey:<owner>:<id>`, `owner` attribute); a new `root` authorized key was reported only as a generic `BO-PER-002` at medium instead of critical. `BO-PER-002` still reports *changed* key records.
- A new process name on a high-port listener is detected (`BO-NET-003`; `BO-NET-002` when it is a netcat-style tool). Before, an `nc` listener on `0.0.0.0:44444` produced no detection and exit 0 whenever the baseline already had a listener above the ephemeral threshold on the same bind. The same name on another high port stays quiet (documented limit; use `fixed_ports`).
- New rule `BO-FND-001`: audit findings of `high`/`critical` severity that are new, escalated or gained evidence are detections unless an equally severe inventory detection already covers the same evidence; a less severe cover is linked. The diff already reported these but the rule layer ignored `findings`, so e.g. a reverse-shell cron job was only a medium `BO-SCH-001`. A malformed finding entry is a rule error (coverage incomplete); a non-list `findings.new`/`findings.changed` is rejected (exit 3).
- Linux collector emits `config:sysctl:kernel.randomize_va_space` (inventory only), so the ASLR branch of `BO-CFG-002` can fire on a real host; `BO-CFG-002` also reads the Windows `config:ip_forward` record (`enabled`).
- `tests/shared/test_rule_collector_contract.py` runs the real Linux collector and checks the PowerShell sources so rule keys and collector keys cannot drift apart; `tests/shared/test_detection_regressions.py` pins each reproduced failure with its negative cases.
- Test data: `tests/fixtures/baseline-e2e/linux/changed.json` `user:mallory` now carries the `/etc/passwd` evidence reference that real user records have.
- Detections schema, exit codes and the diff contract are unchanged; the rule count is now 27.

### Added (detection validation)
- `docs/detection-validation.md`: expected outcomes written before the runs, results, deviations, false positives, false negatives, platform coverage and limitations.
- `tests/shared/test_detection_validation_linux.py` (real audit over disposable fixture roots) and `tests/shared/test_detection_validation_windows.py` (PowerShell collector over mutated fixture copies; needs PowerShell), with a small shared helper `tests/shared/detection_validation.py`.
- The validation found the `BO-PER-001` key mismatch (LS-04) and recorded the Windows `ip_forward` gap (FN-3); both are fixed by the detection-correctness entry above (`docs/detection-validation.md` is updated accordingly).

### Added (detection rules, v0.3)
- `python -m shared.reporting.detect` (`shared/reporting/{detect,detection}.py`): offline, read-only, explainable detections over the baseline comparison. 26 rules (`BO-USR/GRP/PER/EXE/SCH/SVC/NET/CFG-nnn`) each carry a severity, rationale, supporting evidence, ATT&CK orientation and investigation steps, and are labelled `observed` (fact in the report) or `heuristic` (suspicion). Rules fire on changes only; matches on one record merge into one detection and detections sharing an artifact are linked; incomplete coverage yields exit 6, never a clean result.
- `shared/schemas/detections.schema.json` (`kind: "detections"`), `--from-diff`, `--min-severity`, `--list-rules`; reuses diff exit codes.
- `tests/shared/test_detection.py`: per-rule firing and false-positive scenarios, pinned Linux/Windows end-to-end results, remediation, coverage, determinism, malformed input and read-only/offline checks. CI smoke test for the CLI.
- `docs/detection-rules.md`: output model, rule catalogue, regression matrix, limitations.
- Accepted-change allowlist (`--accepted FILE`, `shared/reporting/accepted.py`, `examples/accepted-changes.example.json`): per-subject, rule-scoped, severity-capped (never critical), expiring entries with reason and approver. Matches move to `accepted[]` unchanged with an `acceptance` block; `allowlist` audits every entry (matched/unused/expired and why not applied). Malformed files exit 3.
- `unknown[]` on every detection: hash-only startup/sudoers/PAM records now state what the report cannot show (content, direction of the change).
- Remediation false positives removed: already-down security services, ASLR raised, a listener leaving a netcat-style tool (low), temporary paths already present before the change.
- `tests/shared/test_accepted.py`: remediation, hash-only and allowlist regression tests.

### Fixed (baseline comparison conclusions)
- A report whose `inventory` is present but not an object, whose `inventory.coverage`/`findings`/`errors` is not a list, or that holds a non-object finding or error is now rejected (exit 3) instead of being read as missing data; dropped errors could hide a failed module and report findings as resolved.
- Findings absent from a run are *unverified*, not resolved, after a new error that names no check, or a failure/partial run exit code the baseline did not have.
- A `complete` collection of users, groups, services or processes that is empty while the other side is not no longer yields mass removals or additions.
- Windows console helpers (`tasklist.exe`, `whoami.exe`, ...) from `System32` are transient by default; added to `transient_processes` in `shared/config/baseline-diff.default.json`.

### Added (listener comparison)
- `fixed_ports` option (config file) compares listeners on the listed ports exactly even in the ephemeral range, so a new stable high-port listener is no longer hidden by an existing process name.

### Added (baseline end-to-end regression tests)
- `tests/shared/test_baseline_e2e.py` and `tests/fixtures/baseline-e2e/`: sanitized synthetic Linux and Windows audit snapshots driven through the real `python -m shared.reporting.diff` CLI. They pin the behavior for identical snapshots, added/removed/modified records, transient processes and ephemeral ports, permission gaps and failed modules, malformed or incompatible input (exit 3), offline/read-only operation and deterministic output. No behavior change.
- `docs/baseline-diff.md`: expected-behavior matrix and newly documented limitations (trust in coverage statements, Windows transient helpers need configuration, high-port services are bucketed as ephemeral, non-object `inventory` is treated as absent).

### Added (baseline snapshots and change detection, schema 0.2.0)
- Offline comparison engine and CLI (`python -m shared.reporting.diff`, `shared/reporting/{inventory,baseline,baseline_render,diff}.py`): additions, removals and modifications of users, groups, services, processes, listeners, scheduled tasks, persistence and configuration, with observation timestamps, evidence and related-finding links; text and JSON (`shared/schemas/baseline-diff.schema.json`) output; exit codes 0/4/6/3/2/1. See `docs/baseline-diff.md`.
- Audit-report schema **0.2.0**: optional `inventory` (`coverage[]` + `records[]` with stable keys, compared `attrs`, `volatile` context and `evidence`). Additive: 0.1.0 reports remain valid and load (findings delta only, exit 6 with a `NO_INVENTORY` warning). `SCHEMA_VERSION` is `0.2.0`; `READABLE_REPORT_VERSIONS` lists the readable lines.
- Linux collectors emit inventory (users/groups/sudoers/SSH-key fingerprints, processes, listeners and network config, services, cron/persistence, PAM, SUID) with per-domain coverage (`bo_inv`, `bo_cov` in `linux/lib/common.sh`).
- Windows collectors emit inventory (users and groups by SID, services, processes, listeners, tasks, autoruns/persistence, security/firewall/network configuration) with coverage that degrades on errors, fallbacks and crashed or missing modules (`Add-BoInventory`, `Add-BoCoverage` in `windows/lib/Common.ps1`).
- Handling of transient PIDs, ephemeral ports (per-OS thresholds), transient helper processes, partial/degraded/unavailable coverage, privilege differences and duplicate keys; hardened report loader (size and nesting limits, duplicate keys, BOM, control characters).
- Tests: `tests/shared/test_baseline_diff.py` (synthetic and adversarial baselines), `test_baseline_cli.py` (golden files in `tests/fixtures/baseline/`, CLI, read-only/offline checks), `test_linux_baseline_e2e.py`, `tests/linux/inventory.bats`, `tests/windows/Inventory.Tests.ps1`; CI smoke step for the diff CLI.
- `shared/config/baseline-diff.default.json`: default comparison options.

### Changed
- Reports now declare `schema_version` `0.2.0` (Linux and Windows collectors); the example report was updated.

### Added
- Windows read-only audit v0.1 (`windows/audit/Invoke-WindowsAudit.ps1`, `windows/persistence/Find-Persistence.ps1`, `windows/lib/Common.ps1`): system, users, processes, network, services, scheduled tasks, autoruns, persistence, firewall, security configuration and filesystem modules emitting schema 0.1.0 reports. See `docs/windows-audit.md`.
- Pester suites, synthetic Windows host fixtures and a schema-conformance pytest; the CI PowerShell job now runs Pester under Windows PowerShell 5.1 and PowerShell 7.
- `audit-pam.sh` module (`PAM-*` findings): read-only PAM configuration review.
- `--package-integrity` option: opt-in Debian `dpkg --verify` checks (`FS-PKG-*`).
- `SVC-FAILED-002`: failed systemd socket units.
- `FS-PKG-004`: modified security-sensitive conffiles under `--package-integrity`.

### Fixed
- SUID/SGID inventory returned zero on real hosts: `/proc/mounts` was read with the wrong field separator, so no scan roots were found. Overlay filesystems are now scanned too.
- False positives: standard X11 `/tmp` socket paths, and the packaged `postgres` account's shell.

### Fixed
- Heuristic exceptions no longer hide real findings: `find -exec`, `cp`/`mv`/`tar` of `/tmp` paths, and a broad X11 exemption are no longer ignored; PAM bypasses via `success=done` and `pam_succeed_if` are detected.
- `PAM-MODULE-002` ignores `include`/`substack` lines and dash-prefixed optional modules; common Debian SUID helpers are recognized; `--package-integrity` requires root (`PKG_NEEDS_ROOT`).
- Recent-file scan is about 6x faster on large trees.

### Added (earlier in Unreleased)
- Linux read-only host audit (v0.1): `linux/audit/audit-linux.sh` unified entry point plus standalone modules `audit-system.sh`, `audit-users.sh`, `audit-processes.sh`, `audit-network.sh`, `audit-services.sh`, `audit-filesystem.sh`, and `linux/persistence/check-persistence.sh`; shared helpers in `linux/lib/common.sh`; human and JSON (schema 0.1.0) output; see `docs/linux-audit.md`.
- Bats tests with synthetic fixtures (`tests/linux`, `tests/fixtures/linux-*`) and a pytest schema-conformance test for the Linux reports.
- Initial repository scaffolding: directory layout, `CLAUDE.md`, documentation set.
- CI and lint workflows (ShellCheck, shfmt, PSScriptAnalyzer, Ruff, pytest, Bats, Pester), Dependabot config.
- Versioned JSON audit-report schema (v0.1.0), severity levels, and exit-code contract with tests.
