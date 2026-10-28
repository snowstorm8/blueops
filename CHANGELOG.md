# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed (detection validation)
- `BO-PER-001` now matches the Linux collector's real SSH key records (`persist:ssh-authkey:<owner>:<id>`, `owner` attribute). Before, a new `root` authorized key was reported only by `BO-PER-002` at medium instead of critical.

### Added (detection validation)
- `docs/detection-validation.md`: expected outcomes written before the runs, results, deviations, false positives, false negatives, platform coverage and limitations.
- `tests/shared/test_detection_validation_linux.py` (real audit over disposable fixture roots) and `tests/shared/test_detection_validation_windows.py` (PowerShell collector over mutated fixture copies; needs PowerShell), with a small shared helper `tests/shared/detection_validation.py`.

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
