# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
