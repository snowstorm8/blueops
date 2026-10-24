# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
