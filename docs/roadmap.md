# Roadmap

Everything beyond Phase 0 is **planned** and subject to change.

## Phase 0 — Foundation (current)

- [x] Repository layout, conventions (`CLAUDE.md`), docs
- [x] CI/lint workflows, Dependabot, formatting rules
- [x] Audit-report schema v0.1.0, severity and exit-code contracts

## Phase 1 — Linux read-only host auditing (v0.1)

- [x] v0.2: PAM review, failed socket units, Debian package-integrity option, SUID fix, context heuristics
- [x] Bash `lib/common.sh`: logging, arg parsing, finding/error recording, JSON emit, run-dir management
- [x] `audit-linux.sh` + modules: system, users, processes, network, services, persistence, filesystem
- [x] Bats tests with synthetic fixtures; Linux CI
- [ ] Bash `lib/`: confirmation and dry-run helpers (needed by hardening/containment)

## Phase 1b — Shared libraries
- [x] PowerShell `lib/Common.ps1`: logging, finding/error recording, JSON emit, run-dir management (confirmation/dry-run helpers still planned)
- [ ] Python: report validation CLI, merge/diff

## Phase 2 — Read-only audit and persistence

- [x] Linux: users/groups, services, network listeners, scheduled jobs, startup, SUID/permissions (v0.1; baselines/allowlists via profiles still planned)
- [x] Windows (v0.1): system, users/groups, processes, network listeners, services, tasks, Run keys/autoruns, WMI subscriptions and other persistence, firewall, security configuration, filesystem

## Phase 3 — Incident response

- [ ] Evidence collection with hashing/manifests (both platforms)
- [ ] Opt-in containment actions with rollback

## Phase 4 — Hardening

- [ ] Profile format and protected-service checks
- [ ] Baseline hardening profiles with dry-run/rollback

## Phase 5 — Reporting and releases

- [ ] HTML/Markdown report rendering, multi-host merge
- [ ] Checksummed release process
