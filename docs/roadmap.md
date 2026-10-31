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
- [x] Python: baseline diff / change detection (`python -m shared.reporting.diff`, schema 0.2.0 inventory; see [baseline-diff.md](baseline-diff.md))
- [ ] Python: report validation CLI, multi-host merge

## Phase 2 — Read-only audit and persistence

- [x] Linux: users/groups, services, network listeners, scheduled jobs, startup, SUID/permissions (v0.1; baselines/allowlists via profiles still planned)
- [x] Windows (v0.1): system, users/groups, processes, network listeners, services, tasks, Run keys/autoruns, WMI subscriptions and other persistence, firewall, security configuration, filesystem

## Phase 2b — Baselines and change detection (v0.2)

- [x] Structured inventory with stable keys and per-domain coverage (Linux and Windows collectors)
- [x] Offline comparison engine: additions, removals, modifications, indeterminate results, findings delta
- [x] Text and JSON diff reports; golden and adversarial regression tests
- [ ] Baseline allowlists in `profiles/` (accepted changes), HTML rendering, multi-host merge
- [ ] Inventory for Windows local groups beyond Administrators/Remote Desktop Users, installed software, and Linux package state

## Phase 2c — Detection validation and investigation (v0.3)

- [x] Rule engine over baseline-diff data: severity, rationale, evidence, investigation steps, observed vs. heuristic basis, per-subject merging and artifact correlation (`python -m shared.reporting.detect`; see [detection-rules.md](detection-rules.md))
- [x] Synthetic regression tests including false-positive and remediation cases; CI smoke test
- [ ] Accepted-change allowlists in `profiles/` (shared with baseline allowlists)
- [ ] Standing-state rules over a single report (no baseline needed), SIEM/log-based rules, Linux service binary paths in the inventory
- [ ] Detection of changes to files/logs outside the current inventory domains

## Phase 2d — Audit remediation (v0.3.x)

- [x] Detection and inventory gaps from the engineering audit (command content, standing-state checks, hash-only direction, contract mismatches) — see [audit-remediation.md](audit-remediation.md)
- [x] Security and integrity hardening (test-hook gating, trusted `PATH`, run manifest and verifier, strict JSON, injective text encoding, TSV forgery, redaction)
- [ ] Run the new PowerShell code on a Windows runner (Pester `Hardening.Tests.ps1`) — written without a local PowerShell, unverified until CI
- [ ] Single-report (baseline-free) detection mode; the new standing-state checks are audit findings only
- [ ] `apk`/`pacman` package integrity; Alpine/BusyBox and Bash 4.2 CI jobs; coverage measurement; pin CI actions by commit SHA

## Phase 3 — Incident response

- [ ] Evidence collection with hashing/manifests (both platforms)
- [ ] Opt-in containment actions with rollback

## Phase 4 — Hardening

- [ ] Profile format and protected-service checks
- [ ] Baseline hardening profiles with dry-run/rollback

## Phase 5 — Reporting and releases

- [ ] HTML/Markdown report rendering, multi-host merge
- [ ] Checksummed release process
