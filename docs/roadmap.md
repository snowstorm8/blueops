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

## Phase 2e — Assessment platform (v0.4)

- [x] Assessment engine: registry, plugin manifests, dependency planning, per-module time limits, strict output validation, profiles (`python -m shared.engine`; see [assessment-engine.md](assessment-engine.md))
- [x] Central findings and evidence: stable ids, deduplication, provenance, standards references ([findings.md](findings.md))
- [x] Coverage-aware snapshot comparison (new / resolved / persistent / severity / configuration / coverage) ([reporting.md](reporting.md))
- [x] JSON, Markdown and self-contained HTML reports
- [x] Linux `auth` and `sysconfig` modules; Windows `eventlog` module (**unverified on a real PowerShell**)
- [ ] Run the new Windows module and the engine's PowerShell path on a Windows runner (Pester `EventLog.Tests.ps1`, engine smoke test)
- [ ] Feed assessments to `shared.reporting.detect` (detection rules over snapshot comparisons); multi-host merge and fleet report
- [ ] Windows: local groups beyond Administrators/Remote Desktop Users, security-policy export (`secedit`), SMB/WinRM listener configuration
- [ ] Linux: installed-software inventory, `apk`/`pacman` integrity, container awareness
- [ ] Parallel module execution (opt-in), resumable assessments, output size caps for module streams
- [ ] Signed plugin manifests

## Phase 2f — Detection and correlation engine (v0.5)

- [x] Rule engine: JSON rule packs, condition language, validation with diagnostics, enable/disable, versions ([detection-engine.md](detection-engine.md))
- [x] Correlation: clauses, joins, distinct/min-matches, optional corroboration, explicit severity/confidence rules, explanations
- [x] Snapshot- and history-aware detections; detections across snapshots; indeterminate instead of false conclusions
- [x] Investigation workflow (statuses, notes, links, history) in a portable append-only file
- [x] 29 rules with executable examples ([detection-library.md](detection-library.md)); CLI, reports (JSON/Markdown/HTML), export
- [ ] Merge the v0.3 baseline-diff rules (`shared.reporting.detect`) into the engine
- [ ] Windows privilege-assignment and event-log-content collectors, then rules over them
- [ ] Multi-host correlation (needs the fleet merge); rule-pack signing; allowlists/accepted changes for the new engine
- [ ] A rule-authoring linter for false-positive review (e.g. warn on broad regexes)

## Phase 2g — Endpoint telemetry and threat hunting (v0.6)

- [x] Versioned telemetry schema with provenance and coverage semantics ([telemetry.md](telemetry.md))
- [x] Linux and Windows collectors (JSON Lines), offline import, deduplication, conflict reporting, derived authentication summaries
- [x] Query layer (constrained JSON/flags), process trees, coverage-aware snapshot comparison
- [x] 24 hunting rules through the detection engine; cases, reports (JSON/Markdown/HTML)
- [ ] Verify the Windows collector on more Windows versions/SKUs and under constrained language mode
- [ ] Process-image integrity (signature/hash of running executables), Linux runtime service state, Sysmon/ETW and auditd rule packs as optional sources
- [ ] Streaming/continuous collection and multi-host correlation
- [ ] Allowlists / accepted changes for hunting rules

## Phase 3 — Incident response

- [ ] Evidence collection with hashing/manifests (both platforms)
- [ ] Opt-in containment actions with rollback

## Phase 4 — Hardening

- [ ] Profile format and protected-service checks
- [ ] Baseline hardening profiles with dry-run/rollback

## Phase 5 — Reporting and releases

- [x] HTML/Markdown report rendering (single host; see Phase 2e)
- [ ] Multi-host merge
- [ ] Checksummed release process
