# Roadmap

Everything beyond Phase 0 is **planned** and subject to change.

## Phase 0 — Foundation (current)

- [x] Repository layout, conventions (`CLAUDE.md`), docs
- [x] CI/lint workflows, Dependabot, formatting rules
- [x] Audit-report schema v0.1.0, severity and exit-code contracts

## Phase 1 — Shared libraries

- [ ] Bash `lib/`: logging, arg parsing, confirmation, dry-run, JSON emit, run-dir management
- [ ] PowerShell `lib/`: equivalent module
- [ ] Python: report validation CLI, merge/diff

## Phase 2 — Read-only audit and persistence

- [ ] Linux: users/groups, services, network listeners, scheduled jobs, startup, SUID/permissions
- [ ] Windows: users/groups, services, tasks, Run keys, WMI subscriptions, listeners

## Phase 3 — Incident response

- [ ] Evidence collection with hashing/manifests (both platforms)
- [ ] Opt-in containment actions with rollback

## Phase 4 — Hardening

- [ ] Profile format and protected-service checks
- [ ] Baseline hardening profiles with dry-run/rollback

## Phase 5 — Reporting and releases

- [ ] HTML/Markdown report rendering, multi-host merge
- [ ] Checksummed release process
