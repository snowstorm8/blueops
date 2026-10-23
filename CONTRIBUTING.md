# Contributing to BlueOps

Thanks for helping. BlueOps is defensive tooling; contributions must keep it safe, portable, and dependency-light. Read [CLAUDE.md](CLAUDE.md) — it is the authoritative set of conventions for humans and AI assistants alike.

## Ground rules

- Defensive use only. No exploit, evasion, credential-attack, or other offensive functionality.
- Read-only by default; state changes need confirmation, `--dry-run`, and rollback.
- No new runtime dependencies without discussion. Tools must work offline.
- No real credentials, hostnames, IPs, or collected evidence in commits, issues, or fixtures.

## Workflow

1. Open an issue (or comment on one) before large changes.
2. Branch from `main`: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `chore/<topic>`.
3. Make focused changes with tests and docs. Update `CHANGELOG.md` under `[Unreleased]`.
4. Run `scripts/development/check.sh` (Linux/macOS) or `scripts/development/check.ps1` (Windows).
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/), e.g. `feat(linux/audit): add listening-port audit`.
6. Open a PR using the template; CI must pass.

## Development setup

See [docs/development.md](docs/development.md) for tool installation (ShellCheck, shfmt, Bats, PSScriptAnalyzer, Pester, Ruff, pytest).

## Reporting security issues

Do not open public issues for vulnerabilities in BlueOps; see [SECURITY.md](SECURITY.md).
