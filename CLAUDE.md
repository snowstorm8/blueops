# CLAUDE.md — BlueOps project instructions

These rules apply to every change made in this repository. Keep this file practical; update it when conventions change.

## 1. Vision and users

BlueOps is a portable, cross-platform Blue Team toolkit for competitions (CCDC-style Red vs. Blue), incident response, host auditing, persistence detection, evidence collection, and hardening. Users are defenders working under time pressure on hosts they are **authorized** to administer, often offline, often with unfamiliar or degraded systems.

Priorities, in order: **(1) preserve service availability and evidence, (2) reliability, (3) portability and minimal dependencies, (4) speed of deployment, (5) features.**

Status: the repository is scaffolding. Do not claim a capability exists until it is implemented and tested. Planned work lives in `docs/roadmap.md`.

## 2. Repository layout

| Path | Responsibility |
|---|---|
| `linux/{audit,persistence,incident,hardening,lib}` | Bash tooling. `lib/` holds sourced helpers only (no top-level side effects). |
| `windows/{audit,persistence,incident,hardening,lib}` | PowerShell tooling. `lib/` holds dot-sourced/imported helpers only. |
| `shared/schemas/` | Versioned JSON Schemas (the contract between platforms and tooling). |
| `shared/reporting/` | Python 3 (stdlib-first) code: contracts, report validation, merging, rendering. |
| `shared/config/` | Platform-neutral default configuration. |
| `profiles/{linux,windows}/` | Named hardening/audit profiles (e.g. per-competition service allowlists). |
| `tests/{linux,windows,shared,fixtures}` | Bats, Pester, pytest tests; fixtures are synthetic data only. |
| `docs/` | Architecture, development, deployment, security model, roadmap, contracts. |
| `examples/` | Example reports and configs (synthetic). |
| `blueops` (repo root) | Linux launcher: `doctor`, `audit`, `persistence`, `diff`, `detect`. Read-only; works from any cwd. |
| `scripts/setup/` | Dependency setup, separate from auditing. Changes the system only with `--install`, after confirmation. |
| `scripts/development/` | Maintainer/dev helpers (never deployed to targets). |

Category semantics: **audit** = read-only inspection. **persistence** = read-only detection of persistence mechanisms. **incident** = evidence collection and (opt-in) containment. **hardening** = state-changing configuration. Never mix these in one script: a script lives in exactly one category and its behavior must match that category.

## 3. Safety model (non-negotiable)

- **Read-only by default.** Anything outside `hardening/` and explicit containment actions in `incident/` must not modify system state (beyond writing its own output directory).
- **Explicit confirmation** before any system modification: interactive prompt, or `--yes` / `-Yes` for automation. Without a TTY and without the flag, abort (exit 5).
- **Dry-run** (`--dry-run` / `-DryRun`) for every state-changing operation: print exactly what would change, change nothing, exit 0. Dry-run must exercise the same code path up to the mutation.
- **Rollback.** Every reversible change records prior state (to the run's `rollback/` dir) before applying, and ships a matching restore path (`--rollback <run-dir>`). Irreversible actions must be labelled as such in help text and require an extra confirmation.
- **Service availability.** Before changing anything, check dependencies (listening services, scored ports, dependent units/services). Profiles declare protected services/ports; hardening must refuse or skip changes that would break them. Prefer disabling over deleting, and reloading over restarting.
- **No destructive defaults.** No file deletion, process killing, account removal, firewall flush, or log clearing unless explicitly requested per-action, confirmed, and (where possible) preceded by a backup.
- **Authorized environments only.** Banner/help text states this. Never add offensive, exploit, evasion, or credential-attack functionality.
- **No unverified remote code.** Never `curl | sh`, `iex (iwr ...)`, or fetch-and-execute. No network access at runtime by default; tooling must work fully offline. Any download feature must be opt-in and verify checksums/signatures.
- **Secrets.** Never log, print, or commit credentials, keys, tokens, or hashes. Redact in output; never accept secrets as command-line arguments (visible in process lists) — use files with 0600/ACL perms, env vars, or prompts. Evidence may contain sensitive data: restrict output permissions (0700 dir / owner-only ACL).

## 4. Conventions common to all languages

- **Naming:** scripts are `kebab-case` (`check-cron-jobs.sh`, `Get-ScheduledTaskAudit.ps1` is the exception for PowerShell: `Verb-Noun.ps1`). Flags are long-form, kebab-case on Bash (`--output-dir`), PascalCase on PowerShell (`-OutputDir`). Same concept = same name on both platforms.
- **Standard flags** (where applicable): `--help`, `--version`, `--output-dir`, `--format {text,json}`, `--json`, `--quiet`, `--verbose`, `--dry-run`, `--yes`, `--no-color`.
- **Exit codes** (see `shared/reporting/contracts.py` and `docs/contracts.md`): `0` ok, `1` unexpected error, `2` usage error, `3` precondition failed (privileges, OS, missing tool), `4` findings detected, `5` aborted by user/confirmation declined, `6` partial failure. Never invent other codes.
- **Output streams:** human text and logs → stderr when `--json` is active; machine-readable JSON → stdout or the file named by `--output-dir`. Never mix.
- **Timestamps:** ISO 8601 UTC with `Z` suffix (`2026-01-31T14:05:09Z`) everywhere; filenames use `YYYYMMDDTHHMMSSZ`.
- **Logging:** levels `DEBUG|INFO|WARN|ERROR`; each line has UTC timestamp, level, module. Logs go to the run directory, not system log locations, unless asked.
- **Evidence preservation:** collect in order of volatility; never modify originals; copy then hash (SHA-256) and record hashes, collector version, host, user, and start/end time in a manifest. Evidence directories are append-only within a run.
- **JSON output:** every audit/collection tool supports `--json` conforming to `shared/schemas/` and carries `schema_version`. Schema changes follow semver (see `docs/contracts.md`); never change the meaning of an existing field in a minor/patch release.
- **Backward compatibility:** do not rename flags, exit codes, output fields, or file layouts without a deprecation period and a CHANGELOG entry.
- **Dependencies:** use only what ships with the OS (coreutils, `ss`/`netstat`, `systemctl`, built-in PowerShell cmdlets/CIM). Probe optional tools with fallbacks and report degraded coverage rather than failing. Python is optional on targets; Bash/PowerShell collectors must work without it, with Python used only for shared analysis/reporting on an analyst machine. Any new dependency requires justification in the PR. Dev-only tools live in `requirements-dev.txt`.

## 5. Bash (`linux/`)

- Target Bash ≥ 4.2, no GNU-only assumptions unless guarded (detect and degrade). Shebang `#!/usr/bin/env bash`.
- `set -Eeuo pipefail`; `IFS=$'\n\t'`; use `trap` for cleanup and error reporting. Quote every expansion; use `[[ ]]`, `local`, `readonly`, arrays; never parse `ls`; use `--` before user-supplied paths.
- Structure: header comment (purpose, category, safety level, usage), `usage()`, `parse_args()` (long options via `while/case`, reject unknown), `main()`, and `main "$@"` guarded by `[[ "${BASH_SOURCE[0]}" == "$0" ]]` so files are sourceable by tests.
- Functions in `lib/` are namespaced (`bo_log_info`, `bo_require_root`, …) and idempotent to source.
- Format with `shfmt` (config in `.editorconfig`); must pass `shellcheck` with no new disables. Any `# shellcheck disable=` needs a reason comment.
- Tests: Bats (`tests/linux/*.bats`).

## 6. PowerShell (`windows/`)

- Compatible with Windows PowerShell 5.1 **and** PowerShell 7 (Server 2012R2+ where feasible). No external modules. Files are UTF-8 **without BOM** (see `docs/development.md` for 5.1 limitations): prefer ASCII in source, and when non-ASCII is unavoidable, build it from escapes (`[char]0x00E9`) rather than literals, since Windows PowerShell 5.1 reads BOM-less files as the ANSI code page. Write files explicitly with `-Encoding utf8` knowing 5.1 emits a BOM; never rely on the default.
- `#Requires -Version 5.1`; `[CmdletBinding()]` with `param()` block; `Set-StrictMode -Version Latest`; `$ErrorActionPreference = 'Stop'`. Use approved verbs (`Verb-Noun`), `[ValidateSet]`, `SupportsShouldProcess` (`-WhatIf` mapped to `-DryRun`, `-Confirm`) on state-changing functions.
- Use CIM (`Get-CimInstance`) rather than deprecated WMI cmdlets; avoid aliases and positional parameters in scripts; no `Invoke-Expression`; no `Write-Host` for data (use `Write-Output`/`Write-Verbose`/`Write-Information`).
- Exit via `exit <code>` at script level only; functions throw typed errors.
- Must pass PSScriptAnalyzer with `PSScriptAnalyzerSettings.psd1`. Tests: Pester v5 (`tests/windows/*.Tests.ps1`).

## 7. Python (`shared/`)

- Python ≥ 3.9, standard library first; any third-party import in runtime code needs explicit justification. Type hints on public functions; `from __future__ import annotations`.
- Format and lint with Ruff (`ruff format`, `ruff check`; config in `pyproject.toml`). No `print` for library output — return data; CLI entry points use `argparse` and the shared exit codes.
- Parse untrusted input defensively (evidence and logs are attacker-influenced). Never `eval`/`exec`/`pickle`/`shell=True`.
- Tests: pytest (`tests/shared/`), no network, fixtures from `tests/fixtures/`.

## 7a. Deployment contract (fresh clone)

The supported deployment is `sudo apt install git; git clone https://github.com/snowstorm8/blueops.git; cd blueops`. Keep it true:

- Everything a collector, the launcher or setup needs is tracked in Git (`tests/shared/test_fresh_clone.py` copies only tracked files and runs the flow from an unrelated cwd). Never rely on untracked, ignored or locally generated files, absolute dev paths, or a particular cwd; resolve paths from `BASH_SOURCE`/`$PSScriptRoot`.
- Setup is separate from auditing. Collectors and `blueops` never install packages or edit configuration; a missing required command exits 3 with the fix. `scripts/setup/` modifies the system only with `--install`, after showing the exact commands and confirming (`--yes`; no TTY and no `--yes` exits 5).
- New required commands go into `BO_DEPS_REQUIRED_CMDS` in `linux/lib/deps.sh` (with package names); new required files into `BO_DEPS_REQUIRED_FILES`.

## 8. Testing and quality

- Every module ships with tests in the matching `tests/<platform>/` directory. State-changing code requires tests for dry-run, confirmation refusal, and rollback.
- Run `scripts/development/check.sh` (or `check.ps1` on Windows) before committing. CI runs ShellCheck, shfmt, PSScriptAnalyzer, Ruff, pytest, Bats, and Pester.
- **Never claim a test, linter, or build passed unless you actually ran it in this session and saw the output.** If a tool is unavailable locally, say so explicitly.
- Fixtures are synthetic. Never commit real hostnames, IPs, credentials, or collected evidence.

## 9. Documentation

- Each script has a usage header and `--help`. User-visible behavior changes update `README.md`/`docs/` and `CHANGELOG.md` (Keep a Changelog format, `[Unreleased]` section) in the same change.
- README must distinguish **implemented** from **planned** features; update it when status changes. Do not invent releases, links, CI badges for nonexistent workflows, or results.
- Record design decisions in `docs/architecture.md`; threat/trust assumptions in `docs/security-model.md`.

## 10. Git workflow

- Branches: `main` (always releasable), `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `chore/<topic>`. Work through pull requests; keep them small and single-purpose.
- Commits: Conventional Commits (`feat(linux/audit): ...`, `fix(shared): ...`, `docs:`, `test:`, `chore:`, `ci:`), imperative mood, body explains *why*.
- Never commit secrets, evidence, reports, or local config (see `.gitignore`). Don't rewrite shared history. Don't commit or push unless asked.

## 11. Working agreements for Claude

1. Inspect existing code and conventions before modifying; follow them.
2. Prefer the smallest change that solves the problem; avoid unnecessary dependencies and speculative abstraction.
3. Preserve backward compatibility of flags, outputs, and schemas.
4. Keep audit, containment, and hardening separated; when in doubt choose the safer, read-only behavior and ask.
5. Refuse to add offensive capability or behavior that targets systems without authorization.
6. Report honestly what was run and what was not.
