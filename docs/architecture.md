# Architecture

## Principles

1. **Independent platform collectors.** Bash (Linux) and PowerShell (Windows) tools run standalone, offline, with OS-native commands only.
2. **Shared contracts, not shared runtime.** Platforms agree on JSON schemas, exit codes, severities, and naming (see [contracts.md](contracts.md)); they do not depend on each other or on Python being present.
3. **Python for analysis, not collection.** `shared/reporting/` validates, merges, diffs, and renders reports, typically on an analyst machine.
4. **Strict separation of intent.** `audit` and `persistence` are read-only; `incident` collects evidence and offers opt-in containment; `hardening` changes state. A script lives in exactly one category.
5. **Safety by construction.** Confirmation, dry-run, rollback records, and protected-service checks are implemented once in each platform's `lib/` and reused.

## Data flow (planned)

```
linux/*.sh ──┐                        ┌─> report.json (schema 0.x)
             ├─> per-host run dir ────┤
windows/*.ps1┘   (logs, evidence,     └─> evidence/ + manifest.json (SHA-256)
                  rollback/)                     │
                                                 v
                          shared/reporting (merge / diff / render)
```

## Directory responsibilities

See the table in [CLAUDE.md](../CLAUDE.md#2-repository-layout).

## Deviations from the initial layout

- Added `docs/contracts.md` (output, exit-code, severity, schema contracts).
- Added root `pyproject.toml`, `requirements-dev.txt`, `PSScriptAnalyzerSettings.psd1`, `.shellcheckrc`: tool configuration must live at the root to be discovered by the tools.
- Added `.github/dependabot.yml` and `.github/ISSUE_TEMPLATE/*.md`.
- `shared/` and `shared/reporting/` are Python packages (`__init__.py`) so tests import `shared.reporting`.
- `.gitkeep` placeholders keep empty directories tracked; remove one when real files land in that directory.
- Line endings: all text is LF (including `.ps1`) and files are UTF-8 without BOM (the repo-wide norm). Windows PowerShell 5.1 limitations are documented in `docs/development.md`.

## Decisions to revisit

- Bats-core is the Bash test framework (dev-only dependency).
- License: MIT (change before first release if a different license is wanted).
