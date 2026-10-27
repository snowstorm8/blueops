# Architecture

## Principles

1. **Independent platform collectors.** Bash (Linux) and PowerShell (Windows) tools run standalone, offline, with OS-native commands only.
2. **Shared contracts, not shared runtime.** Platforms agree on JSON schemas, exit codes, severities, and naming (see [contracts.md](contracts.md)); they do not depend on each other or on Python being present.
3. **Python for analysis, not collection.** `shared/reporting/` validates, merges, diffs, and renders reports, typically on an analyst machine. Baseline comparison (`python -m shared.reporting.diff`, see [baseline-diff.md](baseline-diff.md)) and detection rules over its output (`python -m shared.reporting.detect`, see [detection-rules.md](detection-rules.md)) are implemented; merge/render are planned.
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

## Inventory and change detection (decisions)

- **Structured inventory, not text diffing.** Collectors emit `inventory.records` with stable keys beside the existing findings; the comparison engine never reads free-text descriptions. Schema 0.2.0 is additive, so 0.1.0 consumers and producers keep working.
- **Coverage is part of the data.** Each domain/scope states how completely it was collected, so a missing module, a permission gap or an interrupted scan can never be read as "removed". The engine concludes only what the evidence supports and reports the rest as indeterminate.
- **Volatile vs. identity.** PIDs, ephemeral ports and counts are carried but never compared; unknown (null) attributes are never compared.
- **Offline and read-only.** The engine reads two files and writes one; it is deliberately separate from the collectors and has no network or host access.
- **Untrusted input.** Reports may come from compromised hosts: strict loader limits, duplicate-key rejection, and output sanitisation.

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
