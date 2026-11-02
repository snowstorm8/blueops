# Architecture

## Principles

1. **Independent platform collectors.** Bash (Linux) and PowerShell (Windows) tools run standalone, offline, with OS-native commands only.
2. **Shared contracts, not shared runtime.** Platforms agree on JSON schemas, exit codes, severities, and naming (see [contracts.md](contracts.md)); they do not depend on each other or on Python being present.
3. **Python for analysis, not collection.** `shared/reporting/` validates, merges, diffs, and renders reports, typically on an analyst machine. Baseline comparison (`python -m shared.reporting.diff`, see [baseline-diff.md](baseline-diff.md)) and detection rules over its output (`python -m shared.reporting.detect`, see [detection-rules.md](detection-rules.md)) are implemented; merge/render are planned.
4. **Strict separation of intent.** `audit` and `persistence` are read-only; `incident` collects evidence and offers opt-in containment; `hardening` changes state. A script lives in exactly one category.
5. **Safety by construction.** Confirmation, dry-run, rollback records, and protected-service checks are implemented once in each platform's `lib/` and reused.

## Data flow

```
linux/*.sh ──┐                        ┌─> report.json (audit-report 0.2.0)
             ├─> per-host run dir ────┤
windows/*.ps1┘   (logs, evidence,     └─> evidence/ + manifest.json (SHA-256)
plugins ─────┘    rollback/)                    │
                                                v
                  shared/engine (registry -> runner -> validation -> assessment)
                                                │
                       shared/findings (BOF-/EV- identity, dedupe, provenance)
                                                │
              assessment.json ──> shared/reporting (snapshot compare, Markdown, HTML)
                                  shared/reporting.diff / detect (inventory diff, detection rules)
```

The assessment platform (engine, findings, comparison, reports) is described in [assessment-engine.md](assessment-engine.md), [findings.md](findings.md), [reporting.md](reporting.md) and [plugins.md](plugins.md).

### Layers

| Layer | Package | Depends on | Must not |
|---|---|---|---|
| Collectors | `linux/`, `windows/` | OS tools only | import Python, call the engine |
| Contracts | `shared/schemas/`, `shared/reporting/contracts.py` | nothing | change meaning of a field in a minor release |
| Validation | `shared/reporting/schema_lite.py`, `jsonio.py` | stdlib | accept a schema keyword it cannot check |
| Findings | `shared/findings/` | contracts | read a host |
| Engine | `shared/engine/` | validation, findings | inspect a host, load plugin code, use a shell |
| Detection | `shared/rules/` | engine documents, findings | read a host, execute rule content, store analyst state in assessments |
| Analysis and reporting | `shared/reporting/` | engine documents | write anything but the file it is told to |

### Decisions (detection engine)

Details in [detection-engine.md](detection-engine.md#design-decisions). In short: rules are JSON data validated and compiled once; one clause/`require` model covers single and correlated rules; severity changes only through explicit, explained rules (never by count); absence-based conclusions need declared coverage and otherwise end *indeterminate*; analyst state lives in a separate append-only, hash-chained file; history is a directory of assessments, not a database. The v0.3 detection tool over baseline diffs (`shared.reporting.detect`) is kept unchanged beside it.

### Decisions (assessment platform)

- **A central document derived from, not replacing, the collector reports.** Old tooling (`diff`, `detect`, `verify`) keeps working on report files; an assessment projects back onto the report shape (`assessment_to_report`) so the inventory engine can be reused unchanged.
- **Separate schema version line.** The audit-report schema stays at 0.2.0 (no collector change was needed for the platform); assessment, snapshot-comparison, manifest, module and profile documents start at 0.1.0 (`shared/engine/__init__.py`). Alternative considered: bump everything to 0.3.0. Rejected: it would force a version change onto every golden fixture without any change in meaning.
- **Identity per check per host, evidence-level detail inside.** Alternative considered: one finding per evidence item. Rejected: it would contradict the collectors' own findings and make counts depend on list truncation (`only the first N are listed`); evidence ids remain available for item-level tracking.
- **Coverage before conclusions.** The comparison reports `indeterminate` rather than guessing when a module did not run cleanly, extending the principle already used for inventory.
- **No parallelism, no resume.** Chosen for availability and simplicity; revisit with evidence.

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

## Hardening decisions (audit remediation)

- **Test hooks are explicit.** Fixture hooks need `BO_TEST_MODE=1`; otherwise they are removed/ignored and the run records it. Alternative considered: refuse to run. Rejected: a failing audit is a denial of service for whoever can set one variable, while an audit that proceeds on the real host and says why is both safe and useful.
- **`PATH` is sanitised, not replaced.** Replacing it would break hosts whose tools live in non-standard but legitimate root-owned directories (Nix, Homebrew-style prefixes). Entries that are relative, missing, non-root-owned or group/other-writable are dropped and listed.
- **Integrity is a manifest plus an off-host digest.** Signing would need keys on the audited host; hashes recorded elsewhere give the same guarantee against tampering after the run without new dependencies.
- **Escapes instead of substitution.** Lossy `?` replacement made different names equal; byte/UTF-16 escapes keep them apart at the cost of readability for non-ASCII names.
- **Coarse process keys are kept.** Per-instance process comparison would make every restart an alert; the trade-off is documented in [detection-rules.md](detection-rules.md#limitations).
- **Attributes one collector version lacks are skipped, not "unknown".** `null` means a permission gap (indeterminate); an attribute absent from a whole report means a collector difference and is reported once (`ATTRIBUTES_NOT_COMPARED`).
- **Kernel modules are never loaded for inspection.** The Linux firewall check runs `iptables -S` / `nft` only when their kernel module is already loaded, because running them otherwise makes the kernel load it (a state change).

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
