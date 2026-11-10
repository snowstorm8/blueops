# Implementation report: endpoint telemetry and threat hunting (v0.6)

Scope: a normalized telemetry model, Linux and Windows collectors, an ingestion pipeline, a query layer, snapshot comparison, and hunting rules integrated into the existing detection engine, case workflow and reports. This report says what was built, what was run, and what was not. Reference documentation is in [telemetry.md](telemetry.md); this file deliberately contains no CI results (they belong to a commit and are on the pull request).

## 1. Starting point

| Finding | Consequence |
|---|---|
| PR #20 (assessment platform) and PR #21 (detection engine, based on #20) were open drafts; `main` contained neither. | This work is stacked on `feat/detection-engine` (branch `feat/telemetry-hunting`); the dependencies are preserved, nothing was rebased or merged. |
| The assessment inventory already carries processes, users, groups, services, listeners, scheduled tasks, persistence and configuration. | An adapter re-expresses it as telemetry; nothing is collected twice. Telemetry adds what the inventory lacks: process parentage and command lines per instance, established connections with owners, authentication and security *events*, integrity hashes, event-time semantics. |
| The detection engine already has a condition language, explanations, coverage handling, ids, cases and reports. | Hunting is two new sources in that engine, not a second engine. |
| Collector targets may not have Python (project rule). | Collectors are Bash/PowerShell emitting JSON Lines; Python validates and analyzes on the analyst machine. |
| Existing static guards (`test_windows_sources.py`) apply to every `windows/**/*.ps1`. | They caught two violations in the first Windows collector draft (a PATH-resolved `netstat.exe`; `Invoke-CimMethod`); both were fixed in the collector, the guards were not touched. |

## 2. What was built

| Area | Delivered | Where |
|---|---|---|
| Schema | `telemetry` 1.0.0 and `telemetry-comparison` 1.0.0; provenance on every record; coverage with `complete/partial/unavailable/not_applicable` | `shared/schemas/` |
| Model | vocabulary, derived record ids, strict per-record normalization (rejections with reasons), zone-less timestamps refused | `shared/telemetry/model.py` |
| Ingestion | stream/document/store/assessment readers, dedup with occurrence counts, conflict reporting, coverage merge rules, truncation detection, derived auth summaries, verified `0700` store with raw sources | `ingest.py`, `derive.py`, `adapter.py` |
| Comparison | coverage-aware added/removed/changed, events never "removed", volatile attributes ignored | `compare.py` |
| Query | JSON/flag syntax over the rule condition language, field catalog, process tree | `query.py` |
| Hunting | 24 rules, sources `telemetry`/`telemetry_changes`, `telemetry:<category>` coverage, executable examples, `not_applicable`/`indeterminate` semantics | `shared/rules/{subjects,engine,telemetry_subjects}.py`, `library/telemetry-hunting.json` |
| Collectors | Linux (Bash) and Windows (PowerShell 5.1/7) | `linux/telemetry/`, `windows/telemetry/`, `windows/lib/Telemetry.ps1` |
| CLI | `telemetry collect|import|show|query|tree|compare|hunt|report`; `detect run --telemetry` | `shared/telemetry/cli.py`, `shared/rules/cli.py` |
| Reports | Markdown and CSP-pinned HTML with coverage, problems and suspicious/unusual/lead groups | `render.py` |

Modified existing behavior (all additive): detection-results gained the contributing type `telemetry` and an optional `telemetry` block; the rule schema gained two sources, a coverage kind and example keys; `detect run`'s assessment argument became optional (still a usage error, exit 2, when neither assessment nor telemetry is given); `RuleSet.only()`. The schema line (0.1.0) was **not** bumped because it is shared by four documents; this is a deliberate deviation from "schema changes follow semver" and is recorded in `contracts.md`. The golden detection files changed only by the 24 new `not_applicable` rule results, the new pack entry and the rule counts.

## 3. Verification: what was run

Run in the authoring environment (Linux, uid 0, Python 3.13.18; Python 3.9.25 and 3.12.13 for the full pytest suite):

| Check | Result |
|---|---|
| `scripts/development/check.sh` (ShellCheck, shfmt, ruff check/format, pytest, Bats) | exit 0; pytest 1733 passed / 18 skipped; Bats 228 ok / 0 not ok; `pwsh` **skipped (not installed)** |
| pytest on Python 3.9.25 and on 3.12.13 | 1733 passed / 18 skipped on each |
| Linux collector as root against a synthetic root; against the real host as root; unprivileged (`setpriv` to uid 65534, directly and through the unprivileged-gap test) | passed (real-host checks assert invariants, not host contents) |
| Windows-shaped synthetic streams through ingestion and the hunting rules | passed on Linux |
| Mutation spot-checks | not repeated for this feature; the hunting rules were instead checked with benign-host false-positive guards and per-rule negative examples |

The 18 skips are the Windows-host and PowerShell tests. **Nothing PowerShell was executed in the authoring environment**: an attempt to install PowerShell for local verification was declined by the sandbox and not worked around. Consequently:

* `windows/telemetry/Invoke-TelemetryCollection.ps1`, `windows/lib/Telemetry.ps1` and `tests/windows/Telemetry.Tests.ps1` were checked only by static guards (`test_windows_sources.py`), a bracket-balance scan, and ASCII-only checks. Their first real execution is the Windows CI jobs (Pester on Windows PowerShell 5.1 and 7; the live-collector pytest on Windows). Treat the Windows collector as **unverified until those jobs have passed**.
* PSScriptAnalyzer was not run locally.

Test files added: `test_telemetry_core.py`, `_compare.py`, `_hunt.py`, `_cli.py`, `_linux.py`, `_windows.py`, `_live.py`, `tests/linux/telemetry.bats`, `tests/windows/Telemetry.Tests.ps1`, plus the 24 rules' 100+ embedded examples (run by the existing library tests). No existing test was weakened; where a new assertion initially contradicted behavior I had implemented (for example the exit code of `--fail-on critical` when rules were indeterminate), the test was corrected to the documented contract, not loosened.

## 4. Limitations

* **Windows collector unverified locally** (above). Specific unknowns: behavior under constrained language mode, on Server Core, on non-English Windows for the `netstat` fallback, and the cost of `Win32_Process`/event queries on busy hosts. Process owners need elevation; the Security log needs elevation.
* **Snapshots, not streams.** Collection is point in time. Events are bounded by `--since-hours` and `--max-events`; oldest events beyond the cap are not read (reported as `EVENT_LIMIT`).
* **Linux**: service *runtime state* is not collected (unit definitions only); traditional syslog lines have no usable time and are kept without one; the window filter compares the log's wall-clock text with UTC (up to the zone offset of error); other users' socket owners and the journal need root; auditd is optional; SELinux/AppArmor and sysctl coverage is a selected list.
* **Windows**: service/batch logons and machine accounts are not recorded; per-user startup folders, domain accounts and PowerShell script-block text are not collected; unresolved member SIDs leave the user unknown (and the account-then-group correlation cannot fire).
* **No integrity of running images** (no hashing or signature checks of process executables), no memory or packet analysis, no multi-host correlation, no allowlist for hunting rules.
* **A compromised host can lie to its collector**; telemetry is evidence of what the host reported.
* **Rule quality**: rules were validated on synthetic data only. No real-world false-positive rate is known; each rule lists benign causes and has negative examples, which is not field validation. Thresholds (10 failures / 3 accounts; 5 failures then success) are judgment calls.
* Host identity is hostname plus OS family (shared with findings): two hosts with the same name are indistinguishable.
* Schema line not bumped for the additive detection-results/rule-schema changes (above).
* `detect run --telemetry-baseline` without `--telemetry` is rejected (exit 3), but an assessment-only `detect run` with `--telemetry` of another host is also rejected (exit 3) rather than evaluated.

## 5. Suggested next phase

1. Read the Windows CI results; fix whatever the first real PowerShell run exposes; add Pester tests for the sections that only run live.
2. Lab validation on real Linux and Windows hosts (one benign, one with staged activity) to measure false positives and tune thresholds and confidence.
3. Process-image integrity (hash/signature of running executables) and Linux runtime service state.
4. Optional richer sources: Sysmon/ETW and auditd rule packs as additional `eventlog`/`file` sources behind the same schema.
5. Allowlists/accepted changes for hunting rules, and multi-host correlation once the fleet merge exists.
