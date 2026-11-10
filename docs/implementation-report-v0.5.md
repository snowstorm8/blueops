# Implementation report: detection and correlation engine (v0.5)

Scope: a rule-based detection framework, a correlation engine, snapshot- and history-aware detections, an explainable detection output model, a rule library, an investigation workflow, CLI and report integration. This report says what was found, built, run and *not* run.

## 1. Investigation

| Finding | Consequence |
|---|---|
| PR #20 (the assessment platform, open as a draft) is the base: `shared/engine`, `shared/findings`, snapshot comparison, reports, 10 Linux and 12 Windows modules. This work is stacked on it (branch `feat/detection-engine`, PR base = PR #20's branch). | Reused: central findings and evidence ids, `compare_snapshots`, `finding_coverage` (made public), report renderers, manifest, CLI. |
| A *different* detection tool already exists: `shared.reporting.detect` (v0.3, 31 rules over **baseline diffs**, ids `BO-*`/`DET-*`). | Not touched. The new engine works on assessments (ids `DR-*`/`DT-*`); both exist side by side and the docs say so. Merging them is listed as future work. |
| PR #20's CI had failures I had not seen: Pester 253 passed / 2 failed (my own retention test, a real bug), the engine smoke test failed on an unprivileged runner (example plugin crashed on `/etc/sudoers.d`), and the `ubuntu-latest` Python 3.9 job cannot start (runner image Ubuntu 26.04 has no Python 3.9 for `setup-python`). | Fixed the first two on PR #20's branch (regression test added; the plugin fix verified here by running as an unprivileged user). The 3.9 job is an environment problem: not changed, needs a pinned runner image. |
| The collectors expose no Windows privilege assignments, no event-log content and no process-to-binary permissions. | No rule can claim those areas; the Windows rules use account state, services, tasks, security settings, logging configuration and persistence. Documented as a limitation. |
| Check ids guessed from memory were wrong (e.g. `PER-RC-002`). | A drift test now fails when a rule names a check id no collector emits. It caught four such mistakes in my first draft. |

## 2. What was built

| Area | Delivered | Where |
|---|---|---|
| Rule format and validation | JSON rule packs; schema + semantic validation with path-qualified diagnostics (unknown field with suggestion, bad operator, unknown clause, nested-quantifier regex, nature/shape consistency, missing coverage declarations, missing examples); invalid rules are excluded and reported, valid ones still run; versions; enable/disable and overrides; duplicate ids refused | `shared/rules/{model,validate,loader}.py`, `shared/schemas/detection-rule.schema.json` |
| Conditions | exact, partial, regex, numeric, set membership, missing-value, boolean, `all`/`any`/`not`; strict missing-value semantics; trace of the true leaves | `shared/rules/conditions.py` |
| Evaluation and correlation | clauses over findings, inventory, snapshot changes, snapshot facts; `join`, `min_matches`, `distinct`, optional clauses, boolean `require`; explicit `severity_rules` / `confidence_rules`; coverage requirements; indeterminate results; bounds | `shared/rules/{subjects,engine}.py` |
| History | directory-based history without a database; per-finding streaks and reappearance with unknown ≠ absent; value stability for config; detections across snapshots with `unverified` | `shared/rules/{history,timeline}.py`, `detection-comparison.schema.json` |
| Output | `detection-results` document with all requested fields plus `nature`, disclaimer, caveats, missing corroboration | `detection-results.schema.json` |
| Library | 29 rules (Linux 9, Windows 6, cross-platform 9, change/history 5), 119 executable examples | `shared/rules/library/`, `docs/detection-library.md` (generated) |
| Investigation | five statuses with checked transitions, required note for resolved/dismissed, notes, links, related detections, analyst history, append-only hash-chained `cases.jsonl` (0600/0700, locked) | `shared/rules/investigation.py` |
| CLI | `rules list/validate/show/test/docs`, `detect run/compare/show/report/export`, `case list/show/status/note/link`, `run --detect` | `shared/rules/cli.py`, mounted in `shared/engine/cli.py` |
| Reports | Detections section in HTML (overview, severity/confidence/nature/category distributions, affected host, filter + sort, expandable cards with explanations, evidence and finding links, investigation status, recommended actions) and Markdown; standalone detection report; JSON/JSONL/CSV export (formula-safe) | `shared/reporting/render_detections.py`, `render_html.py`, `render_markdown.py`, `export.py` |
| Docs | `detection-engine.md` (architecture, rule authoring, correlation, coverage, history, workflow, commands, limits), `detection-library.md`; updates to architecture, contracts, security model, development, roadmap, README, CHANGELOG, CLAUDE.md | `docs/` |

ATT&CK handling: every mapping has `relationship` (`direct`/`possible`) and an explanation; all 29 rules use `possible` for indicators (the data shows configuration, never an adversary action), a test enforces that only observations may even claim `direct`, and validation forbids a hypothesis from claiming it. NIST SP 800-53 Rev. 5 controls are listed by id with titles.

## 3. Test results

Run in this session on Linux, uid 0, Python 3.13 (new tests also on Python 3.9.25).

| Suite | Result |
|---|---|
| `scripts/development/check.sh` (before the rebase onto the CI fixes) | exit 0: ShellCheck, shfmt, ruff, pytest **1442 passed, 17 skipped** (PR #20 base: 978 / 17), Bats 221 ok / 0 failed; `pwsh` SKIPPED |
| pytest after the rebase onto the CI fixes | **1443 passed, 17 skipped** (the 17 are the same PowerShell/Windows/uid-0 skips as before) |
| Detection tests only, Python 3.9.25 | 458 passed |
| Mutation spot-checks of the rule tests | 4 deliberate engine/condition/store breakages (missing-value semantics, count-based severity elevation, ignoring coverage gaps, skipping the hash-chain check) each made the suite fail; code restored |
| Pester / PSScriptAnalyzer | **not run locally** (no PowerShell); CI ran Pester on PR #20 (253 passed, 2 failed before the fix) |

New tests: `test_rules_conditions` (108), `_validation` (50), `_library` (182: one test per embedded example, plus drift, honesty and documentation-sync checks), `_engine` (32), `_history` (13 + timeline), `_investigation` (26), `_reports` (10), `_cli` (25), `_hosts` (12: clean and compromised synthetic Linux/Windows hosts, golden result files, stored real-collector output, existing Windows/Linux report fixtures including module-failed and unprivileged). No existing test was changed or weakened; the only edits to existing files are additive (HTML cards gained an `id` anchor; two optional parameters on the renderers; `finding_coverage`).

### 3.1 Manual check

HTML report with detections opened in headless Chromium: no console or CSP errors, severity/text filters and sort work, expand-all works, no horizontal overflow at 1200 px and 390 px; screenshots inspected. Not part of the automated suite.

## 4. Limitations and what was not done

- **No PowerShell run locally.** Rules read assessment *documents*, so nothing in the detection engine depends on PowerShell, but the Windows collectors that feed the Windows rules were exercised only through synthetic documents here (the Windows hosts in the tests are hand-built specs, not real collector output). Real Windows output is covered only by the older `baseline-e2e` fixtures.
- Rules were validated against **synthetic** data and stored output from the fixture Linux host. No real-world false-positive rate is known; each rule lists benign causes and the tests include false-positive guards, which is not the same as field validation.
- No privilege-assignment or event-log-content rules (no data); no multi-host correlation; no allowlist / accepted-change mechanism for the new engine (the v0.3 tool has one); the v0.3 rules are not merged in.
- Group-membership rule reports that membership changed, without judging who was added.
- `evidence.paths` joins are textual; regex safety is a mitigation; the case file's hash chain does not protect its last line or a fully rewritten file; no concurrent-writer stress test beyond the lock-contention test.
- Rule library is JSON authored by hand (the generator used to draft it is not part of the repo); there is no rule-authoring linter beyond validation.
- CI: the `ubuntu-latest` Python 3.9 job fails for an environment reason independent of this work.

## 5. Recommended next steps

1. Re-run CI on both PRs; confirm the Pester `eventlog` fix; pin the Python-matrix runner image.
2. Run the engine against real hosts (a lab Linux and Windows VM) to measure false positives and tune rule confidence; feed findings back into `false_positives` and examples.
3. Collect Windows privilege assignments (`secedit`) and relevant event IDs, then add the rules the data would support.
4. Merge the v0.3 baseline-diff rules and allowlists into the engine (one rule format, one output).
5. Fleet view: multi-host merge and cross-host correlation.
6. Rule-pack signing and a rule-quality linter.
