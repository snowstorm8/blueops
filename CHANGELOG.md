# Changelog

All notable changes are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed (unverified-input policy, case provenance, versions)
- One policy for every manifest-less input: verified is accepted, unverified is refused unless `--allow-unverified`, invalid is refused always. **Behaviour change:** raw telemetry streams, bare `telemetry.json`, stored detection-results files and the telemetry baseline are now refused by default (`telemetry import|show|query|tree|compare|report|hunt`, `detect run|show|export|report` gained `--allow-unverified`). A lone file inside a directory whose manifest matches is verified by that manifest. Telemetry stores keep no opt-out.
- Case store: every observation records whether its source results were `verified`, `unverified` or `unknown`; a case is verified only if all of them were (shown by `case show`, `case list --json`, and the detection reports). Older case files read as `unknown`.
- Schema versions: `telemetry` and `telemetry-comparison` 1.0.0 -> 1.1.0; `audit-report` 0.2.0 -> 0.3.0 (`READABLE_REPORT_VERSIONS` gains `0.3`; engine reports are emitted as 0.3.0, collectors and the legacy documents stay 0.2.0).

### Added (input provenance)
- Every derived output records which inputs it came from and whether each was verified: `inputs_verified` (true only if all were) and `inputs` (`role`, `path`, `verified`, `reason`, `via`) on assessments, audit reports, snapshot comparisons, detection results, detection comparisons, telemetry documents and telemetry comparisons. Status is per input and survives conversion, saving and later verified loads; an input of unknown provenance counts as unverified. Markdown, HTML and text reports warn at the top when any input is unverified and list each input; JSONL and CSV detection exports carry `inputs_verified` on every row (CSV: a new trailing column).
- `engine run --allow-unverified` for `--compare` and `--history` inputs (default stays fail-closed). The record and its rendering live in `shared/engine/provenance.py` and `shared/reporting/render_provenance.py`.
- `docs/adr/0001-detection-engine-coexistence.md`: the legacy detection tool and the detection engine coexist; no replacement before rule parity, an engine allowlist and documented output semantics.

### Changed (input provenance)
- Verification has three outcomes. `--allow-unverified` / `verify=False` now *tries* verification and records the result: inputs that verify are *verified*; inputs with nothing to verify against (no manifest, a bare file) are accepted as *unverified* with the reason; inputs whose manifest exists but fails (mismatch, malformed, missing or unlisted file, symlink, wrong digest) are *invalid* and refused even with the flag. Before this change `verify=False` skipped the check, so a tampered directory loaded silently.
- A stored detection-results file read by `detect show|export|report` and `telemetry report` is now verified through its directory's manifest when present (invalid if it fails) and otherwise refused unless `--allow-unverified` (then recorded as unverified); what the file claims about its own inputs is ignored. `telemetry query|compare|tree|import` outputs now carry or print the provenance of the store they read.
- A stored comparison JSON passed to `--compare` is a bare file and now needs `--allow-unverified` (it could never be verified; previously it was read without any check).
- Schemas gain the optional `inputs_verified`, `inputs` and `inputs_omitted` properties without a version bump (additive, optional). Consumers that validate these documents against an older copy of the strict (`additionalProperties: false`) schemas will reject documents that carry the fields; update the schema copy first.
- Documentation of input verification, `--allow-unverified`, manifest limits, the TOCTOU window, plugin trust limits, environment sanitization and the plugin environment change is now identical in `security-model.md`, `assessment-engine.md`, `telemetry.md` and `plugins.md`.
- **Breaking (plugins):** plugins and `telemetry collect` no longer inherit the caller's environment; variables a plugin needs must be named `BLUEOPS_*` (see `docs/plugins.md`).

### Fixed (input provenance)
- Removed `PSMODULEPATH_OVERRIDE` from the Windows environment denylist: it is not a variable PowerShell defines.

### Fixed (Bash version requirement)
- `collect-telemetry.sh` crashed on Bash older than 4 with `declare: -A: invalid option` and exit 2 (the usage code). `linux/lib/bashcheck.sh` (parseable by Bash 3.2) is now sourced first and exits **3** (precondition failed) with a diagnostic naming the required and running versions. Tests: `tests/linux/bashcheck.bats`.
- Not changed: the audit orchestrator and `check-persistence.sh` still run on Bash 3.2 with the modules that use Bash 4 syntax (`auth`, `network`, `sysconfig`) failing as recorded module errors (exit 6); see docs/linux-audit.md.

### Security (runtime environment and plugin trust)
- Modules and `telemetry collect` no longer inherit a copy of the caller's environment. `BASH_ENV` (which runs a file before a collector's first line) and `LD_PRELOAD`/`DYLD_*`, interpreter hooks and secrets are not passed; `PATH` is rebuilt from trusted directories; names of withheld hook variables are reported on stderr. `RunContext(env=...)` stays explicit and trusted. New: `shared/engine/environment.py`. Plugins that relied on inherited variables must use `BLUEOPS_*`. The Windows rule is a small denylist and is unverified on Windows.
- Plugin trust now also requires root-or-operator ownership, covers the files the command line launches (not only the manifest), every ancestor directory, and is re-checked immediately before each launch. New: `shared/engine/trust.py`. An untrusted plugin file is a `failed` module, not a silent run.

### Added (detection migration analysis)
- `docs/detection-migration.md` and `tests/shared/test_detection_parity.py`: rule-by-rule comparison of the legacy diff detections (`BO-*`) with the detection engine (`DR-*`), measured by running both on the same synthetic scenarios. Result: 1 of 31 legacy rules has a predicate-equivalent, 19 partial, 11 none; the engine has no accepted-change allowlist. Recommendation: coexist, no replacement or compatibility layer yet. No behavior changes.

### Fixed (assessment integrity verification fails closed)
- `load_assessment` verified an assessment directory only `if` its `manifest.json` existed, so deleting the manifest turned a verified load into an unverified one, and `assessment.json`/`report.json` given as a file were never verified. Verification is now the default and fails closed: a missing, symlinked, malformed or non-matching manifest, unlisted files and symlinks are errors (exit 3); files are verified through their directory; a bare file with no manifest is refused. Telemetry store directories (`telemetry import`/`load_telemetry`) get the same rule.
- Added: `--allow-unverified` on `compare`, `report`, `detect run|compare|report`, `telemetry import|hunt` (library `verify=False`) as the explicit opt-in for trusted data such as synthetic fixtures; `expected_sha256` is now accepted by `load_assessment` and is an error combined with `verify=False` rather than silently ignored.
- Behaviour change: scripts that pass bare assessment/report files to these commands must add `--allow-unverified` or point at a verified directory.

### Added (endpoint telemetry and threat hunting, v0.6)
- `shared/telemetry/`: versioned telemetry schema (`telemetry.schema.json`, 1.0.0) with per-record provenance and coverage that distinguishes *observed absence* from *could not collect*; ingestion of collector streams, telemetry documents/stores and assessments with per-record validation (rejections and collection errors stay visible), deduplication, conflict reporting, derived authentication summaries and a manifest-verified store; coverage-aware snapshot comparison (`telemetry-comparison.schema.json`); constrained queries and process trees.
- `linux/telemetry/collect-telemetry.sh` and `windows/telemetry/Invoke-TelemetryCollection.ps1`: read-only collectors emitting a JSON Lines stream (processes with parentage, accounts and groups, sessions, services, scheduled tasks, sockets with owners, authentication and security events, security configuration, file hashes, persistence locations). No network access, no secrets collected.
- `python -m shared.engine telemetry collect|import|show|query|tree|compare|hunt|report`; `detect run --telemetry`.
- Detection engine: sources `telemetry` and `telemetry_changes`, coverage requirement `telemetry:<category>`, 24 hunting rules (`shared/rules/library/telemetry-hunting.json`, `DR-<LNX|WIN|ANY>-H<AREA>-NNN`) presented as *unusual / suspicious / lead* (never "confirmed"). Without telemetry they are `not_applicable`; with unavailable coverage, `indeterminate`.
- `detect run` takes the assessment as optional when `--telemetry` is given. The detection-results document gains, additively, the contributing type `telemetry` and an optional `telemetry` block (see docs/contracts.md).
- Tests: model/ingestion/comparison/hunting/CLI, the Linux collector against a synthetic root, against the real host and unprivileged, and (Pester) the PowerShell helpers and the collector on Windows. Docs: docs/telemetry.md, docs/implementation-report-v0.6.md.

### Fixed (CI portability and repository hygiene)
- Tests no longer create the deceptive `/tmp/...` fixture file on non-POSIX hosts (Windows rejects that name); the real-collector `run --detect` test runs only where bash exists, and a cross-platform plugin-based `run --detect` end-to-end test covers every platform.
- Generated bytecode (`examples/plugins/__pycache__/*.pyc`) is no longer tracked: `.gitignore` now ignores bytecode under `examples/` and `tests/fixtures/` after the `!examples/**` / `!tests/fixtures/**` negations that had re-included it; `tests/shared/test_repo_hygiene.py` guards against recurrence.

### Added (detection and correlation engine, v0.5)
- `shared/rules/`: rule engine over assessments. Rules are JSON packs (`detection-rule.schema.json`) with a condition language (exact, partial, regex, numeric, set, missing-value, boolean, `all`/`any`/`not`), clauses over findings, inventory, snapshot changes and history, correlation (`join`, `min_matches`, `distinct`, optional clauses, boolean `require`), explicit severity/confidence rules with stated reasons, per-rule coverage requirements, executable examples, versions and enable/disable. Malformed rules fail safely with path-qualified diagnostics.
- 29 rules (`shared/rules/library/`, [docs/detection-library.md](docs/detection-library.md)): Linux accounts, sshd, SUID, persistence, log tampering, core_pattern, package integrity, legacy services; Windows accounts, services, tasks, logging, credential protections, persistence; cross-platform exposure, privileged-group changes, correlations and snapshot/history rules.
- Detections (`detection-results.schema.json`): contributing findings and evidence, matched conditions, correlation reason, severity and confidence rationale, missing corroboration, benign causes, investigation steps, remediation, ATT&CK (`direct`/`possible` with explanation) and NIST references, `nature` and disclaimer. Indeterminate rules are listed instead of silently passing.
- History without a database (`--history DIR`, `--previous`), detections across snapshots (`detect compare`, `detection-comparison.schema.json`).
- Investigation workflow (`case list|show|status|note|link`, `--state-dir`): statuses, required notes for closing, analyst history, related detections, tamper-evident append-only `cases.jsonl`.
- CLI in `python -m shared.engine`: `rules list|validate|show|test|docs`, `detect run|compare|show|report|export`, `case ...`, `run --detect`; Detections section in the HTML and Markdown reports (filter, sort, status, evidence links); JSON/JSONL/CSV export (formula-injection safe).
- Tests: 458 new pytest cases (conditions, validation, library examples, engine, history/timeline, investigation, reports, CLI, synthetic hosts with golden files).
- `finding_coverage()` is now public in `shared.reporting.snapshot_compare`; HTML finding cards carry their `BOF-` id as an anchor. No existing flag, schema or output was changed.

### Added (assessment platform, v0.4)
- **Assessment engine** `python -m shared.engine` (`list`, `run`, `compare`, `report`, `validate`, `verify`): module registry with built-in collector modules and declarative `*.module.json` plugins, dependency planning, one process per module with hard time limits (process-group kill), strict output validation against the audit-report schema, profiles (`profiles/<platform>/*.json`: `default`, `quick`, `persistence-hunt`, Linux `full`), assessment directory with a SHA-256 manifest. Docs: `assessment-engine.md`, `plugins.md`.
- **Central findings and evidence** (`shared/findings/`): stable finding ids (`BOF-…`) and evidence ids (`EV-…`), deduplication, provenance back to the module report by digest, remediation priority P1-P4, MITRE ATT&CK and NIST SP 800-53 Rev. 5 references. Doc: `findings.md`.
- **Snapshot comparison**: new, resolved, persistent findings, severity changes, configuration changes (reusing the inventory engine) and coverage differences, with `indeterminate` instead of a guess when a module did not run cleanly; accepts assessments, run directories and older audit reports. Doc: `reporting.md`.
- **Reports**: Markdown and a self-contained, responsive HTML report (executive summary, metadata, host, severity distribution, findings breakdown with filters, evidence index, remediation priorities, historical comparison) with a pinned-hash Content-Security-Policy.
- `shared/reporting/schema_lite.py`: dependency-free JSON Schema validator for the schemas in this repository; unsupported keywords are refused, parity with `jsonschema` is tested.
- New schemas (version line 0.1.0): `assessment`, `snapshot-comparison`, `assessment-manifest`, `module-manifest`, `assessment-profile`. The audit-report schema is unchanged (0.2.0).
- **Linux modules** `auth` (login.defs defaults, password aging, group integrity, PAM password-quality and lockout: `ATH-*`) and `sysconfig` (temp-mount options, `core_pattern`/`suid_dumpable`, log-tampering indicators, logging pipeline: `CFG-*`). Fixture root gained `etc/login.defs` and two `/proc/sys` files so the new partitions are collectable.
- **Windows module** `eventlog` (`EVT-*`: Event Log service, log sizes and retention, disabled diagnostic channels; registry only). Written without a local PowerShell: **unverified until the Windows CI runner executes `tests/windows/EventLog.Tests.ps1`**.
- Example assessment and example plugin (`examples/`), CI smoke test for the engine.

### Changed (assessment platform)
- `audit-linux.sh --list-modules` now lists ten modules (`auth`, `sysconfig` added) and `Invoke-WindowsAudit.ps1 -ListModules` twelve (`eventlog` added); existing tests were updated for the new counts. A host whose `/etc/login.defs`, `kernel.core_pattern` or `fs.suid_dumpable` is unreadable now reports those new inventory partitions as `unavailable` (comparison treats that as a coverage gap, never as removal). Take a new baseline after upgrading.
- `pyproject.toml`: `E501` is ignored for `shared/reporting/render_html.py` only (inline HTML/CSS literals).
- `CLAUDE.md` layout table lists `shared/engine/` and `shared/findings/`.

### Security and integrity (audit remediation, P1-P3)
- **Test hooks need `BO_TEST_MODE=1`** on both platforms (`BO_ROOT`, `BO_FORCE_MISSING_TOOLS`, `BO_FIXTURE_DIR`, `BO_FORCE_MISSING`). Without it they are removed/ignored and the run records `TEST_HOOKS_IGNORED` (material, exit 6); reports made with them carry the new optional `host.test_mode` (report schema 0.2.0, additive). The comparison warns (`TEST_MODE`). Test harnesses (Bats helper, pytest, Pester) now set it explicitly.
- **Trusted `PATH` (Linux):** the system directories first; relative, missing, non-root-owned and group/other-writable entries are dropped and recorded (`PATH_SANITIZED`). **Windows:** `netstat.exe`, `schtasks.exe`, `auditpol.exe` and `net.exe` run from `System32` by full path.
- **Run manifest:** `manifest.json` (new `shared/schemas/run-manifest.schema.json` 0.1.0, example in `examples/`) beside every report with SHA-256 and size of each output file and of the collector scripts, owner-only; the collector prints its digest for off-host recording. New `python -m shared.reporting.verify RUN_DIR [--expect-sha256 DIGEST]`; `diff` and `detect` refuse a run directory that no longer matches its manifest.
- **Windows run directories are never reused** (numeric suffix like Linux) instead of silently overwriting earlier evidence.
- **Secret redaction (Linux)** now covers URL credentials, `Authorization` header values, `curl -u user:pass`, `sshpass -p` and mysql-style `-pSECRET`; Windows gained URL and `curl -u` parity. `NOPASSWD:`/`PASSWD:` sudoers tags are no longer mistaken for secrets (a rule used to read `NOPASSWD: <redacted>`).
- **Text encoding is injective:** non-ASCII bytes become `\u00XX` per byte (Linux) and `\uXXXX` per UTF-16 unit (Windows) instead of `?`, so different names no longer collide.
- **Process/persistence TSV row forgery fixed:** tabs, newlines and carriage returns in command lines, `comm` names, executable paths and file names can no longer add columns or forged records.
- **Strict JSON everywhere untrusted input is read** (`--from-diff`, `--accepted`, `--config`, manifests): size cap, duplicate keys, `NaN`/infinity and deep nesting are clean exit-3 errors (a nested file used to crash with a traceback); saved-diff keys over 1024 characters are rejected.
- **IPv6:** `/proc/net/tcp6` addresses decode to the compressed form `ss` prints (stable keys across tools); loopback is parsed (`::ffff:127.0.0.1` is loopback, `::1f00:1` and `127.evil` are not).

### Added (audit remediation, coverage)
- **Detections:** `BO-EXE-002` (attack patterns in the text of job/service/persistence commands), `BO-CFG-008` (sshd settings), `BO-CFG-009` (new kernel module), `BO-CFG-010` (Linux firewall opened); `BO-GRP-001` also sees primary-group members; `BO-CFG-002` covers `kptr_restrict`, `ptrace_scope`, `dmesg_restrict`, `suid_dumpable` and no longer lets `::restrictanonymous` match `::restrictanonymoussam`; `BO-CFG-005` covers loaded PAM modules; `BO-PER-002` states how many lines were added and removed; the same SSH key under several accounts is linked (`correlated`) instead of reported as unrelated detections. 31 rules.
- **Linux checks:** sudoers `#include`/`@include` targets (followed and flagged), `Defaults` and aliases (`USR-SUDO-004/005`); administrative primary groups (`USR-GROUP-003`); PAM `\` continuation lines and SHA-256 of every referenced PAM module; sshd effective settings (`NET-SSHD-001/002`); kernel hardening sysctls (`NET-SYSCTL-001`); host firewall state (`NET-FW-001/002`); loaded kernel modules with taint (`SYS-KMOD-001`); symlinked and dangling systemd units; `ld.so.conf` search paths (`PER-LDCONF-001`); `cron.allow/deny`, `at.allow/deny`; auditd rules (`PER-AUDITD-001`); line count and line fingerprints on persistence files; `--package-integrity` also supports `rpm -Va` and states the trust limit of both backends.
- Suspicious command patterns (`bo_suspicious_reasons`): `ncat --exec/--sh-exec`, `nc ... | sh`, `sh -i | nc`, `mkfifo` shells, `bash <(curl ...)`, perl/python socket and pty shells, `openssl s_client | sh`.
- Comparison: attributes present in only one report are skipped and reported once (`ATTRIBUTES_NOT_COMPARED`) instead of making every such record indeterminate.
- Tests: `tests/linux/hardening.bats`, `tests/linux/coverage-gaps.bats`, `tests/shared/test_remediation.py`, `test_schemas.py`, `test_windows_sources.py`, `tests/windows/Hardening.Tests.ps1`; manifest and rule/collector contract tests extended.
- `docs/audit-remediation.md`: finding-by-finding status, what was deliberately not changed and why, residual risks.

### Changed (audit remediation)
- A reverse-shell cron line is now `high` on its own (it was `medium`, with the audit finding promoted beside it).
- Collector upgrade: take a new baseline. Records gained attributes (`line_ids`, `primary_members`, ...), sudoers rule text is no longer redacted after `NOPASSWD:`, and `config:kmod:`, `config:sshd:`, `config:firewall:`, `config:pam-module:` records appear.
- The two permission tests that cannot work as uid 0 (`LC-03`, `LC-04`) are skipped when run as root.
- Documentation: security model (residual risks), exit-code precedence, deployment (verifying a run), architecture decisions.

### Fixed (detection correctness, audit P0-1..P0-4)
- `BO-PER-001` now matches the Linux collector's real SSH key records (`persist:ssh-authkey:<owner>:<id>`, `owner` attribute); a new `root` authorized key was reported only as a generic `BO-PER-002` at medium instead of critical. `BO-PER-002` still reports *changed* key records.
- A new process name on a high-port listener is detected (`BO-NET-003`; `BO-NET-002` when it is a netcat-style tool). Before, an `nc` listener on `0.0.0.0:44444` produced no detection and exit 0 whenever the baseline already had a listener above the ephemeral threshold on the same bind. The same name on another high port stays quiet (documented limit; use `fixed_ports`).
- New rule `BO-FND-001`: audit findings of `high`/`critical` severity that are new, escalated or gained evidence are detections unless an equally severe inventory detection already covers the same evidence; a less severe cover is linked. The diff already reported these but the rule layer ignored `findings`, so e.g. a reverse-shell cron job was only a medium `BO-SCH-001`. A malformed finding entry is a rule error (coverage incomplete); a non-list `findings.new`/`findings.changed` is rejected (exit 3).
- Linux collector emits `config:sysctl:kernel.randomize_va_space` (inventory only), so the ASLR branch of `BO-CFG-002` can fire on a real host; `BO-CFG-002` also reads the Windows `config:ip_forward` record (`enabled`).
- `tests/shared/test_rule_collector_contract.py` runs the real Linux collector and checks the PowerShell sources so rule keys and collector keys cannot drift apart; `tests/shared/test_detection_regressions.py` pins each reproduced failure with its negative cases.
- Test data: `tests/fixtures/baseline-e2e/linux/changed.json` `user:mallory` now carries the `/etc/passwd` evidence reference that real user records have.
- Detections schema, exit codes and the diff contract are unchanged; the rule count is now 27.

### Added (detection validation)
- `docs/detection-validation.md`: expected outcomes written before the runs, results, deviations, false positives, false negatives, platform coverage and limitations.
- `tests/shared/test_detection_validation_linux.py` (real audit over disposable fixture roots) and `tests/shared/test_detection_validation_windows.py` (PowerShell collector over mutated fixture copies; needs PowerShell), with a small shared helper `tests/shared/detection_validation.py`.
- The validation found the `BO-PER-001` key mismatch (LS-04) and recorded the Windows `ip_forward` gap (FN-3); both are fixed by the detection-correctness entry above (`docs/detection-validation.md` is updated accordingly).

### Added (detection rules, v0.3)
- `python -m shared.reporting.detect` (`shared/reporting/{detect,detection}.py`): offline, read-only, explainable detections over the baseline comparison. 26 rules (`BO-USR/GRP/PER/EXE/SCH/SVC/NET/CFG-nnn`) each carry a severity, rationale, supporting evidence, ATT&CK orientation and investigation steps, and are labelled `observed` (fact in the report) or `heuristic` (suspicion). Rules fire on changes only; matches on one record merge into one detection and detections sharing an artifact are linked; incomplete coverage yields exit 6, never a clean result.
- `shared/schemas/detections.schema.json` (`kind: "detections"`), `--from-diff`, `--min-severity`, `--list-rules`; reuses diff exit codes.
- `tests/shared/test_detection.py`: per-rule firing and false-positive scenarios, pinned Linux/Windows end-to-end results, remediation, coverage, determinism, malformed input and read-only/offline checks. CI smoke test for the CLI.
- `docs/detection-rules.md`: output model, rule catalogue, regression matrix, limitations.
- Accepted-change allowlist (`--accepted FILE`, `shared/reporting/accepted.py`, `examples/accepted-changes.example.json`): per-subject, rule-scoped, severity-capped (never critical), expiring entries with reason and approver. Matches move to `accepted[]` unchanged with an `acceptance` block; `allowlist` audits every entry (matched/unused/expired and why not applied). Malformed files exit 3.
- `unknown[]` on every detection: hash-only startup/sudoers/PAM records now state what the report cannot show (content, direction of the change).
- Remediation false positives removed: already-down security services, ASLR raised, a listener leaving a netcat-style tool (low), temporary paths already present before the change.
- `tests/shared/test_accepted.py`: remediation, hash-only and allowlist regression tests.

### Fixed (baseline comparison conclusions)
- A report whose `inventory` is present but not an object, whose `inventory.coverage`/`findings`/`errors` is not a list, or that holds a non-object finding or error is now rejected (exit 3) instead of being read as missing data; dropped errors could hide a failed module and report findings as resolved.
- Findings absent from a run are *unverified*, not resolved, after a new error that names no check, or a failure/partial run exit code the baseline did not have.
- A `complete` collection of users, groups, services or processes that is empty while the other side is not no longer yields mass removals or additions.
- Windows console helpers (`tasklist.exe`, `whoami.exe`, ...) from `System32` are transient by default; added to `transient_processes` in `shared/config/baseline-diff.default.json`.

### Added (listener comparison)
- `fixed_ports` option (config file) compares listeners on the listed ports exactly even in the ephemeral range, so a new stable high-port listener is no longer hidden by an existing process name.

### Added (baseline end-to-end regression tests)
- `tests/shared/test_baseline_e2e.py` and `tests/fixtures/baseline-e2e/`: sanitized synthetic Linux and Windows audit snapshots driven through the real `python -m shared.reporting.diff` CLI. They pin the behavior for identical snapshots, added/removed/modified records, transient processes and ephemeral ports, permission gaps and failed modules, malformed or incompatible input (exit 3), offline/read-only operation and deterministic output. No behavior change.
- `docs/baseline-diff.md`: expected-behavior matrix and newly documented limitations (trust in coverage statements, Windows transient helpers need configuration, high-port services are bucketed as ephemeral, non-object `inventory` is treated as absent).

### Added (baseline snapshots and change detection, schema 0.2.0)
- Offline comparison engine and CLI (`python -m shared.reporting.diff`, `shared/reporting/{inventory,baseline,baseline_render,diff}.py`): additions, removals and modifications of users, groups, services, processes, listeners, scheduled tasks, persistence and configuration, with observation timestamps, evidence and related-finding links; text and JSON (`shared/schemas/baseline-diff.schema.json`) output; exit codes 0/4/6/3/2/1. See `docs/baseline-diff.md`.
- Audit-report schema **0.2.0**: optional `inventory` (`coverage[]` + `records[]` with stable keys, compared `attrs`, `volatile` context and `evidence`). Additive: 0.1.0 reports remain valid and load (findings delta only, exit 6 with a `NO_INVENTORY` warning). `SCHEMA_VERSION` is `0.2.0`; `READABLE_REPORT_VERSIONS` lists the readable lines.
- Linux collectors emit inventory (users/groups/sudoers/SSH-key fingerprints, processes, listeners and network config, services, cron/persistence, PAM, SUID) with per-domain coverage (`bo_inv`, `bo_cov` in `linux/lib/common.sh`).
- Windows collectors emit inventory (users and groups by SID, services, processes, listeners, tasks, autoruns/persistence, security/firewall/network configuration) with coverage that degrades on errors, fallbacks and crashed or missing modules (`Add-BoInventory`, `Add-BoCoverage` in `windows/lib/Common.ps1`).
- Handling of transient PIDs, ephemeral ports (per-OS thresholds), transient helper processes, partial/degraded/unavailable coverage, privilege differences and duplicate keys; hardened report loader (size and nesting limits, duplicate keys, BOM, control characters).
- Tests: `tests/shared/test_baseline_diff.py` (synthetic and adversarial baselines), `test_baseline_cli.py` (golden files in `tests/fixtures/baseline/`, CLI, read-only/offline checks), `test_linux_baseline_e2e.py`, `tests/linux/inventory.bats`, `tests/windows/Inventory.Tests.ps1`; CI smoke step for the diff CLI.
- `shared/config/baseline-diff.default.json`: default comparison options.

### Changed
- Reports now declare `schema_version` `0.2.0` (Linux and Windows collectors); the example report was updated.

### Added
- Windows read-only audit v0.1 (`windows/audit/Invoke-WindowsAudit.ps1`, `windows/persistence/Find-Persistence.ps1`, `windows/lib/Common.ps1`): system, users, processes, network, services, scheduled tasks, autoruns, persistence, firewall, security configuration and filesystem modules emitting schema 0.1.0 reports. See `docs/windows-audit.md`.
- Pester suites, synthetic Windows host fixtures and a schema-conformance pytest; the CI PowerShell job now runs Pester under Windows PowerShell 5.1 and PowerShell 7.
- `audit-pam.sh` module (`PAM-*` findings): read-only PAM configuration review.
- `--package-integrity` option: opt-in Debian `dpkg --verify` checks (`FS-PKG-*`).
- `SVC-FAILED-002`: failed systemd socket units.
- `FS-PKG-004`: modified security-sensitive conffiles under `--package-integrity`.

### Fixed
- SUID/SGID inventory returned zero on real hosts: `/proc/mounts` was read with the wrong field separator, so no scan roots were found. Overlay filesystems are now scanned too.
- False positives: standard X11 `/tmp` socket paths, and the packaged `postgres` account's shell.

### Fixed
- Heuristic exceptions no longer hide real findings: `find -exec`, `cp`/`mv`/`tar` of `/tmp` paths, and a broad X11 exemption are no longer ignored; PAM bypasses via `success=done` and `pam_succeed_if` are detected.
- `PAM-MODULE-002` ignores `include`/`substack` lines and dash-prefixed optional modules; common Debian SUID helpers are recognized; `--package-integrity` requires root (`PKG_NEEDS_ROOT`).
- Recent-file scan is about 6x faster on large trees.

### Added (earlier in Unreleased)
- Linux read-only host audit (v0.1): `linux/audit/audit-linux.sh` unified entry point plus standalone modules `audit-system.sh`, `audit-users.sh`, `audit-processes.sh`, `audit-network.sh`, `audit-services.sh`, `audit-filesystem.sh`, and `linux/persistence/check-persistence.sh`; shared helpers in `linux/lib/common.sh`; human and JSON (schema 0.1.0) output; see `docs/linux-audit.md`.
- Bats tests with synthetic fixtures (`tests/linux`, `tests/fixtures/linux-*`) and a pytest schema-conformance test for the Linux reports.
- Initial repository scaffolding: directory layout, `CLAUDE.md`, documentation set.
- CI and lint workflows (ShellCheck, shfmt, PSScriptAnalyzer, Ruff, pytest, Bats, Pester), Dependabot config.
- Versioned JSON audit-report schema (v0.1.0), severity levels, and exit-code contract with tests.
