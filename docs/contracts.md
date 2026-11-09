# Shared design contracts

These contracts are what keep Bash, PowerShell, and Python components interchangeable. Machine-checked by `tests/shared/test_contracts.py`.

## Output conventions

- Human-readable text goes to stdout by default; when `--json`/`-Json` is set, JSON goes to stdout (or `--output-dir`) and all human text/logs go to stderr.
- Timestamps: ISO 8601 UTC with `Z` (`2026-01-31T14:05:09Z`); filenames use `YYYYMMDDTHHMMSSZ`.
- Run directory layout: `<output-dir>/blueops-run-<YYYYMMDDTHHMMSSZ>-<tool>/` containing `report.json`, `run.log`, optional `evidence/` (+ `manifest.json` with SHA-256 hashes) and `rollback/`.
- Standard flags: `--help`, `--version`, `--output-dir`, `--json`, `--quiet`, `--verbose`, `--dry-run`, `--yes`, `--no-color` (PowerShell: PascalCase equivalents).
- Secrets are never written to reports or logs (command lines are redacted for the forms listed in [security-model.md](security-model.md)).
- `manifest.json` (`shared/schemas/run-manifest.schema.json`, 0.1.0) lists the SHA-256 and size of every file in a run directory and of the collector scripts; it is written beside `report.json` by both platforms with owner-only permissions and its digest is printed to stderr for off-host recording. Verification: `python -m shared.reporting.verify RUN_DIR [--expect-sha256 DIGEST]`.
- The host block may carry `test_mode: true` (only when fixture hooks were active under `BO_TEST_MODE=1`); comparison tools warn about such reports (`TEST_MODE`).

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| 0 | OK | Completed; nothing to report (or dry-run completed) |
| 1 | ERROR | Unexpected error |
| 2 | USAGE | Invalid arguments |
| 3 | PRECONDITION | Missing privilege, unsupported OS, required tool absent |
| 4 | FINDINGS | Run completed and findings at/above the threshold exist |
| 5 | ABORTED | Confirmation declined or non-interactive without `--yes` |
| 6 | PARTIAL | Run completed with some checks/steps failed (see `errors[]`) |

Defined in `shared/reporting/contracts.py`; the report schema's `run.exit_code` range (0-6) is tested against it.

**Precedence (collectors and the Python tools).** `4` wins over `6`: a run that has findings at or above the threshold exits 4 even when it also has coverage gaps. The gaps are never hidden, they are in `errors[]` (collectors) and in `coverage` / `domains` (diff, detect), and a `4` run's absence of further findings must not be read as completeness. `6` is returned only when nothing reached the threshold and a material gap exists, so `0` always means "nothing found *and* nothing material missing". `5` (declined confirmation) and `3` (precondition) end a run before any of this applies. This precedence is deliberate and unchanged: changing it would break callers that gate on `4`.

## Severity classification

| Severity | Use for |
|---|---|
| `critical` | Active compromise indicators or exposure enabling immediate takeover (e.g. confirmed backdoor, unauthenticated remote admin) |
| `high` | Likely compromise or serious misconfiguration (e.g. unknown privileged account, suspicious persistence) |
| `medium` | Weakness materially increasing risk (e.g. weak service config, unexpected listener) |
| `low` | Minor hardening gap or deviation from baseline |
| `info` | Context, inventory, or coverage notes; no action required |

Findings may also carry `confidence` (`low|medium|high`) to separate how bad from how sure. Severity is ordered `info < low < medium < high < critical`.

## Audit-report schema

- File: `shared/schemas/audit-report.schema.json` (JSON Schema draft 2020-12). Example: `examples/audit-report.example.json`.
- Top level: `schema_version`, `tool`, `run`, `host`, `findings[]`, `errors[]` (optional), `inventory` (optional, 0.2.0+), `summary`.
- Finding IDs are stable, `<AREA>-<TOPIC>-<NNN>` (e.g. `PER-CRON-001`); never reuse an ID for a different check.
- Coverage gaps (unreadable paths, missing tools) go in `errors[]` and should yield exit code 6 when material.

### Versioning

Semantic versioning on `schema_version`.

- **Current: `0.2.0` (pre-stable).** 0.2.0 only adds the optional `inventory` object (structured records plus per-domain coverage; see [baseline-diff.md](baseline-diff.md)); every valid 0.1.0 report is still valid. Earlier: `0.1.0`. No producer or consumer exists yet, so the shape is unproven. Per SemVer, `0.y.z` signals that any minor bump may be breaking; this lets the schema change while the first real audit tools are built, without burning a `2.0.0`. The schema accepts `0.x.y`.
- **`1.0.0`** is declared once at least one Linux and one Windows tool emit conforming reports and the shape has survived real use. From then on: patch = clarifications; minor = backward-compatible additions; major = breaking changes (schema `$id` and filename version bump; consumers must check the major).
- During `0.x`, every change is recorded in `CHANGELOG.md` and the example/fixtures are updated in the same commit.

## Inventory and baseline-diff contracts (0.2.0)

- `inventory = { coverage: [{domain, scope?, status, reason?}], records: [{domain, scope?, key, attrs, volatile?, evidence?}] }`. Domains: `users groups services processes listeners scheduled_tasks persistence config` (`INVENTORY_DOMAINS` in `shared/reporting/contracts.py`); coverage statuses `complete degraded partial unavailable` (`COVERAGE_STATUSES`).
- `key` is a stable identifier and must not contain PIDs, timestamps or free text; `attrs` are compared (null = unknown, arrays = sets); `volatile` is shown but never compared. Same concept = same key convention on both platforms (e.g. `listener:<proto>/<bind>/<port>`).
- The comparison output is `shared/schemas/baseline-diff.schema.json` (`kind: "baseline-diff"`); exit codes for `python -m shared.reporting.diff` are listed in [baseline-diff.md](baseline-diff.md#exit-codes) and reuse the table above (0, 4, 6, 3, 2, 1).
- Compatibility: producers may add record keys and attributes in minor releases; renaming a key or changing an attribute's meaning is a breaking change (CHANGELOG entry and deprecation period).
- Detections (`python -m shared.reporting.detect`) are described by `shared/schemas/detections.schema.json` (`kind: "detections"`, same `schema_version` line as the diff). Exit codes reuse the table above (0, 4, 6, 3, 2, 1); see [detection-rules.md](detection-rules.md#exit-codes). Rule ids (`BO-<AREA>-NNN`) and detection ids (`DET-<hash>`) are stable and never reused.
## Telemetry documents (1.1.0)

Independent version line (`TELEMETRY_SCHEMA_VERSION`, `shared/telemetry/model.py`), stable `1.x`; **1.1.0** adds the optional `inputs_verified` / `inputs` / `inputs_omitted` provenance fields (a minor, additive change: 1.0.0 documents stay valid and readable, the loader checks the major only, and a 1.0 consumer that ignores unknown fields is unaffected; the JSON Lines *stream* header stays `1.0.0`): `telemetry` (`telemetry.schema.json`) and `telemetry-comparison` (`telemetry-comparison.schema.json`); collectors emit a JSON Lines stream (`header`, `coverage`, `record`, `error`, `end`) described in [telemetry.md](telemetry.md). Record ids `TEL-<16 hex>` are derived from (host id, category, key); changing how a collector builds a `key` changes ids and is a breaking change. Coverage statuses: `complete partial unavailable not_applicable`; `unavailable` never means "nothing there". `telemetry hunt` exits 0 / 4 / 6 / 3 / 2 like `detect run`; `telemetry compare` exits 0 (no differences), 4 (differences), 6 (only indeterminate categories), 3, 2. The detection-results document gained, additively and without a version bump (the rule-pack line is shared by four documents), the contributing type `telemetry` (with `category`) and an optional `telemetry` block; the rule schema gained the sources `telemetry`/`telemetry_changes`, the coverage requirement `telemetry:<category>[/<scope>]` and the example keys `telemetry`/`previous_telemetry`.

## Assessment-platform documents (0.1.0)

Independent version line (`ASSESSMENT_SCHEMA_VERSION`, `shared/engine/__init__.py`); same SemVer rules, `0.y.z` = pre-stable. All are validated at run time by `shared/reporting/schema_lite.py`.

| Document | Schema | Produced by |
|---|---|---|
| `assessment` | `assessment.schema.json` | `python -m shared.engine run` |
| `snapshot-comparison` | `snapshot-comparison.schema.json` | `python -m shared.engine compare` / `run --compare` |
| `assessment-manifest` | `assessment-manifest.schema.json` | `run` (verified by `verify`) |
| `module` (plugin manifest) | `module-manifest.schema.json` | plugin authors |
| `profile` | `assessment-profile.schema.json` | `profiles/<platform>/*.json` |

Detection documents (same 0.1.0 line, `RULES_SCHEMA_VERSION` in `shared/rules/__init__.py`): `rule-pack` (`detection-rule.schema.json`), `detection-results` (`detection-results.schema.json`), `detection-comparison` (`detection-comparison.schema.json`); the case store (`cases.jsonl`) is JSON Lines with `seq`, `prev` (SHA-256 of the previous line), `ts`, `actor`, `action`, `detection`, `data`. Rule ids `DR-<LNX|WIN|ANY>-<AREA>-<NNN>` and detection ids `DT-<16 hex>` are stable and never reused; a rule's meaning changes only with a version bump; `nature` is one of `observation indicator correlated hypothesis`; ATT&CK `relationship` is `direct` or `possible`; case statuses are `new acknowledged investigating resolved dismissed`. `python -m shared.engine detect run` exits 0 / 4 / 6 / 3 / 2 as described in [detection-engine.md](detection-engine.md#commands).

Contracts: a finding's `category` is part of its identity, so renaming a category (or moving a check to another one) changes every finding id derived from it and is a breaking change; finding ids `BOF-<16 hex>` and evidence ids `EV-<16 hex>` are derived as described in [findings.md](findings.md) and never change meaning; module ids are `<platform>.<name>` and, once published, are not renamed without a deprecation period; module statuses are `ok partial failed timeout invalid_output skipped`; remediation priorities are `P1`..`P4`. The report schema is unchanged by the platform. Exit codes of the new commands reuse the table above ([assessment-engine.md](assessment-engine.md#exit-codes)).

- Tested by `tests/shared/test_contracts.py`, `tests/shared/test_baseline_diff.py`, `tests/shared/test_detection.py` and the golden files in `tests/fixtures/baseline/`.

## Provenance fields and versions

`inputs_verified`, `inputs` and `inputs_omitted` are optional additions (see [security-model.md](security-model.md)). Version lines that moved with them: `telemetry` and `telemetry-comparison` **1.0.0 -> 1.1.0**; `audit-report` **0.2.0 -> 0.3.0** (the schema accepts any `0.x`; `READABLE_REPORT_VERSIONS` now lists `0.1`, `0.2`, `0.3`, so reports from every earlier line are still read, and the engine emits `0.3.0` only from `assessment_to_report`). The collectors, `baseline-diff` and `detections` stay on `0.2.0` because their output contract is unchanged; the `0.2.0` reports collectors emit validate against the `0.3.0` schema. Migration impact: a tool built before this change refuses a `0.3.x` report (unknown minor, exit 3); produce reports with the matching tool or compare through the engine. The `0.1.0` lines of `assessment`, `snapshot-comparison`, `detection-results` and `detection-comparison` were not bumped: they are unreleased (PRs #20-#22) and carry the fields from their first version.
