# Shared design contracts

These contracts are what keep Bash, PowerShell, and Python components interchangeable. Machine-checked by `tests/shared/test_contracts.py`.

## Output conventions

- Human-readable text goes to stdout by default; when `--json`/`-Json` is set, JSON goes to stdout (or `--output-dir`) and all human text/logs go to stderr.
- Timestamps: ISO 8601 UTC with `Z` (`2026-01-31T14:05:09Z`); filenames use `YYYYMMDDTHHMMSSZ`.
- Run directory layout: `<output-dir>/blueops-run-<YYYYMMDDTHHMMSSZ>-<tool>/` containing `report.json`, `run.log`, optional `evidence/` (+ `manifest.json` with SHA-256 hashes) and `rollback/`.
- Standard flags: `--help`, `--version`, `--output-dir`, `--json`, `--quiet`, `--verbose`, `--dry-run`, `--yes`, `--no-color` (PowerShell: PascalCase equivalents).
- Secrets are never written to reports or logs.

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
- Tested by `tests/shared/test_contracts.py`, `tests/shared/test_baseline_diff.py` and the golden files in `tests/fixtures/baseline/`.
