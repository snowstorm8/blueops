# Baseline end-to-end snapshots

Sanitized, synthetic audit reports (schema 0.2.0) used by `tests/shared/test_baseline_e2e.py`. Hostnames are `web01.example.test` and `WIN-SRV01`; there are no real addresses, keys, hashes of real files or accounts. Edit them by hand and keep them readable; the tests validate them against `shared/schemas/audit-report.schema.json` and scan them for anything that looks like a secret or a non-reserved address.

| Path | Contents |
|---|---|
| `{linux,windows}/baseline.json` | known-good elevated run, every domain `complete` |
| `{linux,windows}/identical.json` | same inventory; only volatile data (PIDs, an ephemeral port) differs. The Windows copy also changes key case, set order and dynamic RPC ports |
| `{linux,windows}/changed.json` | added, removed and modified records in every domain, plus new and changed findings |
| `{linux,windows}/churn.json` | new PIDs, helper processes and moving or multiplying ephemeral ports; nothing else |
| `{linux,windows}/unprivileged.json` | non-elevated run: partial, degraded and unavailable partitions, unreadable values, no findings |
| `{linux,windows}/module-failed.json` | a crashed persistence module: `unavailable` coverage and a `MODULE_FAILED` error |
| `invalid/` | files that must be refused with exit 3, each tried as baseline and as current |
| `no-inventory/` | readable reports that carry no usable inventory (schema 0.1.0; `inventory` not an object) |

Adversarial variants (a helper named `sleep` running from `/tmp`, corrupt records, hostile attribute text, shuffled order) are derived from these files inside the tests so each fixture stays a realistic report. To add a scenario, add the snapshot here, then a test that names the behavior it pins; if a case needs a one-field mutation, derive it with `_derive` instead of adding a file.

Files in `invalid/` that are not parseable as strict JSON (or that Python's lenient parser would accept, such as duplicate keys and `NaN`) use the `.report` extension so the repository-wide "validate every tracked `*.json`" lint step does not reject them.
