# Findings and evidence

The engine keeps one central, deduplicated list of findings and one list of evidence items per assessment ([assessment.schema.json](../shared/schemas/assessment.schema.json), `kind: "assessment"`). Collectors are unchanged: they keep emitting `audit-report` findings keyed by a *check id*; the findings layer (`shared/findings/`) re-identifies, enriches and links them. Nothing here reads a host.

## Finding record

```json
{
  "id": "BOF-6c5602dec75bf618",
  "check_id": "USR-UID0-001",
  "title": "Non-root account with UID 0",
  "description": "Accounts other than 'root' have UID 0 and therefore full root privileges.",
  "severity": "critical",
  "confidence": "high",
  "category": "users",
  "component": "users",
  "host": { "hostname": "web01", "host_id": "H-ae4f8139ee0a" },
  "detected_at": "2026-03-01T10:00:00Z",
  "evidence": ["EV-0ddfdf1f81616380"],
  "remediation": { "summary": "Verify each account; if unauthorized, lock it ...", "priority": "P1" },
  "standards": [
    { "framework": "MITRE ATT&CK", "id": "T1136.001", "url": "https://attack.mitre.org/techniques/T1136/001/" },
    { "framework": "NIST SP 800-53 Rev. 5", "id": "AC-2", "title": "Account Management" }
  ],
  "sources": [ { "module": "linux.users", "run_id": "…", "check_id": "USR-UID0-001" } ],
  "occurrences": 1
}
```

| Field | Notes |
|---|---|
| `id` | `BOF-` + 16 hex digits of `SHA-256("blueops/finding/v1", host_id, check_id, component)`. Stable across runs, machines and tool versions. |
| `check_id` | The collector's id (`<AREA>-<TOPIC>-<NNN>`); never reused for a different check ([contracts.md](contracts.md)). |
| `severity`, `confidence` | `info…critical`, `low…high`, as emitted by the collector. Severity says how bad, confidence how sure. |
| `host.host_id` | `H-` + 12 hex digits of `SHA-256(os_family, casefolded hostname)`. A host that is renamed is a new host; hostnames compare case-insensitively. |
| `component` | The part of the system the finding is about. Today it equals `category` (`users`, `network`, `sysconfig`, …); the field is separate so finer components can be added without changing the schema. |
| `detected_at` | Start time of the collector run that first reported it (the earliest wins when several modules report the same finding). |
| `remediation.priority` | `P1` act now · `P2` fix soon · `P3` plan · `P4` routine. Derived from severity; low confidence moves it one step down. It is guidance for ordering work, not a risk score. |
| `standards` | MITRE ATT&CK techniques the collector tagged, plus indicative NIST SP 800-53 Rev. 5 control families for the category ([standards.py](../shared/findings/standards.py)). The NIST mapping says "this area relates to that control", not "this finding proves non-compliance". Technique *names* and CIS section numbers are deliberately not stored (a wrong one is worse than none). |
| `sources` | Which module/run/check reported it. Several entries when two modules report the same finding. |
| `occurrences` | How many times it was reported across modules in this assessment. |

### Identity: what is and is not part of it

The id covers the **host, the check and the component**. It does *not* cover severity, confidence, wording or evidence, so:

- a finding that worsens (`medium` → `high`) is the *same* finding with a changed severity, which snapshot comparison reports as such;
- a finding that gains a new piece of evidence (a second UID-0 account) stays one finding with a larger evidence set;
- the same check on another host is a different finding (`IDENTITY_MISMATCH` is raised when two hosts are compared on purpose).

The granularity is one finding per *check per host*, as the collectors emit them: a check that lists ten files is one finding with ten evidence items. If you need to track the files separately, use the evidence ids.

### Deduplication

Records with one id are merged in `FindingStore`: highest severity wins (and brings its title and description), highest confidence wins, evidence and standards are unioned, earliest `detected_at` is kept, `sources` accumulate and `occurrences` counts reports. When two findings tie on severity the first one reported keeps its title and description. A malformed finding in an otherwise valid report is rejected, recorded as a `FINDING_REJECTED` error and never aborts the rest.

## Evidence record

```json
{
  "id": "EV-0ddfdf1f81616380",
  "type": "file",
  "ref": "/etc/passwd",
  "sha256": "…optional, only when the collector hashed the object…",
  "excerpts": ["account 'toor' has UID 0"],
  "provenance": [
    { "module": "linux.users", "run_id": "…", "check_id": "USR-UID0-001",
      "collected_at": "2026-03-01T10:00:00Z", "collector": "audit-users 0.1.0",
      "report_sha256": "…SHA-256 of the module report the item came from…" }
  ]
}
```

- `id` = `EV-` + 16 hex digits of `SHA-256("blueops/evidence/v1", type, ref)`. The same object reported by several checks or modules is stored **once** with one provenance entry per reporting `(module, run, check)`.
- `type` is one of `file registry process network command log other`. `ref` is a path, key or identifier, never a secret; excerpts are capped at 2000 characters, five per item.
- **Provenance is the chain back to the original data**: `report_sha256` is the digest of `modules/<id>/output/…/report.json`, which the assessment `manifest.json` also lists, and the module directory also holds that run's own `manifest.json`, `report.txt` and `run.log`. `python -m shared.engine verify DIR` re-hashes all of it.
- Evidence is collected read-only by the collectors (they never modify originals; large content is represented by metadata and hashes rather than copies). The engine copies *nothing* from the host: it only re-shapes what collectors wrote.

## Inventory and coverage

The assessment carries the merged `inventory` (records and per-partition coverage) of the module reports, in the same shape as the audit report ([baseline-diff.md](baseline-diff.md)). A module that did not produce usable output contributes `unavailable` coverage for the partitions it `provides`, with the reason. Two modules reporting different attributes for one record keep the first and raise `INVENTORY_CONFLICT`.

## Untrusted data

Every string from a report is attacker-influenced. On the way in, control characters (except tab and newline) become `?` and lengths are capped; the reports escape on the way out ([reporting.md](reporting.md)). Reports are parsed with the strict JSON loader (size cap, duplicate keys, `NaN`, nesting) and validated against the schema before anything is ingested.

## Importing older reports

`load_assessment` accepts a plain `audit-report` (file or run directory, schema 0.1.x/0.2.x) and wraps it as an assessment with profile `imported` and a single pseudo-module `imported.report`. Finding ids are identical to those of a native assessment of the same host, so an old baseline can be compared with a new assessment. The per-module breakdown is not recoverable, so an imported report is judged as a whole when deciding whether absence can be concluded ([reporting.md](reporting.md#snapshot-comparison)).
