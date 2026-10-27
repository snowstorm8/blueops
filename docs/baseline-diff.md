# Baseline snapshots and change detection (v0.2)

Status: **implemented** for Linux and Windows reports. The comparison is **offline and read-only**: it reads two report files (and an optional config file) and writes one diff. It makes no network connections, does not touch the audited hosts, and never modifies its inputs.

A *baseline* is simply an audit report taken when the host was in a known state. Compare it with a later report from the same host to see what changed in between:

```bash
python -m shared.reporting.diff BASELINE CURRENT [--format text|json] [--output FILE]
```

`BASELINE` and `CURRENT` are `report.json` files or run directories (`<output-dir>/blueops-run-.../`). Run it on an analyst machine (Python >= 3.9, standard library only); the collectors on the hosts do not need Python.

## Workflow

1. Take the baseline when the host is known-good: `sudo linux/audit/audit-linux.sh --json --output-dir baselines/` (Windows: `.\windows\audit\Invoke-WindowsAudit.ps1 -Json -OutputDir baselines`). Run as root/Administrator: unprivileged runs report degraded or partial coverage.
2. Later, take another report the same way.
3. `python -m shared.reporting.diff baselines/<run-a> out/<run-b>`.

Treat baselines as sensitive (they list accounts, listeners and persistence on the host) and store them off-host. Reports contain no secrets, hashes of passwords or key material.

## What is compared

Each audit report may carry an `inventory` (schema 0.2.0): structured records with stable identifiers, plus a per-domain **coverage** statement. Free-text finding descriptions are never compared.

| Domain | Linux key examples | Windows key examples |
|---|---|---|
| `users` | `user:alice` (uid, shell, home, password state: `set`/`locked`/`empty`) | `user:S-1-5-21-...-1001` (name, enabled, password flags) |
| `groups` | `group:sudo` (members as a set) | `group:S-1-5-32-544` (member SIDs) |
| `services` | `service:ssh.service` (active, sub, enabled) | `service:spooler` (state, start mode, account, image path) |
| `processes` | `process:root:sshd` (exe) | `process:svchost.exe` (exe) |
| `listeners` | `listener:tcp/0.0.0.0/22` (process) | `listener:tcp/0.0.0.0/445` (process) |
| `scheduled_tasks` | `cron:/etc/cron.d/backup#<line-hash>`, `at` jobs | `task:\vendor\job` (user, run level, hidden, actions, triggers) |
| `persistence` | `persist:<scope>:<path>` (sha256, mode) | `persist:run:...`, `persist:wmi:...`, IFEO, AppInit, Winlogon, startup files |
| `config` | sysctl, sudoers, PAM, SUID/SGID, DNS, hosts | security registry settings, firewall profiles and rules, proxy, shares, Defender exclusions |

Evidence-hash conventions: file contents are recorded as SHA-256, never copied. SSH authorized keys are fingerprinted by key blob; the key material itself is never emitted.

### Record fields

```json
{
  "domain": "listeners",
  "scope": "",
  "key": "listener:tcp/0.0.0.0/22",
  "attrs":    { "proto": "tcp", "bind": "0.0.0.0", "port": "22", "process": "sshd" },
  "volatile": { "pid": "812" },
  "evidence": [{ "type": "network", "ref": "tcp 0.0.0.0:22" }]
}
```

- **`key`** is a stable identifier (never a PID, never free text). Unique within a domain, except for `processes` and `listeners`, which the engine aggregates.
- **`attrs`** are compared. Values are normalised to text (booleans become `"true"`/`"false"`, integers become strings) and arrays compare as **sets**. `null` (or an absent attribute) means *unknown*, never "empty".
- **`volatile`** values (PIDs, command lines, counts, ephemeral ports) are shown in the diff but never compared.
- **`evidence`** points at the file, registry value, process or socket the record came from; it is carried into the diff.

## Coverage, scopes and why the engine refuses to guess

Every domain (optionally a **scope** within it, e.g. `persistence/systemd`, `config/sudoers`) declares how completely it was collected:

| Status | Meaning | Effect |
|---|---|---|
| `complete` | every record was collected | additions and removals are reported |
| `degraded` | every record was collected, some attributes are unknown (e.g. needs root) | unknown attributes are not compared |
| `partial` | some records may be missing | removals are **not** concluded |
| `unavailable` | not collected | the domain is not compared |

Rules:

- A record is **removed** only if the *current* collection of its domain/scope was `complete` or `degraded`; **added** only if the *baseline* collection was.
- An attribute is **modified** only if both sides know it. Otherwise the record is listed under `indeterminate` with reason `ATTRIBUTE_UNKNOWN`.
- A record whose partition has no coverage declaration is treated as `partial`. An invalid record taints every partition of its domain. Duplicate coverage entries merge to the worst status. Reaching the record limit degrades all domains.
- A module that was not run, or crashed, marks its partitions `unavailable`/`partial`; it never appears as "everything was removed".
- Indeterminate reasons: `BASELINE_INCOMPLETE`, `CURRENT_INCOMPLETE`, `ATTRIBUTE_UNKNOWN`, `RECORD_CONFLICT` (two records with the same key but different attributes).
- Different privilege levels (`elevated` differs) add a `PRIVILEGE_DIFFERS` warning.
- Different hostnames or OS families are refused (exit 3) unless `--allow-host-mismatch`.

### Transient data

- **PIDs** live in `volatile`; a new PID for the same process is not a change. Processes with the same user and name are aggregated into one record (their PIDs and counts are volatile). Short-lived helpers named in `transient_processes` (default `awk cat cut find grep head ps readlink sed sleep sort ss stat tail tr`) are reported as *transient* and hidden from the text output unless `--show-transient`, but only when their executable is **known** to be in a system directory (`/bin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `C:\\Windows\\System32`...). A helper-named process with an unknown or non-system executable (for example `/tmp/sleep`) is a normal, counted change.
- **Ephemeral ports**: listeners whose port is at or above `ephemeral_from` (default 32768 on Linux, 49152 on Windows) are re-keyed to `listener:<proto>/<bind>/ephemeral`, with the port kept as volatile. A client service that moves from port 51234 to 51871 is therefore not reported. Override with `--ephemeral-from PORT` or in the config.
- Loopback-only listeners are compared like any other (they can be backdoors), but get a lower triage priority (`low`).

## Output

### Text (default)

Header (hosts, run ids, the window in which changes happened), a one-line result, coverage per domain, then per-domain `+ added`, `- removed`, `~ modified` entries with the changed attributes, evidence, related findings and the two observation timestamps, then indeterminate records and the findings delta. All values are sanitised to printable ASCII (control and escape characters are shown as `\xNN`) and truncated, because report content is attacker-influenced.

### JSON (`--json` / `--format json`)

Schema: `shared/schemas/baseline-diff.schema.json` (`kind: "baseline-diff"`). Main fields: `baseline`/`current` (run metadata), `window`, `warnings`, `domains` (coverage and comparison status per domain/scope), `changes[]`, `indeterminate[]`, `findings{new,resolved,changed,unverified}`, `summary`.

Each change has `domain`, `scope`, `key`, `change` (`added|removed|modified`), `priority` (a **triage hint**, not a severity), `transient`, `attributes[]` (`name`, `before`, `after`), `unverified_attributes[]`, `observed{baseline_at,current_at}` (the end time of the run each side was seen in), `baseline`/`current` (record snapshot with `attrs`, `volatile`, `evidence`) and `related_findings[]` (finding IDs sharing file/registry evidence).

*Timestamps.* Audit reports carry run start/finish times, not per-record times, so a change can only be dated to the window `baseline.finished_at` .. `current.started_at`. The diff says so rather than inventing a precise time.

### Findings delta

Findings are compared by `id`, `severity` and file/registry evidence refs only (not by title/description text). Findings whose evidence list was truncated (`only the first N are listed`) are not compared. A finding whose check reported a coverage error in either run is listed as **unverified**, not as new or resolved. Findings missing from the current report are also **unverified** (not resolved) when the current run had a failed or missing module, or lost privileges relative to an elevated baseline.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No differences and the comparison was complete |
| 4 | Differences found (added, removed or modified records, or new/changed findings) |
| 6 | No differences found, but some domains were partial/unavailable, records were indeterminate, or a report has no inventory (0.1.x): **not** a clean bill of health |
| 3 | Reports unreadable, malformed, not comparable (host/OS mismatch, unsupported schema) or bad config |
| 2 | Usage error |
| 1 | Unexpected error, e.g. the output file already exists |

## Options and config

| Option | Meaning |
|---|---|
| `--format text|json`, `--json` | Output format (default text) |
| `--output FILE` | Write the diff to FILE (created with mode 0600, refuses to overwrite) instead of stdout |
| `--config FILE` | JSON config (below) |
| `--ephemeral-from PORT` | Override the ephemeral port threshold |
| `--allow-host-mismatch` | Compare reports from different hostnames |
| `--show-transient` | List transient process changes in text output |
| `--generated-at TS` | Timestamp to record (for reproducible output) |
| `--quiet` | Suppress the stderr summary |

With `--json` or `--output`, the human summary goes to stderr and JSON to stdout/the file; they are never mixed.

Config file (`shared/config/baseline-diff.default.json` shows the defaults):

```json
{
  "ephemeral_from": 32768,
  "transient_processes": ["ps", "sleep"],
  "ignore": { "processes": ["process:*:backup-agent"], "config": ["config:hosts:*"] }
}
```

`ignore` maps a domain to `fnmatch` glob patterns over record keys; ignored records are counted in `summary.ignored`. Unknown keys and invalid values are rejected (exit 3).

## Schema versions and migration

- **0.2.0** (current) adds the optional `inventory` object to the audit-report schema. It is additive: all 0.1.0 reports remain valid.
- A **0.1.x report has no inventory** and can still be loaded: it contributes `has_inventory: false`, every inventory domain is "not compared", and only the findings delta is produced (with a warning). There is nothing to migrate in place; re-run the audit with a 0.2 collector to obtain a usable baseline.
- Reports of an unknown major/minor line are refused (exit 3). Readable lines are listed in `READABLE_REPORT_VERSIONS` (`shared/reporting/contracts.py`).
- The diff schema is versioned together with the audit-report schema; see [contracts.md](contracts.md).

## Loader hardening

Reports are untrusted input. The loader enforces a 64 MiB limit, accepts a UTF-8 BOM (Windows PowerShell 5.1 writes one), rejects duplicate JSON keys, `NaN`/`Infinity`, over-deep nesting and control characters in keys, caps the record count, and validates every record; invalid records degrade coverage of their domain instead of crashing the comparison or silently disappearing.

## Limitations

- It is only as complete as the audits behind it: anything the collectors do not inventory (e.g. file contents outside the listed paths) cannot be diffed.
- A compromised host can lie to its own audit (see [security-model.md](security-model.md)); a clean diff is not proof of integrity. Compare against a baseline taken before the incident, ideally cross-checked from offline media.
- Windows keys are compared case-insensitively; attribute values are compared exactly.
- Per-record change times are not available (see *Timestamps*).
- Multi-host merge and HTML rendering are planned, not implemented ([roadmap.md](roadmap.md)).

## Developing

Golden files live in `tests/fixtures/baseline/` (synthetic data only). Regenerate after an intentional output change with `BLUEOPS_UPDATE_GOLDEN=1 python -m pytest tests/shared/test_baseline_cli.py` and review the diff. Producers: `bo_inv`/`bo_cov` in `linux/lib/common.sh`, `Add-BoInventory`/`Add-BoCoverage` in `windows/lib/Common.ps1`.
