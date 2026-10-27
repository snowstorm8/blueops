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
- A `complete`/`degraded` collection of `users`, `groups`, `services` or `processes` that returned **no records** while the other side had some is treated as a collector failure: nothing is concluded for that partition (a note says why; exit 6).
- A record whose partition has no coverage declaration is treated as `partial`. An invalid record taints every partition of its domain. Duplicate coverage entries merge to the worst status. Reaching the record limit degrades all domains.
- A module that was not run, or crashed, marks its partitions `unavailable`/`partial`; it never appears as "everything was removed".
- Indeterminate reasons: `BASELINE_INCOMPLETE`, `CURRENT_INCOMPLETE`, `ATTRIBUTE_UNKNOWN`, `RECORD_CONFLICT` (two records with the same key but different attributes).
- Different privilege levels (`elevated` differs) add a `PRIVILEGE_DIFFERS` warning.
- Different hostnames or OS families are refused (exit 3) unless `--allow-host-mismatch`.

### Transient data

- **PIDs** live in `volatile`; a new PID for the same process is not a change. Processes with the same user and name are aggregated into one record (their PIDs and counts are volatile). Short-lived helpers named in `transient_processes` (default `awk cat cut find grep head ps readlink sed sleep sort ss stat tail tr`) are reported as *transient* and hidden from the text output unless `--show-transient`, but only when their executable is **known** to be in a system directory (`/bin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `C:\\Windows\\System32`...). A helper-named process with an unknown or non-system executable (for example `/tmp/sleep`) is a normal, counted change.
- **Ephemeral ports**: listeners whose port is at or above `ephemeral_from` (default 32768 on Linux, 49152 on Windows) are re-keyed to `listener:<proto>/<bind>/ephemeral`, with the port kept as volatile. A client service that moves from port 51234 to 51871 is therefore not reported. Override with `--ephemeral-from PORT` or in the config.
- **Stable services on high ports.** Ephemeral bucketing compares only the process names in a bucket, so a metrics agent that always listens on 40111 is not reported when it moves, but a *second* listener from the same process on 41000 is invisible too. Name ports that are really fixed in the config file and they keep their own identity:

  ```json
  { "ephemeral_from": 32768, "fixed_ports": [40111, 50000] }
  ```

  With this, `listener:tcp/0.0.0.0/40111` is compared exactly (removed if the agent stops or moves to another port, added if a new listener appears there), while other ports at or above 32768 still collapse into `listener:tcp/0.0.0.0/ephemeral`. Ports must be integers from 1 to 65535; anything else is a config error (exit 3). Use `python -m shared.reporting.diff A B --config diff.json`.
- Loopback-only listeners are compared like any other (they can be backdoors), but get a lower triage priority (`low`).

See [detection-rules.md](detection-rules.md) for the rule layer that ranks and explains these changes (`python -m shared.reporting.detect`).

## Output

### Text (default)

Header (hosts, run ids, the window in which changes happened), a one-line result, coverage per domain, then per-domain `+ added`, `- removed`, `~ modified` entries with the changed attributes, evidence, related findings and the two observation timestamps, then indeterminate records and the findings delta. All values are sanitised to printable ASCII (control and escape characters are shown as `\xNN`) and truncated, because report content is attacker-influenced.

### JSON (`--json` / `--format json`)

Schema: `shared/schemas/baseline-diff.schema.json` (`kind: "baseline-diff"`). Main fields: `baseline`/`current` (run metadata), `window`, `warnings`, `domains` (coverage and comparison status per domain/scope), `changes[]`, `indeterminate[]`, `findings{new,resolved,changed,unverified}`, `summary`.

Each change has `domain`, `scope`, `key`, `change` (`added|removed|modified`), `priority` (a **triage hint**, not a severity), `transient`, `attributes[]` (`name`, `before`, `after`), `unverified_attributes[]`, `observed{baseline_at,current_at}` (the end time of the run each side was seen in), `baseline`/`current` (record snapshot with `attrs`, `volatile`, `evidence`) and `related_findings[]` (finding IDs sharing file/registry evidence).

*Timestamps.* Audit reports carry run start/finish times, not per-record times, so a change can only be dated to the window `baseline.finished_at` .. `current.started_at`. The diff says so rather than inventing a precise time.

### Findings delta

Findings are compared by `id`, `severity` and file/registry evidence refs only (not by title/description text). Findings whose evidence list was truncated (`only the first N are listed`) are not compared. A finding whose check reported a coverage error in either run is listed as **unverified**, not as new or resolved. Findings missing from the current report are also **unverified** (not resolved) when the current run had a failed or missing module, an error that names no check and was not already in the baseline (for example `PASSWD_UNREADABLE`), a failure/partial exit code (`1`, `3`, `6`) that the baseline did not have, or lost privileges relative to an elevated baseline. Errors present in both runs (a standing `UPTIME_UNAVAILABLE`) do not block resolutions.

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
  "fixed_ports": [40111],
  "transient_processes": ["ps", "sleep"],
  "ignore": { "processes": ["process:*:backup-agent"], "config": ["config:hosts:*"] }
}
```

`fixed_ports` lists ports that are compared exactly even though they are at or above `ephemeral_from`. `ignore` maps a domain to `fnmatch` glob patterns over record keys; ignored records are counted in `summary.ignored`. Unknown keys and invalid values are rejected (exit 3).

## Expected behavior (regression matrix)

`tests/shared/test_baseline_e2e.py` drives the real CLI over complete synthetic reports in `tests/fixtures/baseline-e2e/` (a Linux host and a Windows host; each has a known-good `baseline.json` and five later runs). These are the guarantees the tests pin, so a change that breaks one is a behavior change, not a refactor:

| Scenario (fixture) | Expected result | Exit |
|---|---|---|
| `identical`: same inventory, new run id, new PIDs, a moved ephemeral port; Windows also differs in key case, member order and dynamic RPC ports | no changes, no indeterminate, no warnings | 0 |
| a report compared with itself | no changes, `SAME_RUN` warning | 0 |
| `changed`: users, group membership, services, listeners, scheduled tasks, persistence and config added, removed and modified | exactly the 15 (Linux) / 14 (Windows) records that differ, each with the changed attributes, a triage priority, evidence, related findings and the observation window; new and changed findings are listed | 4 |
| swapping baseline and current | additions and removals invert, modifications stay modifications, `REVERSED_ORDER` warns | 4 |
| `churn`: new PIDs, helper processes (`sleep`, `ps`, `grep`, `awk`), ephemeral ports that move or open a second socket | no counted changes; helpers are kept as `transient` and hidden from text unless `--show-transient` | 0 |
| `churn` on Windows: `tasklist.exe`, `wmic.exe` from `System32` | transient | 0 |
| a helper name running from `/tmp`, `/dev/shm`, `C:\\Users\\Public` or with an unknown executable; a non-listed `System32` tool such as `net.exe` | counted as a normal addition | 4 |
| a *different* process on an ephemeral port | `modified` on `listener:<proto>/<bind>/ephemeral` | 4 |
| `unprivileged`: a non-elevated re-run with partial, degraded and unavailable domains | no additions, removals or modifications; missing records are `CURRENT_INCOMPLETE`, unreadable values are `ATTRIBUTE_UNKNOWN`; unavailable partitions are not compared; `PRIVILEGE_DIFFERS`; the baseline's finding is *unverified*, not resolved | 6 |
| an unprivileged *baseline* against a full run | no additions are concluded | 6 |
| a real removal in a fully collected domain during an incomplete run | still reported (`removed`), alongside the indeterminate records | 4 |
| `module-failed`: a crashed module (`MODULE_FAILED`) | its partitions are not compared; no removals; its findings are *unverified* | 6 |
| a complete but empty `users`/`groups`/`services`/`processes` collection; a new check-less error, or a failure exit code, when findings vanish | no removals; findings unverified | 6 |
| a domain missing from the current report with no coverage entry and no error | not compared; no mass removal | 6 |
| a `partial` domain with zero records, or records with no coverage declaration | removals withheld (`CURRENT_INCOMPLETE`) | 6 |
| unparseable JSON (empty, truncated, not JSON, duplicate keys, `NaN`), top level not an object, missing `run` or `host.os.family`, bad timestamp, unsupported `schema_version` (`1.0.0`, `0.3.0`), on either side | one `blueops-diff:` line on stderr, empty stdout, no `--output` file created | 3 |
| missing path, directory without `report.json`, unreadable file | same | 3 |
| Linux against Windows (even with `--allow-host-mismatch`); different hostnames without the flag | refused | 3 |
| schema 0.1.0 report (no `inventory` key) | loads with `NO_INVENTORY`; nothing is concluded from inventory, only findings are compared | 6 (4 if findings differ) |
| `inventory`, `inventory.coverage`, `findings` or `errors` of the wrong type, or a finding/error entry that is not an object | refused | 3 |
| a corrupt record (non-object, empty or control-character key, nested attribute value) | its domain is degraded; removals in it are withheld | 6 |
| an unknown coverage status such as `"totally-fine"` | treated as `partial` | 6 |
| two records with one key and different attributes | `RECORD_CONFLICT`, no change reported | 6 |
| escape sequences and newlines inside an attribute value | shown as `\xNN` in text, so a report cannot forge lines; the JSON form keeps the raw value | 4 |

Determinism: the same two inputs produce byte-identical text and JSON across repeated runs, shuffled record, coverage and finding order, file versus run-directory input, `--output` versus stdout, and different `PYTHONHASHSEED`, `TZ` and `LC_ALL` (only `generated_at` varies, and `--generated-at` pins it). The diff carries no file paths or host-local data. The tests also verify that the inputs are left untouched (hash, mtime, directory listing) and that no socket or subprocess is created.

## Schema versions and migration

- **0.2.0** (current) adds the optional `inventory` object to the audit-report schema. It is additive: all 0.1.0 reports remain valid.
- A **0.1.x report has no inventory** and can still be loaded: it contributes `has_inventory: false`, every inventory domain is "not compared", and only the findings delta is produced (with a warning). There is nothing to migrate in place; re-run the audit with a 0.2 collector to obtain a usable baseline.
- Reports of an unknown major/minor line are refused (exit 3). Readable lines are listed in `READABLE_REPORT_VERSIONS` (`shared/reporting/contracts.py`).
- The diff schema is versioned together with the audit-report schema; see [contracts.md](contracts.md).

## Loader hardening

Reports are untrusted input. A report whose `findings` or `errors` is not a list of objects (with a string `id`/`code`), or whose `inventory` is present but not an object (including `null`) or whose `inventory.coverage` is not a list, is **rejected** (exit 3) instead of being read as if the data were absent: silently dropping an error or a finding could turn an unknown into a conclusion. Only a report with no `inventory` key at all (0.1.x) loads without inventory. The loader enforces a 64 MiB limit, accepts a UTF-8 BOM (Windows PowerShell 5.1 writes one), rejects duplicate JSON keys, `NaN`/`Infinity`, over-deep nesting and control characters in keys, caps the record count, and validates every record; invalid records degrade coverage of their domain instead of crashing the comparison or silently disappearing.

## Limitations

- It is only as complete as the audits behind it: anything the collectors do not inventory (e.g. file contents outside the listed paths) cannot be diffed.
- A compromised host can lie to its own audit (see [security-model.md](security-model.md)); a clean diff is not proof of integrity. Compare against a baseline taken before the incident, ideally cross-checked from offline media.
- Windows keys are compared case-insensitively; attribute values are compared exactly.
- Per-record change times are not available (see *Timestamps*).
- The comparison trusts the report's own `coverage` statements. A collector (or an attacker who controls the host) that declares `complete` while omitting records produces removals; one that omits a coverage entry produces `not_compared`. Only the second is detected.
- Windows transient helpers are a short built-in list of read-only console tools (`tasklist.exe`, `whoami.exe`, `ipconfig.exe`, ...). Anything else (including `net.exe`, `sc.exe`, `reg.exe`, `cmd.exe`) is a normal change, and a listed name outside `System32`/`SysWOW64` is too.
- Ephemeral listeners are aggregated per protocol and bind address, and only their process names are compared. A new listener on another high port whose process name is already in the bucket is therefore invisible. List services that really listen on a stable high port in `fixed_ports` (config file) to compare them by exact port.
- The comparison still believes a report's `coverage` statements about *which records exist*. A collector (or an attacker controlling the host) that declares `complete` while omitting some records produces removals. The engine only second-guesses implausible cases: an empty core domain, new collection errors, a failed run exit code and lost privileges (below).
- Multi-host merge and HTML rendering are planned, not implemented ([roadmap.md](roadmap.md)).

## Developing

End-to-end snapshots live in `tests/fixtures/baseline-e2e/` (see its README for the layout and how to add a scenario). Golden files live in `tests/fixtures/baseline/` (synthetic data only). Regenerate after an intentional output change with `BLUEOPS_UPDATE_GOLDEN=1 python -m pytest tests/shared/test_baseline_cli.py` and review the diff. Producers: `bo_inv`/`bo_cov` in `linux/lib/common.sh`, `Add-BoInventory`/`Add-BoCoverage` in `windows/lib/Common.ps1`.
