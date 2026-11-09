# Endpoint telemetry and threat hunting

BlueOps can collect normalized endpoint telemetry, import it for reproducible investigations, compare snapshots, query it, and hunt over it with explainable rules that run through the existing detection engine. Everything is local and read-only: no collector changes a host, establishes persistence, or contacts a network, and telemetry is never transmitted anywhere.

Status: implemented in v0.6. What was and was not verified is in [implementation-report-v0.6.md](implementation-report-v0.6.md); in particular the Windows collector is exercised by the Windows CI jobs, not by anything in this repository's Linux checks.

## Workflow

```bash
# On the target host (as root / elevated for full coverage), or on an analyst machine for imports:
python -m shared.engine telemetry collect --output-dir ./telemetry
python -m shared.engine telemetry import stream.jsonl assessment-dir/ --output-dir ./telemetry   # offline, reproducible
python -m shared.engine telemetry show   ./telemetry/blueops-telemetry-...        # coverage and problems
python -m shared.engine telemetry query  STORE --category process --contains cmdline~/tmp/
python -m shared.engine telemetry tree   STORE --pid 4242
python -m shared.engine telemetry compare BASELINE_STORE CURRENT_STORE
python -m shared.engine telemetry hunt   STORE --telemetry-baseline BASELINE_STORE --state-dir ./cases
python -m shared.engine telemetry hunt   STORE --assessment ASSESSMENT_DIR --format html --output hunt.html
python -m shared.engine telemetry report STORE --detections hunt.json --format html --output report.html
python -m shared.engine case list --state-dir ./cases
```

`detect run --telemetry STORE` is the same thing from the detection side. Telemetry hunting results are ordinary detection results (`DT-` ids, `detection-results` schema): they register as cases, appear in the existing detection reports and are exported with `detect export`.

Exit codes follow [contracts.md](contracts.md): `0` ok, `2` usage, `3` bad input/precondition (including a tampered store or a collector for another platform), `4` detections at or above `--fail-on` (or differences found by `compare`), `6` incomplete coverage or rules that could not be evaluated.

## Architecture and data flow

```
 Linux collector (Bash)  ─┐                        ┌─ query / tree        (telemetry/query.py)
 Windows collector (PS)  ─┼─ JSONL stream ─ ingest ─┼─ compare             (telemetry/compare.py)
 assessment inventory    ─┘  (untrusted)  validate  ├─ hunt: rules engine  (shared/rules, telemetry sources)
 earlier telemetry store ─────────────────  dedupe  └─ report (md / html)  (telemetry/render.py)
                                          derive            │
                                          store + manifest  └─ case workflow (shared/rules/investigation.py)
```

| Module | Responsibility |
|---|---|
| `linux/telemetry/collect-telemetry.sh` | Bash collector; stream to stdout; honors `BO_ROOT` fixture hooks like the audit collectors. |
| `windows/telemetry/Invoke-TelemetryCollection.ps1`, `windows/lib/Telemetry.ps1` | PowerShell collector and its pure helpers (event parsing, redaction). |
| `shared/telemetry/model.py` | Vocabulary, record ids, per-record validation and normalization. |
| `shared/telemetry/ingest.py` | Readers (stream, document, store), deduplication, conflicts, coverage merge, summaries, store writing. |
| `shared/telemetry/adapter.py` | Assessment inventory → telemetry (nothing is collected twice). |
| `shared/telemetry/derive.py` | Derived authentication summaries (labelled `derived`, traceable). |
| `shared/telemetry/compare.py` | Coverage-aware snapshot comparison. |
| `shared/telemetry/query.py` | Constrained queries and process trees. |
| `shared/rules/telemetry_subjects.py`, `shared/rules/library/telemetry-hunting.json` | The `telemetry` / `telemetry_changes` rule sources and the 24 hunting rules. |
| `shared/telemetry/hunt.py`, `render.py`, `cli.py` | Hunt preparation, text/Markdown/HTML views, CLI. |

Design decisions:

* **One rule engine.** Hunting rules are detection rules with two new sources, `telemetry` (current records) and `telemetry_changes` (differences from a baseline telemetry). They get severity/confidence reasoning, coverage handling, executable examples, ATT&CK/NIST mappings, `DT-` ids and the case workflow for free. There is no second evaluator.
* **Collectors do not need Python.** They are Bash/PowerShell producing a JSON Lines stream; Python is used on the analyst machine to validate and analyze (and `telemetry collect` simply runs the collector and ingests its output).
* **Untrusted input.** A stream may come from a compromised host. Every record is rebuilt from validated parts; unusable input is kept as a `rejected` entry with reasons, never silently dropped; XML event data is parsed with external entities disabled; reports escape everything for their format; no query or rule evaluates code.
* **Host identity.** `host_id` is derived from hostname and OS family exactly as for findings, so telemetry and assessments of one host join. Two hosts that share a hostname are indistinguishable (a known limit shared with the assessment engine).

## Telemetry schema (`telemetry.schema.json`, version 1.0.0)

One document describes one host. Top level: `schema_version`, `kind: "telemetry"`, `generated_at`, `collection` (id, start/end, collectors, mode `live|import|assessment`, `elevated`, `imported_from` with SHA-256 of each input), `host`, `coverage[]`, `records[]`, `errors[]`, `rejected[]`, `conflicts[]`, `summary`.

Every record carries provenance:

| Field | Meaning |
|---|---|
| `record_id` | `TEL-` + 16 hex of SHA-256(host id, category, key). Stable across collections. |
| `host_id`, `os_family`, `collector{name,version}` | Where and by what. |
| `category`, `scope` | What kind of observation (see below); optional sub-source such as `cron` or `sshd`. |
| `key`, `identity` | `key` makes the observation unique within a collection; `identity` is what the *same thing* is across snapshots (for a process: user + executable, not the pid). |
| `observed_at`, `event_time` | Collection timestamp; for events, when the event happened (UTC; **a timestamp without a zone is refused, never assumed**). |
| `source{type,ref}`, `method` | `proc|file|command|api|eventlog|registry|assessment|derived` and where exactly it came from. |
| `attributes`, `unknown_attributes` | The data. An attribute that could not be collected is `null` **and** listed in `unknown_attributes`; an attribute that is simply absent does not apply. |
| `status`, `limitations` | `ok` or `partial` with the reasons (unknown attributes, missing event time, truncation). |
| `occurrences`, `first_seen`, `last_seen` | Repeated identical observations are merged and counted. |
| `derived_from` | For derived records, the ids they summarize. |

Categories and their required attributes: `process` (pid, name; ppid, exe, cmdline, user, exe_deleted), `user` (name; uid/sid, shell, password_state, enabled), `group` (name; members), `session` (user), `service` (name; path, state, start_mode, account), `scheduled_task` (name; command, schedule, user, kind), `network_connection` (protocol, local_port; state, remote_address, remote_port, pid, process), `listener` (protocol, local_port; local_address, pid, process), `auth_event` (action, result; user, source_address, method, change, group, actor), `security_event` (event_id; outcome, summary, actor), `config_change` (object, change; name, actor, path), `system_config` (setting; value, source), `integrity` (path; sha256, mode, size, mtime), `persistence` (mechanism, location; value, user), `auth_summary` (grouping; derived).

`auth_event.action` is one of `login_success, login_failure, logoff, privilege_use, sudo, su, account_change, group_change, lockout, credential_use, other`; `result` is `success|failure|unknown`. Unrecognised values are normalized to `other` / `unknown` with a note.

### Absence versus "could not collect"

`coverage[]` has one entry per category (and optionally scope): `complete`, `partial`, `unavailable`, or `not_applicable`, with a reason and the number of records.

* `complete` with zero records is an **observed absence**: the source was read and held nothing.
* `unavailable` means the data **could not be collected** (no permission, no such source). It says nothing about the host.
* `partial` means some of it was collected.
* A category that has records but no declared coverage is recorded as `partial` ("the collector declared no coverage"), never assumed complete.
* A stream without its end marker, or with a record count that disagrees with the marker, downgrades every `complete` entry to `partial`.
* Within one input the worst status wins (a collector can report a problem and then `complete`); across inputs the best wins (a second source that saw the category completely).

Rules, queries and comparisons use this: a rule whose category is `unavailable` is reported **indeterminate** with the collector's reason instead of passing; a removal is claimed only when both snapshots were `complete`.

### Stream format (collectors)

JSON Lines, ASCII, one object per line: `header` (collector, host, collection id/start/elevation), `coverage`, `record`, `error`, then `end` (`ended_at`, `records`). A collector emits records without ids; ingestion assigns them. Third parties can produce the same stream (it is how plugins contribute telemetry): validate with `telemetry import`.

## Collectors

### Linux (`linux/telemetry/collect-telemetry.sh`)

Bash ≥ 4.2, coreutils, awk (POSIX features only, so mawk/gawk/busybox work), no network, no writes. Options: `--since-hours N` (default 24), `--max-events N` (default 5000), `--categories LIST`. Exit `0`, `2` usage, `3` Bash older than 4.2 (checked first by `linux/lib/bashcheck.sh`, before any newer syntax is parsed; nothing is collected), `6` collected with gaps.

| Category | Source | Notes |
|---|---|---|
| process | `/proc/<pid>/{stat,status,cmdline,exe}` | ppid, owner, executable, `exe_deleted`; command lines redacted. Key includes the start time so a reused pid is a different process. |
| user, group | `/etc/passwd`, `/etc/group`, `/etc/shadow` | Password hashes are never read into output: only `locked/set/empty`. Unreadable shadow → `password_state` unknown, coverage partial. |
| session | `who` | Interactive sessions only. |
| service | systemd unit files | Definitions (ExecStart, User, enabled); **not** runtime state. |
| scheduled_task | cron files/spools, `cron.*` directories, systemd timers | |
| network_connection, listener | `/proc/net/{tcp,tcp6,udp,udp6}` | IPv6 canonicalized, IPv4-mapped unwrapped; socket owners from `/proc/<pid>/fd` (needs root for other users' sockets; otherwise `pid`/`process` unknown, coverage partial). |
| auth_event | `/var/log/auth.log`, `/var/log/secure`, else `journalctl` | sshd, sudo, su, useradd/usermod/userdel/gpasswd/groupadd/passwd. ISO-8601 timestamps are exact; traditional syslog lines have no year/zone and are kept **without** a time (limitation). An unreadable journal is `unavailable`; an empty result for a non-root user is `partial`, not "no events". |
| security_event, config_change | `/var/log/audit/audit.log` | Selected auditd record types only. Absent/unreadable auditd → `unavailable`. |
| system_config | sshd (first-wins, stops at `Match`), `/proc/sys`, SELinux/AppArmor, auditd presence | Selected settings only. |
| integrity | SHA-256 + mode/owner/mtime of a fixed list (passwd, group, sudoers(.d), sshd_config(.d), ld.so.preload, crontab/cron.d, rc.local, pam.d, authorized_keys…) | Secrets (shadow files, private keys) are deliberately excluded. |
| persistence | ld.so.preload, rc.local, profile.d, XDG autostart, authorized_keys | Key material is never read: only counts and whether options are used. |

Permissions: run as root for full coverage. Unprivileged runs work and **declare** each gap (`NOT_PRIVILEGED` error plus coverage reasons). Different distributions: tools are probed (`journalctl`, `who`, GNU `date`), never assumed; a missing tool is a coverage reason, not a failure. Fixture hooks (`BO_TEST_MODE=1`, `BO_ROOT`) are reported as a `TEST_MODE` error so a fixture run is never mistaken for a host.

### Windows (`windows/telemetry/Invoke-TelemetryCollection.ps1`)

Windows PowerShell 5.1 and PowerShell 7, built-in cmdlets/CIM only, no network, no writes; ASCII output (non-ASCII as `\uXXXX`). Options: `-SinceHours`, `-MaxEvents`, `-Categories`, `-ShowVersion`.

| Category | Source |
|---|---|
| process | `Win32_Process` (ppid, path, command line, creation time; owner via `GetOwner` for the first 1500) — names are lower-cased |
| user, group, session | `Get-LocalUser/LocalGroup/LocalGroupMember` (CIM fallback), `Win32_LogonSession` |
| service | `Win32_Service` |
| scheduled_task | `Get-ScheduledTask` (declared unavailable if the module is missing) |
| network_connection, listener | `Get-NetTCPConnection`/`Get-NetUDPEndpoint`; `netstat -ano` fallback (partial: TCP only, state names not interpreted) |
| auth_event | Security log: 4624/4625 (network, interactive, remote, unlock, cached; **service/batch logons and machine accounts are not recorded**), 4648, 4720–4726, 4738, 4740, 4728/4732/4756 and removals (member SIDs resolved to names; unresolved → user unknown) |
| security_event, config_change | 1102, 104 (log cleared), 4719, 4697/7045 (service install), 4698/4699/4702 (tasks) |
| system_config | UAC, LSA (RunAsPPL, LM level), WDigest, SMB1, RDP/NLA, PowerShell script-block logging, AutoRun, firewall profiles, Defender real-time protection; `not_set` = value absent |
| integrity | hosts, PowerShell profiles, all-users startup folder |
| persistence | Run/RunOnce (HKLM + loaded HKU hives), Winlogon, AppInit_DLLs, IFEO debuggers, all-users startup, WMI event consumers |

Permissions: the Security log requires elevation; without it `auth_event`, `security_event` and `config_change` are `unavailable` with the system's message. Not recorded at all: PowerShell script-block text (it can contain secrets), per-user startup folders, domain accounts.

## Querying

`telemetry query` takes flags or a JSON query (`--query FILE`, `-` for stdin); both are validated before anything runs and nothing is evaluated as code:

```json
{"category": ["process", "network_connection"],
 "since": "2026-03-01T00:00:00Z", "until": "2026-03-02T00:00:00Z",
 "where": {"all": [{"field": "attrs.name", "op": "in", "value": ["nc", "ncat"]},
                    {"field": "process.parent_name", "op": "eq", "value": "bash"}]},
 "sort": "time", "limit": 100}
```

Keys: `category`, `host`, `since`, `until` (ISO 8601 with a zone), `scope`, `where`, `sort` (`time|key|category`), `limit` (1–10000). `where` is the detection-rule condition language (`eq ne ieq contains icontains startswith endswith regex gt gte lt lte in not_in missing present is_true is_false len_*`, combined with `all/any/not`; regexes with nested quantifiers are rejected). Fields: `record_id category scope key identity status occurrences partial observed_at event_time hour_utc weekday first_seen last_seen source.type source.ref method collector limitations unknown_attributes derived os_family attrs.<name>` and, for processes, `process.parent_name process.parent_exe process.parent_user process.ancestors process.depth process.orphan process.children`. A missing value never matches a comparison (not even `ne`); test absence explicitly with `missing`.

Flag shortcuts: `--attr NAME=VALUE` (case-insensitive equality), `--contains NAME~TEXT`. `telemetry tree --pid N | --name X` prints ancestors and descendants (cycle-safe, depth- and size-capped).

## Hunting rules

`rules list --category hunt-process` etc.; full text with examples in [detection-library.md](detection-library.md). Ids follow the library convention `DR-<LNX|WIN|ANY>-H<AREA>-NNN`.

| Area | Rules |
|---|---|
| Process relationships | shell under a network-facing service (HPRC-001); executable in a temporary location (002); deleted executable still running, Linux (003); shell with an established external connection, process + socket joined by pid (004); script host under Office, Windows (005); encoded PowerShell, Windows (006) |
| Network | listener owned by a process in a temporary location (HNET-001); external connection from an interpreter/downloader (002) |
| Authentication | many failures from one source across accounts (HAUTH-001); success after repeated failures (002); remote login to root/Administrator (003); account created then added to a privileged group (004); log cleared, Windows (005) |
| Services, tasks, persistence | service in a user-writable path (HSVC-001); service-install event + writable path (002); download-and-execute / remote-shell job (HTSK-001); privileged job running a writable-path program (002); ld.so.preload, Linux (HPER-001); autostart in a writable path (002) |
| Snapshot changes | new listener (HCHG-001), new service (002), changed sensitive file hash (003), privileged group membership changed (004), new scheduled task (005) |

Every detection has: severity and confidence **with reasons**, the matched conditions, the contributing `TEL-` records (with source and attribute excerpts), missing corroboration, possible benign causes, investigation steps, remediation advice that never assumes the tool changes anything, and ATT&CK (`possible`, with an explanation) and NIST references.

**Suspicious, unusual, confirmed.** A rule's `nature` is presented as: `observation` → *unusual* (a factual difference; no wrongdoing implied), `indicator`/`correlated` → *suspicious* (matches a pattern associated with malicious activity; benign causes are common; not proof), `hypothesis` → *lead*. **BlueOps never reports anything as confirmed.** Confirmation is an analyst's decision, recorded by resolving a case with a note.

**Coverage behaviour.** No telemetry supplied → hunting rules are `not_applicable` (hunting was not requested). Category `unavailable` → the rule is `indeterminate` with the reason. `partial` → the rule runs, confidence drops one step and the caveat names the gap. Change rules need a baseline (`--telemetry-baseline`) and are `indeterminate` when the baseline did not completely cover the category.

## Snapshot comparison

`telemetry compare BASELINE CURRENT` (schema `telemetry-comparison.schema.json`): per category added/removed/changed by `identity`. Removals and attribute changes are reported only for categories `complete` in both snapshots; otherwise the category is listed as `indeterminate` and only additions appear. Event categories are logs: new events are reported, absent events are never "removed". Volatile attributes (`pid`, `ppid`, …) and attributes unknown on either side do not register as changes.

## Error handling

* Unusable records → `rejected[]` with origin (`file:line`) and reasons; malformed JSON lines, unknown categories, missing required attributes, bad attribute names/types.
* Collector problems → `errors[]` (`NOT_PRIVILEGED`, `TEST_MODE`, `EVENT_LIMIT`, `SECTION_FAILED`, `TRUNCATED_STREAM`, `RECORD_COUNT_MISMATCH`, `COLLECTOR_EXIT`, `UNMAPPED_DOMAIN`, …). A failing collector section never stops the others; it becomes a coverage gap.
* Repeated identical observations merge (`occurrences`); the same record with different attributes is a `conflict` (newest kept, differing attributes listed).
* `summary.complete` is true only with coverage on every category, nothing rejected and no errors.

## Input verification and provenance

Telemetry follows the rules in [security-model.md](security-model.md#input-integrity-and-provenance); the points specific to it:

**Three outcomes, not two.** *Verified*: a manifest exists and every file matched. *Unverified*: there is nothing to verify against (no `manifest.json`, or a bare file) and you explicitly accepted that. *Invalid*: a manifest exists and verification was attempted and **failed** (a file differs, a file is missing or not listed, the manifest is malformed, is of the wrong kind, is a symbolic link or does not match an expected digest, or a listed file is a symlink). Invalid data is refused under every option, including `--allow-unverified`, and a bare file addressed directly in a directory whose manifest fails is invalid too.

**`--allow-unverified` (library: `verify=False`) does exactly this, and nothing more.** It is accepted by every command that reads an input which can lack a manifest: `engine compare`, `engine report`, `engine run` (its `--compare` and `--history` inputs), `detect run`, `detect compare`, `detect report`, `detect show`, `detect export`, `telemetry import`, `telemetry show`, `telemetry query`, `telemetry tree`, `telemetry compare`, `telemetry report` and `telemetry hunt`. **One policy applies to all of them:** a *verified* input is accepted; an *unverified* input (a raw collector stream, a bare `telemetry.json` or detection-results file, a bare report, a directory without a manifest, a stored comparison) is refused (exit 3) unless `--allow-unverified` is given, and is then accepted and recorded as unverified; an *invalid* input is refused always. A lone file inside a directory whose manifest matches is verified by that manifest. Telemetry **stores** (directories written by `telemetry import`) always carry a manifest and have no opt-out at all. The one input that is trusted without a manifest is the stream `telemetry collect` captured in the same process (it is recorded as `(this run)`). Only the *unverified* case is accepted: an input with no manifest to check, or a bare file, is loaded and recorded as **unverified**, with the reason; an input that verifies is recorded as verified. An *invalid* input is refused (exit 3; in a `--history` directory it is skipped and listed in the notes; in `run --compare` it is reported as `comparison skipped` and the run exits 6). Malformed or schema-invalid data and symbolic links are refused too, the flag never applies to modules, plugin trust or the environment, and it cannot be combined with an expected manifest digest. Use it only for data you already trust, such as synthetic fixtures.

**Stored outputs and legacy tools.** A saved detection-results file read by `detect show|export|report` or `telemetry report --detections` is verified through its directory's manifest when it has one (a failing manifest is invalid, whatever the flag says); with no manifest it is refused unless `--allow-unverified`, and is then recorded as unverified. A provenance claim written inside such a file never makes it verified. **Case store:** `--state-dir` registers detections as cases, and each observation records whether the results it came from were `verified`, `unverified` or `unknown` (no provenance record, counted as unverified). A case is shown as verified only if *every* observation of it was; one unverified or unknown source makes it unverified for good, and a later verified observation does not undo that. Invalid data never reaches the store. **Legacy tools:** the `blueops-diff` / `blueops-detect` outputs (`baseline-diff`, `detections`, schema 0.2.0) keep their documented, input-form-independent format and so carry **no** provenance fields. Their loader verifies a run directory that has a manifest (a failing or symlinked manifest is refused), and for any input it could not verify (a bare report, a directory without a manifest, a saved `--from-diff`) it now prints an `UNVERIFIED` warning per input on **stderr**, which `--quiet` does not hide; stdout and `--output` files are unchanged. A pipeline that reads only stdout, or discards stderr, still sees no marker: for verified provenance use the engine commands.

Telemetry specifics:

* A **telemetry store** (`blueops-telemetry-*`) is verified against its `manifest.json` on every read (`show`, `query`, `tree`, `compare`, `hunt`, `detect run --telemetry`); there is no opt-out for stores.
* `telemetry import` and every command that reads telemetry apply the one policy above. A raw collector stream (`.jsonl`) or a bare `telemetry.json` has no manifest, so it is **refused unless `--allow-unverified`** (this changes the earlier behaviour, where such files were accepted and merely recorded as unverified), and is then recorded as **unverified** (`a bare file has no manifest`). To get a verified standing, import it once with `--allow-unverified` knowingly and keep the store, or collect with `telemetry collect` on the analysis host. A stream captured by `telemetry collect` in the same process is recorded as produced by this run.
* The resulting telemetry document, store, comparison, hunting results and the telemetry Markdown/HTML views carry `inputs` / `inputs_verified`. Importing a store keeps what the store recorded, so `inputs_verified: false` stays false through any number of re-imports, and a store's own manifest check does not clear it.

**Limits of a self-contained manifest.** The manifest sits next to the data it describes. It detects accidental corruption and changes that did not also rewrite the manifest; it does not stop someone who can write the directory from changing the data *and* the manifest. To close that gap, record the manifest's SHA-256 off the host when the run finishes and check it later with `engine verify DIR --expect-sha256 DIGEST` (library: `load_assessment(..., expected_sha256=...)`); the comparison, report, run and detection commands do not take a digest. `inputs_verified: true` therefore means "the files still match the manifest they came with", not "the data is true" or "the author is known".

**Residual time-of-check/time-of-use risk.** Verification hashes the files, then the loader reads `assessment.json` again; a process that can write the directory between the two can substitute data that was not hashed. Keep input directories owner-only (the tool creates them `0700`/`0600`), do not verify data in a directory other users can write, and copy untrusted data to a private location before loading it.

**Environment sanitization.** Modules and `telemetry collect` are started with an allowlisted environment, not a copy of the caller's (`shared/engine/environment.py`): locale, terminal and identity variables (`HOME`, `LANG`, `LANGUAGE`, `TZ`, `TERM`, `TMPDIR`, `USER`, `LOGNAME`, `NO_COLOR`, `LC_*`) and anything named `BLUEOPS_*` or `BO_*` pass; everything else does not, including secrets and the loader and interpreter hooks (`BASH_ENV`, `ENV`, `LD_*`, `DYLD_*`, `PYTHON*`, `PERL5*`, `RUBY*`, `NODE_OPTIONS`). The *names* of withheld hooks are reported on stderr, never their values. `PATH` is rebuilt from the system directories plus only those entries that are root-owned and not group/other-writable, and `pwsh`, `powershell` and non-absolute plugin commands are resolved through it.

**Exceptions and limits.** (1) With `BO_TEST_MODE=1` the given `PATH` is kept as it is; whoever controls the whole invocation can set it, and reports made that way say `test_mode`. (2) `BO_*` passes through, which includes the collectors' test hooks; the collectors ignore them unless `BO_TEST_MODE=1` and report when they were used. (3) The engine process itself, and the `blueops` launcher (a Bash script), run in the environment they were given: a `BASH_ENV` or `PYTHON*` variable set before they start affects them and cannot be defended against from inside. (4) On Windows the rule is a small denylist of .NET host-injection variables (`COR_*`, `CORECLR_*`, `COMPLUS_*`, `DOTNET_STARTUP*`, `DOTNET_ADDITIONAL*`, `__PSLOCKDOWNPOLICY`) and has **not been exercised on a Windows host**; it is not an allowlist.

`telemetry collect` also starts its collector with this environment, so variables the collector needs must be `BLUEOPS_*` or `BO_*`. Plugins are not involved in telemetry collection; see [plugins.md](plugins.md) for their trust rules and the breaking change for plugin environments.

## Known limitations

See [implementation-report-v0.6.md](implementation-report-v0.6.md#limitations). In short: Windows collector behavior is verified only by the Windows CI jobs; no process-integrity (signature/hash of running images), no memory or network-content analysis, no real-time collection (snapshots only), no multi-host correlation, authentication windows are bounded by `--since-hours`/`--max-events`, traditional syslog lines have no usable time, runtime service state is not collected on Linux, and rule false-positive rates are unknown outside synthetic data.
