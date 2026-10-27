# Detection rules (v0.3)

Status: **implemented** for Linux and Windows reports. Detection is **offline and read-only**: it consumes the structured output of the [baseline comparison](baseline-diff.md) (`baseline-diff` JSON, schema 0.2.0), applies a fixed catalogue of rules, and writes one report. It makes no network connections, reads no host, and never modifies its inputs.

```bash
python -m shared.reporting.detect BASELINE CURRENT [--format text|json] [--output FILE] [--min-severity LEVEL]
python -m shared.reporting.detect --from-diff diff.json          # reuse a saved `diff --json` document
python -m shared.reporting.detect --list-rules
```

`BASELINE`/`CURRENT` are the same report files or run directories the diff accepts (`--config`, `--ephemeral-from`, `--allow-host-mismatch` are passed to the comparison). Run it on an analyst machine (Python >= 3.9, standard library only).

## Why a rule layer on top of the diff

The diff answers *what changed*. During an incident the next question is *which of these changes should I look at first, and why*. A detection adds a severity, the reason in plain language, the supporting evidence and what to check next, without inventing new data: every rule reads one diff change (plus the set of accounts created in the same window) and nothing else.

## Output

Text (default) groups everything under one heading per detection. JSON conforms to `shared/schemas/detections.schema.json` (`kind: "detections"`). Each detection has:

| Field | Meaning |
|---|---|
| `id` | `DET-` + 10 hex digits derived from domain/scope/key: the same subject keeps its id across runs |
| `severity` | `info`..`critical`: the highest severity among its reasons. A **triage hint**, not a verdict |
| `basis` | `observed` or `heuristic` for the reason(s) that set the severity (below) |
| `subject` | `domain`, `scope`, `key`, `change` of the diff record |
| `reasons[]` | each rule that fired: `rule`, `severity`, `basis`, `observation` (what the data shows), `rationale` (why it matters, including benign explanations) |
| `before` / `after` / `attributes[]` | the record attributes and the exact attribute changes |
| `evidence[]`, `related_findings[]` | file/registry/socket references, and audit finding ids that already cover the same evidence |
| `correlated[]` | other detections that share an artifact (linked, not merged) |
| `techniques[]` | MITRE ATT&CK ids, for orientation only |
| `investigation[]` | read-only next steps |

The document also carries `coverage` (below) and a `summary`.

### Confirmed observation vs. heuristic suspicion

* **observed**: the report itself shows the condition: a UID 0 account exists, a group gained a member, a firewall profile is disabled, a service binary path changed. The *fact* is established; whether it is malicious still depends on authorisation.
* **heuristic**: a pattern that is common in attacks but also in legitimate software: a job that runs from `/tmp`, a listener on port 4444, a hidden scheduled task, a set-UID `find`. These are suspicions and the text says so.

A detection's `basis` follows the reason that sets its severity, so an `observed` medium fact that also matches a `heuristic` high pattern is reported as `high` / `heuristic`. Per-reason bases are always listed.

### No duplicate alerts

* Rules fire on **changes only**. Something already present in the baseline never alerts, and a state that did not change cannot be re-reported.
* All rules matching one record are merged into **one detection** with several reasons (a new hidden task from `Users\Public` is one detection with three reasons, not three alerts).
* Records that share an artifact (the same normalised path, or a listener whose process name equals the file name of a suspicious path) are **linked** through `correlated` so a campaign reads as a cluster rather than as unrelated alerts. They are not merged because each is a separate thing to remove.
* Audit findings that already cite the same file/registry evidence are listed in `related_findings`; the detection does not re-describe them.
* Transient changes (helper processes, ephemeral ports) never reach the rules.

### Coverage: when absence of detections means nothing

`coverage.complete` is false, and the exit code is `6` instead of `0`, when the comparison had partial or uncompared domains, indeterminate records, a report without inventory (schema 0.1), or a rule raised an error. `coverage.gaps`, `indeterminate` and `rule_errors` say why. Unverified attributes and indeterminate records are never evaluated, so a permission gap cannot produce an alert.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No detections and coverage complete |
| 4 | At least one detection at or above `--min-severity` |
| 6 | No detections, but coverage incomplete: **not** a clean bill of health |
| 3 | Reports or diff unreadable, malformed or not comparable |
| 2 | Usage error |
| 1 | Unexpected error, e.g. the output file already exists |

## Rule catalogue

`python -m shared.reporting.detect --list-rules` prints the same list. Severities are the defaults; the second column gives the adjustments.

| Rule | Basis | Fires on | Severity |
|---|---|---|---|
| `BO-USR-001` | observed | non-root account with UID 0 appeared (Linux) | critical |
| `BO-USR-002` | observed | new local account | medium; low if no login shell or disabled; high if no password required |
| `BO-USR-003` | observed | no-login account given an interactive shell | high |
| `BO-USR-004` | observed | disabled account re-enabled | high for built-in Administrator/Guest (RID 500/501), else medium |
| `BO-USR-005` | observed | password requirement removed / empty password | high |
| `BO-GRP-001` | observed | member added to a privileged group (`sudo`, `wheel`, `admin`, `root`, Administrators; weaker: `docker`, `lxd`, `disk`, `shadow`, Server/Account/Backup Operators, Remote Desktop Users) | high or medium by group; **critical** if the member was created in the same window |
| `BO-PER-001` | observed | new SSH authorized key (fingerprint only) | high; critical for `root` |
| `BO-PER-002` | observed | persistence entry added or its content changed | medium for a new Run/startup item; high for a changed entry or a high-risk mechanism (Winlogon, IFEO, accessibility, AppInit/AppCert, LSA, netsh, port monitors, time providers, WMI, BootExecute) |
| `BO-EXE-001` | heuristic | new job/service/persistence value (or process) runs from `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, or `Users\Public`, `AppData`, `Windows\Temp`, `Temp`, `$Recycle.Bin`, `PerfLogs` | high; medium for processes |
| `BO-SCH-001` | observed | new cron/at/scheduled task | medium |
| `BO-SCH-002` | heuristic | new scheduled task flagged hidden | high |
| `BO-SCH-003` | observed | command of an existing job changed | high; low if it moved *out of* a temporary location (looks like remediation) |
| `BO-SVC-001` | observed | new service | medium; low if disabled |
| `BO-SVC-002` | observed | service binary changed, or account changed to LocalSystem | high; low if the binary moved out of a temporary location |
| `BO-SVC-003` | heuristic | telnet/rsh/rlogin/rexec/tftp service installed or started | medium |
| `BO-SVC-004` | observed | logging/security service stopped, disabled or removed (`auditd`, `rsyslog`, `fail2ban`, `ufw`, `firewalld`, `eventlog`, `sysmon`, `windefend`, `mpssvc`, ...) | high for audit/event log/Sysmon/Defender/firewall core; else medium |
| `BO-NET-001` | observed | new listener reachable beyond loopback | medium |
| `BO-NET-002` | heuristic | new listener owned by `nc`/`ncat`/`socat`-style tool or on 4444/4445/1337/31337/6666/12345 | high; medium on loopback |
| `BO-NET-003` | observed | different process now owns an existing listener (not ephemeral) | high on well-known ports (22, 23, 80, 443, 445, 3389, 5985/6), else medium |
| `BO-CFG-001` | observed | firewall profile disabled or default inbound set to Allow | high |
| `BO-CFG-002` | observed | known hardening value weakened: UAC `EnableLUA`, `RestrictAnonymous`, `kernel.randomize_va_space`, `net.ipv4.ip_forward` | high or medium |
| `BO-CFG-003` | observed | new set-UID/set-GID file | medium |
| `BO-CFG-004` | heuristic | new set-ID file that is a shell-capable tool (`find`, `vim`, `python`, `bash`, ...) or sits in a temporary directory | high |
| `BO-CFG-005` | observed | sudoers or PAM file added or changed | high |
| `BO-CFG-006` | observed | antivirus exclusion added | high |
| `BO-CFG-007` | observed | hosts-file entry or DNS server added/changed | medium |

False-positive controls that are pinned by tests: a UID 0 account that was already in the baseline is silent; "tmp" as a path component (`/home/alice/tmp/x`) or a drive-less Windows fragment is not a volatile location; restoring a stopped security service, turning IP forwarding off, enabling a firewall, removing a group member and a new loopback-only listener are silent; a new no-login or disabled account is `low`, not `high`; ephemeral listener churn is never an alert.

## Expected behavior (regression matrix)

`tests/shared/test_detection.py` pins, on synthetic data only:

| Scenario | Expected |
|---|---|
| 27 synthetic scenarios covering all 26 rules | the rule fires with the documented severity and basis |
| 14 benign/unchanged scenarios and 3 ordinary-path cases | no detection (or no `BO-EXE-001`) |
| e2e `changed` fixture, Linux | 12 detections: 2 critical, 7 high, 3 medium; the exact keys, severities, bases and rules are listed in the test |
| e2e `changed` fixture, Windows | 10 detections: 1 critical, 9 high; the four records pointing at `Users\Public\upd.exe` are linked to each other |
| e2e `identical` and `churn` fixtures | no detections, coverage complete, exit 0 |
| e2e `unprivileged` and `module-failed` fixtures | no detections, `coverage.complete=false`, exit 6 |
| comparison reversed (remediation) | no heuristic alerts, no criticals; commands/binaries moved out of `/tmp` or `Users\Public` are `low` |
| shuffled input, other `PYTHONHASHSEED`/`TZ`/`LC_ALL` | byte-identical JSON |
| malformed diff, wrong kind or schema version, bad change entry | exit 3, nothing on stdout |
| a rule that raises | recorded in `coverage.rule_errors`; other rules still run; exit 4/6, never a crash |
| attacker-controlled escape sequences and newlines in values | shown as `\xNN` in text, cannot forge lines |
| inputs after the run; sockets/subprocesses | unchanged; none created |

## Limitations

* **Change-based only.** A backdoor that was already on the host when the baseline was taken is invisible to detection, and a host compromised before the baseline passes. Standing-state checks belong to the audit findings.
* **Only as good as the inventory.** Rules see the attributes the collectors record. Examples: Linux services carry no binary path (so `BO-EXE-001`/`BO-SVC-002` mostly help on Windows services and on cron/persistence), listeners carry a process name and not an executable path, and sudoers/PAM/startup files are compared by hash so the rule can say *changed* but not *what* changed.
* **Remediation is also a change.** Reverting a modification is reported as a modification (e.g. a restored `rc.local` shows as `BO-PER-002`); only the cases the rules can recognise as moving away from a temporary location are lowered to `low`.
* **Heuristics are lists.** Volatile paths, netcat-style tool names, payload ports, cleartext service names, set-ID tools and security services are short built-in lists. They can miss renamed tools and will flag portable or per-user installers (AppData is common for legitimate updaters).
* **No allowlist yet.** Accepted changes cannot yet be suppressed with a profile (planned with the baseline allowlists in [roadmap.md](roadmap.md)); use `--min-severity` for triage.
* **Account correlation is by name/SID.** Escalating "new account added to an admin group" needs both records in the same comparison.
* **ATT&CK ids are orientation, not classification.** A reasonable technique mapping is given; do not treat it as a coverage claim.
* A compromised host can lie to its own audit (see [security-model.md](security-model.md)); a clean detection run is not proof of integrity.

## Adding a rule

Add a function to `shared/reporting/detection.py` decorated with `@rule("BO-<AREA>-NNN", "<domain>", ...)`; the first docstring line is its catalogue summary. It receives one diff change and returns `Signal`s (use `_sig`), must treat all values as untrusted text, must say whether it is `observed` or `heuristic`, and must not fire on unchanged state. Then add: a firing scenario and at least one quiet (false-positive) scenario in `tests/shared/test_detection.py`, a row in the catalogue above, and a CHANGELOG line. IDs are never reused.
