# Detection validation (v0.3.1)

Controlled, repeatable validation of the detection rules ([detection-rules.md](detection-rules.md)) **through the real collectors**, not just through hand-written reports. This document was written first: Part 1 fixes the expected outcome of every scenario before any scenario was run. Part 2 (results, false positives, false negatives, coverage) is filled in afterwards and is the only part allowed to differ from the plan, with every deviation called out.

## Method

* **Disposable environments only.** Each scenario copies a synthetic host fixture into a pytest temp directory, applies a *synthetic or benign* change to the copy, runs the real collector, and discards the copy. No scenario touches a live host, creates accounts, services, tasks or registry values on the machine running the tests, opens a port, or makes a network connection.
  * **Linux:** `tests/fixtures/linux-root` (a deliberately dirty synthetic root) + `tests/fixtures/linux-bin` command shims, collected by `linux/audit/audit-linux.sh` with `BO_ROOT`. Runs anywhere with Bash.
  * **Windows:** `tests/fixtures/windows-host` (CIM/registry/task data as JSON), collected by `windows/audit/Invoke-WindowsAudit.ps1` with `BO_FIXTURE_DIR`. Needs PowerShell; skipped without it and executed on the CI runners.
* **Pipeline under test:** collector `report.json` -> `shared.reporting.baseline.compare` -> `shared.reporting.detection.detect` (-> allowlist). Same code paths as the CLIs.
* **Reuse, no new framework.** Tests are ordinary pytest modules that import the helpers of `test_linux_baseline_e2e.py` and `test_windows_audit_report.py`; scenarios are rows in a table, assertions are plain `assert`.
* **Expected outcomes are data.** Each row states the detection key, the rule ids that must be among its reasons, its severity and its basis. "Benign" rows state a *ceiling* (no detection above a severity) instead.
* **Invariant checked on every run:** exit code 0 only if there are no detections *and* `coverage.complete`; the document validates against `detections.schema.json`; the run is deterministic (a second detect over the same diff is byte-identical).

## Part 1 - Expected outcomes (written before running)

### Linux, suspicious changes (baseline = clean fixture, current = fixture + one change)

| ID | Change applied to the copy | Expected detection (key) | Rules | Severity | Basis |
|---|---|---|---|---|---|
| LS-01 | `mallory:x:0:0` appended to `passwd`, `mallory` appended to group `sudo` | `user:mallory`; `group:sudo` | USR-001 (+USR-002); GRP-001 | critical; critical | observed; observed |
| LS-02 | new `etc/sudoers.d/91-ops2` | `config:sudoers:/etc/sudoers.d/91-ops2` | CFG-005 | high | observed, `unknown[]` non-empty |
| LS-03 | new `etc/cron.d/newjob` running `/tmp/x.sh` | `cron:/etc/cron.d/newjob#1` | SCH-001, EXE-001 | high | heuristic (top reason is heuristic) |
| LS-04 | second key appended to `root/.ssh/authorized_keys` | `persist:ssh_key:root:*` | PER-001 | critical | observed |
| LS-05 | `nc` listening on `0.0.0.0:4444` (ss shim) | `listener:tcp/0.0.0.0/4444` | NET-002, NET-001 | high | heuristic |
| LS-06 | `etc/rc.local` rewritten | `persist:file:/etc/rc.local` | PER-002 | high | observed, `unknown[]` non-empty |
| LS-07 | set-UID bit added to `usr/bin/find` | `config:suid:/usr/bin/find` | CFG-004, CFG-003 | high | heuristic |
| LS-08 | public-looking host entry in `etc/hosts` | `config:hosts:*` | CFG-007 | medium | observed |

### Linux, benign administration (ceiling: no high/critical unless listed as a known false positive)

| ID | Change | Expected |
|---|---|---|
| LB-01 | new service account with `nologin` shell | exactly one detection, `user:*`, USR-002, **low** |
| LB-02 | new cron job running `/usr/local/bin/backup.sh` | SCH-001 **medium**, no EXE-001 |
| LB-03 | internal hosts entry (`10.0.0.5 internal.example.test`) | CFG-007 **medium** at most |
| LB-04 | new unprivileged group `developers` with an existing user | no detection |
| LB-05 | existing user `bob` added to `sudo` | GRP-001 **high, not critical** (privilege change is worth review; `bob` is not new) |
| LB-06 | no change (second audit of the same root) | no detection |
| LB-07 | administrator edits existing `sudoers.d/90-ops` benignly | **known false positive FP-1**: CFG-005 high observed, `unknown[]` says direction/content unknown, resolvable with a hash-pinned accepted change |

### Linux, remediation (baseline = state with changes, current = repaired state)

| ID | Scenario | Expected |
|---|---|---|
| LR-01 | baseline = LS-01..LS-08 applied together, current = clean fixture | no critical, no heuristic detection; the only detection is `persist:file:/etc/rc.local` (PER-002, high, observed) - **known limitation FP-2**: a restored hash looks like a modification |
| LR-02 | cron command moved from `/tmp/x.sh` to `/usr/local/bin/x.sh` | SCH-003 **low**; nothing high |
| LR-03 | listener on 4444 changes owner from `nc` to `sshd` | NET-003 **low** with "remediation" in the summary |
| LR-04 | baseline already contains the compromise (the dirty fixture: `toor` UID 0, backdoor cron, `nc` on 9999) and nothing changes | **known false negative FN-1**: no detection (change-based); the baseline audit itself still reports findings |

### Linux, accepted changes (current = LS-01 + LS-02 + LS-06 together)

| ID | Allowlist | Expected |
|---|---|---|
| LA-01 | hash-pinned entry for `rc.local` | only that detection moves to `accepted[]`, unchanged; the others remain; exit 4 |
| LA-02 | same entry, wrong hash | nothing accepted (`not_applied` / no match) |
| LA-03 | entry for a neighbouring key (`/etc/sudoers.d/90-ops`, not `91-ops2`) | nothing accepted; entry `unused` |
| LA-04 | entry for `user:mallory`, `max_severity: high` | critical `user:mallory` stays; reason `severity above max_severity`; `max_severity: critical` is refused at load |
| LA-05 | entry that expired before the run | nothing accepted; status `expired` |
| LA-06 | accepting all non-critical detections with exact entries | `accepted[]` holds exactly them, evidence identical to the run without allowlist, critical ones still reported, exit 4 |

### Linux, coverage

| ID | Scenario | Expected |
|---|---|---|
| LC-01 | current audit cannot run `ss` (forced missing) while a listener change exists | no listener detection (it cannot be seen), `coverage.complete=false` with a `listeners` gap, **exit 6, never 0** |
| LC-02 | LC-01 plus the LS-01 account change | LS-01 detections reported, `complete=false`, exit 4 |
| LC-03 | invariant on every Linux run | exit 0 only if `complete` and no detections |

### Windows (real PowerShell collector over a mutated fixture copy; one shell)

| ID | Change applied to the fixture copy | Expected |
|---|---|---|
| WS-01 | new local user added to Administrators (`cim.Win32_UserAccount`, `group.administrators`) | `group:S-1-5-32-544` **critical** GRP-001 (new account is privileged) and the new user USR-002 |
| WS-02 | `HKLM\...\Run` value pointing to `C:\Users\Public\upd.exe` | persistence detection with EXE-001, **high, heuristic** |
| WS-03 | new hidden scheduled task running from `C:\Users\Public` | SCH-001/SCH-002/EXE-001, **high** |
| WS-04 | benign: new service under `C:\Program Files\Acme` | SVC-001 **medium**, nothing high |
| WS-05 | benign: new ordinary enabled user requiring a password | USR-002 **medium**, nothing high |
| WS-06 | remediation: baseline = WS-02 + WS-03 applied, current = clean | no detection above **low**, no heuristic detection |
| WS-07 | coverage: baseline full audit, current `-Modules users` | domains not collected are gaps, `complete=false`, **exit 6 (never 0)** |

### Recorded up front as out of scope

* Mutating a **live** host (creating real accounts, tasks, services, registry values, listeners) even on a disposable CI runner: rejected in this PR because the failure mode is a mutated machine; the fixture-copy approach tests the same rules through the same collectors.
* The Windows rows for allowlists (platform-neutral logic, covered by LA-* and the unit tests) and a Windows set-ID/SUID equivalent (not applicable).
* Kernel/runtime effects (PIDs, ports) beyond what the collectors read from the fixture.

## Part 2 - Results

_To be filled in after the scenarios are run._
