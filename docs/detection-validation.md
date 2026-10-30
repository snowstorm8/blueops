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

Run on 2026-10-27. Linux: 31 scenario tests in `tests/shared/test_detection_validation_linux.py`, run locally (macOS, Python 3.14; the set-ID scenario is skipped there) and on `ubuntu-latest` (Python 3.9 and 3.12, all scenarios). Windows: 6 tests in `tests/shared/test_detection_validation_windows.py`, which could **not** be run locally (no PowerShell); they ran on `windows-latest` (Python 3.9 and 3.12) and on `ubuntu-latest` with `pwsh`, and all passed. Only the first available shell (`pwsh`) is used per run.

### Outcome against the plan

| Area | Planned | Result |
|---|---|---|
| Suspicious (LS-01..08) | all fire with the stated rules, severity, basis | **7 of 8 as planned. LS-04 failed: a real false negative, fixed (below).** Key naming in the plan was also wrong for `rc.local` and cron (cosmetic, see D1) |
| Benign (LB-01..07) | nothing above the stated ceiling | **as planned, except LB-07 whose premise was wrong (D4).** One high that is a benign change remains: FP-1 |
| Remediation (LR-01..04) | reversal is quiet or low | LR-01, LR-03, LR-04 as planned. **LR-02 differs** (D5): medium, not low |
| Accepted changes (LA-01..06) | suppress only exact approved matches | **as planned**; wrong hash, neighbouring key, expired, wrong rule, higher severity and critical all suppress nothing; evidence identical |
| Coverage (LC-01..03) | never a clean bill of health | **as planned after the scenario was redesigned (D3, D6)**; two scenarios added (LC-03, LC-04) |
| Windows (WS-01..07) | as in the plan | **all six tests passed on first CI run** (WS-01..03 share one attacked audit, WS-04/05 one benign audit) |

### Re-run with the detection-correctness fixes (PR #14)

The scenarios were re-run unchanged on the branch that combines this validation with PR #14 (27 rules, including `BO-FND-001`, the high-port listener rules, the ASLR record and the Windows `ip_forward` rule).

* Python suite as a non-root user (what the CI runners are): 538 passed, 13 skipped (PowerShell/Windows-only), 0 failed. All 31 Linux scenarios, including LC-03/LC-04, LA-* and the collector-format `BO-PER-001` scenario, pass against the combined rules.
* Bats: 137 ok, 0 failed, 6 skipped. ShellCheck, shfmt and ruff are clean.
* Applying the seven attack mutations of the Linux scenarios together with an `nc` listener on 4444 yields 11 detections (3 critical, 7 high, 1 medium) and no `finding:*` detection: the `PER-CRON-002` audit finding is absorbed by the equally severe cron detection, so `BO-FND-001` adds no duplicate here.
* LC-03/LC-04 need a non-root user: as uid 0 the collector reads every file and reports no permission gap, so those two tests fail when run as root (containers, `sudo pytest`). This predates the integration.
* The Windows scenarios (WS-*) were **not** run: they need PowerShell. See "Platform coverage".

### Deviations from the plan

* **D1 - key naming.** The plan used the synthetic forms. The Linux collector emits `persist:startup:/etc/rc.local`, `cron:<file>#<hash of the line>` and `persist:ssh-authkey:<owner>:<id>`. Tests use the real keys.
* **D2 - false negative found and fixed (LS-04).** `BO-PER-001` only matched `persist:ssh_key:<user>:...` with a `user` attribute, a form no collector emits. A new `root` authorized key was therefore reported only by the generic `BO-PER-002` at **medium** instead of **critical**. The rule now matches both key forms and reads `owner` or `user`; `test_detection.py` gained a scenario using the collector's real record. The integrated implementation is the one from PR #14 (detection-correctness fixes): it additionally falls back to the owner in the key's own segment and leaves *changed* key records to `BO-PER-002` (high), so editing the options or file of an existing key is still reported.
* **D3 - unprivileged runs are partial.** The Linux collector marks four persistence partitions `partial` when not root, so even an unchanged host exits 6. The tests add an `id` shim (the same test-double mechanism as the existing `ss` shim) so the main scenarios run as an operator would, and LC-03/LC-04 cover the real unprivileged case: a key added in a partial partition is `indeterminate`, not detected, and the run exits 6.
* **D4 - Linux sudoers is not hash-only.** It is inventoried one rule per record (`config:sudoers:<file>#<hash>` with `file` and `rule`). A comment-only edit is correctly silent; a new or changed rule is an `added` record with readable content (`unknown[]` empty). The hash-only `unknown[]` text applies to PAM, startup, systemd and shell files (verified for `rc.local`).
* **D5 - editing a cron line is a new job.** Cron records are keyed by the line's content, so a repair is "remove + add": the repaired job is `BO-SCH-001` medium, never the `BO-SCH-003` low the plan expected. `BO-SCH-003` can only trigger for Windows tasks, where the task name is the key.
* **D6 - LC-01 redesigned.** With `ss` missing the collector falls back to `/proc/net` without process names (listeners `degraded`), so the original scenario never contained the listener. The test now audits the baseline with `ss` and the current host without: the listener owners become indeterminate, `complete=false`, exit 6.
* **D7 - platform.** LS-07 (set-ID bit) needs GNU `stat`; BSD `stat` on macOS does not report the bit, so it is skipped there and runs on Linux CI.

### False positives (documented, not fixed)

| ID | Where | What | Mitigation |
|---|---|---|---|
| FP-1 | `BO-CFG-005` | any new sudoers rule is `high`, including a narrow password-protected rule for an ops group; any PAM file hash change is `high` | investigate; accept with an exact entry (rule, key, optional hash pin, expiry). A rule-content-aware grading is possible future work |
| FP-2 | `BO-PER-002` | a restored startup/systemd/shell file shows as a modification (a hash has no direction) | `unknown[]` says so; accept with a hash-pinned entry |
| FP-3 | `BO-SCH-001` | repaired or edited cron lines are reported as a new job (medium) | below high by design |
| FP-4 | `BO-CFG-007`, `BO-USR-002` | an internal hosts entry is medium; a new service account is low | ceilings asserted by LB-01/LB-03 |
| FP-5 | `BO-GRP-001` | promoting an existing user into `sudo` is high (not critical) | intended: a privilege change deserves review |

### False negatives (documented)

| ID | Gap | Evidence |
|---|---|---|
| FN-1 | compromise already present in the baseline is never reported (change-based) | LR-04: the dirty fixture yields standing-state findings but no detections |
| FN-2 | unprivileged Linux audit cannot read other users' keys etc.; additions in partial partitions are indeterminate | LC-04: not detected, exit 6, never exit 0 |
| FN-3 | (fixed) Windows `config:ip_forward` (`enabled`) was not evaluated by `BO-CFG-002` (it read Linux-style `value`) | closed by PR #14: `BO-CFG-002` now reports `enabled` false to true (medium, observed); the former pin in `test_detection.py` is replaced by `test_detection_regressions.py::test_windows_ip_forwarding_*` |
| FN-4 | Linux services carry no binary path, so `BO-EXE-001`/`BO-SVC-002` cannot see a replaced service binary | inventory limitation, see detection-rules.md |
| FN-5 | listener owner names need `ss`/root; without them rules on process names are blind | LC-01: the run is incomplete (exit 6), not clean |
| FN-6 | (fixed) new root SSH key reported as medium | D2 |

### Platform coverage

| | Linux | Windows |
|---|---|---|
| Real collector exercised | yes (`audit-linux.sh`, all modules) | yes (`Invoke-WindowsAudit.ps1`, all modules; PowerShell 7) |
| Disposable environment | temp copy of `linux-root` + shims | temp copy of `windows-host` |
| Suspicious / benign / remediation / coverage | 8 / 7 (+1) / 4 / 4 | 3 / 2 / 1 / 1 |
| Allowlist | 6 scenarios | not repeated (platform-neutral logic) |
| Locally verified | yes, except set-ID on macOS | no, verified on CI only |

### Limitations of this validation

* Data is synthetic and the environments are fixture copies, not real hosts: kernel, service-manager and registry behaviour is not exercised, only what the collectors read. No live mutation was done (see "out of scope").
* The `id` and `ss` shims model an operator and a listener; real `ss`/`systemctl` output formats are covered by the existing collector tests, not re-validated here.
* Windows runs use one shell; Windows PowerShell 5.1 is covered by the existing report-schema tests, not by these scenarios.
* One rule set version: 27 rules. The 26 per-change rules are what these scenarios were written against; `BO-FND-001` (new or escalated high/critical audit findings, added by PR #14) reads the diff's findings and is covered by `tests/shared/test_detection_regressions.py` and `tests/shared/test_rule_collector_contract.py`, not by a scenario here. Scenarios pin severities, so a deliberate severity change must update this document and the tests together.
