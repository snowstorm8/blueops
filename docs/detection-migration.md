# Detection migration analysis: legacy diff detections vs. the detection engine

Status: analysis only. **Neither implementation is removed, merged or deprecated by this document.**
The tests that back every statement here are in `tests/shared/test_detection_parity.py`; they run
both systems on the same synthetic scenarios and pin what each does.

## The two systems

| | Legacy (`shared.reporting.detect` / `detection.py`) | Engine (`shared.rules`) |
|---|---|---|
| Input | a **baseline-diff** of two audit reports | an **assessment** (+ optional previous snapshots, history, telemetry) |
| Trigger | a *change* between the reports; "never on standing state" | mostly *standing state* (inventory, findings); 5 change rules, 9 correlation rules |
| Rules | 31 Python functions (`BO-<DOMAIN>-NNN`) | 29 JSON rules over assessments + 24 over telemetry (`DR-<OS>-<AREA>-NNN`) |
| Output | `detections` 0.x, ids `DET-...` | `detection-results` 0.x, ids `DT-...` |
| Severity | per *reason* (`observed` / `heuristic` basis), highest wins per subject | per *rule* with `severity_reason`, `confidence` + reason, explicit adjusters |
| Guidance | `investigate` steps, ATT&CK technique ids | investigation, remediation, references, false positives, ATT&CK `direct`/`possible` |
| Allowlisting | `--accepted` allowlist (scoped, expiring; matches move to `accepted`) | **none** (false positives are prose only) |
| Incomplete data | removals withheld, indeterminate records unused | rule listed as *indeterminate* when required coverage is missing |
| State | none | cases in an append-only file, history directory |

## What running both on the same data shows

The legacy suite has 49 scenarios that must alert (`FIRE`) and 14 benign ones that must not (`QUIET`).
Feeding each to the engine (current report as the assessment, baseline as the previous snapshot):

* The engine fires on **4 of the 49** alert scenarios: `BO-USR-001` (2 scenarios), `BO-USR-002` (empty password) and `BO-GRP-001` (sudo). It fires nothing on the other 45, and lists 8-10 rules as *indeterminate* for each (the scenario does not collect what those rules need), which is the intended behavior and not a defect.
* **Severity differs on identical data**: `BO-USR-001` is *critical*, `DR-LNX-ACC-001` is *high*.
* The engine alerts on **2 of the 14** benign scenarios where the legacy tool is silent: a second UID-0 account that was already in the baseline (standing state), and a privileged group member *removed* (`DR-ANY-PRIV-001` fires on any membership change).
* The engine has no accepted-change allowlist; replacing the legacy tool today would remove that capability. (`test_the_engine_has_no_accepted_change_allowlist` pins this and will fail, deliberately, when one is added.)
* This comparison is limited to what the legacy scenarios contain: inventory records. Engine rules that key on collector *findings* (`DR-LNX-SSH-001`, `DR-WIN-CRED-001`, ...) or telemetry cannot be exercised by them. Those are marked `partial` from reading the rule, not from observation.

## Rule-by-rule mapping

`predicate` = same condition, different semantics (state vs. change, different severity);
`partial` = overlaps but fires on a different trigger or a subset; `none` = nothing in the engine
(assessment or telemetry packs) covers it. **No legacy rule has a drop-in replacement.**
Totals: 1 predicate, 19 partial, 11 none (of 31).

| Legacy rule | What it detects | Legacy severity | Class | Engine rule(s) | Difference |
|---|---|---|---|---|---|
| `BO-USR-001` | Account other than root with UID 0 appeared | critical | **predicate** | `DR-LNX-ACC-001` | uid 0; standing state, high not critical |
| `BO-USR-002` | New local account | low/medium/high | **partial** | `DR-LNX-ACC-002` | only the empty-password part; no new-account rule |
| `BO-USR-003` | Service account given an interactive login shell | high | **none** | - | service account given a login shell |
| `BO-USR-004` | Disabled account was enabled | medium/high | **none** | - | disabled account enabled (needs a change) |
| `BO-USR-005` | Password requirement removed from an account | high | **partial** | `DR-WIN-ACC-001` | standing 'enabled without password'; not a removal |
| `BO-GRP-001` | Member added to a privileged group | critical | **partial** | `DR-ANY-PRIV-001` | sudo/wheel/admin only (no docker/lxd/disk); also fires on removal |
| `BO-PER-001` | SSH authorized key added | high/critical | **none** | - | authorized_keys additions are not in any assessment rule |
| `BO-PER-002` | Persistence mechanism added or its content changed | medium/high | **partial** | `DR-LNX-PER-001`, `DR-WIN-PER-001` | finding-based, standing |
| `BO-EXE-001` | Autostart or process runs from a temporary or world-writable location | medium/high | **partial** | `DR-WIN-SVC-001`, `DR-WIN-TSK-001`, `DR-ANY-COR-001` | Windows or finding-based |
| `BO-EXE-002` | Autostart command text matches a reverse-shell, download-and-execute or similar pattern | high | **partial** | `DR-ANY-HTSK-001` | needs telemetry |
| `BO-SCH-001` | New scheduled job | medium | **partial** | `DR-ANY-COR-003` | only in combination with account changes |
| `BO-SCH-002` | New scheduled task marked hidden | high | **none** | - | hidden scheduled task |
| `BO-SCH-003` | Command of an existing scheduled job changed | low/high | **none** | - | scheduled command changed |
| `BO-SVC-001` | New service | low/medium | **partial** | `DR-ANY-HCHG-002`, `DR-ANY-HSVC-002` | needs telemetry |
| `BO-SVC-002` | Existing service points at a different binary or runs as a more privileged account | low/high | **none** | - | service binary or account changed |
| `BO-SVC-003` | Cleartext remote-access service installed or started | medium | **partial** | `DR-LNX-SVC-001`, `DR-ANY-NET-001` | requires the service to be listening |
| `BO-SVC-004` | Logging or security service stopped, disabled or removed | varies | **partial** | `DR-ANY-COR-005`, `DR-WIN-LOG-001`, `DR-LNX-LOG-001` | finding-based |
| `BO-NET-001` | New listener reachable from the network | medium | **partial** | `DR-ANY-HCHG-001`, `DR-ANY-NET-001` | telemetry, or cleartext ports only |
| `BO-NET-002` | Listener owned by a netcat-style tool or on a port favoured by common payloads | medium/high | **partial** | `DR-ANY-HNET-001` | needs telemetry |
| `BO-NET-003` | A different process now owns an existing listener | low/medium/high | **none** | - | listener ownership changed |
| `BO-CFG-001` | Host firewall profile disabled or opened | high | **partial** | `DR-ANY-NET-002` | only with a listening management/data port |
| `BO-CFG-002` | Known hardening setting moved to its weak value | varies | **partial** | `DR-ANY-CHG-004` | generic long-stable setting; needs 3 snapshots |
| `BO-CFG-003` | New set-UID/set-GID file | medium | **none** | - | any new set-ID file |
| `BO-CFG-004` | New set-ID file is a shell-capable tool or lives in a temporary location | high | **partial** | `DR-LNX-FS-001` | temporary/user-writable locations only |
| `BO-CFG-005` | sudoers or PAM configuration added or changed | high | **none** | - | sudoers or PAM changes |
| `BO-CFG-006` | Antivirus exclusion added | high | **partial** | `DR-WIN-CRED-001` | finding-based, standing |
| `BO-CFG-007` | Hosts-file entry or DNS server added or changed | medium | **none** | - | hosts file or DNS |
| `BO-CFG-008` | SSH daemon setting weakened or redirected | varies | **partial** | `DR-LNX-SSH-001` | finding-based, standing |
| `BO-CFG-009` | New kernel module (flagged out-of-tree or unsigned is rated higher) | low/medium | **none** | - | kernel modules |
| `BO-CFG-010` | Linux host firewall opened (INPUT policy ACCEPT or rules removed) | high | **partial** | `DR-ANY-NET-002`, `DR-ANY-COR-002` | needs listeners / a new listener |
| `BO-FND-001` | Audit finding of high or critical severity appeared or escalated (engine-evaluated) | varies | **partial** | `DR-ANY-CHG-003`, `DR-ANY-CHG-001` | escalation only, not 'appeared' |


`BO-SCH-001`, `BO-SVC-001` and `BO-FND-001` have no scenario in the `FIRE` table (the legacy suite exercises them in other tests), so their rows rest on reading the rules, not on running both systems; the same is true of every `partial` row whose engine rule keys on findings or telemetry.

## Identifiers and output semantics

* Rule ids `BO-` vs `DR-`, detection ids `DET-` vs `DT-`; the two never collide (tested). No id mapping between a legacy detection and an engine detection exists or is attempted here.
* Legacy merges every rule that fires on one record into **one detection with several reasons** and links detections that share an artifact. The engine produces detections **per rule (per matched group)**, with correlation expressed as separate correlation rules; I did not compare how the two group records.
* Exit-code semantics follow the shared contract in both, but "alert" means different things (a change vs. a state), so a CI gate moved from one to the other will change behavior.

## Recommendation

**Coexist now; do not replace; no compatibility layer.**

1. *Not replace*: the engine covers 1 of 31 legacy rules on the same trigger and lacks the allowlist. Removing `reporting.detect` would silently drop capabilities, which the project rules forbid.
2. *No compatibility layer*: the two answer different questions (what *changed* vs. what *is*). A translator would have to turn diffs into assessments or back and would hide the semantic differences listed above. Keep one entry point per question and document which to use.
3. *Coexist with a stated rule of thumb*: baseline-vs-current review of a known-good host -> `diff` + legacy `detect`; assessment of a host with no trusted baseline, correlation, history, cases, telemetry -> the engine.
4. *Converge deliberately, later*, only when these hold (each is testable with the parity file): an accepted-change allowlist in the engine; change-triggered engine rules (or an explicit decision to drop) for the 11 `none` rules and the high-value `partial` ones (`BO-CFG-005`, `BO-PER-001`, `BO-SCH-003`, `BO-SVC-002`, `BO-NET-003`); agreed severity for UID-0 and privileged-group changes; the two benign-scenario divergences resolved or accepted. At that point mark `reporting.detect` deprecated for one release before any removal.

## Can the migration decision be made now?

The **coexistence** decision can: the evidence above is sufficient. A **replacement** decision cannot until the allowlist and the `none` rules are addressed; that is a feature gap, not a documentation gap. Nothing in this document changes behavior.
