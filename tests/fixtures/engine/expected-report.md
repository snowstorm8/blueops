# BlueOps assessment report

_Generated 2026-03-09T00:00:00Z_

> **WARNING - UNVERIFIED INPUTS. At least one input was not checked against a manifest \(--allow-unverified\), so its content may have been altered. Treat the results below as unverified until the inputs are checked another way.**

> Read-only assessment. For systems you are authorized to administer. Findings are leads for investigation, not verdicts.

## Executive summary

**Immediate attention required**

- 3 finding\(s\) on gold01 \(Synthetic 1\): 1 critical, 1 medium, 1 low.
- 1 finding\(s\) need immediate action \(P1\) and 1 soon \(P2\).
- 2 of 2 module\(s\) produced results; 0 did not finish cleanly.
- Compared with the previous snapshot: 1 new, 2 resolved, 2 persistent finding\(s\); trend: worse.

## Assessment metadata

| Field | Value |
|---|---|
| Assessment id | `golden-current` |
| Profile | test |
| Started | 2026-03-08T10:00:00Z |
| Finished | 2026-03-08T10:00:00Z |
| Status | complete |
| Exit code | 4 |
| Fail threshold | medium |
| Engine | blueops-engine 0.4.0 |

## Input provenance

**Not all inputs were verified.**

| Document | Role | Input | Status |
|---|---|---|---|
| assessment | source | `tests/fixtures/engine/current.assessment.json` | **UNVERIFIED** - a bare file has no manifest, so it cannot be verified |
| comparison 1 | baseline | `tests/fixtures/engine/baseline.assessment.json` | **UNVERIFIED** - a bare file has no manifest, so it cannot be verified |
| comparison 1 | current | `tests/fixtures/engine/current.assessment.json` | **UNVERIFIED** - a bare file has no manifest, so it cannot be verified |

## Host

| Field | Value |
|---|---|
| Hostname | gold01 |
| Operating system | Synthetic 1 \(linux\) |
| Architecture | x86\_64 |
| User | unknown |
| Privileged | yes |

## Severity distribution

| Severity | Count |  |
|---|---|---|
| critical | 1 | `#######` |
| high | 0 | `` |
| medium | 1 | `#######` |
| low | 1 | `#######` |
| info | 0 | `` |

## Module results

| Module | Status | Findings | Seconds | Note |
|---|---|---|---|---|
| `linux.users` | ok | 3 | 0.5 |  |
| `linux.network` | ok | 0 | 0.5 |  |

## Remediation priorities

### P1 - Act now: probable compromise or serious exposure

- **critical** Non-root account with UID 0 (`USR-UID0-001`): Review USR-UID0-001 and remediate.

### P2 - Fix soon: material weakness or likely misuse

- **medium** System accounts with interactive shells (`USR-SHELL-001`): Review USR-SHELL-001 and remediate.

### P3 - Plan: hardening gap or lower-confidence signal

- **low** A new weak setting (`USR-NEW-001`): Review USR-NEW-001 and remediate.

## Findings

### users (3)

#### CRITICAL - Non-root account with UID 0

- Id: `BOF-915e4a45caefe294`  Check: `USR-UID0-001`  Confidence: high  Priority: P1
- Component: users on gold01
- Detected: 2026-03-08T10:00:00Z
- Description: Synthetic finding for the golden regression files.
- Remediation: Review USR-UID0-001 and remediate.
- Standards: NIST SP 800-53 Rev. 5 AC-2, NIST SP 800-53 Rev. 5 AC-6
- Evidence: `EV-0ddfdf1f81616380`, `EV-9d31a1da3ba12231`

#### MEDIUM - System accounts with interactive shells

- Id: `BOF-1a8f1be75c9c94ac`  Check: `USR-SHELL-001`  Confidence: high  Priority: P2
- Component: users on gold01
- Detected: 2026-03-08T10:00:00Z
- Description: Synthetic finding for the golden regression files.
- Remediation: Review USR-SHELL-001 and remediate.
- Standards: NIST SP 800-53 Rev. 5 AC-2, NIST SP 800-53 Rev. 5 AC-6
- Evidence: `EV-0ddfdf1f81616380`

#### LOW - A new weak setting

- Id: `BOF-48752e7330551e3f`  Check: `USR-NEW-001`  Confidence: high  Priority: P3
- Component: users on gold01
- Detected: 2026-03-08T10:00:00Z
- Description: Synthetic finding for the golden regression files.
- Remediation: Review USR-NEW-001 and remediate.
- Standards: NIST SP 800-53 Rev. 5 AC-2, NIST SP 800-53 Rev. 5 AC-6
- Evidence: `EV-c50723f1b37edbbe`

## Evidence index

| Id | Type | Reference | SHA-256 (prefix) | Collected by |
|---|---|---|---|---|
| `EV-0ddfdf1f81616380` | file | `/etc/passwd` |  | linux.users |
| `EV-9d31a1da3ba12231` | file | `/etc/passwd.bak` |  | linux.users |
| `EV-c50723f1b37edbbe` | file | `/etc/login.defs` |  | linux.users |

## Historical comparison

### 2026-03-01T10:00:00Z -> 2026-03-08T10:00:00Z

Trend: **worse**; weighted index 20 -> 19 (-1).

| New | Resolved | Persistent | Severity up | Severity down | Config changes | Indeterminate |
|---|---|---|---|---|---|---|
| 1 | 2 | 2 | 1 | 0 | 4 | 0 |

**New**

- low: A new weak setting (`USR-NEW-001`)

**Resolved**

- high: Login-capable account with empty password (`USR-PWD-001`)
- medium: Exposed legacy service (`NET-LISTEN-001`)

**Severity changed**

- critical: Non-root account with UID 0 (`USR-UID0-001`)

**Persistent findings with changed evidence**

- critical: Non-root account with UID 0 (+1 / -0 evidence)


## Errors and warnings

None.
