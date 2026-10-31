# Audit remediation record

Status of every finding from the engineering and security audit of BlueOps (v0.3), re-evaluated against the code after PRs #13 and #14 and then remediated. Each item says what was verified, what changed, where it is tested, and what remains. Nothing here is a claim about hosts: all verification used synthetic fixtures and disposable copies.

Legend: **Resolved (PR)** already fixed by a merged PR and not re-implemented · **Fixed** changed in this remediation · **Documented** deliberately not changed (reason given) · **Open** not resolved.

## P0 (resolved earlier)

| ID | Finding | Status | Evidence |
|---|---|---|---|
| P0-1 | New process in the high-port listener bucket invisible (`nc` on 44444) | Resolved (PR #14) | `test_detection_regressions.py::test_netcat_on_a_high_port_*`. Residual: same name on a new high port is indistinguishable from port churn; mitigation `fixed_ports` ([detection-rules.md](detection-rules.md#limitations)) |
| P0-2 | `BO-PER-001` never matched the collector's SSH key records | Resolved (PR #14, #13) | `test_detection_regressions.py` (P0-2), `test_rule_collector_contract.py` |
| P0-3 | Rule layer ignored `diff["findings"]` | Resolved (PR #14) | `BO-FND-001`, `test_detection_regressions.py` (P0-3) |
| P0-4 | ASLR record not emitted; Windows `ip_forward` not read | Resolved (PR #14) | contract test + `tests/linux/inventory.bats`. Extended here with four more kernel sysctls |

## P1: detection and inventory

| ID | Finding | Status | Change and tests |
|---|---|---|---|
| P1-1 | Command text of cron/job entries not analysed by the rules | **Fixed** | `BO-EXE-002` (`detection.py`: `COMMAND_PATTERNS`, input capped at 2000 chars). Tests: `test_remediation.py` (25 attack and 13 benign commands, regex-time bound), real-collector cron tests in `test_rule_collector_contract.py` |
| P1-2 | Suspicious-command patterns missed `ncat --exec`, `nc \| sh`, `bash <(curl)`, perl/pty shells | **Fixed** | `bo_suspicious_reasons` (`linux/lib/common.sh`); positive and negative corpora in `tests/linux/hardening.bats` |
| P1-3 | Linux secret redaction gaps | **Fixed** (residual documented) | `bo_redact`: URL credentials, `Authorization`, `curl -u`, `sshpass -p`, mysql `-pX`; sudoers `NOPASSWD:` no longer mangled. Windows `Protect-BoText` gained URL and `curl -u` rules. Residual: stdin/here-strings/files/positional secrets cannot be pattern-detected ([security-model.md](security-model.md)) |
| P1-4 | Missing standing-state checks | **Fixed** (see list) | sshd settings (`NET-SSHD-*`), `ld.so.conf` (`PER-LDCONF-001`), kernel hardening sysctls (`NET-SYSCTL-001`), loaded kernel modules (`SYS-KMOD-001`, `BO-CFG-009`), host firewall (`NET-FW-*`, `BO-CFG-010`), auditd rules (`PER-AUDITD-001`), systemd enablement/symlinked units, `cron.allow/deny`. Tests: `tests/linux/coverage-gaps.bats`, `test_remediation.py`. **Open:** the rule layer stays change-based; a baseline-free detection mode is on the roadmap |
| P1-5 | Process inventory keys too coarse (`process:<user>:<comm>`) | **Documented** | Not changed. Comparing instance counts or command lines would turn every restart into an alert (they are volatile on purpose); a masquerading binary still shows as an extra `exe` value. See [detection-rules.md](detection-rules.md#limitations) |
| P1-6 | Hash-only persistence records | **Fixed** (partly by design) | Line count and per-line fingerprints (no text, <= 200 lines) on persistence files; `BO-PER-002` states lines added/removed. Content is deliberately not stored (it may hold secrets). Residual: what the added lines *say* is unknown |

## P2: security and integrity

| ID | Finding | Status | Change and tests |
|---|---|---|---|
| P2-1 | No integrity metadata | **Fixed** (residual documented) | `manifest.json` on both platforms; `shared/reporting/{manifest,verify}.py`; loaders refuse a mismatching run directory. Tests: `test_remediation.py` (tamper, planted/missing file, symlink, rewritten manifest with off-host digest), real-collector manifest tests, `Hardening.Tests.ps1` (CI only). Residual: the manifest cannot vouch for itself without an off-host digest |
| P2-2 | Windows run directory collision overwrote evidence | **Fixed** (not executed here) | `Write-BoRunDirectory` suffix loop; static test + Pester (`Hardening.Tests.ps1`) |
| P2-3 | TSV row injection through newline-containing process data | **Fixed** | `bo_tsv_field`, process collector, persistence `hits.tsv`; `hardening.bats` (forged `pid 999 sshd` row, tab in `comm`) |
| P2-4 | Lossy JSON encoding (`?`) | **Fixed** | Linux `_bo_escape_bytes`; Windows `ConvertTo-BoSafeString` (injective, literal `\uXXXX` escaped first); `hardening.bats`, Pester |
| P2-5 | Test hooks active in production | **Fixed** | `BO_TEST_MODE=1` required; ignored + `TEST_HOOKS_IGNORED` otherwise; `host.test_mode`; `TEST_MODE` warning in comparisons. Tests: `hardening.bats`, `test_windows_sources.py`, Pester. Residual: an attacker owning the whole invocation can set the flag; the report then says so |
| P2-6 | Tools resolved through an untrusted `PATH` | **Fixed** | Linux `bo_sanitize_path` (test: writable/relative/missing entries dropped, planted `df` never run); Windows System32 full paths (static test found a fourth, `net.exe`) |
| P2-7 | Insufficient JSON input validation | **Fixed** | `shared/reporting/jsonio.py` used by reports, diffs, allowlists, configs, manifests; saved-diff key length cap. Tests: deep nesting, duplicate keys, `NaN`, oversize, bad UTF-8 through every CLI (exit 3, no traceback) |

## P3: reliability and coverage

| ID | Finding | Status | Notes |
|---|---|---|---|
| P3-1 | `--package-integrity` is dpkg-only | **Fixed** (partly) | `rpm -Va` backend (`bats`: content/config/metadata classification). **Open:** apk and pacman (no read-only verify with comparable semantics; documented) |
| P3-2 | MD5 baseline of dpkg | **Documented** | Cannot be fixed on the host: the lists are root-writable plain text. The finding text, [linux-audit.md](linux-audit.md) and [security-model.md](security-model.md) state the limit; rpm uses the package's own (SHA-256) digests |
| P3-3 | Exit-code precedence (4 hides gaps) | **Documented** | Behaviour unchanged on purpose (callers gate on 4); precedence written down in [contracts.md](contracts.md); gaps are never hidden, they are in `errors[]` / `coverage` |
| P3-4 | IPv6 parsing and loopback detection | **Fixed** | `_net_hexaddr` (RFC 5952, compared with Python `ipaddress` while developing), `is_loopback_address` (parsed, replaces prefix matching in both languages); `hardening.bats`, `test_remediation.py` |
| P3-5 | CI coverage gaps | **Fixed** (partly) | Added: manifest verification smoke step, new test modules run in the existing jobs. **Open:** Bash 4.2/Alpine job (cannot be verified without a container runtime here), coverage measurement (new dev dependency), action pinning by SHA (needs network lookup of commit SHAs) |
| P3-6 | Documentation caveats and inconsistencies | **Fixed** | security-model residual risks, contracts, deployment, development, linux/windows guides, rule catalogue (31 rules), baseline-diff warnings |

## Previously unreviewed areas

| Area | Result |
|---|---|
| Linux `users` module | Reviewed. Found and fixed: `#includedir` treated as a comment, `Defaults`/aliases never inventoried, primary-group privilege invisible, `NOPASSWD: ALL` shown as `NOPASSWD: <redacted>` |
| Linux `services` module | Reviewed; no defect. Open (documented): services carry no binary path, so a replaced service binary is seen only through the unit file hash |
| Linux `system` module | Reviewed. Added kernel module inventory |
| Linux `pam` module | Reviewed. Found and fixed: backslash-continued rules hid `pam_permit`; module files were not hashed |
| Windows collectors | Reviewed statically (no PowerShell could be run): four PATH-resolved native calls, hook handling, run directory, lossy text. Verified read-only by `test_windows_sources.py`. **Open:** runtime behaviour on a real Windows host is unverified until CI runs `Hardening.Tests.ps1` |
| `docs/windows-audit.md` | Reviewed; corrected. It disclosed that Authenticode checks may use the network; recorded as a residual risk |
| Example allowlist | Tested end to end: matches only its own subject, expires on 2026-06-01 (so it accepts nothing today and must be copied and renewed), and does not apply to another host family |
| JSON schema consistency | `test_schemas.py`: all schemas valid, versions agree across Bash, PowerShell and Python, examples validate, host block fields pinned |

## Follow-ups from the integration review of PR #13/#14

| Finding | Status |
|---|---|
| One added SSH key reported as four unrelated detections (accounts sharing `/root`) | **Fixed**: detections for the same key are linked through `correlated` (`test_remediation.py`) |
| `LC-03`/`LC-04` fail as uid 0 | **Fixed**: skipped when run as root, with the reason |

## Found while remediating

`bo_redact` hid sudo rule contents · `manifest.json` was created `0644` because a redirection ran before the subshell's `umask` (caught by a test) · a fourth PATH-resolved Windows call (`net.exe`) · several `IFS=$'\n\t'` word-splitting traps in new Bash code (caught by tests) · a `NO_MANIFEST` warning would have broken the "same output for a report and its run directory" contract, so manifest-less runs load silently.

## Not verified

* Everything PowerShell: Pester (including the new `Hardening.Tests.ps1`), PSScriptAnalyzer, and the changed `.ps1` files were not executed in this session (the sandbox did not allow running a PowerShell interpreter). They are covered by static tests and by CI.
* Real hosts, other distributions (RHEL-family, Alpine, SUSE), big-endian hosts for `/proc/net/tcp6`, and Bash 4.2 (only the current Bash was exercised).
