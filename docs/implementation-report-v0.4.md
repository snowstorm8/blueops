# Implementation report: assessment platform (v0.4)

Scope: turn the existing collectors and comparison tools into a cohesive, extensible assessment platform. This report states what was found, what was built, what was run and what was **not** run.

## 1. Investigation (before any change)

| Finding | Consequence |
|---|---|
| The repository already had Linux (8 modules) and Windows (11 modules) read-only collectors, an inventory/baseline diff engine (`shared.reporting.diff`), 31 detection rules (`detect`), a run-manifest verifier, strict JSON input handling, 709 pytest cases, ~190 Bats cases and Pester suites. | Preserve all of it; build on top, not beside. |
| **There is no graphical or web UI.** "UI" before this work meant CLI text output (`report.txt`, `baseline_render.py` text). Nothing communicates with a backend over a network. | The "polished HTML interface" is a new, static, offline report (no server, no network). The only module "communication" is: collector process -> `report.json` on disk -> Python readers. |
| Findings were keyed by *check id* only (`USR-UID0-001`), had no host/component, no per-finding timestamp and no cross-run identity; evidence had no provenance back to a run. | Added a findings layer with stable identity and provenance without touching the collectors' output contract. |
| No orchestration: each module was selectable inside one collector invocation (`--modules`), with one global timeout (none) and one failure domain. | Engine runs one process per module with per-module limits. |
| No schema validation at run time in Python (jsonschema is dev-only; runtime is stdlib-only by policy). | Wrote a small validator for exactly the keywords the schemas use, tested for parity with `jsonschema`. |
| Technical debt noted, **not** fixed (out of scope): Windows collector code is only exercised on the Windows CI runner; `shared/reporting/detection.py` is a 2,000-line module; the Bash collector pays start-up per invocation. | Listed under next milestones. |

Baseline before changes (this environment, Python 3.13, Bats 1.10, ShellCheck 0.9, shfmt 3.8, ruff): **pytest 709 passed, 17 skipped**; **Bats all passing** (6 skipped because uid 0 cannot simulate permission failures); ruff and format clean; ShellCheck and shfmt clean. PowerShell/Pester was **not available** (see section 6).

## 2. What was built

| Area | Delivered | Where |
|---|---|---|
| Assessment engine | Registry of built-in and plugin modules; declarative plugin manifests with safety checks; dependency planning (auto-add, cycle and unknown-dependency errors, skip on failed dependency); runner with argv-only execution, no stdin, per-module timeout and process-group kill, strict JSON + schema validation of output; statuses `ok/partial/failed/timeout/invalid_output/skipped`; profiles; assessment directory (0700/0600, exclusive create, never reused) with SHA-256 manifest; CLI `list/run/compare/report/validate/verify` | `shared/engine/`, `profiles/` |
| Findings and evidence | `BOF-` finding ids and `EV-` evidence ids, host ids, deduplication/merge, remediation priority P1-P4, ATT&CK and NIST SP 800-53 references, provenance by module/run/check/report digest, input sanitising | `shared/findings/` |
| Comparison | New / resolved / persistent / severity up and down / evidence delta / configuration changes (via the existing inventory engine) / coverage differences / indeterminate with reasons / trend and weighted index; accepts assessments, run directories and old audit reports | `shared/reporting/snapshot_compare.py` |
| Reports | JSON (canonical), Markdown (escaped), self-contained responsive HTML with CSP | `shared/reporting/render_*.py` |
| Audit expansion | Linux `auth` (8 check ids: login.defs, password aging, four group-integrity checks, PAM quality and lockout) and `sysconfig` (7 check ids); Windows `eventlog` (4 checks) | `linux/audit/`, `windows/audit/` |
| Schemas | `assessment`, `snapshot-comparison`, `assessment-manifest`, `module-manifest`, `assessment-profile` (0.1.0); audit-report unchanged | `shared/schemas/` |
| Documentation | `assessment-engine.md` (architecture diagrams, interface, config, install, usage, testing), `findings.md`, `reporting.md`, `plugins.md` (module development), plus updates to architecture, contracts, security model, deployment, development, linux/windows audit docs, roadmap, README, CHANGELOG, CLAUDE.md | `docs/` |
| Examples | `examples/assessment.example.json`, `examples/plugins/` (working plugin) | `examples/` |

Design decisions and their alternatives are recorded in [architecture.md](architecture.md#decisions-assessment-platform). Compatibility: no existing flag, exit code, schema field or file layout was renamed or removed. Deliberate behaviour changes: the module lists grew (`--list-modules` 8 -> 10 on Linux, 11 -> 12 on Windows) and the Linux/Windows full audits gained new findings and inventory partitions (take a new baseline). Existing assertions were updated only for those counts (Bats `--list-modules`; Pester `-ListModules`, "every module contributes" and the dot-source list in `Common.Tests.ps1`); no assertion was relaxed or removed.

### Bugs found while testing (and fixed)

- Module directories were created with `exist_ok` logic comparing two fresh `Path` objects with `is`, so every module after the first failed; found by the real-collector integration test, fixed before the first commit.
- The loader accepted any `0.x` audit-report version although the diff engine only reads 0.1/0.2; found by reusing the existing `invalid/unknown-minor.json` fixture; now refused.
- `LB-06` ("no change means no detection") failed once the new Linux partitions existed because the synthetic host lacked `login.defs` and two `/proc/sys` files and the partitions were correctly reported `unavailable`; fixed by completing the fixture (the check itself is unchanged).
- Markdown code spans carried raw `<script>` text; angle brackets are now rendered as guillemets (the exact value stays in the JSON).

## 3. Test results

All numbers are from runs in this session on Linux (Python 3.13; the new Python tests were also run on **Python 3.9.25**, the project minimum, and passed).

| Suite | Result |
|---|---|
| pytest (`python -m pytest`, venv with pytest + jsonschema) | **978 passed, 17 skipped** (baseline 709 / 17). 269 new tests: engine registry/runner/assessment/CLI, findings, schema parity, snapshot comparison, golden regression, rendering, examples. |
| Bats (`bats --recursive tests/linux`, as root, via `scripts/development/check.sh`) | **221 ok, 0 not ok** (6 of them skipped by the tests themselves, see 3.1); baseline 187 |
| ruff check / ruff format --check | clean |
| ShellCheck / shfmt (all tracked `.sh`, `.bash`, `.bats` and the new files) | clean |
| Pester (`tests/windows`) | **NOT RUN** |
| PSScriptAnalyzer | **NOT RUN** |

### 3.1 Bats

221 cases pass, none fail. 6 report themselves as skipped because they need a non-root user or non-Linux host (uid 0 cannot simulate permission failures); that set is unchanged. 34 of the 221 are new (`tests/linux/audit-expansion.bats`). `scripts/development/check.sh` as a whole exited 0 with `pwsh` reported as "SKIPPED (tool not installed)".

### 3.2 Skipped tests (17 pytest)

Same 17 as before the work: 14 need PowerShell / a Windows host, 3 cannot be reproduced as uid 0. A skipped test is not a pass.

### 3.3 Manual checks (not automated)

HTML report opened in headless Chromium (Playwright): no console or CSP errors, severity filter and text filter work, "expand all" works, no horizontal overflow at 1280 px and 390 px, dark scheme renders, screenshots inspected. This was done by hand and is not part of the test suite.

## 4. Platform-specific limitations

- **PowerShell was not available.** I downloaded the official PowerShell release archive, but running it was blocked by the environment's permission policy; I did not work around that and deleted the archive. Consequences:
  - `windows/audit/Get-EventLogAudit.ps1` and its Pester file `tests/windows/EventLog.Tests.ps1` were written without ever being executed or linted. Static Python tests that scan the Windows sources (`test_windows_sources.py`, `test_rule_collector_contract.py`, `test_repo_layout.py`) pass, but they do not parse PowerShell. The first real execution will be the Windows CI runner; expect that it may need fixes.
  - The engine's Windows path is tested with a fake PowerShell resolver and fake executor (argument construction, platform handling, skip behaviour, report ingestion of a Windows-shaped report), **not** against a real `pwsh`/`powershell.exe`.
  - The Windows module-count assertions in Pester were edited by hand (11 -> 12, EVT prefix) and are likewise unrun.
  - The `eventlog` channel check addresses registry keys whose names contain `/`; whether the PowerShell registry provider handles that literally on all versions is unconfirmed (worst case: the check finds nothing).
- macOS and Windows runs of the *Python* tests were not performed here; tests that need bash, symlinks or POSIX permissions are marked to skip elsewhere, and the CI matrix (ubuntu and windows, Python 3.9 and 3.12) will exercise them.
- Linux tests ran as uid 0, so the "group/other-writable plugin" and "unreadable file" branches are exercised through modes and removed files, not through real permission denials.
- Everything was tested against synthetic fixtures; no real multi-distribution or real Windows host was assessed.

## 5. Incomplete items and known limits

- Windows `eventlog` and the Windows engine path: unverified (above).
- Audit-expansion requests not implemented: Windows local groups beyond Administrators/Remote Desktop Users, a Windows security-policy export (`secedit`), SMB/WinRM listener configuration; Linux installed-software inventory and container awareness. (Linux "package integrity" and "persistence indicators" already existed; Linux "users and groups", "authentication", "system configuration" were extended; Windows "scheduled tasks", "firewall", "registry security configuration", "persistence" already existed and were not changed.)
- Detection rules (`shared.reporting.detect`) are not yet run over assessments or snapshot comparisons; only the inventory diff is reused.
- No multi-host merge or fleet report; the HTML report describes one host.
- No parallel or resumable execution; module stdout/stderr files have no size cap (time-limited only).
- Plugin trust is by directory permission only; no signing. Windows ACLs on plugin directories are not checked.
- Standards mapping is coarse: NIST control families by category, ATT&CK ids as tagged by collectors; no CIS section numbers (deliberately).
- The weighted index is a trend aid, not a risk model.
- `shared/reporting/render_html.py` is exempt from the line-length rule (inline markup).

## 6. Recommended next milestones

1. **Windows verification** (smallest, highest value): run Pester on the Windows runner, fix `EventLog.Tests.ps1`/`Get-EventLogAudit.ps1`, add an engine smoke test on `windows-latest` (real `powershell.exe` and `pwsh`), confirm the `/` channel-key behaviour.
2. **Detections over assessments**: feed snapshot comparisons to the 31 rules and show detections in the report; allow accepted-change allowlists in profiles.
3. **Fleet view**: multi-host merge and a fleet HTML page (host ids already exist in finding identity).
4. **Coverage depth**: Windows local groups/secedit/SMB/WinRM; Linux software inventory, containers, `apk`/`pacman` integrity.
5. **Operational hardening**: opt-in parallelism with a load cap, stream size caps, resumable runs, signed plugin manifests.
6. **Release process**: checksummed release archive so "copy, verify, run" has a published digest.
