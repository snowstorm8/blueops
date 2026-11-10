# Assessment engine

`python -m shared.engine` turns the platform collectors into one assessment: it runs a **profile** (a named list of **modules**), validates what each module returns, merges the results into a single **assessment** document with centrally managed findings and evidence, and renders reports. It is the layer that makes BlueOps a platform instead of a set of scripts.

> **Status:** implemented and tested on Linux (Bash collectors, real runs against synthetic fixtures). The Windows wiring is unit-tested with a fake PowerShell resolver but has **not been run against a real PowerShell** in development; see [Limitations](#limitations).

## Architecture

```mermaid
flowchart LR
    subgraph Host["audited host (read-only)"]
        L["linux/audit/audit-linux.sh<br/>--modules NAME"]
        W["windows/audit/Invoke-WindowsAudit.ps1<br/>-Modules NAME"]
        P["plugin programs<br/>(*.module.json)"]
    end
    subgraph Engine["shared/engine"]
        R["Registry<br/>built-ins + plugins<br/>dependency plan"]
        X["Runner<br/>argv only, time limit,<br/>process-group kill"]
        V["Validation<br/>strict JSON +<br/>audit-report schema"]
        A["Assessment<br/>assembly"]
    end
    subgraph Findings["shared/findings"]
        F["FindingStore<br/>BOF- ids, dedupe<br/>EV- evidence + provenance"]
    end
    subgraph Out["assessment directory (0700)"]
        J["assessment.json"]
        M["modules/&lt;id&gt;/ (unchanged module output)"]
        H["report.html / report.md"]
        MF["manifest.json (SHA-256)"]
    end
    R --> X --> L & W & P
    L & W & P --> V --> A --> F --> J
    X --> M
    J --> H
    J & M & H --> MF
    J -. "compare" .-> C["snapshot-comparison.json"]
```

```
profile ──> registry.plan() ──> for each module (sequential, dependencies first)
                                   │ run_module(): build argv -> start -> wait(timeout) -> kill tree
                                   │ parse report.json strictly -> validate against audit-report schema
                                   v
                   FindingStore.add_report()  (identity, dedupe, evidence, provenance)
                                   v
                   assessment.json  + report.{html,md} + manifest.json
```

### Design decisions

- **Collectors stay independent.** The engine never inspects the host. Bash and PowerShell collectors keep working alone and without Python ([architecture.md](architecture.md)); the engine is optional glue for hosts (or analyst machines) that have Python 3.9+.
- **One process per module.** A crash, hang or timeout in one module cannot affect another and every module has its own time limit. Cost: the collector start-up is paid per module (about 0.2 s each for the Bash collector on the development host; a full default run over the synthetic fixture host took about 5 s).
- **Sequential execution.** CLAUDE.md puts service availability first; running modules in parallel on a stressed host would add load for little gain. Parallelism can be added later behind an explicit option.
- **Declarative plugins, no code loading.** A plugin is a JSON manifest plus a program. The engine never imports or evaluates plugin code ([plugins.md](plugins.md)).
- **Module output is evidence.** Each module's output directory (report, `report.txt`, `run.log`, its own `manifest.json`, `stdout.txt`, `stderr.txt`) is kept unchanged under `modules/<id>/` and hashed by the assessment manifest. The central document is a *derived view* whose findings can be traced back to those files (`sources`, `provenance`).
- **Findings are identified by `(host, check id, category)`**, not by severity or evidence, so a finding that gets worse is the same finding ([findings.md](findings.md)).
- **No new runtime dependency.** Schema validation uses `shared/reporting/schema_lite.py`, a small validator for exactly the JSON Schema keywords the repository uses; it refuses unknown keywords instead of ignoring them and is checked against `jsonschema` by the test suite.

## Commands

```bash
python -m shared.engine list [--platform linux|windows] [--plugin-dir DIR] [--json]
python -m shared.engine run --output-dir DIR [--profile NAME|FILE] [--modules a,b] [--timeout S]
                            [--fail-on SEV] [--report html,markdown|none] [--compare PATH ...]
                            [--plugin-dir DIR ...] [--json] [--quiet]
python -m shared.engine compare BASELINE CURRENT [--format json|markdown] [--output FILE]
python -m shared.engine report ASSESSMENT [--format html|markdown|json] [--compare PATH ...] [--output FILE]
python -m shared.engine validate FILE
python -m shared.engine verify DIR [--expect-sha256 DIGEST]
```

`--output-dir` is mandatory for `run`: the engine writes nothing unless you name a location. It creates `blueops-assessment-<UTC>-<profile>/` (mode 0700; never reuses a directory; files are created exclusively with mode 0600).

### Examples

```bash
# Everything this host supports, read-only; HTML + Markdown report beside the JSON.
sudo python -m shared.engine run --output-dir /var/lib/blueops

# Fast triage (accounts, processes, listeners, services), custom threshold.
sudo python -m shared.engine run --profile quick --fail-on high --output-dir out

# Two specific modules, 60 s each, JSON on stdout (human text on stderr).
sudo python -m shared.engine run --modules users,network --timeout 60 --json --output-dir out > assessment.json

# Run now and compare with two earlier snapshots (newest first); the report gains a history section.
sudo python -m shared.engine run --output-dir out --compare snapshots/2026-02 --compare snapshots/2026-01

# Compare two snapshots (assessments, run directories or plain audit reports) and write JSON.
python -m shared.engine compare snapshots/2026-02 out/blueops-assessment-* --output cmp.json

# Re-render an old assessment as Markdown.
python -m shared.engine report snapshots/2026-02 --format markdown > report.md

# Check that nothing was altered after the run (digest recorded off-host at run time).
python -m shared.engine verify out/blueops-assessment-* --expect-sha256 <digest>
```

On a Windows host the same commands apply with `py -m shared.engine ...`; modules run through `pwsh` or `powershell.exe`, whichever is found.

### Exit codes

The contract in [contracts.md](contracts.md) applies. `run`: **0** everything ran and nothing reached `--fail-on`; **4** a finding at or above the threshold (wins over gaps, as everywhere); **6** no such finding but a module did not finish cleanly; **3** nothing could run (all modules skipped) or a plugin/profile was rejected; **2** usage; **1** every module failed or an internal consistency check failed. `compare`: **0** identical, **4** anything differs, **6** nothing differs but the comparison is incomplete, **3** snapshots cannot be compared or are unreadable. `validate` and `verify`: **0** or **3**.

## Module interface

Every module has metadata (`shared/engine/module.py: ModuleSpec`) and an execution contract.

| Field | Meaning |
|---|---|
| `id` | `<platform>.<name>`, e.g. `linux.users`; unique across built-ins and plugins |
| `platform` | `linux`, `windows` or `any`; a module for another platform is *skipped*, never started |
| `category` | `audit` or `persistence` (read-only categories only; the engine has no hardening or containment modules) |
| `requires` | module ids that must finish `ok` or `partial` first; they are added to the plan automatically and a failed dependency makes the dependent `skipped` |
| `provides` | inventory partitions (`domain:scope`) the module owns; if the module does not run, they are reported as *unavailable coverage* so a later comparison cannot read their emptiness as "removed" |
| `timeout_seconds` | hard limit; the whole process group is killed |
| `privilege` | `none`, `recommended`, `required` (informational today; elevation is reported by the collector in `host.elevated`) |
| `output` | `run-dir` (a `report.json` under the output directory) or `stdout` |
| `argv` | command template: `{repo}`, `{plugin_dir}`, `{output_dir}`, `{module}`, `{powershell}`; each placeholder lands inside one argv element |

Execution contract: the program exits **0** (nothing to report), **4** (findings), **6** (partial) after writing a schema-valid `audit-report` document (`shared/schemas/audit-report.schema.json`, 0.1.x/0.2.x). Exit **3** means "precondition not met" and marks the module `skipped`. Anything else is `failed`.

### Module statuses

| Status | Meaning | Findings and inventory used? |
|---|---|---|
| `ok` | exit 0/4 and a valid report | yes |
| `partial` | exit 6 and a valid report (coverage gaps are in `errors`) | yes, but absence proves nothing |
| `failed` | could not start, crashed, or an unexpected exit code | no |
| `timeout` | killed after the time limit | no |
| `invalid_output` | no report, unreadable JSON (duplicate keys, `NaN`, nesting bombs, bad UTF-8) or a schema violation | no |
| `skipped` | wrong platform, no PowerShell, unmet precondition, failed dependency | no |

### Built-in modules

Linux (`audit-linux.sh --modules NAME`): `system users pam auth processes network services persistence filesystem sysconfig`. Windows (`Invoke-WindowsAudit.ps1 -Modules NAME`): `system users processes network services tasks autoruns persistence firewall security eventlog filesystem`. A test (`tests/shared/test_engine_registry.py`) parses `linux/lib/common.sh` and `windows/lib/Common.ps1` and fails if the registry and the collectors disagree on module names or inventory partitions.

## Profiles and configuration

Profiles live in `profiles/<platform>/<name>.json` ([schema](../shared/schemas/assessment-profile.schema.json)); `--profile` accepts a name or a file path.

```json
{
  "schema_version": "0.1.0", "kind": "profile", "name": "full", "platform": "linux",
  "description": "Every module plus package-integrity verification (slow).",
  "modules": ["all"],
  "fail_on": "medium",
  "options": { "package_integrity": true }
}
```

`modules` holds ids or the single entry `all`. `options` is limited to what the collectors support (`recent_days`, `package_integrity`); a profile can select and parameterise modules but cannot add commands. Shipped: `default`, `quick`, `persistence-hunt` (both platforms) and `full` (Linux). Baseline-comparison tuning (ephemeral ports, ignored records) stays in the existing `--config` of `shared.reporting.diff` ([baseline-diff.md](baseline-diff.md)); the snapshot comparison reuses its defaults.

## Installation

There is no installer ([deployment.md](deployment.md)). Copy the repository to the host or analyst machine (verify it against a digest obtained out of band). Requirements: Python 3.9+ for the engine, nothing else; the collectors need Bash 4.2+ (Linux) or PowerShell 5.1+ (Windows). No network access is needed or used. Development tools (`pytest`, `ruff`, `jsonschema`) are listed in `requirements-dev.txt` and are not needed at run time.

## Testing

`tests/shared/test_engine_*.py`, `test_findings.py`, `test_snapshot_compare.py`, `test_render.py`, `test_schema_lite.py`: unit tests, real-subprocess tests (timeouts and process-tree kill, hostile output), integration tests that run the real Bash collector through the engine on the synthetic fixture host and prove the engine finds exactly what the monolithic collector finds, schema-parity tests against `jsonschema`, malformed-input tests over the existing invalid fixtures, and cross-platform tests (Windows-shaped reports compare and render; Windows modules are skipped on Linux; a Linux/Windows comparison is refused). See [development.md](development.md#testing-the-assessment-platform).

## Input verification and provenance

This section, the ones in [security-model.md](security-model.md), [telemetry.md](telemetry.md) and [plugins.md](plugins.md) describe the same behaviour.

**What is required.** Every input that carries data into an assessment, comparison, detection or telemetry result is verified before it is used: a directory must contain a `manifest.json` that matches every file in it, and a collector run directory a valid run manifest. A missing, malformed or non-matching manifest, an unlisted file or a symbolic link is an error (exit 3). `assessment.json` or `report.json` given as a file is verified through its directory. Any other bare file, including a stored comparison passed to `--compare`, has no manifest and is refused. In a `--history` directory a snapshot that cannot be verified is skipped and listed in the run's notes, not read. Telemetry *stores* are verified the same way and have no opt-out.

**Three outcomes, not two.** *Verified*: a manifest exists and every file matched. *Unverified*: there is nothing to verify against (no `manifest.json`, or a bare file) and you explicitly accepted that. *Invalid*: a manifest exists and verification was attempted and **failed** (a file differs, a file is missing or not listed, the manifest is malformed, is of the wrong kind, is a symbolic link or does not match an expected digest, or a listed file is a symlink). Invalid data is refused under every option, including `--allow-unverified`, and a bare file addressed directly in a directory whose manifest fails is invalid too.

**`--allow-unverified` (library: `verify=False`) does exactly this, and nothing more.** It is accepted by every command that reads an input which can lack a manifest: `engine compare`, `engine report`, `engine run` (its `--compare` and `--history` inputs), `detect run`, `detect compare`, `detect report`, `detect show`, `detect export`, `telemetry import`, `telemetry show`, `telemetry query`, `telemetry tree`, `telemetry compare`, `telemetry report` and `telemetry hunt`. **One policy applies to all of them:** a *verified* input is accepted; an *unverified* input (a raw collector stream, a bare `telemetry.json` or detection-results file, a bare report, a directory without a manifest, a stored comparison) is refused (exit 3) unless `--allow-unverified` is given, and is then accepted and recorded as unverified; an *invalid* input is refused always. A lone file inside a directory whose manifest matches is verified by that manifest. Telemetry **stores** (directories written by `telemetry import`) always carry a manifest and have no opt-out at all. The one input that is trusted without a manifest is the stream `telemetry collect` captured in the same process (it is recorded as `(this run)`). Only the *unverified* case is accepted: an input with no manifest to check, or a bare file, is loaded and recorded as **unverified**, with the reason; an input that verifies is recorded as verified. An *invalid* input is refused (exit 3; in a `--history` directory it is skipped and listed in the notes; in `run --compare` it is reported as `comparison skipped` and the run exits 6). Malformed or schema-invalid data and symbolic links are refused too, the flag never applies to modules, plugin trust or the environment, and it cannot be combined with an expected manifest digest. Use it only for data you already trust, such as synthetic fixtures.

**Provenance is recorded in every derived output.** Assessments, snapshot comparisons, detection results, detection comparisons, telemetry documents and telemetry comparisons carry `inputs` (one entry per input: `role`, `path`, `verified`, and a `reason` when not verified) and `inputs_verified`, which is true only if every entry is. Per-input entries are authoritative; the boolean is only the summary. An input that was itself derived from unverified inputs keeps those entries (`via` names the carrier), so a clean manifest on a later file does not launder what it was built from. An input whose provenance is unknown (a document rebuilt or copied without its record) counts as unverified; schema validity never makes anything verified. Markdown, HTML and text reports show a warning at the top when any input is unverified and list every input with its status; JSON Lines and CSV detection exports repeat the status on every row. A document with no provenance record (written by an earlier version) is shown without a claim either way.

**Limits of a self-contained manifest.** The manifest sits next to the data it describes. It detects accidental corruption and changes that did not also rewrite the manifest; it does not stop someone who can write the directory from changing the data *and* the manifest. To close that gap, record the manifest's SHA-256 off the host when the run finishes and check it later with `engine verify DIR --expect-sha256 DIGEST` (library: `load_assessment(..., expected_sha256=...)`); the comparison, report, run and detection commands do not take a digest. `inputs_verified: true` therefore means "the files still match the manifest they came with", not "the data is true" or "the author is known".

**Residual time-of-check/time-of-use risk.** Verification hashes the files, then the loader reads `assessment.json` again; a process that can write the directory between the two can substitute data that was not hashed. Keep input directories owner-only (the tool creates them `0700`/`0600`), do not verify data in a directory other users can write, and copy untrusted data to a private location before loading it.

**In `run`.** `--compare` and `--history` (with `--detect`) are verified by default. A refused `--compare` input prints `comparison skipped` and the run exits 6 (partial) with the assessment intact; a refused history snapshot is skipped and noted. With `--allow-unverified` the same inputs are used and `assessment.json`, `comparison-N.json`, `detections.json` and the reports record which were unverified; the module outputs themselves, produced by this very run, are not listed. A run with no such inputs records `inputs_verified: true` and an empty `inputs`.

**Environment sanitization.** Modules and `telemetry collect` are started with an allowlisted environment, not a copy of the caller's (`shared/engine/environment.py`): locale, terminal and identity variables (`HOME`, `LANG`, `LANGUAGE`, `TZ`, `TERM`, `TMPDIR`, `USER`, `LOGNAME`, `NO_COLOR`, `LC_*`) and anything named `BLUEOPS_*` or `BO_*` pass; everything else does not, including secrets and the loader and interpreter hooks (`BASH_ENV`, `ENV`, `LD_*`, `DYLD_*`, `PYTHON*`, `PERL5*`, `RUBY*`, `NODE_OPTIONS`). The *names* of withheld hooks are reported on stderr, never their values. `PATH` is rebuilt from the system directories plus only those entries that are root-owned and not group/other-writable, and `pwsh`, `powershell` and non-absolute plugin commands are resolved through it.

**Exceptions and limits.** (1) With `BO_TEST_MODE=1` the given `PATH` is kept as it is; whoever controls the whole invocation can set it, and reports made that way say `test_mode`. (2) `BO_*` passes through, which includes the collectors' test hooks; the collectors ignore them unless `BO_TEST_MODE=1` and report when they were used. (3) The engine process itself, and the `blueops` launcher (a Bash script), run in the environment they were given: a `BASH_ENV` or `PYTHON*` variable set before they start affects them and cannot be defended against from inside. (4) On Windows the rule is a small denylist of .NET host-injection variables (`COR_*`, `CORECLR_*`, `COMPLUS_*`, `DOTNET_STARTUP*`, `DOTNET_ADDITIONAL*`, `__PSLOCKDOWNPOLICY`) and has **not been exercised on a Windows host**; it is not an allowlist.

**Plugin trust (POSIX).** A plugin's manifest, its directory and every file the command line launches (the program, or the script given to an interpreter) must not be symlinks, must be owned by root or by the user running the engine, and must not be group- or other-writable; no ancestor directory may be group/other-writable unless it is sticky (`/tmp`). This is checked when the plugin is discovered and again immediately before each launch; a failure is a `failed` module with the reason. Built-in modules are exempt. **Limits:** only the files named on the command line are checked, so a plugin that imports sibling modules, sources other scripts or reads data files from its directory is not covered for those files; there is a short window between the launch-time check and the program starting; and on Windows ACLs are not inspected, so protect plugin directories yourself. A plugin is a program you chose to run with the engine's privileges, and review is the control that matters.

**Breaking change: plugins no longer inherit the caller's environment.** A plugin sees only the allowlisted variables above. A variable it needs must be passed as `BLUEOPS_<NAME>` (set in the engine's environment), and tools it needs must be in a root-owned system directory or addressed by absolute path; a tool in a user-writable `PATH` directory is no longer found, and credentials or tokens present in the caller's environment are not forwarded. Existing plugins that read an unprefixed variable (`MY_API_URL`, `HTTP_PROXY`, ...) must be changed.

## Limitations

- Windows modules are started through `pwsh`/`powershell.exe`, but this wiring has **not been executed against a real PowerShell** during development (only argument construction and the skip path are unit-tested). The Windows collector itself has its own Pester suite, which runs on the Windows CI runner.
- No parallel execution; no resume of an interrupted assessment (a killed engine leaves a partial directory without `assessment.json`).
- stdout/stderr of a module are written to files without a size cap; a runaway module is bounded by its time limit, not by bytes.
- On POSIX a plugin's manifest, directory and launched files are refused if they are symlinks, owned by another user, or group/other-writable, and so is a directory chain with a group/other-writable non-sticky ancestor; on Windows ACLs are not inspected, so protect plugin directories yourself. Modules run with an allowlisted environment and a trusted `PATH` ([security-model.md](security-model.md)).
- Programs are found through the rebuilt `PATH` (system directories plus root-owned, non-writable entries) and receive the allowlisted environment; the engine process itself and the `blueops` launcher run in the environment they were given ([security-model.md](security-model.md#runtime-environment-and-plugin-trust)).
- The engine records `privilege` metadata but does not elevate or check it; run it with the privileges you want the collectors to have.
