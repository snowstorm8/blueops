# Reporting and snapshot comparison

## Formats

| Format | Command | Notes |
|---|---|---|
| JSON | `assessment.json` (always written); `report --format json` | The canonical, machine-readable result ([findings.md](findings.md)); validates against `assessment.schema.json`. |
| Markdown | `report.md`; `report --format markdown` | Every report value is escaped and reduced to one line, so a hostile file name cannot add headings, links, images or HTML. `<`/`>` inside code spans are shown as single guillemets. |
| HTML | `report.html`; `report --format html` | One self-contained file: inline CSS and a ~1.1 KB script, no external fonts, images or requests. |

`run` writes HTML and Markdown beside the JSON by default (`--report none` to skip). Reports are deterministic for a given input and `--generated-at`.

## HTML report

Sections (also the sticky navigation): **Executive summary** (posture headline, key counts, coverage caveats, severity distribution), **Assessment metadata and host**, **Module results**, **Remediation priorities** (P1…P4), **Findings breakdown** (grouped by category, filterable by severity and free text, expandable cards with description, remediation, evidence, standards and provenance), **Evidence index** (id, type, reference, hash prefix, collecting module), **Historical comparison** (one block per `--compare`), **Errors and warnings**.

Design notes: responsive (checked at 390 px and 1280 px; grids collapse, tables scroll inside their frame), light and dark themes by `prefers-color-scheme`, severity shown as text as well as colour, keyboard-reachable controls with visible focus, print stylesheet. The *posture headline* only reflects the worst severity present ("Immediate attention required" … "No actionable findings"); the **coverage caveats** box states why the absence of findings is not proof of health (modules that failed, unprivileged collection, partial inventory, fixture data).

Security properties (tested): all values pass through `html.escape`; the page carries a `Content-Security-Policy` of `default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-…'` where the hash pins exactly the one script the file contains; the script reads the DOM and never evaluates report data; there are no inline event handlers. Opening the file makes no network request. Checked in Chromium (no console errors under the policy, filters work, no horizontal overflow at 390 px or 1280 px, dark mode renders); that browser check was done by hand, not as an automated test.

## Snapshot comparison

`python -m shared.engine compare BASELINE CURRENT` (or `run --compare`) produces a `snapshot-comparison` document ([schema](../shared/schemas/snapshot-comparison.schema.json)). Inputs may be assessments, assessment directories, audit reports or collector run directories; every input is **verified by default**: a directory must have a `manifest.json` that matches all of its files (a missing, malformed or non-matching manifest, an unlisted file or a symbolic link is an error, exit 3); `assessment.json` / `report.json` given as a file is verified through its directory; any other bare file cannot be verified and is refused. `--allow-unverified` (library: `verify=False`) is the deliberate opt-in for data you already trust, such as synthetic fixtures: inputs that verify are recorded as verified, inputs with nothing to verify against (no manifest, a bare file) are loaded and recorded as unverified, and inputs whose manifest exists but fails are refused (invalid) even with the flag; the schema is still validated. The comparison and every report built from it carry `inputs_verified` / `inputs` and show a warning when any input is unverified ([security-model.md](security-model.md#input-integrity-and-provenance)). A manifest cannot vouch for itself: to detect one rewritten together with the data, record its digest off the host and check it with `verify --expect-sha256` (library: `load_assessment(..., expected_sha256=...)`, which is an error together with `verify=False`).

| Section | Contents |
|---|---|
| `findings.new` / `resolved` | In current only / in baseline only, **when the evidence supports the conclusion** |
| `findings.persistent` | In both; each carries `evidence` added/removed/unchanged and the baseline severity and confidence |
| `findings.severity_changed` | Persistent findings whose severity moved, with `direction` (`increased`/`decreased`) |
| `findings.indeterminate` | Differences that cannot be concluded, with the reason ("module linux.network finished as timeout", "was not run in this snapshot") |
| `configuration` | Added/removed/modified inventory records (users, groups, services, listeners, tasks, persistence, configuration) from the existing inventory engine ([baseline-diff.md](baseline-diff.md)), its indeterminate items and domain coverage; `available: false` with a reason when a snapshot has no inventory |
| `coverage` | Modules added, removed, or whose status changed; inventory partitions whose coverage changed |
| `summary` | Counts, `weighted_index` (info 0, low 1, medium 3, high 7, critical 15; a relative trend aid, **not** a risk score) and `trend` (`better`/`worse`/`unchanged`/`indeterminate`) |

Rules that keep it honest:

- **Resolved** only if the module that reported the finding finished `ok` in the current snapshot; **new** only if it finished `ok` in the baseline. A failed, timed-out, partial or missing module makes the difference *indeterminate*.
- Any new finding or any severity increase makes the trend `worse`; a worse index with no other change also does; improvement requires resolved findings or severity decreases.
- Hosts must match (case-insensitively) unless `--allow-host-mismatch`, in which case finding ids, which embed the host, never match and the output says so. Different OS families are refused. Warnings: reversed order, same run, different privilege, fixture data.
- Exit code: 0 identical, 4 anything differs (the same convention as `shared.reporting.diff`: a resolved finding is a difference), 6 identical but incomplete, 3 not comparable.

The older single-purpose tools remain: `shared.reporting.diff` (inventory changes between two *reports*) and `shared.reporting.detect` (explainable detection rules over that diff). The snapshot comparison embeds the first and does not replace either; wiring the detection rules into assessments is future work ([roadmap.md](roadmap.md)).
