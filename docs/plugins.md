# Module development and plugin interface

There are two ways to add a module: a **built-in collector module** (Bash or PowerShell, part of this repository) and a **plugin** (any program plus a JSON manifest, loaded from a directory you choose). Both produce the same thing: an `audit-report` document.

## Plugin interface

A plugin directory contains `<name>.module.json` manifests ([schema](../shared/schemas/module-manifest.schema.json)) next to the programs they launch:

```json
{
  "schema_version": "0.1.0", "kind": "module",
  "id": "linux.sudoers-nopasswd", "title": "Passwordless sudo rules",
  "version": "1.0.0", "platform": "linux", "category": "audit",
  "requires": [], "provides": [], "privilege": "recommended", "timeout_seconds": 60,
  "output": "run-dir",
  "command": ["python3", "-I", "{plugin_dir}/sudoers_nopasswd.py", "{output_dir}"]
}
```

Contract:

1. `command` is an argv list executed directly (never through a shell). Placeholders: `{plugin_dir}` (resolved manifest directory), `{output_dir}` (a fresh, empty, 0700 directory for this run), `{repo}`, `{module}`. Each placeholder is substituted *inside* one argv element, so a path containing spaces or `;` cannot become a second argument.
2. With `output: "run-dir"` write `report.json` into `{output_dir}` (or into one `blueops-run-*` sub-directory, as the built-in collectors do); with `output: "stdout"` print it.
3. The report must validate against `shared/schemas/audit-report.schema.json` (0.1.x/0.2.x). Finding ids are `<AREA>-<TOPIC>-<NNN>` and must be stable: they become the `check_id` that identity is built from. Put per-item detail in `evidence`, not in the id.
4. Exit **0** (nothing to report), **4** (findings), **6** (some source unreadable, listed in `errors`), **3** (precondition not met: the module is *skipped*). Other codes mean the module failed.
5. Be read-only. The engine cannot enforce this for a program it launches; it can only run it with the privileges of the engine, so review plugins like any code you run as administrator.
6. Never write secrets (hashes, keys, tokens) to evidence or excerpts; redact before writing.
7. Declare `provides` (inventory partitions as `domain:scope`) if the module emits inventory, so a failure is visible as *unavailable coverage*. `requires` lists module ids that must succeed first; they are run automatically and a failed dependency skips the dependent.

Loading rules (`shared/engine/registry.py`): the manifest must validate; ids cannot shadow a built-in or another plugin; on POSIX a manifest or directory that is a symlink or writable by group/other is refused, because whoever can edit it can make the assessment run a command of their choosing. `python -m shared.engine list --plugin-dir DIR` shows what loaded. A complete, tested example lives in [`examples/plugins/`](../examples/plugins/) (`tests/shared/test_engine_examples.py` runs it through the engine against the synthetic host).

## Adding a built-in Linux module

1. Create `linux/audit/audit-<name>.sh` following the existing modules: header comment (purpose, category, safety), `mod_<name>()`, standalone guard calling `bo_cli_main audit-<name> audit <name> 0 "$@"`. Use `bo_path` for every file read (it honours the test root), `bo_finding` for findings, `bo_inv`/`bo_cov` for inventory and coverage, `bo_error`/`bo_perm_error` for gaps.
2. Register it in `linux/lib/common.sh`: add the name to `BO_ALL_MODULES`, a title in `bo_module_title`, and its inventory partitions in `bo_module_partitions`.
3. Register it in the engine: add a row to `_LINUX` in `shared/engine/builtin.py` (title, category, partitions). `tests/shared/test_engine_registry.py` fails if the two lists or the partitions disagree.
4. Add a category row to `NIST_800_53_BY_CATEGORY` in `shared/findings/standards.py` if the finding category is new.
5. Tests: a `tests/linux/*.bats` file that edits a copy of `tests/fixtures/linux-root` per test (see `tests/linux/audit-expansion.bats`): positive, negative, malformed input, missing file, "does not modify the tree", "no secret in the output". Keep the base fixture benign so existing totals do not move; add files to it only when a partition would otherwise be reported `unavailable`.
6. Document the checks in `docs/linux-audit.md` and `CHANGELOG.md`.

## Adding a built-in Windows module

Same shape with PowerShell: `windows/audit/Get-<Name>Audit.ps1` defining `Invoke-Bo<Name>Module` (use `Register-BoCheck`, `Add-BoHit`, `Add-BoInventory`, `Publish-BoCheck`; read data through the providers so fixtures can replace it); add it to `$script:BoAllModules`, `$script:BoModuleFunctions` and `$script:BoModulePartitions` in `windows/lib/Common.ps1`, dot-source it in `Invoke-WindowsAudit.ps1`, register it in `_WINDOWS` in `shared/engine/builtin.py`, and add a Pester file under `tests/windows/` (see `EventLog.Tests.ps1`). Source files stay ASCII/UTF-8 without BOM ([development.md](development.md)).

## Checklist for any module

- It belongs to exactly one read-only category and changes nothing outside its own output directory.
- Every unreadable source is an `errors[]` entry (`bo_error`), and partitions that could not be collected are marked `unavailable`/`partial`, never left looking complete.
- Output for hostile input (odd characters, huge values, missing files) is bounded and escaped.
- No network access, no downloaded code, no secret values in any output.
