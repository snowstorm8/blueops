# Development

Conventions: [CLAUDE.md](../CLAUDE.md). Contribution flow: [CONTRIBUTING.md](../CONTRIBUTING.md).

## Tools

| Purpose | Tool | Install |
|---|---|---|
| Bash lint | ShellCheck | `apt install shellcheck` / `brew install shellcheck` |
| Bash format | shfmt | `apt install shfmt` / `brew install shfmt` |
| Bash tests | Bats | `apt install bats` / `brew install bats-core` |
| PowerShell lint | PSScriptAnalyzer | `Install-Module PSScriptAnalyzer -Scope CurrentUser` |
| PowerShell tests | Pester 5 | `Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser -SkipPublisherCheck` |
| Python lint/format/test | Ruff, pytest, jsonschema | `python3 -m pip install -r requirements-dev.txt` |

## Running checks

```bash
scripts/development/check.sh        # Linux/macOS; skipped tools are reported, not counted as passed
```

```powershell
./scripts/development/check.ps1     # Windows
```

CI (`.github/workflows/ci.yml`, `lint.yml`) runs the same checks on Linux and Windows runners. Pester (run under Windows PowerShell 5.1 and again under PowerShell 7), PSScriptAnalyzer, Bats and ShellCheck/shfmt are enforced.

### Testing the Linux tooling

Bats tests (`tests/linux/*.bats`) run the real scripts against a synthetic root filesystem (`tests/fixtures/linux-root`) so they pass on any POSIX host, including macOS. Test-only environment hooks make this possible: `BO_ROOT` (prefix for every file read) and `BO_FORCE_MISSING_TOOLS` (space-separated tools treated as absent). They are honoured **only with `BO_TEST_MODE=1`** (`tests/linux/test_helper.bash` exports it); without it the collector removes them from the environment, ignores them and records `TEST_HOOKS_IGNORED` (exit 6), so a stray or planted variable cannot make an audit read a fake host. In test mode the command shims in `PATH` are used as they are; in production `PATH` is reduced to trusted directories (`bo_sanitize_path`). Tests of the production behaviour run `env -u BO_TEST_MODE ...` (see `tests/linux/hardening.bats`). Fake `ss`/`systemctl`/`who`/`ps` live in `tests/fixtures/linux-bin`. Permission bits git cannot store (SUID, 0600) are applied by `tests/linux/test_helper.bash` on a per-test copy. Use `refute cmd`, not `! cmd`, for negative assertions: Bats ignores a bare `!`.

### Collector/rule contract and static guards

`tests/shared/test_rule_collector_contract.py` runs the real Linux collector and asserts that every record shape a detection rule reads exists in its output (the bug class behind `BO-PER-001` and the ASLR rule). `tests/shared/test_windows_sources.py` checks the PowerShell sources statically on every platform: tools are resolved from System32 (never `PATH`), fixture hooks are read only in the gated helpers, nothing but the run directory is written. `tests/shared/test_schemas.py` keeps schema versions, examples and the example allowlist in step with the code. PowerShell runtime behaviour is covered by Pester on CI (`tests/windows/Hardening.Tests.ps1`).

### Testing the Windows tooling

Pester tests (`tests/windows/*.Tests.ps1`) run the real entry scripts in a child process against a synthetic host (`tests/fixtures/windows-host`: `data/` provider snapshots and an `fs/` tree) so they pass on any OS with PowerShell. Test-only hooks, honoured only with `BO_TEST_MODE=1` (otherwise ignored and recorded as `TEST_HOOKS_IGNORED`): `BO_FIXTURE_DIR` (fixture root), `BO_FORCE_MISSING` (space-separated providers treated as unavailable); and `BO_TEST_SHELL` (child shell; default `powershell.exe` on Windows, `pwsh` elsewhere). Date tokens `@@AGO:n@@` in fixtures are replaced per test copy. `tests/shared/test_windows_audit_report.py` validates a Windows report against the JSON schema when PowerShell is available. See [windows-audit.md](windows-audit.md).

### Testing the assessment platform

`tests/shared/engine_support.py` provides synthetic audit reports (built on `baseline_builders.py`) and a fake module executor that writes a canned report instead of starting a process, so engine behaviour (ordering, dependencies, failure statuses, exit codes, deduplication, manifest tampering) is tested without any host. Real-process tests use the running Python as the plugin program (timeouts, process-tree kill, hostile output, symlinked reports, nesting bombs). Integration tests run `python -m shared.engine run` against the real Bash collector on `tests/fixtures/linux-root` and assert that the engine finds exactly the findings the monolithic collector finds and that every finding traces back to a module report by digest. `test_schema_lite.py` checks the dependency-free validator against `jsonschema` (which stays a dev-only dependency) on every shipped schema and on mutated documents. `test_render.py` parses the generated HTML for balance and external references, checks the CSP script hash, and feeds hostile values through both renderers. Windows behaviour that needs PowerShell is skipped where PowerShell is absent; a skipped test is not a pass (see the reported counts).

```bash
python3 -m pytest tests/shared                 # all Python tests (some need bash; Windows ones need PowerShell)
bats --recursive tests/linux                   # the Bash collector tests, including audit-expansion.bats
```

## PowerShell encoding policy and Windows PowerShell 5.1 limitations

All sources are **UTF-8 without BOM** with LF endings (enforced by `.editorconfig`/`.gitattributes`).

- Windows PowerShell 5.1 reads a BOM-less script as the system ANSI code page, so non-ASCII literals in `.ps1` files may be corrupted. PowerShell 7 reads UTF-8 by default.
- Therefore: keep source ASCII where possible; express non-ASCII characters via escapes (`[char]0x2713`).
- 5.1 `Out-File`/`Set-Content -Encoding utf8` writes a BOM, and `-Encoding utf8NoBOM` does not exist. For machine-readable output (JSON reports, manifests) use `[System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding $false))`, which works on both versions.
- Consumers of BlueOps JSON must tolerate a leading BOM from older tooling.
- `Join-Path` accepts only one child path on 5.1 (nest calls); avoid PowerShell 7-only syntax (`??`, ternary, `&&`) -- PSScriptAnalyzer's `PSUseCompatibleSyntax` enforces 5.1/7.0 compatibility.

## Local tool coverage

CI is the authoritative check. Locally, `check.sh` reports every missing tool as SKIPPED; a skipped tool is not a pass.

## Adding a module

1. Pick exactly one category directory and platform.
2. Follow the Bash/PowerShell conventions in CLAUDE.md; emit a report conforming to the schema.
3. Add tests in `tests/<platform>/` (`*.bats` or `*.Tests.ps1`); state-changing code needs dry-run, refusal, and rollback tests.
4. Update README status, `docs/roadmap.md`, and `CHANGELOG.md`.
