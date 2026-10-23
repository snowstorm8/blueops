# BlueOps

A portable, cross-platform Blue Team toolkit for competitions, incident response, host auditing, persistence detection, evidence collection, and system hardening — built on Bash and PowerShell with minimal dependencies.

> **Status: pre-alpha scaffolding.** The repository structure, development tooling, and shared contracts exist. **No security functionality is implemented yet.** Everything under "Planned capabilities" is a plan, not a feature.

## Motivation

In CCDC-style Red vs. Blue exercises and real incidents, defenders take over unfamiliar Linux and Windows hosts with little time, no internet, and services that must stay up. Existing tools are often heavyweight, platform-specific, need installation or network access, or change systems without clear safeguards. BlueOps aims to give defenders a small, auditable set of scripts that:

- run from a USB stick or copied directory with no installation,
- default to read-only inspection,
- produce consistent, structured output on both platforms,
- never break scored services by surprise.

## Objectives

Portability · reliability · modularity · rapid deployment · minimal dependencies · availability preservation · evidence integrity.

## Planned capabilities

All items below are **planned**.

| Area | Linux (Bash) | Windows (PowerShell) |
|---|---|---|
| Host audit (users, services, network, packages, configs) | planned | planned |
| Persistence detection (cron/systemd/rc/profile; tasks/services/registry/WMI) | planned | planned |
| Incident response and evidence collection (with hashing and manifests) | planned | planned |
| Opt-in containment actions (dry-run, confirmation, rollback) | planned | planned |
| Hardening profiles with service-dependency protection | planned | planned |
| Shared analysis/reporting (merge, diff, render) in Python 3 | planned | planned |

## Implemented today

- Repository layout, CI and lint workflows, formatting rules
- Versioned JSON audit-report schema (`shared/schemas/audit-report.schema.json`, v0.1.0, pre-stable) with example and tests
- Shared contracts: severity levels and exit codes (`shared/reporting/contracts.py`, [docs/contracts.md](docs/contracts.md))

## Architecture

Platform collectors (Bash, PowerShell) are independent and dependency-free; they emit JSON that conforms to a shared schema. Python 3 is optional and used on an analyst machine for validation, merging, and rendering. Read-only audit, evidence/containment, and hardening are strictly separated. See [docs/architecture.md](docs/architecture.md).

## Repository structure

```
linux/      audit/ persistence/ incident/ hardening/ lib/    Bash tooling
windows/    audit/ persistence/ incident/ hardening/ lib/    PowerShell tooling
shared/     schemas/ reporting/ config/                      JSON schemas, Python, defaults
profiles/   linux/ windows/                                  Named hardening/audit profiles
tests/      linux/ windows/ shared/ fixtures/                Bats, Pester, pytest
docs/                                                        Design and process docs
examples/                                                    Synthetic example outputs
scripts/development/                                         Maintainer helpers
```

## Installation and deployment philosophy

There is no installer. BlueOps is meant to be copied to a host (or run from read-only media) after verifying its integrity against a checksum you obtained out-of-band. It never downloads or executes remote code, and never needs internet access. See [docs/deployment.md](docs/deployment.md).

## Configuration overview

Defaults live in `shared/config/`; per-environment choices (protected services/ports, allowlists, output location) live in `profiles/<platform>/`. Local overrides (`*.local.*`, `local/`) are git-ignored. Configuration never contains credentials.

## Usage conventions

Planned (not yet available) — every tool will follow the same conventions:

```text
# Illustrative only — these commands do not exist yet.
linux/audit/<tool>.sh      --output-dir DIR [--json] [--quiet]
linux/hardening/<tool>.sh  --profile NAME --dry-run        # preview
linux/hardening/<tool>.sh  --profile NAME --yes            # apply (records rollback)
windows\audit\<Tool>.ps1   -OutputDir DIR [-Json]
windows\hardening\<Tool>.ps1 -Profile NAME -DryRun
```

Exit codes and flags are defined in [CLAUDE.md](CLAUDE.md) and [docs/contracts.md](docs/contracts.md).

## Security and authorization

BlueOps is for **defensive use on systems you own or are explicitly authorized to administer**. Hardening and containment can disrupt services; always use dry-run first and follow your event rules or organizational policy. The software is provided without warranty. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Development status and roadmap

Pre-alpha. See [docs/roadmap.md](docs/roadmap.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/development.md](docs/development.md). Contributors and AI assistants must follow [CLAUDE.md](CLAUDE.md).

## License

MIT — see [LICENSE](LICENSE).
