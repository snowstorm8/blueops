# Security Policy

## Supported versions

BlueOps is pre-alpha; only the `main` branch is supported.

## Reporting a vulnerability

Please report vulnerabilities **privately** using GitHub's "Report a vulnerability" (private security advisories) feature on this repository. Do not open public issues or pull requests for security problems. Include affected files, reproduction steps, and impact. Expect an acknowledgement on a best-effort basis.

Relevant issues include: command/argument injection, unsafe temp-file handling, secrets leaking to logs or output, evidence tampering, unintended state changes in read-only modes, and supply-chain risks in CI.

## Intended use

BlueOps is for defensive work on systems you own or are explicitly authorized to administer. Reports requesting offensive capabilities will be declined.

See [docs/security-model.md](docs/security-model.md) for the threat model and trust assumptions.
