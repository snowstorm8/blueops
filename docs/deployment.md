# Deployment

BlueOps has no installer. The supported deployment is a plain `git clone`; every file the tools need is tracked in Git, and they run from any directory.

```bash
sudo apt install git
git clone https://github.com/snowstorm8/blueops.git
cd blueops
./blueops doctor
```

## Principles

- **Clone, check, run.** `./blueops doctor` is read-only and tells you exactly what, if anything, is missing.
- **Setup is separate from auditing.** Collectors and the launcher never install packages or change configuration. If a required command is missing they stop with exit code 3 and name the fix. The only thing that installs packages is `scripts/setup/setup-linux.sh --install`, which prints the exact commands and asks first.
- **Never fetch-and-execute.** No `curl | sh`, no `iex (iwr ...)`. The only network use is your own `git clone` and, if you choose it, your package manager.
- **Least footprint.** Tools write only to a user-specified `--output-dir`. The launcher does not write bytecode into the checkout (`python -B`).
- **Independent of the working directory.** Paths are resolved from the script's own location (also through a symlink). `/path/to/blueops/blueops audit` works from anywhere.
- **Privileges.** Run as root/Administrator for full coverage; unprivileged runs record the gaps (`errors[]`, exit 6) instead of failing silently.

Output directories (reports, baselines) list accounts, listeners and persistence on the host: keep them owner-only and move them off the host promptly.

## Linux

### Commands

| Command | Purpose |
|---|---|
| `./blueops doctor` | Check the checkout and dependencies. Exit 0 ok, 3 if something required is missing. |
| `sudo ./scripts/setup/setup-linux.sh` | Report what is missing and the packages that would be installed. Changes nothing. |
| `sudo ./scripts/setup/setup-linux.sh --install` | Show the exact commands, ask, then install. `--dry-run` prints without running; `--yes` skips the prompt (required without a terminal, otherwise exit 5); `--minimal` installs only what collectors strictly need. |
| `sudo ./blueops audit --json --output-dir DIR` | Read-only audit (`linux/audit/audit-linux.sh`). |
| `sudo ./blueops persistence` | Read-only persistence detection. |
| `./blueops diff BASE CURRENT` / `./blueops detect BASE CURRENT` | Offline comparison and detections (Python >= 3.9). |
| `./blueops version` | Version and Git commit; compare it with the commit you meant to deploy. |

### What is required

| Need | Required for | If missing |
|---|---|---|
| Bash >= 4.2 (warned, not enforced, below that) | everything | install/upgrade; older shells may give unreliable results |
| `awk cat cut date find grep head id mktemp sed sort stat tail tr uname wc` and one of `sha256sum`/`shasum`/`openssl` | collectors | exit 3 with the list; `setup-linux.sh --install` provides them |
| `ps ss ip who timeout` (`systemctl` on systemd hosts) | better coverage | optional; each has a fallback or the module reports a gap. Setup installs `procps`/`iproute2`; it never installs an init system |
| Python >= 3.9 | `diff`, `detect` only | collectors do not need Python; run analysis on an analyst machine or install it |
| `dpkg` | `--package-integrity` only | Debian/Ubuntu only |

Package names used by setup:

| | Debian / Ubuntu | Rocky / RHEL | Arch |
|---|---|---|---|
| awk | `mawk` | `gawk` | `gawk` |
| ps | `procps` | `procps-ng` | `procps-ng` |
| ss, ip | `iproute2` | `iproute` | `iproute2` |
| Python | `python3` | `python3` (Rocky 9: 3.9) or `python3.11` (Rocky 8) | `python` |
| Manager | `apt-get update` then `apt-get install -y --no-install-recommends` | `dnf install -y` (or `yum`) | `pacman -S --needed --noconfirm` (no database refresh; run `pacman -Syu` yourself if it fails) |

### Debian / Ubuntu

The workflow at the top of this page is the whole procedure. A minimal image lacks `iproute2` and `python3`; the collectors still run (they fall back to `/proc/net`) and `doctor` lists what is optional. `sudo ./scripts/setup/setup-linux.sh --install` adds them. If `apt` cannot reach a mirror (offline lab), skip setup, or fetch the `.deb` files elsewhere and install them yourself.

### Rocky Linux / RHEL family

- Use `sudo dnf install -y git` in place of the `apt` line.
- `ss` is in `iproute`, `ps` in `procps-ng`; both are normally present on a standard install.
- **Python:** Rocky 9's `python3` is 3.9 (enough). Rocky 8's is 3.6 (too old for `diff`/`detect`); setup requests `python3.11`. Collectors do not need Python at all.
- `--package-integrity` is Debian/Ubuntu only; use `rpm -Va` by hand. SELinux state is not audited.
- Rocky is not yet a validated target (see Verification status); expect some modules to report gaps.

### Offline or restricted hosts

`git clone` and package installation need network access to GitHub and a mirror. If a host cannot reach them, clone once on a machine that can and copy the working tree preserving modes (for example `tar -C /path/to -cf blueops.tar blueops`, then `scp`, then `tar -xf` on the target), or run through `bash ./blueops ...`, which does not need the executable bit. `./blueops doctor` works the same on a copied tree. Verify the copy with `./blueops version` (a copied tree keeps `.git`) or a checksum you compute on the source.

### `noexec` mounts and root-owned clones

If the clone is on a `noexec` file system, run `bash ./blueops audit ...`. Running the tools with `sudo` from a clone owned by another user is fine; `./blueops version` degrades to `unknown` if Git refuses the ownership.

## Windows

There is no Windows launcher or setup step: the collectors use only what ships with Windows.

- **Requirements:** Windows PowerShell 5.1 or PowerShell 7, an elevated prompt for full coverage, no extra modules, no Python on the target.
- **Getting the code:** `git clone` needs Git for Windows, which is not present by default (and `winget` is absent on Server Core and Server 2025 images). If it cannot be installed, clone on another machine and copy the folder (SMB, `scp` with the built-in OpenSSH client, or RDP file transfer). Use a short path such as `C:\blueops`.
- **Line endings:** `.gitattributes` forces LF in the working tree, which Windows PowerShell 5.1 reads fine; do not re-save scripts with another encoding.
- **Running:**
  ```powershell
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\audit\Invoke-WindowsAudit.ps1 -Json -OutputDir C:\blueops-out
  ```
  `-ExecutionPolicy Bypass` affects only that process. Constrained Language Mode hosts may degrade (reported as gaps).
- **Analysis (`diff`, `detect`):** needs Python >= 3.9 and is best done on an analyst machine: from the repository root run `python -m shared.reporting.detect BASE CURRENT` (use `py -3` if `python` is not on `PATH`).
- A missing prerequisite on Windows surfaces as the collector's own exit 3 (not Windows / not supported) or as a reported gap; there is no separate dependency report.

## Recommended procedure

1. Clone (or copy) and `./blueops doctor`. Resolve anything marked MISSING.
2. Run the read-only audit; take a baseline early, as root/Administrator, and store it off-host.
3. Re-audit after changes and compare with `diff`/`detect` on an analyst machine.
4. Hardening and containment are not implemented yet ([roadmap](roadmap.md)); make changes by hand and record prior state yourself.

## Verification status

What was actually exercised (see the CHANGELOG entry for this change):

| Scenario | Status |
|---|---|
| Fresh `git clone` of the tracked files into a temporary directory, flow run from `/` with a scrubbed environment (macOS, Bash 3.2, fixture host) | verified |
| Same flow on a stock Ubuntu 22.04 container (aarch64): `apt install git`, clone, `doctor`, `setup --install` refusal/dry-run/`--yes`, real audits from `/`, `detect`, `persistence`, clone left unmodified | verified |
| Full test suite and lint run inside the fresh clone | verified (see change notes) |
| Debian 13, Rocky 8/9, Arch, x86_64 hardware | **not verified** |
| Windows (all of the above, including Git for Windows and Server Core) | **not verified here**; Windows collectors are tested by CI on `windows-latest` |
