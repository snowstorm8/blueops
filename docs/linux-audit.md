# Linux read-only audit (v0.1)

`linux/audit/audit-linux.sh` inspects a Linux host and reports findings. It is **read-only**: it never changes system state and writes only to `--output-dir` (private `0700` run directory) and a temporary scratch directory that is removed on exit. Use it only on hosts you are authorized to administer.

```bash
sudo linux/audit/audit-linux.sh                              # all modules, human summary on stdout
sudo linux/audit/audit-linux.sh --json --output-dir ./out    # JSON report + report.txt + run.log in ./out/blueops-run-<UTC>-audit-linux/
linux/audit/audit-linux.sh --modules users,network --quiet --json > report.json
```

Run as root for full coverage; unprivileged runs work but record the gaps (`NOT_ROOT`, `PERM_DENIED`) in `errors[]`.

## Options

| Option | Meaning |
|---|---|
| `--modules LIST` | Comma-separated subset of `system,users,pam,processes,network,services,persistence,filesystem` (default: all). `--list-modules` prints them. |
| `--json` / `--format json` | JSON on stdout (or `report.json` with `--output-dir`); human text goes to stderr. |
| `--output-dir DIR` | Create `DIR/blueops-run-<YYYYMMDDTHHMMSSZ>-audit-linux/` with `report.json`, `report.txt`, `run.log`. |
| `--fail-on SEV` | Lowest severity that yields exit 4 (default `medium`). |
| `--recent-days N` | Window for "recently modified" (default 3). |
| `--fs-path DIR` | Restrict filesystem scans to DIR (repeatable). |
| `--package-integrity` | Opt-in: verify installed files against their package checksums with `dpkg --verify` (Debian family) or `rpm -Va` (RHEL/SUSE family). Read-only, hashes every packaged file, can take minutes; root only (the package tools misreport files they cannot read). Without either database, or unprivileged, it records `PKG_UNSUPPORTED` / `PKG_NEEDS_ROOT` and exits 6. The checksums come from the package database on the same host (dpkg: MD5, rpm: the package's own digest): they catch unplanned changes, not a root-level attacker who edits file and database together. |
| `--quiet`, `--verbose`, `--no-color` | Output control. |

Each module is also runnable alone (`audit-system.sh`, `audit-users.sh`, `audit-pam.sh`, `audit-processes.sh`, `audit-network.sh`, `audit-services.sh`, `audit-filesystem.sh`, and `linux/persistence/check-persistence.sh`) with the same options except `--modules`.

## Safety properties of the collector itself

- **Test hooks need `BO_TEST_MODE=1`** (see [development.md](development.md)); in a normal run `BO_ROOT` and `BO_FORCE_MISSING_TOOLS` are removed from the environment and the run records `TEST_HOOKS_IGNORED` (material, exit 6).
- **Trusted `PATH`.** The system directories come first; relative, missing, non-root-owned and group/other-writable entries are dropped and listed in `PATH_SANITIZED` (non-material).
- **Reports are text-safe.** Tabs/newlines in attacker-controlled text (command lines, process names, file names) cannot add columns or rows to the internal TSV files, and non-ASCII bytes are escaped (`\u00XX` per byte) rather than replaced by `?`, so different names stay different.
- **Run manifest.** `--output-dir` also writes `manifest.json` (SHA-256 and size of each output file and the collector scripts; mode `0600`) and prints its digest to stderr. Verify with `python -m shared.reporting.verify`. See [deployment.md](deployment.md).
- **No side effects from inspection.** Firewall rules are read with `iptables -S` / `nft list ruleset` only when the kernel module is already loaded (running them otherwise would make the kernel load it); `/proc/modules`, `/sys/module/NAME/taint` are read as data and the module name is never used as a path unless it is a plain identifier.

## Exit codes

`0` nothing at/above `--fail-on` and no material gaps · `2` usage error · `3` not Linux · `4` findings at/above `--fail-on` · `6` no such findings but a material coverage gap (for example no `/etc/passwd`, no `ps` and no `/proc`, a module crashed). Gaps that are expected when unprivileged (`NOT_ROOT`, `PERM_DENIED`) or covered by a fallback are listed in `errors[]` but do not change the exit code. Exit 4 takes precedence over 6; check `errors[]` either way.

## Output

Reports conform to `shared/schemas/audit-report.schema.json` (0.1.0), which has no field for raw inventory, so inventory is emitted as `info` findings (`*-INFO-001`, `*-LISTEN-001`, ...) whose evidence lists the items. Evidence lists are capped (100 items; 500 for the process inventory) and the description says when truncated. Findings aggregate one check per ID with evidence per item. Secrets are never printed: password hashes and SSH key material are not read into output, and command lines, cron/unit lines are redacted (`password=`, `token`, `secret`, `api-key`, `--password X`). Non-ASCII bytes are replaced with `?` so JSON is always valid.

## Checks

| Module | IDs | Checks |
|---|---|---|
| system | SYS-* | OS/kernel/hostname/uptime/CPU/memory/disks inventory; unrecognized distro; uptime > 1 year; kernel taint by out-of-tree/unsigned modules; loaded kernel modules inventory with per-module taint (`SYS-KMOD-001`) |
| users | USR-* | account inventory; non-root UID 0 (critical); duplicate UIDs; system accounts with login shells; empty passwords (needs root); hashes in `/etc/passwd`; sudoers rules, NOPASSWD, unsafe sudoers modes; admin and root-equivalent groups; active sessions (`who`/`w`); authorized_keys inventory, root keys, system-account keys, forced commands, writable `.ssh`; sudoers `#include`/`@include` directives (files outside `/etc/sudoers.d` are followed and flagged, `USR-SUDO-004`), `Defaults` and `*_Alias` lines (dangerous `Defaults`, `USR-SUDO-005`); accounts whose *primary* group is root/sudo/wheel/admin (`USR-GROUP-003`) |
| pam | PAM-* | `/etc/pam.d` and `/etc/pam.conf` parsed as data (modules are never loaded; backslash-continued lines are joined; the referenced module files are hashed into the inventory): `pam_permit` accepting without a credential check, modules loaded from outside the system directories or missing from them, weak `pam_unix` hashing, `nullok`, writable PAM config, recently modified module files |
| processes | PRC-* | inventory with parent/child tree and executable paths (`/proc`, `ps` fallback); deleted/memfd executables; execution from `/tmp`, `/var/tmp`, `/dev/shm`; kernel-thread masquerading; reverse-shell command lines; hidden-dir and non-standard paths |
| network | NET-* | listeners and established connections (`ss`, `netstat`, `/proc/net` fallbacks, IPv6 decoded to the text `ss` prints); exposed legacy/DB/remote-access ports; shells or netcat as listener/connection owner; routes, IP forwarding, DNS, `/etc/hosts` overrides, interfaces; sshd effective settings (`NET-SSHD-001/002`: first occurrence wins, `Include` expanded, `Match` blocks not global); kernel hardening sysctls (`NET-SYSCTL-001`); host firewall state (`NET-FW-001/002`, root only) |
| services | SVC-* | systemd service inventory, enabled units, failed services (`SVC-FAILED-001`) and failed socket units (`SVC-FAILED-002`), legacy services; SysV fallback |
| persistence | PER-* | systemd units (system and user) and drop-ins, cron/anacron/at, `rc.local`, init scripts, `ld.so.preload`, shell profiles/rc files, XDG autostart, udev `RUN`, APT hooks, `pam_exec`, `sshrc`; suspicious-command patterns (reverse shells, download-and-execute, world-writable paths, setuid, alias hijack, `LD_PRELOAD`); symlinked units in the administrator systemd directories (target recorded, dangling links kept), `*.wants` enablement links, `ld.so.conf(.d)` search paths in writable locations (`PER-LDCONF-001`), `cron.allow/deny` and `at.allow/deny`, auditd rules (`PER-AUDITD-001` when configured but empty); persistence files carry a line count and line fingerprints (no text) |
| filesystem | FS-* | SUID/SGID inventory with known-package and GTFOBins-style classification; recently modified files; world-writable files/dirs; executables in temp dirs; orphaned files; deceptive names; modes of `passwd`, `shadow`, `sudoers`, `sshd_config`, etc.; with `--package-integrity`: modified programs/libraries (`FS-PKG-001`), other discrepancies (`FS-PKG-002`), summary (`FS-PKG-003`) |

## Inventory for baseline comparison (schema 0.2.0)

Besides findings, every run emits `inventory` (records with stable keys plus per-domain coverage) for [baseline-diff.md](baseline-diff.md). Modules contribute: users (`user:`, `group:`, sudoers `config:sudoers:`, SSH keys `persist:ssh-authkey:` fingerprinted by key blob), processes (`process:<user>:<comm>`, PIDs volatile), network (`listener:`, sysctl/DNS/hosts `config:`; sysctl covers `net.ipv4.ip_forward`, IPv6 forwarding and `kernel.randomize_va_space`), services (`service:`), persistence (`cron:`, `persist:<scope>:`), pam (`config:pam:`), filesystem (`config:suid:`). Coverage is `partial` when not root for protected paths, when `find` reported errors or `--fs-path` narrows the scan, and when a module is missing or aborts; unknown executables are `null`, never empty. Key material and password hashes are never emitted.

## Contextual heuristics (false-positive control)

- Housekeeping commands that only *name* a path (`rm`, `ls`, `chmod`, `mkdir`, `test`, `tmpreaper`, ...) are not "execution from a world-writable directory". `find ... -exec CMD`, `cp`, `mv` and `tar` are deliberately **not** exempt, because they run or stage files from `/tmp`.
- Standard X11/ICE socket paths are ignored only inside test brackets (`[ -S /tmp/.X11-unix/X0 ]`) and `ICEAUTHORITY`/`XAUTHORITY` assignments, never as a command or script argument, in `ExecStart=`, or in a cron command. Real X sockets are not regular files, so any *regular* executable under `/tmp/.X11-unix` is still reported.
- The `postgres` account's login shell is expected only when its home is a package path (`/var/lib/postgresql`, `/var/lib/pgsql`); it is disclosed in `USR-INFO-001` rather than flagged. Other accounts, and `postgres` with another home, are still flagged.
- `pam_permit` is reported as `sufficient`/`success=done`/`ok` in `auth`, or as the sole authenticating module of a file with no `@include`; `pam_succeed_if uid >= 0` bypasses are reported likewise.
- `--package-integrity` does not list ordinary modified conffiles or documentation, but does list conffiles under PAM, SSH, sudo, cron, systemd, boot scripts and TLS trust (`FS-PKG-004`).
- SUID/SGID scanning walks every local mount point from `/proc/mounts` (ext*/xfs/btrfs/zfs/f2fs/vfat/overlay...), de-duplicated; network and pseudo filesystems are skipped.

## Known limitations

- Findings are heuristics. `medium`/`low` confidence items (unknown SUID, recent changes, forwarding) routinely have benign explanations; the SUID known-package list is short and distribution-agnostic.
- Detection is point-in-time and userland-only: a kernel rootkit can hide processes, sockets, and files from every check here.
- Process names/paths for other users and `/etc/shadow`, `/etc/sudoers` need root. Process names for sockets need `ss -p`/`netstat -p` privileges.
- File names containing newlines are split across list items by the line-oriented scans.
- Tested on Ubuntu 22.04 (Bash 5.1) and macOS (Bash 3.2) against synthetic fixtures only; other distributions (RHEL-family, Alpine/BusyBox, SUSE) are untested and may degrade. Docker/container hosts, SELinux/AppArmor state and journal/log analysis are not covered. The IPv6 `/proc/net` decoding assumes a little-endian host (x86, arm64).
- `--package-integrity` supports dpkg and rpm databases only (no apk/pacman); it trusts the local package database, which an attacker with root can also alter. See *Residual risks* in [security-model.md](security-model.md).
- Filesystem scans use `find` and can be slow on large trees; they stay on local filesystems (`-xdev`). Use `--fs-path` to narrow scope.
