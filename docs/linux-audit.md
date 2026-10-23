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
| `--modules LIST` | Comma-separated subset of `system,users,processes,network,services,persistence,filesystem` (default: all). `--list-modules` prints them. |
| `--json` / `--format json` | JSON on stdout (or `report.json` with `--output-dir`); human text goes to stderr. |
| `--output-dir DIR` | Create `DIR/blueops-run-<YYYYMMDDTHHMMSSZ>-audit-linux/` with `report.json`, `report.txt`, `run.log`. |
| `--fail-on SEV` | Lowest severity that yields exit 4 (default `medium`). |
| `--recent-days N` | Window for "recently modified" (default 3). |
| `--fs-path DIR` | Restrict filesystem scans to DIR (repeatable). |
| `--quiet`, `--verbose`, `--no-color` | Output control. |

Each module is also runnable alone (`audit-system.sh`, `audit-users.sh`, `audit-processes.sh`, `audit-network.sh`, `audit-services.sh`, `audit-filesystem.sh`, and `linux/persistence/check-persistence.sh`) with the same options except `--modules`.

## Exit codes

`0` nothing at/above `--fail-on` and no material gaps · `2` usage error · `3` not Linux · `4` findings at/above `--fail-on` · `6` no such findings but a material coverage gap (for example no `/etc/passwd`, no `ps` and no `/proc`, a module crashed). Gaps that are expected when unprivileged (`NOT_ROOT`, `PERM_DENIED`) or covered by a fallback are listed in `errors[]` but do not change the exit code. Exit 4 takes precedence over 6; check `errors[]` either way.

## Output

Reports conform to `shared/schemas/audit-report.schema.json` (0.1.0), which has no field for raw inventory, so inventory is emitted as `info` findings (`*-INFO-001`, `*-LISTEN-001`, ...) whose evidence lists the items. Evidence lists are capped (100 items; 500 for the process inventory) and the description says when truncated. Findings aggregate one check per ID with evidence per item. Secrets are never printed: password hashes and SSH key material are not read into output, and command lines, cron/unit lines are redacted (`password=`, `token`, `secret`, `api-key`, `--password X`). Non-ASCII bytes are replaced with `?` so JSON is always valid.

## Checks

| Module | IDs | Checks |
|---|---|---|
| system | SYS-* | OS/kernel/hostname/uptime/CPU/memory/disks inventory; unrecognized distro; uptime > 1 year; kernel taint by out-of-tree/unsigned modules |
| users | USR-* | account inventory; non-root UID 0 (critical); duplicate UIDs; system accounts with login shells; empty passwords (needs root); hashes in `/etc/passwd`; sudoers rules, NOPASSWD, unsafe sudoers modes; admin and root-equivalent groups; active sessions (`who`/`w`); authorized_keys inventory, root keys, system-account keys, forced commands, writable `.ssh` |
| processes | PRC-* | inventory with parent/child tree and executable paths (`/proc`, `ps` fallback); deleted/memfd executables; execution from `/tmp`, `/var/tmp`, `/dev/shm`; kernel-thread masquerading; reverse-shell command lines; hidden-dir and non-standard paths |
| network | NET-* | listeners and established connections (`ss`, `netstat`, `/proc/net` fallbacks); exposed legacy/DB/remote-access ports; shells or netcat as listener/connection owner; routes, IP forwarding, DNS, `/etc/hosts` overrides, interfaces |
| services | SVC-* | systemd service inventory, enabled and failed units, legacy services; SysV fallback |
| persistence | PER-* | systemd units (system and user) and drop-ins, cron/anacron/at, `rc.local`, init scripts, `ld.so.preload`, shell profiles/rc files, XDG autostart, udev `RUN`, APT hooks, `pam_exec`, `sshrc`; suspicious-command patterns (reverse shells, download-and-execute, world-writable paths, setuid, alias hijack, `LD_PRELOAD`) |
| filesystem | FS-* | SUID/SGID inventory with known-package and GTFOBins-style classification; recently modified files; world-writable files/dirs; executables in temp dirs; orphaned files; deceptive names; modes of `passwd`, `shadow`, `sudoers`, `sshd_config`, etc. |

## Known limitations

- Findings are heuristics. `medium`/`low` confidence items (unknown SUID, recent changes, forwarding) routinely have benign explanations; the SUID known-package list is short and distribution-agnostic.
- Detection is point-in-time and userland-only: a kernel rootkit can hide processes, sockets, and files from every check here.
- Process names/paths for other users and `/etc/shadow`, `/etc/sudoers` need root. Process names for sockets need `ss -p`/`netstat -p` privileges.
- File names containing newlines are split across list items by the line-oriented scans.
- Tested on Ubuntu 22.04 (Bash 5.1) and macOS (Bash 3.2) against synthetic fixtures only; other distributions (RHEL-family, Alpine/BusyBox, SUSE) are untested and may degrade. Docker/container hosts, SELinux/AppArmor state, package integrity (`debsums`/`rpm -V`), and journal/log analysis are not covered.
- Filesystem scans use `find` and can be slow on large trees; they stay on local filesystems (`-xdev`). Use `--fs-path` to narrow scope.
