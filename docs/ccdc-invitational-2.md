# WCComps 2026 Invitational 2: deployment and operations guide

This guide is specific to one event. The generic toolkit is described in the [README](../README.md); nothing here changes how BlueOps behaves.

**Source of truth:** the Acme LLC team packet titled "WCComps 2026 Invitational 2" (15 pages). Every machine name, address, OS and rule below comes from it. Where the packet is silent, this guide says "not in the packet" and does not guess. The file name of the packet says 2027 while its title says 2026; if your rules differ from what is quoted here, the packet and the organizers win.

**Status of BlueOps:** only the read-only audit, persistence, baseline-diff and detection tools exist. There is **no** hardening, containment, evidence-collection or rollback tooling ([roadmap](roadmap.md)). Every change you make during the event is made by hand and tracked by hand.

## 1. Ground rules from the packet that shape tool use

| Packet fact | Consequence for BlueOps |
|---|---|
| Team network `192.168.220.0/24`; external `10.100.1XX.Y` maps 1:1 to `192.168.220.Y` | Collectors read the host's own addresses, so reports show `192.168.220.Y`. Nothing in BlueOps hardcodes a network (checked: the only RFC1918 literal in the repo is a synthetic test entry). `XX` is your team number and is not in the packet; do not put it in any config. |
| Routers `.1`/`.2` (`tweety`, OPNsense 26.7); a router reset is -100 and cutover windows are every 30 min | BlueOps never touches, scans or logs in to the routers. No firewall, NAT, route or network-wide action exists in the toolkit and none should be added. |
| About 10 services (plus or minus 2) scored every 2-4 minutes; an SLA violation occurs after 5 failed checks | A scored service can be dead roughly 10-20 minutes before an SLA hit (derived: 5 checks x 2-4 min). Treat that as the outer limit, not a budget. Run audits one host at a time and watch Quotient during and after. |
| Which services are scored is **not listed**; the table "gives a clue" and the real list is in Quotient (`scoring.wccomps.org`) | Build the protected-service list at event start from Quotient plus the listener inventory (section 4). Do not derive it from host names alone. |
| Red Team may deface, stop services, add/remove users, modify files and reboot any server including routers | Expect state to change under you; baselines and re-audits are the way to see it. |
| Red Team penalties include -25 for sensitive files and -50 for recovered user IDs/passwords | Reports list accounts, listeners and persistence. Do not leave them on a target host; move them to your analyst machine promptly. |
| Master credentials arrive at 9 AM (Discord); password changes go through the Quotient portal; tickets (incident reports must be detailed) go to `teams.wccomps.org` | BlueOps never takes, stores or prints credentials. Use your normal SSH/RDP sessions to run it. |
| Access is over NetBird VPN from 9 AM, one device per player, shared team account | Copy the toolkit to targets over the connections you already use (SCP/RDP file transfer). No internet is assumed or needed. |
| Injects: AI-generated text scores 0 for that inject | BlueOps output is data for your own notes. Write inject text yourselves. |

## 2. Machine inventory and BlueOps coverage

Roles are copied from the packet table. "Packet OS" is exactly what the packet says; versions it does not give are marked.

| .Y | Name | Packet OS | Packet role | BlueOps tier | Collector |
|---|---|---|---|---|---|
| .1/.2 | tweety | OPNsense 26.7 | Router | **Do not use BlueOps** | none |
| .10 | bugs | Windows Server 2025 | Domain Controller | **Partial** | `Invoke-WindowsAudit.ps1` (no AD coverage) |
| .46 | speedy | Windows Server Core 2022 | E-Commerce | **Full** (Server Core unverified) | `Invoke-WindowsAudit.ps1` |
| .112 | wil.e | Windows 11 | Gallery | **Full** | `Invoke-WindowsAudit.ps1` |
| .77 | elmer | Ubuntu 22.04 | Forums | **Full** | `audit-linux.sh` |
| .11 | daffy | Debian (version not in packet) | Blog | **Full** | `audit-linux.sh` |
| .169 | taz | Debian 13 | Photo Management | **Full** (13 untested) | `audit-linux.sh` |
| .199 | marvin | Ubuntu (version not in packet) | Database | **Full, lighter modules** | `audit-linux.sh` |
| .13 | foghorn | Rocky Linux (version not in packet) | Wiki/Chat | **Partial** | `audit-linux.sh` |
| .69 | sylvester | Rocky Linux (version not in packet) | Video Streamer | **Partial, lighter modules** | `audit-linux.sh` |
| .67 | porky | Arch | Tracker | **Partial** | `audit-linux.sh` |
| .12 | roadrunner | Tiny Core + "???" | K8S "Secure(?) Services" | **Manual; do not rely on BlueOps** | none supported |
| other | unknown | unknown | unknown | decide after inventory | per OS |

The packet warns there "may be other servers and services"; inventory first.

### Why each tier

* **Full.** The platform is what the collectors were built and tested for. Linux: tested on Ubuntu 22.04 and macOS against synthetic fixtures ([linux-audit.md](linux-audit.md)). Windows: tested on CI runners with PowerShell 5.1/7 against synthetic data ([windows-audit.md](windows-audit.md)). **Nothing has been run on a real Acme host**, and nothing on real Windows hardware beyond CI.
* **Debian and Ubuntu** also support the opt-in `--package-integrity` check (`dpkg --verify`). It hashes every packaged file and can take minutes; use it on `elmer`/`daffy`/`taz` only when disk and CPU headroom allow, never on `marvin` mid-event.
* **Rocky (`foghorn`, `sylvester`) and Arch (`porky`) are partial** because the docs list RHEL-family as untested and say they "may degrade"; Arch is not mentioned at all. Expect some modules to report gaps (`errors[]`, exit 6). There is no `rpm -V` or `pacman -Qkk` equivalent, so package-integrity checking on these is a manual step. SELinux state is not covered. A gap means "not checked", never "clean".
* **`bugs` (domain controller) is partial.** The Windows user module reads *local* accounts (`Win32_UserAccount` with `LocalAccount=True`). On a domain controller the accounts that matter are domain accounts and groups (Domain Admins, Enterprise Admins, krbtgt, GPOs, replication). The docs state Active Directory checks are not covered. The audit is still useful for services, processes, listeners, tasks, autoruns, persistence, firewall and security settings, but its `users` result must not be read as an AD review. Behaviour of the user module on a DC has not been tested; read that part of the report skeptically. Review AD by hand with built-in tools.
* **`roadrunner` is excluded.** Tiny Core is a BusyBox-based distribution; the collectors need Bash 4.2+ (not guaranteed there), the docs list BusyBox as untested, and the Kubernetes layer (containers, pods, RBAC, kubelet/API exposure) is not covered by any module. The packet itself marks it "???". Inspect it by hand (section 6). If you later confirm Bash 4.2+ is present you may try `--modules users,network,processes` read-only, but treat any output as unverified. Also check whether the install is RAM-only: if so, anything written on it, including a report, disappears on reboot and Red Team reboots are allowed.

## 3. Workflow

All times are relative to the 9:00 start. Do the same loop on every host: **collect, copy off, compare, investigate, change by hand, verify in Quotient, re-collect.**

### Before 9:00 (no target access yet)

1. Check out the repo on the analyst machine at a tagged or known commit and record its SHA-256 (CLAUDE.md: verify out-of-band; no release process exists yet, so record the commit hash and a `shasum -a 256` of the copied archive).
2. Create the report area. `reports/` is git-ignored, so nothing here is committed:
   ```
   reports/inv2/<host>/baseline/    first audit
   reports/inv2/<host>/YYYYMMDDTHHMMSSZ/   later audits
   reports/inv2/notes/change-log.md   hand-kept log of every change
   ```
3. Confirm Python 3.9+ on the analyst machine (diff and detect run there only; targets do not need Python).
4. **Decide how the code reaches each target.** The intended Linux method is `sudo apt install git; git clone https://github.com/snowstorm8/blueops.git; cd blueops` ([deployment.md](deployment.md)). The packet does **not** say whether the competition machines can reach GitHub or an apt mirror, so treat that as unverified until you try it at 9:00. Prepare the fallback now: clone on the analyst machine and copy the whole tree preserving modes (`tar` over SCP), then run `bash ./blueops ...`. On Windows hosts, plan to copy the folder (Git for Windows is not present by default).
5. Make sure the commit you will deploy is on `main` (a plain `git clone` gets `main`), and note its `./blueops version` commit hash.

### 9:00 to roughly 9:20: inventory and baseline

1. Receive master credentials (Discord); change passwords through the Quotient portal, not on the box.
2. Open Quotient and write down the scored services per host. This becomes the protected list. Add the listening ports each host actually has (step 4 below).
3. Copy the toolkit to **one host at a time** and run a full baseline as root/Administrator. Start with the cheapest and most exposed: `bugs`, then the web-facing hosts.
   * Linux (as root; `./blueops doctor` first, setup only if it says something required is MISSING):
     ```bash
     ./blueops doctor
     sudo ./blueops audit --json --output-dir /root/blueops-out
     ```
     Replace `/root/blueops-out` with any directory only root can read; BlueOps creates `blueops-run-<UTC>-audit-linux/` with mode 0700.
   * Windows (elevated; `speedy` is Server Core, so use its PowerShell prompt):
     ```powershell
     powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\audit\Invoke-WindowsAudit.ps1 -Json -OutputDir C:\blueops-out
     ```
     The bypass affects only that process.
4. Copy the whole run directory back to `reports/inv2/<host>/baseline/` on the analyst machine, then manage the on-host copy (below).
5. Note the exit code: `0` clean, `4` findings, `6` coverage gap (read `errors[]`), `3` wrong OS/precondition. Findings on a baseline are leads, not proof, and a compromise already present is **not** reported as a change (known false negative FN-1 in [detection-validation.md](detection-validation.md)): read the baseline's own findings.

Keep the load low: no host should be audited while another audit of the same host runs, and `marvin` (database) and `sylvester` (streamer) get lighter module sets:

```bash
sudo ./blueops audit --json --output-dir /root/blueops-out \
  --modules system,users,pam,processes,network,services,persistence
```

That skips the `filesystem` module, the heavy `find`-based SUID/world-writable/recent-file walk. Run `filesystem` on those hosts later, narrowed with `--fs-path` (for example `--fs-path /etc --fs-path /usr/local`), or not at all. Prefixing `nice -n 19` (and `ionice -c3` where available) is a sensible extra safeguard but BlueOps does not do it for you and it has not been tested here.

Windows boxes: Authenticode checks may contact certificate-revocation endpoints; on an isolated host they can be slow (documented limitation). Expect the first run on `bugs`, `speedy` and `wil.e` to take longer.

### Where to save reports

* **Analyst machine:** `reports/inv2/<host>/...` as above (git-ignored). Never commit reports or the change log: they list accounts and listeners, which counts as sensitive data under the packet's scoring.
* **On the target:** a root-/Administrators-only directory you create yourself, outside web roots and shares. After the copy-off, remove the on-host run directory yourself if you want it gone (BlueOps never deletes anything, including its own output). If you do keep it, remember Red Team can read anything they reach.
* Do not email reports, paste them into Discord channels other than your private `teamXX-chat`, or into tickets. Cite specific evidence lines in tickets instead.

### Ongoing: re-collect and compare

* Re-collect after every batch of changes and on a rhythm you can sustain (rotate hosts rather than all at once). The compare step is offline and costs the targets nothing.
* Compare on the analyst machine, from the repo root:
  ```bash
  ./blueops diff   reports/inv2/elmer/baseline/blueops-run-... reports/inv2/elmer/<later>/blueops-run-...
  ./blueops detect reports/inv2/elmer/baseline/blueops-run-... reports/inv2/elmer/<later>/blueops-run-...
  ```
  Exit `4` means detections, `6` means the comparison is incomplete. Never read exit `6` as "nothing changed".
* After you deliberately make a change, record it in the change log, then accept it with an exact, expiring `--accepted` entry ([detection-rules.md](detection-rules.md), format in `examples/accepted-changes.example.json`) so your own work stops hiding Red Team's. Keep entries narrow; the tool refuses to accept critical detections.

### Investigating a finding

1. Open the detection: severity, rationale, evidence, "basis" (`observed` = a recorded fact, `heuristic` = a pattern that may be benign), and listed investigation steps.
2. Cross-check against the packet and Quotient before judging. An unusual port or service on a scored host may be the scored service itself. **Do not disable anything just because it looks odd.**
3. Confirm with native tools on the host (current logins, process tree, unit/task definition, file timestamps). BlueOps is point-in-time and userland-only; a kernel-level implant can hide from it.
4. If it is malicious, write the ticket at `teams.wccomps.org` with specifics (host, time, what, evidence). Vague tickets are not acted on.
5. Choose the least disruptive fix, and fix it (section 5).

### Verifying a change without disrupting scoring

1. Before: check the protected list; confirm the change does not touch a scored port, its service unit/Windows service, its dependencies, or the account the scorer logs in with. Prefer disabling to deleting and reloading to restarting.
2. Record prior state by hand (copy the config file, note the setting, export the firewall rule) because BlueOps has no rollback yet.
3. Apply one change on one host.
4. Watch Quotient for at least two full check cycles (up to about 8 minutes at the 4-minute end) and confirm the affected service still passes from the scorer's point of view, not just locally. A service up on `localhost` can still fail through the router.
5. If it fails, revert immediately; do not stack fixes.
6. Re-run a narrow audit (`--modules` on that area) and diff to confirm the intended effect and no surprises.

## 4. Building the protected-service list

The packet gives hostnames, roles and a list of common protocols, not ports. The BlueOps way to derive them:

1. From Quotient, list each scored service and its host.
2. From each baseline report, read the network listener findings (`NET-*` on Linux and Windows) to see what actually listens and which process owns it.
3. Mark a port protected when Quotient scores it or when a scored service depends on it (for example a web app and its database or directory service). Include `bugs` (DC): domain authentication and DNS being down can break dependent hosts, so treat DC services as protected until proven otherwise.
4. Keep this list in `reports/inv2/notes/` and update it as injects arrive. It is read by humans; there is no profile loader yet (`profiles/` is empty).

## 5. What you may change, and how

BlueOps changes nothing. The decisions below are yours and follow the packet:

* **Router:** treat as off limits to scripts and bulk edits. The packet warns that locking yourself out or blocking the scoring engine leads to a very hard day, and each reset costs 100 points. Any firewall edit is a manual, reviewed, one-at-a-time decision by a named person, with the cutover-window timing (every 30 minutes) in mind. The packet recommends not disabling syslog or WAN firewall configuration access; it leaves that to each team.
* **Passwords:** via Quotient only.
* **Hosts:** manual, minimal, one change at a time, as in the verification procedure.

## 6. Manual checklist for `roadrunner` (Tiny Core + K8S) and unknowns

BlueOps cannot help here; do these by hand and record the results in your notes:

* Identify what it really is: `uname -a`, `cat /etc/os-release`, whether Bash exists, what persists across reboot.
* Listening sockets and owners (`netstat -tulpn` or `ss -tulpn` if present); compare to what Quotient scores.
* Running processes and the container runtime in use; which Kubernetes distribution (if any) and whether the API server or kubelet is reachable from outside the host.
* Local users, SSH keys and startup scripts (on Tiny Core: boot-time customization such as `bootlocal.sh`, persisted extensions and backup/restore lists) for anything you did not expect.
* Treat any "Secure(?)" claim in the packet as unverified.

Do the same for any host not in the packet table once you discover it.

## 7. Known limits to remember during the event

* Everything is untested on real Acme hosts. The best-covered targets are `elmer` (Ubuntu 22.04) and the Windows desktop/server family.
* `bugs`: no AD coverage. `roadrunner`: unsupported. Rocky and Arch: expect gaps.
* Detection is change-based; the baseline must be taken early, and an attacker present before the baseline is only visible through its standing findings.
* Unprivileged runs are partial and exit 6.
* There is no automatic hardening, containment, evidence manifest or rollback. Anything you do beyond audit is your manual procedure.
* No tool here should be pointed at the routers, the Quotient scoring engine, or any system outside your team's `192.168.220.0/24` pod.
