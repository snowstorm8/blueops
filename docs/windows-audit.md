# Windows read-only audit (v0.1)

`windows/audit/Invoke-WindowsAudit.ps1` inspects a Windows host and reports findings. It is **read-only**: it never changes system state and writes only to `-OutputDir` (a run directory with an owner/Administrators-only ACL). Use it only on hosts you are authorized to administer.

It targets Windows PowerShell 5.1 (and also runs on PowerShell 7), needs no modules and no network access, and reads data through registry, CIM, and built-in cmdlets/tools with fallbacks.

```powershell
.\windows\audit\Invoke-WindowsAudit.ps1                                  # all modules, human summary (run as Administrator for full coverage)
.\windows\audit\Invoke-WindowsAudit.ps1 -Json -OutputDir .\out           # JSON on stdout; report.json/report.txt/run.log in .\out\blueops-run-<UTC>-audit-windows\
.\windows\audit\Invoke-WindowsAudit.ps1 -Modules users,network -Quiet -Json > report.json
.\windows\persistence\Find-Persistence.ps1 -Json                         # persistence module alone
```

If script execution is restricted, run with `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows\audit\Invoke-WindowsAudit.ps1` (this affects only that process).

## Options

| Option | Meaning |
|---|---|
| `-Modules LIST` | Subset of `system,users,processes,network,services,tasks,autoruns,persistence,firewall,security,filesystem` (default: all). `-ListModules` prints them. |
| `-Json` / `-Format json` | JSON on stdout (or `report.json` with `-OutputDir`); human text goes to stderr. |
| `-OutputDir DIR` | Create `DIR\blueops-run-<YYYYMMDDTHHMMSSZ>-audit-windows\` with `report.json`, `report.txt`, `run.log`. |
| `-FailOn SEV` | Lowest severity that yields exit 4 (default `medium`). |
| `-RecentDays N` | Window for "recently modified" (default 7). |
| `-FsPath DIR` | Restrict the filesystem executable scan to DIR (repeatable). |
| `-Quiet`, `-Verbose`, `-NoColor` | Output control. |

Individual module scripts live in `windows/audit/` (`Get-SystemAudit.ps1`, ...) and `windows/persistence/Get-PersistenceAudit.ps1`; they are dot-sourced by the entry points, not run directly. `Find-Persistence.ps1` is the standalone persistence tool (tool name `find-persistence`, category `persistence`).

## Exit codes

`0` nothing at/above `-FailOn` and no material gaps · `2` usage error · `3` not Windows · `4` findings at/above `-FailOn` · `6` no such findings but a material coverage gap (a module crashed, or a core data source such as the firewall policy was unavailable). Gaps expected when not elevated (access denied) or covered by a fallback are listed in `errors[]` but do not change the exit code. Exit 4 takes precedence over 6.

## Output

Reports conform to `shared/schemas/audit-report.schema.json` (0.1.0). Inventory is emitted as `info` findings (`*-INFO-001`, ...) whose evidence lists the items; findings aggregate one check per ID with evidence per item. Evidence lists are capped and the description says when truncated. Secrets are not printed: command lines and registry strings are redacted (`password=`, `token`, `secret`, `api-key`, `--password X`, `Authorization:` headers), hashes and key material are never read. Non-ASCII text is escaped so JSON is always valid.

## Checks

| Module | IDs | Checks |
|---|---|---|
| system | SYS-* | OS/build/hostname/domain/uptime/hardware inventory; end-of-life Windows versions; uptime > 1 year; newest hotfix older than 90 days |
| users | USR-* | local account inventory; administrators and group changes; enabled Guest; passwords that never expire / not required; hidden (`$`) accounts; renamed built-in Administrator (RID 500); RDP users; active sessions |
| processes | PRC-* | inventory with parent and command line; system-process name masquerading and wrong parents; suspicious command lines (encoded/hidden PowerShell, download cradles, LOLBin abuse); execution from temp/user-writable paths |
| network | NET-* | listeners and established connections (`Get-NetTCPConnection`, `netstat` fallback); exposed legacy/remote-access/database ports; shells as network owners; interfaces, DNS, `hosts` overrides, proxy settings, SMB shares, IP forwarding |
| services | SVC-* | service inventory; unusual accounts; unquoted paths; binaries in user-writable paths; suspicious command lines; legacy services; stopped/disabled security services; drivers outside system directories |
| tasks | TSK-* | scheduled task inventory; suspicious actions; user-writable targets; hidden tasks; tasks running as SYSTEM from non-system paths |
| autoruns | AUT-* | Run/RunOnce (including Policies and Wow6432Node), Active Setup, Winlogon `Shell`/`Userinit`, startup folders (machine and loaded user hives) |
| persistence | PER-* | WMI event subscriptions, IFEO debuggers, SilentProcessExit, AppInit/AppCert DLLs, LSA packages, netsh helpers, time providers, print monitors, COM hijack candidates, screensavers, `Command Processor\AutoRun`, logon scripts, boot execute, PowerShell profiles, BITS jobs, accessibility-binary replacement |
| firewall | FW-* | profile state, default actions, logging; rule review (broad inbound allow, risky ports, program rules in user-writable paths) read from the policy registry |
| security | SEC-* | UAC, LSA protection, SMBv1/signing, RDP/NLA, auto-logon, LLMNR, Defender state and exclusions, audit policy, password policy, PowerShell logging, WinRM, Windows Update |
| filesystem | FS-* | executables and scripts in user-writable/temp locations (signature checked, capped), root-of-drive oddities, recent changes to system directories, writable ACLs on sensitive paths |

## Contextual heuristics (false-positive control)

- Findings carry a path "zone" (system, Program Files, temp, AppData, ProgramData, other) combined with the Authenticode status. A validly signed binary in a user-writable folder is rated lower than an unsigned one; known per-user application folders are not treated like `Temp`.
- Command-line heuristics separate strong indicators (encoded commands, hidden windows with download cradles) from weak ones (a bare `powershell.exe`), which are only reported alongside another signal.
- Loaded user hives are read through `HKEY_USERS\<SID>`; offline `NTUSER.DAT` files are never loaded, so profiles of users who are not logged in are covered only for startup folders.
- Check severity is the maximum over the explicit severity of its hits.

## Known limitations

- Findings are heuristics; many `medium`/`low` items have benign explanations. Detection is point-in-time and userland-only; a kernel-level implant can hide from every check.
- Not elevated, the audit still runs but records `PERM_DENIED`-style gaps (other users' processes, services' paths, audit policy, some ACLs).
- BITS jobs are listed only while the BITS service is running (`BITS_UNREADABLE` otherwise): starting a stopped BITS service changes its startup type from Manual to Automatic, which a read-only audit must not do.
- Offline user hives, event-log analysis, Active Directory/domain controller checks, and memory inspection are not covered.
- Windows PowerShell 5.1 and PowerShell 7 are supported; Constrained Language Mode hosts may degrade (reported as gaps).
- Tests run against synthetic fixtures; behaviour on real Windows editions beyond the CI runners is unverified.

## Testing hooks

Test-only environment variables (never use in production): `BO_FIXTURE_DIR` (read `data/*.json|txt` and a file tree from `tests/fixtures/windows-host` instead of the live host), `BO_FORCE_MISSING` (space-separated provider names treated as unavailable), and `BO_TEST_SHELL` (shell used by Pester to launch the scripts; default `powershell.exe` on Windows, `pwsh` elsewhere).
