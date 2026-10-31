#!/usr/bin/env bash
# Module: persistence - systemd units, cron/at, startup scripts, shell profiles, autostart.
# Category: persistence. Safety: read-only detection; nothing is modified or executed.
# Usage: check-persistence.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

_per_scope_of() {
  case "$1" in
    SYSTEMD) echo systemd ;; CRON) echo cron ;; STARTUP | LDCONF | ACCESS) echo startup ;; UDEV) echo udev ;;
    APT) echo apt ;; SHELL) echo shell ;; AUTOSTART) echo autostart ;; AUDITD) echo auditd ;; *) echo "" ;;
  esac
}
_per_domain_of() { if [[ "$1" == CRON ]]; then echo scheduled_tasks; else echo persistence; fi; }

# _per_line_ids FILE : sets _PER_LINES (effective lines: not blank, not a comment) and _PER_IDS
# (comma-separated 12-hex fingerprints of the whitespace-normalised lines, up to 200 lines).
# Fingerprints, not text: they say how many lines were added or removed between two runs
# without copying file content (which may hold secrets) into the report.
_per_line_ids() {
  local line h n=0
  _PER_IDS=""
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
    n=$((n + 1))
    if ((n <= 200)); then
      line="$(printf '%s' "${line}" | tr -s '[:space:]' ' ')"
      h="$(bo_hash_id "${line}" 12)"
      _PER_IDS+="${_PER_IDS:+,}${h}"
    fi
  done <"$1"
  _PER_LINES=${n}
}

# Inventory for one persistence file. Crontab-style files get one record per entry (so a new
# job is visible by itself); everything else is one record with the file's SHA-256 and mode.
_per_inventory() { # TAG FILE REL
  local tag="$1" f="$2" rel="$3" scope domain=persistence h mode line norm
  case "${tag}" in
    SYSTEMD) scope=systemd ;;
    CRON)
      scope=cron
      domain=scheduled_tasks
      ;;
    STARTUP | LDCONF | ACCESS) scope=startup ;;
    AUDITD) scope=auditd ;;
    UDEV) scope=udev ;;
    APT) scope=apt ;;
    SHELL) scope=shell ;;
    AUTOSTART) scope=autostart ;;
    *) return 0 ;;
  esac
  if [[ "${tag}" == CRON && "${rel}" != /etc/cron.hourly/* && "${rel}" != /etc/cron.daily/* && "${rel}" != /etc/cron.weekly/* && "${rel}" != /etc/cron.monthly/* ]]; then
    while IFS= read -r line || [[ -n "${line}" ]]; do
      [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
      norm="$(printf '%s' "${line}" | tr -s '[:space:]' ' ')"
      bo_inv "${domain}" "${scope}" "cron:${rel}#$(bo_hash_id "${norm}")" "file=${rel}" "entry=$(printf '%s' "${norm:0:300}" | bo_redact)" "^file=${rel}"
    done <"${f}"
    return 0
  fi
  if ! h="$(bo_sha256_file "${f}")"; then
    h="@unknown"
    bo_cov "${domain}" "${scope}" degraded "no SHA-256 tool available or ${rel} unreadable; content hashes unknown"
  fi
  mode="$(bo_mode "${f}" || echo "@unknown")"
  local -a extra=()
  # Where a symlinked unit or script points is part of its identity.
  [[ -L "${f}" ]] && extra+=("target=$(readlink -- "${f}" 2>/dev/null || echo @unknown)")
  # Vendor unit files are only hashed (hundreds of them, changed by every package update).
  case "${rel}" in
    /usr/lib/systemd/* | /lib/systemd/*) ;;
    *)
      _per_line_ids "${f}"
      extra+=("lines=${_PER_LINES}")
      if ((_PER_LINES <= 200)); then extra+=("line_ids[]=${_PER_IDS}"); fi
      ;;
  esac
  bo_inv "${domain}" "${scope}" "persist:${scope}:${rel}" "sha256=${h}" "mode=${mode}" ${extra[@]+"${extra[@]}"} "^file=${rel}"
}

# _per_scan_file TAG FILE [LINE_FILTER_REGEX]
# Appends "TAG<TAB>ref<TAB>reason: redacted-line" to hits.tsv for suspicious lines.
_per_scan_file() {
  local tag="$1" f="$2" filter="${3-}" line reasons rel
  [[ -f "${f}" ]] || return 0
  rel="$(bo_unroot "${f}")"
  if [[ ! -r "${f}" ]]; then
    bo_perm_error "cannot read ${rel}" "PER-${tag}"
    bo_cov "$(_per_domain_of "${tag}")" "$(_per_scope_of "${tag}")" partial "cannot read ${rel}"
    return 0
  fi
  _per_inventory "${tag}" "${f}" "${rel}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ -n "${filter}" && ! "${line}" =~ ${filter} ]]; then continue; fi
    reasons="$(bo_suspicious_reasons "${line}")"
    [[ -n "${reasons}" ]] || continue
    bo_tsv_field "${rel}" >/dev/null # a file name may hold a newline: never a forged hits row
    printf '%s\t%s\t%s: %s\n' "${tag}" "${REPLY}" "${reasons}" "$(printf '%s' "${line:0:200}" | bo_redact)" >>"${BO_SCRATCH}/hits.tsv"
  done <"${f}"
}

_per_emit_hits() { # TAG ID TITLE SEVERITY CONFIDENCE DESC REMEDIATION MITRE
  local tag="$1" id="$2" title="$3" sev="$4" conf="$5" desc="$6" rem="$7" mitre="$8" t ref r
  local -a ev=()
  while IFS=$'\t' read -r t ref r; do
    [[ "${t}" == "${tag}" ]] && ev+=("file|${ref}|${r}")
  done <"${BO_SCRATCH}/hits.tsv"
  ((${#ev[@]} > 0)) && bo_finding "${id}" "${sev}" "${conf}" persistence "${title}" "${desc}" "${rem}" "${mitre}" "${ev[@]}"
  return 0
}

_per_systemd() {
  local d f
  local -a custom=()
  bo_find_failed || true # discard failures from earlier scans
  local -a types
  for d in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    [[ -d "$(bo_path "${d}")" ]] || continue
    # Administrator directories also list symlinks: `systemctl enable` is a symlink, and so is a
    # unit that points at /tmp. Vendor directories hold hundreds of aliases and stay files-only.
    types=(-type f)
    case "${d}" in /etc/* | /run/* | /usr/local/*) types=(\( -type f -o -type l \)) ;; *) ;; esac
    while IFS= read -r f; do
      [[ -n "${f}" ]] || continue
      if [[ -L "${f}" && ! -e "${f}" ]]; then
        # A dangling link still names a unit; record it instead of dropping it.
        bo_inv persistence systemd "persist:systemd:$(bo_unroot "${f}")" "sha256=@unknown" "target=$(readlink -- "${f}" 2>/dev/null || echo @unknown)" "^file=$(bo_unroot "${f}")"
        continue
      fi
      _per_scan_file SYSTEMD "${f}" '^[[:space:]]*(Exec[A-Za-z]*|Environment)='
      case "${d}" in
        /etc/* | /run/* | /usr/local/*)
          if [[ "${f}" == *.service || "${f}" == *.timer ]] && [[ "${f}" != *.d/* && "${f}" != *.wants/* && "${f}" != *.requires/* ]]; then
            custom+=("file|$(bo_unroot "${f}")")
          fi
          ;;
        *) ;;
      esac
    done < <(bo_find "$(bo_path "${d}")" -maxdepth 2 "${types[@]}" \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.conf' \))
  done
  while IFS=$'\t' read -r _ _ h; do
    for f in "${h}"/.config/systemd/user/*.service "${h}"/.config/systemd/user/*.timer; do
      [[ -f "${f}" ]] || continue
      _per_scan_file SYSTEMD "${f}" '^[[:space:]]*Exec[A-Za-z]*='
      custom+=("file|$(bo_unroot "${f}")|user-level unit")
    done
  done < <(bo_homes)
  bo_find_failed && bo_cov persistence systemd partial "find hit unreadable directories under the systemd unit paths"
  bo_is_root || bo_cov persistence systemd partial "not running as root; other users' user-level units may be unreadable"
  bo_cov persistence systemd complete
  ((${#custom[@]} > 0)) && bo_finding PER-SYSTEMD-002 low low persistence "Administrator-defined systemd units" \
    "${#custom[@]} service/timer unit(s) outside the vendor directories (and user-level units). Expected for local services; also a common persistence method." \
    "Confirm each unit is expected." "T1543.002" "${custom[@]}"
  _per_emit_hits SYSTEMD PER-SYSTEMD-001 "Suspicious systemd unit commands" high medium \
    "Unit Exec/Environment lines match reverse-shell, download-and-execute, world-writable-path or similar patterns." \
    "Preserve the unit file, then disable it (systemctl disable --now) after confirming it is not a scored service." T1543.002
}

_per_cron() {
  local d f n=0
  local -a inv=()
  local -a files=("$(bo_path /etc/crontab)" "$(bo_path /etc/anacrontab)")
  for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron /var/spool/cron/crontabs; do
    [[ -d "$(bo_path "${d}")" ]] || continue
    if [[ ! -r "$(bo_path "${d}")" || ! -x "$(bo_path "${d}")" ]]; then
      bo_perm_error "cannot list $(bo_unroot "$(bo_path "${d}")")" "PER-CRON-002"
      bo_cov scheduled_tasks cron partial "cannot list ${d}"
      continue
    fi
    for f in "$(bo_path "${d}")"/*; do [[ -f "${f}" ]] && files+=("${f}"); done
  done
  for f in ${files[@]+"${files[@]}"}; do
    [[ -f "${f}" ]] || continue
    n=$((n + 1))
    inv+=("file|$(bo_unroot "${f}")")
    _per_scan_file CRON "${f}"
  done
  bo_cov scheduled_tasks cron complete
  ((n > 0)) && bo_finding PER-CRON-001 info high persistence "Scheduled job files" "${n} cron/anacron file(s) found." "" "T1053.003" "${inv[@]}"
  _per_emit_hits CRON PER-CRON-002 "Suspicious cron job" high medium \
    "Cron entries match reverse-shell, download-and-execute, world-writable-path or similar patterns." \
    "Preserve the file, then remove or comment the entry after review." T1053.003
  local at_dir
  for at_dir in /var/spool/at /var/spool/cron/atjobs; do
    [[ -d "$(bo_path "${at_dir}")" ]] || continue
    if [[ -r "$(bo_path "${at_dir}")" ]]; then
      local -a atj=()
      for f in "$(bo_path "${at_dir}")"/*; do
        [[ -f "${f}" && "${f##*/}" != ".SEQ" ]] || continue
        atj+=("file|$(bo_unroot "${f}")")
        bo_inv scheduled_tasks at "at:$(bo_unroot "${f}")" "sha256=$(bo_sha256_file "${f}" || echo @unknown)" "^file=$(bo_unroot "${f}")"
      done
      ((${#atj[@]} > 0)) && bo_finding PER-AT-001 low medium persistence "Pending at jobs" "${#atj[@]} queued at job(s)." "Review with atq/at -c." "T1053.002" "${atj[@]}"
    else
      bo_perm_error "cannot read ${at_dir}" "PER-AT-001"
      bo_cov scheduled_tasks at partial "cannot read ${at_dir}"
    fi
  done
  bo_cov scheduled_tasks at complete
}

# Library search paths: a directory listed in ld.so.conf(.d) is searched before others for every
# dynamically linked program, so one that ordinary users or processes can write is a hijack path.
_per_ldconf() {
  local f line rel
  for f in "$(bo_path /etc/ld.so.conf)" "$(bo_path /etc/ld.so.conf.d)"/*.conf; do
    [[ -f "${f}" ]] || continue
    _per_scan_file LDCONF "${f}" '^NO-GENERIC-PATTERN-SCAN$' # inventory only; the path check below is specific
    [[ -r "${f}" ]] || continue
    rel="$(bo_unroot "${f}")"
    bo_tsv_field "${rel}" >/dev/null
    rel="${REPLY}"
    while IFS= read -r line || [[ -n "${line}" ]]; do
      line="${line%%#*}"
      line="${line#"${line%%[![:space:]]*}"}"
      line="${line%"${line##*[![:space:]]}"}"
      if [[ "${line}" =~ ^/(tmp|var/tmp|dev/shm|run/user|home|mnt|media)(/|$) ]]; then
        printf 'LDCONF\t%s\t%s\n' "${rel}" "library search path in a world- or user-writable location: ${line:0:200}" >>"${BO_SCRATCH}/hits.tsv"
      fi
    done <"${f}"
  done
  _per_emit_hits LDCONF PER-LDCONF-001 "Library search path in a writable location" high medium \
    "ld.so.conf lists a directory under /tmp, /home or another location ordinary users can write; libraries placed there are loaded by every dynamically linked program." \
    "Preserve the file and the directory contents, then remove the entry and run ldconfig." T1574.006
}

# Files that decide who may use cron and at: tampering lets an attacker schedule jobs (or lock
# administrators out).
_per_access() {
  local f
  for f in /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny; do
    _per_scan_file ACCESS "$(bo_path "${f}")"
  done
}

# auditd rules are what makes the host's own logging useful; their hash and line fingerprints are
# inventoried (a rule file emptied or replaced is a change), and a host that has auditd configured
# but defines no rule at all is reported as a standing weakness.
_per_auditd() {
  local f nrules=0 any=0
  [[ -d "$(bo_path /etc/audit)" ]] || return 0
  for f in "$(bo_path /etc/audit/audit.rules)" "$(bo_path /etc/audit/auditd.conf)" "$(bo_path /etc/audit/rules.d)"/*.rules; do
    [[ -f "${f}" ]] || continue
    any=1
    _per_scan_file AUDITD "${f}"
    [[ "${f}" == *.rules && -r "${f}" ]] && nrules=$((nrules + $(grep -c -E '^[[:space:]]*-[wa][[:space:]]' "${f}" 2>/dev/null || true)))
  done
  bo_cov persistence auditd complete
  if ((any && nrules == 0)); then
    bo_finding PER-AUDITD-001 low medium persistence "auditd is configured but defines no audit rules" \
      "/etc/audit exists but no watch (-w) or syscall (-a) rule is defined, so the audit daemon records almost nothing useful for investigation." \
      "Load a baseline rule set (for example from the audit package's sample rules) after checking it does not disturb scored services." "T1562.012" "file|/etc/audit"
  fi
}

_per_startup() {
  local f rc
  rc="$(bo_path /etc/rc.local)"
  if [[ -f "${rc}" ]]; then
    _per_scan_file STARTUP "${rc}"
    if [[ -r "${rc}" ]] && grep -v -E '^[[:space:]]*(#|exit[[:space:]]+0|$)' "${rc}" | grep -q -v '^#!'; then
      bo_finding PER-RC-001 low medium persistence "rc.local contains commands" "/etc/rc.local runs at boot and is a classic persistence location." \
        "Review its contents." "T1037.004" "file|/etc/rc.local"
    fi
  fi
  for f in "$(bo_path /etc/init.d)"/* "$(bo_path /etc/rc.d/init.d)"/*; do
    [[ -f "${f}" ]] && _per_scan_file STARTUP "${f}"
  done
  _per_emit_hits STARTUP PER-STARTUP-001 "Suspicious startup script" high medium \
    "Boot-time scripts match reverse-shell, download-and-execute, world-writable-path or similar patterns." \
    "Preserve the script, then remove the offending lines after review." T1037.004
  _per_ldconf
  _per_access
  _per_auditd
  local pre
  pre="$(bo_path /etc/ld.so.preload)"
  [[ -f "${pre}" ]] && _per_inventory STARTUP "${pre}" /etc/ld.so.preload
  if [[ -s "${pre}" ]] && grep -q -v -E '^[[:space:]]*(#|$)' "${pre}" 2>/dev/null; then
    bo_finding PER-LDPRE-001 high high persistence "/etc/ld.so.preload is populated" \
      "Libraries listed here are injected into every dynamically linked process; a standard userland rootkit technique." \
      "Inspect the listed libraries (hash them) before removal." T1574.006 "file|/etc/ld.so.preload"
  fi
  for f in "$(bo_path /etc/udev/rules.d)"/*.rules; do _per_scan_file UDEV "${f}" 'RUN'; done
  _per_emit_hits UDEV PER-UDEV-001 "Suspicious udev RUN rule" high low \
    "udev rules that execute programs can persist across reboots and hotplug events." "Review the rule." T1546
  for f in "$(bo_path /etc/apt/apt.conf.d)"/*; do _per_scan_file APT "${f}" 'Invoke|Update-Post|Pre-Install'; done
  _per_emit_hits APT PER-APT-001 "Suspicious package-manager hook" high medium \
    "APT hooks run as root on package operations." "Review the hook." T1546.016
  local -a pam=()
  if [[ -d "$(bo_path /etc/pam.d)" ]]; then
    while IFS= read -r f; do pam+=("file|$(bo_unroot "${f}")"); done < <(grep -l -E '^[^#]*pam_exec\.so' "$(bo_path /etc/pam.d)"/* 2>/dev/null || true)
  fi
  ((${#pam[@]} > 0)) && bo_finding PER-PAM-001 medium low persistence "PAM stack executes external programs" \
    "pam_exec runs commands during authentication; legitimate for some setups, also used to capture credentials." \
    "Review the referenced commands." T1556.003 "${pam[@]}"
  f="$(bo_path /etc/ssh/sshrc)"
  [[ -f "${f}" ]] && _per_inventory STARTUP "${f}" /etc/ssh/sshrc
  bo_cov persistence startup complete
  bo_cov persistence udev complete
  bo_cov persistence apt complete
  if [[ -f "${f}" ]]; then
    bo_finding PER-SSHRC-001 medium medium persistence "System-wide sshrc present" "/etc/ssh/sshrc runs on every SSH login." "Review its contents." T1546 "file|/etc/ssh/sshrc"
  fi
}

_per_shell() {
  local f h
  for f in "$(bo_path /etc/profile)" "$(bo_path /etc/bash.bashrc)" "$(bo_path /etc/bashrc)" "$(bo_path /etc/zsh/zshrc)" "$(bo_path /etc/environment)" "$(bo_path /etc/profile.d)"/*; do
    _per_scan_file SHELL "${f}"
  done
  while IFS=$'\t' read -r _ _ h; do
    for f in .bashrc .bash_profile .bash_login .profile .zshrc .zprofile .bash_logout .ssh/rc; do
      _per_scan_file SHELL "${h}/${f}"
    done
    for f in "${h}"/.config/autostart/*.desktop; do _per_scan_file AUTOSTART "${f}" '^Exec='; done
  done < <(bo_homes)
  for f in "$(bo_path /etc/xdg/autostart)"/*.desktop; do _per_scan_file AUTOSTART "${f}" '^Exec='; done
  bo_is_root || bo_cov persistence shell partial "not running as root; other users' dotfiles may be unreadable"
  bo_is_root || bo_cov persistence autostart partial "not running as root; other users' autostart entries may be unreadable"
  bo_cov persistence shell complete
  bo_cov persistence autostart complete
  _per_emit_hits SHELL PER-SHELL-001 "Suspicious shell startup content" high medium \
    "Profile/rc files run on login or shell start and match reverse-shell, alias-hijack, LD_PRELOAD or similar patterns." \
    "Preserve the file, then remove the offending lines after review." T1546.004
  _per_emit_hits AUTOSTART PER-AUTOSTART-001 "Suspicious desktop autostart entry" high medium \
    "Autostart entries execute at graphical login." "Review the entry." T1547.013
}

mod_persistence() {
  : >"${BO_SCRATCH}/hits.tsv"
  _per_systemd
  _per_cron
  _per_startup
  _per_shell
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main check-persistence persistence persistence 0 "$@" || rc=$?
  exit "${rc}"
fi
