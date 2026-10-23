#!/usr/bin/env bash
# Module: persistence - systemd units, cron/at, startup scripts, shell profiles, autostart.
# Category: persistence. Safety: read-only detection; nothing is modified or executed.
# Usage: check-persistence.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

# _per_scan_file TAG FILE [LINE_FILTER_REGEX]
# Appends "TAG<TAB>ref<TAB>reason: redacted-line" to hits.tsv for suspicious lines.
_per_scan_file() {
  local tag="$1" f="$2" filter="${3-}" line reasons rel
  [[ -f "${f}" ]] || return 0
  rel="$(bo_unroot "${f}")"
  if [[ ! -r "${f}" ]]; then
    bo_perm_error "cannot read ${rel}" "PER-${tag}"
    return 0
  fi
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ -n "${filter}" && ! "${line}" =~ ${filter} ]]; then continue; fi
    reasons="$(bo_suspicious_reasons "${line}")"
    [[ -n "${reasons}" ]] || continue
    printf '%s\t%s\t%s: %s\n' "${tag}" "${rel}" "${reasons}" "$(printf '%s' "${line:0:200}" | bo_redact)" >>"${BO_SCRATCH}/hits.tsv"
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
  for d in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    [[ -d "$(bo_path "${d}")" ]] || continue
    while IFS= read -r f; do
      [[ -n "${f}" ]] || continue
      _per_scan_file SYSTEMD "${f}" '^[[:space:]]*(Exec[A-Za-z]*|Environment)='
      case "${d}" in /etc/* | /run/* | /usr/local/*) [[ "${f}" == *.service || "${f}" == *.timer ]] && [[ "${f}" != *.d/* ]] && custom+=("file|$(bo_unroot "${f}")") ;; *) ;; esac
    done < <(bo_find "$(bo_path "${d}")" -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.conf' \))
  done
  while IFS=$'\t' read -r _ _ h; do
    for f in "${h}"/.config/systemd/user/*.service "${h}"/.config/systemd/user/*.timer; do
      [[ -f "${f}" ]] || continue
      _per_scan_file SYSTEMD "${f}" '^[[:space:]]*Exec[A-Za-z]*='
      custom+=("file|$(bo_unroot "${f}")|user-level unit")
    done
  done < <(bo_homes)
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
  ((n > 0)) && bo_finding PER-CRON-001 info high persistence "Scheduled job files" "${n} cron/anacron file(s) found." "" "T1053.003" "${inv[@]}"
  _per_emit_hits CRON PER-CRON-002 "Suspicious cron job" high medium \
    "Cron entries match reverse-shell, download-and-execute, world-writable-path or similar patterns." \
    "Preserve the file, then remove or comment the entry after review." T1053.003
  local at_dir
  for at_dir in /var/spool/at /var/spool/cron/atjobs; do
    [[ -d "$(bo_path "${at_dir}")" ]] || continue
    if [[ -r "$(bo_path "${at_dir}")" ]]; then
      local -a atj=()
      for f in "$(bo_path "${at_dir}")"/*; do [[ -f "${f}" && "${f##*/}" != ".SEQ" ]] && atj+=("file|$(bo_unroot "${f}")"); done
      ((${#atj[@]} > 0)) && bo_finding PER-AT-001 low medium persistence "Pending at jobs" "${#atj[@]} queued at job(s)." "Review with atq/at -c." "T1053.002" "${atj[@]}"
    else
      bo_perm_error "cannot read ${at_dir}" "PER-AT-001"
    fi
  done
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
  local pre
  pre="$(bo_path /etc/ld.so.preload)"
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
