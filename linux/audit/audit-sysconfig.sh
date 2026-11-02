#!/usr/bin/env bash
# Module: sysconfig - mount options, core-dump handling and logging integrity.
# Category: audit. Safety: read-only (/proc/mounts, /proc/sys, /var/log metadata, journald and
# syslog configuration). Log *contents* are never read.
# Usage: audit-sysconfig.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

# /proc/mounts escapes spaces as \040; the three directories checked here never contain any.
_cfg_mounts() {
  local mt mnt fstype opts _r want flags missing o
  mt="$(bo_path /proc/mounts)"
  if [[ ! -r "${mt}" ]]; then
    bo_error MOUNTS_UNREADABLE "/proc/mounts unreadable; mount options not assessed" "CFG-MNT-001"
    bo_cov config mounts unavailable "/proc/mounts unreadable"
    return 0
  fi
  local -a weak=()
  # The last mount of a path wins (stacked mounts), so read everything first.
  declare -A opt_of=() type_of=()
  while IFS=' ' read -r _ mnt fstype opts _r; do
    [[ -n "${mnt}" ]] || continue
    opt_of["${mnt}"]="${opts}"
    type_of["${mnt}"]="${fstype}"
  done <"${mt}"
  for want in /tmp /var/tmp /dev/shm; do
    [[ -n "${opt_of[${want}]+x}" ]] || continue
    opts="${opt_of[${want}]}"
    flags=""
    missing=""
    for o in nosuid nodev noexec; do
      if [[ ",${opts}," == *",${o},"* ]]; then flags+="${flags:+,}${o}"; else missing+="${missing:+, }${o}"; fi
    done
    bo_inv config mounts "mount:${want}" "fstype=${type_of[${want}]}" "flags[]=${flags}" "^file=/proc/mounts"
    [[ -z "${missing}" ]] || weak+=("file|/proc/mounts|${want} (${type_of[${want}]}) is mounted without ${missing}")
  done
  bo_cov config mounts complete
  ((${#weak[@]} > 0)) && bo_finding CFG-MNT-001 low high sysconfig "World-writable directory mounted without nosuid/nodev/noexec" \
    "Everyone can write to these directories, so they are where payloads are staged and executed. Mount options that forbid set-ID files, device nodes and execution make that harder. Only separately mounted directories are assessed." \
    "Add nosuid,nodev,noexec in /etc/fstab and remount. Test first: some installers and scored services execute from /tmp." "T1059" "${weak[@]}"
  return 0
}

# Known handlers that legitimately receive core dumps through a pipe.
_cfg_core_handler_ok() {
  case "$1" in
    "|/usr/lib/systemd/systemd-coredump "* | "|/lib/systemd/systemd-coredump "* | "|/usr/share/apport/apport "* | "|/usr/libexec/abrt-hook-ccpp "* | "|/usr/lib/systemd/systemd-coredump" | "|/lib/systemd/systemd-coredump") return 0 ;;
    *) return 1 ;;
  esac
}

_cfg_core() {
  local pat dump
  pat="$(bo_path /proc/sys/kernel/core_pattern)"
  dump="$(bo_path /proc/sys/fs/suid_dumpable)"
  local -a ev=()
  if [[ -r "${pat}" ]]; then
    local p
    p="$(head -n 1 "${pat}" 2>/dev/null || true)"
    bo_inv config core "config:core:core_pattern" "value=${p}" "^file=/proc/sys/kernel/core_pattern"
    if [[ "${p}" == '|'* ]] && ! _cfg_core_handler_ok "${p}"; then
      bo_finding CFG-CORE-001 high medium sysconfig "core_pattern pipes crash dumps to an unrecognised program" \
        "When a process crashes, the kernel runs this program as root. Attackers use it as a persistence and privilege-escalation hook. Known handlers (systemd-coredump, apport, abrt) are not flagged." \
        "Confirm the program is part of an installed package; if not, restore the distribution default (kernel.core_pattern) and investigate who set it." "T1546" "file|/proc/sys/kernel/core_pattern|${p:0:200}"
    fi
    bo_cov config core complete
  else
    bo_cov config core unavailable "/proc/sys/kernel/core_pattern unreadable"
  fi
  if [[ -r "${dump}" ]]; then
    local d
    d="$(head -n 1 "${dump}" 2>/dev/null || true)"
    bo_inv config core "config:core:suid_dumpable" "value=${d}" "^file=/proc/sys/fs/suid_dumpable"
    if [[ "${d}" =~ ^[0-9]+$ && "${d}" != "0" ]]; then
      ev+=("file|/proc/sys/fs/suid_dumpable|fs.suid_dumpable=${d}")
      bo_finding CFG-CORE-002 low high sysconfig "Set-ID programs may write core dumps" \
        "With fs.suid_dumpable above 0, a crashing privileged program can leave a dump containing secrets (password hashes, keys) readable by others." \
        "Set fs.suid_dumpable=0 in /etc/sysctl.d/ and apply with 'sysctl --system'." "T1003" "${ev[@]}"
    fi
  fi
  return 0
}

# A log that is a link to /dev/null (or any other device) silently discards everything written.
_cfg_log_tamper() {
  local name f target size
  local -a bad=() odd=() empty=()
  for name in wtmp btmp lastlog auth.log secure syslog messages kern.log audit/audit.log; do
    f="$(bo_path "/var/log/${name}")"
    if [[ -L "${f}" ]]; then
      target="$(readlink -- "${f}" 2>/dev/null || true)"
      case "${target}" in
        /dev/*) bad+=("log|/var/log/${name}|is a symbolic link to ${target}: log records are discarded") ;;
        # Alias or rotation links that stay inside the log tree are ordinary.
        /var/log/* | /run/* | /var/run/*) ;;
        /* | *../*) odd+=("log|/var/log/${name}|is a symbolic link to ${target:0:120}") ;;
        ?*) ;;
        *) odd+=("log|/var/log/${name}|is a symbolic link to ${target:0:120}") ;;
      esac
    elif [[ -f "${f}" ]]; then
      size="$(stat -c %s -- "${f}" 2>/dev/null || echo 1)"
      case "${name}" in
        wtmp | btmp | lastlog) [[ "${size}" == "0" ]] && empty+=("log|/var/log/${name}|exists but is empty") ;;
        *) ;;
      esac
    fi
  done
  ((${#bad[@]} > 0)) && bo_finding CFG-LOG-001 high high sysconfig "Log file redirected to a device" \
    "A system log is a symbolic link to /dev/null (or another device), which discards every record written to it. This is a standard way to hide activity." \
    "Preserve the link and its timestamps as evidence, then restore a regular file and restart the logging service; review what happened while logging was off." "T1070.002" "${bad[@]}"
  ((${#odd[@]} > 0)) && bo_finding CFG-LOG-004 medium medium sysconfig "Log file is a symbolic link leaving the log directory" \
    "A system log points outside /var/log. This is occasionally deliberate (a separate log volume) and also how records get redirected away from the usual place." \
    "Confirm the target is an intended log volume; otherwise replace it with a regular file." "T1070.002" "${odd[@]}"
  ((${#empty[@]} > 0)) && bo_finding CFG-LOG-002 low low sysconfig "Login records are empty" \
    "wtmp, btmp or lastlog exists but has no content. On a host that has been up for a while this can mean the records were truncated; on a fresh install it is normal." \
    "Compare with the host's age and with backups; if unexplained, treat as possible log clearing." "T1070.002" "${empty[@]}"
  return 0
}

# Logs that are not kept after a reboot (or not kept at all) remove the evidence defenders need.
_cfg_log_pipeline() {
  local syslog=no journal=auto storage f jd
  for f in /etc/rsyslog.conf /etc/syslog-ng/syslog-ng.conf /etc/syslog.conf; do
    [[ -e "$(bo_path "${f}")" ]] && syslog=yes
  done
  storage=""
  jd="$(bo_path /etc/systemd)"
  if [[ -d "${jd}" ]]; then
    storage="$(grep -hsE -e '^[[:space:]]*Storage[[:space:]]*=' "${jd}/journald.conf" "${jd}"/journald.conf.d/*.conf 2>/dev/null | tail -n 1 | sed -E 's/^[^=]*=[[:space:]]*//' || true)"
  fi
  [[ -n "${storage}" ]] && journal="${storage}"
  [[ -d "$(bo_path /var/log/journal)" ]] && journal="persistent-dir"
  bo_inv config logging "config:logging:pipeline" "syslog_daemon=${syslog}" "journal_storage=${journal}"
  bo_cov config logging complete
  if [[ "${syslog}" == "no" ]]; then
    case "${journal}" in
      persistent | persistent-dir) ;;
      volatile | none)
        bo_finding CFG-LOG-003 medium high sysconfig "Logs are not persisted" \
          "journald is configured with Storage=${journal} and no syslog daemon configuration was found, so logs are lost on reboot (or never kept)." \
          "Create /var/log/journal and set Storage=persistent in journald.conf, or install and configure a syslog daemon; forward logs off the host where possible." "T1562.006" "file|/etc/systemd/journald.conf|Storage=${journal}"
        ;;
      *)
        bo_finding CFG-LOG-003 low low sysconfig "No persistent logging detected" \
          "No syslog daemon configuration and no /var/log/journal directory were found; with journald's default (Storage=auto) logs may be lost on reboot. Other collectors (agents, remote logging) are not detected." \
          "Confirm where logs are kept; create /var/log/journal or configure a syslog daemon, and forward logs off the host." "T1562.006" "file|/var/log/journal|directory not found"
        ;;
    esac
  fi
  return 0
}

mod_sysconfig() {
  _cfg_mounts
  _cfg_core
  _cfg_log_tamper
  _cfg_log_pipeline
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-sysconfig audit sysconfig 0 "$@" || rc=$?
  exit "${rc}"
fi
