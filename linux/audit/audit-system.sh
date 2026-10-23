#!/usr/bin/env bash
# Module: system - OS, kernel, hostname, uptime, hardware.
# Category: audit. Safety: read-only (reads /etc, /proc, /sys; runs uname/df).
# Usage: audit-system.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

_sys_first_line() {
  local f
  f="$(bo_path "$1")"
  [[ -r "${f}" ]] && head -n 1 -- "${f}"
  return 0
}

mod_system() {
  local pretty id idlike ver kernel host arch up_s up_txt ncpu cpu mem_kb virt taint
  pretty="$(bo_osrel PRETTY_NAME)"
  id="$(bo_osrel ID)"
  idlike="$(bo_osrel ID_LIKE)"
  ver="$(bo_osrel VERSION_ID)"
  kernel="$(_sys_first_line /proc/sys/kernel/osrelease)"
  [[ -n "${kernel}" ]] || kernel="$(uname -r 2>/dev/null || echo unknown)"
  host="$(bo_hostname)"
  arch="$(uname -m 2>/dev/null || echo unknown)"

  up_s="$(_sys_first_line /proc/uptime)"
  up_s="${up_s%%.*}"
  up_s="${up_s%% *}"
  if [[ "${up_s}" =~ ^[0-9]+$ ]]; then
    up_txt="$((up_s / 86400))d $((up_s % 86400 / 3600))h $((up_s % 3600 / 60))m"
  else
    up_txt="unknown"
    up_s=""
    bo_error UPTIME_UNAVAILABLE "could not read /proc/uptime" "SYS-INFO-001" 0
  fi

  ncpu="unknown"
  cpu="unknown"
  if [[ -r "$(bo_path /proc/cpuinfo)" ]]; then
    ncpu="$(grep -c '^processor' "$(bo_path /proc/cpuinfo)" || true)"
    cpu="$(sed -n 's/^model name[[:space:]]*:[[:space:]]*//p' "$(bo_path /proc/cpuinfo)" | head -n 1)"
    [[ -n "${cpu}" ]] || cpu="unknown"
  else
    bo_error HW_UNAVAILABLE "/proc/cpuinfo not readable; CPU details missing" "SYS-INFO-001" 0
  fi
  mem_kb=""
  if [[ -r "$(bo_path /proc/meminfo)" ]]; then
    mem_kb="$(awk '/^MemTotal:/ {print $2}' "$(bo_path /proc/meminfo)")"
  fi
  virt=""
  if bo_have systemd-detect-virt && [[ -z "${BO_ROOT:-}" ]]; then
    virt="$(systemd-detect-virt 2>/dev/null || true)"
  fi
  [[ -n "${virt}" ]] || virt="$(_sys_first_line /sys/class/dmi/id/product_name)"

  local mem_txt=unknown desc
  [[ -n "${mem_kb}" ]] && mem_txt="$((mem_kb / 1024)) MiB"
  desc="Hostname ${host}; OS ${pretty:-unknown} (id=${id:-unknown}, version=${ver:-unknown}); kernel ${kernel}; arch ${arch}; uptime ${up_txt}; CPUs ${ncpu} (${cpu}); memory ${mem_txt}; platform ${virt:-unknown}"
  local -a ev=("file|/etc/os-release" "file|/proc/sys/kernel/osrelease")
  if bo_have df; then
    local disks
    disks="$(df -Pk 2>/dev/null | awk 'NR>1 && $1 ~ /^\// && $2 > 0 {printf "%s %dMiB %s %s; ", $1, $2/1024, $5, $6}' | head -c 600 || true)"
    [[ -n "${disks}" ]] && desc+="; disks: ${disks%; }"
  else
    bo_error TOOL_MISSING "df not found; disk usage omitted" "SYS-INFO-001" 0
  fi
  bo_finding SYS-INFO-001 info high system "System inventory" "${desc}" "" "" "${ev[@]}"

  case "${id}" in
    debian | ubuntu | rhel | centos | fedora | rocky | almalinux | ol | amzn | sles | opensuse* | alpine | arch | kali | raspbian | linuxmint) ;;
    *)
      if [[ -z "${id}" ]]; then
        bo_error DISTRO_UNKNOWN "no readable /etc/os-release; distribution undetected, path assumptions follow the FHS" "SYS-OS-001" 0
      fi
      bo_finding SYS-OS-001 low high system "Unrecognized or undetected distribution" \
        "ID='${id:-none}' ID_LIKE='${idlike}' is not a distribution BlueOps has been exercised against; module coverage may be degraded." \
        "Review coverage gaps in this report and verify results manually." "" "file|/etc/os-release"
      ;;
  esac

  if [[ -n "${up_s}" ]] && ((up_s > 365 * 86400)); then
    bo_finding SYS-UPTIME-001 low medium system "Uptime exceeds one year" \
      "Uptime is ${up_txt}; kernel and library updates likely require a reboot to take effect." \
      "Plan a reboot window after confirming scored services restart cleanly." "" "file|/proc/uptime"
  fi

  taint="$(_sys_first_line /proc/sys/kernel/tainted)"
  if [[ "${taint}" =~ ^[0-9]+$ ]] && (((taint & 12288) != 0)); then
    bo_finding SYS-KERN-001 low low system "Kernel tainted by out-of-tree or unsigned module" \
      "Taint mask ${taint} includes out-of-tree (4096) or unsigned (8192) module bits. Legitimate for some drivers; also seen with rootkit modules." \
      "Review loaded modules (lsmod) against expected drivers." "T1547.006" "file|/proc/sys/kernel/tainted"
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-system audit system 0 "$@" || rc=$?
  exit "${rc}"
fi
