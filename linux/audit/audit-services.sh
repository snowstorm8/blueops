#!/usr/bin/env bash
# Module: services - systemd units, enabled services, failed services.
# Category: audit. Safety: read-only (systemctl list-*, init script listing).
# Usage: audit-services.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

# Drop the status bullet systemctl prints before failed units.
_svc_strip() { sed 's/^[^A-Za-z0-9_@-]*//'; }

_svc_legacy_name() {
  case "${1%.service}" in
    telnet* | rsh* | rlogin* | rexec* | tftp* | xinetd | inetd | vsftpd | proftpd | pure-ftpd | rpcbind | nfs-server | smbd | nmbd | smb | snmpd | avahi-daemon) return 0 ;;
    *) return 1 ;;
  esac
}

_svc_sysv() {
  local d f
  local -a ev=()
  for d in /etc/init.d /etc/rc.d/init.d; do
    [[ -d "$(bo_path "${d}")" ]] || continue
    for f in "$(bo_path "${d}")"/*; do
      if [[ -f "${f}" ]]; then
        ev+=("file|$(bo_unroot "${f}")")
        bo_inv services "" "service:sysv:${f##*/}" "~file=$(bo_unroot "${f}")"
      fi
    done
  done
  if ((${#ev[@]} > 0)); then
    bo_finding SVC-INFO-001 info medium services "SysV init scripts (systemd not detected)" \
      "${#ev[@]} init script(s). Run state is not determined without systemd." "" "" "${ev[@]}"
    bo_cov services "" degraded "systemd not detected; only SysV init scripts are listed, run state is unknown"
  else
    bo_error NO_INIT_SYSTEM "neither systemd nor SysV init scripts found; service state unknown" "SVC-INFO-001"
    bo_cov services "" unavailable "no init system detected"
  fi
}

mod_services() {
  if ! bo_have systemctl || { [[ -z "${BO_ROOT:-}" ]] && [[ ! -d /run/systemd/system ]]; }; then
    bo_error NO_SYSTEMD "systemd not active or systemctl missing; falling back to init scripts" "SVC-INFO-001" 0
    _svc_sysv
    return 0
  fi
  local units unitfiles failed
  units="$(systemctl list-units --type=service --all --no-legend --no-pager --plain 2>/dev/null | _svc_strip || true)"
  unitfiles="$(systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager 2>/dev/null | _svc_strip || true)"
  failed="$(systemctl list-units --type=service,socket --state=failed --no-legend --no-pager --plain 2>/dev/null | _svc_strip || true)"
  if [[ -z "${units}" && -z "${unitfiles}" ]]; then
    bo_error SYSTEMCTL_FAILED "systemctl returned no data (not booted with systemd, or bus unreachable)" "SVC-INFO-001"
    _svc_sysv
    return 0
  fi
  local u active sub desc state n_run=0 n_all=0 est
  local -a running=() fail=() failsock=() enabled=() legacy=()
  while IFS=' ' read -r u _ active sub desc; do
    [[ -n "${u}" ]] || continue
    u="${u#●}"
    n_all=$((n_all + 1))
    if [[ "${sub}" == "running" ]]; then
      n_run=$((n_run + 1))
      running+=("other|${u}|${active}/${sub} ${desc}")
    fi
  done <<<"${units}"
  while IFS=' ' read -r u _ active sub desc; do
    [[ -n "${u}" ]] || continue
    case "${u}" in
      *.socket) failsock+=("other|${u}|${active}/${sub} ${desc}") ;;
      *) fail+=("other|${u}|${active}/${sub} ${desc}") ;;
    esac
  done <<<"${failed}"
  while IFS=' ' read -r u state _; do
    [[ -n "${u}" ]] || continue
    enabled+=("other|${u}|${state}")
    if _svc_legacy_name "${u}"; then legacy+=("other|${u}|enabled"); fi
  done <<<"${unitfiles}"

  # One record per unit (loaded or enabled); run state is compared, so a stopped or failed
  # service shows up as a modification.
  while IFS=' ' read -r u _ active sub _; do
    [[ -n "${u}" ]] || continue
    u="${u#●}"
    est="$(awk -v u="${u}" '$1 == u { print $2; exit }' <<<"${unitfiles}")"
    bo_inv services "" "service:${u}" "active=${active}" "sub=${sub}" "enabled=${est:-no}"
  done <<<"${units}"
  awk '{ print $1 }' <<<"${units}" >"${BO_SCRATCH}/loaded-units.txt"
  while IFS=' ' read -r u state _; do
    [[ -n "${u}" ]] || continue
    grep -q -F -x -e "${u}" "${BO_SCRATCH}/loaded-units.txt" && continue
    bo_inv services "" "service:${u}" "active=@unknown" "sub=@unknown" "enabled=${state}"
  done <<<"${unitfiles}"
  bo_cov services "" complete
  bo_finding SVC-INFO-001 info high services "Service inventory" \
    "${n_all} service units loaded, ${n_run} running, ${#enabled[@]} enabled at boot, ${#fail[@]} failed, ${#failsock[@]} failed socket unit(s)." "" "" ${running[@]+"${running[@]}"}
  bo_finding SVC-ENABLED-001 info high services "Enabled services" "${#enabled[@]} unit(s) start at boot." "" "" ${enabled[@]+"${enabled[@]}"}
  ((${#fail[@]} > 0)) && bo_finding SVC-FAILED-001 medium high services "Failed services" \
    "Failed units may indicate a broken scored service or a tampered/removed binary." \
    "Inspect with 'systemctl status UNIT' and 'journalctl -u UNIT'; restore from a known-good package." "" "${fail[@]}"
  ((${#failsock[@]} > 0)) && bo_finding SVC-FAILED-002 medium high services "Failed socket units" \
    "A failed .socket unit means its service can no longer be activated on demand (for example ssh.socket, cups.socket)." \
    "Inspect with 'systemctl status UNIT'; check for port conflicts or tampered unit files before restarting." "" "${failsock[@]}"
  ((${#legacy[@]} > 0)) && bo_finding SVC-LEGACY-001 low medium services "Legacy or high-exposure services enabled" \
    "Services historically abused or rarely needed (telnet, r-services, tftp, FTP, NFS, SMB, SNMP, Avahi)." \
    "Disable if unnecessary - confirm they are not scored services first." "" "${legacy[@]}"
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-services audit services 0 "$@" || rc=$?
  exit "${rc}"
fi
