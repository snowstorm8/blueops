#!/usr/bin/env bash
# deps.sh - dependency detection shared by `blueops doctor`, the collectors and
# scripts/setup/setup-linux.sh. Sourced only; no top-level side effects. Read-only:
# nothing here installs or changes anything.
#
# Environment (test hooks): BO_DEPS_OS_RELEASE overrides /etc/os-release.

if [[ -n "${BO_DEPS_LOADED:-}" ]]; then return 0; fi
BO_DEPS_LOADED=1

BO_DEPS_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

# Commands the collectors cannot work without.
BO_DEPS_REQUIRED_CMDS="awk cat cut date find grep head id mktemp sed sort stat tail tr uname wc"
# Commands that only improve coverage; each has a fallback or the module reports a gap.
BO_DEPS_RECOMMENDED_CMDS="ps ss ip systemctl who timeout"
# Files that must be present in a complete checkout (all are tracked in Git).
BO_DEPS_REQUIRED_FILES="blueops
linux/lib/common.sh
linux/lib/deps.sh
linux/audit/audit-linux.sh
linux/audit/audit-system.sh
linux/audit/audit-users.sh
linux/audit/audit-pam.sh
linux/audit/audit-processes.sh
linux/audit/audit-network.sh
linux/audit/audit-services.sh
linux/audit/audit-filesystem.sh
linux/persistence/check-persistence.sh
scripts/setup/setup-linux.sh
shared/reporting/diff.py
shared/reporting/detect.py
shared/schemas/audit-report.schema.json
shared/config/baseline-diff.default.json"

# Filled by bo_deps_scan.
BO_DEPS_MISSING_FILES=""
BO_DEPS_MISSING_REQ=""
BO_DEPS_MISSING_REC=""
BO_DEPS_PYTHON=""
BO_DEPS_PYTHON_NOTE=""
BO_DEPS_BASH_NOTE=""

bo_deps_have() { command -v -- "$1" >/dev/null 2>&1; }

# debian | rhel | arch | other
bo_deps_family() {
  local f="${BO_DEPS_OS_RELEASE:-/etc/os-release}" id="" like=""
  if [[ -r "${f}" ]]; then
    id="$(sed -n 's/^ID=//p' "${f}" 2>/dev/null | head -n 1 | sed "s/[\"']//g" | tr '[:upper:]' '[:lower:]')"
    like="$(sed -n 's/^ID_LIKE=//p' "${f}" 2>/dev/null | head -n 1 | sed "s/[\"']//g" | tr '[:upper:]' '[:lower:]')"
  fi
  case " ${id} ${like} " in
    *" debian "* | *" ubuntu "*) echo debian ;;
    *" rhel "* | *" fedora "* | *" centos "* | *" rocky "*) echo rhel ;;
    *" arch "*) echo arch ;;
    *) echo other ;;
  esac
}

bo_deps_os_major() {
  local f="${BO_DEPS_OS_RELEASE:-/etc/os-release}" v=""
  if [[ -r "${f}" ]]; then
    v="$(sed -n 's/^VERSION_ID=//p' "${f}" 2>/dev/null | head -n 1 | sed "s/[\"']//g")"
  fi
  echo "${v%%.*}"
}

# bo_deps_pkg COMMAND FAMILY -> package that provides COMMAND (empty if unknown)
bo_deps_pkg() {
  local cmd="$1" fam="$2"
  case "${cmd}" in
    awk) case "${fam}" in debian) echo mawk ;; *) echo gawk ;; esac ;;
    find) echo findutils ;;
    grep) echo grep ;;
    sed) echo sed ;;
    cat | cut | date | head | id | mktemp | sort | stat | tail | tr | uname | wc | timeout | who | coreutils) echo coreutils ;;
    ps) case "${fam}" in debian) echo procps ;; *) echo procps-ng ;; esac ;;
    ss | ip) case "${fam}" in rhel) echo iproute ;; *) echo iproute2 ;; esac ;;
    systemctl) echo "" ;; # never installed by setup: the init system belongs to the host
    python) case "${fam}" in
      arch) echo python ;;
      rhel) if [[ "$(bo_deps_os_major)" == "8" ]]; then echo python3.11; else echo python3; fi ;;
      *) echo python3 ;;
    esac ;;
    git) echo git ;;
    *) echo "" ;;
  esac
}

# Prints the interpreter path of the first Python >= 3.9, or returns 1.
bo_deps_find_python() {
  local c p
  for c in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python; do
    p="$(command -v -- "${c}" 2>/dev/null || true)"
    [[ -n "${p}" ]] || continue
    if "${p}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
      echo "${p}"
      return 0
    fi
  done
  return 1
}

bo_deps_scan() {
  local IFS=$' \t\n'
  local c f
  BO_DEPS_MISSING_FILES="" BO_DEPS_MISSING_REQ="" BO_DEPS_MISSING_REC=""
  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    [[ -e "${BO_DEPS_ROOT}/${f}" ]] || BO_DEPS_MISSING_FILES+="${f} "
  done <<<"${BO_DEPS_REQUIRED_FILES}"
  for c in ${BO_DEPS_REQUIRED_CMDS}; do
    bo_deps_have "${c}" || BO_DEPS_MISSING_REQ+="${c} "
  done
  if ! bo_deps_have sha256sum && ! bo_deps_have shasum && ! bo_deps_have openssl; then
    BO_DEPS_MISSING_REQ+="sha256sum "
  fi
  for c in ${BO_DEPS_RECOMMENDED_CMDS}; do
    if [[ "${c}" == "ss" ]] && bo_deps_have netstat; then continue; fi
    bo_deps_have "${c}" || BO_DEPS_MISSING_REC+="${c} "
  done
  if ((${BASH_VERSINFO[0]:-0} < 4 || (${BASH_VERSINFO[0]:-0} == 4 && ${BASH_VERSINFO[1]:-0} < 2))); then
    BO_DEPS_BASH_NOTE="Bash ${BASH_VERSION:-unknown} is older than the supported 4.2; results may be unreliable"
  fi
  if BO_DEPS_PYTHON="$(bo_deps_find_python)"; then
    :
  else
    BO_DEPS_PYTHON=""
    if bo_deps_have python3; then
      BO_DEPS_PYTHON_NOTE="python3 is older than 3.9 ($(python3 -V 2>&1 || true))"
    else
      BO_DEPS_PYTHON_NOTE="python3 not found"
    fi
  fi
}

# Packages to install for what bo_deps_scan found missing. Args: FAMILY [minimal]
# Prints one package per line, de-duplicated. Python is included unless "minimal".
bo_deps_packages() {
  local IFS=$' \t\n'
  local fam="$1" minimal="${2:-}" c p
  {
    for c in ${BO_DEPS_MISSING_REQ}; do
      [[ "${c}" == "sha256sum" ]] && c=coreutils
      bo_deps_pkg "${c}" "${fam}"
    done
    if [[ "${minimal}" != "minimal" ]]; then
      for c in ${BO_DEPS_MISSING_REC}; do bo_deps_pkg "${c}" "${fam}"; done
      if [[ -z "${BO_DEPS_PYTHON}" ]]; then bo_deps_pkg python "${fam}"; fi
    fi
  } | while IFS= read -r p; do [[ -n "${p}" ]] && echo "${p}"; done | sort -u
}

# Human-readable report on stdout. Returns 3 if the checkout is incomplete or a
# required command is missing, else 0. Args: [setup-hint]
bo_deps_report() {
  local IFS=$' \t\n'
  local hint="${1:-sudo $(printf '%q' "${BO_DEPS_ROOT}/scripts/setup/setup-linux.sh") --install}" c rc=0
  echo "BlueOps environment check (read-only; nothing is installed or changed)"
  echo "  checkout   : ${BO_DEPS_ROOT}"
  echo "  os family  : $(bo_deps_family)"
  echo "  bash       : ${BASH_VERSION:-unknown}"
  if [[ -n "${BO_DEPS_MISSING_FILES}" ]]; then
    rc=3
    echo "[MISSING] files absent from the checkout: ${BO_DEPS_MISSING_FILES}"
    echo "          The clone is incomplete or damaged. Re-clone: git clone https://github.com/snowstorm8/blueops.git"
  else
    echo "[ok] all required repository files are present"
  fi
  if [[ -n "${BO_DEPS_BASH_NOTE}" ]]; then echo "[warn] ${BO_DEPS_BASH_NOTE}"; fi
  for c in ${BO_DEPS_MISSING_REQ}; do echo "[MISSING] required command: ${c} (collectors cannot run without it)"; done
  if [[ -z "${BO_DEPS_MISSING_REQ}" ]]; then echo "[ok] required commands present"; else rc=3; fi
  for c in ${BO_DEPS_MISSING_REC}; do
    if [[ "${c}" == "systemctl" ]]; then
      echo "[missing-optional] systemctl (no systemd on this host: service/unit modules report a gap; setup never installs an init system)"
    else
      echo "[missing-optional] ${c} (coverage reduced; a fallback or a reported gap applies)"
    fi
  done
  if [[ -n "${BO_DEPS_PYTHON}" ]]; then
    echo "[ok] python for diff/detect: ${BO_DEPS_PYTHON}"
  else
    echo "[missing-optional] python >= 3.9: ${BO_DEPS_PYTHON_NOTE} (only needed for 'blueops diff' and 'blueops detect'; collectors do not need it)"
  fi
  if ((rc != 0)) || [[ -n "${BO_DEPS_MISSING_REC}" ]] || [[ -z "${BO_DEPS_PYTHON}" ]]; then
    echo "To see and approve the exact install command (setup is separate and asks first):"
    echo "  ${hint}"
  fi
  return "${rc}"
}
