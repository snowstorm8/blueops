#!/usr/bin/env bash
# setup-linux.sh - install missing BlueOps dependencies (Debian/Ubuntu, RHEL-family incl. Rocky, Arch).
# Category: setup (separate from auditing). Safety: changes the system ONLY with --install, after
# showing the exact commands and asking for confirmation (or --yes). Default run is read-only.
# For hosts you are authorized to administer. Needs the network only for the package manager.
# Usage: setup-linux.sh [--install] [--yes] [--dry-run] [--minimal] [--help]
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../linux/lib/deps.sh
source "${SCRIPT_DIR}/../../linux/lib/deps.sh"

usage() {
  cat <<'EOF'
Usage: setup-linux.sh [--install] [--yes] [--dry-run] [--minimal] [--help]

  (no options)  report what is missing and the command that would fix it; changes nothing
  --install     install the missing packages with the system package manager (needs root)
  --yes         do not prompt (required when there is no terminal)
  --dry-run     with --install: print the exact commands and exit 0 without running them
  --minimal     only what the collectors need; skip optional tools and Python
  --help        this text

Debian/Ubuntu: apt-get update, then apt-get install --no-install-recommends.
Rocky/RHEL:    dnf (or yum) install. Rocky 8 ships Python 3.6; python3.11 is requested for diff/detect.
Arch:          pacman -S --needed (no database refresh; run 'pacman -Syu' yourself if it fails).
Nothing else is modified: no services, no configuration files, no upgrades of installed packages.
Exit codes: 0 ok, 2 usage, 3 precondition failed, 5 declined/no terminal, 6 partial failure.
EOF
}

die() {
  local code="$1"
  shift
  echo "setup-linux: $*" >&2
  exit "${code}"
}

main() {
  local install=0 yes=0 dry=0 minimal=""
  while (($# > 0)); do
    case "$1" in
      --install) install=1 ;;
      --yes) yes=1 ;;
      --dry-run) dry=1 ;;
      --minimal) minimal=minimal ;;
      --help | -h)
        usage
        return 0
        ;;
      *) die 2 "unknown option: $1 (try --help)" ;;
    esac
    shift
  done
  if ((dry && ! install)); then die 2 "--dry-run applies to --install"; fi

  if [[ "$(uname -s 2>/dev/null)" != "Linux" ]]; then die 3 "Linux only (detected: $(uname -s 2>/dev/null || echo unknown))"; fi

  local fam pkgs=() p
  fam="$(bo_deps_family)"
  bo_deps_scan
  local rc=0
  bo_deps_report || rc=$?
  while IFS= read -r p; do [[ -n "${p}" ]] && pkgs+=("${p}"); done < <(bo_deps_packages "${fam}" "${minimal}")

  # The script's IFS is newline/tab, so join explicitly with spaces for display and command strings.
  local pkg_list
  pkg_list="$(
    IFS=' '
    echo "${pkgs[*]:-}"
  )"

  if ((${#pkgs[@]} == 0)); then
    echo "Nothing to install."
    return "${rc}"
  fi
  if ((! install)); then
    echo "Packages that would be installed: ${pkg_list}"
    echo "Nothing was changed. Re-run with --install to proceed (it will ask first)."
    return "${rc}"
  fi

  # Build the exact commands once; the plan shown is the plan executed.
  local -a cmds=()
  case "${fam}" in
    debian)
      bo_deps_have apt-get || die 3 "apt-get not found; install manually: ${pkg_list}"
      cmds+=("apt-get update")
      cmds+=("env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${pkg_list}")
      ;;
    rhel)
      if bo_deps_have dnf; then
        cmds+=("dnf install -y ${pkg_list}")
      elif bo_deps_have yum; then
        cmds+=("yum install -y ${pkg_list}")
      else
        die 3 "dnf/yum not found; install manually: ${pkg_list}"
      fi
      ;;
    arch)
      bo_deps_have pacman || die 3 "pacman not found; install manually: ${pkg_list}"
      cmds+=("pacman -S --needed --noconfirm ${pkg_list}")
      ;;
    *) die 3 "unsupported distribution; install these (or their equivalents) manually: ${pkg_list}" ;;
  esac

  echo
  echo "Planned commands (run as root):"
  local c
  for c in "${cmds[@]}"; do echo "  ${c}"; done
  if ((dry)); then
    echo "Dry run: nothing was executed."
    return 0
  fi

  if ((! yes)); then
    [[ -t 0 ]] || die 5 "no terminal to confirm on; re-run with --yes to proceed non-interactively"
    local ans=""
    read -r -p "Run these commands now? [y/N] " ans || true
    case "${ans}" in y | Y | yes | YES) ;; *) die 5 "declined; nothing was changed" ;; esac
  fi
  if [[ "$(id -u 2>/dev/null || echo 1)" != "0" ]]; then
    die 3 "--install needs root. Re-run: sudo ./scripts/setup/setup-linux.sh --install"
  fi

  for c in "${cmds[@]}"; do
    echo "+ ${c}"
    # The command string was built above from fixed words and validated package names.
    IFS=' ' read -r -a argv <<<"${c}"
    "${argv[@]}" || die 6 "command failed: ${c} (no further commands were run)"
  done

  echo
  bo_deps_scan
  bo_deps_report || exit 6
  echo "Setup complete. Next: ./blueops audit --json --output-dir <dir>"
}

main "$@"
