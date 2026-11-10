# shellcheck shell=bash
# bashcheck.sh - refuse to run on a Bash that is too old, before any newer syntax is reached.
#
# Sourced as the FIRST thing by collectors that need Bash >= 4.2 (associative arrays, ${x,,}).
# This file must stay parseable by Bash 3.2 (the oldest Bash in the wild, macOS /bin/bash): no
# associative arrays, no ${x,,}, no mapfile, no &>>. Functions only; no top-level side effects.
#
# Exit code 3 is the documented "precondition failed" code (docs/contracts.md), distinct from 2
# (usage) so that callers can tell "fix the command line" from "fix the environment".

[[ -n "${BO_BASHCHECK_LOADED:-}" ]] && return 0
BO_BASHCHECK_LOADED=1

# bo_bash_at_least MAJOR MINOR [HAVE_MAJOR HAVE_MINOR]: succeeds when the running Bash (or the
# given version, which exists so tests can try versions this machine does not have) is >= MAJOR.MINOR.
bo_bash_at_least() {
  local want_major="$1" want_minor="$2"
  local have_major="${3:-${BASH_VERSINFO[0]:-0}}" have_minor="${4:-${BASH_VERSINFO[1]:-0}}"
  ((have_major > want_major || (have_major == want_major && have_minor >= want_minor)))
}

# bo_require_bash MAJOR MINOR [HAVE_MAJOR HAVE_MINOR]: exit 3 with a diagnostic when too old.
bo_require_bash() {
  local want_major="$1" want_minor="$2" tool="${0##*/}"
  if bo_bash_at_least "$@"; then
    return 0
  fi
  {
    echo "${tool}: Bash ${want_major}.${want_minor} or newer is required, but this is Bash ${BASH_VERSION:-unknown} (${BASH:-bash})."
    echo "  Nothing was collected. Run it with a newer Bash (for example: /path/to/newer/bash ${0})"
    echo "  or install one (macOS: 'brew install bash')."
  } >&2
  exit 3
}
