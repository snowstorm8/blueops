#!/usr/bin/env bash
# audit-linux.sh - unified read-only Linux host audit (BlueOps).
# Category: audit. Safety: read-only; writes only to --output-dir when given.
# For hosts you are authorized to administer.
# Usage: audit-linux.sh [--modules system,users,...] [--json] [--output-dir DIR] ...
#        audit-linux.sh --help
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

main() {
  bo_cli_main audit-linux audit all 1 "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  main "$@" || rc=$?
  exit "${rc}"
fi
