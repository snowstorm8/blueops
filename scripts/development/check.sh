#!/usr/bin/env bash
# Run all available local checks (lint, format, tests). Development helper only.
# Missing optional tools are reported as SKIPPED, never as passed.
set -Eeuo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

failed=0
skipped=()

run() {
  local name="$1"
  shift
  echo "==> ${name}"
  if ! "$@"; then
    echo "FAILED: ${name}" >&2
    failed=1
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

bash_files=()
while IFS= read -r -d '' f; do bash_files+=("${f}"); done < <(git ls-files -z '*.sh' '*.bash' '*.bats' 2>/dev/null || true)

if ((${#bash_files[@]} > 0)); then
  if have shellcheck; then run shellcheck shellcheck --external-sources "${bash_files[@]}"; else skipped+=(shellcheck); fi
  if have shfmt; then run shfmt shfmt -d "${bash_files[@]}"; else skipped+=(shfmt); fi
fi

if have ruff; then
  run ruff-check ruff check .
  run ruff-format ruff format --check .
else skipped+=(ruff); fi

if have pytest; then run pytest python3 -m pytest; else skipped+=(pytest); fi

if have bats && compgen -G "tests/linux/*.bats" >/dev/null; then
  run bats bats --recursive tests/linux
elif ! have bats; then skipped+=(bats); fi

if have pwsh; then
  run pester pwsh -NoProfile -File scripts/development/check.ps1
else skipped+=(pwsh); fi

if ((${#skipped[@]} > 0)); then
  echo "SKIPPED (tool not installed): ${skipped[*]}" >&2
fi
if ((failed)); then
  echo "Some checks FAILED." >&2
  exit 1
fi
echo "All executed checks passed."
