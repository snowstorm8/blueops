#!/usr/bin/env bats
# linux/lib/bashcheck.sh: the Bash >= 4.2 requirement is enforced before newer syntax is parsed.

load test_helper

LIB="${REPO_ROOT}/linux/lib/bashcheck.sh"

# Is the Bash that "bash" resolves to older than 4.2 (e.g. macOS /bin/bash 3.2)?
old_bash() {
  bash -c '((BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 2)))'
}

@test "bo_bash_at_least compares major then numeric minor" {
  run bash -c "source '${LIB}'
    bo_bash_at_least 4 2 5 1 && echo a5.1
    bo_bash_at_least 4 2 4 2 && echo a4.2
    bo_bash_at_least 4 2 4 10 && echo a4.10
    bo_bash_at_least 4 2 4 1 || echo n4.1
    bo_bash_at_least 4 2 3 2 || echo n3.2
    bo_bash_at_least 4 2 0 0 || echo n0.0"
  [ "${status}" -eq 0 ]
  [ "${output}" = $'a5.1\na4.2\na4.10\nn4.1\nn3.2\nn0.0' ]
}

@test "bo_require_bash passes on a supported version and prints nothing" {
  run bash -c "source '${LIB}'; bo_require_bash 4 2 4 2; echo continued"
  [ "${status}" -eq 0 ]
  [ "${output}" = "continued" ]
}

@test "bo_require_bash on an unsupported version exits 3 (not 2) with a diagnostic and does not continue" {
  run bash -c "source '${LIB}'; bo_require_bash 4 2 3 2; echo continued"
  [ "${status}" -eq 3 ]
  [[ "${output}" == *"Bash 4.2 or newer is required"* ]]
  [[ "${output}" == *"Nothing was collected"* ]]
  [[ "${output}" != *continued* ]]
}

@test "sourcing bashcheck.sh twice is idempotent and has no side effects" {
  run bash -c "source '${LIB}'; source '${LIB}'; echo ok"
  [ "${status}" -eq 0 ]
  [ "${output}" = "ok" ]
}

@test "bashcheck.sh uses no syntax newer than Bash 3.2" {
  run bash -c "grep -vE '^[[:space:]]*#' '${LIB}' | grep -nE 'declare -A|local -A|mapfile|readarray|[$][{][A-Za-z_]+(,,|[\\^][\\^])[}]|&>>|;&|[|]&'"
  [ "${status}" -eq 1 ]
}

@test "the telemetry collector refuses an old Bash with exit 3 before it parses newer syntax" {
  old_bash || skip "this machine's bash is 4.2 or newer"
  run bash "${REPO_ROOT}/linux/telemetry/collect-telemetry.sh" --help
  [ "${status}" -eq 3 ]
  [[ "${output}" == *"collect-telemetry.sh: Bash 4.2 or newer is required"* ]]
  [[ "${output}" != *"invalid option"* ]]
}

@test "the telemetry collector starts normally on a supported Bash" {
  old_bash && skip "needs bash 4.2 or newer"
  run bash "${REPO_ROOT}/linux/telemetry/collect-telemetry.sh" --help
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Usage: collect-telemetry.sh"* ]]
}
