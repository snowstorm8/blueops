#!/usr/bin/env bats
# Linux telemetry collector: command-line behavior and the stream contract (shell level).
# Content and ingestion are covered by tests/shared/test_telemetry_linux.py.

load test_helper

bats_require_minimum_version 1.5.0

COLLECTOR="${BATS_TEST_DIRNAME}/../../linux/telemetry/collect-telemetry.sh"

setup() {
  export BO_TEST_MODE=1
  export BO_ROOT="${BATS_TEST_DIRNAME}/../fixtures/linux-root"
  export BO_FORCE_MISSING_TOOLS="ip route ifconfig netstat systemd-detect-virt"
  export PATH="${BATS_TEST_DIRNAME}/../fixtures/linux-bin:${PATH}"
}

@test "telemetry: --help states it is read-only and exits 0" {
  run "${COLLECTOR}" --help
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Read-only"* ]]
  [[ "${output}" == *"authorized"* ]]
}

@test "telemetry: --version prints the version" {
  run "${COLLECTOR}" --version
  [ "${status}" -eq 0 ]
  [[ "${output}" =~ collect-telemetry\.sh\ [0-9]+\.[0-9]+\.[0-9]+ ]]
}

@test "telemetry: unknown options and bad values are usage errors (exit 2, nothing on stdout)" {
  run --separate-stderr "${COLLECTOR}" --bogus
  [ "${status}" -eq 2 ]
  [ -z "${output}" ]
  run --separate-stderr "${COLLECTOR}" --since-hours 0
  [ "${status}" -eq 2 ]
  run --separate-stderr "${COLLECTOR}" --categories nope
  [ "${status}" -eq 2 ]
}

@test "telemetry: stdout is a JSON Lines stream with a header first and an end marker last" {
  run --separate-stderr "${COLLECTOR}" --since-hours 100000 --categories user,group
  [ "${status}" -eq 0 ] || [ "${status}" -eq 6 ]
  first="$(printf '%s\n' "${output}" | head -n 1)"
  last="$(printf '%s\n' "${output}" | tail -n 1)"
  [[ "${first}" == '{"type":"header"'* ]]
  [[ "${last}" == '{"type":"end"'* ]]
}

@test "telemetry: diagnostics go to stderr, never into the stream" {
  run --separate-stderr "${COLLECTOR}" --since-hours 100000 --categories user
  [[ "${stderr}" == *"TEST_MODE"* ]]
  while IFS= read -r line; do
    [[ "${line}" == '{'* ]]
  done <<<"${output}"
}

@test "telemetry: test hooks without BO_TEST_MODE are ignored and reported" {
  unset BO_TEST_MODE
  run --separate-stderr "${COLLECTOR}" --categories group
  [[ "${output}" == *"TEST_HOOKS_IGNORED"* ]]
}

@test "telemetry: the collector never modifies the fixture root" {
  before="$(find "${BO_ROOT}" -type f -newer "${COLLECTOR}" | wc -l)"
  run "${COLLECTOR}" --since-hours 100000
  after="$(find "${BO_ROOT}" -type f -newer "${COLLECTOR}" | wc -l)"
  [ "${before}" -eq "${after}" ]
}
