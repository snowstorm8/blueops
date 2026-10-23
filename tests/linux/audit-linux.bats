#!/usr/bin/env bats
# Integration tests for the audit-linux.sh entry point (CLI, report shape, safety).

load test_helper

setup() {
  make_root
  use_fake_tools
}

@test "--help prints usage and exits 0" {
  run "${AUDIT}" --help
  [ "${status}" -eq 0 ]
  [[ "${output}" == *"Usage: audit-linux"* ]]
  [[ "${output}" == *"READ-ONLY"* ]]
  [[ "${output}" == *"--modules"* ]]
}

@test "--version prints the tool version" {
  run "${AUDIT}" --version
  [ "${status}" -eq 0 ]
  [[ "${output}" == "audit-linux "* ]]
}

@test "--list-modules lists all seven modules" {
  run "${AUDIT}" --list-modules
  [ "${status}" -eq 0 ]
  [ "${#lines[@]}" -eq 7 ]
  [[ "${output}" == *persistence* && "${output}" == *filesystem* ]]
}

@test "usage errors exit 2" {
  run "${AUDIT}" --bogus
  [ "${status}" -eq 2 ]
  run "${AUDIT}" --modules nosuch
  [ "${status}" -eq 2 ]
  run "${AUDIT}" --format yaml
  [ "${status}" -eq 2 ]
  run "${AUDIT}" --recent-days 0
  [ "${status}" -eq 2 ]
  run "${AUDIT}" --fail-on severe
  [ "${status}" -eq 2 ]
  run "${AUDIT}" --output-dir
  [ "${status}" -eq 2 ]
}

@test "refuses to run on non-Linux hosts without a fixture root (exit 3)" {
  [ "$(uname -s)" != "Linux" ] || skip "only meaningful on non-Linux hosts"
  unset BO_ROOT
  run "${AUDIT}" --modules system
  [ "${status}" -eq 3 ]
  [[ "${output}" == *"Linux only"* ]]
}

@test "full audit emits schema-shaped JSON and exit code 4 when findings exist" {
  run_audit
  [ "${status}" -eq 4 ]
  [ "$(json_py "d['schema_version']")" = "0.1.0" ]
  [ "$(json_py "d['tool']['name']")" = "audit-linux" ]
  [ "$(json_py "d['tool']['category']")" = "audit" ]
  [ "$(json_py "d['run']['mode']")" = "read-only" ]
  [ "$(json_py "d['run']['dry_run']")" = "False" ]
  [ "$(json_py "d['run']['exit_code']")" = "4" ]
  [ "$(json_py "d['host']['hostname']")" = "fixture-host" ]
  [ "$(json_py "d['host']['os']['name']")" = "Ubuntu" ]
}

@test "finding ids are unique and summary counts match the findings" {
  run_audit
  [ "$(json_py "len(set(f['id'] for f in d['findings'])) == len(d['findings'])")" = "True" ]
  [ "$(json_py "d['summary']['total'] == len(d['findings'])")" = "True" ]
  [ "$(json_py "all(d['summary']['by_severity'][s] == sum(1 for f in d['findings'] if f['severity']==s) for s in ('info','low','medium','high','critical'))")" = "True" ]
}

@test "every module contributes findings in a full audit" {
  run_audit
  for p in SYS USR PRC NET SVC PER FS; do
    [ "$(json_py "any(f['id'].startswith('${p}-') for f in d['findings'])")" = "True" ]
  done
}

@test "--json keeps stdout machine-readable and sends human text to stderr" {
  run_audit
  json_py "1" >/dev/null
  grep -q "USR-UID0-001" "${ERR}"
}

@test "--quiet --json emits only JSON" {
  run_audit --quiet
  json_py "1" >/dev/null
  [ ! -s "${ERR}" ]
}

@test "text mode prints a human summary with severities and coverage gaps" {
  run_text --modules users,network
  [ "${status}" -eq 4 ]
  grep -q "Findings:" "${OUT}"
  grep -q "\[CRITICAL\] USR-UID0-001" "${OUT}"
  grep -q "Coverage gaps" "${OUT}"
  grep -q "Exit code: 4" "${OUT}"
}

@test "--modules selects and de-duplicates modules" {
  run_audit --modules system,system,users
  [ "$(json_py "sorted(set(f['id'].split('-')[0] for f in d['findings']))")" = "['SYS', 'USR']" ]
}

@test "--output-dir creates a private run directory with report, text and log" {
  local out="${BATS_TEST_TMPDIR}/reports"
  run_audit --modules system --output-dir "${out}"
  [ ! -s "${OUT}" ]
  local rd
  rd="$(echo "${out}"/blueops-run-*-audit-linux)"
  [ -f "${rd}/report.json" ] && [ -f "${rd}/report.txt" ] && [ -f "${rd}/run.log" ]
  [ "$(json_py "d['tool']['name']" "${rd}/report.json")" = "audit-linux" ]
  [ "$(bo_mode_of "${rd}")" = "700" ]
}

@test "--fail-on critical ignores lower severities" {
  run_audit --modules network,persistence --fail-on critical
  [ "${status}" -eq 0 ]
  run_audit --modules users --fail-on critical
  [ "${status}" -eq 4 ]
}

@test "clean subset exits 0 and records only non-material coverage notes" {
  run_audit --modules system,processes,services,network --fail-on critical
  [ "${status}" -eq 0 ]
}

@test "missing data sources degrade to partial results (exit 6), not a crash" {
  make_root linux-root-min
  export BO_FORCE_MISSING_TOOLS="systemctl who ss ip route ifconfig netstat"
  run_audit --modules system,users,services,persistence,filesystem --fs-path "${ROOT}"
  [ "${status}" -eq 6 ]
  has_error PASSWD_UNREADABLE
  has_error DISTRO_UNKNOWN
  has_error NO_INIT_SYSTEM
  has_finding SYS-OS-001
  [ "$(json_py "d['run']['exit_code']")" = "6" ]
}

@test "a crashing module is reported and does not abort the others" {
  cat >"${BATS_TEST_TMPDIR}/crash.sh" <<CRASH
source "${REPO_ROOT}/linux/audit/audit-linux.sh"
mod_users() { : "\${definitely_unset_var}"; }
bo_cli_main audit-linux audit all 1 --json --modules users,system
CRASH
  run bash -c "set -Eeuo pipefail; export BO_ROOT='${ROOT}'; bash '${BATS_TEST_TMPDIR}/crash.sh' 2>/dev/null"
  [[ "${output}" == *'"MODULE_FAILED"'* ]]
  [[ "${output}" == *'"SYS-INFO-001"'* ]]
}

@test "audit is read-only: the audited tree is byte- and mode-identical afterwards" {
  snap() {
    (cd "${ROOT}" && find . -print0 | sort -z | xargs -0 ls -ld | awk '{print $1,$NF}' && find . -type f -print0 | sort -z | xargs -0 cksum)
  }
  snap >"${BATS_TEST_TMPDIR}/before"
  run_audit
  snap >"${BATS_TEST_TMPDIR}/after"
  diff "${BATS_TEST_TMPDIR}/before" "${BATS_TEST_TMPDIR}/after"
}

@test "no secrets or key material reach any output stream" {
  run_audit
  run cat "${OUT}" "${ERR}"
  [[ "${output}" != *REDACTEDHASHFIXTURE* ]]
  [[ "${output}" != *FIXTUREONLY* ]]
  [[ "${output}" != *hunter2* ]]
  [[ "${output}" != *AAAAC3NzaC1lZDI1NTE5* ]]
  [[ "${output}" != *AAAAB3NzaC1yc2E* ]]
}

@test "odd filenames (spaces, quotes, backslashes) still yield valid JSON" {
  printf '#!/bin/sh\n' >"${ROOT}/tmp/we ird\"na\\me"
  chmod 755 "${ROOT}/tmp/we ird\"na\\me"
  run_audit --modules filesystem
  json_py "1" >/dev/null
  evidence_has FS-PERM-003 'we ird'
}

@test "scratch files are removed after a run" {
  local before after
  before="$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'blueops.*' 2>/dev/null | wc -l)"
  run_audit --modules system
  after="$(find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'blueops.*' 2>/dev/null | wc -l)"
  [ "${before}" -eq "${after}" ]
}

@test "standalone module scripts run and carry their own tool name" {
  local out
  out="$("${REPO_ROOT}/linux/audit/audit-system.sh" --json 2>/dev/null || true)"
  [ "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["tool"]["name"])' "${out}")" = "audit-system" ]
  out="$("${REPO_ROOT}/linux/persistence/check-persistence.sh" --json 2>/dev/null || true)"
  [ "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["tool"]["category"])' "${out}")" = "persistence" ]
  run "${REPO_ROOT}/linux/audit/audit-system.sh" --modules system
  [ "${status}" -eq 2 ]
}
