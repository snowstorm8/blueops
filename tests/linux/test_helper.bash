# Shared Bats helpers for the Linux audit tests. Fixtures are synthetic.

# The fixture hooks (BO_ROOT, BO_FORCE_MISSING_TOOLS) and the command shims in PATH are honoured
# only in explicit test mode; tests of the production behaviour run `env -u BO_TEST_MODE ...`.
export BO_TEST_MODE=1

# BATS_TEST_TMPDIR needs Bats >= 1.4; provide a fallback for older releases.
if [[ -z "${BATS_TEST_TMPDIR:-}" ]]; then
  BATS_TEST_TMPDIR="$(mktemp -d "${BATS_TMPDIR:-${TMPDIR:-/tmp}}/bo-test.XXXXXX")"
fi

REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
FIXTURES="${REPO_ROOT}/tests/fixtures"
AUDIT="${REPO_ROOT}/linux/audit/audit-linux.sh"

# Fresh copy of the fixture root with the permission bits git cannot store.
make_root() {
  local src="${1:-linux-root}"
  ROOT="${BATS_TEST_TMPDIR:?}/root"
  rm -rf "${ROOT:?}"
  cp -R "${FIXTURES}/${src}" "${ROOT}"
  if [[ "${src}" == "linux-root" ]]; then
    chmod 4755 "${ROOT}/usr/bin/su" "${ROOT}/usr/bin/find" "${ROOT}/usr/bin/mystery"
    chmod 644 "${ROOT}/etc/shadow" "${ROOT}/etc/passwd" "${ROOT}/etc/hosts"
    chmod 440 "${ROOT}/etc/sudoers"
    chmod 755 "${ROOT}/root" "${ROOT}/tmp/dropper"
    chmod 755 "${ROOT}/etc/pam.d" "${ROOT}/etc/pam.d"/*
    chmod 644 "${ROOT}/etc/pam.d"/*
    # Windows cannot check out a file named "...", so it is created here instead.
    echo x >"${ROOT}/tmp/..."
    chmod 644 "${ROOT}/tmp/..."
  fi
  export BO_ROOT="${ROOT}"
}

# Deterministic tool environment: fake ss/systemctl/who/ps first in PATH, and the
# real network tools hidden so the /proc fallbacks are exercised.
use_fake_tools() {
  export PATH="${FIXTURES}/linux-bin:${PATH}"
  export BO_FORCE_MISSING_TOOLS="${BO_FORCE_MISSING_TOOLS:-ip route ifconfig netstat systemd-detect-virt}"
}

# run_audit ARGS... : JSON on stdout -> $OUT, stderr -> $ERR, exit status -> $status
run_audit() {
  OUT="${BATS_TEST_TMPDIR}/out.json"
  ERR="${BATS_TEST_TMPDIR}/err.txt"
  status=0
  "${AUDIT}" --json --no-color "$@" >"${OUT}" 2>"${ERR}" || status=$?
  : "${status}"
}

# run_text ARGS... : human report on stdout -> $OUT
run_text() {
  OUT="${BATS_TEST_TMPDIR}/out.txt"
  ERR="${BATS_TEST_TMPDIR}/err.txt"
  status=0
  "${AUDIT}" --no-color "$@" >"${OUT}" 2>"${ERR}" || status=$?
  : "${status}"
}

# json_py 'python expression over d' [file]
json_py() {
  python3 -c 'import json,sys; d=json.load(open(sys.argv[2])); print(eval(sys.argv[1]))' "$1" "${2:-${OUT}}"
}

has_finding() { json_py "'$1' in [f['id'] for f in d['findings']]" | grep -qx True; }
no_finding() { ! has_finding "$1"; }
# Bats does not fail a test on a bare `! cmd`; this does.
refute() { if "$@"; then return 1; fi; }
finding_sev() { json_py "[f['severity'] for f in d['findings'] if f['id']=='$1'][0]"; }
evidence_has() { json_py "any('$2' in (e['ref']+' '+e.get('excerpt','')) for f in d['findings'] if f['id']=='$1' for e in f.get('evidence',[]))" | grep -qx True; }
has_error() { json_py "'$1' in [e['code'] for e in d['errors']]" | grep -qx True; }

skip_if_root() {
  if [[ "$(id -u)" == "0" ]]; then skip "permission-denied cases cannot be simulated as root"; fi
}

bo_mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
