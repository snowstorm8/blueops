#!/usr/bin/env bats
# The `auth` module (login.defs, password aging, group integrity, PAM quality/lockout) and the
# `sysconfig` module (mount options, core dumps, log tampering, logging pipeline).
# Synthetic data only; every test edits a disposable copy of the fixture root.

# shellcheck disable=SC2016 # the shadow/group fixtures below contain literal "$6$..." text
load test_helper

setup() {
  make_root
  use_fake_tools
}

has_rec() { json_py "'$1' in [r['key'] for r in d['inventory']['records']]" | grep -qx True; }
rec_attr() { json_py "[r['attrs']['$2'] for r in d['inventory']['records'] if r['key']=='$1'][0]"; }
# Substring test on a finding's evidence; the needle is passed as an argument, so quotes are safe.
ev_has() { # FINDING NEEDLE
  python3 -c 'import json,sys; d=json.load(open(sys.argv[3])); n=sys.argv[2]; sys.exit(0 if any(n in (e["ref"]+" "+e.get("excerpt","")) for f in d["findings"] if f["id"]==sys.argv[1] for e in f.get("evidence",[])) else 1)' "$1" "$2" "${OUT}"
}
evidence_count() { json_py "len([e for f in d['findings'] if f['id']=='$1' for e in f['evidence']])"; }
scope_status() { json_py "[c['status'] for c in d['inventory']['coverage'] if c.get('scope')=='$1'][0]"; }

# ================================================================================== auth

write_defs() { printf '%b' "$1" >"${ROOT}/etc/login.defs"; }

@test "auth: weak login.defs defaults are one low finding naming each setting" {
  write_defs '# comment\nPASS_MAX_DAYS\t99999\nENCRYPT_METHOD MD5\nUMASK 000\n'
  run_audit --modules auth
  has_finding ATH-DEFS-001
  [ "$(finding_sev ATH-DEFS-001)" = "low" ]
  [ "$(evidence_count ATH-DEFS-001)" -eq 3 ]
  ev_has ATH-DEFS-001 'PASS_MAX_DAYS 99999'
  ev_has ATH-DEFS-001 'ENCRYPT_METHOD MD5'
  ev_has ATH-DEFS-001 'UMASK 000'
}

@test "auth: sensible login.defs is quiet and is inventoried" {
  write_defs 'PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nENCRYPT_METHOD SHA512\nUMASK 027\n'
  run_audit --modules auth
  no_finding ATH-DEFS-001
  has_rec config:logindefs:PASS_MAX_DAYS
  [ "$(rec_attr config:logindefs:UMASK value)" = "027" ]
}

@test "auth: the last occurrence of a login.defs key wins and comments are ignored" {
  write_defs 'PASS_MAX_DAYS 99999\n#PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 90\n   # ENCRYPT_METHOD MD5\n'
  run_audit --modules auth
  no_finding ATH-DEFS-001
  [ "$(rec_attr config:logindefs:PASS_MAX_DAYS value)" = "90" ]
}

@test "auth: umask 002, 022 and 077 do not make new files world-writable; 001 and 005 do" {
  local u
  for u in 002 022 077; do
    write_defs "UMASK ${u}\n"
    run_audit --modules auth
    no_finding ATH-DEFS-001
  done
  for u in 001 005; do
    write_defs "UMASK ${u}\n"
    run_audit --modules auth
    has_finding ATH-DEFS-001
  done
}

@test "auth: non-numeric or odd login.defs values never crash the module" {
  write_defs 'PASS_MAX_DAYS banana\nUMASK 9z9\nENCRYPT_METHOD\n\n\t\nPASS_MIN_DAYS -1\n'
  run_audit --modules auth
  [ "${status}" -eq 0 ] || [ "${status}" -eq 4 ] || [ "${status}" -eq 6 ]
  no_finding ATH-DEFS-001
  [ "$(json_py "d['summary']['total'] == len(d['findings'])")" = "True" ]
}

@test "auth: a missing login.defs is a non-material coverage note, not a failure" {
  rm -f "${ROOT}/etc/login.defs"
  run_audit --modules auth
  has_error LOGINDEFS_MISSING
  [ "$(scope_status logindefs)" = "unavailable" ]
  [ "$(json_py "[e for e in d['errors'] if e['code']=='LOGINDEFS_MISSING'][0].get('check_id')")" = "ATH-DEFS-001" ]
}

@test "auth: only login accounts with a usable password and no maximum age are flagged" {
  printf '%s\n' \
    'neverexp:x:2000:2000::/home/n:/bin/bash' \
    'agedok:x:2001:2001::/home/a:/bin/bash' \
    'lockedacct:x:2002:2002::/home/l:/bin/bash' \
    'svc:x:2003:2003::/srv:/usr/sbin/nologin' \
    'unset:x:2004:2004::/home/u:/bin/bash' >"${ROOT}/etc/passwd"
  printf '%s\n' \
    'neverexp:$6$FIXTUREHASHAAA$zzz:19000:0:99999:7:::' \
    'agedok:$6$FIXTUREHASHBBB$zzz:19000:0:90:7:::' \
    'lockedacct:!$6$FIXTUREHASHCCC$zzz:19000:0:99999:7:::' \
    'svc:$6$FIXTUREHASHDDD$zzz:19000:0:99999:7:::' \
    'unset:$6$FIXTUREHASHEEE$zzz:19000:::::' >"${ROOT}/etc/shadow"
  chmod 644 "${ROOT}/etc/shadow"
  run_audit --modules auth
  has_finding ATH-AGING-001
  ev_has ATH-AGING-001 "account 'neverexp'"
  ev_has ATH-AGING-001 "account 'unset'"
  refute ev_has ATH-AGING-001 "agedok"
  refute ev_has ATH-AGING-001 "lockedacct"
  refute ev_has ATH-AGING-001 "'svc'"
  refute grep -q 'FIXTUREHASH' "${OUT}" "${ERR}"
}

@test "auth: no password hash ever reaches the report or the log" {
  run_audit --modules auth
  refute grep -q 'REDACTEDHASHFIXTURE\|FIXTUREONLY' "${OUT}" "${ERR}"
}

@test "auth: without a readable shadow the aging check is skipped with a recorded gap" {
  rm -f "${ROOT}/etc/shadow"
  run_audit --modules auth
  no_finding ATH-AGING-001
  has_error PERM_DENIED
}

@test "auth: duplicate GIDs, duplicate names and group passwords are findings; hashes stay hidden" {
  printf '%s\n' 'root:x:0:' 'ops:x:500:' 'dupe:x:500:bob' 'twice:x:501:' 'twice:x:502:' \
    'secretgrp:$6$FIXTUREGROUPHASH$abc:503:' 'okgrp:x:504:' 'emptyok::505:' >"${ROOT}/etc/group"
  run_audit --modules auth
  has_finding ATH-GROUP-001
  ev_has ATH-GROUP-001 'gid 500 shared by'
  has_finding ATH-GROUP-004
  ev_has ATH-GROUP-004 'twice'
  has_finding ATH-GROUP-002
  ev_has ATH-GROUP-002 "group 'secretgrp'"
  refute ev_has ATH-GROUP-002 "okgrp"
  refute ev_has ATH-GROUP-002 "emptyok"
  refute grep -q 'FIXTUREGROUPHASH' "${OUT}" "${ERR}"
}

@test "auth: an account whose primary group is not defined is reported" {
  printf '%s\n' 'root:x:0:0:r:/root:/bin/bash' 'ghost:x:3000:3999::/home/g:/bin/bash' >"${ROOT}/etc/passwd"
  printf '%s\n' 'root:x:0:' >"${ROOT}/etc/group"
  run_audit --modules auth
  has_finding ATH-GROUP-003
  ev_has ATH-GROUP-003 "account 'ghost'"
  refute ev_has ATH-GROUP-003 "account 'root'"
}

@test "auth: a consistent group file raises no group finding" {
  printf '%s\n' 'root:x:0:0:r:/root:/bin/bash' 'u:x:1000:1000::/home/u:/bin/bash' >"${ROOT}/etc/passwd"
  printf '%s\n' 'root:x:0:' 'u:x:1000:' >"${ROOT}/etc/group"
  run_audit --modules auth
  local id
  for id in ATH-GROUP-001 ATH-GROUP-002 ATH-GROUP-003 ATH-GROUP-004; do no_finding "${id}"; done
}

@test "auth: PAM quality and lockout findings disappear when the modules are configured" {
  run_audit --modules auth
  has_finding ATH-PWQ-001
  has_finding ATH-LOCKOUT-001
  echo 'password requisite pam_pwquality.so retry=3 minlen=12' >"${ROOT}/etc/pam.d/common-password"
  echo 'auth required pam_faillock.so preauth deny=5' >"${ROOT}/etc/pam.d/common-lockout"
  run_audit --modules auth
  no_finding ATH-PWQ-001
  no_finding ATH-LOCKOUT-001
}

@test "auth: commented-out PAM modules do not count as configured" {
  echo '# password requisite pam_pwquality.so' >"${ROOT}/etc/pam.d/common-password"
  echo '   #auth required pam_faillock.so' >"${ROOT}/etc/pam.d/common-lockout"
  run_audit --modules auth
  has_finding ATH-PWQ-001
  has_finding ATH-LOCKOUT-001
}

@test "auth: pwquality.conf settings count as password-quality enforcement" {
  mkdir -p "${ROOT}/etc/security"
  printf 'minlen = 14\n' >"${ROOT}/etc/security/pwquality.conf"
  run_audit --modules auth
  no_finding ATH-PWQ-001
}

@test "auth: no PAM configuration at all is a non-material gap, not a finding" {
  rm -rf "${ROOT}/etc/pam.d"
  run_audit --modules auth
  has_error PAM_MISSING
  no_finding ATH-PWQ-001
  no_finding ATH-LOCKOUT-001
}

# ============================================================================== sysconfig

set_mounts() { printf '%b' "$1" >"${ROOT}/proc/mounts"; }

@test "sysconfig: /tmp without nosuid/nodev/noexec is reported with the missing options" {
  set_mounts '/dev/sda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw,nodev 0 0\n'
  run_audit --modules sysconfig
  has_finding CFG-MNT-001
  ev_has CFG-MNT-001 'without nosuid, noexec'
}

@test "sysconfig: fully restricted temp mounts are quiet and inventoried" {
  set_mounts 'tmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\ntmpfs /var/tmp tmpfs rw,nosuid,nodev,noexec 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n'
  run_audit --modules sysconfig
  no_finding CFG-MNT-001
  has_rec mount:/tmp
  has_rec mount:/dev/shm
  [ "$(json_py "sorted([r['attrs']['flags'] for r in d['inventory']['records'] if r['key']=='mount:/tmp'][0])")" = "['nodev', 'noexec', 'nosuid']" ]
}

@test "sysconfig: the last of stacked mounts decides" {
  set_mounts 'tmpfs /tmp tmpfs rw 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\n'
  run_audit --modules sysconfig
  no_finding CFG-MNT-001
}

@test "sysconfig: no separate temp mounts means nothing to assess, not a finding" {
  set_mounts '/dev/sda1 / ext4 rw 0 0\n'
  run_audit --modules sysconfig
  no_finding CFG-MNT-001
}

@test "sysconfig: unreadable /proc/mounts degrades coverage" {
  rm -f "${ROOT}/proc/mounts"
  run_audit --modules sysconfig
  has_error MOUNTS_UNREADABLE
  [ "$(scope_status mounts)" = "unavailable" ]
}

set_core() {
  mkdir -p "${ROOT}/proc/sys/kernel" "${ROOT}/proc/sys/fs"
  printf '%s\n' "$1" >"${ROOT}/proc/sys/kernel/core_pattern"
}

@test "sysconfig: core_pattern piping to an unknown program is high; known handlers are quiet" {
  set_core '|/tmp/.x/handler %p'
  run_audit --modules sysconfig
  has_finding CFG-CORE-001
  [ "$(finding_sev CFG-CORE-001)" = "high" ]
  local ok
  for ok in '|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h' '|/usr/share/apport/apport -p%p -s%s' 'core' '/var/crash/core.%e.%p'; do
    set_core "${ok}"
    run_audit --modules sysconfig
    no_finding CFG-CORE-001
  done
}

@test "sysconfig: a look-alike handler path is not trusted" {
  set_core '|/usr/lib/systemd/systemd-coredump-evil %p'
  run_audit --modules sysconfig
  has_finding CFG-CORE-001
  set_core '|/home/x/usr/lib/systemd/systemd-coredump %p'
  run_audit --modules sysconfig
  has_finding CFG-CORE-001
}

@test "sysconfig: suid_dumpable above zero is a low finding; zero and junk are quiet" {
  mkdir -p "${ROOT}/proc/sys/fs"
  echo 2 >"${ROOT}/proc/sys/fs/suid_dumpable"
  run_audit --modules sysconfig
  has_finding CFG-CORE-002
  echo 0 >"${ROOT}/proc/sys/fs/suid_dumpable"
  run_audit --modules sysconfig
  no_finding CFG-CORE-002
  echo garbage >"${ROOT}/proc/sys/fs/suid_dumpable"
  run_audit --modules sysconfig
  no_finding CFG-CORE-002
}

@test "sysconfig: a log linked to /dev/null is high; ordinary aliases are quiet" {
  mkdir -p "${ROOT}/var/log"
  ln -s /dev/null "${ROOT}/var/log/auth.log"
  ln -s syslog "${ROOT}/var/log/messages"
  : >"${ROOT}/var/log/syslog"
  run_audit --modules sysconfig
  has_finding CFG-LOG-001
  [ "$(finding_sev CFG-LOG-001)" = "high" ]
  ev_has CFG-LOG-001 'auth.log'
  refute ev_has CFG-LOG-001 'messages'
  no_finding CFG-LOG-004
}

@test "sysconfig: a log linked outside /var/log is medium, a link inside is quiet" {
  mkdir -p "${ROOT}/var/log" "${ROOT}/srv"
  ln -s /srv/elsewhere.log "${ROOT}/var/log/secure"
  ln -s /var/log/syslog "${ROOT}/var/log/kern.log"
  run_audit --modules sysconfig
  has_finding CFG-LOG-004
  [ "$(finding_sev CFG-LOG-004)" = "medium" ]
  ev_has CFG-LOG-004 'secure'
  refute ev_has CFG-LOG-004 'kern.log'
}

@test "sysconfig: empty login records are a low-confidence hint" {
  mkdir -p "${ROOT}/var/log"
  : >"${ROOT}/var/log/wtmp"
  echo data >"${ROOT}/var/log/btmp"
  run_audit --modules sysconfig
  has_finding CFG-LOG-002
  [ "$(json_py "[f['confidence'] for f in d['findings'] if f['id']=='CFG-LOG-002'][0]")" = "low" ]
  ev_has CFG-LOG-002 'wtmp'
  refute ev_has CFG-LOG-002 'btmp'
}

@test "sysconfig: log contents are never read into the report" {
  mkdir -p "${ROOT}/var/log"
  echo 'Failed password for root from 203.0.113.9 SECRETLOGLINE' >"${ROOT}/var/log/auth.log"
  run_audit --modules sysconfig
  refute grep -q 'SECRETLOGLINE' "${OUT}" "${ERR}"
}

@test "sysconfig: volatile journald without a syslog daemon is medium; persistence silences it" {
  mkdir -p "${ROOT}/etc/systemd"
  printf '[Journal]\nStorage=volatile\n' >"${ROOT}/etc/systemd/journald.conf"
  run_audit --modules sysconfig
  has_finding CFG-LOG-003
  [ "$(finding_sev CFG-LOG-003)" = "medium" ]
  touch "${ROOT}/etc/rsyslog.conf"
  run_audit --modules sysconfig
  no_finding CFG-LOG-003
  rm "${ROOT}/etc/rsyslog.conf"
  mkdir -p "${ROOT}/var/log/journal"
  run_audit --modules sysconfig
  no_finding CFG-LOG-003
}

@test "sysconfig: journald drop-ins override the main file" {
  mkdir -p "${ROOT}/etc/systemd/journald.conf.d"
  printf '[Journal]\nStorage=volatile\n' >"${ROOT}/etc/systemd/journald.conf"
  printf '[Journal]\nStorage=persistent\n' >"${ROOT}/etc/systemd/journald.conf.d/50-persist.conf"
  run_audit --modules sysconfig
  no_finding CFG-LOG-003
}

# ===================================================================== both modules together

tree_fingerprint() {
  (cd "${ROOT}" && find . \( -type f -o -type l \) -print0 | sort -z | xargs -0 stat -c '%n %s %Y %a' | sha256sum)
}

@test "expansion modules never modify the audited tree" {
  local before after
  before="$(tree_fingerprint)"
  run_audit --modules auth,sysconfig
  after="$(tree_fingerprint)"
  [ "${before}" = "${after}" ]
}

@test "expansion modules produce unique ids, a matching summary and the right categories" {
  run_audit --modules auth,sysconfig
  [ "$(json_py "len(set(f['id'] for f in d['findings'])) == len(d['findings'])")" = "True" ]
  [ "$(json_py "d['summary']['total'] == len(d['findings'])")" = "True" ]
  [ "$(json_py "sorted(set(f['category'] for f in d['findings']))")" = "['auth', 'sysconfig']" ]
  [ "$(json_py "d['run']['mode']")" = "read-only" ]
}

@test "expansion modules declare coverage for every inventory partition they own" {
  write_defs 'PASS_MAX_DAYS 90\n'
  run_audit --modules auth,sysconfig
  [ "$(json_py "sorted(c.get('scope','') for c in d['inventory']['coverage'])")" = "['core', 'logging', 'logindefs', 'mounts']" ]
}

@test "unknown modules are still rejected next to the new ones" {
  run "${AUDIT}" --modules auth,nosuch
  [ "${status}" -eq 2 ]
}
