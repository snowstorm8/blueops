#!/usr/bin/env bats
# Regression tests for issues found in field testing of v0.1 (SUID inventory,
# X11/PostgreSQL false positives, failed socket units) plus the PAM and
# package-integrity additions.

load test_helper

setup() {
  make_root
  use_fake_tools
}

# ------------------------------------------------ 1. SUID/SGID inventory

@test "suid: only local-filesystem mounts from /proc/mounts are scan roots" {
  # "/" is tmpfs here, so only the (space-containing) ext4 mount is scanned; the
  # fixture's /usr/bin/su and the file under the nfs mount point must not appear.
  printf '%s\n' \
    'tmpfs / tmpfs rw 0 0' \
    '/dev/sdb1 /usr/local/a\040b ext4 rw 0 0' \
    'server:/x /mnt/nfs nfs4 rw 0 0' >"${ROOT}/proc/mounts"
  mkdir -p "${ROOT}/usr/local/a b" "${ROOT}/mnt/nfs"
  echo x >"${ROOT}/usr/local/a b/helper"
  chmod 4755 "${ROOT}/usr/local/a b/helper"
  echo x >"${ROOT}/mnt/nfs/remote"
  chmod 4755 "${ROOT}/mnt/nfs/remote"
  run_audit --modules filesystem
  evidence_has FS-SUID-001 "/usr/local/a b/helper"
  refute evidence_has FS-SUID-001 /usr/bin/su
  refute evidence_has FS-SUID-001 /mnt/nfs/remote
}

@test "suid: files reachable through overlapping mounts are listed once" {
  printf '%s\n' '/dev/a / ext4 rw 0 0' '/dev/b /usr ext4 rw 0 0' >"${ROOT}/proc/mounts"
  run_audit --modules filesystem
  [ "$(json_py "[e['ref'] for f in d['findings'] if f['id']=='FS-SUID-001' for e in f['evidence']].count('/usr/bin/su')")" = "1" ]
  [ "$(json_py "len([e for f in d['findings'] if f['id']=='FS-SUID-001' for e in f['evidence']])")" = "3" ]
}

@test "suid: overlay (container) and btrfs roots are scanned" {
  printf '%s\n' 'overlay / overlay rw 0 0' >"${ROOT}/proc/mounts"
  run_audit --modules filesystem
  evidence_has FS-SUID-001 /usr/bin/su
  printf '%s\n' '/dev/x / btrfs rw 0 0' >"${ROOT}/proc/mounts"
  run_audit --modules filesystem
  evidence_has FS-SUID-001 /usr/bin/su
}

@test "suid: unreadable /proc/mounts falls back to the root, not to zero results" {
  rm "${ROOT}/proc/mounts"
  run_audit --modules filesystem
  evidence_has FS-SUID-001 /usr/bin/su
}

@test "suid: live host count is not lower than native find" {
  [ "$(uname -s)" = "Linux" ] || skip "needs a Linux host"
  unset BO_ROOT
  local native
  native="$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l | tr -d ' ')"
  [ "${native}" -gt 0 ] || skip "no SUID files on / of this host"
  run_audit --modules filesystem --fs-path /nonexistent-bo-dir
  # Without --fs-path restriction the mount scan must cover at least what find / -xdev sees.
  run_audit --modules filesystem
  local got
  got="$(json_py "int([f for f in d['findings'] if f['id']=='FS-SUID-001'][0]['description'].split()[0])")"
  [ "${got}" -ge "${native}" ]
}

# ------------------------------------------------ 2. X11 and PostgreSQL

@test "x11: standard /tmp X11 and ICE socket handling is not suspicious" {
  run_audit --modules persistence
  refute evidence_has PER-SHELL-001 x11.sh
}

@test "x11: X11 runtime files are not reported as temporary executables or deceptive names" {
  run_audit --modules filesystem
  refute evidence_has FS-PERM-003 ".X11-unix"
  refute evidence_has FS-PERM-003 ".X0-lock"
  refute evidence_has FS-HIDDEN-001 ".X11-unix"
  evidence_has FS-PERM-003 /tmp/dropper
}

@test "x11: a script dropped into the X11 directory is still flagged" {
  printf '#!/bin/sh\n' >"${ROOT}/tmp/.X11-unix/payload.sh"
  chmod 755 "${ROOT}/tmp/.X11-unix/payload.sh"
  echo 'bash /tmp/.X11-unix/payload.sh' >"${ROOT}/etc/profile.d/evil.sh"
  run_audit --modules filesystem,persistence
  evidence_has FS-PERM-003 payload.sh
  evidence_has PER-SHELL-001 evil.sh
}

@test "postgres: the packaged postgres shell is not flagged but is disclosed" {
  run_audit --modules users
  refute evidence_has USR-SHELL-001 postgres
  evidence_has USR-SHELL-001 www-data
  local d
  d="$(json_py "[f for f in d['findings'] if f['id']=='USR-INFO-001'][0]['description']")"
  [[ "${d}" == *"expected service-account shells not flagged: postgres"* ]]
}

@test "postgres: a postgres account with an unexpected home is still flagged" {
  sed -i.bak 's#/var/lib/postgresql:/bin/bash#/tmp/pg:/bin/bash#' "${ROOT}/etc/passwd"
  run_audit --modules users
  evidence_has USR-SHELL-001 postgres
}

@test "postgres: other system accounts are not exempted by name alone" {
  sed -i.bak 's#^www-data:x:33:33:www-data:/var/www#postgres2:x:34:34:x:/var/lib/postgresql#' "${ROOT}/etc/passwd"
  run_audit --modules users
  evidence_has USR-SHELL-001 postgres2
}

@test "postgres: SSH keys on the postgres account are still reported" {
  mkdir -p "${ROOT}/var/lib/postgresql/.ssh"
  echo "ssh-ed25519 AAAAC3NzaFIXTURE pg@x" >"${ROOT}/var/lib/postgresql/.ssh/authorized_keys"
  run_audit --modules users
  evidence_has USR-SSH-004 postgres
}

# ------------------------------------------------ 3. failed socket units

@test "services: failed socket units are reported separately from failed services" {
  run_audit --modules services
  evidence_has SVC-FAILED-001 backup.service
  refute evidence_has SVC-FAILED-001 cups.socket
  [ "$(finding_sev SVC-FAILED-002)" = "medium" ]
  evidence_has SVC-FAILED-002 cups.socket
  local d
  d="$(json_py "[f for f in d['findings'] if f['id']=='SVC-INFO-001'][0]['description']")"
  [[ "${d}" == *"1 failed, 1 failed socket"* ]]
}

# ------------------------------------------------ 4a. PAM audit

@test "pam: inventory lists config files and modules" {
  run_audit --modules pam
  has_finding PAM-INFO-001
  evidence_has PAM-INFO-001 /etc/pam.d/common-auth
  local d
  d="$(json_py "[f for f in d['findings'] if f['id']=='PAM-INFO-001'][0]['description']")"
  [[ "${d}" == *pam_unix.so* && "${d}" == *pam_limits.so* ]]
}

@test "pam: pam_permit as sufficient or as the only auth module is high severity" {
  run_audit --modules pam
  [ "$(finding_sev PAM-PERMIT-001)" = "high" ]
  evidence_has PAM-PERMIT-001 login-bad
  evidence_has PAM-PERMIT-001 su-bad
}

@test "pam: the Debian default stack (pam_unix, pam_deny, pam_permit) is not flagged" {
  run_audit --modules pam
  refute evidence_has PAM-PERMIT-001 common-auth
  refute evidence_has PAM-PERMIT-001 sshd
}

@test "pam: nullok is low and weak hashes are medium; bracketed controls parse" {
  run_audit --modules pam
  [ "$(finding_sev PAM-NULLOK-001)" = "low" ]
  evidence_has PAM-NULLOK-001 common-auth
  [ "$(finding_sev PAM-HASH-001)" = "medium" ]
  evidence_has PAM-HASH-001 "md5"
}

@test "pam: out-of-tree and missing modules are reported" {
  run_audit --modules pam
  [ "$(finding_sev PAM-MODULE-001)" = "high" ]
  evidence_has PAM-MODULE-001 /opt/evil/pam_capture.so
  [ "$(finding_sev PAM-MODULE-002)" = "medium" ]
  evidence_has PAM-MODULE-002 pam_ghost.so
  refute evidence_has PAM-MODULE-002 pam_nologin.so
}

@test "pam: world-writable PAM config is high; recent module changes respect --recent-days" {
  chmod 666 "${ROOT}/etc/pam.d/sshd"
  run_audit --modules pam
  [ "$(finding_sev PAM-PERM-001)" = "high" ]
  evidence_has PAM-RECENT-001 pam_unix.so
  touch -t 200001010000 "${ROOT}"/lib/x86_64-linux-gnu/security/*.so
  run_audit --modules pam
  no_finding PAM-RECENT-001
}

@test "pam: comments, blank lines, dash-prefixed types and @include lines are handled" {
  printf '# c\n\n-session optional pam_systemd.so\n@include common-auth\nauth requisite pam_deny.so # trailing\n' >"${ROOT}/etc/pam.d/odd"
  chmod 644 "${ROOT}/etc/pam.d/odd"
  run_audit --modules pam
  json_py "1" >/dev/null
  refute evidence_has PAM-MODULE-002 "pam_deny.so"
}

@test "pam: legacy /etc/pam.conf with a service column is parsed" {
  rm -f "${ROOT}"/etc/pam.d/*
  rmdir "${ROOT}/etc/pam.d"
  echo 'other auth sufficient pam_permit.so' >"${ROOT}/etc/pam.conf"
  chmod 644 "${ROOT}/etc/pam.conf"
  run_audit --modules pam
  has_finding PAM-PERMIT-001
}

@test "pam: absent configuration is a non-material gap" {
  rm -rf "${ROOT:?}/etc/pam.d"
  run_audit --modules pam
  has_error PAM_ABSENT
  [ "${status}" -eq 0 ]
}

@test "pam: missing module directory skips existence checks with a note" {
  rm -rf "${ROOT:?}/lib/x86_64-linux-gnu"
  run_audit --modules pam
  has_error PAM_MODULES_DIR
  no_finding PAM-MODULE-002
  has_finding PAM-MODULE-001
}

@test "pam: audit never modifies PAM files" {
  (cd "${ROOT}" && find etc/pam.d lib -type f -exec cksum {} +) >"${BATS_TEST_TMPDIR}/b"
  run_audit --modules pam
  (cd "${ROOT}" && find etc/pam.d lib -type f -exec cksum {} +) >"${BATS_TEST_TMPDIR}/a"
  diff "${BATS_TEST_TMPDIR}/b" "${BATS_TEST_TMPDIR}/a"
}

# ------------------------------------------------ 4b. package integrity

@test "pkg: integrity checks are off unless --package-integrity is given" {
  run_audit --modules filesystem
  no_finding FS-PKG-001
  no_finding FS-PKG-003
}

@test "pkg: modified programs are high; conffiles and docs are summarized, not listed" {
  run_audit --modules filesystem --package-integrity
  [ "$(finding_sev FS-PKG-001)" = "high" ]
  evidence_has FS-PKG-001 /usr/bin/ssh
  refute evidence_has FS-PKG-001 sshd_config
  refute evidence_has FS-PKG-002 copyright
  [ "$(finding_sev FS-PKG-002)" = "medium" ]
  evidence_has FS-PKG-002 /usr/bin/gone
  evidence_has FS-PKG-002 /opt/app/data.bin
  local d
  d="$(json_py "[f for f in d['findings'] if f['id']=='FS-PKG-003'][0]['description']")"
  [[ "${d}" == *"1 modified configuration file(s) and 1 documentation"* ]]
}

@test "pkg: non-Debian hosts get a recorded gap and exit 6" {
  BO_FORCE_MISSING_TOOLS="dpkg ip route ifconfig netstat" run_audit --modules filesystem --package-integrity --fail-on critical
  has_error PKG_UNSUPPORTED
  [ "${status}" -eq 6 ]
}

@test "pkg: dpkg database absent is treated as unsupported" {
  rm "${ROOT}/var/lib/dpkg/status"
  run_audit --modules filesystem --package-integrity
  has_error PKG_UNSUPPORTED
}

@test "pkg: option is accepted by the unified entry point and documented in --help" {
  run "${AUDIT}" --help
  [[ "${output}" == *"--package-integrity"* ]]
  run_audit --package-integrity --modules system
  json_py "1" >/dev/null
}
