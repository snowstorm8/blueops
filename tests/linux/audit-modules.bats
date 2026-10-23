#!/usr/bin/env bats
# Per-module behaviour: system, users, processes, network, services.

load test_helper

setup() {
  make_root
  use_fake_tools
}

# ---------------------------------------------------------------- system

@test "system: inventory reports OS, kernel, hostname, uptime and hardware" {
  run_audit --modules system
  evidence_has SYS-INFO-001 os-release
  local d
  d="$(json_py "[f for f in d['findings'] if f['id']=='SYS-INFO-001'][0]['description']")"
  [[ "${d}" == *"Ubuntu 22.04.4 LTS"* ]]
  [[ "${d}" == *"5.15.0-fixture"* ]]
  [[ "${d}" == *"fixture-host"* ]]
  [[ "${d}" == *"46d"* ]]
  [[ "${d}" == *"CPUs 2"* ]]
  [[ "${d}" == *"3952 MiB"* ]]
}

@test "system: kernel taint from out-of-tree modules is flagged" {
  run_audit --modules system
  has_finding SYS-KERN-001
  echo 0 >"${ROOT}/proc/sys/kernel/tainted"
  run_audit --modules system
  no_finding SYS-KERN-001
}

@test "system: unknown distribution is reported, not fatal" {
  rm "${ROOT}/etc/os-release"
  run_audit --modules system
  has_finding SYS-OS-001
  has_error DISTRO_UNKNOWN
  has_finding SYS-INFO-001
}

@test "system: very long uptime is noted" {
  echo "40000000.00 1.00" >"${ROOT}/proc/uptime"
  run_audit --modules system
  has_finding SYS-UPTIME-001
}

# ----------------------------------------------------------------- users

@test "users: extra UID 0 account is critical" {
  run_audit --modules users
  [ "$(finding_sev USR-UID0-001)" = "critical" ]
  evidence_has USR-UID0-001 toor
}

@test "users: duplicate UIDs, system-account shells and empty passwords are flagged" {
  run_audit --modules users
  has_finding USR-DUPUID-001
  evidence_has USR-DUPUID-001 twin
  has_finding USR-SHELL-001
  evidence_has USR-SHELL-001 www-data
  [ "$(finding_sev USR-PWD-001)" = "high" ]
  evidence_has USR-PWD-001 nopass
}

@test "users: sync/nologin service accounts are not reported as shell abuse" {
  run_audit --modules users
  refute evidence_has USR-SHELL-001 "'sync'"
  refute evidence_has USR-SHELL-001 daemon
}

@test "users: sudo rules, NOPASSWD and sudoers.d name filtering" {
  run_audit --modules users
  has_finding USR-SUDO-001
  evidence_has USR-SUDO-002 bob
  # README.bak contains a '.', so sudo (and BlueOps) ignore it.
  refute evidence_has USR-SUDO-001 evil
}

@test "users: group-based privilege and root-equivalent groups" {
  run_audit --modules users
  evidence_has USR-GROUP-001 alice
  evidence_has USR-GROUP-002 docker
}

@test "users: group/other-writable sudoers is high severity" {
  chmod 666 "${ROOT}/etc/sudoers.d/90-ops"
  run_audit --modules users
  [ "$(finding_sev USR-SUDO-003)" = "high" ]
}

@test "users: active sessions are listed, and a missing who/w is a coverage gap" {
  run_audit --modules users
  evidence_has USR-SESS-001 alice
  BO_FORCE_MISSING_TOOLS="who w" run_audit --modules users
  has_error TOOL_MISSING
  no_finding USR-SESS-001
}

@test "users: SSH keys are inventoried without key material; root and forced commands flagged" {
  run_audit --modules users
  has_finding USR-SSH-001
  evidence_has USR-SSH-001 "type ssh-ed25519"
  has_finding USR-SSH-002
  has_finding USR-SSH-005
  refute grep -q "AAAAC3Nza" "${OUT}"
}

@test "users: keys on system accounts and writable .ssh files are flagged" {
  mkdir -p "${ROOT}/var/www/.ssh"
  echo "ssh-ed25519 AAAAC3NzaFIXTURE www@x" >"${ROOT}/var/www/.ssh/authorized_keys"
  chmod 666 "${ROOT}/home/alice/.ssh/authorized_keys"
  run_audit --modules users
  has_finding USR-SSH-004
  evidence_has USR-SSH-004 www-data
  has_finding USR-SSH-003
}

@test "users: unreadable shadow is a coverage gap, not a failure" {
  skip_if_root
  chmod 000 "${ROOT}/etc/shadow"
  run_audit --modules users
  has_error PERM_DENIED
  no_finding USR-PWD-001
  has_finding USR-UID0-001
  chmod 644 "${ROOT}/etc/shadow"
}

@test "users: malformed passwd lines do not crash parsing" {
  printf '\n#comment\nbroken-line-without-colons\n+@nis\nok:x:5000:5000::/nonexistent:/usr/sbin/nologin\n' >>"${ROOT}/etc/passwd"
  run_audit --modules users
  json_py "1" >/dev/null
  has_finding USR-INFO-001
}

# ------------------------------------------------------------- processes

@test "processes: inventory has pid, parent, user and executable path" {
  run_audit --modules processes
  evidence_has PRC-INFO-001 "ppid=100 user=alice comm=bash exe=/usr/bin/bash"
  evidence_has PRC-INFO-001 "exe=/usr/sbin/sshd"
}

@test "processes: parent-child tree is printed in text mode" {
  run_text --modules processes
  grep -qE '^ +1 root systemd' "${OUT}"
  grep -qE '^ {6}100 root sshd' "${OUT}"
  grep -qE '^ {8}200 alice bash' "${OUT}"
  grep -qE '^ {10}300 alice payload' "${OUT}"
}

@test "processes: deleted exe, kernel-thread masquerade, reverse-shell cmdline and hidden dirs" {
  run_audit --modules processes
  [ "$(finding_sev PRC-DELETED-001)" = "high" ]
  evidence_has PRC-DELETED-001 "pid=300"
  has_finding PRC-MASQ-001
  evidence_has PRC-MASQ-001 "pid=301"
  has_finding PRC-CMD-001
  evidence_has PRC-CMD-001 "pid=302"
  has_finding PRC-HIDDEN-001
}

@test "processes: kernel threads and normal daemons produce no findings" {
  run_audit --modules processes
  refute evidence_has PRC-DELETED-001 "pid=2"
  refute evidence_has PRC-MASQ-001 "pid=2"
  refute evidence_has PRC-MASQ-001 "pid=100"
}

@test "processes: secrets in command lines are redacted" {
  run_audit --modules processes
  refute grep -q hunter2 "${OUT}"
  grep -q "password <redacted>" "${OUT}"
}

@test "processes: falls back to ps when /proc is unavailable" {
  rm -rf "${ROOT:?}/proc"
  run_audit --modules processes
  has_error PROC_UNAVAILABLE
  evidence_has PRC-INFO-001 "comm=sshd"
  refute grep -q "abc123" "${OUT}"
}

@test "processes: no /proc and no ps is a material coverage failure" {
  rm -rf "${ROOT:?}/proc"
  BO_FORCE_MISSING_TOOLS="ps" run_audit --modules processes
  has_error TOOL_MISSING
  [ "${status}" -eq 6 ]
}

@test "processes: unreadable exe links are aggregated into one coverage gap" {
  rm "${ROOT}/proc/200/exe" "${ROOT}/proc/301/exe"
  run_audit --modules processes
  has_error PERM_DENIED
  [ "$(json_py "sum(1 for e in d['errors'] if e['code']=='PERM_DENIED')")" = "1" ]
}

# --------------------------------------------------------------- network

@test "network: listeners are inventoried with owning processes" {
  run_audit --modules network
  evidence_has NET-LISTEN-001 "tcp 0.0.0.0:22"
  evidence_has NET-LISTEN-001 "sshd/100"
  evidence_has NET-LISTEN-001 "udp 127.0.0.53:53"
}

@test "network: exposed telnet is high, exposed redis medium, loopback mysql ignored" {
  run_audit --modules network
  [ "$(finding_sev NET-EXPOSE-001)" = "high" ]
  evidence_has NET-EXPOSE-001 ":23"
  [ "$(finding_sev NET-EXPOSE-002)" = "medium" ]
  evidence_has NET-EXPOSE-002 ":6379"
  refute evidence_has NET-EXPOSE-002 ":3306"
}

@test "network: netcat listener and shell with outbound connection are flagged" {
  run_audit --modules network
  evidence_has NET-LISTEN-002 ":9999"
  [ "$(finding_sev NET-ESTAB-002)" = "high" ]
  has_finding NET-ESTAB-003
}

@test "network: falls back to /proc/net when ss and netstat are missing" {
  BO_FORCE_MISSING_TOOLS="ss netstat ip route ifconfig" run_audit --modules network
  evidence_has NET-LISTEN-001 "tcp 0.0.0.0:22"
  evidence_has NET-LISTEN-001 "tcp 127.0.0.1:3306"
  evidence_has NET-ESTAB-001 "203.0.113.5:4444"
  has_error TOOL_MISSING
}

@test "network: routing, forwarding, DNS and hosts" {
  run_audit --modules network
  evidence_has NET-ROUTE-001 "gw=10.0.0.1"
  has_finding NET-FWD-001
  local d
  d="$(json_py "[f for f in d['findings'] if f['id']=='NET-DNS-001'][0]['description']")"
  [[ "${d}" == *"10.0.0.2"* && "${d}" == *"corp.example"* ]]
  evidence_has NET-HOSTS-001 "updates.example.test"
  refute evidence_has NET-HOSTS-001 localhost
}

@test "network: world-writable /etc/hosts is flagged" {
  chmod 666 "${ROOT}/etc/hosts"
  run_audit --modules network
  has_finding NET-HOSTS-002
}

@test "network: missing resolv.conf and routes degrade gracefully" {
  rm "${ROOT}/etc/resolv.conf" "${ROOT}/proc/net/route"
  run_audit --modules network
  has_error RESOLV_UNREADABLE
  has_error TOOL_MISSING
  has_finding NET-LISTEN-001
}

# -------------------------------------------------------------- services

@test "services: failed and legacy-enabled units are reported" {
  run_audit --modules services
  [ "$(finding_sev SVC-FAILED-001)" = "medium" ]
  evidence_has SVC-FAILED-001 backup.service
  evidence_has SVC-LEGACY-001 telnet.service
  evidence_has SVC-INFO-001 ssh.service
  evidence_has SVC-ENABLED-001 cron.service
}

@test "services: without systemctl, falls back to init scripts" {
  mkdir -p "${ROOT}/etc/init.d"
  echo '#!/bin/sh' >"${ROOT}/etc/init.d/legacyd"
  BO_FORCE_MISSING_TOOLS="systemctl" run_audit --modules services
  has_error NO_SYSTEMD
  evidence_has SVC-INFO-001 legacyd
}

@test "services: no systemd and no init scripts is a material gap" {
  BO_FORCE_MISSING_TOOLS="systemctl" run_audit --modules services
  has_error NO_INIT_SYSTEM
  [ "${status}" -eq 6 ]
}
