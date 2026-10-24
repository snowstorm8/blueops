#!/usr/bin/env bats
# Baseline inventory emitted by the Linux collectors (schema 0.2.0 "inventory").

load test_helper

setup() {
  make_root
  use_fake_tools
}

inv_has_key() { json_py "'$1' in [r['key'] for r in d['inventory']['records']]" | grep -qx True; }
cov_status() { json_py "[c['status'] for c in d['inventory']['coverage'] if c['domain']=='$1' and c.get('scope','')=='$2']"; }

@test "inventory: records use stable identifiers and never embed pids" {
  run_audit
  inv_has_key "user:root"
  inv_has_key "group:sudo" || inv_has_key "group:root"
  inv_has_key "service:ssh.service"
  inv_has_key "process:root:systemd" || inv_has_key "process:root:init"
  inv_has_key "listener:tcp/0.0.0.0/22"
  [ "$(json_py "sum(1 for r in d['inventory']['records'] if 'pid=' in r['key'])")" = "0" ]
}

@test "inventory: process pids and command lines are volatile, not compared" {
  run_audit
  [ "$(json_py "all('pid' not in r['attrs'] and 'cmdline' not in r['attrs'] for r in d['inventory']['records'] if r['domain']=='processes')")" = "True" ]
  [ "$(json_py "any('pid' in r.get('volatile',{}) for r in d['inventory']['records'] if r['domain']=='processes')")" = "True" ]
}

@test "inventory: listeners record the owning process as an attribute" {
  run_audit
  [ "$(json_py "[r['attrs']['process'] for r in d['inventory']['records'] if r['key']=='listener:tcp/0.0.0.0/22'][0]")" = "sshd" ]
}

@test "inventory: cron entries are per-line records without secrets" {
  run_audit
  [ "$(json_py "sum(1 for r in d['inventory']['records'] if r['key'].startswith('cron:/etc/cron.d/benign#'))")" = "1" ]
  refute grep -q 's3cretvalue' "${OUT}"
}

@test "inventory: password hashes and key material never reach the report" {
  run_audit
  refute grep -q 'REDACTEDHASHFIXTURE' "${OUT}"
  refute grep -q 'FIXTUREONLY' "${OUT}"
  [ "$(json_py "[r['attrs']['password'] for r in d['inventory']['records'] if r['key']=='user:nopass'][0]")" = "empty" ]
}

@test "inventory: every record has a coverage declaration for its partition" {
  run_audit
  [ "$(json_py "all(any(c['domain']==r['domain'] and c.get('scope','')==r.get('scope','') for c in d['inventory']['coverage']) for r in d['inventory']['records'])")" = "True" ]
}

@test "inventory: a single module only declares its own partitions" {
  run_audit --modules users
  [ "$(json_py "sorted(set(c['domain'] for c in d['inventory']['coverage']))")" = "['config', 'groups', 'persistence', 'users']" ]
  [ "$(json_py "sorted(set(c.get('scope','') for c in d['inventory']['coverage'] if c['domain']=='config'))")" = "['sudoers']" ]
}

@test "inventory: unprivileged runs declare partial coverage where other users' files are unreadable" {
  [ "$(id -u)" != "0" ] || skip "only meaningful when not root"
  run_audit
  [[ "$(cov_status persistence shell)" == *partial* ]]
  [[ "$(cov_status persistence ssh-authkeys)" == *partial* ]]
}

@test "inventory: missing hash tools degrade coverage instead of inventing hashes" {
  export BO_FORCE_MISSING_TOOLS="ip route ifconfig netstat systemd-detect-virt sha256sum shasum openssl"
  run_audit
  [ "$(json_py "[r['attrs']['sha256'] for r in d['inventory']['records'] if r['key']=='persist:startup:/etc/rc.local'][0]")" = "None" ]
  [[ "$(cov_status persistence startup)" == *degraded* ]]
  # Entry identifiers fall back to cksum, so cron lines stay distinct.
  [ "$(json_py "len(set(r['key'] for r in d['inventory']['records'] if r['domain']=='scheduled_tasks'))")" = "$(json_py "len([r for r in d['inventory']['records'] if r['domain']=='scheduled_tasks'])")" ]
}

@test "inventory: collection never modifies the fixture host" {
  before="$(find "${ROOT}" -type f -exec cksum {} + | sort | cksum)"
  run_audit
  after="$(find "${ROOT}" -type f -exec cksum {} + | sort | cksum)"
  [ "${before}" = "${after}" ]
}
