#!/usr/bin/env bash
# Module: telemetry - normalized endpoint telemetry as a JSON Lines stream.
# Category: audit (read-only). Safety: reads /proc, /sys and configuration/log files; writes only to
#   stdout (the stream) and stderr (diagnostics). Never modifies the host, never contacts a network.
# Usage: collect-telemetry.sh [--since-hours N] [--max-events N] [--categories LIST] [--help]
# Authorized environments only. Output may contain sensitive data (user names, command lines, source
# addresses): store it with restrictive permissions. Passwords, keys and tokens are not collected:
# command lines are redacted, account password hashes and private keys are never read.
#
# Stream format (see docs/telemetry.md): one JSON object per line - header, then coverage / record /
# error lines, then an end marker. A stream without the end marker is treated as incomplete.
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# Needs Bash >= 4.2 (associative arrays). Checked before anything newer is parsed; exit 3 if too old.
# shellcheck source=../lib/bashcheck.sh
source "${SCRIPT_DIR}/../lib/bashcheck.sh"
bo_require_bash 4 2
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

TEL_VERSION="1.0.0"
TEL_ALL_CATEGORIES="process user group session service scheduled_task network_connection listener auth_event security_event config_change system_config integrity persistence"
TEL_SINCE_HOURS=24
TEL_MAX_EVENTS=5000
TEL_CATEGORIES=""
TEL_COUNT=0
TEL_NOW=""
TEL_TMP=""
TEL_CUTOFF=""
declare -A TEL_COV_STATE=()

tel_usage() {
  cat <<'EOF'
Usage: collect-telemetry.sh [options]

Collects endpoint telemetry (processes, accounts, services, scheduled tasks, network sockets,
authentication events, security configuration, integrity hashes, persistence locations) as a
JSON Lines stream on stdout. Read-only; no network access. For authorized systems only.

Options:
  --since-hours N     event window for log sources (default 24)
  --max-events N      cap per event source (default 5000)
  --categories LIST   comma-separated subset of the categories (default: all)
  --help              show this help
  --version           show the collector version

Exit codes: 0 ok, 2 usage error, 6 collected with gaps (see coverage and error lines in the stream).
Collect as root for full coverage; unprivileged runs report each unreadable source as a gap.
EOF
}

tel_parse_args() {
  while (($#)); do
    case "$1" in
      --since-hours)
        TEL_SINCE_HOURS="${2:-}"
        shift 2 || return 2
        ;;
      --max-events)
        TEL_MAX_EVENTS="${2:-}"
        shift 2 || return 2
        ;;
      --categories)
        TEL_CATEGORIES="${2:-}"
        shift 2 || return 2
        ;;
      --no-color | --quiet) shift ;;
      --help | -h)
        tel_usage
        exit 0
        ;;
      --version)
        printf 'collect-telemetry.sh %s\n' "${TEL_VERSION}"
        exit 0
        ;;
      *)
        printf 'unknown option: %s\n' "$1" >&2
        return 2
        ;;
    esac
  done
  # Fixture logs have fixed dates, so test mode (BO_TEST_MODE=1) allows a very wide window.
  local max_hours=2160
  [[ "${BO_TEST_MODE:-}" == 1 ]] && max_hours=1000000
  if ! [[ "${TEL_SINCE_HOURS}" =~ ^[0-9]+$ ]] || ((TEL_SINCE_HOURS < 1 || TEL_SINCE_HOURS > max_hours)); then
    echo "--since-hours must be 1..${max_hours}" >&2
    return 2
  fi
  if ! [[ "${TEL_MAX_EVENTS}" =~ ^[0-9]+$ ]] || ((TEL_MAX_EVENTS < 1 || TEL_MAX_EVENTS > 1000000)); then
    echo "--max-events must be 1..1000000" >&2
    return 2
  fi
  local c
  if [[ -n "${TEL_CATEGORIES}" ]]; then
    local IFS=,
    for c in ${TEL_CATEGORIES}; do
      [[ " ${TEL_ALL_CATEGORIES} " == *" ${c} "* ]] || {
        printf 'unknown category: %s\n' "${c}" >&2
        return 2
      }
    done
  fi
  return 0
}

tel_wants() { # CATEGORY
  [[ -z "${TEL_CATEGORIES}" ]] && return 0
  [[ ",${TEL_CATEGORIES}," == *",$1,"* ]]
}

# ---------------------------------------------------------------- stream output

tel_line() { printf '%s\n' "$1"; }

# tel_cov CATEGORY STATUS [REASON] [SCOPE]
tel_cov() {
  local j
  j="{\"type\":\"coverage\",\"category\":$(bo_json_str "$1"),\"status\":$(bo_json_str "$2")"
  [[ -n "${3-}" ]] && j+=",\"reason\":$(bo_json_str "$3")"
  [[ -n "${4-}" ]] && j+=",\"scope\":$(bo_json_str "$4")"
  tel_line "${j}}"
  TEL_COV_STATE["$1"]="$2"
}

# tel_err CODE MESSAGE [CATEGORY]
tel_err() {
  local j
  j="{\"type\":\"error\",\"code\":$(bo_json_str "$1"),\"message\":$(bo_json_str "$2")"
  [[ -n "${3-}" ]] && j+=",\"category\":$(bo_json_str "$3")"
  tel_line "${j}}"
  printf '%s %s: %s\n' "$(bo_now_utc)" "$1" "$2" >&2
}

# tel_rec CATEGORY SCOPE KEY SOURCE_TYPE SOURCE_REF METHOD EVENT_TIME TOKEN...
#   NAME=VALUE   string attribute          +NAME=VALUE  number or true/false
#   NAME[]=A,B   list of strings           ?NAME        value could not be collected (null + unknown)
# An empty EVENT_TIME means "not an event / no usable time".
tel_rec() {
  local cat="$1" scope="$2" key="$3" stype="$4" sref="$5" method="$6" etime="$7" tok name val item items attrs="" unknown=""
  shift 7
  for tok in "$@"; do
    case "${tok}" in
      '?'*)
        name="${tok#\?}"
        _bo_jq "${name}"
        attrs+="${attrs:+,}${REPLY}:null"
        unknown+="${unknown:+,}${REPLY}"
        ;;
      '+'*)
        name="${tok#+}"
        val="${name#*=}"
        name="${name%%=*}"
        _bo_jq "${name}"
        if [[ "${val}" =~ ^-?[0-9]+$ || "${val}" == true || "${val}" == false ]]; then
          attrs+="${attrs:+,}${REPLY}:${val}"
        else
          attrs+="${attrs:+,}${REPLY}:null"
          unknown+="${unknown:+,}${REPLY}"
        fi
        ;;
      *'[]='*)
        name="${tok%%\[\]=*}"
        val="${tok#*\[\]=}"
        _bo_jq "${name}"
        local q="${REPLY}"
        items=""
        local IFS=,
        for item in ${val}; do
          _bo_jq "${item}"
          items+="${items:+,}${REPLY}"
        done
        IFS=$'\n\t'
        attrs+="${attrs:+,}${q}:[${items}]"
        ;;
      *)
        name="${tok%%=*}"
        val="${tok#*=}"
        _bo_jq "${name}"
        local qn="${REPLY}"
        _bo_jq "${val}"
        attrs+="${attrs:+,}${qn}:${REPLY}"
        ;;
    esac
  done
  local line
  _bo_jq "${cat}"
  line="{\"type\":\"record\",\"category\":${REPLY}"
  _bo_jq "${key}"
  line+=",\"key\":${REPLY}"
  if [[ -n "${scope}" ]]; then
    _bo_jq "${scope}"
    line+=",\"scope\":${REPLY}"
  fi
  _bo_jq "${stype}"
  line+=",\"source\":{\"type\":${REPLY}"
  _bo_jq "${sref}"
  line+=",\"ref\":${REPLY}},\"method\":$(bo_json_str "${method}"),\"observed_at\":\"${TEL_NOW}\""
  [[ -n "${etime}" ]] && line+=",\"event_time\":$(bo_json_str "${etime}")"
  line+=",\"attributes\":{${attrs}},\"unknown_attributes\":[${unknown}]"
  tel_line "${line}}"
  TEL_COUNT=$((TEL_COUNT + 1))
}

# ---------------------------------------------------------------- helpers

# Redact secrets in command lines (reads stdin, writes stdout).
tel_clean_stream() { bo_redact; }

tel_trunc() { # STRING MAX -> REPLY
  local s="${1-}" m="${2:-300}"
  s="${s//$'\t'/ }"
  s="${s//$'\r'/ }"
  s="${s//$'\n'/ }"
  ((${#s} > m)) && s="${s:0:m}..."
  REPLY="${s}"
}

# User name for a uid from the (possibly fixture) passwd file.
tel_uid_name() {
  local n
  n="$(awk -F: -v u="$1" '$3 == u { print $1; exit }' "$(bo_path /etc/passwd)" 2>/dev/null || true)"
  printf '%s' "${n:-$1}"
}

# Window start (ISO wall-clock, as logged) when GNU date is available; empty otherwise.
tel_cutoff() {
  date -u -d "${TEL_SINCE_HOURS} hours ago" +%Y-%m-%dT%H:%M:%S 2>/dev/null || true
}

# ---------------------------------------------------------------- processes

collect_process() {
  local proc d pid line rest comm ppid uid exe cmd user deleted unreadable=0 total=0 st
  proc="$(bo_path /proc)"
  if [[ ! -d "${proc}" ]] || ! compgen -G "${proc}/[0-9]*" >/dev/null; then
    tel_cov process unavailable "/proc is not available on this host"
    return 0
  fi
  local tsv="${TEL_TMP}/procs.tsv"
  : >"${tsv}"
  for d in "${proc}"/[0-9]*; do
    [[ -d "${d}" && -r "${d}/stat" ]] || continue
    pid="${d##*/}"
    line=""
    read -r line <"${d}/stat" 2>/dev/null || continue
    comm="${line#*(}"
    comm="${comm%)*}"
    rest="${line##*) }"
    # The global IFS has no space; the stat fields after "(comm) " are space separated.
    local fields=()
    IFS=' ' read -r -a fields <<<"${rest}"
    ppid="${fields[1]:-}"
    st="${fields[19]:-}" # starttime in clock ticks since boot
    uid="$(awk '/^Uid:/ { print $2; exit }' "${d}/status" 2>/dev/null || true)"
    exe="$(readlink "${d}/exe" 2>/dev/null || true)"
    deleted=false
    if [[ "${exe}" == *" (deleted)" ]]; then
      deleted=true
      exe="${exe% (deleted)}"
    fi
    if [[ -z "${exe}" ]]; then
      exe="-"
      [[ -r "${d}/cmdline" && -s "${d}/cmdline" ]] && unreadable=$((unreadable + 1))
    fi
    cmd="$(tr '\0\n\t\r' '    ' <"${d}/cmdline" 2>/dev/null | tel_clean_stream || true)"
    cmd="${cmd%"${cmd##*[![:space:]]}"}"
    bo_tsv_field "${comm}" >/dev/null
    comm="${REPLY}"
    bo_tsv_field "${exe}" >/dev/null
    exe="${REPLY}"
    bo_tsv_field "${cmd}" >/dev/null
    cmd="${REPLY}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "${pid}" "${ppid:--}" "${uid:--}" "${comm}" "${exe}" "${deleted}" "${st:--}" "${cmd:--}" >>"${tsv}"
  done
  while IFS=$'\t' read -r pid ppid uid comm exe deleted st cmd; do
    total=$((total + 1))
    user="$(tel_uid_name "${uid}")"
    local toks=("name=${comm}" "user=${user}" "+pid=${pid}" "+ppid=${ppid}" "+exe_deleted=${deleted}")
    if [[ "${exe}" == "-" ]]; then toks+=("?exe"); else toks+=("exe=${exe}"); fi
    if [[ "${cmd}" == "-" ]]; then toks+=("?cmdline"); else
      tel_trunc "${cmd}" 500
      toks+=("cmdline=${REPLY}")
    fi
    tel_rec process "" "pid:${pid}:${st}" proc "/proc/${pid}" "procfs" "" "${toks[@]}"
  done <"${tsv}"
  if ((unreadable > 0)); then
    tel_cov process partial "${unreadable} process executable link(s) were unreadable (run as root for full coverage)"
  else
    tel_cov process complete
  fi
}

# ---------------------------------------------------------------- users and groups

collect_user() {
  local pw sh pwd_state shadow_ok=false
  pw="$(bo_path /etc/passwd)"
  sh="$(bo_path /etc/shadow)"
  if [[ ! -r "${pw}" ]]; then
    tel_cov user unavailable "/etc/passwd is not readable"
    return 0
  fi
  [[ -r "${sh}" ]] && shadow_ok=true
  local shadow_map="${TEL_TMP}/shadow.tsv"
  : >"${shadow_map}"
  # Only the lock/empty/set classification of the password field is kept; the hash is never read
  # into a variable, written, or logged.
  if ${shadow_ok}; then
    awk -F: '{ s = ($2 == "") ? "empty" : (($2 ~ /^[!*]/) ? "locked" : "set"); print $1 "\t" s }' "${sh}" >"${shadow_map}" 2>/dev/null || shadow_ok=false
  fi
  local name _x uid gid gecos home shell
  while IFS=: read -r name _x uid gid gecos home shell; do
    [[ -z "${name}" || "${name}" == \#* ]] && continue
    tel_trunc "${gecos}" 80
    local comment="${REPLY}"
    if ${shadow_ok}; then
      pwd_state="$(awk -F'\t' -v u="${name}" '$1 == u { print $2; exit }' "${shadow_map}")"
      pwd_state="${pwd_state:-unknown}"
    else
      pwd_state=""
    fi
    local toks=("name=${name}" "+uid=${uid}" "+gid=${gid}" "home=${home}" "shell=${shell}" "comment=${comment}")
    if [[ -n "${pwd_state}" ]]; then toks+=("password_state=${pwd_state}"); else toks+=("?password_state"); fi
    tel_rec user "" "user:${name}" file "/etc/passwd" "file-parse" "" "${toks[@]}"
  done <"${pw}"
  if ${shadow_ok}; then
    tel_cov user complete
  else
    tel_cov user partial "/etc/shadow is not readable; password state is unknown (run as root)"
  fi
}

collect_group() {
  local gr name _x gid members
  gr="$(bo_path /etc/group)"
  if [[ ! -r "${gr}" ]]; then
    tel_cov group unavailable "/etc/group is not readable"
    return 0
  fi
  while IFS=: read -r name _x gid members; do
    [[ -z "${name}" || "${name}" == \#* ]] && continue
    tel_rec group "" "group:${name}" file "/etc/group" "file-parse" "" "name=${name}" "+gid=${gid}" "members[]=${members}"
  done <"${gr}"
  tel_cov group complete
}

collect_session() {
  if ! bo_have who; then
    tel_cov session unavailable "'who' is not available"
    return 0
  fi
  local out="${TEL_TMP}/who.txt" user tty rest src
  if ! who >"${out}" 2>/dev/null; then
    tel_cov session unavailable "'who' failed (utmp unreadable?)"
    return 0
  fi
  local n=0
  while IFS=$' \t' read -r user tty rest; do
    [[ -z "${user}" ]] && continue
    src=""
    [[ "${rest}" =~ \(([^\)]*)\) ]] && src="${BASH_REMATCH[1]}"
    n=$((n + 1))
    local toks=("user=${user}" "terminal=${tty}")
    if [[ -n "${src}" ]]; then toks+=("source_address=${src}"); else toks+=("source_address=local"); fi
    tel_rec session "" "session:${user}:${tty}" command "who" "who" "" "${toks[@]}"
  done <"${out}"
  tel_cov session complete
}

# ---------------------------------------------------------------- services and scheduled tasks

collect_service() {
  local dirs=(/etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system) d f n=0 seen=""
  local found_dir=false
  for d in "${dirs[@]}"; do
    [[ -d "$(bo_path "${d}")" ]] || continue
    found_dir=true
    for f in "$(bo_path "${d}")"/*.service; do
      [[ -f "${f}" ]] || continue
      local base="${f##*/}"
      case "${seen}" in *"|${base}|"*) continue ;; esac # earlier directories take precedence
      seen+="|${base}|"
      local exec user enabled=no
      exec="$(sed -n 's/^ExecStart=[-@+!:]*//p' "${f}" 2>/dev/null | head -n 1)"
      user="$(sed -n 's/^User=//p' "${f}" 2>/dev/null | head -n 1)"
      if compgen -G "$(bo_path /etc/systemd/system)/*.wants/${base}" >/dev/null; then enabled=yes; fi
      tel_trunc "${exec}" 400
      local toks=("name=${base}" "path=${REPLY}" "start_mode=${enabled}" "unit_file=${d}/${base}" "account=${user:-root}")
      [[ -z "${exec}" ]] && toks=("name=${base}" "?path" "start_mode=${enabled}" "unit_file=${d}/${base}" "account=${user:-root}")
      tel_rec service "systemd" "service:${base}" file "${d}/${base}" "unit-file-parse" "" "${toks[@]}"
      n=$((n + 1))
    done
  done
  if ${found_dir}; then
    tel_cov service complete "unit definitions; runtime state (running/stopped) is not collected" systemd
  else
    tel_cov service unavailable "no systemd unit directories found"
  fi
}

# cron fields: minute hour dom mon dow [user] command
collect_cron_file() { # FILE HAS_USER_FIELD
  local f="$1" has_user="$2" ln=0 line min hour dom mon dow user cmd rest owner_name
  while IFS= read -r line || [[ -n "${line}" ]]; do
    ln=$((ln + 1))
    line="${line#"${line%%[![:space:]]*}"}"
    [[ -z "${line}" || "${line}" == \#* || "${line}" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] && continue
    if [[ "${line}" == @* ]]; then
      IFS=$' \t' read -r min rest <<<"${line}"
      hour="" dom="" mon="" dow=""
    else
      IFS=$' \t' read -r min hour dom mon dow rest <<<"${line}"
    fi
    if [[ "${has_user}" == yes ]]; then
      IFS=$' \t' read -r user cmd <<<"${rest}"
    else
      owner_name="${f##*/}"
      user="${owner_name}"
      cmd="${rest}"
    fi
    cmd="$(printf '%s' "${cmd}" | tel_clean_stream)"
    tel_trunc "${cmd}" 500
    local shown="${f#"$(bo_root)"}"
    tel_rec scheduled_task cron "cron:${shown}#${ln}" file "${shown}" "cron-parse" "" "name=${shown}#${ln}" "command=${REPLY}" "schedule=${min} ${hour} ${dom} ${mon} ${dow}" "user=${user}" "kind=cron"
  done <"${f}"
}

collect_scheduled_task() {
  local f d unreadable=0
  f="$(bo_path /etc/crontab)"
  if [[ -r "${f}" ]]; then
    collect_cron_file "${f}" yes
  fi
  for f in "$(bo_path /etc/cron.d)"/*; do
    [[ -f "${f}" ]] || continue
    if [[ -r "${f}" ]]; then collect_cron_file "${f}" yes; else unreadable=$((unreadable + 1)); fi
  done
  for d in /var/spool/cron /var/spool/cron/crontabs; do
    [[ -d "$(bo_path "${d}")" ]] || continue
    for f in "$(bo_path "${d}")"/*; do
      [[ -f "${f}" ]] || continue
      if [[ -r "${f}" ]]; then collect_cron_file "${f}" no; else unreadable=$((unreadable + 1)); fi
    done
    if [[ ! -r "$(bo_path "${d}")" ]]; then unreadable=$((unreadable + 1)); fi
  done
  for d in hourly daily weekly monthly; do
    for f in "$(bo_path /etc/cron.${d})"/*; do
      [[ -f "${f}" ]] || continue
      local shown="${f#"$(bo_root)"}"
      tel_rec scheduled_task "cron.${d}" "cronscript:${shown}" file "${shown}" "directory-listing" "" "name=${shown}" "command=${shown}" "schedule=${d}" "user=root" "kind=cron.${d}"
    done
  done
  local seen_timers=""
  for f in "$(bo_path /etc/systemd/system)"/*.timer "$(bo_path /usr/lib/systemd/system)"/*.timer "$(bo_path /lib/systemd/system)"/*.timer; do
    [[ -f "${f}" ]] || continue
    case "${seen_timers}" in *"|${f##*/}|"*) continue ;; esac # /lib is /usr/lib on merged-usr hosts
    seen_timers+="|${f##*/}|"
    local base="${f##*/}" cal unit
    cal="$(sed -n 's/^OnCalendar=//p' "${f}" 2>/dev/null | head -n 1)"
    unit="$(sed -n 's/^Unit=//p' "${f}" 2>/dev/null | head -n 1)"
    tel_rec scheduled_task "systemd-timer" "timer:${base}" file "${f#"$(bo_root)"}" "unit-file-parse" "" "name=${base}" "command=${unit:-${base%.timer}.service}" "schedule=${cal:-unknown}" "user=root" "kind=systemd-timer"
  done
  if ((unreadable > 0)); then
    tel_cov scheduled_task partial "${unreadable} scheduled-task location(s) were unreadable (run as root)"
  else
    tel_cov scheduled_task complete
  fi
}

# ---------------------------------------------------------------- network

# Hex address (/proc/net format) -> text. IPv4: 8 hex digits little-endian. IPv6: 4 little-endian words.
tel_net_awk() {
  cat <<'AWK'
function hex(s,  i, n, c, d) { n = 0; s = tolower(s); for (i = 1; i <= length(s); i++) { c = substr(s, i, 1); d = index("0123456789abcdef", c) - 1; n = n * 16 + d } return n }
function ip4(h) { return hex(substr(h, 7, 2)) "." hex(substr(h, 5, 2)) "." hex(substr(h, 3, 2)) "." hex(substr(h, 1, 2)) }
function ip6(h,  i, g, w, z, best, bl, cur, cl, out, s) {
  for (i = 0; i < 4; i++) { w = substr(h, i * 8 + 1, 8); g[i * 2 + 1] = tolower(substr(w, 7, 2) substr(w, 5, 2)); g[i * 2 + 2] = tolower(substr(w, 3, 2) substr(w, 1, 2)) }
  if (g[1] g[2] g[3] g[4] g[5] == "00000000000000000000" && g[6] == "ffff") return hex(substr(g[7], 1, 2)) "." hex(substr(g[7], 3, 2)) "." hex(substr(g[8], 1, 2)) "." hex(substr(g[8], 3, 2))
  for (i = 1; i <= 8; i++) { sub(/^0+/, "", g[i]); if (g[i] == "") g[i] = "0" }
  best = 0; bl = 0; cur = 0; cl = 0
  for (i = 1; i <= 8; i++) { if (g[i] == "0") { if (cl == 0) cur = i; cl++; if (cl > bl) { bl = cl; best = cur } } else cl = 0 }
  out = ""
  if (bl < 2) { for (i = 1; i <= 8; i++) out = out (i > 1 ? ":" : "") g[i]; return out }
  for (i = 1; i < best; i++) out = out (i > 1 ? ":" : "") g[i]
  out = out "::"
  for (i = best + bl; i <= 8; i++) out = out (i > best + bl ? ":" : "") g[i]
  return out
}
function addr(h) { return (length(h) == 8) ? ip4(h) : ip6(h) }
NR > 1 {
  split($2, l, ":"); split($3, r, ":")
  print proto "\t" $4 "\t" addr(l[1]) "\t" hex(l[2]) "\t" addr(r[1]) "\t" hex(r[2]) "\t" $10 "\t" $8
}
AWK
}

collect_network() { # fills both network_connection and listener
  local proto file n=0 missing=0 awkprog tsv="${TEL_TMP}/net.tsv" owners="${TEL_TMP}/owners.tsv" proc
  awkprog="$(tel_net_awk)"
  : >"${tsv}"
  for proto in tcp tcp6 udp udp6; do
    file="$(bo_path /proc/net/${proto})"
    if [[ -r "${file}" ]]; then
      awk -v proto="${proto}" "${awkprog}" "${file}" >>"${tsv}" 2>/dev/null || missing=$((missing + 1))
    else
      missing=$((missing + 1))
    fi
  done
  if ((missing == 4)); then
    tel_cov network_connection unavailable "/proc/net is not readable"
    tel_cov listener unavailable "/proc/net is not readable"
    return 0
  fi
  # Socket inode -> pid (needs permission to read other users' /proc/<pid>/fd).
  proc="$(bo_path /proc)"
  : >"${owners}"
  local fd_ok=false
  if compgen -G "${proc}/[0-9]*/fd/*" >/dev/null 2>&1; then
    fd_ok=true
    # shellcheck disable=SC2012 # symlink targets are the data; names are not used
    ls -l "${proc}"/[0-9]*/fd 2>/dev/null | awk '/^\/.*\/fd:$/ { split($0, p, "/"); pid = p[length(p) - 1]; next } /socket:\[/ { s = $0; sub(/.*socket:\[/, "", s); sub(/\].*/, "", s); print s "\t" pid }' >"${owners}" || true
  fi
  local p la lp ra rp inode st pid pname state key unowned=0
  while IFS=$'\t' read -r p st la lp ra rp inode _x; do
    pid="" pname=""
    if [[ -s "${owners}" && "${inode}" != 0 ]]; then
      pid="$(awk -F'\t' -v i="${inode}" '$1 == i { print $2; exit }' "${owners}")"
      if [[ -n "${pid}" && -r "${proc}/${pid}/comm" ]]; then pname="$(head -n 1 "${proc}/${pid}/comm" 2>/dev/null || true)"; fi
    fi
    case "${p}:${st}" in
      tcp*:0A) state=listen ;;
      tcp*:01) state=established ;;
      tcp*:02) state=syn_sent ;;
      tcp*:03) state=syn_recv ;;
      tcp*:06) state=time_wait ;;
      tcp*:08) state=close_wait ;;
      tcp*) state=other ;;
      udp*) state=udp ;;
      *) state=other ;;
    esac
    local ptoks=()
    if [[ -n "${pid}" ]]; then
      ptoks=("+pid=${pid}" "process=${pname}")
    else
      ptoks=("?pid" "?process")
      [[ "${inode}" != 0 ]] && unowned=$((unowned + 1))
    fi
    if [[ "${state}" == listen || ("${state}" == udp && "${ra}" =~ ^(0\.0\.0\.0|0+:0+:0+:0+:0+:0+:0+:0+)$) ]]; then
      key="listener:${p}:${la}:${lp}"
      tel_rec listener "" "${key}" proc "/proc/net/${p}" "procfs" "" "protocol=${p%6}" "local_address=${la}" "+local_port=${lp}" "+inode=${inode}" "${ptoks[@]}"
    elif [[ "${state}" != udp ]]; then
      key="conn:${p}:${la}:${lp}:${ra}:${rp}"
      tel_rec network_connection "" "${key}" proc "/proc/net/${p}" "procfs" "" "protocol=${p%6}" "state=${state}" "local_address=${la}" "+local_port=${lp}" "remote_address=${ra}" "+remote_port=${rp}" "+inode=${inode}" "${ptoks[@]}"
    fi
    n=$((n + 1))
  done <"${tsv}"
  local why=""
  ${fd_ok} || why="socket owners (pid/process) were not resolved: /proc/<pid>/fd is not readable (run as root)"
  if [[ -z "${why}" ]] && ((unowned > 0)); then
    why="the owning process of ${unowned} socket(s) could not be resolved (sockets of other users need root)"
  fi
  if [[ -n "${why}" ]]; then
    tel_cov network_connection partial "${why}"
    tel_cov listener partial "${why}"
  else
    tel_cov network_connection complete
    tel_cov listener complete
  fi
}

# ---------------------------------------------------------------- events

# Lines of a log (bounded) -> TSV: iso_time <TAB> program <TAB> message
tel_syslog_tsv() { # FILE -> stdout
  local f="$1"
  tail -n "$((TEL_MAX_EVENTS * 4))" -- "${f}" 2>/dev/null | awk -v cutoff="${TEL_CUTOFF}" '
    function trim(s) { sub(/^[ \t]+/, "", s); return s }
    {
      line = $0; t = ""
      if (match(line, /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9:.]+([+-][0-9][0-9]:?[0-9][0-9]|Z)/)) {
        t = substr(line, RSTART, RLENGTH); rest = substr(line, RLENGTH + 2)
        w = substr(t, 1, 19)
      } else if (match(line, /^[A-Z][a-z][a-z] +[0-9]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        t = "";  w = ""; rest = substr(line, RLENGTH + 2)
      } else { next }
      if (cutoff != "" && w != "" && w < cutoff) next
      sub(/^[^ ]+ /, "", rest)              # host
      prog = rest; sub(/[:\[ ].*/, "", prog)
      msg = rest; sub(/^[^:]*: ?/, "", msg); sub(/^ +/, "", msg)
      gsub(/\t/, " ", msg)
      print t "\t" prog "\t" msg
    }'
}

# Parse authentication messages into event TSV: time action result user source service method change group actor
tel_auth_awk() {
  cat <<'AWK'
BEGIN { FS = "\t"; OFS = "\037" }
function out(t, action, result, user, src, svc, method, change, grp, actor) { print t, action, result, user, src, svc, method, change, grp, actor }
{
  t = $1; prog = $2; m = $3
  if (prog == "sshd") {
    if (match(m, /^(Accepted|Failed) [a-z-]+(\/[a-z]+)? for (invalid user )?[^ ]+ from [^ ]+/)) {
      s = substr(m, RSTART, RLENGTH); n = split(s, a, " ")
      res = (a[1] == "Accepted") ? "success" : "failure"
      method = a[2]; i = 4; if (a[4] == "invalid") i = 6
      out(t, (res == "success") ? "login_success" : "login_failure", res, a[i], a[n], "sshd", method, "", "", "")
    } else if (match(m, /^Invalid user [^ ]+ from [^ ]+/)) {
      s = substr(m, RSTART, RLENGTH); split(s, a, " "); out(t, "other", "failure", a[3], a[5], "sshd", "invalid_user", "", "", "")
    }
  } else if (prog == "sudo") {
    if (match(m, /^[^ ]+ : .*(NOT in sudoers|command not allowed|incorrect password attempts|3 incorrect)/)) {
      split(m, a, " "); out(t, "sudo", "failure", a[1], "", "sudo", "denied", "", "", "")
    } else if (match(m, /^[^ ]+ : .*COMMAND=/)) {
      split(m, a, " "); u = a[1]; tgt = ""
      if (match(m, /USER=[^ ;]+/)) tgt = substr(m, RSTART + 5, RLENGTH - 5)
      out(t, "sudo", "success", u, "", "sudo", "command", "", "", tgt)
    } else if (match(m, /authentication failure;.* user=[^ ]+/)) {
      s = substr(m, RSTART, RLENGTH); sub(/.* user=/, "", s); out(t, "sudo", "failure", s, "", "sudo", "auth", "", "", "")
    }
  } else if (prog == "su" || prog == "su-l") {
    if (match(m, /^\(to [^)]+\) [^ ]+/)) { s = substr(m, RSTART, RLENGTH); split(s, a, " "); gsub(/[()]/, "", a[2]); out(t, "su", "success", a[3], "", "su", "to:" a[2], "", "", "") }
    else if (match(m, /^FAILED SU \(to [^)]+\) [^ ]+/)) { s = substr(m, RSTART, RLENGTH); split(s, a, " "); out(t, "su", "failure", a[5], "", "su", "denied", "", "", "") }
  } else if (prog == "useradd") {
    if (match(m, /new user: name=[^,]+/)) { s = substr(m, RSTART + 15, RLENGTH - 15); out(t, "account_change", "success", s, "", "useradd", "", "created", "", "") }
  } else if (prog == "userdel") {
    if (match(m, /delete user .[^ ]+./)) { s = substr(m, RSTART + 13, RLENGTH - 13); gsub(/[']/, "", s); out(t, "account_change", "success", s, "", "userdel", "", "deleted", "", "") }
  } else if (prog == "usermod" || prog == "gpasswd" || prog == "groupmod") {
    if (match(m, /^add .[^ ]+. to (shadow )?group .[^ ]+./)) { split(m, a, " "); u = a[2]; g = a[length(a)]; gsub(/[']/, "", u); gsub(/[']/, "", g); out(t, "group_change", "success", u, "", prog, "", "member_added", g, "") }
    else if (match(m, /^user [^ ]+ added by [^ ]+ to group [^ ]+/)) { split(m, a, " "); out(t, "group_change", "success", a[2], "", prog, "", "member_added", a[length(a)], a[5]) }
    else if (match(m, /^user [^ ]+ removed by [^ ]+ from group [^ ]+/)) { split(m, a, " "); out(t, "group_change", "success", a[2], "", prog, "", "member_removed", a[length(a)], a[5]) }
  } else if (prog == "passwd") {
    if (match(m, /^password changed for [^ ]+/)) { s = substr(m, RSTART + 21, RLENGTH - 21); out(t, "account_change", "success", s, "", "passwd", "", "password_changed", "", "") }
  } else if (prog == "groupadd") {
    if (match(m, /new group: name=[^,]+/)) { s = substr(m, RSTART + 16, RLENGTH - 16); out(t, "group_change", "success", "", "", "groupadd", "", "group_created", s, "") }
  }
}
AWK
}

collect_auth_event() {
  local src="" f cand n=0 skipped_time=0
  TEL_CUTOFF="$(tel_cutoff)"
  for cand in /var/log/auth.log /var/log/secure; do
    f="$(bo_path "${cand}")"
    if [[ -r "${f}" ]]; then
      src="${f}"
      break
    fi
  done
  local tsv="${TEL_TMP}/auth.tsv" ev="${TEL_TMP}/authev.tsv"
  : >"${tsv}"
  local origin="" reason=""
  if [[ -n "${src}" ]]; then
    origin="${src#"$(bo_root)"}"
    tel_syslog_tsv "${src}" >"${tsv}" || true
  elif [[ -z "${BO_ROOT:-}" ]] && bo_have journalctl; then # never the real journal in fixture mode
    origin="journalctl"
    local jerr="${TEL_TMP}/journal.err"
    if journalctl --no-pager -o short-iso --since "${TEL_SINCE_HOURS} hours ago" _COMM=sshd _COMM=sudo _COMM=su _COMM=useradd _COMM=usermod _COMM=userdel _COMM=passwd _COMM=gpasswd _COMM=groupadd -n "$((TEL_MAX_EVENTS * 4))" >"${TEL_TMP}/journal.txt" 2>"${jerr}"; then
      if grep -qi 'insufficient permissions\|permission denied\|not seeing messages' "${jerr}" 2>/dev/null; then
        reason="the system journal is not readable by this user (needs root or membership of the adm/systemd-journal group)"
      elif [[ -s "${TEL_TMP}/journal.txt" ]]; then
        awk '{ t = $1; $1 = ""; $2 = ""; sub(/^ +/, ""); prog = $1; sub(/\[.*/, "", prog); sub(/:$/, "", prog); msg = $0; sub(/^[^:]*: ?/, "", msg); print t "\t" prog "\t" msg }' "${TEL_TMP}/journal.txt" >"${tsv}" || true
      fi
    else
      reason="journalctl could not read the journal: $(head -c 200 "${jerr}" | tr '\n' ' ')"
    fi
  else
    reason="neither /var/log/auth.log, /var/log/secure nor journalctl is available"
  fi
  if [[ -n "${reason}" ]]; then
    tel_cov auth_event unavailable "${reason}"
    return 0
  fi
  # Traditional syslog lines carry no year or zone: their times are not guessed (event time stays
  # unknown and is reported as a limitation); ISO-8601 logs (rsyslog RFC3339, journald) are exact.
  awk -f <(tel_auth_awk) "${tsv}" >"${ev}" 2>/dev/null || tel_err AUTH_PARSE_FAILED "the authentication parser failed" auth_event
  local t action result user srcaddr svc method change grp actor key
  while IFS=$'\037' read -r t action result user srcaddr svc method change grp actor; do
    [[ -z "${action}" ]] && continue
    n=$((n + 1))
    ((n > TEL_MAX_EVENTS)) && {
      tel_err EVENT_LIMIT "more than ${TEL_MAX_EVENTS} authentication events; the rest were not recorded" auth_event
      break
    }
    [[ -z "${t}" ]] && skipped_time=$((skipped_time + 1))
    key="${t:-notime}|${action}|${result}|${user}|${srcaddr}|${svc}|${method}|${change}|${grp}"
    local toks=("action=${action}" "result=${result}" "user=${user}" "service=${svc}")
    [[ -n "${srcaddr}" ]] && toks+=("source_address=${srcaddr}")
    [[ -n "${method}" ]] && toks+=("method=${method}")
    [[ -n "${change}" ]] && toks+=("change=${change}")
    [[ -n "${grp}" ]] && toks+=("group=${grp}")
    [[ -n "${actor}" ]] && toks+=("actor=${actor}")
    tel_rec auth_event "" "${key}" file "${origin}" "log-parse" "${t}" "${toks[@]}"
  done <"${ev}"
  local note=""
  [[ -z "${TEL_CUTOFF}" ]] && note="the time window could not be applied (no GNU date); "
  if [[ "${origin}" == journalctl ]] && ((n == 0)) && ! bo_is_root; then
    tel_cov auth_event partial "${note}no events were returned; the journal shows an unprivileged user only part of the system log, so this does not prove there were none" auth
  elif ((skipped_time > 0)); then
    tel_cov auth_event partial "${note}${skipped_time} event(s) have no usable time (syslog lines without year/zone); they are kept without a time" auth
  else
    tel_cov auth_event complete "${note}events from ${origin}, last ${TEL_SINCE_HOURS}h, at most ${TEL_MAX_EVENTS}"
  fi
}

# auditd records -> security_event / config_change. audit(EPOCH.ms:SERIAL) is converted in awk.
tel_audit_awk() {
  cat <<'AWK'
function civil(z,  era, doe, yoe, y, doy, mp, d, m) {
  z += 719468; era = int(z / 146097); doe = z - era * 146097
  yoe = int((doe - int(doe / 1460) + int(doe / 36524) - int(doe / 146096)) / 365)
  y = yoe + era * 400; doy = doe - (365 * yoe + int(yoe / 4) - int(yoe / 100))
  mp = int((5 * doy + 2) / 153); d = doy - int((153 * mp + 2) / 5) + 1; m = mp < 10 ? mp + 3 : mp - 9
  if (m <= 2) y++
  return sprintf("%04d-%02d-%02d", y, m, d)
}
function iso(e,  days, s) { days = int(e / 86400); s = e - days * 86400; return civil(days) sprintf("T%02d:%02d:%02dZ", int(s / 3600), int((s % 3600) / 60), s % 60) }
BEGIN { OFS = "\037" }
/^type=/ {
  type = $1; sub(/^type=/, "", type)
  if (!match($0, /audit\([0-9]+/)) next
  e = substr($0, RSTART + 6, RLENGTH - 6) + 0
  if (e < since) next
  res = ""; if (match($0, /res=[a-z]+/)) res = substr($0, RSTART + 4, RLENGTH - 4)
  acct = ""; if (match($0, /acct="[^"]*"/)) acct = substr($0, RSTART + 6, RLENGTH - 7)
  auid = ""; if (match($0, / auid=[0-9]+/)) auid = substr($0, RSTART + 6, RLENGTH - 6)
  op = ""; if (match($0, /op="?[^" ]+/)) { op = substr($0, RSTART + 3, RLENGTH - 3); gsub(/"/, "", op) }
  if (type ~ /^(ADD_USER|DEL_USER|ADD_GROUP|DEL_GROUP|USER_MGMT|CONFIG_CHANGE|USER_AUTH|USER_LOGIN|USER_START|USER_END|USER_CMD|SYSTEM_BOOT|SERVICE_START|SERVICE_STOP|AVC)$/)
    print iso(e), type, res, acct, auid, op
}
AWK
}

collect_security_event() {
  local f
  f="$(bo_path /var/log/audit/audit.log)"
  if [[ ! -e "${f}" ]]; then
    tel_cov security_event unavailable "auditd is not installed or has no log (/var/log/audit/audit.log)"
    tel_cov config_change unavailable "auditd is not installed or has no log"
    return 0
  fi
  if [[ ! -r "${f}" ]]; then
    tel_cov security_event unavailable "/var/log/audit/audit.log is not readable (run as root)"
    tel_cov config_change unavailable "/var/log/audit/audit.log is not readable"
    return 0
  fi
  local since out="${TEL_TMP}/audit.tsv" n=0 t type res acct auid op
  since="$(date -u -d "${TEL_SINCE_HOURS} hours ago" +%s 2>/dev/null || echo 0)"
  tail -n "$((TEL_MAX_EVENTS * 6))" -- "${f}" 2>/dev/null | awk -v since="${since}" -f <(tel_audit_awk) >"${out}" || true
  while IFS=$'\037' read -r t type res acct auid op; do
    n=$((n + 1))
    ((n > TEL_MAX_EVENTS)) && {
      tel_err EVENT_LIMIT "more than ${TEL_MAX_EVENTS} audit events; the rest were not recorded" security_event
      break
    }
    case "${type}" in
      ADD_USER | DEL_USER | ADD_GROUP | DEL_GROUP | CONFIG_CHANGE)
        local obj=user chg=added
        [[ "${type}" == *GROUP ]] && obj=group
        [[ "${type}" == CONFIG_CHANGE ]] && {
          obj=audit_rules
          chg=modified
        }
        [[ "${type}" == DEL_* ]] && chg=deleted
        tel_rec config_change "" "audit:${t}:${type}:${acct}:${op}" file "/var/log/audit/audit.log" "audit-parse" "${t}" "object=${obj}" "change=${chg}" "name=${acct}" "actor=${auid}" "summary=${type} ${op}"
        ;;
    esac
    tel_rec security_event "" "audit:${t}:${type}:${res}:${acct}:${auid}:${op}" file "/var/log/audit/audit.log" "audit-parse" "${t}" "event_id=${type}" "source=auditd" "outcome=${res:-unknown}" "summary=${acct} ${op}" "actor=${auid}"
  done <"${out}"
  tel_cov security_event complete "auditd events of the last ${TEL_SINCE_HOURS}h (selected types), at most ${TEL_MAX_EVENTS}"
  tel_cov config_change complete "derived from auditd account/group/rule-change events only"
}

# ---------------------------------------------------------------- configuration

collect_system_config() {
  local f v n=0 line key val ln
  # sshd: first occurrence of a directive wins, Match blocks end the global section.
  local sshd_files=()
  [[ -r "$(bo_path /etc/ssh/sshd_config)" ]] && sshd_files+=("$(bo_path /etc/ssh/sshd_config)")
  for f in "$(bo_path /etc/ssh/sshd_config.d)"/*.conf; do [[ -r "${f}" ]] && sshd_files=("${f}" "${sshd_files[@]+"${sshd_files[@]}"}"); done
  declare -A seen=()
  for f in "${sshd_files[@]+"${sshd_files[@]}"}"; do
    ln=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
      ln=$((ln + 1))
      line="${line%%#*}"
      IFS=$' \t' read -r key val <<<"${line}"
      [[ -z "${key}" ]] && continue
      [[ "${key,,}" == match ]] && break
      case "${key,,}" in
        permitrootlogin | passwordauthentication | permitemptypasswords | pubkeyauthentication | x11forwarding | usepam | challengeresponseauthentication | kbdinteractiveauthentication | allowusers | allowgroups | maxauthtries | permituserenvironment | protocol | loglevel | clientaliveinterval)
          [[ -n "${seen[${key,,}]:-}" ]] && continue
          seen[${key,,}]=1
          tel_rec system_config sshd "sshd:${key,,}" file "${f#"$(bo_root)"}:${ln}" "config-parse" "" "setting=sshd.${key,,}" "value=${val,,}" "source=${f#"$(bo_root)"}"
          n=$((n + 1))
          ;;
        *) ;;
      esac
    done <"${f}"
  done
  # kernel and MAC settings from /proc and /sys
  local pair
  for pair in kernel/randomize_va_space:kernel.randomize_va_space kernel/yama/ptrace_scope:kernel.yama.ptrace_scope net/ipv4/ip_forward:net.ipv4.ip_forward fs/suid_dumpable:fs.suid_dumpable kernel/kptr_restrict:kernel.kptr_restrict kernel/dmesg_restrict:kernel.dmesg_restrict net/ipv4/conf/all/accept_redirects:net.ipv4.conf.all.accept_redirects; do
    f="$(bo_path "/proc/sys/${pair%%:*}")"
    if [[ -r "${f}" ]]; then
      v="$(head -n 1 "${f}" 2>/dev/null || true)"
      tel_rec system_config sysctl "sysctl:${pair##*:}" proc "/proc/sys/${pair%%:*}" "procfs" "" "setting=${pair##*:}" "value=${v}" "source=/proc/sys"
      n=$((n + 1))
    fi
  done
  f="$(bo_path /sys/fs/selinux/enforce)"
  if [[ -r "${f}" ]]; then
    v="$(head -n 1 "${f}" 2>/dev/null || true)"
    tel_rec system_config mac "mac:selinux" file "/sys/fs/selinux/enforce" "sysfs" "" "setting=selinux.enforce" "value=${v}" "source=/sys/fs/selinux/enforce"
    n=$((n + 1))
  fi
  f="$(bo_path /sys/module/apparmor/parameters/enabled)"
  if [[ -r "${f}" ]]; then
    v="$(head -n 1 "${f}" 2>/dev/null || true)"
    tel_rec system_config mac "mac:apparmor" file "/sys/module/apparmor/parameters/enabled" "sysfs" "" "setting=apparmor.enabled" "value=${v}" "source=/sys/module/apparmor/parameters/enabled"
    n=$((n + 1))
  fi
  if [[ -d "$(bo_path /etc/audit)" || -d "$(bo_path /var/log/audit)" ]]; then v=present; else v=absent; fi
  tel_rec system_config mac "audit:auditd" file "/etc/audit" "stat" "" "setting=auditd.installed" "value=${v}" "source=/etc/audit"
  n=$((n + 1))
  if ((n == 0)); then
    tel_cov system_config unavailable "no configuration sources were readable"
  else
    tel_cov system_config complete "selected settings only (sshd, kernel, MAC, auditd presence); not a full configuration audit"
  fi
}

# ---------------------------------------------------------------- integrity and persistence

tel_stat() { # FILE -> "mode uid mtime size" or empty
  stat -c '%a %u %Y %s' -- "$1" 2>/dev/null || stat -f '%Lp %u %m %z' -- "$1" 2>/dev/null || true
}

tel_integrity_one() { # PATH(display) REAL_PATH
  local shown="$1" real="$2" st mode uid mtime size sha
  [[ -f "${real}" ]] || return 0
  st="$(tel_stat "${real}")"
  if [[ -r "${real}" ]]; then
    sha="$(bo_sha256_file "${real}" 2>/dev/null || true)"
  else
    sha=""
  fi
  IFS=$' \t' read -r mode uid mtime size <<<"${st}"
  local toks=("path=${shown}" "mode=${mode:-?}" "+uid=${uid:-x}" "+size=${size:-x}" "+mtime=${mtime:-x}")
  if [[ -n "${sha}" ]]; then toks+=("sha256=${sha}"); else toks+=("?sha256"); fi
  tel_rec integrity "" "integrity:${shown}" file "${shown}" "sha256" "" "${toks[@]}"
  TEL_INTEG_N=$((TEL_INTEG_N + 1))
  [[ -z "${sha}" ]] && TEL_INTEG_UNREAD=$((TEL_INTEG_UNREAD + 1))
  return 0
}

collect_integrity() {
  TEL_INTEG_N=0
  TEL_INTEG_UNREAD=0
  local p f u uid home
  # Account, privilege, login, scheduling and name-resolution files. Secrets (shadow files, private
  # keys) are deliberately excluded - a hash of them is not needed to detect tampering of the rest.
  for p in /etc/passwd /etc/group /etc/sudoers /etc/ssh/sshd_config /etc/ld.so.preload /etc/crontab /etc/rc.local /etc/hosts /etc/resolv.conf /etc/environment /etc/profile /etc/bash.bashrc; do
    tel_integrity_one "${p}" "$(bo_path "${p}")"
  done
  for f in "$(bo_path /etc/sudoers.d)"/* "$(bo_path /etc/pam.d)"/* "$(bo_path /etc/cron.d)"/* "$(bo_path /etc/ssh/sshd_config.d)"/*; do
    tel_integrity_one "${f#"$(bo_root)"}" "${f}"
  done
  while IFS=$'\t' read -r u uid home; do
    tel_integrity_one "${home#"$(bo_root)"}/.ssh/authorized_keys" "${home}/.ssh/authorized_keys"
  done < <(bo_homes)
  if ((TEL_INTEG_UNREAD > 0)); then
    tel_cov integrity partial "${TEL_INTEG_UNREAD} file(s) exist but were unreadable, so no hash was taken (run as root)"
  else
    tel_cov integrity complete "fixed list of ${TEL_INTEG_N} sensitive file(s) present; absent files are simply not listed"
  fi
}

collect_persistence() {
  local f line v n=0 u uid home
  f="$(bo_path /etc/ld.so.preload)"
  if [[ -r "${f}" ]]; then
    v="$(grep -v '^[[:space:]]*#' "${f}" 2>/dev/null | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
    if [[ -n "${v}" ]]; then
      tel_trunc "${v}" 400
      tel_rec persistence "" "persist:ld_preload" file "/etc/ld.so.preload" "file-parse" "" "mechanism=ld_preload" "location=/etc/ld.so.preload" "value=${REPLY}"
      n=$((n + 1))
    fi
  fi
  f="$(bo_path /etc/rc.local)"
  if [[ -r "${f}" ]]; then
    v="$(grep -v '^[[:space:]]*\(#\|$\|exit\)' "${f}" 2>/dev/null | tr '\n' ';' | tel_clean_stream)"
    if [[ -n "${v}" ]]; then
      tel_trunc "${v}" 400
      tel_rec persistence "" "persist:rc_local" file "/etc/rc.local" "file-parse" "" "mechanism=rc_local" "location=/etc/rc.local" "value=${REPLY}"
      n=$((n + 1))
    fi
  fi
  for f in "$(bo_path /etc/profile.d)"/*.sh; do
    [[ -f "${f}" ]] || continue
    local shown="${f#"$(bo_root)"}"
    v="$(grep -v '^[[:space:]]*\(#\|$\)' "${f}" 2>/dev/null | head -n 3 | tr '\n' ';' | tel_clean_stream || true)"
    tel_trunc "${v}" 300
    tel_rec persistence "" "persist:profile:${shown}" file "${shown}" "file-parse" "" "mechanism=profile_script" "location=${shown}" "value=${REPLY}"
    n=$((n + 1))
  done
  while IFS=$'\t' read -r u uid home; do
    for f in "${home}/.config/autostart"/*.desktop; do
      [[ -f "${f}" ]] || continue
      local shown="${f#"$(bo_root)"}"
      v="$(sed -n 's/^Exec=//p' "${f}" 2>/dev/null | head -n 1 | tel_clean_stream)"
      tel_trunc "${v}" 300
      tel_rec persistence "" "persist:autostart:${shown}" file "${shown}" "file-parse" "" "mechanism=autostart" "location=${shown}" "value=${REPLY}" "user=${u}"
      n=$((n + 1))
    done
    f="${home}/.ssh/authorized_keys"
    if [[ -r "${f}" ]]; then
      local keys opts
      keys="$(grep -c -v '^[[:space:]]*\(#\|$\)' "${f}" 2>/dev/null || true)"
      opts="$(grep -c '^[[:space:]]*\(command=\|no-\|from=\|environment=\)' "${f}" 2>/dev/null || true)"
      # Key material is never read into the output: only the count and whether options are used.
      tel_rec persistence "" "persist:authkeys:${u}" file "${f#"$(bo_root)"}" "file-parse" "" "mechanism=authorized_key" "location=${f#"$(bo_root)"}" "value=${keys:-0} key(s); ${opts:-0} with options" "user=${u}"
      n=$((n + 1))
    fi
  done < <(bo_homes)
  tel_cov persistence complete "selected locations only: ld.so.preload, rc.local, profile.d, XDG autostart, authorized_keys; cron/systemd are in scheduled_task/service"
}

# ---------------------------------------------------------------- main

tel_run_section() { # FUNCTION CATEGORY... : one failing section never stops the others
  local fn="$1" c
  shift
  local want=false
  for c in "$@"; do tel_wants "${c}" && want=true; done
  ${want} || return 0
  if ! "${fn}"; then
    tel_err SECTION_FAILED "${fn} failed unexpectedly" "$1"
    for c in "$@"; do
      [[ -z "${TEL_COV_STATE[${c}]:-}" ]] && tel_cov "${c}" partial "collector section failed"
    done
  fi
}

tel_cleanup() {
  [[ -n "${TEL_TMP}" && -d "${TEL_TMP}" ]] && rm -rf -- "${TEL_TMP}"
  return 0
}

main() {
  tel_parse_args "$@" || exit 2
  TEL_TMP="$(mktemp -d "${TMPDIR:-/tmp}/blueops-tel.XXXXXX")" || {
    echo "cannot create a temporary directory" >&2
    exit 3
  }
  chmod 700 "${TEL_TMP}"
  trap tel_cleanup EXIT
  umask 077
  TEL_NOW="$(bo_now_utc)"
  local host name ver arch elev=false tm="" cid
  host="$(bo_hostname)"
  name="$(bo_osrel NAME)"
  ver="$(bo_osrel VERSION_ID)"
  arch="$(uname -m 2>/dev/null || echo unknown)"
  bo_is_root && elev=true
  cid="tel-$(bo_stamp)-$$"
  tel_line "{\"type\":\"header\",\"schema_version\":\"1.0.0\",\"collector\":{\"name\":\"blueops-linux-telemetry\",\"version\":\"${TEL_VERSION}\"},\"host\":{\"hostname\":$(bo_json_str "${host}"),\"os\":{\"family\":\"linux\",\"name\":$(bo_json_str "${name:-unknown}"),\"version\":$(bo_json_str "${ver:-unknown}")},\"arch\":$(bo_json_str "${arch}")},\"collection\":{\"id\":\"${cid}\",\"started_at\":\"${TEL_NOW}\",\"elevated\":${elev}}}"
  if [[ -n "${BO_TEST_HOOKS_IGNORED}" ]]; then
    tel_err TEST_HOOKS_IGNORED "test hooks were ignored because BO_TEST_MODE is not 1: ${BO_TEST_HOOKS_IGNORED}"
  fi
  if [[ -n "${BO_ROOT:-}${BO_FORCE_MISSING_TOOLS:-}" ]]; then
    tm="fixture hooks (BO_ROOT / BO_FORCE_MISSING_TOOLS) were active: this is not a real host"
    tel_err TEST_MODE "${tm}"
  fi
  if ! bo_is_root; then
    tel_err NOT_PRIVILEGED "running without root: sources readable only by root are reported as gaps in the coverage lines"
  fi
  tel_run_section collect_process process
  tel_run_section collect_user user
  tel_run_section collect_group group
  tel_run_section collect_session session
  tel_run_section collect_service service
  tel_run_section collect_scheduled_task scheduled_task
  tel_run_section collect_network network_connection listener
  tel_run_section collect_auth_event auth_event
  tel_run_section collect_security_event security_event config_change
  tel_run_section collect_system_config system_config
  tel_run_section collect_integrity integrity
  tel_run_section collect_persistence persistence
  local gaps=0 c
  for c in "${!TEL_COV_STATE[@]}"; do
    [[ "${TEL_COV_STATE[${c}]}" != complete ]] && gaps=1
  done
  tel_line "{\"type\":\"end\",\"ended_at\":\"$(bo_now_utc)\",\"records\":${TEL_COUNT}}"
  exit $((gaps ? 6 : 0))
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
