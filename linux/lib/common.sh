#!/usr/bin/env bash
# BlueOps Linux shared helpers (sourced only; no top-level side effects).
#
# Provides: logging, finding/error recording, JSON emission, CLI driver, and
# small portable utilities used by linux/audit and linux/persistence modules.
#
# Test hooks (not for production use):
#   BO_ROOT                    prefix applied to every file path read (fixture root)
#   BO_FORCE_MISSING_TOOLS     space-separated tool names treated as not installed
# shellcheck shell=bash

[[ -n "${BO_COMMON_LOADED:-}" ]] && return 0
BO_COMMON_LOADED=1

BO_VERSION="0.1.0"
BO_SCHEMA_VERSION="0.2.0"
BO_LINUX_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BO_ALL_MODULES="system users pam processes network services persistence filesystem"

BO_SCRATCH=""
BO_QUIET=0
BO_VERBOSE=0
BO_COLOR=0
BO_MAX_EVIDENCE=100
BO_RECENT_DAYS=3
export BO_PKG_CHECK=0 # set by --package-integrity; read by audit-filesystem.sh
BO_FS_PATHS=()

# ---------------------------------------------------------------- utilities

bo_now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
bo_stamp() { date -u +%Y%m%dT%H%M%SZ; }

# Map an absolute path into the (optional) fixture root.
bo_root() {
  local r="${BO_ROOT:-}"
  printf '%s' "${r%/}"
}
bo_path() { printf '%s%s' "$(bo_root)" "$1"; }
# Strip the fixture root prefix for display.
bo_unroot() {
  local p="$1"
  if [[ -n "${BO_ROOT:-}" ]]; then p="${p#"$(bo_root)"}"; fi
  printf '%s' "${p:-/}"
}

bo_have() {
  local t IFS=' '
  for t in ${BO_FORCE_MISSING_TOOLS:-}; do
    [[ "${t}" == "$1" ]] && return 1
  done
  command -v -- "$1" >/dev/null 2>&1
}

# Fail early and actionably when a command the collectors cannot work without is missing.
# Never installs anything; the fix is the separate setup step.
bo_preflight_deps() {
  local tool="$1" f="${BO_LINUX_DIR}/lib/deps.sh"
  [[ -r "${f}" ]] || return 0
  # shellcheck source=linux/lib/deps.sh
  source "${f}"
  bo_deps_scan
  if [[ -n "${BO_DEPS_MISSING_REQ}" ]]; then
    echo "${tool}: required command(s) not found: ${BO_DEPS_MISSING_REQ}" >&2
    echo "${tool}: run './blueops doctor' to see everything missing, then 'sudo ${BO_LINUX_DIR}/../scripts/setup/setup-linux.sh --install' (asks before changing anything)." >&2
    return 1
  fi
  return 0
}

bo_is_root() { [[ "$(id -u 2>/dev/null || echo 1)" == "0" ]]; }

# Octal mode of a path (GNU stat, then BSD stat).
bo_mode() {
  local m
  m="$(stat -c '%a' -- "$1" 2>/dev/null)" || m="$(stat -f '%Lp' -- "$1" 2>/dev/null)" || return 1
  printf '%s' "${m}"
}

# True when mode (octal string) has any of the given octal bits set.
bo_mode_has() {
  local mode="$1" bits="$2"
  [[ "${mode}" =~ ^[0-7]+$ ]] || return 1
  (((8#${mode} & 8#${bits}) != 0))
}

# Value of KEY from /etc/os-release (never sourced; parsed as data).
bo_osrel() {
  local f
  f="$(bo_path /etc/os-release)"
  [[ -r "${f}" ]] || f="$(bo_path /usr/lib/os-release)"
  [[ -r "${f}" ]] || return 0
  sed -n "s/^$1=//p" "${f}" | head -n 1 | tr -d "\"'"
}

# Redact obvious secrets from command lines before they reach any output.
bo_redact() {
  local key='([Pp][Aa][Ss][Ss]([Ww][Oo][Rr][Dd]|[Ww][Dd])?|[Pp][Ww][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Aa][Pp][Ii][-_]?[Kk][Ee][Yy])'
  sed -E \
    -e "s/(${key}[A-Za-z_]*[=:][[:space:]]*)[^[:space:]\"']+/\\1<redacted>/g" \
    -e "s/(--[A-Za-z-]*(pass|secret|token|key)[A-Za-z-]*[ =])[^[:space:]]+/\\1<redacted>/g"
}

# Print reasons (semicolon separated) if a command line matches known-bad patterns.
bo_suspicious_reasons() {
  local s="$1" r=""
  if [[ "${s}" =~ /dev/(tcp|udp)/ ]]; then r+="bash /dev/tcp redirect (reverse-shell pattern); "; fi
  if [[ "${s}" =~ (^|[^[:alnum:]_])(nc|ncat|netcat|socat)[[:space:]].*(-e[[:space:]]|-c[[:space:]]|EXEC:|exec:) ]]; then
    r+="netcat/socat with command execution; "
  fi
  if [[ "${s}" =~ (curl|wget)[^|]*\|[[:space:]]*(sudo[[:space:]]+)?(ba|z|da|k)?sh ]]; then r+="download piped to shell; "; fi
  if [[ "${s}" =~ base64[[:space:]]+(-d|--decode).*\|[[:space:]]*(ba|z|da)?sh ]]; then r+="decoded payload piped to shell; "; fi
  if [[ "${s}" =~ (python[0-9.]*|perl|ruby|php)[[:space:]]+-[ecr][[:space:]].*(socket|fsockopen) ]]; then r+="scripted socket shell; "; fi
  if [[ "${s}" =~ (/tmp|/var/tmp|/dev/shm)/ ]]; then
    # Benign mentions of these directories are removed before testing:
    #  - housekeeping commands that name a path but do not execute it (rm, ls, chmod ...);
    #    "find ... -exec CMD" keeps CMD, and cp/mv/tar are deliberately NOT exempt (staging).
    #  - standard X11/ICE socket paths, but only in test brackets ([ -S /tmp/.X11-unix/X0 ])
    #    or ICEAUTHORITY/XAUTHORITY assignments, never as a command or script argument.
    local t x='(\.X11-unix|\.ICE-unix|\.font-unix|\.XIM-unix|\.Test-unix)' b='\[\[?[[:space:]]+(![[:space:]]+)?-[SdefLrwx][[:space:]]+["'"'"']?'
    t="$(printf '%s' "${s}" | sed -E \
      -e 's#find[[:space:]][^;&|]*-exec(dir)?[[:space:]]+# #g' \
      -e "s#(${b})/tmp/${x}(/[A-Za-z0-9_-]+)?#\\1X11-RUNTIME#g" \
      -e "s#(${b})/tmp/\\.X[0-9]+-lock#\\1X11-RUNTIME#g" \
      -e "s#(ICEAUTHORITY|XAUTHORITY)=[\"']?/tmp/${x}(/[A-Za-z0-9_-]+)?#\\1=X11-RUNTIME#g" \
      -e 's/(^|[^[:alnum:]_.-])(rm|rmdir|find|ls|cat|touch|du|echo|tail|head|grep|stat|mkdir|chmod|chown|test|tmpreaper|tmpwatch|systemd-tmpfiles)[[:space:]][^;&|]*//g')"
    if [[ "${t}" =~ (^|[[:space:]=\"\'])(/tmp|/var/tmp|/dev/shm)/ ]]; then r+="references world-writable directory; "; fi
  fi
  if [[ "${s}" =~ chmod[[:space:]]+([ugoa]*\+s|[0-7]*[4267][0-7]{3}) ]]; then r+="sets setuid/setgid bit; "; fi
  if [[ "${s}" =~ alias[[:space:]]+(sudo|su|ssh|passwd)= ]]; then r+="aliases a privileged command; "; fi
  if [[ "${s}" =~ (^|[[:space:];])(export[[:space:]]+)?LD_PRELOAD= ]]; then r+="sets LD_PRELOAD; "; fi
  printf '%s' "${r%; }"
}

# ------------------------------------------------------------------ logging

bo_log() {
  local level="$1"
  shift
  local line
  line="$(bo_now_utc) ${level} ${BO_TOOL:-blueops}/${BO_MODULE:-main} $*"
  [[ -n "${BO_SCRATCH}" ]] && printf '%s\n' "${line}" >>"${BO_SCRATCH}/run.log"
  case "${level}" in
    ERROR | WARN) ((BO_QUIET)) || printf '%s\n' "${line}" >&2 ;;
    INFO) ((BO_VERBOSE)) && printf '%s\n' "${line}" >&2 ;;
    DEBUG) ((BO_VERBOSE > 1)) && printf '%s\n' "${line}" >&2 ;;
    *) ;;
  esac
  return 0
}

# ---------------------------------------------------------------- JSON/state

# _bo_jq STRING : JSON-quote STRING into REPLY without a subshell (hot path for inventory).
_bo_jq() {
  local s="${1-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  s="${s//$'\r'/\\r}"
  if [[ "${s}" =~ [^[:print:]] ]]; then
    s="$(printf '%s' "${s}" | LC_ALL=C tr -c '\040-\176' '?')"
  fi
  REPLY="\"${s}\""
}

bo_json_str() {
  _bo_jq "${1-}"
  printf '%s' "${REPLY}"
}

bo_init_scratch() {
  BO_SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/blueops.XXXXXX")" || return 1
  chmod 700 "${BO_SCRATCH}"
  : >"${BO_SCRATCH}/findings.jsonl"
  : >"${BO_SCRATCH}/errors.jsonl"
  : >"${BO_SCRATCH}/inventory.jsonl"
  : >"${BO_SCRATCH}/coverage.jsonl"
  : >"${BO_SCRATCH}/errors.txt"
  : >"${BO_SCRATCH}/human.txt"
  : >"${BO_SCRATCH}/sev.log"
  : >"${BO_SCRATCH}/material.log"
  : >"${BO_SCRATCH}/run.log"
}

bo_cleanup() {
  if [[ -n "${BO_SCRATCH}" && -d "${BO_SCRATCH}" ]]; then rm -rf -- "${BO_SCRATCH}"; fi
  return 0
}

# ---------------------------------------------------------------- inventory
# Structured records for offline baseline comparison (docs/baseline-diff.md). Keys must
# be stable between runs: never put pids, ephemeral ports or free text in a key.

# bo_sha256_file FILE / bo_sha256_str STRING : print the hex digest, or fail if no tool exists.
bo_sha256_file() {
  local h
  if bo_have sha256sum; then
    h="$(sha256sum -- "$1" 2>/dev/null)" || return 1
  elif bo_have shasum; then
    h="$(shasum -a 256 -- "$1" 2>/dev/null)" || return 1
  elif bo_have openssl; then
    h="$(openssl dgst -sha256 -- "$1" 2>/dev/null | sed 's/.*= //')" || return 1
  else
    return 1
  fi
  [[ "${h%% *}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "${h%% *}"
}

bo_sha256_str() {
  local h
  if bo_have sha256sum; then
    h="$(printf '%s' "$1" | sha256sum 2>/dev/null)" || return 1
  elif bo_have shasum; then
    h="$(printf '%s' "$1" | shasum -a 256 2>/dev/null)" || return 1
  elif bo_have openssl; then
    h="$(printf '%s' "$1" | openssl dgst -sha256 2>/dev/null | sed 's/.*= //')" || return 1
  else
    return 1
  fi
  [[ "${h%% *}" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s' "${h%% *}"
}

# bo_hash_id STRING [LENGTH] : short stable identifier for a record key. SHA-256 when a tool
# exists, otherwise the POSIX cksum (prefixed "ck", so a key never silently changes meaning).
bo_hash_id() {
  local h len="${2:-16}"
  if h="$(bo_sha256_str "$1")"; then
    printf '%s' "${h:0:len}"
  else
    printf 'ck%s' "$(printf '%s' "$1" | cksum | awk '{ print $1 "-" $2 }')"
  fi
}

# NAME=VALUE -> "NAME":"VALUE"; NAME[]=A,B -> "NAME":["A","B"]; VALUE @unknown -> null.
# Result goes to _BO_PAIR (no subshell; this runs once per attribute of every record).
_bo_inv_pair() {
  local tok="$1" name val item items="" qname
  name="${tok%%=*}"
  val=""
  [[ "${tok}" == *=* ]] && val="${tok#*=}"
  if [[ "${name}" == *'[]' ]]; then
    name="${name%'[]'}"
    _bo_jq "${name}"
    qname="${REPLY}"
    local IFS=,
    for item in ${val}; do
      _bo_jq "${item}"
      items+="${items:+,}${REPLY}"
    done
    _BO_PAIR="${qname}:[${items}]"
  elif [[ "${val}" == "@unknown" ]]; then
    _bo_jq "${name}"
    _BO_PAIR="${REPLY}:null"
  else
    _bo_jq "${name}"
    qname="${REPLY}"
    _bo_jq "${val}"
    _BO_PAIR="${qname}:${REPLY}"
  fi
}

# bo_inv DOMAIN SCOPE KEY [TOKEN...]
#   NAME=VALUE      attribute that is compared (a value of @unknown means "not collectable")
#   NAME[]=A,B,C    attribute that is a set of strings
#   ~NAME=VALUE     volatile context that is shown but never compared (pids, command lines)
#   ^TYPE=REF       supporting evidence (file, registry, ...)
bo_inv() {
  local domain="$1" scope="$2" key="$3" tok attrs="" vol="" ev="" type ref line qd qk
  shift 3
  for tok in "$@"; do
    case "${tok}" in
      '^'*)
        type="${tok#^}"
        ref="${type#*=}"
        type="${type%%=*}"
        _bo_jq "${type}"
        ev+="${ev:+,}{\"type\":${REPLY}"
        _bo_jq "${ref}"
        ev+=",\"ref\":${REPLY}}"
        ;;
      '~'*)
        _bo_inv_pair "${tok#\~}"
        vol+="${vol:+,}${_BO_PAIR}"
        ;;
      *)
        _bo_inv_pair "${tok}"
        attrs+="${attrs:+,}${_BO_PAIR}"
        ;;
    esac
  done
  _bo_jq "${domain}"
  qd="${REPLY}"
  _bo_jq "${key}"
  qk="${REPLY}"
  # One write per record so a crash can never leave a torn line in the report.
  line="{\"domain\":${qd},\"key\":${qk},\"attrs\":{${attrs}}"
  if [[ -n "${scope}" ]]; then
    _bo_jq "${scope}"
    line+=",\"scope\":${REPLY}"
  fi
  [[ -n "${vol}" ]] && line+=",\"volatile\":{${vol}}"
  [[ -n "${ev}" ]] && line+=",\"evidence\":[${ev}]"
  printf '%s}\n' "${line}" >>"${BO_SCRATCH}/inventory.jsonl"
  return 0
}

# bo_cov DOMAIN SCOPE STATUS [REASON]
# STATUS: complete | degraded (all records, some attributes unknown) | partial | unavailable.
# Several calls for one partition are merged by the comparison engine (worst status wins),
# so a module can report a problem where it happens and "complete" at the end.
bo_cov() {
  local j
  j="{\"domain\":$(bo_json_str "$1")"
  [[ -n "$2" ]] && j+=",\"scope\":$(bo_json_str "$2")"
  j+=",\"status\":$(bo_json_str "$3")"
  [[ -n "${4-}" ]] && j+=",\"reason\":$(bo_json_str "$4")"
  printf '%s}\n' "${j}" >>"${BO_SCRATCH}/coverage.jsonl"
  return 0
}

# Inventory partitions (domain/scope) each module owns, used to mark them when a module aborts.
bo_module_partitions() {
  case "$1" in
    users) echo "users: groups: persistence:ssh-authkeys config:sudoers" ;;
    processes) echo "processes:" ;;
    network) echo "listeners: config:dns config:hosts config:sysctl" ;;
    services) echo "services:" ;;
    persistence) echo "persistence:systemd persistence:startup persistence:udev persistence:apt persistence:shell persistence:autostart scheduled_tasks:cron scheduled_tasks:at" ;;
    pam) echo "config:pam" ;;
    filesystem) echo "config:suid" ;;
    *) echo "" ;;
  esac
}

bo_cov_module() { # MODULE STATUS REASON
  local p IFS=' '
  for p in $(bo_module_partitions "$1"); do bo_cov "${p%%:*}" "${p#*:}" "$2" "$3"; done
}

bo_section() { printf '\n== %s ==\n' "$1" >>"${BO_SCRATCH}/human.txt"; }
bo_human() { printf '%s\n' "$@" >>"${BO_SCRATCH}/human.txt"; }

# bo_error CODE MESSAGE [CHECK_ID] [MATERIAL=1]
# Records a coverage gap. Non-material gaps are listed but do not force exit 6.
bo_error() {
  local code="$1" msg="$2" check="${3-}" material="${4-1}" j
  j="{\"code\":$(bo_json_str "${code}"),\"message\":$(bo_json_str "${msg}")"
  [[ -n "${check}" ]] && j+=",\"check_id\":$(bo_json_str "${check}")"
  printf '%s}\n' "${j}" >>"${BO_SCRATCH}/errors.jsonl"
  printf '%s: %s\n' "${code}" "${msg}" >>"${BO_SCRATCH}/errors.txt"
  [[ "${material}" == "1" ]] && echo "${code}" >>"${BO_SCRATCH}/material.log"
  bo_log WARN "${code}: ${msg}"
  return 0
}

# Permission problems are expected (non-material) when not running as root.
bo_perm_error() {
  local mat=1
  bo_is_root || mat=0
  bo_error PERM_DENIED "$1" "${2-}" "${mat}"
}

# bo_finding ID SEVERITY CONFIDENCE CATEGORY TITLE DESCRIPTION REMEDIATION MITRE_CSV [TYPE|REF[|EXCERPT]...]
bo_finding() {
  local id="$1" sev="$2" conf="$3" cat="$4" title="$5" desc="$6" rem="$7" mitre="$8"
  shift 8
  local n=$# total=$# ev="" item type rest ref exc count=0 m human_ev=""
  for item in "$@"; do
    ((count >= BO_MAX_EVIDENCE)) && break
    type="${item%%|*}"
    rest="${item#*|}"
    ref="${rest%%|*}"
    exc=""
    [[ "${rest}" == *"|"* ]] && exc="${rest#*|}"
    [[ -n "${ev}" ]] && ev+=","
    ev+="{\"type\":$(bo_json_str "${type}"),\"ref\":$(bo_json_str "${ref}")"
    [[ -n "${exc}" ]] && ev+=",\"excerpt\":$(bo_json_str "${exc:0:1900}")"
    ev+="}"
    ((count < 10)) && human_ev+="      - ${ref}${exc:+  (${exc:0:120})}"$'\n'
    count=$((count + 1))
  done
  if ((total > count)); then
    desc+=" [${total} items; only the first ${count} are listed]"
  fi
  local j
  j="{\"id\":$(bo_json_str "${id}"),\"title\":$(bo_json_str "${title}"),\"severity\":$(bo_json_str "${sev}"),\"confidence\":$(bo_json_str "${conf}"),\"category\":$(bo_json_str "${cat}"),\"description\":$(bo_json_str "${desc}")"
  ((n > 0)) && j+=",\"evidence\":[${ev}]"
  [[ -n "${rem}" ]] && j+=",\"remediation\":$(bo_json_str "${rem}")"
  if [[ -n "${mitre}" ]]; then
    local ml=""
    local IFS=,
    for m in ${mitre}; do ml+="${ml:+,}$(bo_json_str "${m}")"; done
    j+=",\"mitre_attack\":[${ml}]"
  fi
  printf '%s}\n' "${j}" >>"${BO_SCRATCH}/findings.jsonl"
  printf '%s\n' "${sev}" >>"${BO_SCRATCH}/sev.log"
  local tag
  tag="$(printf '%s' "${sev}" | tr '[:lower:]' '[:upper:]')"
  {
    if ((BO_COLOR)); then
      case "${sev}" in
        critical | high) printf '  \033[31m[%-8s]\033[0m %s  %s\n' "${tag}" "${id}" "${title}" ;;
        medium) printf '  \033[33m[%-8s]\033[0m %s  %s\n' "${tag}" "${id}" "${title}" ;;
        *) printf '  [%-8s] %s  %s\n' "${tag}" "${id}" "${title}" ;;
      esac
    else
      printf '  [%-8s] %s  %s\n' "${tag}" "${id}" "${title}"
    fi
    printf '      %s\n' "${desc}"
    printf '%s' "${human_ev}"
    ((count > 10)) && printf '      ... %d more (see JSON report)\n' "$((total - 10))"
    [[ -n "${rem}" && "${sev}" != "info" ]] && printf '      fix: %s\n' "${rem}"
  } >>"${BO_SCRATCH}/human.txt"
  return 0
}

bo_count_sev() { grep -c -x -- "$1" "${BO_SCRATCH}/sev.log" 2>/dev/null || true; }

# ------------------------------------------------------------ host/run info

bo_uuid() {
  local f
  f="$(bo_path /proc/sys/kernel/random/uuid)"
  if [[ -z "${BO_ROOT:-}" && -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  elif bo_have uuidgen; then
    uuidgen | tr '[:upper:]' '[:lower:]'
  else
    : "${f}"
    printf '%08x-%04x-4%03x-8%03x-%04x%08x\n' "$((RANDOM * RANDOM))" "${RANDOM}" "$((RANDOM % 4096))" "$((RANDOM % 4096))" "${RANDOM}" "$((RANDOM * RANDOM))"
  fi
}

bo_hostname() {
  local h="" f
  for f in /proc/sys/kernel/hostname /etc/hostname; do
    [[ -r "$(bo_path "${f}")" ]] && h="$(head -n 1 -- "$(bo_path "${f}")")" && [[ -n "${h}" ]] && break
  done
  if [[ -z "${h}" ]] && bo_have hostname; then h="$(hostname 2>/dev/null || true)"; fi
  printf '%s' "${h:-unknown}"
}

bo_host_json() {
  local name ver arch user elev=false
  name="$(bo_osrel NAME)"
  ver="$(bo_osrel VERSION_ID)"
  arch="$(uname -m 2>/dev/null || echo unknown)"
  user="$(id -un 2>/dev/null || echo unknown)"
  bo_is_root && elev=true
  printf '{"hostname":%s,"os":{"family":"linux","name":%s,"version":%s},"arch":%s,"user":%s,"elevated":%s}' \
    "$(bo_json_str "$(bo_hostname)")" "$(bo_json_str "${name:-unknown}")" "$(bo_json_str "${ver}")" \
    "$(bo_json_str "${arch}")" "$(bo_json_str "${user}")" "${elev}"
}

# Home directories from passwd: "user<TAB>uid<TAB>home" for existing dirs.
bo_homes() {
  local pw
  pw="$(bo_path /etc/passwd)"
  [[ -r "${pw}" ]] || return 0
  awk -F: -v root="$(bo_root)" '$6 != "" && $6 != "/" && $6 != "/nonexistent" { print $1 "\t" $3 "\t" root $6 }' "${pw}" \
    | while IFS=$'\t' read -r u uid h; do
      [[ -d "${h}" ]] && printf '%s\t%s\t%s\n' "${u}" "${uid}" "${h}"
    done
}

# ----------------------------------------------------------------- CLI driver

bo_usage() {
  local tool="$1" select="$2"
  cat <<EOF
Usage: ${tool} [options]

BlueOps ${tool} ${BO_VERSION} - READ-ONLY Linux host inspection.
For hosts you are authorized to administer. Makes no system changes
(writes only to --output-dir when given).

Options:
EOF
  if [[ "${select}" == "1" ]]; then
    cat <<EOF
  --modules LIST        comma-separated subset (default: all)
                        modules: ${BO_ALL_MODULES// /,}
  --list-modules        print available modules and exit
EOF
  fi
  cat <<'EOF'
  --json                emit JSON report on stdout (human text goes to stderr)
  --format text|json    same as above (default: text)
  --output-dir DIR      write report.json, report.txt, run.log to a new run dir in DIR
  --fail-on SEVERITY    lowest severity giving exit 4 (default: medium)
  --recent-days N       "recently modified" window for filesystem checks (default: 3)
  --fs-path DIR         restrict filesystem scans to DIR (repeatable)
  --package-integrity   also verify installed files against Debian package
                        checksums (dpkg --verify; read-only, can be slow)
  --quiet               suppress human output and warnings
  --verbose             log progress to stderr
  --no-color            disable ANSI colors
  --version             print version
  --help                show this help

Exit codes: 0 ok, 2 usage, 3 precondition failed, 4 findings at/above
--fail-on, 6 partial (coverage gaps; see errors[] in JSON).
EOF
}

bo_sev_rank() {
  case "$1" in info) echo 0 ;; low) echo 1 ;; medium) echo 2 ;; high) echo 3 ;; critical) echo 4 ;; *) echo -1 ;; esac
}

bo_valid_module() {
  local m IFS=' '
  for m in ${BO_ALL_MODULES}; do [[ "${m}" == "$1" ]] && return 0; done
  return 1
}

bo_module_file() {
  case "$1" in
    persistence) printf '%s/persistence/check-persistence.sh' "${BO_LINUX_DIR}" ;;
    *) printf '%s/audit/audit-%s.sh' "${BO_LINUX_DIR}" "$1" ;;
  esac
}

bo_module_title() {
  case "$1" in
    system) echo "System" ;;
    users) echo "Users and access" ;;
    pam) echo "PAM" ;;
    processes) echo "Processes" ;;
    network) echo "Network" ;;
    services) echo "Services" ;;
    persistence) echo "Persistence" ;;
    filesystem) echo "Filesystem" ;;
    *) echo "$1" ;;
  esac
}

# bo_cli_main TOOL CATEGORY DEFAULT_MODULES ALLOW_SELECT ARGS...
bo_cli_main() {
  local tool="$1" category="$2" modules="$3" select="$4"
  shift 4
  export LC_ALL=C
  BO_TOOL="${tool}"
  local format=text outdir="" fail_on=medium list=0 nocolor=0 arg
  while (($#)); do
    arg="$1"
    case "${arg}" in
      -h | --help)
        bo_usage "${tool}" "${select}"
        return 0
        ;;
      --version)
        echo "${tool} ${BO_VERSION}"
        return 0
        ;;
      --list-modules)
        [[ "${select}" == "1" ]] || {
          echo "${tool}: unknown option: ${arg}" >&2
          return 2
        }
        list=1
        ;;
      --modules | --format | --output-dir | --fail-on | --recent-days | --fs-path)
        if (($# < 2)) || [[ "$2" == --* ]]; then
          echo "${tool}: option ${arg} requires a value" >&2
          return 2
        fi
        case "${arg}" in
          --modules)
            [[ "${select}" == "1" ]] || {
              echo "${tool}: unknown option: ${arg}" >&2
              return 2
            }
            modules="$2"
            ;;
          --format) format="$2" ;;
          --output-dir) outdir="$2" ;;
          --fail-on) fail_on="$2" ;;
          --recent-days) BO_RECENT_DAYS="$2" ;;
          --fs-path) BO_FS_PATHS+=("$2") ;;
          *) ;;
        esac
        shift
        ;;
      --json) format=json ;;
      --package-integrity) BO_PKG_CHECK=1 ;;
      --quiet) BO_QUIET=1 ;;
      --verbose) BO_VERBOSE=1 ;;
      --no-color) nocolor=1 ;;
      *)
        echo "${tool}: unknown option: ${arg}" >&2
        return 2
        ;;
    esac
    shift
  done
  if ((list)); then
    printf '%s\n' "${BO_ALL_MODULES// /$'\n'}"
    return 0
  fi
  [[ "${format}" == "text" || "${format}" == "json" ]] || {
    echo "${tool}: --format must be text or json" >&2
    return 2
  }
  [[ "$(bo_sev_rank "${fail_on}")" -ge 0 ]] || {
    echo "${tool}: invalid --fail-on: ${fail_on}" >&2
    return 2
  }
  [[ "${BO_RECENT_DAYS}" =~ ^[1-9][0-9]{0,3}$ ]] || {
    echo "${tool}: --recent-days must be a positive integer" >&2
    return 2
  }
  local -a mods=()
  local m seen=" "
  local -a requested
  IFS=, read -r -a requested <<<"${modules}"
  for m in "${requested[@]}"; do
    [[ -z "${m}" ]] && continue
    if [[ "${modules}" == "all" ]]; then break; fi
    bo_valid_module "${m}" || {
      echo "${tool}: unknown module: ${m} (available: ${BO_ALL_MODULES// /,})" >&2
      return 2
    }
    [[ "${seen}" == *" ${m} "* ]] || {
      mods+=("${m}")
      seen+="${m} "
    }
  done
  if [[ "${modules}" == "all" ]]; then IFS=" " read -r -a mods <<<"${BO_ALL_MODULES}"; fi
  ((${#mods[@]} > 0)) || {
    echo "${tool}: no modules selected" >&2
    return 2
  }

  if [[ -z "${BO_ROOT:-}" ]] && [[ "$(uname -s 2>/dev/null)" != "Linux" ]]; then
    echo "${tool}: this tool supports Linux only (detected: $(uname -s 2>/dev/null || echo unknown))" >&2
    return 3
  fi
  bo_preflight_deps "${tool}" || return 3
  if [[ -n "${outdir}" && ! -d "${outdir}" ]]; then
    (umask 077 && mkdir -p -- "${outdir}") 2>/dev/null || {
      echo "${tool}: cannot create output dir: ${outdir}" >&2
      return 3
    }
  fi

  bo_init_scratch || return 1
  trap bo_cleanup EXIT
  local human_fd=1
  [[ "${format}" == "json" ]] && human_fd=2
  if [[ -z "${NO_COLOR:-}" && "${nocolor}" == 0 && -t "${human_fd}" ]]; then BO_COLOR=1; fi
  local started run_id
  started="$(bo_now_utc)"
  run_id="$(bo_uuid)"
  bo_is_root || bo_error NOT_ROOT "running unprivileged; coverage reduced (other users' files, process exe links, shadow, sudoers)" "" 0

  local src
  for m in "${mods[@]}"; do
    BO_MODULE="${m}"
    bo_log INFO "module start"
    if ! declare -F "mod_${m}" >/dev/null; then
      src="$(bo_module_file "${m}")"
      # shellcheck source=/dev/null
      if [[ -r "${src}" ]]; then source "${src}"; fi
    fi
    if ! declare -F "mod_${m}" >/dev/null; then
      bo_error MODULE_MISSING "module '${m}' not found" "${m}"
      bo_cov_module "${m}" unavailable "module not found"
      continue
    fi
    bo_section "$(bo_module_title "${m}")"
    # Run in a subshell so a crashing module cannot take down the others; the
    # marker file distinguishes "ran to the end" from "aborted midway".
    rm -f -- "${BO_SCRATCH}/done.${m}"
    (
      "mod_${m}" || true
      : >"${BO_SCRATCH}/done.${m}"
    ) || true
    if [[ ! -e "${BO_SCRATCH}/done.${m}" ]]; then
      bo_error MODULE_FAILED "module '${m}' aborted unexpectedly; results incomplete" "${m}"
      bo_cov_module "${m}" partial "module aborted unexpectedly"
    fi
    bo_log INFO "module end"
  done
  BO_MODULE=main

  local finished
  finished="$(bo_now_utc)"
  local n_info n_low n_med n_high n_crit total gate=0 s
  n_info="$(bo_count_sev info)"
  n_low="$(bo_count_sev low)"
  n_med="$(bo_count_sev medium)"
  n_high="$(bo_count_sev high)"
  n_crit="$(bo_count_sev critical)"
  total=$((n_info + n_low + n_med + n_high + n_crit))
  local min
  min="$(bo_sev_rank "${fail_on}")"
  for s in info low medium high critical; do
    if (($(bo_sev_rank "${s}") >= min)); then gate=$((gate + $(bo_count_sev "${s}"))); fi
  done
  local exit_code=0 mat
  mat="$(wc -l <"${BO_SCRATCH}/material.log" | tr -d ' ')"
  if ((gate > 0)); then
    exit_code=4
  elif ((mat > 0)); then
    exit_code=6
  fi

  local report="${BO_SCRATCH}/report.json"
  {
    printf '{\n"schema_version":%s,\n' "$(bo_json_str "${BO_SCHEMA_VERSION}")"
    printf '"tool":{"name":%s,"version":%s,"category":%s},\n' "$(bo_json_str "${tool}")" "$(bo_json_str "${BO_VERSION}")" "$(bo_json_str "${category}")"
    printf '"run":{"id":%s,"started_at":"%s","finished_at":"%s","mode":"read-only","dry_run":false,"exit_code":%d},\n' "$(bo_json_str "${run_id}")" "${started}" "${finished}" "${exit_code}"
    printf '"host":%s,\n' "$(bo_host_json)"
    printf '"findings":[\n'
    sed '$!s/$/,/' "${BO_SCRATCH}/findings.jsonl"
    printf '],\n"errors":[\n'
    sed '$!s/$/,/' "${BO_SCRATCH}/errors.jsonl"
    printf '],\n"inventory":{"coverage":[\n'
    sed '$!s/$/,/' "${BO_SCRATCH}/coverage.jsonl"
    printf '],"records":[\n'
    sed '$!s/$/,/' "${BO_SCRATCH}/inventory.jsonl"
    printf ']},\n"summary":{"total":%d,"by_severity":{"info":%d,"low":%d,"medium":%d,"high":%d,"critical":%d}}\n}\n' \
      "${total}" "${n_info}" "${n_low}" "${n_med}" "${n_high}" "${n_crit}"
  } >"${report}"

  local text="${BO_SCRATCH}/report.txt"
  {
    printf 'BlueOps %s %s - read-only audit for authorized hosts\n' "${tool}" "${BO_VERSION}"
    printf 'Host: %s  Run: %s  UTC: %s -> %s\n' "$(bo_hostname)" "${run_id}" "${started}" "${finished}"
    printf 'Findings: %d total (critical %d, high %d, medium %d, low %d, info %d)\n' \
      "${total}" "${n_crit}" "${n_high}" "${n_med}" "${n_low}" "${n_info}"
    cat "${BO_SCRATCH}/human.txt"
    if [[ -s "${BO_SCRATCH}/errors.txt" ]]; then
      printf '\n== Coverage gaps ==\n'
      sed 's/^/  /' "${BO_SCRATCH}/errors.txt"
    fi
    printf '\nExit code: %d\n' "${exit_code}"
  } >"${text}"

  if [[ -n "${outdir}" ]]; then
    local rd i=0
    rd="${outdir%/}/blueops-run-$(bo_stamp)-${tool}"
    while [[ -e "${rd}" ]]; do
      i=$((i + 1))
      rd="${outdir%/}/blueops-run-$(bo_stamp)-${tool}-${i}"
    done
    (umask 077 && mkdir -p -- "${rd}") || return 1
    chmod 700 "${rd}"
    (umask 077 && cp -- "${report}" "${rd}/report.json" && cp -- "${text}" "${rd}/report.txt" && cp -- "${BO_SCRATCH}/run.log" "${rd}/run.log")
    ((BO_QUIET)) || echo "Report written to ${rd}" >&2
  fi
  if [[ "${BO_QUIET}" == 0 ]]; then
    if [[ "${format}" == "json" ]]; then
      [[ -n "${outdir}" ]] || cat -- "${report}"
      [[ -n "${outdir}" ]] || cat -- "${text}" >&2
    else
      cat -- "${text}"
    fi
  elif [[ "${format}" == "json" && -z "${outdir}" ]]; then
    cat -- "${report}"
  fi
  return "${exit_code}"
}

# ---------------------------------------------------- find wrapper (scans)

# bo_find ARGS... : runs find, recording one coverage error if it complained.
bo_find() {
  local err="${BO_SCRATCH}/find.err" n
  find "$@" 2>"${err}" || true
  if [[ -s "${err}" ]]; then
    : >"${BO_SCRATCH}/find.failed"
    n="$(wc -l <"${err}" | tr -d ' ')"
    bo_perm_error "find reported ${n} error(s) (unreadable paths); results may be incomplete" "find"
  fi
  return 0
}

# True (and the marker is cleared) when a bo_find since the last check hit unreadable paths;
# callers use it to mark their inventory partition partial.
bo_find_failed() {
  if [[ -e "${BO_SCRATCH}/find.failed" ]]; then
    rm -f -- "${BO_SCRATCH}/find.failed"
    return 0
  fi
  return 1
}
