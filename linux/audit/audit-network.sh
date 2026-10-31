#!/usr/bin/env bash
# Module: network - listeners, established connections, routes, DNS, interfaces.
# Category: audit. Safety: read-only (ss/netstat/ip or /proc/net fallbacks).
# Usage: audit-network.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

# Normalized rows: proto<TAB>address<TAB>port<TAB>peer<TAB>process
_net_ss_awk='
  function addr(s,   i) { i = match(s, /:[^:]*$/); return substr(s, 1, i-1) }
  function port(s,   i) { i = match(s, /:[^:]*$/); return substr(s, i+1) }
  function clean(a) { gsub(/^\[|\]$/, "", a); sub(/%.*/, "", a); return a }
  function proc(line,   p, n) {
    n = "-"
    if (match(line, /users:\(\("[^"]*"/)) { n = substr(line, RSTART+9, RLENGTH-10) }
    if (match(line, /pid=[0-9]+/)) { n = n "/" substr(line, RSTART+4, RLENGTH-4) }
    return n
  }'

_net_listeners() {
  local pf="" f
  if bo_have ss; then
    ss -tulnp 2>/dev/null | awk "${_net_ss_awk}"'
      NR > 1 && ($1 == "tcp" || $1 == "udp") { printf "%s\t%s\t%s\t%s\t%s\n", $1, clean(addr($5)), port($5), $6, proc($0) }'
    return 0
  fi
  if bo_have netstat; then
    netstat -tulnp 2>/dev/null | awk "${_net_ss_awk}"'
      $1 ~ /^(tcp|udp)6?$/ { p=$1; sub(/6$/, "", p); last=$NF; printf "%s\t%s\t%s\t%s\t%s\n", p, clean(addr($4)), port($4), $5, (last ~ /[0-9]+\// ? last : "-") }'
    return 0
  fi
  bo_error TOOL_MISSING "neither ss nor netstat found; using /proc/net (no process names)" "NET-LISTEN-001" 0
  for pf in tcp tcp6 udp udp6; do
    f="$(bo_path /proc/net/${pf})"
    [[ -r "${f}" ]] || continue
    _net_procfs "${pf}" "${f}" listen
  done
}

# Hex address from /proc/net/{tcp,udp}[6] as text. IPv4 is one 32-bit word; IPv6 is four 32-bit
# words, each printed in host byte order (little-endian assumed, as on x86 and arm64), so the
# bytes of every word are reversed. The result is the compressed form `ss` prints (RFC 5952:
# lower case, the longest run of two or more zero groups becomes `::`), so a record keeps the
# same key whichever tool produced it. IPv4-mapped addresses print as ::ffff:a.b.c.d.
_net_hexaddr() {
  local h="$1" w v i
  local -a g=()
  if ((${#h} == 8)); then
    printf '%d.%d.%d.%d' "$((16#${h:6:2}))" "$((16#${h:4:2}))" "$((16#${h:2:2}))" "$((16#${h:0:2}))"
    return 0
  fi
  if [[ ! "${h}" =~ ^[0-9A-Fa-f]{32}$ ]]; then
    printf 'ipv6:%s' "${h}"
    return 0
  fi
  for ((w = 0; w < 4; w++)); do
    v="${h:w*8:8}"
    g+=("$((16#${v:6:2}${v:4:2}))" "$((16#${v:2:2}${v:0:2}))")
  done
  if ((g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0xffff)); then
    printf '::ffff:%d.%d.%d.%d' "$((g[6] >> 8))" "$((g[6] & 255))" "$((g[7] >> 8))" "$((g[7] & 255))"
    return 0
  fi
  local best=-1 bestlen=0 cur=-1 curlen=0
  for ((i = 0; i < 8; i++)); do
    if ((g[i] == 0)); then
      if ((cur < 0)); then
        cur=${i}
        curlen=0
      fi
      curlen=$((curlen + 1))
      if ((curlen > bestlen)); then
        best=${cur}
        bestlen=${curlen}
      fi
    else
      cur=-1
      curlen=0
    fi
  done
  local out="" sep=""
  if ((bestlen < 2)); then best=-1; fi
  for ((i = 0; i < 8; i++)); do
    if ((best >= 0 && i == best)); then
      out+="::"
      i=$((best + bestlen - 1))
      sep=""
      continue
    fi
    out+="${sep}$(printf '%x' "${g[i]}")"
    sep=":"
  done
  printf '%s' "${out}"
}

# _net_procfs NAME FILE listen|estab
_net_procfs() {
  local name="$1" file="$2" mode="$3" proto la ra st
  proto="${name%6}"
  tail -n +2 -- "${file}" | while IFS=' ' read -r _ la ra st _; do
    if [[ "${mode}" == "listen" ]]; then
      if [[ "${proto}" == "tcp" && "${st}" != "0A" ]]; then continue; fi
      if [[ "${proto}" == "udp" && "${st}" != "07" ]]; then continue; fi
    else
      [[ "${st}" == "01" ]] || continue
    fi
    printf '%s\t%s\t%d\t%s:%d\t-\n' "${proto}" "$(_net_hexaddr "${la%%:*}")" "$((16#${la##*:}))" "$(_net_hexaddr "${ra%%:*}")" "$((16#${ra##*:}))"
  done
}

_net_established() {
  local pf f
  if bo_have ss; then
    ss -tnp 2>/dev/null | awk "${_net_ss_awk}"'
      NR > 1 && $1 == "ESTAB" { printf "tcp\t%s\t%s\t%s\t%s\n", clean(addr($4)), port($4), $5, proc($0) }'
    return 0
  fi
  if bo_have netstat; then
    netstat -tnp 2>/dev/null | awk "${_net_ss_awk}"'
      $6 == "ESTABLISHED" { last=$NF; printf "tcp\t%s\t%s\t%s\t%s\n", clean(addr($4)), port($4), $5, (last ~ /[0-9]+\// ? last : "-") }'
    return 0
  fi
  for pf in tcp tcp6; do
    f="$(bo_path /proc/net/${pf})"
    [[ -r "${f}" ]] && _net_procfs "${pf}" "${f}" estab
  done
}

# 127.0.0.0/8, ::1 and IPv4-mapped 127.0.0.0/8 (::ffff:127.x.x.x); nothing else counts as loopback.
_net_is_loopback() { [[ "$1" == 127.* || "$1" == "::1" || "$1" == "localhost" || "$1" == ::ffff:127.* ]]; }

_net_listen_check() {
  local tsv="${BO_SCRATCH}/listen.tsv" proto addr port peer proc pname
  _net_listeners >"${tsv}" || true
  local -a inv=() legacy=() exposed=() shells=()
  local n=0 unknown_proc=0 inv_proc
  while IFS=$'\t' read -r proto addr port peer proc; do
    n=$((n + 1))
    inv+=("network|${proto} ${addr}:${port}|process ${proc}")
    pname="${proc%%/*}"
    # Listeners are keyed by protocol, bind address and port; the owner is a compared attribute
    # (unknown without root) and its pid is volatile.
    inv_proc="${pname}"
    if [[ -z "${pname}" || "${pname}" == "-" ]]; then
      inv_proc="@unknown"
      unknown_proc=$((unknown_proc + 1))
    fi
    bo_inv listeners "" "listener:${proto}/${addr}/${port}" "proto=${proto}" "bind=${addr}" "port=${port}" "process=${inv_proc}" "~pid=${proc#*/}"
    case "${pname}" in sh | bash | dash | zsh | nc | ncat | netcat | socat | python* | perl | ruby | php) shells+=("network|${proto} ${addr}:${port}|process ${proc}") ;; *) ;; esac
    _net_is_loopback "${addr}" && continue
    case "${port}" in
      21 | 23 | 69 | 512 | 513 | 514 | 2375) legacy+=("network|${proto} ${addr}:${port}|process ${proc}; $(_net_port_name "${port}")") ;;
      3306 | 5432 | 6379 | 11211 | 27017 | 9200 | 5984 | 1433 | 1521 | 2049 | 5900 | 5901 | 6000 | 445 | 139 | 3389)
        exposed+=("network|${proto} ${addr}:${port}|process ${proc}; $(_net_port_name "${port}")")
        ;;
      *) ;;
    esac
  done <"${tsv}"
  if ! bo_have ss && ! bo_have netstat && [[ ! -r "$(bo_path /proc/net/tcp)" ]]; then
    bo_cov listeners "" unavailable "no ss, netstat or /proc/net/tcp"
  elif ((unknown_proc > 0)); then
    bo_cov listeners "" degraded "${unknown_proc} listener(s) without a visible owning process (needs root, or ss/netstat missing)"
  else
    bo_cov listeners "" complete
  fi
  bo_finding NET-LISTEN-001 info high network "Listening sockets" "${n} listening TCP/UDP socket(s). Process names need root; '-' means unknown." "" "" ${inv[@]+"${inv[@]}"}
  ((${#legacy[@]} > 0)) && bo_finding NET-EXPOSE-001 high medium network "Cleartext or unauthenticated admin service reachable on the network" \
    "Legacy services (ftp, telnet, tftp, r-services, Docker TCP API) listening on a non-loopback address." \
    "If not required (check scored services first), disable the unit or bind to loopback." "T1021" "${legacy[@]}"
  ((${#exposed[@]} > 0)) && bo_finding NET-EXPOSE-002 medium low network "Database, cache, file-sharing or remote-desktop port exposed" \
    "Data stores and remote-access services are listening beyond loopback." \
    "Restrict with bind addresses or firewall rules where the service is not meant to be remote." "T1190" "${exposed[@]}"
  ((${#shells[@]} > 0)) && bo_finding NET-LISTEN-002 high medium network "Listener owned by a shell, netcat or script interpreter" \
    "Generic interpreters listening on a socket are a common bind-shell/backdoor pattern." \
    "Identify the owning process and its parent; preserve evidence before termination." "T1059" "${shells[@]}"
  return 0
}

_net_port_name() {
  case "$1" in
    21) echo ftp ;; 23) echo telnet ;; 69) echo tftp ;; 512 | 513 | 514) echo r-services ;; 2375) echo docker-api ;;
    3306) echo mysql ;; 5432) echo postgresql ;; 6379) echo redis ;; 11211) echo memcached ;; 27017) echo mongodb ;;
    9200) echo elasticsearch ;; 5984) echo couchdb ;; 1433) echo mssql ;; 1521) echo oracle ;; 2049) echo nfs ;;
    5900 | 5901) echo vnc ;; 6000) echo x11 ;; 445 | 139) echo smb ;; 3389) echo rdp ;; *) echo "port $1" ;;
  esac
}

_net_estab_check() {
  local tsv="${BO_SCRATCH}/estab.tsv" proto addr port peer proc pname rport
  _net_established >"${tsv}" || true
  local -a inv=() rev=() oddport=()
  local n=0
  while IFS=$'\t' read -r proto addr port peer proc; do
    n=$((n + 1))
    inv+=("network|${addr}:${port} -> ${peer}|process ${proc}")
    pname="${proc%%/*}"
    rport="${peer##*:}"
    _net_is_loopback "${addr}" && continue
    case "${pname}" in sh | bash | dash | zsh | nc | ncat | netcat | socat) rev+=("network|${addr}:${port} -> ${peer}|process ${proc}") ;; *) ;; esac
    case "${rport}" in 4444 | 4445 | 1337 | 31337 | 6667) oddport+=("network|${addr}:${port} -> ${peer}|process ${proc}") ;; *) ;; esac
  done <"${tsv}"
  bo_finding NET-ESTAB-001 info high network "Established TCP connections" "${n} established connection(s)." "" "" ${inv[@]+"${inv[@]}"}
  ((${#rev[@]} > 0)) && bo_finding NET-ESTAB-002 high medium network "Shell or netcat process with an established connection" \
    "An interactive shell or netcat/socat holding a network connection is characteristic of a reverse shell." \
    "Identify the process tree and remote peer; preserve evidence before containment." "T1059.004" "${rev[@]}"
  ((${#oddport[@]} > 0)) && bo_finding NET-ESTAB-003 medium low network "Connection to a port commonly used by remote-access tooling" \
    "Remote ports 4444, 4445, 1337, 31337 and 6667 are frequent in default listeners and IRC bots; may be benign." \
    "Check the owning process and destination." "T1571" "${oddport[@]}"
  return 0
}

_net_route_check() {
  local out="" f fwd="" v
  if bo_have ip; then
    out="$(ip route show 2>/dev/null || true)"
  elif bo_have route; then
    out="$(route -n 2>/dev/null || true)"
  elif [[ -r "$(bo_path /proc/net/route)" ]]; then
    bo_error TOOL_MISSING "ip/route not found; routes decoded from /proc/net/route" "NET-ROUTE-001" 0
    out="$(tail -n +2 "$(bo_path /proc/net/route)" | while read -r iface dest gwy _ _ _ _ mask _; do
      printf '%s dest=%s gw=%s mask=%s\n' "${iface}" "$(_net_hexaddr "${dest}")" "$(_net_hexaddr "${gwy}")" "$(_net_hexaddr "${mask}")"
    done)"
  else
    bo_error TOOL_MISSING "no way to read the routing table (ip, route, /proc/net/route)" "NET-ROUTE-001"
  fi
  if [[ -n "${out}" ]]; then
    local -a ev=()
    while IFS= read -r v; do ev+=("command|route|${v}"); done <<<"${out}"
    bo_finding NET-ROUTE-001 info high network "Routing table" "${#ev[@]} route entries." "" "" "${ev[@]}"
    if ! grep -q -E '^default|^0\.0\.0\.0|dest=0\.0\.0\.0' <<<"${out}"; then
      bo_finding NET-ROUTE-002 info medium network "No default route" "The host has no default route; it may be isolated or misconfigured." "" "" "command|route"
    fi
  fi
  for f in /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv6/conf/all/forwarding; do
    [[ -e "$(bo_path "${f}")" ]] || continue # absent (e.g. IPv6 disabled) is not a coverage gap
    if [[ ! -r "$(bo_path "${f}")" ]]; then
      bo_cov config sysctl partial "${f} not readable"
      continue
    fi
    v="$(head -n 1 -- "$(bo_path "${f}")")"
    bo_inv config sysctl "config:sysctl:$(tr / . <<<"${f#/proc/sys/}")" "value=${v}" "^file=${f}"
    [[ "${v}" == "1" ]] && fwd+="${f} "
  done
  # Kernel hardening values compared by BO-CFG-002 (inventory) and judged by NET-SYSCTL-001
  # (standing state). They sit outside the forwarding loop above, where a value of 1 would mean
  # "enabled". An absent file (feature not built in) is not a coverage gap.
  local -a weak=()
  local sysf
  for sysf in kernel/randomize_va_space kernel/kptr_restrict kernel/yama/ptrace_scope kernel/dmesg_restrict kernel/modules_disabled fs/suid_dumpable; do
    f="/proc/sys/${sysf}"
    [[ -e "$(bo_path "${f}")" ]] || continue
    if [[ ! -r "$(bo_path "${f}")" ]]; then
      bo_cov config sysctl partial "${f} not readable"
      continue
    fi
    v="$(head -n 1 -- "$(bo_path "${f}")")"
    bo_inv config sysctl "config:sysctl:$(tr / . <<<"${sysf}")" "value=${v}" "^file=${f}"
    case "${sysf}:${v}" in
      kernel/randomize_va_space:0 | kernel/randomize_va_space:1) weak+=("file|${f}|ASLR level ${v} (2 = full randomisation)") ;;
      kernel/kptr_restrict:0) weak+=("file|${f}|kernel pointers are exposed to unprivileged users (kptr_restrict=0)") ;;
      kernel/yama/ptrace_scope:0) weak+=("file|${f}|any process may ptrace another of the same user (ptrace_scope=0)") ;;
      fs/suid_dumpable:1) weak+=("file|${f}|set-UID programs may write readable core dumps (suid_dumpable=1)") ;;
      *) ;;
    esac
  done
  bo_cov config sysctl complete
  ((${#weak[@]} > 0)) && bo_finding NET-SYSCTL-001 low medium network "Kernel hardening setting at a weak value" \
    "Settings that raise the cost of local privilege escalation and information leaks are at their weakest value. Some are intentionally relaxed for debugging or specific software." \
    "Raise them with sysctl after checking nothing on the host depends on the weak value." "T1068" "${weak[@]}"
  [[ -n "${fwd}" ]] && bo_finding NET-FWD-001 low medium network "IP forwarding enabled" \
    "Forwarding is expected on routers, VPN and container hosts but not on ordinary servers." \
    "Disable with sysctl if the host is not a router (check container/VPN use first)." "" "file|${fwd%% *}"
  return 0
}

_net_dns_check() {
  local rc hosts ns search extra mode
  rc="$(bo_path /etc/resolv.conf)"
  if [[ -r "${rc}" ]]; then
    ns="$(awk '$1=="nameserver" {printf "%s ", $2}' "${rc}")"
    search="$(awk '$1=="search" || $1=="domain" {$1=""; printf "%s ", $0}' "${rc}")"
    bo_inv config dns "config:dns:resolv.conf" "nameservers[]=$(tr -s ' ' ',' <<<"${ns% }")" "search[]=$(tr -s ' ' ',' <<<"$(printf '%s' "${search}" | sed 's/^ *//;s/ *$//')")" "^file=/etc/resolv.conf"
    bo_cov config dns complete
    bo_finding NET-DNS-001 info high network "DNS configuration" "nameservers: ${ns% }; search: $(printf '%s' "${search}" | tr -s ' ' | sed 's/^ //;s/ $//')" "" "" "file|/etc/resolv.conf"
    [[ -n "${ns}" ]] || bo_finding NET-DNS-002 low medium network "No DNS nameserver configured" \
      "resolv.conf lists no nameserver (may be managed by a local stub resolver)." "Verify name resolution works." "" "file|/etc/resolv.conf"
  else
    bo_error RESOLV_UNREADABLE "/etc/resolv.conf not readable; DNS settings missing" "NET-DNS-001" 0
    bo_cov config dns unavailable "/etc/resolv.conf not readable"
  fi
  hosts="$(bo_path /etc/hosts)"
  if [[ -r "${hosts}" ]]; then
    local -a ev=()
    local self
    self="$(bo_hostname)"
    # Container runtimes and installers add an entry for the host's own name; ignore those.
    while IFS= read -r extra; do
      ev+=("file|/etc/hosts|${extra}")
      bo_inv config hosts "config:hosts:$(bo_hash_id "${extra}")" "entry=${extra}" "^file=/etc/hosts"
    done < <(awk -v self="${self}" '!/^[[:space:]]*#/ && NF >= 2 && $1 !~ /^(127\.|::1$|fe00::|ff0[0-9]::)/ { own = 0; for (i = 2; i <= NF; i++) if ($i == self) own = 1; if (!own) print }' "${hosts}" | tr -s ' \t' ' ')
    bo_cov config hosts complete
    ((${#ev[@]} > 0)) && bo_finding NET-HOSTS-001 low medium network "Non-loopback entries in /etc/hosts" \
      "Static host entries override DNS and can redirect update or authentication domains." "Verify each entry is intended." "T1565.001" "${ev[@]}"
    mode="$(bo_mode "${hosts}" || true)"
    if [[ -n "${mode}" ]] && bo_mode_has "${mode}" 022; then
      bo_finding NET-HOSTS-002 medium high network "/etc/hosts writable by non-root" "Mode ${mode}." "chmod 0644 /etc/hosts" "T1565.001" "file|/etc/hosts|mode ${mode}"
    fi
  else
    bo_cov config hosts unavailable "/etc/hosts not readable"
  fi
  return 0
}

_net_iface_check() {
  local out="" v d
  local -a ev=()
  if bo_have ip; then
    out="$(ip -o addr show 2>/dev/null | awk '{print $2 " " $3 " " $4}' || true)"
  elif bo_have ifconfig; then
    out="$(ifconfig -a 2>/dev/null | awk '/^[a-z0-9]/ {i=$1} /inet6? / {print i " " $1 " " $2}' || true)"
  elif [[ -d "$(bo_path /sys/class/net)" ]]; then
    bo_error TOOL_MISSING "ip/ifconfig not found; interface names only (from /sys/class/net)" "NET-IFACE-001" 0
    for d in "$(bo_path /sys/class/net)"/*; do out+="${d##*/}"$'\n'; done
  else
    bo_error TOOL_MISSING "cannot enumerate interfaces" "NET-IFACE-001"
    return 0
  fi
  while IFS= read -r v; do [[ -n "${v}" ]] && ev+=("command|interface|${v}"); done <<<"${out}"
  bo_finding NET-IFACE-001 info high network "Network interfaces" "${#ev[@]} address entries." "" "" ${ev[@]+"${ev[@]}"}
}

# sshd_config: the first occurrence of a keyword wins (OpenSSH), Include is expanded in place, and
# keywords inside a Match block are conditional and are not part of the effective global value.
_net_sshd_collect() { # prints "keyword<TAB>value<TAB>file" for global directives, in effect order
  local f="$1" line kw val inmatch=0 inc g rel
  local -a incs=()
  [[ -r "${f}" ]] || return 0
  rel="$(bo_unroot "${f}")"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -n "${line}" ]] || continue
    kw="${line%%[[:space:]=]*}"
    val="${line#"${kw}"}"
    val="${val#"${val%%[![:space:]=]*}"}"
    val="${val#=}"
    val="${val#"${val%%[![:space:]]*}"}"
    kw="${kw,,}"
    if [[ "${kw}" == match ]]; then
      inmatch=1
      continue
    fi
    ((inmatch)) && continue
    if [[ "${kw}" == include ]]; then
      IFS=' ' read -r -a incs <<<"${val}"
      for inc in ${incs[@]+"${incs[@]}"}; do
        [[ "${inc}" == /* ]] || inc="/etc/ssh/${inc}"
        # shellcheck disable=SC2231 # the include value is an intentional glob
        for g in $(bo_path "${inc}"); do [[ -f "${g}" ]] && _net_sshd_collect "${g}"; done
      done
      continue
    fi
    printf '%s\t%s\t%s\n' "${kw}" "${val}" "${rel}"
  done <"${f}"
}

_net_sshd_check() {
  local main tsv="${BO_SCRATCH}/sshd.tsv" kw val file seen=" "
  main="$(bo_path /etc/ssh/sshd_config)"
  if [[ ! -e "${main}" ]]; then
    bo_cov config sshd complete # no sshd configuration: nothing to inventory
    return 0
  fi
  if [[ ! -r "${main}" ]]; then
    bo_perm_error "/etc/ssh/sshd_config not readable; sshd settings skipped" "NET-SSHD-001"
    bo_cov config sshd partial "/etc/ssh/sshd_config not readable"
    return 0
  fi
  _net_sshd_collect "${main}" >"${tsv}"
  local -a bad=() info=()
  while IFS=$'\t' read -r kw val file; do
    [[ "${seen}" == *" ${kw} "* ]] && continue # first occurrence wins
    seen+="${kw} "
    case "${kw}" in
      permitrootlogin | permitemptypasswords | passwordauthentication | pubkeyauthentication | permituserenvironment | authorizedkeysfile | authorizedkeyscommand | authorizedkeyscommanduser | allowtcpforwarding | gatewayports | x11forwarding | usepam | challengeresponseauthentication | kbdinteractiveauthentication | hostbasedauthentication | ignorerhosts | permittunnel | forcecommand | banner) ;;
      *) continue ;;
    esac
    bo_inv config sshd "config:sshd:${kw}" "value=$(printf '%s' "${val}" | bo_redact)" "^file=${file}"
    info+=("file|${file}|${kw} ${val}")
    case "${kw}:${val,,}" in
      permitrootlogin:yes) bad+=("file|${file}|PermitRootLogin yes allows direct root login with a password") ;;
      permitemptypasswords:yes) bad+=("file|${file}|PermitEmptyPasswords yes allows accounts with empty passwords to log in") ;;
      permituserenvironment:no) ;;
      permituserenvironment:*) bad+=("file|${file}|PermitUserEnvironment ${val} lets users inject environment variables (for example LD_PRELOAD) through ~/.ssh/environment or authorized_keys") ;;
      hostbasedauthentication:yes) bad+=("file|${file}|HostbasedAuthentication yes trusts the connecting host") ;;
      authorizedkeysfile:*)
        # Anything other than the per-user files under the home directory redirects where keys are read from.
        [[ "${val}" =~ ^(\.ssh/authorized_keys2?|%h/\.ssh/authorized_keys2?)( (\.ssh/authorized_keys2?|%h/\.ssh/authorized_keys2?))*$ || "${val,,}" == "none" ]] \
          || bad+=("file|${file}|AuthorizedKeysFile ${val} reads keys from a non-default location")
        ;;
      authorizedkeyscommand:*) [[ -n "${val}" && "${val,,}" != none ]] && bad+=("file|${file}|AuthorizedKeysCommand ${val} runs a program to decide who may log in") ;;
      *) ;;
    esac
  done <"${tsv}"
  bo_cov config sshd complete
  bo_finding NET-SSHD-001 info high network "sshd effective settings (global scope)" \
    "${#info[@]} security-relevant sshd directive(s); first occurrence wins, Include is expanded, Match blocks are not evaluated." "" "" ${info[@]+"${info[@]}"}
  ((${#bad[@]} > 0)) && bo_finding NET-SSHD-002 high medium network "sshd setting that weakens authentication or hides key sources" \
    "These directives allow passwordless or direct-root logins, inject user environment, or read authorised keys from places an attacker can control." \
    "Review each setting; restore the distribution default after preserving the file, and check scored services still log in." "T1098.004" "${bad[@]}"
  return 0
}

# Host firewall state, read-only. `iptables -S` can make the kernel load ip_tables (and `nft` the
# nf_tables module), which would be a state change: they are run only when the module is already
# loaded. Needs root to read the rules; unprivileged runs record a coverage gap, never a result.
_net_firewall_check() {
  local out rules policy
  local -a t=()
  bo_have timeout && t=(timeout 10)
  if [[ -r "$(bo_path /proc/net/ip_tables_names)" ]] && bo_have iptables; then
    if out="$("${t[@]+"${t[@]}"}" iptables -S 2>/dev/null)" && [[ -n "${out}" ]]; then
      rules="$(grep -c -E '^-A ' <<<"${out}" || true)"
      policy="$(sed -n 's/^-P INPUT //p' <<<"${out}" | head -n 1)"
      bo_inv config firewall "config:firewall:linux-iptables" "policy_input=${policy:-@unknown}" "rules=${rules}" "sha256=$(bo_sha256_str "${out}" || echo @unknown)"
      bo_finding NET-FW-001 info medium network "Host firewall (iptables)" "INPUT policy ${policy:-unknown}, ${rules} rule(s)." "" "" "command|iptables -S"
      if [[ "${policy}" == ACCEPT && "${rules}" == 0 ]]; then
        bo_finding NET-FW-002 medium medium network "Host firewall allows everything inbound" \
          "iptables has no rules and its INPUT policy is ACCEPT." "Add rules for the services that must be reachable; confirm scored ports first." "T1562.004" "command|iptables -S"
      fi
      bo_cov config firewall complete
    else
      bo_perm_error "iptables -S returned nothing (needs root); firewall state unknown" "NET-FW-001"
      bo_cov config firewall partial "iptables rules could not be read"
    fi
  elif [[ -r "$(bo_path /proc/modules)" ]] && grep -q '^nf_tables ' "$(bo_path /proc/modules)" && bo_have nft; then
    if out="$("${t[@]+"${t[@]}"}" nft list ruleset 2>/dev/null)" && [[ -n "${out}" ]]; then
      rules="$(grep -c -E '^[[:space:]]+(ip|ip6|tcp|udp|iif|iifname|ct|meta|counter|accept|drop|reject|jump|log)[ ;]' <<<"${out}" || true)"
      policy="$(grep -E 'hook input' <<<"${out}" | sed -n 's/.*policy \([a-z]*\).*/\1/p' | head -n 1 | tr '[:lower:]' '[:upper:]')"
      bo_inv config firewall "config:firewall:linux-nft" "policy_input=${policy:-@unknown}" "rules=${rules}" "sha256=$(bo_sha256_str "${out}" || echo @unknown)"
      bo_finding NET-FW-001 info medium network "Host firewall (nftables)" "INPUT policy ${policy:-unknown}, ${rules} rule line(s)." "" "" "command|nft list ruleset"
      bo_cov config firewall complete
    else
      bo_perm_error "nft list ruleset returned nothing (needs root); firewall state unknown" "NET-FW-001"
      bo_cov config firewall partial "nftables ruleset could not be read"
    fi
  else
    bo_cov config firewall complete # no packet-filter module loaded or no tool: nothing to read
  fi
  return 0
}

mod_network() {
  _net_listen_check
  _net_estab_check
  _net_route_check
  _net_dns_check
  _net_iface_check
  _net_sshd_check
  _net_firewall_check
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-network audit network 0 "$@" || rc=$?
  exit "${rc}"
fi
