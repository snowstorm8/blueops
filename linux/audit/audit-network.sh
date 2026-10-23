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

_net_hexaddr() {
  local h="$1"
  if ((${#h} == 8)); then
    printf '%d.%d.%d.%d' "$((16#${h:6:2}))" "$((16#${h:4:2}))" "$((16#${h:2:2}))" "$((16#${h:0:2}))"
  elif [[ "${h}" == "00000000000000000000000000000000" ]]; then
    printf '::'
  elif [[ "${h}" == "00000000000000000000000001000000" ]]; then
    printf '::1'
  else
    printf 'ipv6:%s' "${h}"
  fi
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

_net_is_loopback() { [[ "$1" == 127.* || "$1" == "::1" || "$1" == "localhost" ]]; }

_net_listen_check() {
  local tsv="${BO_SCRATCH}/listen.tsv" proto addr port peer proc pname
  _net_listeners >"${tsv}" || true
  local -a inv=() legacy=() exposed=() shells=()
  local n=0
  while IFS=$'\t' read -r proto addr port peer proc; do
    n=$((n + 1))
    inv+=("network|${proto} ${addr}:${port}|process ${proc}")
    pname="${proc%%/*}"
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
    [[ -r "$(bo_path "${f}")" ]] || continue
    v="$(head -n 1 -- "$(bo_path "${f}")")"
    [[ "${v}" == "1" ]] && fwd+="${f} "
  done
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
    bo_finding NET-DNS-001 info high network "DNS configuration" "nameservers: ${ns% }; search: $(printf '%s' "${search}" | tr -s ' ' | sed 's/^ //;s/ $//')" "" "" "file|/etc/resolv.conf"
    [[ -n "${ns}" ]] || bo_finding NET-DNS-002 low medium network "No DNS nameserver configured" \
      "resolv.conf lists no nameserver (may be managed by a local stub resolver)." "Verify name resolution works." "" "file|/etc/resolv.conf"
  else
    bo_error RESOLV_UNREADABLE "/etc/resolv.conf not readable; DNS settings missing" "NET-DNS-001" 0
  fi
  hosts="$(bo_path /etc/hosts)"
  if [[ -r "${hosts}" ]]; then
    local -a ev=()
    local self
    self="$(bo_hostname)"
    # Container runtimes and installers add an entry for the host's own name; ignore those.
    while IFS= read -r extra; do ev+=("file|/etc/hosts|${extra}"); done < <(awk -v self="${self}" '!/^[[:space:]]*#/ && NF >= 2 && $1 !~ /^(127\.|::1$|fe00::|ff0[0-9]::)/ { own = 0; for (i = 2; i <= NF; i++) if ($i == self) own = 1; if (!own) print }' "${hosts}" | tr -s ' \t' ' ')
    ((${#ev[@]} > 0)) && bo_finding NET-HOSTS-001 low medium network "Non-loopback entries in /etc/hosts" \
      "Static host entries override DNS and can redirect update or authentication domains." "Verify each entry is intended." "T1565.001" "${ev[@]}"
    mode="$(bo_mode "${hosts}" || true)"
    if [[ -n "${mode}" ]] && bo_mode_has "${mode}" 022; then
      bo_finding NET-HOSTS-002 medium high network "/etc/hosts writable by non-root" "Mode ${mode}." "chmod 0644 /etc/hosts" "T1565.001" "file|/etc/hosts|mode ${mode}"
    fi
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

mod_network() {
  _net_listen_check
  _net_estab_check
  _net_route_check
  _net_dns_check
  _net_iface_check
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-network audit network 0 "$@" || rc=$?
  exit "${rc}"
fi
