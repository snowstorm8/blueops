#!/usr/bin/env bash
# Module: processes - running processes, parent/child tree, executable paths.
# Category: audit. Safety: read-only (/proc, ps). Command lines are redacted.
# Usage: audit-processes.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

# Writes ${BO_SCRATCH}/procs.tsv: pid ppid user comm exe cmdline ("-" when unknown).
_prc_collect() {
  local out="${BO_SCRATCH}/procs.tsv" proc d pid line rest comm ppid uid exe cmd unreadable=0
  proc="$(bo_path /proc)"
  : >"${out}"
  if [[ -r "${proc}/self/stat" || -n "$(find "${proc}" -maxdepth 1 -name '[0-9]*' 2>/dev/null | head -n 1)" ]]; then
    awk -F: '{print $3 "\t" $1}' "$(bo_path /etc/passwd)" 2>/dev/null >"${BO_SCRATCH}/uidmap.tsv" || : >"${BO_SCRATCH}/uidmap.tsv"
    for d in "${proc}"/[0-9]*; do
      [[ -d "${d}" ]] || continue
      pid="${d##*/}"
      [[ -r "${d}/stat" ]] || continue
      line=""
      read -r line <"${d}/stat" 2>/dev/null || continue
      comm="${line#*(}"
      comm="${comm%)*}"
      rest="${line##*) }"
      ppid="$(printf '%s' "${rest}" | awk '{print $2}')"
      uid="$(awk '/^Uid:/ {print $2; exit}' "${d}/status" 2>/dev/null || true)"
      uid="${uid:--}"
      exe="$(readlink "${d}/exe" 2>/dev/null || true)"
      cmd="$(tr '\0' ' ' <"${d}/cmdline" 2>/dev/null | bo_redact || true)"
      cmd="${cmd%"${cmd##*[![:space:]]}"}"
      if [[ -z "${exe}" ]]; then
        exe="-"
        if [[ -n "${cmd}" ]]; then unreadable=$((unreadable + 1)); fi
      fi
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${pid}" "${ppid:--}" "${uid}" "${comm}" "${exe}" "${cmd:--}" >>"${out}"
    done
    # Resolve uid -> name.
    awk -F'\t' 'NR==FNR {if (!($1 in m)) m[$1]=$2; next} {$3 = ($3 in m) ? m[$3] : $3; print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6}' OFS='\t' \
      "${BO_SCRATCH}/uidmap.tsv" "${out}" >"${out}.tmp" && mv -- "${out}.tmp" "${out}"
    if ((unreadable > 0)); then
      bo_perm_error "${unreadable} process executable link(s) unreadable; exe-based checks skipped for them" "PRC-INFO-001"
    fi
    return 0
  fi
  if bo_have ps; then
    bo_error PROC_UNAVAILABLE "/proc not available; using ps (no executable paths)" "PRC-INFO-001" 0
    ps -eo pid=,ppid=,user=,comm=,args= 2>/dev/null \
      | awk '{ cmd=""; for (i=5;i<=NF;i++) cmd = cmd (i>5?" ":"") $i; printf "%s\t%s\t%s\t%s\t-\t%s\n", $1, $2, $3, $4, (cmd==""?"-":cmd) }' \
      | bo_redact >"${out}" || true
    return 0
  fi
  bo_error TOOL_MISSING "no /proc and no ps; process audit impossible" "PRC-INFO-001"
  return 1
}

_prc_tree() {
  awk -F'\t' -v max="$1" '
    { pid[NR]=$1; par[$1]=$2; lab[$1]=$1 " " $3 " " $4 ($5=="-" ? "" : " [" $5 "]"); kids[$2]=kids[$2] " " $1; n++ }
    function walk(p, depth,   a, i, c) {
      if (cnt >= max && max > 0) { trunc=1; return }
      printf "%*s%s\n", depth*2, "", lab[p]; cnt++
      c = split(kids[p], a, " ")
      for (i=1;i<=c;i++) walk(a[i], depth+1)
    }
    END { for (i=1;i<=n;i++) { p=pid[i]; if (!(par[p] in lab) || par[p]==p) walk(p, 0) }
          if (trunc) printf "... truncated at %d lines (use --verbose for the full tree; JSON has every process)\n", max }
  ' "${BO_SCRATCH}/procs.tsv"
}

mod_processes() {
  local tsv="${BO_SCRATCH}/procs.tsv"
  _prc_collect || return 0
  local total
  total="$(wc -l <"${tsv}" | tr -d ' ')"
  if ((total == 0)); then
    bo_error NO_PROCESSES "no processes could be enumerated" "PRC-INFO-001"
    return 0
  fi
  local pid ppid user comm exe cmd reasons
  local -a inv=() deleted=() tmpx=() hidden=() masq=() cmdl=() nonstd=()
  while IFS=$'\t' read -r pid ppid user comm exe cmd; do
    inv+=("process|pid=${pid}|ppid=${ppid} user=${user} comm=${comm} exe=${exe} cmd=${cmd:0:160}")
    # Kernel threads have no cmdline and (usually) no exe; skip exe checks for them.
    [[ "${cmd}" == "-" && "${exe}" == "-" ]] && continue
    if [[ "${cmd}" == "["* && "${exe}" != "-" ]]; then
      masq+=("process|pid=${pid}|user=${user} cmd=${cmd:0:120} exe=${exe}")
    fi
    [[ "${exe}" == "-" ]] && continue
    if [[ "${exe}" == *"(deleted)" || "${exe}" == /memfd:* ]]; then
      deleted+=("process|pid=${pid}|user=${user} exe=${exe}")
    elif [[ "${exe}" == /tmp/* || "${exe}" == /var/tmp/* || "${exe}" == /dev/shm/* ]]; then
      tmpx+=("process|pid=${pid}|user=${user} exe=${exe}")
    elif [[ "${exe}" == */.[!.]* ]]; then
      hidden+=("process|pid=${pid}|user=${user} exe=${exe}")
    else
      case "${exe}" in
        /usr/* | /bin/* | /sbin/* | /lib/* | /lib64/* | /opt/* | /snap/* | /nix/* | /app/* | /proc/*) ;;
        *) nonstd+=("process|pid=${pid}|user=${user} exe=${exe}") ;;
      esac
    fi
    reasons="$(bo_suspicious_reasons "${cmd}")"
    # Plain references to /tmp in a command line are common arguments; keep only strong patterns here.
    reasons="${reasons//references world-writable directory; /}"
    reasons="${reasons//references world-writable directory/}"
    [[ -n "${reasons}" ]] && cmdl+=("process|pid=${pid}|user=${user} ${reasons}: ${cmd:0:160}")
  done <"${tsv}"

  local save="${BO_MAX_EVIDENCE}"
  BO_MAX_EVIDENCE=500
  bo_finding PRC-INFO-001 info high processes "Process inventory" \
    "${total} processes. Evidence lists pid, parent pid, user, executable path and (redacted) command line." "" "" "${inv[@]}"
  BO_MAX_EVIDENCE="${save}"

  local max=80
  ((BO_VERBOSE)) && max=0
  bo_human "" "  Process tree (pid user comm [exe]):"
  _prc_tree "${max}" | sed 's/^/    /' >>"${BO_SCRATCH}/human.txt"

  ((${#deleted[@]} > 0)) && bo_finding PRC-DELETED-001 high high processes "Process running from a deleted or memory-backed executable" \
    "The on-disk binary was removed (or runs from memfd) after launch - typical of fileless or cleaned-up malware, but also of package upgrades without restart." \
    "Capture evidence (/proc/PID/exe copy, memory) before killing; compare with recent package updates." "T1620" "${deleted[@]}"
  ((${#tmpx[@]} > 0)) && bo_finding PRC-TMPEXE-001 high high processes "Process executing from a world-writable directory" \
    "Executables in /tmp, /var/tmp or /dev/shm are a common staging location for malware." \
    "Preserve the binary and its process state, then investigate parent and network activity." "T1036" "${tmpx[@]}"
  ((${#masq[@]} > 0)) && bo_finding PRC-MASQ-001 high medium processes "Process mimics a kernel thread name" \
    "Command line is bracketed like a kernel thread but the process has a user-space executable." \
    "Inspect the executable and parent process." "T1036.004" "${masq[@]}"
  ((${#cmdl[@]} > 0)) && bo_finding PRC-CMD-001 high medium processes "Suspicious command line" \
    "Command line matches reverse-shell, download-and-execute or similar patterns." \
    "Review the process, its parent, and its network connections." "T1059" "${cmdl[@]}"
  ((${#hidden[@]} > 0)) && bo_finding PRC-HIDDEN-001 medium low processes "Process running from a hidden directory" \
    "Executable path contains a dot-prefixed directory." "Verify the binary is expected." "T1564.001" "${hidden[@]}"
  ((${#nonstd[@]} > 0)) && bo_finding PRC-PATH-001 low low processes "Process executing outside standard program directories" \
    "Executable is outside /usr, /bin, /sbin, /lib, /opt and /snap." "Verify the binaries are expected." "" "${nonstd[@]}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-processes audit processes 0 "$@" || rc=$?
  exit "${rc}"
fi
