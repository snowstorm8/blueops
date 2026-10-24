#!/usr/bin/env bash
# Module: users - accounts, UID 0, sudo, sessions, SSH authorized keys.
# Category: audit. Safety: read-only. Never prints password hashes or key material.
# Usage: audit-users.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

_usr_is_nologin() {
  case "${1##*/}" in nologin | false | sync | shutdown | halt | "") return 0 ;; *) return 1 ;; esac
}

# Service accounts that legitimately keep a login shell, judged by account name
# AND its package-managed home directory (so a "postgres" account with a home
# elsewhere is still reported).
_usr_expected_shell() {
  case "$1:$2" in
    postgres:/var/lib/postgresql | postgres:/var/lib/postgresql/* | postgres:/var/lib/pgsql | postgres:/var/lib/pgsql/* | postgres:/var/lib/postgres | postgres:/var/lib/postgres/*) return 0 ;;
    *) return 1 ;;
  esac
}

_usr_accounts() {
  local pw
  pw="$(bo_path /etc/passwd)"
  if [[ ! -r "${pw}" ]]; then
    bo_error PASSWD_UNREADABLE "/etc/passwd not readable; account checks skipped" "USR-INFO-001"
    return 1
  fi
  # name uid gid home shell (tab separated; empty fields become "-")
  awk -F: 'NF >= 7 && $1 !~ /^[#+-]/ { print $1 "\t" $3 "\t" $4 "\t" ($6==""?"-":$6) "\t" ($7==""?"-":$7) }' "${pw}"
}

# Inventory records for accounts: identity and shell, plus the password *state* (never the hash).
_usr_inventory_accounts() {
  local shadow u uid gid home shell state
  shadow="$(bo_path /etc/shadow)"
  : >"${BO_SCRATCH}/shadow-state.tsv"
  if [[ -r "${shadow}" ]]; then
    awk -F: '{ s = "set"; if ($2 == "") s = "empty"; else if ($2 ~ /^[!*]/) s = "locked"; print $1 "\t" s }' "${shadow}" >"${BO_SCRATCH}/shadow-state.tsv"
  else
    bo_cov users "" degraded "/etc/shadow not readable; password state unknown"
  fi
  while IFS=$'\t' read -r u uid gid home shell; do
    state="$(awk -F'\t' -v u="${u}" '$1 == u { print $2; exit }' "${BO_SCRATCH}/shadow-state.tsv")"
    bo_inv users "" "user:${u}" "uid=${uid}" "gid=${gid}" "home=${home}" "shell=${shell}" "password=${state:-@unknown}" "^file=/etc/passwd"
  done <"${BO_SCRATCH}/accounts.tsv"
  bo_cov users "" complete
}

_usr_accounts_check() {
  local pw shadow n_total=0 n_login=0 login_list="" u uid home shell
  pw="$(bo_path /etc/passwd)"
  local expected=""
  local -a uid0=() sysshell=() hashed=() empty=()
  if ! _usr_accounts >"${BO_SCRATCH}/accounts.tsv"; then
    bo_cov users "" unavailable "/etc/passwd not readable"
    return 0
  fi
  _usr_inventory_accounts
  while IFS=$'\t' read -r u uid _ home shell; do
    n_total=$((n_total + 1))
    if ! _usr_is_nologin "${shell}"; then
      n_login=$((n_login + 1))
      login_list+="${u}(uid=${uid},${shell}) "
    fi
    if [[ "${uid}" == "0" && "${u}" != "root" ]]; then uid0+=("file|/etc/passwd|account '${u}' has UID 0"); fi
    if [[ "${uid}" =~ ^[0-9]+$ ]] && ((uid > 0 && uid < 1000)) && ! _usr_is_nologin "${shell}"; then
      if _usr_expected_shell "${u}" "${home#"$(bo_root)"}"; then
        expected+="${u} "
        continue
      fi
      case "${shell##*/}" in bash | sh | zsh | dash | ksh | fish | csh | tcsh | ash) sysshell+=("file|/etc/passwd|system account '${u}' (uid ${uid}) has interactive shell ${shell}") ;; *) ;; esac
    fi
  done <"${BO_SCRATCH}/accounts.tsv"
  # Legacy password hashes in passwd (field 2 not x/!/*); names only.
  while IFS= read -r u; do hashed+=("file|/etc/passwd|account '${u}' stores a password hash in /etc/passwd"); done < <(awk -F: 'NF>=7 && $2 != "x" && $2 != "!" && $2 != "*" && $2 != "" && $1 !~ /^[#+-]/ {print $1}' "${pw}")

  bo_finding USR-INFO-001 info high users "Account inventory" \
    "${n_total} accounts; ${n_login} with a login shell: ${login_list:-none}${expected:+; expected service-account shells not flagged: ${expected% }}" "" "" "file|/etc/passwd"

  if ((${#uid0[@]} > 0)); then
    bo_finding USR-UID0-001 critical high users "Non-root account with UID 0" \
      "Accounts other than 'root' have UID 0 and therefore full root privileges." \
      "Verify each account; if unauthorized, lock it (usermod -L) after capturing evidence." "T1136.001" "${uid0[@]}"
  fi
  local dups
  dups="$(awk -F'\t' '{c[$2]=c[$2] " " $1; n[$2]++} END {for (k in n) if (n[k] > 1) print k ":" c[k]}' "${BO_SCRATCH}/accounts.tsv" | sort)"
  if [[ -n "${dups}" ]]; then
    local -a dev=()
    while IFS= read -r u; do dev+=("file|/etc/passwd|duplicate UID ${u}"); done <<<"${dups}"
    bo_finding USR-DUPUID-001 medium high users "Accounts share a UID" \
      "Distinct account names map to the same UID, giving identical privileges." \
      "Confirm intent; reassign unauthorized duplicates." "T1136.001" "${dev[@]}"
  fi
  ((${#sysshell[@]} > 0)) && bo_finding USR-SHELL-001 medium medium users "System accounts with interactive shells" \
    "Service accounts normally use nologin/false; interactive shells enable direct logon." \
    "Set the shell to /usr/sbin/nologin unless the service requires it." "T1078.003" "${sysshell[@]}"
  ((${#hashed[@]} > 0)) && bo_finding USR-PWD-002 medium high users "Password hashes stored in world-readable /etc/passwd" \
    "Hashes in /etc/passwd are readable by every local user. Values are not shown here." \
    "Migrate to shadow passwords (pwconv)." "T1003.008" "${hashed[@]}"

  shadow="$(bo_path /etc/shadow)"
  if [[ -r "${shadow}" ]]; then
    while IFS= read -r u; do
      local sh
      sh="$(awk -F'\t' -v u="${u}" '$1==u {print $5}' "${BO_SCRATCH}/accounts.tsv")"
      _usr_is_nologin "${sh}" || empty+=("file|/etc/shadow|account '${u}' has an empty password field")
    done < <(awk -F: '$2 == "" {print $1}' "${shadow}")
    ((${#empty[@]} > 0)) && bo_finding USR-PWD-001 high high users "Login-capable account with empty password" \
      "Accounts with an empty password field may authenticate without a password (subject to PAM/sshd config)." \
      "Set a password or lock the account (passwd -l). Coordinate with scored-service credentials first." "T1078.003" "${empty[@]}"
  else
    bo_perm_error "/etc/shadow not readable; empty-password check skipped" "USR-PWD-001"
  fi
}

_usr_sudo_check() {
  local gf f line norm n=0 nopw=0
  local -a files=() nopasswd=() unsafe=() rules=() privgrp=() rootequiv=()
  for f in "$(bo_path /etc/sudoers)" "$(bo_path /etc/sudoers.d)"/*; do
    [[ -f "${f}" ]] || continue
    # sudo ignores sudoers.d entries whose names contain '.' or end in '~'.
    if [[ "${f}" == */sudoers.d/* && ("${f##*/}" == *.* || "${f##*/}" == *~) ]]; then continue; fi
    files+=("${f}")
  done
  if ((${#files[@]} == 0)); then
    [[ -e "$(bo_path /etc/sudoers)" ]] && bo_perm_error "/etc/sudoers not readable; sudo rules skipped" "USR-SUDO-001" && bo_cov config sudoers partial "/etc/sudoers not readable"
    [[ -e "$(bo_path /etc/sudoers)" ]] || bo_error SUDO_ABSENT "no /etc/sudoers present (sudo not installed?)" "USR-SUDO-001" 0
  fi
  for f in ${files[@]+"${files[@]}"}; do
    if [[ ! -r "${f}" ]]; then
      bo_perm_error "$(bo_unroot "${f}") not readable; sudo rules skipped" "USR-SUDO-001"
      bo_cov config sudoers partial "$(bo_unroot "${f}") not readable"
      continue
    fi
    local mode rel
    rel="$(bo_unroot "${f}")"
    mode="$(bo_mode "${f}" || true)"
    if [[ -n "${mode}" ]] && bo_mode_has "${mode}" 022; then
      unsafe+=("file|${rel}|mode ${mode} is writable by group/other")
    fi
    while IFS= read -r line; do
      line="${line%%#*}"
      [[ "${line}" =~ ^[[:space:]]*$ ]] && continue
      [[ "${line}" =~ ^[[:space:]]*(Defaults|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias|@include|#include) ]] && continue
      n=$((n + 1))
      norm="$(printf '%s' "${line}" | tr -s '[:space:]' ' ')"
      bo_inv config sudoers "config:sudoers:${rel}#$(bo_hash_id "${norm}")" "file=${rel}" "rule=$(printf '%s' "${norm}" | bo_redact)" "^file=${rel}"
      rules+=("file|${rel}|$(printf '%s' "${line}" | tr -s '[:space:]' ' ' | bo_redact)")
      if [[ "${line}" == *NOPASSWD* ]]; then
        nopw=$((nopw + 1))
        nopasswd+=("file|${rel}|$(printf '%s' "${line}" | tr -s '[:space:]' ' ')")
      fi
    done <"${f}"
  done
  if ((n > 0)); then
    bo_finding USR-SUDO-001 info high users "Sudo rules" "${n} rule line(s) across ${#files[@]} file(s)." "" "" "${rules[@]}"
  fi
  ((nopw > 0)) && bo_finding USR-SUDO-002 medium medium users "Sudo rules without password (NOPASSWD)" \
    "NOPASSWD grants privilege escalation to anyone able to run as those principals." \
    "Remove NOPASSWD unless required by a scored service." "T1548.003" "${nopasswd[@]}"
  ((${#unsafe[@]} > 0)) && bo_finding USR-SUDO-003 high high users "Sudoers file writable by non-root" \
    "Group/other-writable sudoers files allow privilege escalation." "chmod 0440 on the file after review." "T1548.003" "${unsafe[@]}"

  bo_cov config sudoers complete
  gf="$(bo_path /etc/group)"
  if [[ -r "${gf}" ]]; then
    local g gid members
    while IFS=: read -r g _ gid members; do
      [[ -n "${g}" && "${g}" != "#"* ]] && bo_inv groups "" "group:${g}" "gid=${gid}" "members[]=${members}" "^file=/etc/group"
      case "${g}" in
        sudo | wheel | admin | root) [[ -n "${members}" ]] && privgrp+=("file|/etc/group|group ${g}: ${members}") ;;
        docker | lxd | disk) [[ -n "${members}" ]] && rootequiv+=("file|/etc/group|group ${g}: ${members}") ;;
        *) ;;
      esac
    done <"${gf}"
    bo_cov groups "" complete
    ((${#privgrp[@]} > 0)) && bo_finding USR-GROUP-001 info high users "Members of administrative groups" \
      "Users in sudo/wheel/admin/root groups can typically obtain root." "" "" "${privgrp[@]}"
    ((${#rootequiv[@]} > 0)) && bo_finding USR-GROUP-002 low medium users "Members of root-equivalent groups" \
      "docker, lxd and disk group membership is effectively root access." "Remove members that do not need it." "T1548" "${rootequiv[@]}"
  else
    bo_error GROUP_UNREADABLE "/etc/group not readable; group checks skipped" "USR-GROUP-001"
    bo_cov groups "" unavailable "/etc/group not readable"
  fi
}

_usr_sessions_check() {
  local out
  if bo_have who; then
    out="$(who 2>/dev/null || true)"
  elif bo_have w; then
    out="$(w -h 2>/dev/null || true)"
  else
    bo_error TOOL_MISSING "neither who nor w found; active sessions not enumerated" "USR-SESS-001"
    return 0
  fi
  local -a ev=()
  local line
  while IFS= read -r line; do [[ -n "${line}" ]] && ev+=("other|session|$(printf '%s' "${line}" | tr -s '[:space:]' ' ')"); done <<<"${out}"
  bo_finding USR-SESS-001 info high users "Active login sessions" "${#ev[@]} session(s) reported." "" "" ${ev[@]+"${ev[@]}"}
}

_usr_keytype() {
  local tok IFS=' '
  for tok in $1; do
    case "${tok}" in ssh-* | ecdsa-* | sk-*) printf '%s' "${tok}" && return 0 ;; *) ;; esac
  done
  printf 'unknown'
}

# One record per authorized key, identified by the SHA-256 of its public key blob (never the
# key itself); the free-text label is volatile context.
_usr_inventory_key() {
  local u="$1" rel="$2" line="$3" label="$4" ktype blob id
  IFS=' ' read -r ktype blob < <(printf '%s\n' "${line}" | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^(ssh-|ecdsa-|sk-)/) { print $i, $(i + 1); exit } }')
  if [[ -z "${blob:-}" ]]; then
    bo_cov persistence ssh-authkeys partial "an authorized_keys line in ${rel} could not be fingerprinted"
    return 0
  fi
  id="$(bo_hash_id "${blob}" 24)"
  local opts=no
  [[ "${line%%[[:space:]]*}" == "${ktype}" ]] || opts=yes
  bo_inv persistence ssh-authkeys "persist:ssh-authkey:${u}:${id}" "owner=${u}" "type=${ktype}" "options=${opts}" "file=${rel}" "~label=${label:0:60}" "^file=${rel}"
}

_usr_ssh_check() {
  local u uid home f dir n opts mode line rel total=0
  local -a inv=() forced=() rootk=() sysk=() perms=()
  if [[ ! -r "$(bo_path /etc/passwd)" ]]; then
    bo_cov persistence ssh-authkeys unavailable "/etc/passwd not readable"
    return 0
  fi
  bo_is_root || bo_cov persistence ssh-authkeys partial "not running as root; other users' home directories may be unreadable"
  bo_cov persistence ssh-authkeys complete
  while IFS=$'\t' read -r u uid home; do
    for f in "${home}/.ssh/authorized_keys" "${home}/.ssh/authorized_keys2"; do
      [[ -e "${f}" ]] || continue
      if [[ ! -r "${f}" ]]; then
        bo_perm_error "cannot read $(bo_unroot "${f}")" "USR-SSH-001"
        bo_cov persistence ssh-authkeys partial "cannot read $(bo_unroot "${f}")"
        continue
      fi
      n=0
      opts=0
      rel="$(bo_unroot "${f}")"
      while IFS= read -r line; do
        [[ "${line}" =~ ^[[:space:]]*(#|$) ]] && continue
        n=$((n + 1))
        total=$((total + 1))
        local first="${line%%[[:space:]]*}" comment
        comment="$(printf '%s' "${line}" | awk '{print $NF}')"
        inv+=("file|${rel}|owner ${u}; type $(_usr_keytype "${line}"); label ${comment:0:60}")
        _usr_inventory_key "${u}" "${rel}" "${line}" "${comment}"
        case "${first}" in
          ssh-* | ecdsa-* | sk-*) ;;
          *)
            opts=$((opts + 1))
            if [[ "${line}" == *command=* ]]; then forced+=("file|${rel}|owner ${u}: key with forced command option"); fi
            ;;
        esac
      done <"${f}"
      if ((n > 0)); then
        [[ "${u}" == "root" ]] && rootk+=("file|${rel}|${n} key(s) authorize direct root login")
        if [[ "${uid}" =~ ^[0-9]+$ ]] && ((uid > 0 && uid < 1000)); then
          sysk+=("file|${rel}|system account '${u}' (uid ${uid}) has ${n} authorized key(s)")
        fi
      fi
      dir="${home}/.ssh"
      for p in "${f}" "${dir}"; do
        mode="$(bo_mode "${p}" || true)"
        if [[ -n "${mode}" ]] && bo_mode_has "${mode}" 022; then perms+=("file|$(bo_unroot "${p}")|mode ${mode} writable by group/other"); fi
      done
    done
  done < <(bo_homes)
  ((total > 0)) && bo_finding USR-SSH-001 info high users "SSH authorized keys" \
    "${total} authorized key(s) found. Key material is not shown; labels are free-text comments chosen by the key owner." "" "" "${inv[@]}"
  ((${#rootk[@]} > 0)) && bo_finding USR-SSH-002 medium low users "Authorized SSH keys for root" \
    "Direct root key login is a common persistence mechanism." "Verify each key belongs to an authorized administrator." "T1098.004" "${rootk[@]}"
  ((${#sysk[@]} > 0)) && bo_finding USR-SSH-004 high medium users "Authorized SSH keys on system accounts" \
    "Service accounts rarely need interactive key login." "Verify and remove unexpected keys." "T1098.004" "${sysk[@]}"
  ((${#forced[@]} > 0)) && bo_finding USR-SSH-005 medium low users "Authorized keys with forced commands" \
    "command= options run arbitrary programs on login and can hide persistence." "Review the command." "T1098.004" "${forced[@]}"
  ((${#perms[@]} > 0)) && bo_finding USR-SSH-003 medium high users "Writable SSH key files or directories" \
    "Group/other-writable .ssh paths let other users add keys." "chmod go-w on the paths." "T1098.004" "${perms[@]}"
}

mod_users() {
  _usr_accounts_check
  _usr_sudo_check
  _usr_sessions_check
  _usr_ssh_check
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-users audit users 0 "$@" || rc=$?
  exit "${rc}"
fi
