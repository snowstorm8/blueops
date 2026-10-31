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

# True when sudo would read this file name from an include directory (it skips names that
# contain a dot or end in a tilde).
_usr_sudoers_name_ok() { [[ "$1" != *.* && "$1" != *~ ]]; }

# Directive lines that make sudo read more files: #include, #includedir, @include, @includedir.
# (`#include` is a directive, not a comment; a plain comment such as "# includes foo" is not.)
_usr_sudoers_include() { # LINE -> prints "kind<TAB>path" when LINE is an include directive
  local re='^[[:space:]]*[#@]include(dir)?[[:space:]]+([^[:space:]]+)'
  if [[ "$1" =~ ${re} ]]; then
    printf '%s\t%s' "${BASH_REMATCH[1]:-file}" "${BASH_REMATCH[2]}"
  fi
}

_usr_sudo_check() {
  local gf f line norm n=0 nopw=0 kind target inc
  local -a files=() queue=() nopasswd=() unsafe=() rules=() privgrp=() rootequiv=() includes=() defaults=()
  local seen=" "
  for f in "$(bo_path /etc/sudoers)" "$(bo_path /etc/sudoers.d)"/*; do
    [[ -f "${f}" ]] || continue
    # sudo ignores sudoers.d entries whose names contain '.' or end in '~'.
    if [[ "${f}" == */sudoers.d/* ]] && ! _usr_sudoers_name_ok "${f##*/}"; then continue; fi
    files+=("${f}")
    seen+="${f} "
  done
  if ((${#files[@]} == 0)); then
    [[ -e "$(bo_path /etc/sudoers)" ]] && bo_perm_error "/etc/sudoers not readable; sudo rules skipped" "USR-SUDO-001" && bo_cov config sudoers partial "/etc/sudoers not readable"
    [[ -e "$(bo_path /etc/sudoers)" ]] || bo_error SUDO_ABSENT "no /etc/sudoers present (sudo not installed?)" "USR-SUDO-001" 0
  fi
  # Files are processed as a worklist so that include directives found while reading add their
  # targets. A visited set prevents loops and the worklist is capped at 500 files.
  queue=(${files[@]+"${files[@]}"})
  local idx=0
  while ((idx < ${#queue[@]})); do
    f="${queue[${idx}]}"
    idx=$((idx + 1))
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
    while IFS= read -r line || [[ -n "${line}" ]]; do
      # Directives first: "#include..." would otherwise be stripped as a comment below.
      if inc="$(_usr_sudoers_include "${line}")" && [[ -n "${inc}" ]]; then
        kind="${inc%%$'\t'*}"
        target="${inc#*$'\t'}"
        includes+=("file|${rel}|${kind} ${target}")
        norm="$(printf '%s' "${line}" | tr -s '[:space:]' ' ')"
        bo_inv config sudoers "config:sudoers:${rel}#$(bo_hash_id "${norm}")" "file=${rel}" "rule=${norm}" "^file=${rel}"
        if [[ "${target}" != /* ]] || ((${#queue[@]} >= 500)); then continue; fi
        if [[ "${kind}" == dir ]]; then
          local ef
          for ef in "$(bo_path "${target}")"/*; do
            [[ -f "${ef}" ]] || continue
            _usr_sudoers_name_ok "${ef##*/}" || continue
            [[ "${seen}" == *" ${ef} "* ]] && continue
            seen+="${ef} "
            queue+=("${ef}")
          done
        else
          [[ -f "$(bo_path "${target}")" && "${seen}" != *" $(bo_path "${target}") "* ]] && {
            seen+="$(bo_path "${target}") "
            queue+=("$(bo_path "${target}")")
          }
        fi
        continue
      fi
      line="${line%%#*}"
      [[ "${line}" =~ ^[[:space:]]*$ ]] && continue
      norm="$(printf '%s' "${line}" | tr -s '[:space:]' ' ')"
      # Every effective line is inventoried, including Defaults and *_Alias definitions: they
      # change what the rules mean (for example `Defaults !authenticate`).
      bo_inv config sudoers "config:sudoers:${rel}#$(bo_hash_id "${norm}")" "file=${rel}" "rule=$(printf '%s' "${norm}" | bo_redact)" "^file=${rel}"
      if [[ "${line}" =~ ^[[:space:]]*Defaults ]]; then
        defaults+=("file|${rel}|$(printf '%s' "${norm}" | bo_redact)")
        continue
      fi
      [[ "${line}" =~ ^[[:space:]]*(Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias) ]] && continue
      n=$((n + 1))
      rules+=("file|${rel}|$(printf '%s' "${line}" | tr -s '[:space:]' ' ' | bo_redact)")
      if [[ "${line}" == *NOPASSWD* ]]; then
        nopw=$((nopw + 1))
        nopasswd+=("file|${rel}|$(printf '%s' "${line}" | tr -s '[:space:]' ' ' | bo_redact)")
      fi
    done <"${f}"
  done
  if ((n > 0)); then
    bo_finding USR-SUDO-001 info high users "Sudo rules" "${n} rule line(s) across ${#queue[@]} file(s)." "" "" "${rules[@]}"
  fi
  ((nopw > 0)) && bo_finding USR-SUDO-002 medium medium users "Sudo rules without password (NOPASSWD)" \
    "NOPASSWD grants privilege escalation to anyone able to run as those principals." \
    "Remove NOPASSWD unless required by a scored service." "T1548.003" "${nopasswd[@]}"
  ((${#unsafe[@]} > 0)) && bo_finding USR-SUDO-003 high high users "Sudoers file writable by non-root" \
    "Group/other-writable sudoers files allow privilege escalation." "chmod 0440 on the file after review." "T1548.003" "${unsafe[@]}"
  # Include directives pointing outside /etc/sudoers.d: rules there are read as if they were part
  # of sudoers, and the target is often a directory that is easier to write.
  local -a oddinc=() riskyinc=()
  local inc_item
  for inc_item in ${includes[@]+"${includes[@]}"}; do
    target="${inc_item##* }"
    case "${target}" in
      /etc/sudoers.d | /etc/sudoers.d/* | /etc/sudoers) ;;
      /tmp/* | /var/tmp/* | /dev/shm/* | /run/user/* | /home/* | /mnt/* | /media/*) riskyinc+=("${inc_item}") ;;
      *) oddinc+=("${inc_item}") ;;
    esac
  done
  ((${#riskyinc[@]} > 0)) && bo_finding USR-SUDO-004 high high users "Sudoers includes a temporary or user-writable location" \
    "An include directive makes sudo read rules from a directory ordinary users or processes can usually write." \
    "Remove the include after preserving the target; verify the files it pulled in." "T1548.003" "${riskyinc[@]}"
  ((${#oddinc[@]} > 0)) && bo_finding USR-SUDO-004 medium medium users "Sudoers includes a non-default location" \
    "Rules are read from outside /etc/sudoers.d; legitimate on some systems, also a way to hide rules." \
    "Confirm the include is expected and the target is root-owned and not group/other-writable." "T1548.003" "${oddinc[@]}"
  local -a baddef=()
  local d_item
  for d_item in ${defaults[@]+"${defaults[@]}"}; do
    if [[ "${d_item}" =~ \!authenticate ]] || [[ "${d_item}" =~ env_keep.*(LD_|PYTHONPATH|PERL5LIB|RUBYLIB) ]] || [[ "${d_item}" =~ \!env_reset ]]; then
      baddef+=("${d_item}")
    fi
  done
  ((${#baddef[@]} > 0)) && bo_finding USR-SUDO-005 high medium users "Dangerous sudo Defaults" \
    "Defaults such as !authenticate (no password for anyone), env_keep of loader/interpreter variables, or !env_reset let a caller's environment or identity weaken sudo." \
    "Remove the setting unless it is required, after preserving the file." "T1548.003" "${baddef[@]}"

  bo_cov config sudoers complete
  gf="$(bo_path /etc/group)"
  if [[ -r "${gf}" ]]; then
    local g gid members pm
    local -a primgrp=()
    while IFS=: read -r g _ gid members; do
      [[ -n "${g}" && "${g}" != "#"* ]] || continue
      # Accounts whose *primary* group is a privileged one are not listed in /etc/group at all,
      # yet sudo and file permissions treat them as members: record them for the comparison.
      pm=""
      case "${g}" in
        sudo | wheel | admin | root | docker | lxd | disk | shadow)
          if [[ -s "${BO_SCRATCH}/accounts.tsv" ]]; then
            pm="$(awk -F'\t' -v gid="${gid}" '$3 == gid { printf "%s%s", (n++ ? "," : ""), $1 }' "${BO_SCRATCH}/accounts.tsv")"
          fi
          bo_inv groups "" "group:${g}" "gid=${gid}" "members[]=${members}" "primary_members[]=${pm}" "^file=/etc/group"
          ;;
        *) bo_inv groups "" "group:${g}" "gid=${gid}" "members[]=${members}" "^file=/etc/group" ;;
      esac
      case "${g}" in
        sudo | wheel | admin | root)
          [[ -n "${members}" ]] && privgrp+=("file|/etc/group|group ${g}: ${members}")
          # root itself (and root-aliased accounts of the distribution) legitimately has GID 0.
          local extra="" a
          for a in ${pm//,/ }; do [[ "${a}" == root ]] || extra+="${a} "; done
          [[ -z "${extra}" ]] || primgrp+=("file|/etc/passwd|primary group ${g} (gid ${gid}) of: ${extra% }")
          ;;
        docker | lxd | disk) [[ -n "${members}" ]] && rootequiv+=("file|/etc/group|group ${g}: ${members}") ;;
        *) ;;
      esac
    done <"${gf}"
    bo_cov groups "" complete
    ((${#primgrp[@]} > 0)) && bo_finding USR-GROUP-003 high medium users "Accounts with an administrative primary group" \
      "These accounts are not listed as group members in /etc/group but hold an administrative group (root, sudo, wheel, admin) as their primary group, which grants the same privileges." \
      "Verify each account; change the primary group with usermod -g after preserving the passwd and group files." "T1098" "${primgrp[@]}"
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
