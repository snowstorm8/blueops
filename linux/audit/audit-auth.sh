#!/usr/bin/env bash
# Module: auth - authentication policy and group integrity.
# Category: audit. Safety: read-only (reads /etc/login.defs, /etc/shadow aging fields, /etc/group,
# /etc/passwd, /etc/pam.d). Password hashes are never printed or stored.
# Usage: audit-auth.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

_ath_nologin() {
  case "${1##*/}" in nologin | false | sync | shutdown | halt | "") return 0 ;; *) return 1 ;; esac
}

# Effective login.defs settings, "KEY<TAB>VALUE" per line. The last occurrence of a key wins, as
# in the shadow-utils parser; comments and blank lines are skipped.
_ath_logindefs_values() {
  awk '
    /^[[:space:]]*#/ || NF < 2 { next }
    { v[$1] = $2 }
    END { for (k in v) print k "\t" v[k] }
  ' "$1" | sort
}

_ath_logindefs() {
  local f
  f="$(bo_path /etc/login.defs)"
  if [[ ! -r "${f}" ]]; then
    bo_error LOGINDEFS_MISSING "/etc/login.defs not readable or absent; password policy defaults not assessed" "ATH-DEFS-001" 0
    bo_cov config logindefs unavailable "/etc/login.defs not readable"
    return 0
  fi
  local k v n
  local -a weak=()
  while IFS=$'\t' read -r k v; do
    case "${k}" in
      PASS_MAX_DAYS | PASS_MIN_DAYS | PASS_WARN_AGE | ENCRYPT_METHOD | UMASK | LOGIN_RETRIES | SHA_CRYPT_MIN_ROUNDS | USERGROUPS_ENAB)
        bo_inv config logindefs "config:logindefs:${k}" "value=${v}" "^file=/etc/login.defs"
        ;;
      *) continue ;;
    esac
    case "${k}" in
      PASS_MAX_DAYS)
        if [[ "${v}" =~ ^[0-9]+$ ]] && ((10#${v} > 365)); then
          weak+=("file|/etc/login.defs|PASS_MAX_DAYS ${v}: passwords may stay unchanged for more than a year")
        fi
        ;;
      ENCRYPT_METHOD)
        case "${v^^}" in
          DES | MD5) weak+=("file|/etc/login.defs|ENCRYPT_METHOD ${v}: new passwords use a weak hash") ;;
          *) ;;
        esac
        ;;
      UMASK)
        # The last octal digit is the mask for "other": without bit 2 (write) new files are
        # created world-writable.
        if [[ "${v}" =~ ^0?[0-7]{3}$ ]]; then
          n="${v: -1}"
          if (((8#${n} & 2) == 0)); then
            weak+=("file|/etc/login.defs|UMASK ${v}: new files are created writable by everyone")
          fi
        fi
        ;;
      *) ;;
    esac
  done < <(_ath_logindefs_values "${f}")
  bo_cov config logindefs complete
  ((${#weak[@]} > 0)) && bo_finding ATH-DEFS-001 low high auth "Weak defaults in /etc/login.defs" \
    "Account-creation defaults weaken password hygiene: long or unlimited password lifetime, weak hash for new passwords, or a permissive default umask." \
    "Set PASS_MAX_DAYS to a policy value, ENCRYPT_METHOD to SHA512 or YESCRYPT and UMASK to 027 or 077. Only new accounts and passwords are affected." "T1110" "${weak[@]}"
  return 0
}

# Accounts that can log in with a password that never expires. Reads only the aging fields.
_ath_aging() {
  local shadow pw
  shadow="$(bo_path /etc/shadow)"
  pw="$(bo_path /etc/passwd)"
  if [[ ! -r "${pw}" ]]; then return 0; fi
  if [[ ! -r "${shadow}" ]]; then
    bo_perm_error "/etc/shadow not readable; password-aging check skipped" "ATH-AGING-001"
    return 0
  fi
  local u hash max shell
  local -a never=()
  while IFS=: read -r u hash _ _ max _; do
    [[ -n "${u}" && "${u}" != [#+-]* ]] || continue
    [[ -n "${hash}" && "${hash}" != '!'* && "${hash}" != '*'* ]] || continue
    shell="$(awk -F: -v u="${u}" '$1 == u { print $7; exit }' "${pw}")"
    _ath_nologin "${shell}" && continue
    if [[ -z "${max}" ]] || { [[ "${max}" =~ ^[0-9]+$ ]] && ((10#${max} >= 99999)); }; then
      never+=("file|/etc/shadow|account '${u}': password never expires (max age ${max:-unset})")
    fi
  done <"${shadow}"
  ((${#never[@]} > 0)) && bo_finding ATH-AGING-001 low medium auth "Login accounts whose password never expires" \
    "Accounts with a usable password and a login shell have no maximum password age, so a stolen credential stays valid until someone changes it. Hashes are not shown." \
    "Apply 'chage -M DAYS USER' per account once you have confirmed scored-service accounts will not break; rotate known-compromised credentials first." "T1078.003" "${never[@]}"
  return 0
}

_ath_groups() {
  local gf pw
  gf="$(bo_path /etc/group)"
  pw="$(bo_path /etc/passwd)"
  if [[ ! -r "${gf}" ]]; then
    bo_error GROUP_UNREADABLE "/etc/group not readable; group integrity checks skipped" "ATH-GROUP-001"
    return 0
  fi
  local line u gid gids
  local -a dupgid=() dupname=() pwd_set=() orphan=()
  while IFS= read -r line; do dupgid+=("file|/etc/group|${line}"); done < <(
    awk -F: 'NF >= 3 && $1 !~ /^[#+-]/ { n[$3]++; names[$3] = names[$3] " " $1 } END { for (g in n) if (n[g] > 1) print "gid " g " shared by:" names[g] }' "${gf}" | sort
  )
  while IFS= read -r line; do dupname+=("file|/etc/group|group name ${line} appears more than once"); done < <(
    awk -F: 'NF >= 3 && $1 !~ /^[#+-]/ { n[$1]++ } END { for (g in n) if (n[g] > 1) print g }' "${gf}" | sort
  )
  # A group password hash is never shown: only the group name.
  while IFS= read -r line; do pwd_set+=("file|/etc/group|group '${line}' carries a password field (not 'x')"); done < <(
    awk -F: 'NF >= 3 && $1 !~ /^[#+-]/ && $2 != "x" && $2 != "" && $2 != "!" && $2 != "*" { print $1 }' "${gf}" | sort
  )
  if [[ -r "${pw}" ]]; then
    gids="$(awk -F: 'NF >= 3 && $1 !~ /^[#+-]/ { print $3 }' "${gf}" | sort -u)"
    while IFS=$'\t' read -r u gid; do
      grep -q -F -x -e "${gid}" <<<"${gids}" || orphan+=("file|/etc/passwd|account '${u}' has primary gid ${gid}, which no group defines")
    done < <(awk -F: 'NF >= 7 && $1 !~ /^[#+-]/ { print $1 "\t" $4 }' "${pw}")
  fi
  ((${#dupgid[@]} > 0)) && bo_finding ATH-GROUP-001 medium high auth "Groups share a GID" \
    "Distinct groups with one GID grant identical file access, and a duplicate is a classic way to hide a privileged group." \
    "Confirm each duplicate; renumber unauthorized groups after recording the files they own." "T1098" "${dupgid[@]}"
  ((${#dupname[@]} > 0)) && bo_finding ATH-GROUP-004 medium high auth "Duplicate group names" \
    "A group name defined twice resolves to one of the entries depending on the lookup order." \
    "Remove or rename the unauthorized entry (use vigr)." "T1098" "${dupname[@]}"
  ((${#pwd_set[@]} > 0)) && bo_finding ATH-GROUP-002 medium high auth "Groups with a password" \
    "A group password lets any user join the group with newgrp. Values are not shown here." \
    "Clear the group password (gpasswd -r GROUP) unless it is documented and needed." "T1098" "${pwd_set[@]}"
  ((${#orphan[@]} > 0)) && bo_finding ATH-GROUP-003 low high auth "Accounts with an undefined primary group" \
    "The primary GID does not exist in /etc/group, which is unusual on a managed system and can follow tampering or a removed group." \
    "Create the missing group or correct the account's primary GID." "" "${orphan[@]}"
  return 0
}

# Password-quality and lockout enforcement are properties of the PAM stack: report their absence.
_ath_pam_policy() {
  local d pc
  d="$(bo_path /etc/pam.d)"
  pc="$(bo_path /etc/pam.conf)"
  if [[ ! -d "${d}" && ! -r "${pc}" ]]; then
    bo_error PAM_MISSING "no /etc/pam.d or /etc/pam.conf; password quality and lockout not assessed" "ATH-PWQ-001" 0
    return 0
  fi
  local -a targets=()
  [[ -d "${d}" ]] && targets+=("${d}")
  [[ -r "${pc}" ]] && targets+=("${pc}")
  local cfg
  cfg="$(grep -rhsE -e '^[[:space:]]*[^#[:space:]].*pam_(pwquality|cracklib|passwdqc)' "${targets[@]}" 2>/dev/null || true)"
  if [[ -z "${cfg}" ]] && ! grep -qsE -e '^[[:space:]]*(minlen|minclass|dcredit|ucredit)[[:space:]]*=' "$(bo_path /etc/security/pwquality.conf)" 2>/dev/null; then
    bo_finding ATH-PWQ-001 low low auth "No password-quality module in the PAM stack" \
      "No pam_pwquality, pam_cracklib or pam_passwdqc entry and no pwquality.conf settings were found, so password complexity is not enforced by PAM. Other mechanisms (LDAP, SSSD policy) are not detected." \
      "Install and enable pam_pwquality (or your distribution's equivalent) with a minimum length of 12 or more." "T1110" "file|/etc/pam.d"
  fi
  cfg="$(grep -rhsE -e '^[[:space:]]*[^#[:space:]].*pam_(faillock|tally2|tally)' "${targets[@]}" 2>/dev/null || true)"
  if [[ -z "${cfg}" ]]; then
    bo_finding ATH-LOCKOUT-001 low low auth "No account-lockout module in the PAM stack" \
      "No pam_faillock, pam_tally2 or pam_tally entry was found, so repeated failed logons do not lock an account at the PAM level. sshd rate limiting or fail2ban may still apply and are not detected." \
      "Enable pam_faillock (deny=5, unlock_time=600) after checking that scored-service accounts cannot be locked out by a flood of bad logons." "T1110" "file|/etc/pam.d"
  fi
  return 0
}

mod_auth() {
  _ath_logindefs
  _ath_aging
  _ath_groups
  _ath_pam_policy
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-auth audit auth 0 "$@" || rc=$?
  exit "${rc}"
fi
