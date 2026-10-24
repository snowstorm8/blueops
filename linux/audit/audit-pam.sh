#!/usr/bin/env bash
# Module: pam - PAM stack configuration review (read-only; parses config, loads nothing).
# Category: audit. Safety: read-only. Never executes PAM modules or reads credentials.
# Usage: audit-pam.sh [--json] [--output-dir DIR] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

# Normalize PAM config to: file<TAB>type<TAB>control<TAB>module<TAB>args ("-" when empty).
# Bracketed controls ([success=1 default=ignore]) are joined with "_".
_pam_parse() {
  local f="$1" shift_service="$2"
  awk -v file="$(bo_unroot "${f}")" -v svc="${shift_service}" '
    { line = $0; sub(/[[:space:]]*#.*/, "", line); n = split(line, a, /[[:space:]]+/); i = 1
      if (a[1] == "") i = 2
      if (n < i) next
      if (svc == 1) i++
      t = a[i]
      if (t == "@include") { print file "\t@include\t-\t" a[i+1] "\t-"; next }
      dash = (t ~ /^-/); sub(/^-/, "", t)
      if (t !~ /^(auth|account|password|session)$/) next
      i++; c = a[i]
      if (c == "include" || c == "substack") { print file "\t@include\t-\t" a[i+1] "\t-"; next }
      if (c ~ /^\[/) { while (c !~ /\]$/ && i < n) { i++; c = c "_" a[i] } }
      i++; m = a[i]; args = ""
      for (j = i + 1; j <= n; j++) args = args (j > i + 1 ? " " : "") a[j]
      if (m == "") next
      print file "\t" (dash ? "-" : "") t "\t" c "\t" m "\t" (args == "" ? "-" : args) }' "${f}"
}

_pam_security_dirs() {
  local g
  for g in "$(bo_path /lib/security)" "$(bo_path /lib64/security)" "$(bo_path /usr/lib/security)" "$(bo_path /usr/lib64/security)" \
    "$(bo_path /lib)"/*/security "$(bo_path /usr/lib)"/*/security; do
    [[ -d "${g}" ]] && printf '%s\n' "${g}"
  done
}

mod_pam() {
  local pamd conf
  pamd="$(bo_path /etc/pam.d)"
  conf="$(bo_path /etc/pam.conf)"
  local -a files=() svc=()
  local f
  if [[ -d "${pamd}" ]]; then
    for f in "${pamd}"/*; do [[ -f "${f}" ]] && files+=("${f}") && svc+=(0); done
  fi
  if [[ -f "${conf}" ]]; then
    files+=("${conf}")
    svc+=(1)
  fi
  if ((${#files[@]} == 0)); then
    bo_error PAM_ABSENT "no /etc/pam.d or /etc/pam.conf found; PAM review skipped" "PAM-INFO-001" 0
    return 0
  fi
  local -a dirs=()
  while IFS= read -r f; do [[ -n "${f}" ]] && dirs+=("${f}"); done < <(_pam_security_dirs)
  if ((${#dirs[@]} == 0)); then
    bo_error PAM_MODULES_DIR "no PAM module directory found; module existence/modification checks skipped" "PAM-MODULE-002" 0
  fi

  : >"${BO_SCRATCH}/pam.tsv"
  local i
  for i in "${!files[@]}"; do
    if [[ ! -r "${files[${i}]}" ]]; then
      bo_perm_error "cannot read $(bo_unroot "${files[${i}]}")" "PAM-INFO-001"
      bo_inv config pam "config:pam:$(bo_unroot "${files[${i}]}")" "sha256=@unknown" "mode=@unknown" "^file=$(bo_unroot "${files[${i}]}")"
      bo_cov config pam degraded "$(bo_unroot "${files[${i}]}") not readable; content hash unknown"
      continue
    fi
    bo_inv config pam "config:pam:$(bo_unroot "${files[${i}]}")" "sha256=$(bo_sha256_file "${files[${i}]}" || echo @unknown)" "mode=$(bo_mode "${files[${i}]}" || echo @unknown)" "^file=$(bo_unroot "${files[${i}]}")"
    _pam_parse "${files[${i}]}" "${svc[${i}]}" >>"${BO_SCRATCH}/pam.tsv"
  done

  bo_cov config pam complete
  local file type ctl mod args curfile="" real=0 mode
  local modules=" " nrules=0
  local -a permit=() nullok=() hash=() abspath=() unknown=() perms=() inv=()
  while IFS=$'\t' read -r file type ctl mod args; do
    if [[ "${file}" != "${curfile}" ]]; then
      curfile="${file}"
      real=0
    fi
    if [[ "${type}" == "@include" ]]; then
      real=1
      continue
    fi
    # "-type" means the module may legitimately be absent (no log, no failure).
    local optional=0
    if [[ "${type}" == -* ]]; then
      optional=1
      type="${type#-}"
    fi
    nrules=$((nrules + 1))
    [[ "${modules}" == *" ${mod##*/} "* ]] || modules+="${mod##*/} "
    if [[ "${type}" == "auth" ]]; then
      case "${mod##*/}" in
        pam_permit.so)
          if [[ "${ctl}" == "sufficient" || "${ctl}" == *=done* || "${ctl}" == *=ok* ]]; then
            permit+=("file|${file}|auth sufficient pam_permit.so accepts any user without a password check")
          elif [[ "${ctl}" == "required" || "${ctl}" == "requisite" ]] && [[ "${real}" == 0 ]]; then
            permit+=("file|${file}|auth ${ctl} pam_permit.so with no earlier authenticating module in this file")
          fi
          ;;
        pam_succeed_if.so)
          # "auth sufficient pam_succeed_if.so uid >= 0" (or similar) accepts everyone.
          if [[ ("${ctl}" == "sufficient" || "${ctl}" == *=done* || "${ctl}" == *=ok*) && "${args}" =~ uid[[:space:]]*\>=?[[:space:]]*0([[:space:]]|$) ]]; then
            permit+=("file|${file}|auth ${ctl} pam_succeed_if.so ${args} matches every user")
          fi
          ;;
        pam_unix.so | pam_sss.so | pam_ldap.so | pam_krb5.so | pam_winbind.so | pam_google_authenticator.so | pam_radius_auth.so | pam_u2f.so | pam_fprintd.so) real=1 ;;
        *) ;;
      esac
    fi
    if [[ "${mod##*/}" == "pam_unix.so" ]]; then
      if [[ "${type}" == "auth" && " ${args} " == *" nullok"* ]]; then nullok+=("file|${file}|pam_unix auth permits empty passwords (${args})"); fi
      if [[ "${type}" == "password" && "${args}" =~ (^|[[:space:]])(md5|des|bigcrypt)([[:space:]]|$) ]]; then
        hash+=("file|${file}|pam_unix password hashing uses a weak algorithm (${BASH_REMATCH[2]})")
      fi
    fi
    if [[ "${mod}" == /* ]]; then
      case "${mod}" in
        /lib/security/* | /lib64/security/* | /usr/lib/security/* | /usr/lib64/security/* | /lib/*/security/* | /usr/lib/*/security/*) ;;
        *) abspath+=("file|${file}|${type} ${ctl} ${mod}") ;;
      esac
    elif ((${#dirs[@]} > 0)) && [[ "${optional}" == 0 ]]; then
      local found=0 d
      for d in "${dirs[@]}"; do [[ -e "${d}/${mod}" ]] && found=1 && break; done
      ((found)) || unknown+=("file|${file}|${type} ${ctl} ${mod}: not found in the system PAM module directories")
    fi
  done <"${BO_SCRATCH}/pam.tsv"

  for f in "${pamd}" "${files[@]}"; do
    [[ -e "${f}" ]] || continue
    mode="$(bo_mode "${f}" || true)"
    if [[ -n "${mode}" ]] && bo_mode_has "${mode}" 022; then perms+=("file|$(bo_unroot "${f}")|mode ${mode} is writable by group/other"); fi
  done

  for f in "${files[@]}"; do inv+=("file|$(bo_unroot "${f}")"); done
  bo_finding PAM-INFO-001 info high pam "PAM configuration inventory" \
    "${#files[@]} PAM config file(s), ${nrules} rule(s). Modules referenced:${modules% }." "" "" "${inv[@]}"

  ((${#permit[@]} > 0)) && bo_finding PAM-PERMIT-001 high medium pam "PAM authentication can succeed without verifying a credential" \
    "pam_permit in an auth stack as 'sufficient', or as the only authenticating module, lets any user log in. Debian/RHEL stacks use it only as a final required entry after real checks." \
    "Compare with the distribution default for this service; restore from the package (e.g. pam-auth-update) after preserving the file." "T1556.003" "${permit[@]}"
  ((${#abspath[@]} > 0)) && bo_finding PAM-MODULE-001 high medium pam "PAM module loaded from outside the system module directories" \
    "Absolute module paths outside the standard security directories are rare and are used to load credential-capturing modules." \
    "Hash and inspect the module before removing the rule." "T1556.003" "${abspath[@]}"
  ((${#unknown[@]} > 0)) && bo_finding PAM-MODULE-002 medium low pam "PAM rule references a module that is not installed" \
    "The module is missing from the system module directories; the package may have been removed (a broken stack can lock users out) or the rule may point at planted code." \
    "Install the owning package or remove the stale rule; verify with the package manager." "T1556.003" "${unknown[@]}"
  ((${#perms[@]} > 0)) && bo_finding PAM-PERM-001 high high pam "PAM configuration writable by non-root" \
    "Group/other-writable PAM files allow authentication bypass." "chmod go-w after reviewing contents." "T1556.003" "${perms[@]}"
  ((${#nullok[@]} > 0)) && bo_finding PAM-NULLOK-001 low high pam "pam_unix accepts empty passwords (nullok)" \
    "Debian-family defaults include nullok; it matters only if an account has an empty password." \
    "Remove nullok once no account relies on it (check USR-PWD-001 first)." "T1078.003" "${nullok[@]}"
  ((${#hash[@]} > 0)) && bo_finding PAM-HASH-001 medium high pam "Weak password hashing configured in PAM" \
    "md5/des/bigcrypt hashes are cheap to crack." "Use sha512 or yescrypt." "T1110.002" "${hash[@]}"

  if ((${#dirs[@]} > 0)); then
    local -a recent=()
    while IFS= read -r f; do [[ -n "${f}" ]] && recent+=("file|$(bo_unroot "${f}")|modified within ${BO_RECENT_DAYS} day(s)"); done \
      < <(bo_find "${dirs[@]}" -type f -name '*.so*' -mtime "-${BO_RECENT_DAYS}")
    ((${#recent[@]} > 0)) && bo_finding PAM-RECENT-001 medium low pam "PAM module files modified recently" \
      "Replacing a PAM module is a known credential-theft technique; package upgrades also change them." \
      "Verify against the package manager (see --package-integrity)." "T1556.003" "${recent[@]}"
  fi
  return 0
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-pam audit pam 0 "$@" || rc=$?
  exit "${rc}"
fi
