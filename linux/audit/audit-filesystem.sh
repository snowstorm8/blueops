#!/usr/bin/env bash
# Module: filesystem - recent modifications, unusual permissions, SUID/SGID binaries.
# Category: audit. Safety: read-only (find/stat); never follows into other mounts (-xdev).
# Usage: audit-filesystem.sh [--recent-days N] [--fs-path DIR] [--json] ... (see --help)
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
source "${SCRIPT_DIR}/../lib/common.sh"

# Existing directories among the given absolute paths, mapped through BO_ROOT.
# With --fs-path, those directories replace the defaults.
_fs_roots() {
  local p
  if ((${#BO_FS_PATHS[@]} > 0)); then
    for p in "${BO_FS_PATHS[@]}"; do
      if [[ -d "${p}" ]]; then printf '%s\n' "${p}"; else bo_error FS_PATH_MISSING "--fs-path ${p} is not a directory" "" 1; fi
    done
    return 0
  fi
  for p in "$@"; do [[ -d "$(bo_path "${p}")" ]] && printf '%s\n' "$(bo_path "${p}")"; done
  return 0
}

_fs_known_suid() {
  case "$1" in
    su | sudo | sudoedit | passwd | chsh | chfn | gpasswd | newgrp | chage | expiry | mount | umount | ping | ping6 | pkexec | fusermount | fusermount3 | \
      ssh-agent | ssh-keysign | crontab | at | wall | write | bsd-write | unix_chkpwd | pam_timestamp_check | polkit-agent-helper-1 | dbus-daemon-launch-helper | \
      Xorg.wrap | mount.nfs | mount.cifs | traceroute6.iputils | newuidmap | newgidmap | locate | mlocate | plocate | utempter | umount.nfs | userhelper | \
      unix2_chkpwd | pam_extrausers_chkpwd | dotlockfile | sg | bwrap | eject | ntfs-3g | unix_update | mount.ecryptfs_private | ubuntu-core-launcher | pt_chown | lockfile | screen | dumpcap | procmail | smbmnt | staprun | lppasswd | mtr-packet | snap-confine | ksu | vmware-user-suid-wrapper | chrome-sandbox | pppd | Xorg | doas) return 0 ;;
    *) return 1 ;;
  esac
}

_fs_dangerous_suid() {
  case "$1" in
    find | vim | vi | nano | nmap | python | python2 | python3 | bash | sh | dash | zsh | awk | gawk | mawk | cp | mv | less | more | env | perl | ruby | tar | zip | \
      node | php | docker | strace | gdb | tee | dd | cat | head | tail | sed | xxd | base64 | busybox | openssl | wget | curl | nc | ncat | socat | systemctl | ed | tclsh | lua | man) return 0 ;;
    *) return 1 ;;
  esac
}

# Local (disk-backed) mount points, one per line, mapped through BO_ROOT.
# /proc/mounts is space-separated, so read it with an explicit IFS; spaces in
# mount points are encoded as \040.
_fs_local_mounts() {
  local mt dev mp fs
  mt="$(bo_path /proc/mounts)"
  if [[ ! -r "${mt}" ]]; then
    if [[ -n "${BO_ROOT:-}" ]]; then printf '%s/\n' "$(bo_root)"; else
      bo_error MOUNTS_UNREADABLE "/proc/mounts unreadable; scanning / only" "FS-SUID-001" 0
      printf '/\n'
    fi
    return 0
  fi
  while IFS=' ' read -r dev mp fs _; do
    case "${fs}" in
      ext2 | ext3 | ext4 | xfs | btrfs | zfs | f2fs | jfs | reiserfs | vfat | ntfs | ntfs3 | exfat | overlay)
        : "${dev}"
        mp="${mp//\\040/ }"
        printf '%s\n' "$(bo_path "${mp}")"
        ;;
      *) ;;
    esac
  done <"${mt}" | sort -u
}

_fs_suid() {
  local -a roots=() inv=() bad=() unk=()
  local r f base rel mode perm
  if ((${#BO_FS_PATHS[@]} > 0)); then roots=("${BO_FS_PATHS[@]}"); else
    while IFS= read -r r; do roots+=("${r}"); done < <(_fs_local_mounts)
  fi
  : >"${BO_SCRATCH}/suid.txt"
  bo_find_failed || true # discard failures from earlier scans
  for r in ${roots[@]+"${roots[@]}"}; do
    bo_find "${r}" -xdev -type f \( -perm -4000 -o -perm -2000 \) >>"${BO_SCRATCH}/suid.txt"
  done
  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    base="${f##*/}"
    rel="$(bo_unroot "${f}")"
    mode="$(bo_mode "${f}" || echo '?')"
    perm="mode ${mode}"
    inv+=("file|${rel}|${perm}")
    bo_inv config suid "config:suid:${rel}" "mode=$([[ "${mode}" == "?" ]] && echo @unknown || echo "${mode}")" "^file=${rel}"
    case "${rel}" in
      /tmp/* | /var/tmp/* | /dev/shm/* | /home/* | /root/* | /var/www/* | /srv/* | /mnt/* | /media/*)
        bad+=("file|${rel}|${perm}; non-standard location")
        ;;
      *)
        if _fs_dangerous_suid "${base}"; then
          bad+=("file|${rel}|${perm}; ${base} with SUID/SGID allows privilege escalation (GTFOBins class)")
        elif ! _fs_known_suid "${base}"; then
          unk+=("file|${rel}|${perm}")
        fi
        ;;
    esac
  done < <(sort -u "${BO_SCRATCH}/suid.txt")
  if bo_find_failed; then
    bo_cov config suid partial "find hit unreadable directories; SUID/SGID files there may be missing"
  fi
  if ((${#BO_FS_PATHS[@]} > 0)); then
    bo_cov config suid partial "scan limited to --fs-path roots"
  fi
  bo_cov config suid complete
  bo_finding FS-SUID-001 info high filesystem "SUID/SGID files" "${#inv[@]} SUID/SGID file(s) on local filesystems." "" "" ${inv[@]+"${inv[@]}"}
  ((${#bad[@]} > 0)) && bo_finding FS-SUID-002 high high filesystem "Dangerous or misplaced SUID/SGID binary" \
    "SUID/SGID on general-purpose utilities, interpreters, or files in user-writable locations enables privilege escalation." \
    "Record the hash, then clear the bit (chmod u-s,g-s FILE) after confirming nothing depends on it." "T1548.001" "${bad[@]}"
  ((${#unk[@]} > 0)) && bo_finding FS-SUID-003 medium low filesystem "SUID/SGID binary not in BlueOps' known-package list" \
    "The list is conservative and distribution-agnostic; unknown does not mean malicious." \
    "Verify package ownership (dpkg -S / rpm -qf) and integrity (debsums / rpm -V)." "T1548.001" "${unk[@]}"
  return 0
}

_fs_recent() {
  local -a roots=() sysbin=() syslib=() etc=() other=()
  local r f rel rootp
  rootp="$(bo_root)"
  while IFS= read -r r; do roots+=("${r}"); done < <(_fs_roots /etc /bin /sbin /usr/bin /usr/sbin /usr/local /lib /lib64 /usr/lib /opt /root /home /var/spool /var/www /srv /tmp /var/tmp /dev/shm /boot)
  if ((${#roots[@]} == 0)); then
    bo_error NO_SCAN_ROOTS "no directories to scan for recent modifications" "FS-RECENT-001"
    return 0
  fi
  bo_find "${roots[@]}" -xdev -type f -mtime "-${BO_RECENT_DAYS}" >"${BO_SCRATCH}/recent.txt"
  while IFS= read -r f; do
    [[ -n "${f}" ]] || continue
    rel="${f#"${rootp}"}"
    case "${rel}" in
      */__pycache__/* | *.pyc | */ld.so.cache | /etc/resolv.conf | /etc/mtab | /etc/adjtime | */random-seed | /etc/machine-id | /etc/hosts.* | /etc/.updated) continue ;;
      /bin/* | /sbin/* | /usr/bin/* | /usr/sbin/* | /usr/local/bin/* | /usr/local/sbin/*) sysbin+=("file|${rel}") ;;
      /lib/* | /lib64/* | /usr/lib/* | /boot/*) syslib+=("file|${rel}") ;;
      /etc/*) etc+=("file|${rel}") ;;
      *) other+=("file|${rel}") ;;
    esac
  done <"${BO_SCRATCH}/recent.txt"
  ((${#sysbin[@]} > 0)) && bo_finding FS-RECENT-001 medium low filesystem "Executables modified in the last ${BO_RECENT_DAYS} day(s)" \
    "Files in bin/sbin directories. Expected after package updates; otherwise a sign of trojanized binaries." \
    "Verify against package manager checksums (debsums -c / rpm -Va)." "T1554" "${sysbin[@]}"
  ((${#syslib[@]} > 0)) && bo_finding FS-RECENT-004 low low filesystem "Libraries or boot files modified in the last ${BO_RECENT_DAYS} day(s)" \
    "Commonly changed by package updates; shared-library tampering is rare but high impact." \
    "Verify against package manager checksums (debsums -c / rpm -Va)." "T1574" "${syslib[@]}"
  ((${#etc[@]} > 0)) && bo_finding FS-RECENT-002 low low filesystem "Configuration files modified in the last ${BO_RECENT_DAYS} day(s)" \
    "Compare with your change log." "Review the diffs where a baseline exists." "" "${etc[@]}"
  ((${#other[@]} > 0)) && bo_finding FS-RECENT-003 info medium filesystem "Other files modified in the last ${BO_RECENT_DAYS} day(s)" \
    "Home directories, /opt, web roots and temporary directories." "" "" "${other[@]}"
  return 0
}

_fs_perms() {
  local -a sysroots=() tmproots=() ww=() wwd=() exe=() orphan=() hidden=() crit=()
  local r f rel
  while IFS= read -r r; do sysroots+=("${r}"); done < <(_fs_roots /etc /usr /bin /sbin /lib /lib64 /opt /boot /var/www /srv)
  while IFS= read -r r; do tmproots+=("${r}"); done < <(_fs_roots /tmp /var/tmp /dev/shm)
  local -a homeroot=()
  ((${#BO_FS_PATHS[@]} == 0)) && while IFS= read -r r; do homeroot+=("${r}"); done < <(_fs_roots /home)
  if ((${#sysroots[@]} > 0)); then
    while IFS= read -r f; do [[ -n "${f}" ]] && ww+=("file|$(bo_unroot "${f}")|mode $(bo_mode "${f}" || echo '?')"); done < <(bo_find "${sysroots[@]}" -xdev -type f -perm -0002 ! -type l)
    while IFS= read -r f; do [[ -n "${f}" ]] && wwd+=("file|$(bo_unroot "${f}")|mode $(bo_mode "${f}" || echo '?')"); done < <(bo_find "${sysroots[@]}" ${homeroot[@]+"${homeroot[@]}"} -xdev -type d -perm -0002 ! -perm -1000)
    while IFS= read -r f; do [[ -n "${f}" ]] && orphan+=("file|$(bo_unroot "${f}")|no owning user or group"); done < <(bo_find "${sysroots[@]}" -xdev \( -nouser -o -nogroup \))
    while IFS= read -r f; do [[ -n "${f}" ]] && hidden+=("file|$(bo_unroot "${f}")|name made of dots/spaces"); done < <(bo_find "${sysroots[@]}" -xdev \( -name '...*' -o -name '.. *' -o -name '. *' \))
  fi
  if ((${#tmproots[@]} > 0)); then
    while IFS= read -r f; do [[ -n "${f}" ]] && exe+=("file|$(bo_unroot "${f}")|mode $(bo_mode "${f}" || echo '?')"); done < <(bo_find "${tmproots[@]}" -xdev -type f \( -perm -0100 -o -perm -0010 -o -perm -0001 \))
    while IFS= read -r f; do [[ -n "${f}" ]] && hidden+=("file|$(bo_unroot "${f}")|name made of dots/spaces"); done < <(bo_find "${tmproots[@]}" -xdev \( -name '...*' -o -name '.. *' -o -name '. *' \))
  fi
  ((${#ww[@]} > 0)) && bo_finding FS-PERM-001 medium high filesystem "World-writable files in system directories" \
    "Any user can modify these files." "Remove other-write (chmod o-w) after confirming no service depends on it." "T1222.002" "${ww[@]}"
  ((${#wwd[@]} > 0)) && bo_finding FS-PERM-002 medium high filesystem "World-writable directories without sticky bit" \
    "Users can delete or replace each other's files here." "chmod +t or remove other-write." "T1222.002" "${wwd[@]}"
  ((${#exe[@]} > 0)) && bo_finding FS-PERM-003 high medium filesystem "Executable files in temporary directories" \
    "Executables in /tmp, /var/tmp and /dev/shm are a typical malware staging pattern." \
    "Preserve and hash the files, then investigate who created them." "T1036" "${exe[@]}"
  ((${#orphan[@]} > 0)) && bo_finding FS-PERM-004 low medium filesystem "Files with no owning user or group" \
    "Orphaned files can follow deleted accounts or extracted archives." "Review and reassign." "" "${orphan[@]}"
  ((${#hidden[@]} > 0)) && bo_finding FS-HIDDEN-001 medium medium filesystem "Files or directories with deceptive names" \
    "Names consisting of dots or beginning with dot-space are used to hide data from casual listing." "Inspect the contents." "T1564.001" "${hidden[@]}"

  # Critical file modes: PATH, bits that must NOT be set, severity.
  local spec path bits sev mode
  for spec in "/etc/passwd:022:high" "/etc/group:022:high" "/etc/shadow:007:high" "/etc/gshadow:007:high" "/etc/sudoers:022:high" \
    "/etc/ssh/sshd_config:022:medium" "/etc/crontab:022:medium" "/root:007:low"; do
    IFS=: read -r path bits sev <<<"${spec}"
    [[ -e "$(bo_path "${path}")" ]] || continue
    mode="$(bo_mode "$(bo_path "${path}")" || true)"
    [[ -n "${mode}" ]] || continue
    if bo_mode_has "${mode}" "${bits}"; then crit+=("${sev}|${path}|mode ${mode}"); fi
  done
  if ((${#crit[@]} > 0)); then
    local item top=low ev=()
    for item in "${crit[@]}"; do
      IFS='|' read -r sev path mode <<<"${item}"
      (($(bo_sev_rank "${sev}") > $(bo_sev_rank "${top}"))) && top="${sev}"
      ev+=("file|${path}|${mode}")
    done
    bo_finding FS-MODE-001 "${top}" high filesystem "Unsafe permissions on sensitive system files" \
      "Sensitive files should not be writable by group/other (shadow files not readable by other either)." \
      "Restore distribution defaults (e.g. chmod 0644 passwd/group, 0640 shadow, 0440 sudoers) after checking ownership." "T1222.002" "${ev[@]}"
  fi
  return 0
}

# Opt-in (--package-integrity): compares installed files with the checksums recorded by their
# packages. Backends: `dpkg --verify` (Debian family) or `rpm -Va` (RHEL/SUSE family); both are
# read-only but hash every packaged file. Trust limit, stated in the findings: the checksums live
# in the package database on the same host (dpkg: MD5 lists under /var/lib/dpkg/info, rpm: the
# database under /var/lib/rpm), so an attacker with root can rewrite file and checksum together.
# The check finds sloppy tampering and unplanned changes, not a careful root-level compromise.
# dpkg rows: "??5??????   /path", "??5?????? c /conffile", "missing     /path".
# rpm rows:  "S.5....T.  c /conffile", ".M.......    /path", "missing   c /path"
# (attribute letter c/d/g/l/r after the nine flag characters).
_fs_pkg() {
  local backend="" tool_note
  if bo_have dpkg && [[ -r "$(bo_path /var/lib/dpkg/status)" ]]; then
    backend=dpkg
    tool_note="dpkg --verify compares MD5 sums from /var/lib/dpkg/info/*.md5sums (MD5 is weak and the lists are root-writable)"
  elif bo_have rpm && [[ -d "$(bo_path /var/lib/rpm)" || -d "$(bo_path /usr/lib/sysimage/rpm)" ]]; then
    backend=rpm
    tool_note="rpm -Va compares each package's own digests (SHA-256 for current packages) from the rpm database, which is root-writable"
  else
    bo_error PKG_UNSUPPORTED "--package-integrity supports dpkg (Debian family) and rpm (RHEL/SUSE family) databases; neither was found, check skipped" "FS-PKG-001"
    return 0
  fi
  if ! bo_is_root && [[ -z "${BO_ROOT:-}" ]]; then
    # The package tools cannot read root-only files (e.g. /etc/sudoers) and report them as changed.
    bo_error PKG_NEEDS_ROOT "--package-integrity needs root: ${backend} misreports files it cannot read; check skipped" "FS-PKG-001"
    return 0
  fi
  local out="${BO_SCRATCH}/pkg.txt" err="${BO_SCRATCH}/pkg.err" kind flags path rest attr
  local -a lim=()
  if bo_have timeout; then lim=(timeout 1800); fi
  if [[ "${backend}" == dpkg ]]; then
    "${lim[@]+"${lim[@]}"}" dpkg --verify >"${out}" 2>"${err}" || true
  else
    "${lim[@]+"${lim[@]}"}" rpm -Va >"${out}" 2>"${err}" || true
  fi
  if [[ -s "${err}" ]]; then
    bo_perm_error "${backend} verification reported errors (e.g. unreadable files); results may be incomplete" "FS-PKG-001"
  fi
  local -a crit=() other=() sens=()
  local nconf=0 ndoc=0
  while IFS=' ' read -r flags rest; do
    [[ -n "${flags}" ]] || continue
    kind=modified
    [[ "${flags}" == missing ]] && kind=missing
    # rpm differences that are only metadata (mode, owner, time) are routine and not "tampered".
    if [[ "${backend}" == rpm && "${kind}" == modified && "${flags}" != *[5SL]* ]]; then kind=metadata; fi
    attr=""
    if [[ "${rest}" =~ ^([cdglr])[[:space:]]+(.*)$ ]]; then
      attr="${BASH_REMATCH[1]}"
      rest="${BASH_REMATCH[2]}"
    fi
    path="${rest#"${rest%%[![:space:]]*}"}"
    if [[ "${attr}" == c ]]; then
      # Conffiles change legitimately, but not these: they are authentication, remote
      # access, scheduling, boot and privilege configuration.
      case "${path}" in
        /etc/pam.d/* | /etc/pam.conf | /etc/security/* | /etc/ssh/* | /etc/sudoers | /etc/sudoers.d/* | /etc/cron* | /etc/init.d/* | /etc/systemd/* | /etc/ld.so* | /etc/profile | /etc/profile.d/* | /etc/bash.bashrc | /etc/rc.local | /etc/ssl/* | /etc/ca-certificates* | /etc/apt/* | /etc/nsswitch.conf | /etc/hosts.allow | /etc/hosts.deny)
          sens+=("file|${path}|${kind} ${flags}")
          ;;
        *) nconf=$((nconf + 1)) ;;
      esac
      continue
    fi
    if [[ "${attr}" == [dlr] || "${attr}" == g ]]; then
      ndoc=$((ndoc + 1))
      continue
    fi
    case "${path}" in
      /usr/share/doc/* | /usr/share/man/* | /usr/share/info/* | /usr/share/locale/*)
        ndoc=$((ndoc + 1))
        continue
        ;;
      /bin/* | /sbin/* | /usr/bin/* | /usr/sbin/* | /lib/* | /lib64/* | /usr/lib/* | /usr/lib64/* | /usr/local/bin/* | /boot/*)
        if [[ "${kind}" == modified ]]; then crit+=("file|${path}|${flags}"); else other+=("file|${path}|${kind} ${flags}"); fi
        ;;
      *) other+=("file|${path}|${kind} ${flags}") ;;
    esac
  done <"${out}"
  bo_finding FS-PKG-003 info high filesystem "Package integrity summary" \
    "${backend}: ${#crit[@]} modified program/library file(s), ${#other[@]} other discrepancy(ies); ${#sens[@]} modified security-sensitive configuration file(s); ${nconf} other modified configuration file(s) and ${ndoc} documentation file(s) not listed (expected to change). Trust limit: ${tool_note}." "" ""
  ((${#crit[@]} > 0)) && bo_finding FS-PKG-001 high medium filesystem "Installed programs or libraries differ from their package checksums" \
    "Flags: 5 = content digest changed, S size, T mtime, U/G owner. Content changes outside a package upgrade indicate trojanized binaries. ${tool_note}." \
    "Reinstall the package from a trusted source after preserving the file (apt install --reinstall PKG / dnf reinstall PKG)." "T1554" "${crit[@]}"
  ((${#sens[@]} > 0)) && bo_finding FS-PKG-004 medium low filesystem "Security-sensitive configuration differs from the package default" \
    "Packaged configuration under PAM, SSH, sudo, cron, systemd, boot scripts and TLS trust. Local administrators change these on purpose; so do attackers." \
    "Compare with a known-good copy (dpkg-query/apt-get download or rpm2cpio) and your change log." "T1556.003" "${sens[@]}"
  ((${#other[@]} > 0)) && bo_finding FS-PKG-002 medium low filesystem "Other packaged files modified or missing" \
    "Files outside the main program directories, packaged files that were removed, and (rpm) metadata-only differences." \
    "Compare with your change log; reinstall the owning package if the change is unexplained." "T1565.001" "${other[@]}"
  return 0
}

mod_filesystem() {
  _fs_suid
  _fs_recent
  _fs_perms
  if [[ "${BO_PKG_CHECK}" == 1 ]]; then _fs_pkg; fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  rc=0
  bo_cli_main audit-filesystem audit filesystem 0 "$@" || rc=$?
  exit "${rc}"
fi
