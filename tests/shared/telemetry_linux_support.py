"""A synthetic Linux root with processes, sockets and logs for the telemetry collector tests."""

from __future__ import annotations

import os
from pathlib import Path

from engine_support import collector_env, linux_fixture_root

COLLECTOR = Path(__file__).resolve().parents[2] / "linux" / "telemetry" / "collect-telemetry.sh"

AUTH_LOG = """\
2026-03-01T09:00:01+00:00 web01 sshd[100]: Failed password for root from 198.51.100.4 port 40000 ssh2
2026-03-01T09:00:02+00:00 web01 sshd[100]: Failed password for invalid user admin from 198.51.100.4 port 40001 ssh2
2026-03-01T09:00:03+00:00 web01 sshd[100]: Failed password for alice from 198.51.100.4 port 40002 ssh2
2026-03-01T09:00:04+00:00 web01 sshd[100]: Failed password for root from 198.51.100.4 port 40003 ssh2
2026-03-01T09:00:05+00:00 web01 sshd[100]: Failed password for invalid user admin from 198.51.100.4 port 40004 ssh2
2026-03-01T09:00:06+00:00 web01 sshd[100]: Failed password for alice from 198.51.100.4 port 40005 ssh2
2026-03-01T09:00:07+00:00 web01 sshd[100]: Failed password for root from 198.51.100.4 port 40006 ssh2
2026-03-01T09:00:08+00:00 web01 sshd[100]: Failed password for invalid user admin from 198.51.100.4 port 40007 ssh2
2026-03-01T09:00:09+00:00 web01 sshd[100]: Failed password for alice from 198.51.100.4 port 40008 ssh2
2026-03-01T09:00:10+00:00 web01 sshd[100]: Failed password for root from 198.51.100.4 port 40009 ssh2
2026-03-01T09:00:11+00:00 web01 sshd[100]: Failed password for admin from 198.51.100.4 port 40010 ssh2
2026-03-01T09:00:12+00:00 web01 sshd[100]: Failed password for alice from 198.51.100.4 port 40011 ssh2
2026-03-01T09:05:00+00:00 web01 sshd[101]: Accepted password for alice from 198.51.100.4 port 40100 ssh2
2026-03-01T09:06:00+00:00 web01 sshd[102]: Accepted publickey for root from 203.0.113.77 port 50000 ssh2
2026-03-01T09:07:00+00:00 web01 useradd[300]: new user: name=backdoor, UID=1500, GID=1500, home=/home/backdoor, shell=/bin/bash
2026-03-01T09:07:05+00:00 web01 usermod[301]: add 'backdoor' to group 'sudo'
2026-03-01T09:08:00+00:00 web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
2026-03-01T09:09:00+00:00 web01 sudo:   bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls
2026-03-01T09:10:00+00:00 web01 su[400]: (to root) alice on pts/0
2026-03-01T09:11:00+00:00 web01 su[401]: FAILED SU (to root) bob on pts/1
2026-03-01T09:12:00+00:00 web01 passwd[500]: password changed for alice
2026-03-01T09:13:00+00:00 web01 CRON[600]: pam_unix(cron:session): session opened for user root by (uid=0)
"""
# 1772356800 = 2026-03-01T09:20:00Z
AUDIT_LOG = """\
type=ADD_USER msg=audit(1772356800.101:900): pid=300 uid=0 auid=1000 ses=3 msg='op=adding user acct="backdoor" exe="/usr/sbin/useradd" res=success'
type=USER_AUTH msg=audit(1772356801.202:901): pid=310 uid=0 auid=1000 ses=3 msg='op=PAM:authentication acct="alice" exe="/usr/sbin/sshd" res=failed'
type=CONFIG_CHANGE msg=audit(1772356802.303:902): auid=1000 ses=3 op=remove_rule key="exec" res=1
type=SYSCALL msg=audit(1772356803.404:903): arch=c000003e syscall=59 success=yes
"""


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _proc(
    root: Path, pid: int, ppid: int, comm: str, uid: int, exe: str, cmdline: str, start: int
) -> None:
    d = root / "proc" / str(pid)
    d.mkdir(parents=True, exist_ok=True)
    (d / "stat").write_text(
        f"{pid} ({comm}) S {ppid} {pid} {pid} 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 {start} 1 1\n",
        encoding="utf-8",
    )
    (d / "status").write_text(
        f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n", encoding="utf-8"
    )
    (d / "cmdline").write_bytes(cmdline.replace(" ", "\0").encode() + b"\0")
    (d / "comm").write_text(comm + "\n", encoding="utf-8")
    link = d / "exe"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(exe)


def telemetry_root(dest: Path) -> Path:
    """The synthetic Linux root plus a web server running a reverse shell, a socket-owning agent
    in /dev/shm, authentication and audit logs, and an sshd configuration."""
    root = linux_fixture_root(dest)
    _proc(root, 400, 1, "nginx", 33, "/usr/sbin/nginx", "nginx: master process", 5000)
    _proc(root, 401, 400, "bash", 33, "/usr/bin/bash", "bash -i password=hunter2", 5100)
    _proc(root, 402, 1, "agent", 33, "/dev/shm/.x/agent (deleted)", "/dev/shm/.x/agent", 5200)
    # socket ownership: inode -> pid through /proc/<pid>/fd symlinks
    for pid, inode in ((401, 777001), (402, 777002)):
        fd = root / "proc" / str(pid) / "fd"
        fd.mkdir(exist_ok=True)
        (fd / "3").symlink_to(f"socket:[{inode}]")
    tcp = root / "proc" / "net" / "tcp"
    tcp.write_text(
        tcp.read_text(encoding="utf-8")
        + " 3: 0500000A:9C41 097100CB:115C 01 00000000:00000000 00:00000000 00000000    33        0 777001 1 0\n"
        + " 4: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 777002 1 0\n",
        encoding="utf-8",
    )
    _write(
        root,
        "proc/net/tcp6",
        "  sl  local_address                         remote_address                        st\n   0: 00000000000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9 1 0\n   1: 0000000000000000FFFF00000100007F:0051 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10 1 0\n",
    )
    _write(root, "var/log/auth.log", AUTH_LOG)
    _write(root, "var/log/audit/audit.log", AUDIT_LOG)
    _write(
        root,
        "etc/ssh/sshd_config",
        "# comment\nPermitRootLogin yes\nPasswordAuthentication yes\nMatch User bob\n    PermitRootLogin no\n",
    )
    return root


def env_for(root: Path) -> dict[str, str]:
    env = collector_env(root)
    env.pop("BO_UPDATE_GOLDEN", None)
    return env


def tree_digest(root: Path) -> dict[str, tuple[int, int]]:
    """Path -> (size, mtime_ns) of every file and link under ``root`` (to prove read-only runs)."""
    out = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            st = p.lstat()
            out[str(p.relative_to(root))] = (st.st_size, st.st_mtime_ns)
    return out
