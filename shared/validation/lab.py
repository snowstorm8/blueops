"""Live lab execution: gated, local, reversible, confined.

Nothing here runs unless *all* of these hold (otherwise it refuses, exit 3 or 5, and runs nothing):

1. ``--live`` was given (synthetic evaluation is the default and never touches the host);
2. ``--lab-dir`` names a directory created by ``validate lab init`` (a marker file with a random
   token; a symlink, a pre-existing non-empty directory or a protected path is refused);
3. isolation is *verified* (a recognised container or a GitHub-hosted runner) or the operator
   *attested* with ``--attest-disposable`` (recorded as "attested, not verified");
4. the operator confirmed (``--yes``, or typing ``yes``; without a TTY and without ``--yes`` the run
   is aborted with exit 5).

What a live scenario can do is a closed vocabulary of harmless actions, all implemented here (a
scenario file contains only names and small numbers): start a sleeping child process, start a chain
of child processes, start a child that listens on a loopback port. The children are this run's own
(never attached to other processes), run for a bounded time, are terminated in a ``finally`` block,
and the cleanup is verified. No file outside the lab directory is created, no network traffic
leaves the host (loopback only), no credential is read, no persistence is created.

Isolation verification is a safety interlock against accidents, not a security boundary: the
signals can be forged by anyone who controls the environment.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess  # noqa: S404 - fixed argv built from this module's own code, never a shell
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.engine.environment import sanitized_environment
from shared.engine.runner import current_platform
from shared.reporting.contracts import ExitCode
from shared.rules.cli import _err
from shared.telemetry.ingest import IngestError, build_document, read_stream, write_store
from shared.validation.evaluate import evaluate_scenario
from shared.validation.model import Scenario, ScenarioSet
from shared.validation.runner import assemble, host_info, utc_now

MARKER = ".blueops-lab"
MAX_SECONDS = 180
SETTLE_SECONDS = 2.0
TEMP_PATH = re.compile(
    r"(?i)^(/tmp/|/var/tmp/|/dev/shm/|/run/shm/)|\\(appdata\\local\\temp|windows\\temp|users\\public)\\"
)

CHAIN_CODE = (
    "import subprocess, sys, time\n"
    "depth, secs = int(sys.argv[1]), sys.argv[2]\n"
    "if depth > 0:\n"
    "    subprocess.Popen([sys.executable, '-I', __file__, str(depth - 1), secs])\n"
    "time.sleep(float(secs))\n"
)
LISTEN_CODE = (
    "import socket, sys, time\n"
    "s = socket.socket()\n"
    "s.bind(('127.0.0.1', 0))\n"
    "s.listen(1)\n"
    "print(s.getsockname()[1], flush=True)\n"
    "time.sleep(float(sys.argv[1]))\n"
)


class LabError(ValueError):
    """The lab is missing, unsafe or not verified; the message says what to fix."""


@dataclass
class Probes:
    """System probes, injectable so isolation logic is testable without a real container."""

    env: Mapping[str, str] = field(default_factory=lambda: dict(os.environ))
    exists: Callable[[str], bool] = os.path.exists
    read: Callable[[str], str] = lambda p: Path(p).read_text(encoding="utf-8", errors="replace")[
        :4000
    ]
    platform: str = sys.platform


# ------------------------------------------------------------------------------ isolation


def verify_isolation(probes: Probes | None = None, *, attest: bool = False) -> dict[str, Any]:
    """Evidence that this host is disposable. ``verified`` is true only for a recognised signal;
    an operator attestation is recorded separately and never reported as verification."""
    p = probes or Probes()
    evidence: list[str] = []
    if p.env.get("GITHUB_ACTIONS") == "true" and p.env.get("RUNNER_ENVIRONMENT") == "github-hosted":
        evidence.append("ci-hosted-runner: GitHub-hosted runner (ephemeral virtual machine)")
    if p.platform.startswith("linux"):
        if p.exists("/.dockerenv") or p.exists("/run/.containerenv"):
            evidence.append("container: container marker file present")
        try:
            cg = p.read("/proc/1/cgroup")
        except OSError:
            cg = ""
        if re.search(r"docker|kubepods|containerd|lxc|podman", cg):
            evidence.append("container: container cgroup of PID 1")
    verified = bool(evidence)
    problems = []
    if not verified and not attest:
        problems.append(
            "isolation cannot be verified: this does not look like a container or a hosted CI runner. If (and only if) this host is disposable, repeat with --attest-disposable; the result will say attested, not verified."
        )
    return {
        "verified": verified, "attested": attest and not verified, "method": "verified" if verified else ("attested" if attest else "none"),
        "evidence": evidence, "problems": problems, "allowed": verified or attest,
        "note": "a safety interlock against accidents, not a security boundary",
    }  # fmt: skip


# ------------------------------------------------------------------------------ lab directory


def unsafe_lab_path(path: Path) -> str | None:  # noqa: PLR0911 - one early return per refused location
    """Why ``path`` must not be a lab directory, or ``None``."""
    try:
        resolved = path.resolve()
    except OSError as exc:
        return f"cannot resolve the path: {exc.strerror or exc}"
    if path.is_symlink():
        return "the lab directory must not be a symbolic link"
    repo = Path(__file__).resolve().parents[2]
    home = Path.home().resolve()
    cwd = Path.cwd().resolve()
    if resolved == resolved.parent:
        return "a filesystem root cannot be a lab directory"
    for bad, why in ((home, "the home directory itself"), (cwd, "the current directory")):
        if resolved == bad:
            return f"{why} cannot be a lab directory"
    if resolved == repo or repo in resolved.parents or resolved in repo.parents:
        return "the lab directory must be outside the BlueOps checkout and not contain it"
    protected = (
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/boot",
        "/sys",
        "/proc",
        "/dev",
        "/root/.ssh",
        "c:\\windows",
        "c:\\program files",
    )
    low = str(resolved).lower()
    if any(
        low == pr or low.startswith(pr + os.sep) or low.startswith(pr + "/") for pr in protected
    ):
        return "a system directory cannot be a lab directory"
    return None


def init_lab(path: str | Path) -> Path:
    lab = Path(path)
    why = unsafe_lab_path(lab)
    if why:
        raise LabError(f"{lab}: {why}")
    if lab.exists() and any(lab.iterdir()):
        raise LabError(f"{lab} already exists and is not empty; a lab directory must be new")
    lab.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = {
        "kind": "blueops-lab",
        "token": secrets.token_hex(16),
        "created_at": utc_now(),
        "note": "created by 'validate lab init'; live scenarios may create files only below this directory",
    }
    fd = os.open(lab / MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(marker, indent=2) + "\n")
    return lab


def read_marker(lab_dir: str | Path | None) -> dict[str, Any]:
    if not lab_dir:
        raise LabError(
            "--lab-dir is required for live execution (create one with 'validate lab init DIR')"
        )
    lab = Path(lab_dir)
    why = unsafe_lab_path(lab)
    if why:
        raise LabError(f"{lab}: {why}")
    m = lab / MARKER
    if not lab.is_dir() or not m.is_file() or m.is_symlink():
        raise LabError(
            f"{lab}: not a lab directory (no {MARKER} marker); run 'validate lab init' first"
        )
    if os.name == "posix" and (m.stat().st_mode & 0o022):
        raise LabError(f"{m}: the marker is group/other-writable")
    try:
        data = json.loads(m.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LabError(f"{m}: unreadable marker ({exc})") from None
    if (
        not isinstance(data, dict)
        or data.get("kind") != "blueops-lab"
        or not re.fullmatch(r"[0-9a-f]{32}", str(data.get("token", "")))
    ):
        raise LabError(f"{m}: not a BlueOps lab marker")
    return data


# ------------------------------------------------------------------------------ preconditions


def _loopback_ok() -> bool:
    import socket  # noqa: PLC0415

    try:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


def precondition_failures(s: Scenario, host_family: str, *, lab_ok: bool) -> list[str]:
    out = []
    if host_family not in s.platforms:
        out.append(f"scenario supports {', '.join(s.platforms)}, this host is {host_family}")
    for pre in s.preconditions:
        kind, val = pre["kind"], pre.get("value", "")
        if kind == "os_family" and val and val != host_family:
            out.append(f"requires os_family {val}")
        elif kind == "tool" and not shutil.which(val):
            out.append(f"requires the tool {val!r}")
        elif kind == "python":
            want = tuple(int(x) for x in (val or "3.9").split(".")[:2])
            if sys.version_info[:2] < want:
                out.append(f"requires Python >= {val}")
        elif (
            kind == "privilege"
            and val == "root"
            and not (hasattr(os, "geteuid") and os.geteuid() == 0)
        ):
            out.append("requires root")
        elif kind == "loopback" and not _loopback_ok():
            out.append("loopback sockets are not available")
        elif kind == "lab" and not lab_ok:
            out.append("requires a verified lab")
        elif kind == "interpreter" and TEMP_PATH.search(sys.executable):
            out.append(
                f"the Python interpreter runs from a temporary location ({sys.executable}), which would make the temporary-location rules fire on the lab's own processes"
            )
    return out


# ------------------------------------------------------------------------------ session


class LabSession:
    """The processes and files one scenario creates; everything is released by ``cleanup``."""

    def __init__(self, work: Path) -> None:
        self.work = work
        self.children: list[subprocess.Popen[str]] = []
        self.pids: dict[str, int] = {}
        self.log: list[dict[str, Any]] = []
        work.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _note(self, **kw: Any) -> None:
        self.log.append({"at": utc_now(), **kw})

    def _spawn(self, argv: list[str], *, pipe: bool = False) -> subprocess.Popen[str]:
        kw: dict[str, Any] = {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE if pipe else subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "cwd": str(self.work),
            "text": True,
            "env": {
                k: v
                for k, v in sanitized_environment()[0].items()
                if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME")
            },
        }
        if os.name == "posix":
            kw["start_new_session"] = (
                True  # one process group per child: cleanup kills exactly this tree
            )
        else:
            kw["creationflags"] = 0x00000200  # CREATE_NEW_PROCESS_GROUP
        proc = subprocess.Popen(argv, **kw)  # noqa: S603 - argv is built from this module's constants
        self.children.append(proc)
        return proc

    @staticmethod
    def _bounded(seconds: int) -> int:
        if (
            not isinstance(seconds, int)
            or isinstance(seconds, bool)
            or not 1 <= seconds <= MAX_SECONDS
        ):
            raise LabError(f"duration must be 1..{MAX_SECONDS} seconds, got {seconds!r}")
        return seconds

    def spawn_sleeper(self, name: str, seconds: int) -> None:
        self._bounded(seconds)
        p = self._spawn(
            [
                sys.executable,
                "-I",
                "-c",
                "import sys, time; time.sleep(float(sys.argv[1]))",
                str(seconds),
            ]
        )
        self.pids[f"{name}_pid"] = p.pid
        self._note(action="spawn_sleeper", name=name, pid=p.pid, seconds=seconds)

    def spawn_chain(self, name: str, depth: int, seconds: int) -> None:
        self._bounded(seconds)
        script = self.work / "chain.py"
        script.write_text(CHAIN_CODE, encoding="utf-8")
        p = self._spawn([sys.executable, "-I", str(script), str(depth), str(seconds)])
        self.pids[f"{name}_pid"] = p.pid
        self._note(action="spawn_chain", name=name, pid=p.pid, depth=depth, seconds=seconds)

    def listen_loopback(self, name: str, seconds: int) -> None:
        self._bounded(seconds)
        script = self.work / "listener.py"
        script.write_text(LISTEN_CODE, encoding="utf-8")
        p = self._spawn([sys.executable, "-I", str(script), str(seconds)], pipe=True)
        box: list[str] = []
        t = threading.Thread(target=lambda: box.append(p.stdout.readline()), daemon=True)  # type: ignore[union-attr]
        t.start()
        t.join(15)
        if not box or not box[0].strip().isdigit():
            raise LabError("the loopback listener did not report its port within 15 seconds")
        self.pids[f"{name}_pid"] = p.pid
        self.pids[f"{name}_port"] = int(box[0])
        self._note(
            action="listen_loopback", name=name, pid=p.pid, port=int(box[0]), address="127.0.0.1"
        )

    def cleanup(self) -> dict[str, Any]:
        """Terminate exactly the children this session started and verify they are gone."""
        residual = []
        for p in self.children:
            if p.poll() is None:
                try:
                    if os.name == "posix":
                        import signal  # noqa: PLC0415

                        os.killpg(p.pid, signal.SIGKILL)
                    else:
                        root = os.environ.get("SYSTEMROOT", "C:\\Windows")
                        subprocess.run(  # noqa: S603 - fixed argv, our own pid
                            [
                                str(Path(root) / "System32" / "taskkill.exe"),
                                "/PID",
                                str(p.pid),
                                "/T",
                                "/F",
                            ],
                            capture_output=True,
                            timeout=30,
                            check=False,
                        )  # noqa: S603 - fixed argv, our own pid
                        p.kill()
                except (OSError, subprocess.SubprocessError):
                    p.kill()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                residual.append(p.pid)
            if p.stdout:
                p.stdout.close()
        for f in ("chain.py", "listener.py"):
            (self.work / f).unlink(missing_ok=True)
        self._note(action="cleanup", terminated=len(self.children), residual=residual)
        return {"ok": not residual, "terminated": len(self.children), "residual_pids": residual}


def descendants(tel: dict[str, Any], roots: set[int]) -> set[int]:
    kids: dict[int, list[int]] = {}
    for r in tel["records"]:
        if (
            r["category"] == "process"
            and isinstance(r["attributes"].get("ppid"), int)
            and isinstance(r["attributes"].get("pid"), int)
        ):
            kids.setdefault(r["attributes"]["ppid"], []).append(r["attributes"]["pid"])
    seen, stack = set(roots), list(roots)
    while stack:
        for k in kids.get(stack.pop(), []):
            if k not in seen:
                seen.add(k)
                stack.append(k)
    return seen


def lab_record_ids(tel: dict[str, Any], pids: set[int]) -> set[str]:
    return {
        r["record_id"]
        for r in tel["records"]
        if r["category"] in ("process", "listener", "network_connection")
        and r["attributes"].get("pid") in pids
    }


def collect_live(categories: list[str]) -> dict[str, Any]:
    import argparse  # noqa: PLC0415

    from shared.telemetry.cli import _collector_argv  # noqa: PLC0415 - shares the telemetry CLI's argv builder

    ns = argparse.Namespace(
        since_hours=1, max_events=200, categories=",".join(categories) if categories else None
    )
    argv = _collector_argv(current_platform(), ns)
    if isinstance(argv, str):
        raise LabError(argv)
    proc = subprocess.run(  # noqa: S603 - fixed argv from repository paths
        argv,
        capture_output=True,
        timeout=600,
        check=False,
        shell=False,
        env=sanitized_environment()[0],
    )  # noqa: S603 - fixed argv from repository paths
    try:
        raw = read_stream("lab-collector.jsonl", proc.stdout)
    except IngestError as exc:
        raise LabError(
            f"the collector produced no usable stream (exit {proc.returncode}): {exc}"
        ) from None
    if proc.returncode not in (0, 6):
        raw.errors.append(
            {"code": "COLLECTOR_EXIT", "message": f"collector exited with status {proc.returncode}"}
        )
    return build_document([raw], mode="live")


# ------------------------------------------------------------------------------ plans and runs


def _action_text(a: dict[str, Any]) -> str:
    return {
        "spawn_sleeper": "start a child process that only sleeps",
        "spawn_chain": "start a chain of child processes that only sleep",
        "listen_loopback": "start a child that listens on a loopback port",
    }[a["action"]] + f" ({a.get('name', 'unnamed')}, <= {a.get('seconds', 60)}s)"


def live_plan(chosen: list[Scenario], *, lab_dir: str | None, attest: bool) -> list[dict[str, Any]]:
    iso = verify_isolation(attest=attest)
    try:
        read_marker(lab_dir)
        lab_state = "lab directory ok"
    except LabError as exc:
        lab_state = f"NOT READY: {exc}"
    plan = []
    for s in chosen:
        plan.append(
            {
                "id": s.id,
                "action": "; ".join(_action_text(a) for a in (s.lab or {}).get("actions", []))
                or "collect telemetry only",
                "collect_categories": (s.lab or {}).get("collect_categories", "all"),
                "modifies_host": "only this run's own child processes and files below the lab directory; loopback only",
                "isolation": iso["method"],
                "lab": lab_state,
                "live_capable": s.live_capable,
            }
        )
    return plan


def run_live(
    chosen: list[Scenario], ss: ScenarioSet, rs: Any, *, lab_dir: str | None, attest: bool, assume_yes: bool, command: str, recommend: Callable[[dict[str, Any]], list[dict[str, Any]]] | None = None, probes: Probes | None = None, stdin_is_tty: bool | None = None,
) -> tuple[dict[str, Any] | None, int]:  # fmt: skip
    """Returns ``(results, exit_code)``; ``results`` is ``None`` when nothing was run."""
    live = [s for s in chosen if s.live_capable]
    if not live:
        _err(
            "none of the selected scenarios has a lab section; live execution applies to lab scenarios only (see 'validate list')"
        )
        return None, int(ExitCode.PRECONDITION)
    try:
        marker = read_marker(lab_dir)
    except LabError as exc:
        _err(str(exc))
        return None, int(ExitCode.PRECONDITION)
    iso = verify_isolation(probes, attest=attest)
    if not iso["allowed"]:
        for p in iso["problems"]:
            _err(p)
        return None, int(ExitCode.PRECONDITION)
    tty = sys.stdin.isatty() if stdin_is_tty is None else stdin_is_tty
    sys.stderr.write(
        f"LIVE LAB RUN: {len(live)} scenario(s) will start harmless child processes on THIS host (isolation: {iso['method']}).\n"
    )
    for item in live_plan(live, lab_dir=lab_dir, attest=attest):
        sys.stderr.write(f"  {item['id']}: {item['action']}\n")
    if not assume_yes:
        if not tty:
            _err("not confirmed: pass --yes to run live scenarios without a terminal")
            return None, int(ExitCode.ABORTED)
        if input('Type "yes" to continue: ').strip().lower() != "yes":
            _err("declined")
            return None, int(ExitCode.ABORTED)
    started = utc_now()
    run_id = f"live-{started.replace('-', '').replace(':', '')}-{marker['token'][:6]}"
    evidence = Path(lab_dir or ".") / "runs" / run_id
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    host = current_platform()
    results = []
    for s in chosen:
        if not s.live_capable:
            results.append(_skipped(s, "no lab section: not a live scenario"))
            continue
        why = precondition_failures(s, host, lab_ok=True)
        if why:
            results.append(_skipped(s, "; ".join(why)))
            continue
        results.append(_run_one(s, rs, evidence))
    doc = assemble(
        results,
        ss,
        rs,
        mode="live",
        started_at=started,
        command=command,
        isolation={**iso, "lab_token_prefix": marker["token"][:6]},
        recommend=recommend,
    )
    doc["run"]["host"] = host_info()
    (evidence / "results.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    _err(f"evidence preserved in {evidence}")
    return doc, 0


def _skipped(s: Scenario, reason: str) -> dict[str, Any]:
    return {"id": s.id, "title": s.title, "kind": s.kind, "platforms": list(s.platforms), "dataset_platform": s.dataset_platform, "pack": s.pack, "sha256": s.sha256, "status": "skipped", "reason": reason, "checks": [], "outcomes": [], "detections": [], "indeterminate": [], "rule_errors": [], "telemetry": {}, "limitations": list(s.limitations)}  # fmt: skip


def _run_one(s: Scenario, rs: Any, evidence: Path) -> dict[str, Any]:
    session = LabSession(evidence / "work" / s.id)
    res: dict[str, Any]
    try:
        for a in (s.lab or {}).get("actions", []):
            secs = int(a.get("seconds", 60))
            name = a.get("name", "lab")
            if a["action"] == "spawn_sleeper":
                session.spawn_sleeper(name, secs)
            elif a["action"] == "spawn_chain":
                session.spawn_chain(name, int(a.get("depth", 2)), secs)
            else:
                session.listen_loopback(name, secs)
        time.sleep(SETTLE_SECONDS)  # let the started processes reach their steady state
        tel = collect_live((s.lab or {}).get("collect_categories", []))
        write_store(tel, evidence / "telemetry" / s.id)
        subs = {"runner_pid": os.getpid(), **session.pids}
        owned = descendants(tel, {v for k, v in session.pids.items() if k.endswith("_pid")})
        res = evaluate_scenario(
            s, rs, substitutions=subs, tel=tel, scope_record_ids=lab_record_ids(tel, owned)
        )
    except (LabError, OSError, subprocess.SubprocessError) as exc:
        res = _skipped(s, "")
        res["status"], res["reason"] = "error", f"live execution failed: {exc}"
    finally:
        clean = session.cleanup()
        (session.work / "actions.jsonl").write_text(
            "".join(json.dumps(x) + "\n" for x in session.log), encoding="utf-8"
        )
    res["cleanup"] = clean
    res["live"] = {"actions": session.log}
    if not clean["ok"]:
        res["status"], res["reason"] = (
            "error",
            f"cleanup incomplete: processes still running {clean['residual_pids']}",
        )
    return res


# ------------------------------------------------------------------------------ CLI glue


def lab_command(args: Any) -> int:
    try:
        if args.lab_cmd == "init":
            lab = init_lab(args.lab_dir)
            sys.stdout.write(
                f"lab directory ready: {lab}\nlive scenarios may create files only below it. Run them with --live --lab-dir {lab}\n"
            )
            return int(ExitCode.OK)
        iso = verify_isolation(attest=args.attest_disposable)
        state = {"isolation": iso, "lab": None}
        if args.lab_dir:
            try:
                read_marker(args.lab_dir)
                state["lab"] = "ok"
            except LabError as exc:
                state["lab"] = f"not ready: {exc}"
        if args.format == "json":
            sys.stdout.write(json.dumps(state, indent=2) + "\n")
        else:
            sys.stdout.write(
                f"isolation: {iso['method']} ({'; '.join(iso['evidence']) or 'no signal'})\n"
            )
            sys.stdout.writelines(f"  {p}\n" for p in iso["problems"])
            if args.lab_dir:
                sys.stdout.write(f"lab directory: {state['lab']}\n")
        ready = iso["allowed"] and (not args.lab_dir or state["lab"] == "ok")
        return int(ExitCode.OK if ready else ExitCode.PRECONDITION)
    except LabError as exc:
        _err(str(exc))
        return int(ExitCode.PRECONDITION)
