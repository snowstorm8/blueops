"""Load audit reports into canonical, comparable inventory snapshots.

Reports are attacker-influenced input (they describe a possibly compromised host),
so everything is validated defensively and anything that cannot be trusted lowers
the *coverage* of its domain instead of silently disappearing: a dropped record
would otherwise be reported as a removal.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from shared.reporting.contracts import (
    COVERAGE_STATUSES,
    INVENTORY_DOMAINS,
    READABLE_REPORT_VERSIONS,
)
from shared.reporting.jsonio import (  # noqa: F401 - re-exported for callers of this module
    JsonInputError,
    load_json_strict,
    no_duplicate_keys,
    reject_constant,
)
from shared.reporting.manifest import verify_run_dir

MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 200_000
MAX_KEY_LEN = 1024
MAX_VALUE_LEN = 8192
MAX_LIST_LEN = 4096

# Domains whose records legitimately repeat under one key (many processes share a name,
# many sockets share a bind address); duplicates are merged instead of flagged.
MERGEABLE_DOMAINS = ("processes", "listeners")

DEFAULT_EPHEMERAL_FROM = {"linux": 32768, "windows": 49152}
DEFAULT_TRANSIENT_PROCESSES = (
    "awk",
    "cat",
    "cut",
    "find",
    "grep",
    "head",
    "ps",
    "readlink",
    "sed",
    "sleep",
    "sort",
    "ss",
    "stat",
    "tail",
    "tr",
    # Windows read-only console helpers (still required to run from System32/SysWOW64).
    "findstr.exe",
    "hostname.exe",
    "ipconfig.exe",
    "netstat.exe",
    "tasklist.exe",
    "timeout.exe",
    "where.exe",
    "whoami.exe",
    "wmic.exe",
)

Value = Optional[Union[str, tuple[str, ...]]]

_TS_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?Z$")
_VERSION_RE = re.compile(r"^0\.(\d+)\.(\d+)$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class ReportError(ValueError):
    """The input is not a usable BlueOps audit report."""


@dataclass(frozen=True)
class Options:
    """Comparison options; see ``docs/baseline-diff.md`` for the config file format."""

    ephemeral_from: int | None = None
    fixed_ports: frozenset[int] = frozenset()
    transient_processes: frozenset[str] = frozenset(DEFAULT_TRANSIENT_PROCESSES)
    ignore: dict[str, tuple[str, ...]] = field(default_factory=dict)
    allow_host_mismatch: bool = False
    max_records: int = MAX_RECORDS


@dataclass
class Record:
    domain: str
    key: str
    attrs: dict[str, Value]
    volatile: dict[str, Value] = field(default_factory=dict)
    evidence: tuple[tuple[str, str], ...] = ()
    conflict: str = ""
    scope: str = ""


@dataclass
class RunMeta:
    run_id: str
    tool: str
    tool_version: str
    schema_version: str
    started_at: str
    finished_at: str
    hostname: str
    os_family: str
    os_name: str
    os_version: str
    elevated: bool | None
    exit_code: int | None
    source: str = ""
    test_mode: bool = False


@dataclass
class Snapshot:
    meta: RunMeta
    records: dict[tuple[str, str, str], Record]
    coverage: dict[tuple[str, str], tuple[str, str]]  # (domain, scope) -> (status, reason)
    findings: list[dict[str, Any]]
    warnings: list[dict[str, str]]
    has_inventory: bool
    ignored: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)


# ------------------------------------------------------------------ parsing helpers


def parse_timestamp(value: str) -> datetime:
    m = _TS_RE.match(value)
    if not m:
        raise ReportError(f"not an ISO 8601 UTC timestamp: {value!r}")
    try:
        parts = [int(g) for g in m.groups()]
        return datetime(*parts, tzinfo=timezone.utc)
    except ValueError as exc:
        raise ReportError(f"invalid timestamp {value!r}: {exc}") from None


def read_report_file(path: str | Path) -> dict[str, Any]:
    """Read and parse a report file (or a run directory containing ``report.json``)."""
    p = Path(path)
    if p.is_dir():
        p = p / "report.json"
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise ReportError(f"cannot read {p}: {exc.strerror or exc}") from None
    if size > MAX_REPORT_BYTES:
        raise ReportError(f"{p} is {size} bytes; the limit is {MAX_REPORT_BYTES}")
    try:
        # utf-8-sig: Windows PowerShell 5.1 writes a BOM.
        text = p.read_text(encoding="utf-8-sig")
        data = json.loads(text, object_pairs_hook=no_duplicate_keys, parse_constant=reject_constant)
    except (OSError, UnicodeDecodeError) as exc:
        raise ReportError(f"cannot read {p}: {exc}") from None
    except (ValueError, RecursionError) as exc:
        raise ReportError(f"{p} is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ReportError(f"{p}: top level must be a JSON object")
    return data


def _obj(parent: dict[str, Any], key: str, ctx: str) -> dict[str, Any]:
    v = parent.get(key)
    if not isinstance(v, dict):
        raise ReportError(f"{ctx}.{key} is missing or not an object")
    return v


def _text(parent: dict[str, Any], key: str, ctx: str) -> str:
    v = parent.get(key)
    if not isinstance(v, str) or not v:
        raise ReportError(f"{ctx}.{key} is missing or not a non-empty string")
    return v


def _parse_meta(data: dict[str, Any], source: str) -> RunMeta:
    version = _text(data, "schema_version", "report")
    m = _VERSION_RE.match(version)
    if not m or f"0.{m.group(1)}" not in READABLE_REPORT_VERSIONS:
        raise ReportError(
            f"unsupported schema_version {version!r}; this tool reads "
            + ", ".join(f"{v}.x" for v in READABLE_REPORT_VERSIONS)
        )
    tool = _obj(data, "tool", "report")
    run = _obj(data, "run", "report")
    host = _obj(data, "host", "report")
    os_info = _obj(host, "os", "report.host")
    started = _text(run, "started_at", "report.run")
    finished = _text(run, "finished_at", "report.run")
    parse_timestamp(started)
    parse_timestamp(finished)
    family = _text(os_info, "family", "report.host.os")
    elevated = host.get("elevated")
    exit_code = run.get("exit_code")
    return RunMeta(
        run_id=_text(run, "id", "report.run"),
        tool=_text(tool, "name", "report.tool"),
        tool_version=_text(tool, "version", "report.tool"),
        schema_version=version,
        started_at=started,
        finished_at=finished,
        hostname=_text(host, "hostname", "report.host"),
        os_family=family.lower(),
        os_name=str(os_info.get("name", "")),
        os_version=str(os_info.get("version", "")),
        elevated=elevated if isinstance(elevated, bool) else None,
        exit_code=exit_code
        if isinstance(exit_code, int) and not isinstance(exit_code, bool)
        else None,
        source=source,
        test_mode=host.get("test_mode") is True,
    )


# --------------------------------------------------------------- value normalisation


def _norm_scalar(v: Any) -> str | None:
    """Scalars compare as text so ``1``, ``"1"`` and ``true``/``"true"`` agree across producers."""
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        if len(v) > MAX_VALUE_LEN:
            raise ValueError("value too long")
        return v
    raise ValueError(f"unsupported value type {type(v).__name__}")


def _norm_value(v: Any) -> Value:
    if isinstance(v, list):
        if len(v) > MAX_LIST_LEN:
            raise ValueError("list too long")
        items = [_norm_scalar(x) for x in v]
        if any(x is None for x in items):
            return None  # a list with unknown members is not a trustworthy set
        return tuple(sorted(set(items)))  # type: ignore[arg-type]
    return _norm_scalar(v)


def _norm_map(raw: Any) -> dict[str, Value]:
    if not isinstance(raw, dict):
        raise ValueError("attrs must be an object")
    return {str(k): _norm_value(v) for k, v in raw.items()}


def _parse_record(raw: Any) -> Record:
    if not isinstance(raw, dict):
        raise ValueError("record is not an object")
    domain = raw.get("domain")
    key = raw.get("key")
    if domain not in INVENTORY_DOMAINS:
        raise LookupError(str(domain))
    if not isinstance(key, str) or not key or len(key) > MAX_KEY_LEN or _CONTROL_RE.search(key):
        raise ValueError("record key is missing, too long, or contains control characters")
    scope = raw.get("scope", "")
    if not isinstance(scope, str) or len(scope) > MAX_KEY_LEN or _CONTROL_RE.search(scope):
        raise ValueError("record scope must be a short string without control characters")
    attrs = _norm_map(raw.get("attrs"))
    volatile = _norm_map(raw.get("volatile", {}))
    ev: list[tuple[str, str]] = []
    for e in raw.get("evidence", []) or []:
        if isinstance(e, dict) and isinstance(e.get("ref"), str):
            ev.append((str(e.get("type", "other")), e["ref"]))
    return Record(domain, key, attrs, volatile, tuple(ev), scope=scope)


# ------------------------------------------------------------------ canonicalisation


def is_loopback_address(bind: str) -> bool:
    """True for ``localhost``, 127.0.0.0/8, ``::1`` and IPv4-mapped loopback (``::ffff:127.x``).

    Parsed, not prefix-matched: ``127.evil``, ``::1f00:1`` and the wildcards ``0.0.0.0``/``::``
    are not loopback.
    """
    b = bind.strip().strip("[]").split("%", 1)[0]
    if b.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(b)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback


def _is_loopback(bind: str) -> bool:
    return is_loopback_address(bind)


def as_set(v: Value) -> frozenset[str]:
    if v is None:
        return frozenset()
    return frozenset(v) if isinstance(v, tuple) else frozenset((v,))


def _merge_values(values: list[Value]) -> Value:
    """Union of per-instance values; any unknown instance makes the whole set unknown."""
    if any(v is None for v in values):
        return None
    merged: set = set()
    for v in values:
        merged |= as_set(v)
    return tuple(sorted(merged))


def _merge_group(records: list[Record]) -> Record:
    first = records[0]
    names = sorted({n for r in records for n in r.attrs})
    attrs = {n: _merge_values([r.attrs.get(n) for r in records]) for n in names}
    volatile = {"count": str(len(records))}
    for n in sorted({n for r in records for n in r.volatile}):
        vals = [r.volatile[n] for r in records if r.volatile.get(n) is not None]
        merged = _merge_values(list(vals))
        volatile[n] = merged[:20] if isinstance(merged, tuple) else merged  # type: ignore[assignment]
    ev = tuple(sorted({e for r in records for e in r.evidence}))
    return Record(first.domain, first.key, attrs, volatile, ev, scope=first.scope)


def _ephemeral_threshold(family: str, options: Options) -> int:
    if options.ephemeral_from is not None:
        return options.ephemeral_from
    return DEFAULT_EPHEMERAL_FROM.get(family, 49152)


def _listener_identity(rec: Record, threshold: int, fixed: frozenset[int]) -> Record:
    """Re-key listeners on ephemeral ports so a port that moves between runs is not a change."""
    port = as_set(rec.attrs.get("port"))
    bind = as_set(rec.attrs.get("bind"))
    proto = as_set(rec.attrs.get("proto"))
    if len(port) != 1 or len(bind) != 1 or len(proto) != 1:
        return rec
    p = next(iter(port))
    if not p.isdigit() or int(p) < threshold or int(p) in fixed:
        return rec
    b, pr = next(iter(bind)), next(iter(proto))
    attrs = {k: v for k, v in rec.attrs.items() if k != "port"}
    volatile = dict(rec.volatile)
    volatile["port"] = p
    return Record(
        rec.domain, f"listener:{pr}/{b}/ephemeral", attrs, volatile, rec.evidence, scope=rec.scope
    )


def _casefold_key(rec: Record, family: str) -> Record:
    if family == "windows":
        rec.key = rec.key.casefold()
    return rec


def is_loopback_listener(rec: Record) -> bool:
    binds = as_set(rec.attrs.get("bind"))
    return bool(binds) and all(_is_loopback(b) for b in binds)


def _ignored(rec: Record, options: Options, family: str) -> bool:
    key = rec.key.casefold() if family == "windows" else rec.key
    for pattern in options.ignore.get(rec.domain, ()):
        pat = pattern.casefold() if family == "windows" else pattern
        if fnmatch.fnmatchcase(key, pat):
            return True
    return False


def _canonical(rec: Record, family: str, threshold: int, fixed: frozenset[int]) -> Record:
    out = _casefold_key(rec, family)
    if out.domain == "listeners":
        out = _listener_identity(out, threshold, fixed)
    return out


def _group_records(
    recs: list[Record], family: str, threshold: int, fixed: frozenset[int] = frozenset()
) -> list[Record]:
    buckets: dict[tuple[str, str, str], list[Record]] = {}
    for raw in recs:
        rec = _canonical(raw, family, threshold, fixed)
        buckets.setdefault((rec.domain, rec.scope, rec.key), []).append(rec)
    out: list[Record] = []
    for (domain, _scope, _key), group in buckets.items():
        if domain in MERGEABLE_DOMAINS:
            out.append(_merge_group(group))
        else:
            out.append(_resolve_duplicates(group))
    return out


def _resolve_duplicates(group: list[Record]) -> Record:
    first = group[0]
    for other in group[1:]:
        if other.attrs != first.attrs:
            first.conflict = f"{len(group)} records share this key with different attributes"
            break
    return first


# ---------------------------------------------------------------- coverage handling


def _worst(a: str, b: str) -> str:
    return a if COVERAGE_STATUSES.index(a) >= COVERAGE_STATUSES.index(b) else b


Coverage = dict[tuple[str, str], tuple[str, str]]


def _parse_coverage(inv: dict[str, Any], warnings: list[dict[str, str]]) -> Coverage:
    cov: Coverage = {}
    raw_cov = inv.get("coverage", [])
    if not isinstance(raw_cov, list):
        raise ReportError("inventory.coverage is not a list")
    for item in raw_cov:
        domain = item.get("domain") if isinstance(item, dict) else None
        scope = item.get("scope", "") if isinstance(item, dict) else ""
        if domain not in INVENTORY_DOMAINS or not isinstance(scope, str):
            warnings.append(
                {"code": "BAD_COVERAGE", "message": f"ignored coverage entry for {domain!r}"}
            )
            continue
        status = item.get("status")
        reason = str(item.get("reason", ""))[:500]
        if status not in COVERAGE_STATUSES:
            status, reason = "partial", f"unknown coverage status {status!r}; {reason}".strip("; ")
        if (domain, scope) in cov:
            old_status, old_reason = cov[(domain, scope)]
            reason = "; ".join(r for r in (old_reason, reason) if r)
            status = _worst(old_status, status)
        cov[(domain, scope)] = (status, reason)
    return cov


def _degrade(cov: Coverage, domain: str, scope: str | None, reason: str) -> None:
    """Mark one partition (or, with ``scope=None``, every partition of the domain) partial."""
    targets = [k for k in cov if k[0] == domain and (scope is None or k[1] == scope)]
    if not targets:
        targets = [(domain, scope or "")]
    for key in targets:
        status, old = cov.get(key, ("complete", ""))
        cov[key] = (_worst(status, "partial"), "; ".join(r for r in (old, reason) if r))


def _skipped_domain(raw: Any) -> str:
    """Domain whose coverage an unparseable record taints ("*" when it cannot be trusted)."""
    if isinstance(raw, dict) and raw.get("domain") in INVENTORY_DOMAINS:
        return str(raw["domain"])
    return "*"


def _parse_records(
    inv: dict[str, Any], cov: Coverage, warnings: list[dict[str, str]], limit: int
) -> list[Record]:
    raw_records = inv.get("records", [])
    if not isinstance(raw_records, list):
        raise ReportError("inventory.records is not a list")
    recs: list[Record] = []
    bad: dict[str, int] = {}
    for i, raw in enumerate(raw_records):
        if i >= limit:
            warnings.append(
                {"code": "RECORD_LIMIT", "message": f"only the first {limit} records were read"}
            )
            for d in INVENTORY_DOMAINS:
                _degrade(cov, d, None, "record limit reached; later records not read")
            break
        try:
            recs.append(_parse_record(raw))
        except LookupError as exc:
            warnings.append(
                {"code": "UNKNOWN_DOMAIN", "message": f"skipped record with domain {exc}"}
            )
        except (ValueError, TypeError) as exc:
            domain = _skipped_domain(raw)
            bad[domain] = bad.get(domain, 0) + 1
            warnings.append({"code": "INVALID_RECORD", "message": f"record {i} skipped: {exc}"})
    for domain, n in bad.items():
        for d in INVENTORY_DOMAINS if domain == "*" else (domain,):
            _degrade(cov, d, None, f"{n} invalid record(s) skipped")
    return recs


def _object_list(data: dict[str, Any], key: str, ident: str) -> list[dict[str, Any]]:
    """A report list whose entries must all be objects; silently dropping one could hide a
    finding or an error and turn an unknown into a conclusion."""
    raw = data.get(key, [])
    if not isinstance(raw, list):
        raise ReportError(f"report.{key} is not a list")
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or not isinstance(item.get(ident), str):
            raise ReportError(f"report.{key}[{i}] is not an object with a string {ident!r}")
    return raw


def build_snapshot(data: dict[str, Any], options: Options, source: str = "") -> Snapshot:
    """Validate a parsed report and canonicalise its inventory."""
    meta = _parse_meta(data, source)
    findings = _object_list(data, "findings", "id")
    errors = _object_list(data, "errors", "code")
    warnings: list[dict[str, str]] = []
    if "inventory" not in data:
        return Snapshot(meta, {}, {}, findings, warnings, has_inventory=False, errors=errors)
    inv = data["inventory"]
    if not isinstance(inv, dict):
        raise ReportError("report.inventory is present but not an object")
    cov = _parse_coverage(inv, warnings)
    recs = _parse_records(inv, cov, warnings, options.max_records)
    for rec in recs:
        if (rec.domain, rec.scope) not in cov:
            cov[(rec.domain, rec.scope)] = ("partial", "no coverage declaration for this partition")
    kept: list[Record] = []
    ignored = 0
    for rec in recs:
        if _ignored(rec, options, meta.os_family):
            ignored += 1
        else:
            kept.append(rec)
    grouped = _group_records(
        kept, meta.os_family, _ephemeral_threshold(meta.os_family, options), options.fixed_ports
    )
    records = {(r.domain, r.scope, r.key): r for r in grouped}
    return Snapshot(meta, records, cov, findings, warnings, True, ignored=ignored, errors=errors)


def load_snapshot(path: str | Path, options: Options | None = None) -> Snapshot:
    """Load a report file or run directory.

    A run directory that carries ``manifest.json`` is verified first (every file's SHA-256 and
    size): a report that no longer matches its manifest is refused, not compared. A directory
    without a manifest (runs from before manifests existed) loads unverified; the comparison
    output is deliberately identical for a report file and its run directory.
    """
    opts = options or Options()
    p = Path(path)
    if p.is_dir() and (p / "manifest.json").exists():
        problems = verify_run_dir(p)
        if problems:
            shown = "; ".join(problems[:5]) + (" ..." if len(problems) > 5 else "")
            raise ReportError(f"{p} failed manifest verification: {shown}")
    return build_snapshot(read_report_file(path), opts, source=str(path))


class ConfigError(ValueError):
    """The comparison config file is malformed."""


def options_from_config(data: Any, base: Options | None = None) -> Options:
    """Build ``Options`` from a parsed config file (see ``docs/baseline-diff.md``)."""
    opts = base or Options()
    if not isinstance(data, dict):
        raise ConfigError("config must be a JSON object")
    unknown = set(data) - {"ephemeral_from", "fixed_ports", "transient_processes", "ignore"}
    if unknown:
        raise ConfigError(f"unknown config key(s): {', '.join(sorted(unknown))}")
    ephemeral = opts.ephemeral_from
    if "ephemeral_from" in data:
        ephemeral = data["ephemeral_from"]
        if (
            isinstance(ephemeral, bool)
            or not isinstance(ephemeral, int)
            or not 1 <= ephemeral <= 65536
        ):
            raise ConfigError("ephemeral_from must be an integer between 1 and 65536")
    fixed = opts.fixed_ports
    if "fixed_ports" in data:
        ports = data["fixed_ports"]
        if not isinstance(ports, list) or not all(
            isinstance(x, int) and not isinstance(x, bool) and 1 <= x <= 65535 for x in ports
        ):
            raise ConfigError("fixed_ports must be a list of integers between 1 and 65535")
        fixed = frozenset(ports)
    transient = opts.transient_processes
    if "transient_processes" in data:
        names = data["transient_processes"]
        if not isinstance(names, list) or not all(isinstance(n, str) and n for n in names):
            raise ConfigError("transient_processes must be a list of non-empty strings")
        transient = frozenset(names)
    ignore = dict(opts.ignore)
    for domain, patterns in (data.get("ignore") or {}).items():
        if domain not in INVENTORY_DOMAINS:
            raise ConfigError(f"ignore: unknown domain {domain!r}")
        if not isinstance(patterns, list) or not all(isinstance(p, str) and p for p in patterns):
            raise ConfigError(f"ignore.{domain} must be a list of non-empty glob strings")
        ignore[domain] = tuple(patterns)
    return Options(
        ephemeral_from=ephemeral,
        fixed_ports=fixed,
        transient_processes=transient,
        ignore=ignore,
        allow_host_mismatch=opts.allow_host_mismatch,
        max_records=opts.max_records,
    )
