"""Ingestion: read collector output, validate, normalize, deduplicate and summarize.

Inputs (all untrusted):

* a collector **stream** (JSON Lines, ``type`` = header / record / coverage / error / end),
* a normalized **telemetry document** (re-validated and re-normalized, never trusted as is),
* a telemetry **store directory** (verified against its manifest first).

Nothing is silently discarded: an unusable record becomes a ``rejected`` entry with the reasons,
a missing end marker downgrades coverage, and every input file is hashed and listed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.engine.manifest import MANIFEST_NAME, verify_directory, write_manifest
from shared.findings.model import clean, host_id
from shared.reporting.jsonio import (
    JsonInputError,
    load_json_strict,
    no_duplicate_keys,
    reject_constant,
)
from shared.reporting.schema_lite import validate
from shared.telemetry.derive import derive_auth_summaries
from shared.telemetry.model import (
    CATEGORIES,
    COVERAGE_STATUSES,
    OS_FAMILIES,
    TELEMETRY_SCHEMA_VERSION,
    category_rank,
    normalise_record,
    parse_time,
    utc_now,
)

MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
MAX_RECORDS = 2_000_000
MAX_ERRORS = 500
MAX_REJECTED = 500
DOC_NAME = "telemetry.json"
_COV_RANK = {"complete": 0, "not_applicable": 0, "partial": 1, "unavailable": 2}


class IngestError(ValueError):
    """The input cannot be ingested at all (unreadable, wrong kind, mixed hosts)."""


@dataclass
class RawInput:
    name: str
    fmt: str
    sha256: str
    size: int
    header: dict[str, Any] = field(default_factory=dict)
    records: list[tuple[str, Any]] = field(default_factory=list)  # (origin, raw record)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    ended: bool = True
    collector: dict[str, str] = field(default_factory=lambda: {"name": "unknown", "version": "0"})


def _err(code: str, message: str, **extra: str) -> dict[str, str]:
    return {
        "code": code,
        "message": clean(message, 600),
        **{k: clean(v, 300) for k, v in extra.items()},
    }


# ------------------------------------------------------------------------------ readers


def read_stream(name: str, data: bytes) -> RawInput:  # noqa: PLR0912, PLR0915
    """Parse a JSON Lines collector stream. Bad lines are rejected individually."""
    raw = RawInput(name=name, fmt="jsonl", sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    try:
        text = data.decode("utf-8-sig")  # Windows PowerShell 5.1 writes a BOM
    except UnicodeDecodeError:
        text = data.decode("utf-8", "replace")
        raw.errors.append(
            _err("ENCODING", "input is not valid UTF-8; undecodable bytes were replaced")
        )
    seen_end = False
    declared = None
    n_records = 0
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        origin = f"{name}:{i}"
        if len(line.encode("utf-8", "replace")) > MAX_LINE_BYTES:
            raw.rejected.append({"origin": origin, "reasons": ["line longer than the limit"]})
            continue
        try:
            obj = json.loads(
                line, object_pairs_hook=no_duplicate_keys, parse_constant=reject_constant
            )
        except (ValueError, RecursionError) as exc:
            raw.rejected.append(
                {"origin": origin, "reasons": [f"not valid JSON: {clean(str(exc), 120)}"]}
            )
            continue
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
            raw.rejected.append(
                {"origin": origin, "reasons": ["line is not an object with a 'type'"]}
            )
            continue
        t = obj["type"]
        if t == "header":
            if raw.header:
                raw.errors.append(_err("DUPLICATE_HEADER", f"{origin}: second header ignored"))
            else:
                raw.header = obj
                c = obj.get("collector")
                if (
                    isinstance(c, dict)
                    and isinstance(c.get("name"), str)
                    and isinstance(c.get("version"), str)
                ):
                    raw.collector = {
                        "name": clean(c["name"], 80),
                        "version": clean(c["version"], 40),
                    }
        elif t == "record":
            n_records += 1
            if len(raw.records) >= MAX_RECORDS:
                raw.errors.append(
                    _err("RECORD_LIMIT", f"more than {MAX_RECORDS} records; the rest were not read")
                )
                break
            raw.records.append((origin, obj))
        elif t == "coverage":
            raw.coverage.append(obj)
        elif t == "error":
            raw.errors.append(
                _err(
                    clean(str(obj.get("code", "COLLECTOR_ERROR")), 80),
                    str(obj.get("message", "")),
                    **(
                        {"category": str(obj["category"])}
                        if isinstance(obj.get("category"), str)
                        else {}
                    ),
                )
            )
        elif t == "end":
            seen_end = True
            declared = obj.get("records")
            if isinstance(obj.get("ended_at"), str):
                raw.header.setdefault("_ended_at", obj["ended_at"])
        else:
            raw.rejected.append(
                {"origin": origin, "reasons": [f"unknown line type {clean(t, 30)!r}"]}
            )
    if not raw.header:
        raise IngestError(f"{name}: no header line; not a BlueOps telemetry stream")
    if not seen_end:
        raw.ended = False
        raw.errors.append(
            _err("TRUNCATED_STREAM", f"{name}: no end marker; the collection may be incomplete")
        )
    elif isinstance(declared, int) and declared != n_records:
        raw.ended = False
        raw.errors.append(
            _err(
                "RECORD_COUNT_MISMATCH",
                f"{name}: end marker declares {declared} records, found {n_records}",
            )
        )
    return raw


def _from_document(name: str, doc: dict[str, Any], data: bytes, fmt: str) -> RawInput:
    """A normalized document from elsewhere: re-validated, then its records are re-normalized."""
    problems = validate(doc, "telemetry.schema.json", limit=5)
    if problems:
        raise IngestError(f"{name}: not a valid telemetry document: {'; '.join(problems)}")
    if doc["schema_version"].split(".")[0] != "1":
        raise IngestError(f"{name}: unsupported telemetry schema_version {doc['schema_version']!r}")
    raw = RawInput(name=name, fmt=fmt, sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    h = doc["host"]
    raw.header = {
        "host": h,
        "collection": {
            k: doc["collection"].get(k)
            for k in ("id", "started_at", "ended_at", "elevated", "window")
        },
        "_ended_at": doc["collection"]["ended_at"],
    }
    cols = doc["collection"].get("collectors") or []
    if cols:
        raw.collector = dict(cols[0])
    raw.coverage = [dict(c, type="coverage") for c in doc["coverage"]]
    raw.errors = [dict(e) for e in doc["errors"]]
    raw.rejected = [dict(r) for r in doc["rejected"]]
    for i, r in enumerate(doc["records"]):
        if r["category"] == "auth_summary":
            continue  # derived records are always recomputed, never trusted from a file
        raw.records.append((f"{name}#{i}", dict(r, type="record", event_time=r.get("event_time"))))
    return raw


def read_path(path: str | Path, allow_unverified: bool = False) -> RawInput:
    """Read a stream file, a telemetry document, or a telemetry store directory."""
    p = Path(path)
    if p.is_dir():
        # A store directory is something we wrote and always carries a manifest; a missing one
        # must not turn a verified read into an unverified one.
        if not (p / MANIFEST_NAME).is_file() or (p / MANIFEST_NAME).is_symlink():
            raise IngestError(f"{p}: no {MANIFEST_NAME}; the store's integrity cannot be verified")
        problems = verify_directory(p)
        if problems:
            raise IngestError(f"{p} failed manifest verification: {'; '.join(problems[:3])}")
        p = p / DOC_NAME
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise IngestError(f"cannot read {p}: {exc.strerror or exc}") from None
    if size > MAX_INPUT_BYTES:
        raise IngestError(f"{p}: {size} bytes exceed the limit of {MAX_INPUT_BYTES}")
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise IngestError(f"cannot read {p}: {exc.strerror or exc}") from None
    stripped = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    first_line = stripped.split(b"\n", 1)[0]
    # A JSON document is one (possibly multi-line) object; a stream's first line is a header.
    if first_line.startswith(b"{") and b'"type"' in first_line and b'"header"' in first_line:
        return read_stream(p.name, data)
    try:
        doc, _ = load_json_strict(p, MAX_INPUT_BYTES, "telemetry")
    except JsonInputError as exc:
        raise IngestError(str(exc)) from None
    if not isinstance(doc, dict):
        raise IngestError(f"{p}: top level must be a JSON object")
    kind = doc.get("kind")
    if kind == "telemetry":
        return _from_document(p.name, doc, data, "json")
    if kind in ("assessment",) or "findings" in doc:
        from shared.telemetry.adapter import raw_from_assessment  # noqa: PLC0415 - avoid a cycle

        return raw_from_assessment(p, data, verify=not allow_unverified)
    raise IngestError(f"{p}: unsupported document (kind={clean(str(kind), 40)!r})")


# ------------------------------------------------------------------------------ assembly


def _merge_coverage(  # noqa: PLR0912 - per-input merge, cross-input merge, counts
    inputs: list[RawInput], final_records: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Worst status within an input (a collector may report a problem, then 'complete' at the
    end), best status across inputs (a second source that saw the category completely wins)."""
    per_input: list[dict[tuple[str, str], dict[str, Any]]] = []
    for raw in inputs:
        cov: dict[tuple[str, str], dict[str, Any]] = {}
        for c in raw.coverage:
            cat = c.get("category")
            status = c.get("status")
            if cat not in CATEGORIES or status not in COVERAGE_STATUSES:
                raw.rejected.append(
                    {
                        "origin": f"{raw.name}:coverage",
                        "reasons": [f"invalid coverage entry {clean(str(c)[:80])}"],
                    }
                )
                continue
            scope = clean(str(c.get("scope", "")), 120)
            reason = clean(str(c.get("reason", "")), 600)
            key = (cat, scope)
            if not raw.ended and status == "complete":
                status, reason = "partial", "collection stream ended without an end marker"
            if key in cov:
                cur = cov[key]
                if _COV_RANK[status] > _COV_RANK[cur["status"]]:
                    cur["status"] = status
                if reason and reason not in cur.get("reason", ""):
                    cur["reason"] = "; ".join(x for x in (cur.get("reason", ""), reason) if x)[:600]
            else:
                cov[key] = {
                    "category": cat,
                    "status": status,
                    **({"reason": reason} if reason else {}),
                    **({"scope": scope} if scope else {}),
                }
        per_input.append(cov)
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for cov in per_input:
        for key, entry in cov.items():
            if key not in merged or _COV_RANK[entry["status"]] < _COV_RANK[merged[key]["status"]]:
                merged[key] = dict(entry)
    counts: dict[tuple[str, str], int] = {}
    by_cat: dict[str, int] = {}
    for r in final_records:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
        counts[(r["category"], r.get("scope", ""))] = (
            counts.get((r["category"], r.get("scope", "")), 0) + 1
        )
    # Records in a category nobody declared coverage for: say so instead of assuming completeness.
    for cat in by_cat:
        if not any(k[0] == cat for k in merged):
            merged[(cat, "")] = {
                "category": cat,
                "status": "partial",
                "reason": "the collector declared no coverage for this category",
            }
    out = []
    for key in sorted(merged, key=lambda k: (category_rank(k[0]), k[1])):
        e = merged[key]
        e["records"] = by_cat.get(key[0], 0) if not key[1] else counts.get(key, 0)
        out.append(e)
    return out


def build_document(  # noqa: PLR0912, PLR0915
    inputs: list[RawInput],
    *,
    mode: str = "import",
    generated_at: str | None = None,
    collection_id: str | None = None,
) -> dict[str, Any]:
    if not inputs:
        raise IngestError("no input")
    now = generated_at or utc_now()
    # Host identity: one document describes one host.
    hosts = []
    for raw in inputs:
        h = raw.header.get("host")
        if (
            not isinstance(h, dict)
            or not isinstance(h.get("hostname"), str)
            or not h["hostname"].strip()
        ):
            raise IngestError(f"{raw.name}: header has no host.hostname")
        os_ = h.get("os") if isinstance(h.get("os"), dict) else {}
        fam = os_.get("family")
        if fam not in OS_FAMILIES:
            raise IngestError(f"{raw.name}: host.os.family must be one of {', '.join(OS_FAMILIES)}")
        hosts.append((host_id(h["hostname"], fam), h, os_))
    hid = hosts[0][0]
    for raw, (other, _h, _o) in zip(inputs, hosts):
        if other != hid:
            raise IngestError(
                f"{raw.name}: describes a different host than {inputs[0].name}; "
                "import one host at a time"
            )
    _, h0, os0 = hosts[0]
    family = os0["family"]
    starts, ends, elevated = [], [], []
    for raw in inputs:
        c = raw.header.get("collection") if isinstance(raw.header.get("collection"), dict) else {}
        s = parse_time(c.get("started_at")) or parse_time(raw.header.get("started_at"))
        e = parse_time(raw.header.get("_ended_at")) or parse_time(c.get("ended_at"))
        starts.append(s or now)
        ends.append(e or s or now)
        if isinstance(c.get("elevated"), bool):
            elevated.append(c["elevated"])

    records: dict[str, dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    conflicts: list[dict[str, Any]] = []
    duplicates = 0
    for raw, started in zip(inputs, starts):
        rejected.extend(raw.rejected)
        errors.extend(raw.errors)
        for origin, obj in raw.records:
            rec, notes = normalise_record(
                obj, host_id=hid, os_family=family, observed_default=started,
                collector=raw.collector, origin=origin,
            )  # fmt: skip
            if rec is None:
                cat = (
                    obj.get("category")
                    if isinstance(obj, dict) and isinstance(obj.get("category"), str)
                    else ""
                )
                rejected.append(
                    {
                        "origin": origin,
                        "reasons": [clean(n, 300) for n in notes][:10],
                        **({"category": clean(cat, 60)} if cat else {}),
                    }
                )
                continue
            old = records.get(rec["record_id"])
            if old is None:
                records[rec["record_id"]] = rec
                continue
            duplicates += 1
            same = (
                old["attributes"] == rec["attributes"]
                and old["unknown_attributes"] == rec["unknown_attributes"]
            )
            old["occurrences"] += rec["occurrences"]
            old["first_seen"] = min(old["first_seen"], rec["first_seen"])
            old["last_seen"] = max(old["last_seen"], rec["last_seen"])
            if same:
                continue
            diff = sorted(
                n for n in set(old["attributes"]) | set(rec["attributes"])
                if old["attributes"].get(n) != rec["attributes"].get(n)
            )  # fmt: skip
            newest = rec["observed_at"] > old["observed_at"]
            conflicts.append(
                {
                    "record_id": rec["record_id"],
                    "category": rec["category"],
                    "differing_attributes": diff[:50],
                    "kept": "newest" if newest else "first",
                }
            )
            if newest:
                rec["occurrences"] = old["occurrences"]
                rec["first_seen"] = old["first_seen"]
                rec["last_seen"] = max(old["last_seen"], rec["last_seen"])
                records[rec["record_id"]] = rec
    final = sorted(records.values(), key=lambda r: (category_rank(r["category"]), r["key"]))
    final.extend(derive_auth_summaries(final, hid, family, max(ends)))
    coverage = _merge_coverage(inputs, [r for r in final if r["category"] != "auth_summary"])
    # Derived records inherit the coverage of the events they summarize.
    auth_cov = [c for c in coverage if c["category"] == "auth_event"]
    if any(r["category"] == "auth_summary" for r in final) or auth_cov:
        worst = max(
            (c["status"] for c in auth_cov), key=lambda s: _COV_RANK[s], default="unavailable"
        )
        coverage.append(
            {
                "category": "auth_summary",
                "status": worst if worst != "not_applicable" else "complete",
                "reason": "derived from auth_event records",
                "records": sum(1 for r in final if r["category"] == "auth_summary"),
            }
        )
    errors = errors[:MAX_ERRORS]
    rejected = rejected[:MAX_REJECTED]
    by_cat: dict[str, int] = {}
    by_status: dict[str, int] = {}
    for r in final:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    cov_counts: dict[str, int] = {}
    for c in coverage:
        cov_counts[c["status"]] = cov_counts.get(c["status"], 0) + 1
    complete = (
        bool(coverage)
        and not rejected
        and not errors
        and all(c["status"] in ("complete", "not_applicable") for c in coverage)
    )
    cid = (
        collection_id
        or "-".join(
            sorted({(r.header.get("collection") or {}).get("id") or "" for r in inputs} - {""})
        )
        or f"tel-{hid}-{min(starts)}"
    )
    collectors: list[dict[str, str]] = []
    for raw in inputs:
        if raw.collector not in collectors:
            collectors.append(raw.collector)
    doc: dict[str, Any] = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "kind": "telemetry",
        "generated_at": now,
        "collection": {
            "id": clean(cid, 128),
            "started_at": min(starts),
            "ended_at": max(ends),
            "collectors": collectors,
            "mode": mode,
            "elevated": (all(elevated) if elevated else None),
            "imported_from": [
                {"name": clean(r.name, 255), "sha256": r.sha256, "format": r.fmt, "bytes": r.size}
                for r in inputs
            ],
        },
        "host": {
            "host_id": hid,
            "hostname": clean(h0["hostname"], 255),
            "os": {
                "family": family,
                **{
                    k: clean(os0[k], 120)
                    for k in ("name", "version")
                    if isinstance(os0.get(k), str)
                },
            },
            **({"arch": clean(h0["arch"], 40)} if isinstance(h0.get("arch"), str) else {}),
        },
        "coverage": coverage,
        "records": final,
        "errors": errors,
        "rejected": rejected,
        "conflicts": conflicts[:MAX_ERRORS],
        "summary": {
            "records": len(final),
            "by_category": dict(sorted(by_cat.items())),
            "by_status": dict(sorted(by_status.items())),
            "rejected": len(rejected),
            "duplicates_merged": duplicates,
            "conflicts": len(conflicts),
            "coverage": dict(sorted(cov_counts.items())),
            "complete": complete,
        },
    }
    problems = validate(doc, "telemetry.schema.json", limit=5)
    if problems:  # a bug in this module, never in the input
        raise IngestError(
            "internal error: normalized telemetry violates its schema: " + "; ".join(problems)
        )
    return doc


def ingest_paths(
    paths: list[str | Path],
    *,
    mode: str = "import",
    generated_at: str | None = None,
    allow_unverified: bool = False,
) -> dict[str, Any]:
    raws = [read_path(p, allow_unverified) for p in paths]
    return build_document(raws, mode=mode, generated_at=generated_at)


# ------------------------------------------------------------------------------ storage


def _whole_seconds(ts: str) -> str:
    """``2026-03-01T10:00:00.93Z`` -> ``2026-03-01T10:00:00Z`` (the manifest schema is seconds-only)."""
    return re.sub(r"\.\d+Z$", "Z", ts)


def write_store(
    doc: dict[str, Any], parent: str | Path, sources: list[tuple[str, bytes]] | None = None
) -> Path:
    """Write ``blueops-telemetry-<stamp>-<host>/`` (mode 0700): the normalized document, the
    original inputs byte for byte under ``sources/`` and a hash manifest."""
    parent = Path(parent)
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    stamp = _whole_seconds(doc["collection"]["started_at"]).replace("-", "").replace(":", "")
    host = (
        "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in doc["host"]["hostname"])[:60]
        or "host"
    )
    base = f"blueops-telemetry-{stamp}-{host}"
    root = None
    for n in range(100):
        cand = parent / (base if n == 0 else f"{base}-{n}")
        try:
            os.mkdir(cand, 0o700)
        except FileExistsError:
            continue
        root = cand
        break
    if root is None:
        raise IngestError(f"too many telemetry directories named {base}")
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    fd = os.open(root / DOC_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    if sources:
        (root / "sources").mkdir(mode=0o700)
        for i, (name, data) in enumerate(sources, 1):
            safe = (
                "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)[:80] or "input"
            )
            fd = os.open(
                root / "sources" / f"{i:02d}-{safe}", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
    write_manifest(
        root,
        {
            "assessment": {
                "id": doc["collection"]["id"],
                "started_at": _whole_seconds(doc["collection"]["started_at"]),
                "finished_at": _whole_seconds(doc["collection"]["ended_at"]),
                "exit_code": 0,
            }
        },
    )
    return root


def load_telemetry(path: str | Path) -> dict[str, Any]:
    """Load a telemetry store directory or ``telemetry.json``, verified and re-normalized."""
    p = Path(path)
    if p.is_dir():
        if not (p / MANIFEST_NAME).is_file() or (p / MANIFEST_NAME).is_symlink():
            raise IngestError(f"{p}: no {MANIFEST_NAME}; the store's integrity cannot be verified")
        problems = verify_directory(p)  # a store we wrote: integrity-checked, then schema-checked
        if problems:
            raise IngestError(f"{p} failed manifest verification: {'; '.join(problems[:3])}")
        try:
            doc, _ = load_json_strict(p / DOC_NAME, MAX_INPUT_BYTES, "telemetry")
        except JsonInputError as exc:
            raise IngestError(str(exc)) from None
        bad = validate(doc, "telemetry.schema.json", limit=5)
        if bad:
            raise IngestError(f"{p}: not a valid telemetry document: {'; '.join(bad)}")
        return doc  # type: ignore[no-any-return]
    raw = read_path(path)
    if raw.fmt == "jsonl":
        raise IngestError(f"{path}: a raw collector stream; use 'telemetry import' first")
    return build_document([raw], mode="import", generated_at=None)
