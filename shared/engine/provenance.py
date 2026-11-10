"""Input provenance: which inputs an output was derived from, and whether each was verified.

Every derived document (assessment, snapshot/detection/telemetry comparisons, detection
results, telemetry) carries

``inputs_verified``  true only if **every** recorded input was verified (its directory manifest
                     matched on load), false as soon as one was not;
``inputs``           one entry per input: ``role``, ``path``, ``verified`` and, when not
                     verified, a ``reason``. An input that was itself derived from unverified
                     inputs keeps those entries too (``via`` names the document that carried
                     them), so per-input status survives however many steps separate it.

The status of a *loaded* document is an attribute of the object ``load_assessment`` returns
(``Loaded``). A plain ``dict`` has no such attribute, and **an input of unknown provenance is
treated as unverified**: copying, rebuilding or round-tripping a document can therefore only
lose the claim "verified", never invent it. A document is never marked verified because it
validates against its schema; only a successful manifest check (or being produced by this very
run) does.

``inputs_verified`` is a statement about what the tool was able to check, not about whether the
data is true: a manifest that sits next to the data proves the files were not changed *after*
it was written, not who wrote it (see docs/security-model.md).
"""

from __future__ import annotations

from typing import Any

MAX_INPUTS = 1000
THIS_RUN = "(this run)"
SELF_ROLE = "source"

REASON_NOT_VERIFIED = "verification disabled (--allow-unverified)"
REASON_UNKNOWN = "provenance unknown (verification status was not carried)"
REASON_BARE = "bare file: it has no manifest to verify"
REASON_UPSTREAM = "derived from unverified inputs"


class Loaded(dict):  # type: ignore[type-arg]
    """A document read from disk, remembering whether that read was verified."""

    load_verified: bool = False
    load_source: str = ""
    load_reason: str = ""


def mark(doc: dict[str, Any], *, verified: bool, source: str, reason: str = "") -> Loaded:
    """Wrap ``doc`` (no copy of nested data) with how it was loaded."""
    out = Loaded(doc)
    out.load_verified = bool(verified)
    out.load_source = str(source)
    out.load_reason = "" if verified else (reason or REASON_NOT_VERIFIED)
    return out


def stamp_load(doc: dict[str, Any], *, verified: bool, source: str, reason: str = "") -> Loaded:
    """Return ``doc`` as ``Loaded`` and, when the read was **not** verified, write that into the
    document itself (``inputs_verified: false`` plus a ``source`` entry), so the fact survives
    a plain ``dict`` copy, a conversion or a save. A verified read adds nothing: what the
    document already records about its own inputs is kept as it is."""
    if not verified:
        entry = {
            "role": SELF_ROLE,
            "path": _clean(source or "(unknown)"),
            "verified": False,
            "reason": reason or REASON_NOT_VERIFIED,
        }
        merge_into(doc, [entry])
    return mark(doc, verified=verified, source=source, reason=reason)


def carry(src: dict[str, Any], dst: dict[str, Any]) -> dict[str, Any]:
    """Copy the provenance **recorded in** ``src`` onto ``dst`` (format conversions)."""
    for key in ("inputs_verified", "inputs", "inputs_omitted"):
        if key in src:
            dst[key] = src[key]
    return dst


def produced_here(doc: dict[str, Any]) -> Loaded:
    """``doc`` was produced by the current process from data it just collected."""
    return mark(doc, verified=True, source=THIS_RUN)


def _own(doc: Any) -> tuple[bool, str, str]:
    if isinstance(doc, Loaded):
        return doc.load_verified, doc.load_source, doc.load_reason
    return False, "", REASON_UNKNOWN


def _clean(value: Any, limit: int = 300) -> str:
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value))
    return text[:limit]


def entries(role: str, doc: Any, source: str | None = None) -> list[dict[str, Any]]:
    """Provenance entries for one input: its own load status plus everything it carried."""
    verified, path, reason = _own(doc)
    path = source if source is not None else path
    out: list[dict[str, Any]] = []
    own: dict[str, Any] = {"role": role, "path": _clean(path or "(unknown)"), "verified": verified}
    if not verified:
        own["reason"] = reason or REASON_NOT_VERIFIED
    out.append(own)
    carried = doc.get("inputs") if isinstance(doc, dict) else None
    flagged_false = isinstance(doc, dict) and doc.get("inputs_verified") is False
    seen_false = False
    if isinstance(carried, list):
        for c in carried:
            if not isinstance(c, dict) or not isinstance(c.get("verified"), bool):
                continue
            if (
                c.get("role") == SELF_ROLE
                and _clean(c.get("path", "")) == own["path"]
                and not verified
            ):
                seen_false = True  # this load's own record, stamped into the document: `own`
                continue
            item: dict[str, Any] = {
                "role": _clean(c.get("role", "input"), 40),
                "path": _clean(c.get("path", "(unknown)")),
                "verified": c["verified"],
                "via": own["path"],
            }
            if not c["verified"]:
                item["reason"] = _clean(c.get("reason") or REASON_NOT_VERIFIED, 200)
                seen_false = True
            out.append(item)
    if flagged_false and not seen_false:
        # The document says some input was unverified but not which: keep that fact.
        out.append(
            {
                "role": "upstream",
                "path": own["path"],
                "verified": False,
                "reason": REASON_UPSTREAM,
                "via": own["path"],
            }
        )
    return out


def block(*groups: list[dict[str, Any]]) -> dict[str, Any]:
    """Combine entry groups into ``{"inputs_verified", "inputs"[, "inputs_omitted"]}``."""
    seen: set[tuple[str, str, bool]] = set()
    flat: list[dict[str, Any]] = []
    for g in groups:
        for e in g:
            key = (e["role"], e["path"], e["verified"])  # first sighting (the direct one) wins
            if key not in seen:
                seen.add(key)
                flat.append(e)
    verified = all(e["verified"] for e in flat)
    out: dict[str, Any] = {"inputs_verified": verified}
    if len(flat) > MAX_INPUTS:
        flat = sorted(flat, key=lambda e: e["verified"])  # keep every unverified entry first
        out["inputs_omitted"] = len(flat) - MAX_INPUTS
        flat = flat[:MAX_INPUTS]
    out["inputs"] = flat
    return out


def stamp(doc: dict[str, Any], *groups: list[dict[str, Any]]) -> dict[str, Any]:
    """Record provenance on ``doc`` in place and return it."""
    doc.update(block(*groups))
    return doc


def merge_into(doc: dict[str, Any], *groups: list[dict[str, Any]]) -> dict[str, Any]:
    """Add entries to what ``doc`` already records (never drops an existing one)."""
    have = doc.get("inputs") if isinstance(doc.get("inputs"), list) else []
    doc.update(block(have, *groups))
    return doc


def status(doc: Any) -> tuple[bool | None, list[dict[str, Any]]]:
    """``(inputs_verified, inputs)`` of a document for display; ``None`` if it records nothing."""
    if not isinstance(doc, dict) or "inputs_verified" not in doc:
        return None, []
    raw = doc.get("inputs")
    inputs = [i for i in raw if isinstance(i, dict)] if isinstance(raw, list) else []
    # The summary is recomputed from the entries: a document that says "true" next to an
    # unverified (or malformed) entry is not shown as verified.
    ok = doc["inputs_verified"] is True and all(i.get("verified") is True for i in inputs)
    return ok, inputs


def unverified(doc: Any) -> list[dict[str, Any]]:
    """The entries of ``doc`` that were not verified."""
    return [i for i in status(doc)[1] if i.get("verified") is False]


def banner(doc: Any) -> str:
    """One plain-text line for a renderer: the verdict on the inputs, or ``""`` if none recorded."""
    ok, inputs = status(doc)
    if ok is None:
        return ""
    if ok:
        return f"Inputs: all {len(inputs)} recorded input(s) were verified against their manifests."
    bad = len(unverified(doc)) or 1
    return (
        f"WARNING: {bad} of {max(len(inputs), bad)} recorded input(s) are UNVERIFIED. Their "
        "integrity was not checked, so the results below rest on data that may have been altered."
    )


def gather(*named: tuple[str, Any]) -> tuple[bool | None, list[dict[str, Any]]]:
    """Provenance of several documents shown together (a report with its comparisons and
    detections). Returns ``(overall, rows)``; ``overall`` is ``None`` if none records any, false
    if any recorded input anywhere is unverified. Each row names the document that carries it."""
    rows: list[dict[str, Any]] = []
    overall: bool | None = None
    for label, doc in named:
        ok, inputs = status(doc)
        if ok is None:
            continue
        overall = ok if overall is None else (overall and ok)
        rows += [{**i, "document": label} for i in inputs]
        if not ok and not any(i.get("verified") is False for i in inputs):
            rows.append(
                {
                    "document": label,
                    "role": "unknown",
                    "path": "(not itemised)",
                    "verified": False,
                    "reason": REASON_UPSTREAM,
                }
            )
    return overall, rows
