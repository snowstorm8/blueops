"""Run-manifest verification (offline, read-only).

A collector run directory holds ``report.json``, ``report.txt``, ``run.log`` and a
``manifest.json`` listing the SHA-256 and size of each
(``shared/schemas/run-manifest.schema.json``).
``verify_run_dir`` re-hashes the files and reports every discrepancy. The manifest cannot vouch for
itself: pass the manifest digest the collector printed (kept off the host) as ``expected_sha256``
to detect a rewritten manifest as well.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from shared.reporting.jsonio import JsonInputError, load_json_strict

MAX_MANIFEST_BYTES = 1024 * 1024
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_file(root: Path, entry: object) -> tuple[str | None, list[str]]:
    """Verify one manifest entry; returns (listed name or None, problems)."""
    name = entry.get("path") if isinstance(entry, dict) else None
    if not isinstance(name, str) or not _NAME.match(name) or name == "manifest.json":
        return None, [f"manifest entry has an invalid path: {str(name)[:60]!r}"]
    assert isinstance(entry, dict)  # noqa: S101 - narrowed by the check above
    digest, size = entry.get("sha256"), entry.get("size")
    f = root / name
    if not f.is_file() or f.is_symlink():
        return name, [f"{name}: missing or not a regular file"]
    if not isinstance(digest, str) or not _HEX.match(digest):
        return name, [f"{name}: no usable SHA-256 in the manifest"]
    problems = []
    if f.stat().st_size != size:
        problems.append(f"{name}: size differs from the manifest")
    if sha256_file(f) != digest:
        problems.append(f"{name}: SHA-256 differs from the manifest")
    return name, problems


def _check_run_id(root: Path, doc: dict[str, object]) -> list[str]:
    run = doc.get("run")
    report = root / "report.json"
    if not report.is_file() or not isinstance(run, dict):
        return []
    try:
        data, _ = load_json_strict(report, 64 * 1024 * 1024, "report")
    except JsonInputError:
        return []
    rid = data.get("run", {}).get("id") if isinstance(data, dict) else None
    return [] if rid == run.get("id") else ["report.json run id differs from the manifest"]


def verify_run_dir(path: str | Path, expected_sha256: str | None = None) -> list[str]:
    """Return a list of problems (empty when the directory matches its manifest)."""
    root = Path(path)
    problems: list[str] = []
    try:
        doc, raw = load_json_strict(root / "manifest.json", MAX_MANIFEST_BYTES, "manifest")
    except JsonInputError as exc:
        return [str(exc)]
    if expected_sha256 is not None:
        want = expected_sha256.strip().lower()
        if not _HEX.match(want):
            problems.append("the expected manifest digest is not a SHA-256 hex string")
        elif hashlib.sha256(raw).hexdigest() != want:
            problems.append("manifest.json does not match the expected digest (rewritten?)")
    if not isinstance(doc, dict) or doc.get("kind") != "run-manifest":
        return [*problems, "manifest.json is not a run-manifest document"]
    if doc.get("hash_algorithm") != "sha256":
        problems.append("unsupported hash_algorithm (only sha256 is verified)")
    files = doc.get("files")
    if not isinstance(files, list) or not files:
        return [*problems, "manifest lists no files"]
    if doc.get("complete") is not True:
        problems.append("manifest is incomplete: the collector could not hash every file")
    listed: set[str] = set()
    for entry in files:
        name, found = _check_file(root, entry)
        problems += found
        if name:
            listed.add(name)
    extra = sorted(
        q.name for q in root.iterdir() if q.name != "manifest.json" and q.name not in listed
    )
    if extra:
        problems.append(f"files not listed in the manifest: {', '.join(extra)[:200]}")
    return problems + _check_run_id(root, doc)
