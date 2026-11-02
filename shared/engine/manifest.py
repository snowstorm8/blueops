"""Integrity manifest for an assessment directory (``assessment-manifest.schema.json``).

An assessment directory is a tree (``modules/<id>/output/blueops-run-*/...``), so unlike the flat
collector run-manifest it lists *relative POSIX paths*. Verification refuses anything outside the
directory: absolute paths, ``..`` segments, symbolic links, and files the manifest does not list.
As with every manifest, it cannot vouch for itself: record its digest off the host.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from shared.engine import ASSESSMENT_SCHEMA_VERSION, ENGINE_NAME, ENGINE_VERSION
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.schema_lite import validate

MANIFEST_NAME = "manifest.json"
MAX_FILES = 20000


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk(root: Path) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    problems: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames):
            if (Path(dirpath) / name).is_symlink():
                problems.append(
                    f"{(Path(dirpath) / name).relative_to(root).as_posix()}: symbolic link"
                )
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                problems.append(f"{p.relative_to(root).as_posix()}: not a regular file")
            elif p != root / MANIFEST_NAME:
                files.append(p)
    return files, problems


def write_manifest(root: Path, doc: dict[str, Any]) -> tuple[Path, str]:
    """Write ``manifest.json`` for ``root``; returns ``(path, sha256 of the manifest)``."""
    files, problems = _walk(root)
    if problems or len(files) > MAX_FILES:
        raise OSError("; ".join(problems[:3]) or f"more than {MAX_FILES} files")
    a = doc["assessment"]
    manifest = {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "kind": "assessment-manifest",
        "hash_algorithm": "sha256",
        "engine": {"name": ENGINE_NAME, "version": ENGINE_VERSION},
        "assessment": {
            "id": a["id"],
            "started_at": a["started_at"],
            "finished_at": a["finished_at"],
            "exit_code": a["exit_code"],
        },
        "files": [
            {
                "path": p.relative_to(root).as_posix(),
                "sha256": _sha256(p),
                "size": p.stat().st_size,
            }
            for p in files
        ],
    }
    text = json.dumps(manifest, indent=2) + "\n"
    path = root / MANIFEST_NAME
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path, hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_directory(root: str | Path, expected_sha256: str | None = None) -> list[str]:
    """Problems found re-hashing an assessment directory (empty list = verified)."""
    base = Path(root)
    try:
        manifest, raw = load_json_strict(base / MANIFEST_NAME, 8 * 1024 * 1024, "manifest")
    except JsonInputError as exc:
        return [str(exc)]
    problems: list[str] = []
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256.lower():
        problems.append("manifest.json does not match the expected digest (rewritten?)")
    schema_problems = validate(manifest, "assessment-manifest.schema.json", limit=5)
    if schema_problems:
        return [*problems, *(f"manifest: {p}" for p in schema_problems)]
    listed: set[str] = set()
    for entry in manifest["files"]:
        rel = entry["path"]
        parts = rel.split("/")
        if rel.startswith("/") or ".." in parts or "\\" in rel or rel == MANIFEST_NAME:
            problems.append(f"{rel[:80]!r}: unsafe path in the manifest")
            continue
        listed.add(rel)
        f = base / rel
        if f.is_symlink() or not f.is_file():
            problems.append(f"{rel}: missing or not a regular file")
        elif f.stat().st_size != entry["size"] or _sha256(f) != entry["sha256"]:
            problems.append(f"{rel}: content differs from the manifest")
    files, walk_problems = _walk(base)
    problems += walk_problems
    extra = sorted(
        p.relative_to(base).as_posix()
        for p in files
        if p.relative_to(base).as_posix() not in listed
    )
    if extra:
        problems.append("files not listed in the manifest: " + ", ".join(extra[:5]))
    return problems
