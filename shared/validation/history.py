"""Preserved evaluation history: one immutable results file per run."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.schema_lite import validate

MAX_RESULTS_BYTES = 64 * 1024 * 1024
PREFIX = "validation-run-"


class HistoryError(ValueError):
    """A results file is unreadable, invalid, or from an unsupported schema line."""


def load_results(path: str | Path) -> dict[str, Any]:
    try:
        doc, _ = load_json_strict(path, MAX_RESULTS_BYTES, "validation results")
    except JsonInputError as exc:
        raise HistoryError(str(exc)) from None
    if not isinstance(doc, dict) or doc.get("kind") != "validation-results":
        raise HistoryError(f"{path}: not a validation-results document")
    if str(doc.get("schema_version", "")).split(".")[0] != "1":
        raise HistoryError(
            f"{path}: unsupported validation schema_version {doc.get('schema_version')!r}"
        )
    problems = validate(doc, "validation-results.schema.json", limit=5)
    if problems:
        raise HistoryError(f"{path}: invalid validation results: {'; '.join(problems)}")
    return doc  # type: ignore[no-any-return]


def save_run(doc: dict[str, Any], directory: str | Path) -> Path:
    """Write the run exclusively (0600): an existing result is never overwritten."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    name = f"{PREFIX}{doc['run']['started_at'].replace('-', '').replace(':', '')}-{doc['reproducibility']['digest'][:8]}.json"
    path = d / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(doc, indent=2) + "\n")
    return path


def list_runs(directory: str | Path) -> list[Path]:
    d = Path(directory)
    if not d.is_dir():
        return []
    return sorted(
        p for p in d.iterdir() if p.name.startswith(PREFIX) and p.suffix == ".json" and p.is_file()
    )


def latest(directory: str | Path, n: int = 2) -> list[dict[str, Any]]:
    runs = list_runs(directory)
    if len(runs) < n:
        raise HistoryError(f"{directory}: needs {n} saved run(s), found {len(runs)}")
    return [load_results(p) for p in runs[-n:]]
