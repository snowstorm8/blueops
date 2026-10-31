"""Strict JSON file reading shared by every tool that parses input it did not write.

Reports, diffs, allowlists, configs and manifests may come from a compromised host or an
untrusted channel. They are read with one set of rules: a size cap, valid UTF-8, no duplicate
object keys (a duplicate could show two different meanings to two readers), no ``NaN`` or
infinities, and nesting limits that turn parser exhaustion into an ordinary error.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class JsonInputError(ValueError):
    """A JSON input file is unreadable, too large, not valid JSON, or violates the strict rules."""


def no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate object key {k!r}")
        out[k] = v
    return out


def reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} is not allowed")


def load_json_strict(path: str | Path, max_bytes: int, what: str) -> tuple[Any, bytes]:
    """Read and parse ``path``; return ``(parsed, raw_bytes)``.

    The raw bytes let a caller record a digest of exactly what it parsed. Every failure is a
    ``JsonInputError`` and nothing else escapes (including ``RecursionError`` from deep nesting).
    """
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise JsonInputError(f"cannot read {what} {p}: {exc.strerror or exc}") from None
    if size > max_bytes:
        raise JsonInputError(
            f"cannot read {what} {p}: {size} bytes exceed the limit of {max_bytes}"
        )
    try:
        data = p.read_bytes()
        # utf-8-sig: Windows PowerShell 5.1 writes a BOM.
        parsed = json.loads(
            data.decode("utf-8-sig"),
            object_pairs_hook=no_duplicate_keys,
            parse_constant=reject_constant,
        )
    except OSError as exc:
        raise JsonInputError(f"cannot read {what} {p}: {exc.strerror or exc}") from None
    except UnicodeDecodeError:
        raise JsonInputError(f"cannot read {what} {p}: not valid UTF-8") from None
    except (ValueError, RecursionError) as exc:
        raise JsonInputError(f"cannot read {what} {p}: not valid JSON ({exc})") from None
    return parsed, data
