"""Load assessments (or legacy audit reports) from disk, strictly and verified."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from shared.engine.assessment import assessment_from_report
from shared.engine.manifest import MANIFEST_NAME, verify_directory
from shared.reporting.contracts import READABLE_REPORT_VERSIONS
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.schema_lite import validate

MAX_DOC_BYTES = 256 * 1024 * 1024


class LoadError(ValueError):
    """The file is unreadable, malformed, fails its schema, or fails manifest verification."""


def load_assessment(  # noqa: PLR0912 - file, directory and report forms share one loader
    path: str | Path, verify: bool = True
) -> dict[str, Any]:
    """Load an assessment directory / ``assessment.json``, or an audit ``report.json`` (run
    directory or file), returning an assessment document.

    A directory with a ``manifest.json`` is verified first and refused if it does not match
    (``verify=False`` skips that, for the ``verify`` command's own use and for tests).
    """
    p = Path(path)
    if p.is_dir():
        if (p / "assessment.json").is_file():
            if verify and (p / MANIFEST_NAME).is_file():
                problems = verify_directory(p)
                if problems:
                    raise LoadError(f"{p} failed manifest verification: {'; '.join(problems[:3])}")
            p = p / "assessment.json"
        elif (p / "report.json").is_file():
            p = p / "report.json"
        else:
            raise LoadError(f"{p}: no assessment.json or report.json")
    try:
        doc, raw = load_json_strict(p, MAX_DOC_BYTES, "assessment")
    except JsonInputError as exc:
        raise LoadError(str(exc)) from None
    if not isinstance(doc, dict):
        raise LoadError(f"{p}: top level must be a JSON object")
    if doc.get("kind") == "assessment":
        problems = validate(doc, "assessment.schema.json", limit=5)
        if problems:
            raise LoadError(f"{p}: not a valid assessment: {'; '.join(problems)}")
        if doc["schema_version"].split(".")[:2] != ["0", "1"]:
            raise LoadError(f"{p}: unsupported assessment schema_version {doc['schema_version']!r}")
        return doc
    if "kind" in doc:
        raise LoadError(f"{p}: unsupported document kind {str(doc['kind'])[:40]!r}")
    problems = validate(doc, "audit-report.schema.json", limit=5)
    version = ".".join(str(doc.get("schema_version", "")).split(".")[:2])
    if not problems and version not in READABLE_REPORT_VERSIONS:
        raise LoadError(
            f"{p}: unsupported audit report schema_version {doc['schema_version']!r}; "
            f"readable: {', '.join(v + '.x' for v in READABLE_REPORT_VERSIONS)}"
        )
    if problems:
        raise LoadError(
            f"{p}: neither an assessment nor a valid audit report: {'; '.join(problems)}"
        )
    return assessment_from_report(doc, hashlib.sha256(raw).hexdigest())
