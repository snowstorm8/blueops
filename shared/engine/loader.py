"""Load assessments (or legacy audit reports) from disk, strictly and verified."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from shared.engine.assessment import assessment_from_report
from shared.engine.manifest import MANIFEST_NAME, verify_directory
from shared.reporting.contracts import READABLE_REPORT_VERSIONS
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.manifest import verify_run_dir
from shared.reporting.schema_lite import validate

MAX_DOC_BYTES = 256 * 1024 * 1024
ALLOW_UNVERIFIED_HELP = (
    "load assessments without a manifest check (only for data you already trust, e.g. "
    "synthetic fixtures); by default anything that cannot be verified is refused"
)


class LoadError(ValueError):
    """The file is unreadable, malformed, fails its schema, or fails manifest verification."""


def _check_integrity(p: Path, expected_sha256: str | None) -> None:
    """Verify the directory ``p`` against its manifest; raise ``LoadError`` on any problem.

    A missing manifest is a failure, never a pass: an attacker (or an interrupted run) that
    removes ``manifest.json`` must not turn a verified load into an unverified one.
    """
    if (p / MANIFEST_NAME).is_symlink() or not (p / MANIFEST_NAME).is_file():
        raise LoadError(
            f"{p}: no {MANIFEST_NAME}; integrity cannot be verified "
            "(pass allow_unverified / --allow-unverified only for data you already trust)"
        )
    problems = verify_directory(p, expected_sha256)
    if problems:
        raise LoadError(f"{p} failed manifest verification: {'; '.join(problems[:3])}")


def _verify_collector_run(p: Path, expected_sha256: str | None) -> None:
    """Verify a collector run directory (``report.json`` + a ``run-manifest``)."""
    if (p / MANIFEST_NAME).is_symlink() or not (p / MANIFEST_NAME).is_file():
        raise LoadError(
            f"{p}: no {MANIFEST_NAME}; integrity cannot be verified "
            "(pass allow_unverified / --allow-unverified only for data you already trust)"
        )
    problems = verify_run_dir(p, expected_sha256)
    if problems:
        raise LoadError(f"{p} failed manifest verification: {'; '.join(problems[:3])}")


def load_assessment(  # noqa: PLR0912 - file, directory and report forms share one loader
    path: str | Path, verify: bool = True, expected_sha256: str | None = None
) -> dict[str, Any]:
    """Load an assessment directory / ``assessment.json``, or an audit ``report.json`` (run
    directory or file), returning an assessment document.

    Contract (``verify=True``, the default): the data must come from a directory whose
    ``manifest.json`` is present and matches every file in it.

    * directory with ``assessment.json``  -> verified as an assessment directory;
    * ``<dir>/assessment.json`` (a file)  -> the same, for ``<dir>`` (no shortcut around it);
    * directory with ``report.json`` / ``<dir>/report.json`` -> verified as a collector run;
    * any other file cannot be verified and is refused.

    ``expected_sha256`` is the digest of ``manifest.json`` recorded off the host; it is what
    detects a manifest rewritten together with the data, and is only meaningful when verifying.

    ``verify=False`` is the deliberate escape hatch for data the caller already trusts
    (synthetic fixtures, exports whose provenance is established elsewhere). It performs the
    schema checks only, and combining it with ``expected_sha256`` is an error, not a silent skip.
    """
    p = Path(path)
    if expected_sha256 is not None and not verify:
        raise LoadError("an expected manifest digest cannot be checked with verification off")
    if p.is_symlink():
        raise LoadError(f"{p}: is a symbolic link")
    if p.is_file() and verify:
        if p.name == "assessment.json":
            _check_integrity(p.parent, expected_sha256)
        elif p.name == "report.json":
            _verify_collector_run(p.parent, expected_sha256)
        else:
            raise LoadError(
                f"{p}: a bare file has no manifest, so it cannot be verified "
                "(pass allow_unverified / --allow-unverified only for data you already trust)"
            )
    if p.is_dir():
        if (p / "assessment.json").is_file():
            if verify:
                _check_integrity(p, expected_sha256)
            p = p / "assessment.json"
        elif (p / "report.json").is_file():
            if verify:
                _verify_collector_run(p, expected_sha256)
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
