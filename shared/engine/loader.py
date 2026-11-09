"""Load assessments (or legacy audit reports) from disk, strictly and verified."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from shared.engine.assessment import assessment_from_report
from shared.engine.manifest import MANIFEST_NAME, verify_directory
from shared.engine.provenance import Loaded, stamp_load
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


class IntegrityError(LoadError):
    """Integrity could not be established. Two kinds, with different consequences:

    * ``UnverifiableError``: there is nothing to verify against (no ``manifest.json``, or a bare
      file). The data is *unverified*, and ``verify=False`` / ``--allow-unverified`` may accept it.
    * ``InvalidIntegrityError``: a manifest exists and verification was attempted and failed
      (mismatch, malformed manifest, missing or unlisted file, symlink, wrong digest). The data is
      *invalid*; no option accepts it.
    """

    overridable = False

    def __init__(self, message: str, detail: str) -> None:
        super().__init__(message)
        self.detail = detail

    def reason(self) -> str:
        """Why verification was not possible, without the path (shown separately)."""
        return self.detail[:200]


class UnverifiableError(IntegrityError):
    overridable = True


class InvalidIntegrityError(IntegrityError):
    overridable = False


_HINT = "(pass allow_unverified / --allow-unverified only for data you already trust)"


def _manifest_state(p: Path) -> str:
    """``absent`` (nothing to verify against), ``present`` (a regular file) or ``bad`` (a
    symlink or other non-file: something is there and it is not a valid manifest)."""
    m = p / MANIFEST_NAME
    if not os.path.lexists(m):
        return "absent"
    return "bad" if m.is_symlink() or not m.is_file() else "present"


def _check_manifest(p: Path, verifier: Any, expected_sha256: str | None) -> None:
    """Run ``verifier`` (a function returning a list of problems) against ``p``.

    A missing manifest is *unverifiable*, never a pass. A manifest that is present and fails
    is *invalid*, never overridable.
    """
    state = _manifest_state(p)
    if state == "absent":
        raise UnverifiableError(
            f"{p}: no {MANIFEST_NAME}; integrity cannot be verified {_HINT}",
            f"no {MANIFEST_NAME}; integrity cannot be verified",
        )
    problems = (
        [f"{MANIFEST_NAME} is a symbolic link or not a regular file"]
        if state == "bad"
        else verifier(p, expected_sha256)
    )
    if problems:
        raise InvalidIntegrityError(
            f"{p} failed manifest verification: {'; '.join(problems[:3])}",
            f"failed manifest verification: {'; '.join(problems[:3])}",
        )


def _check_integrity(p: Path, expected_sha256: str | None) -> None:
    _check_manifest(p, verify_directory, expected_sha256)


def _verify_collector_run(p: Path, expected_sha256: str | None) -> None:
    _check_manifest(p, verify_run_dir, expected_sha256)


BARE_REASON = "a bare file has no manifest, so it cannot be verified"


def check_bare_file(p: Path, allow: bool) -> str:
    """A file that is not an assessment entry point cannot be verified on its own.

    If the directory it sits in has a manifest, that manifest is checked first, and a failure is
    *invalid* whatever ``allow`` says (an altered directory must not be accepted just because the
    file was addressed directly). Otherwise the file is merely *unverifiable*: refused unless
    ``allow``, in which case the reason to record is returned.
    """
    if _manifest_state(p.parent) != "absent":
        _check_integrity(p.parent, None)
    if not allow:
        raise UnverifiableError(f"{p}: {BARE_REASON} {_HINT}", BARE_REASON)
    return BARE_REASON


def stored_file_status(p: Path) -> tuple[bool, str]:
    """``(verified, reason)`` for a stored output file that was not loaded through a loader that
    verifies (a saved detection-results file, for instance).

    If the directory it sits in has a manifest, that manifest is checked: a failure raises
    ``InvalidIntegrityError`` (never overridable), and a pass means the file matches what was
    written. With no manifest the file is merely unverifiable: ``(False, reason)``. What the file
    *says* about its own inputs is never trusted to make it verified.
    """
    if _manifest_state(p.parent) != "absent":
        _check_integrity(p.parent, None)
        return True, ""
    return False, BARE_REASON


def load_assessment(
    path: str | Path, verify: bool = True, expected_sha256: str | None = None
) -> Loaded:
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
    (synthetic fixtures, exports whose provenance is established elsewhere). The manifest is
    still *tried*: data that verifies is recorded as verified, and data that cannot be verified
    (no manifest, a mismatch, a bare file) is loaded anyway and recorded as **unverified**, with
    the reason. Only integrity problems are overridable; malformed or schema-invalid data, and
    symbolic links, are refused either way. Combining it with ``expected_sha256`` is an error.

    The result is a ``Loaded`` (a ``dict``) that remembers whether this read was verified; an
    unverified read is also written into the document (``inputs_verified: false``) so the fact
    cannot be lost by copying or saving it. See ``shared/engine/provenance.py``.
    """
    if expected_sha256 is not None and not verify:
        raise LoadError("an expected manifest digest cannot be checked with verification off")
    try:
        return _load(path, True, expected_sha256, "")
    except IntegrityError as exc:
        if verify or not exc.overridable:
            raise  # a failed check is never overridable: only "nothing to check against" is
        return _load(path, False, None, exc.reason())


def _load(  # noqa: PLR0912 - file, directory and report forms share one loader
    path: str | Path, check: bool, expected_sha256: str | None, why: str
) -> Loaded:
    p = Path(path)
    if p.is_symlink():
        raise LoadError(f"{p}: is a symbolic link")
    if p.is_file() and check:
        if p.name == "assessment.json":
            _check_integrity(p.parent, expected_sha256)
        elif p.name == "report.json":
            _verify_collector_run(p.parent, expected_sha256)
        else:
            check_bare_file(p, allow=False)
    if p.is_dir():
        if (p / "assessment.json").is_file():
            if check:
                _check_integrity(p, expected_sha256)
            p = p / "assessment.json"
        elif (p / "report.json").is_file():
            if check:
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
        return stamp_load(doc, verified=check, source=str(path), reason=why)
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
    return stamp_load(
        assessment_from_report(doc, hashlib.sha256(raw).hexdigest()),
        verified=check,
        source=str(path),
        reason=why,
    )
