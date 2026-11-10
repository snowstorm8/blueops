"""Central findings model: identity, normalisation, deduplication, evidence provenance.

Collectors (Bash, PowerShell, plugins) emit ``report.json`` findings keyed by a *check id*
(``USR-UID0-001``). This module turns those into the platform's central finding records:

* **Identity.** A finding's id is ``BOF-`` plus 16 hex digits of
  ``SHA-256(host_id, check_id, component)``. The same check on the same host always yields the
  same id, on any machine and in any run, which is what makes snapshot comparison possible.
  Severity, evidence and wording are *not* part of the identity: a finding that gets worse is
  the same finding with a changed severity, not a new one.
* **Deduplication.** Records with one id are merged: highest severity and confidence win,
  evidence is unioned, sources are listed, the earliest detection time is kept.
* **Evidence.** Evidence items are stored once (id ``EV-`` + hash of type and reference) and
  carry the provenance of every collector run that reported them. Nothing here reads the audited
  host: it only re-shapes data that collectors already wrote.

Everything in a report is attacker-influenced, so every string is stripped of control characters
and length-capped on the way in.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from shared.findings.standards import standards_for
from shared.reporting.contracts import Severity

FINDING_ID_PREFIX = "BOF-"
EVIDENCE_ID_PREFIX = "EV-"
CONFIDENCES = ("low", "medium", "high")
EVIDENCE_TYPES = ("file", "registry", "process", "network", "command", "log", "other")

MAX_TEXT = 4000
MAX_REF = 1024
MAX_EXCERPT = 2000
MAX_EXCERPTS_PER_EVIDENCE = 5
MAX_EVIDENCE_PER_FINDING = 200

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CHECK_ID_RE = re.compile(r"^[A-Z]{2,6}-[A-Z0-9]+-\d{3,}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_PRIORITY = {
    # (severity, confidence is high or medium) -> priority label
    "critical": ("P1", "P1"),
    "high": ("P1", "P2"),
    "medium": ("P2", "P3"),
    "low": ("P3", "P4"),
    "info": ("P4", "P4"),
}


class FindingError(ValueError):
    """A report finding is unusable (the caller records it as a coverage problem)."""


def clean(value: Any, limit: int = MAX_TEXT) -> str:
    """``value`` as text without control characters (newline and tab survive), capped."""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    text = _CONTROL_RE.sub("?", text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def host_id(hostname: str, os_family: str) -> str:
    """Stable, non-reversible-looking host key: hostnames compare case-insensitively."""
    digest = hashlib.sha256(f"{os_family.lower()}\0{hostname.casefold()}".encode()).hexdigest()
    return "H-" + digest[:12]


def finding_id(hid: str, check_id: str, component: str) -> str:
    digest = hashlib.sha256(f"blueops/finding/v1\0{hid}\0{check_id}\0{component}".encode())
    return FINDING_ID_PREFIX + digest.hexdigest()[:16]


def evidence_id(etype: str, ref: str) -> str:
    digest = hashlib.sha256(f"blueops/evidence/v1\0{etype}\0{ref}".encode()).hexdigest()
    return EVIDENCE_ID_PREFIX + digest[:16]


def remediation_priority(severity: str, confidence: str) -> str:
    """P1 (act now) .. P4 (routine). Low confidence downgrades one step, never to nothing."""
    sure, unsure = _PRIORITY[severity]
    return sure if confidence in ("medium", "high") else unsure


@dataclass
class Provenance:
    """Where a piece of evidence came from."""

    module: str
    run_id: str
    check_id: str
    collected_at: str
    collector: str
    report_sha256: str | None = None

    def key(self) -> tuple[str, str, str]:
        return (self.module, self.run_id, self.check_id)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "module": self.module,
            "run_id": self.run_id,
            "check_id": self.check_id,
            "collected_at": self.collected_at,
            "collector": self.collector,
        }
        if self.report_sha256:
            out["report_sha256"] = self.report_sha256
        return out


@dataclass
class Evidence:
    id: str
    type: str
    ref: str
    sha256: str | None = None
    excerpts: list[str] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)

    def merge(self, other: Evidence) -> None:
        if self.sha256 is None:
            self.sha256 = other.sha256
        for ex in other.excerpts:
            if ex not in self.excerpts and len(self.excerpts) < MAX_EXCERPTS_PER_EVIDENCE:
                self.excerpts.append(ex)
        known = {p.key() for p in self.provenance}
        self.provenance += [p for p in other.provenance if p.key() not in known]

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "type": self.type, "ref": self.ref}
        if self.sha256:
            out["sha256"] = self.sha256
        if self.excerpts:
            out["excerpts"] = list(self.excerpts)
        out["provenance"] = [p.to_json() for p in self.provenance]
        return out


@dataclass
class Finding:
    id: str
    check_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    component: str
    hostname: str
    host_id: str
    detected_at: str
    evidence_ids: list[str] = field(default_factory=list)
    remediation: str = ""
    mitre: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    sources: list[dict[str, str]] = field(default_factory=list)
    occurrences: int = 1

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "component": self.component,
            "host": {"hostname": self.hostname, "host_id": self.host_id},
            "detected_at": self.detected_at,
            "evidence": list(self.evidence_ids),
            "remediation": {
                "summary": self.remediation,
                "priority": remediation_priority(self.severity, self.confidence),
            },
            "standards": standards_for(self.category, self.mitre),
            "sources": [dict(s) for s in self.sources],
            "occurrences": self.occurrences,
        }
        if self.references:
            out["references"] = list(self.references)
        return out


def _ts_min(a: str, b: str) -> str:
    return min(a, b)  # ISO 8601 UTC with a fixed layout sorts lexicographically


def merge_findings(a: Finding, b: Finding) -> Finding:
    """Fold ``b`` into ``a`` (same id). Returns ``a``."""
    if a.id != b.id:
        raise FindingError("cannot merge findings with different ids")
    if Severity.parse(b.severity) > Severity.parse(a.severity):
        a.severity = b.severity
        a.title, a.description = b.title, b.description
    if CONFIDENCES.index(b.confidence) > CONFIDENCES.index(a.confidence):
        a.confidence = b.confidence
    a.detected_at = _ts_min(a.detected_at, b.detected_at)
    for eid in b.evidence_ids:
        if eid not in a.evidence_ids and len(a.evidence_ids) < MAX_EVIDENCE_PER_FINDING:
            a.evidence_ids.append(eid)
    for field_name in ("mitre", "references"):
        mine = getattr(a, field_name)
        mine += [x for x in getattr(b, field_name) if x not in mine]
    if not a.remediation:
        a.remediation = b.remediation
    known = {tuple(sorted(s.items())) for s in a.sources}
    a.sources += [s for s in b.sources if tuple(sorted(s.items())) not in known]
    a.occurrences += b.occurrences
    return a


class FindingStore:
    """Collects findings and evidence from any number of reports, deduplicating as it goes."""

    def __init__(self) -> None:
        self.findings: dict[str, Finding] = {}
        self.evidence: dict[str, Evidence] = {}
        self.rejected: list[dict[str, str]] = []

    def _add_evidence(self, ev: Evidence) -> None:
        have = self.evidence.get(ev.id)
        if have is None:
            self.evidence[ev.id] = ev
        else:
            have.merge(ev)

    def add(self, finding: Finding, evidence: list[Evidence]) -> None:
        for ev in evidence:
            self._add_evidence(ev)
        have = self.findings.get(finding.id)
        if have is None:
            self.findings[finding.id] = finding
        else:
            merge_findings(have, finding)

    def add_report(
        self,
        report: dict[str, Any],
        module: str,
        collected_at: str,
        report_sha256: str | None = None,
    ) -> int:
        """Ingest every finding of a (schema-valid) audit report; returns how many were kept.

        A malformed finding is recorded in ``rejected`` and skipped; it never aborts the rest.
        """
        kept = 0
        host = report.get("host") if isinstance(report.get("host"), dict) else {}
        family = (host.get("os") or {}).get("family", "unknown") if isinstance(host, dict) else ""
        hostname = clean(host.get("hostname", "unknown"), 255) if isinstance(host, dict) else "?"
        run = report.get("run") if isinstance(report.get("run"), dict) else {}
        tool = report.get("tool") if isinstance(report.get("tool"), dict) else {}
        collector = clean(f"{tool.get('name', 'unknown')} {tool.get('version', '')}".strip(), 128)
        run_id = clean(run.get("id", "unknown"), 128)
        for raw in report.get("findings", []) if isinstance(report.get("findings"), list) else []:
            try:
                finding, evidence = normalise_finding(
                    raw,
                    hostname,
                    str(family),
                    module,
                    run_id,
                    collected_at,
                    collector,
                    report_sha256,
                )
            except FindingError as exc:
                ident = raw.get("id") if isinstance(raw, dict) else None
                self.rejected.append({"check_id": clean(ident, 64), "reason": str(exc)})
                continue
            self.add(finding, evidence)
            kept += 1
        return kept

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings.values(),
            key=lambda f: (-int(Severity.parse(f.severity)), f.category, f.check_id, f.id),
        )

    def sorted_evidence(self) -> list[Evidence]:
        used = {e for f in self.findings.values() for e in f.evidence_ids}
        return sorted((e for e in self.evidence.values() if e.id in used), key=lambda e: e.id)


def normalise_finding(  # noqa: PLR0913, PLR0917 - mirrors the provenance fields
    raw: Any,
    hostname: str,
    os_family: str,
    module: str,
    run_id: str,
    collected_at: str,
    collector: str,
    report_sha256: str | None = None,
) -> tuple[Finding, list[Evidence]]:
    """Convert one ``audit-report`` finding into a central ``Finding`` plus its evidence."""
    if not isinstance(raw, dict):
        raise FindingError("finding is not an object")
    check_id = raw.get("id")
    if not isinstance(check_id, str) or not _CHECK_ID_RE.match(check_id):
        raise FindingError("finding id is missing or malformed")
    severity = raw.get("severity")
    try:
        Severity.parse(severity if isinstance(severity, str) else "")
    except ValueError:
        raise FindingError(f"unknown severity {clean(severity, 20)!r}") from None
    confidence = raw.get("confidence", "medium")
    if confidence not in CONFIDENCES:
        raise FindingError(f"unknown confidence {clean(confidence, 20)!r}")
    title = clean(raw.get("title"), 300)
    if not title:
        raise FindingError("finding has no title")
    category = clean(raw.get("category"), 64) or "uncategorised"
    hid = host_id(hostname, os_family)
    prov_base = (module, run_id, check_id, collected_at, collector, report_sha256)
    evidence: list[Evidence] = []
    items = raw.get("evidence") if isinstance(raw.get("evidence"), list) else []
    for item in items[:MAX_EVIDENCE_PER_FINDING]:
        if not isinstance(item, dict) or not isinstance(item.get("ref"), str):
            continue
        etype = item.get("type") if item.get("type") in EVIDENCE_TYPES else "other"
        ref = clean(item["ref"], MAX_REF)
        if not ref:
            continue
        digest = item.get("sha256")
        ex = item.get("excerpt")
        evidence.append(
            Evidence(
                id=evidence_id(etype, ref),
                type=etype,
                ref=ref,
                sha256=digest if isinstance(digest, str) and _SHA256_RE.match(digest) else None,
                excerpts=[clean(ex, MAX_EXCERPT)] if isinstance(ex, str) and ex else [],
                provenance=[Provenance(*prov_base)],
            )
        )
    mitre = [t for t in raw.get("mitre_attack", []) if isinstance(t, str)]
    refs = [clean(r, 300) for r in raw.get("references", []) if isinstance(r, str)]
    finding = Finding(
        id=finding_id(hid, check_id, category),
        check_id=check_id,
        title=title,
        description=clean(raw.get("description")),
        severity=severity,
        confidence=confidence,
        category=category,
        component=category,
        hostname=hostname,
        host_id=hid,
        detected_at=collected_at,
        evidence_ids=list(dict.fromkeys(e.id for e in evidence)),
        remediation=clean(raw.get("remediation")),
        mitre=[t for t in mitre if re.match(r"^T\d{4}(\.\d{3})?$", t)],
        references=refs,
        sources=[{"module": module, "run_id": run_id, "check_id": check_id}],
    )
    return finding, evidence
