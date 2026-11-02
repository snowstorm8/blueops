"""Build small synthetic assessments from compact specs (rule examples, tests, docs).

A spec describes only what an example needs::

    {"findings": [{"check_id": "USR-UID0-001", "severity": "critical", "category": "users",
                   "evidence": [{"ref": "/etc/passwd", "excerpt": "account 'toor' has UID 0"}]}],
     "inventory": [{"domain": "users", "key": "user:toor", "attrs": {"uid": "0"}}],
     "modules": {"users": "ok"}}

The result is a schema-valid assessment document. Nothing here touches a host.
"""

from __future__ import annotations

from typing import Any

from shared.engine.assessment import assessment_from_report
from shared.reporting.contracts import SCHEMA_VERSION

_OS = {"linux": ("Synthetic Linux", "1.0"), "windows": ("Synthetic Windows", "10.0")}
# Windows collector modules whose findings use a different category name.
_WIN_MODULE = {"accounts": "users", "scheduled-tasks": "tasks", "security-config": "security"}
_DEFAULT_STARTED = "2026-03-01T10:00:00Z"
_DEFAULT_FINISHED = "2026-03-01T10:05:00Z"


def build_assessment(  # noqa: PLR0912, PLR0915
    spec: dict[str, Any],
    *,
    platform: str = "linux",
    hostname: str = "host01",
    aid: str = "example-run",
) -> dict[str, Any]:
    started = spec.get("started_at", _DEFAULT_STARTED)
    finished = spec.get("finished_at", started)
    findings = []
    for i, f in enumerate(spec.get("findings", [])):
        item: dict[str, Any] = {
            "id": f["check_id"],
            "title": f.get("title", f"Synthetic finding {f['check_id']}"),
            "severity": f.get("severity", "medium"),
            "confidence": f.get("confidence", "high"),
            "category": f.get("category", "users"),
            "description": f.get("description", f"Synthetic description {i}."),
        }
        if f.get("evidence"):
            item["evidence"] = [
                {"type": e.get("type", "file"), "ref": e["ref"], **({"excerpt": e["excerpt"]} if "excerpt" in e else {})}
                for e in f["evidence"]
            ]  # fmt: skip
        if f.get("remediation", True):
            item["remediation"] = f.get("remediation", "Review and remediate.")
        findings.append(item)
    records = [
        {"domain": r["domain"], **({"scope": r["scope"]} if r.get("scope") else {}), "key": r["key"], "attrs": r.get("attrs", {}),
         **({"evidence": [{"type": "file", "ref": e} for e in r["evidence"]]} if r.get("evidence") else {})}
        for r in spec.get("inventory", [])
    ]  # fmt: skip
    seen = sorted({(r["domain"], r.get("scope", "")) for r in records})
    coverage = spec.get("coverage") or [
        {"domain": d, **({"scope": s} if s else {}), "status": "complete"} for d, s in seen
    ]
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "synthetic", "version": "0.0.0", "category": "audit"},
        "run": {"id": aid, "started_at": started, "finished_at": finished, "mode": "read-only", "dry_run": False, "exit_code": 0},
        "host": {"hostname": hostname, "os": {"family": platform, "name": _OS[platform][0], "version": _OS[platform][1]}, "arch": "x86_64", "elevated": spec.get("elevated", True)},
        "findings": findings,
        "errors": [],
        "inventory": {"coverage": coverage, "records": records},
        "summary": {"total": len(findings), "by_severity": dict.fromkeys(("info", "low", "medium", "high", "critical"), 0)},
    }  # fmt: skip
    for f in findings:
        report["summary"]["by_severity"][f["severity"]] += 1
    doc = assessment_from_report(report)

    # Per-module breakdown: findings are attributed to the module named after their category.
    def module_of(category: str) -> str:
        return _WIN_MODULE.get(category, category) if platform == "windows" else category

    modules = dict(spec.get("modules", {}))
    for f in doc["findings"]:
        modules.setdefault(module_of(f["category"]), "ok")
    for f in doc["findings"]:
        for s in f["sources"]:
            s["module"] = f"{platform}.{module_of(f['category'])}"
    for e in doc["evidence"]:
        for p in e["provenance"]:
            cat = next(
                (f["category"] for f in doc["findings"] if e["id"] in f["evidence"]), "users"
            )
            p["module"] = f"{platform}.{module_of(cat)}"
    doc["assessment"]["profile"] = "example"
    doc["assessment"]["modules"] = [f"{platform}.{m}" for m in sorted(modules)]
    doc["modules"] = [
        {
            "id": f"{platform}.{m}", "status": st, "started_at": started, "finished_at": finished,
            "duration_seconds": 0.1, "findings": sum(1 for f in doc["findings"] if module_of(f["category"]) == m),
            **({"reason": "synthetic"} if st != "ok" else {}),
        }
        for m, st in sorted(modules.items())
    ]  # fmt: skip
    doc["assessment"]["status"] = (
        "complete" if all(v == "ok" for v in modules.values()) else "partial"
    )
    doc["assessment"]["id"] = aid
    return doc
