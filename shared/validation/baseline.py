"""Known-good baselines and environment comparison.

A baseline is a verified telemetry store plus metadata. Comparing a later capture against it yields
*differences*, each classified ``expected`` (the baseline's own declared allowances say so) or
``unexpected``, and each with an explanation of why it matters and how to review it. A difference
is never labelled malicious: most differences in a real environment are deployments, updates and
users. Staleness and incompatibility are surfaced before any difference is trusted.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shared.engine.manifest import write_manifest
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.schema_lite import validate
from shared.rules.conditions import check_pattern
from shared.telemetry.compare import CompareError, compare_telemetry
from shared.telemetry.ingest import DOC_NAME, IngestError, load_telemetry
from shared.validation.evaluate import COVERAGE_RANK, observed_coverage
from shared.validation.model import VALIDATION_SCHEMA_VERSION
from shared.validation.runner import utc_now

BASELINE_FILE = "baseline.json"
MAX_META_BYTES = 4 * 1024 * 1024

WHY = {
    ("listener", "added"): (
        "A new listening socket changes how the host can be reached.",
        "Find the owning process, check change records for a deployment, and check whether the port is reachable from untrusted networks.",
    ),
    ("listener", "removed"): (
        "A listener that existed in the baseline is gone; a service may have stopped.",
        "Check whether the service was meant to stop and whether anything depends on the port.",
    ),
    ("service", "added"): (
        "A new service starts programs automatically, with its own privileges.",
        "Reconcile with change records; inspect the service's binary and account.",
    ),
    ("service", "removed"): (
        "A service present in the baseline is no longer registered.",
        "Check whether it was uninstalled deliberately.",
    ),
    ("service", "changed"): (
        "A service's command, account or start mode changed, which changes what runs.",
        "Compare before and after; confirm the change with whoever manages the service.",
    ),
    ("scheduled_task", "added"): (
        "A new scheduled job runs code on a schedule, often with elevated rights.",
        "Read the command, check who created it and whether a change record exists.",
    ),
    ("scheduled_task", "removed"): (
        "A scheduled job from the baseline is gone.",
        "Confirm the removal was intended.",
    ),
    ("scheduled_task", "changed"): (
        "A scheduled job's command, schedule or account changed.",
        "Compare before and after; a changed command is more informative than a changed schedule.",
    ),
    ("user", "added"): (
        "A new local account is a new way to authenticate.",
        "Confirm the account is expected, owned and has appropriate rights.",
    ),
    ("user", "removed"): (
        "A local account from the baseline is gone.",
        "Confirm the removal was intended.",
    ),
    ("user", "changed"): (
        "An account's attributes (shell, enabled state, password state) changed.",
        "Check which attribute changed and whether it widens access.",
    ),
    ("group", "changed"): (
        "Group membership changed; privileged groups change who holds administrative rights.",
        "Compare the member lists and confirm each addition or removal.",
    ),
    ("integrity", "changed"): (
        "The content of a monitored file changed (its hash differs).",
        "Diff against a trusted copy and find who changed it and why.",
    ),
    ("integrity", "removed"): (
        "A monitored file from the baseline is missing.",
        "Check whether it was removed deliberately or by an upgrade.",
    ),
    ("integrity", "added"): (
        "A monitored location now holds a file that did not exist in the baseline.",
        "Check what created it.",
    ),
    ("persistence", "added"): (
        "A new autostart location entry runs code at boot or logon.",
        "Read the value, check who added it and when.",
    ),
    ("persistence", "changed"): ("An autostart entry changed.", "Compare before and after."),
    ("system_config", "changed"): (
        "A security-relevant setting changed value.",
        "Check the setting's direction (weaker or stronger) and who changed it.",
    ),
    ("process", "added"): (
        "A program is running that was not running in the baseline.",
        "Processes come and go; check the program, its parent and its owner before drawing conclusions.",
    ),
    ("network_connection", "added"): (
        "A connection exists that the baseline did not have.",
        "Connections are transient; check the peer and the owning process.",
    ),
    ("auth_event", "added"): (
        "Authentication events occurred in the later window.",
        "Events accumulate over time; review them with the authentication rules rather than as drift.",
    ),
}
GENERIC = (
    "The telemetry differs from the baseline.",
    "Review the item against change records before drawing a conclusion; a difference alone does not indicate a problem.",
)


class BaselineError(ValueError):
    """The baseline cannot be created, read or used."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def _major(version: str) -> str:
    return version.split(".", maxsplit=1)[0] if version else ""


def capture_baseline(
    store: str | Path,
    out_dir: str | Path,
    name: str,
    *,
    purpose: str = "",
    max_age_days: int = 30,
    expected_changes: list[dict[str, Any]] | None = None,
    lab_attested: bool = False,
    captured_at: str | None = None,
) -> Path:
    """Copy a verified telemetry store into ``<out_dir>/<name>`` with metadata (never overwrites)."""
    from shared.engine import ENGINE_VERSION  # noqa: PLC0415

    try:
        tel = load_telemetry(store)
    except IngestError as exc:
        raise BaselineError(f"cannot capture a baseline from {store}: {exc}") from None
    meta: dict[str, Any] = {
        "schema_version": VALIDATION_SCHEMA_VERSION,
        "kind": "validation-baseline",
        "name": name,
        "captured_at": captured_at or utc_now(),
        "purpose": purpose[:300],
        "max_age_days": max_age_days,
        "host": {"host_id": tel["host"]["host_id"], "hostname": tel["host"]["hostname"], "os": tel["host"]["os"], **({"arch": tel["host"]["arch"]} if tel["host"].get("arch") else {})},
        "source": {
            "collection_id": tel["collection"]["id"], "mode": tel["collection"]["mode"],
            "started_at": tel["collection"]["started_at"], "ended_at": tel["collection"]["ended_at"],
            "records": tel["summary"]["records"], "complete": tel["summary"]["complete"],
            "coverage": observed_coverage(tel), "collectors": tel["collection"]["collectors"],
            "telemetry_schema": tel["schema_version"], "errors": sorted({e["code"] for e in tel["errors"]}),
        },
        "expected_changes": expected_changes or [],
        "lab_attested": lab_attested,
        "tool_versions": {"engine": ENGINE_VERSION, "validation": VALIDATION_SCHEMA_VERSION},
    }  # fmt: skip
    problems = validate(meta, "validation-baseline.schema.json", limit=5)
    if problems:
        raise BaselineError("invalid baseline metadata: " + "; ".join(problems))
    for item in meta["expected_changes"]:
        pat = item.get("identity_pattern")
        if pat:
            bad = check_pattern(pat)
            if bad:
                raise BaselineError(f"expected_changes pattern {pat!r}: {bad}")
            re.compile(pat)
    root = Path(out_dir) / name
    root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.mkdir(root, 0o700)
    except FileExistsError:
        raise BaselineError(f"{root} already exists; a baseline is never overwritten") from None
    for fname, text in (
        (DOC_NAME, json.dumps(tel, indent=2, ensure_ascii=False)),
        (BASELINE_FILE, json.dumps(meta, indent=2)),
    ):
        fd = os.open(root / fname, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text + "\n")
    write_manifest(
        root,
        {
            "assessment": {
                "id": tel["collection"]["id"],
                "started_at": tel["collection"]["started_at"].split(".")[0].rstrip("Z") + "Z",
                "finished_at": tel["collection"]["ended_at"].split(".")[0].rstrip("Z") + "Z",
                "exit_code": 0,
            }
        },
    )
    return root


def load_baseline(path: str | Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """``(metadata, telemetry)`` of a baseline directory; refuses a missing or tampered manifest."""
    root = Path(path)
    try:
        tel = load_telemetry(root)  # verifies the manifest and the telemetry schema
    except IngestError as exc:
        raise BaselineError(f"{root}: {exc}") from None
    try:
        meta, _ = load_json_strict(root / BASELINE_FILE, MAX_META_BYTES, "baseline metadata")
    except JsonInputError as exc:
        raise BaselineError(str(exc)) from None
    problems = validate(meta, "validation-baseline.schema.json", limit=5)
    if problems:
        raise BaselineError(f"{root}: invalid baseline metadata: {'; '.join(problems)}")
    if meta["host"]["host_id"] != tel["host"]["host_id"]:
        raise BaselineError(f"{root}: metadata and telemetry describe different hosts")
    return meta, tel


def _issue(code: str, severity: str, message: str) -> dict[str, str]:
    return {"code": code, "severity": severity, "message": message}


def check_baseline(  # noqa: PLR0912 - compatibility, cross-platform parity and differences
    meta: dict[str, Any],
    tel: dict[str, Any],
    current: dict[str, Any] | None = None,
    *,
    now: datetime | None = None,
    max_age_days: int | None = None,
) -> list[dict[str, str]]:
    """Why this baseline may not be a sound reference (and for a given capture, why not for it)."""
    now = now or _now()
    out: list[dict[str, str]] = []
    limit = max_age_days or meta["max_age_days"]
    age = (now - _parse(meta["captured_at"])).days
    if age > limit:
        out.append(
            _issue(
                "STALE",
                "warning",
                f"the baseline is {age} days old (limit {limit}); differences may reflect ordinary drift",
            )
        )
    if _major(meta["source"]["telemetry_schema"]) != _major(tel["schema_version"]):
        out.append(
            _issue(
                "SCHEMA_INCOMPATIBLE",
                "error",
                "baseline metadata and telemetry use different telemetry schema versions",
            )
        )
    if not meta["source"]["complete"]:
        weak = sorted(
            c
            for c, s in meta["source"]["coverage"].items()
            if s not in ("complete", "not_applicable")
        )
        out.append(
            _issue(
                "BASELINE_INCOMPLETE",
                "warning",
                "the baseline was captured with incomplete coverage"
                + (f" ({', '.join(weak)})" if weak else "")
                + "; differences in those categories are not conclusive",
            )
        )
    if "TEST_MODE" in meta["source"]["errors"]:
        out.append(
            _issue(
                "TEST_MODE",
                "warning",
                "the baseline was captured with fixture hooks, not from a real host",
            )
        )
    if not meta["lab_attested"]:
        out.append(
            _issue(
                "NOT_LAB_ATTESTED",
                "info",
                "the baseline was not captured in an attested lab: 'known good' is the operator's claim",
            )
        )
    if current is None:
        return out
    if _major(current["schema_version"]) != _major(tel["schema_version"]):
        out.append(
            _issue(
                "SCHEMA_INCOMPATIBLE",
                "error",
                f"the capture uses telemetry schema {current['schema_version']}, the baseline {tel['schema_version']}",
            )
        )
    bf, cf = tel["host"]["os"]["family"], current["host"]["os"]["family"]
    if bf != cf:
        out.append(
            _issue(
                "CROSS_PLATFORM",
                "info",
                f"baseline is {bf}, capture is {cf}: only coverage parity can be compared, not identities",
            )
        )
    else:
        if tel["host"]["host_id"] != current["host"]["host_id"]:
            out.append(
                _issue(
                    "HOST_MISMATCH",
                    "error",
                    "the capture and the baseline describe different hosts",
                )
            )
        bv, cv = tel["host"]["os"].get("version"), current["host"]["os"].get("version")
        if bv and cv and bv != cv:
            out.append(
                _issue(
                    "OS_VERSION_DIFFERS",
                    "warning",
                    f"OS version differs ({bv} vs {cv}); package and service differences are expected",
                )
            )
    bc = {c["name"]: c["version"] for c in tel["collection"]["collectors"]}
    for c in current["collection"]["collectors"]:
        if c["name"] in bc and _major(bc[c["name"]]) != _major(c["version"]):
            out.append(
                _issue(
                    "COLLECTOR_MAJOR_DIFFERS",
                    "warning",
                    f"collector {c['name']} major version differs ({bc[c['name']]} vs {c['version']}); attributes may differ",
                )
            )
    now_cov = observed_coverage(current)
    lost = sorted(
        c
        for c, s in meta["source"]["coverage"].items()
        if s == "complete" and COVERAGE_RANK.get(now_cov.get(c, "unavailable"), 2) > 0
    )
    if lost:
        out.append(
            _issue(
                "COVERAGE_REGRESSION",
                "warning",
                "categories complete in the baseline are not complete now: " + ", ".join(lost),
            )
        )
    return out


def _allowed(
    meta: dict[str, Any], category: str, change: str, identity: str, attrs: list[str]
) -> str | None:
    for rule in meta["expected_changes"]:
        if rule["category"] != category:
            continue
        if rule.get("change") and rule["change"] != change:
            continue
        pat = rule.get("identity_pattern")
        if pat and not re.search(pat, identity[:512]):
            continue
        if rule.get("attributes") and not set(attrs) <= set(rule["attributes"]):
            continue
        return str(rule["reason"])
    return None


def _difference(
    meta: dict[str, Any], cat: str, change: str, item: dict[str, Any], determinate: bool
) -> dict[str, Any]:
    attrs = item.get("attributes", [])
    why, how = WHY.get((cat, change), GENERIC)
    reason = _allowed(meta, cat, change, item["identity"], [a["name"] for a in attrs])
    out = {
        "category": cat, "change": change, "identity": item["identity"][:300], "record_id": item["record_id"],
        "summary": item.get("summary", item["identity"])[:200], "classification": "expected" if reason else "unexpected",
        "why_it_matters": why, "how_to_review": how, "category_determinate": determinate,
    }  # fmt: skip
    if reason:
        out["expected_by"] = reason
    if attrs:
        out["attributes"] = [
            {"name": a["name"], "before": a.get("before"), "after": a.get("after")}
            for a in attrs[:12]
        ]
    return out


def diff_baseline(  # noqa: PLR0912 - compatibility, cross-platform parity, differences
    meta: dict[str, Any],
    base_tel: dict[str, Any],
    current: dict[str, Any],
    *,
    now: datetime | None = None,
    max_age_days: int | None = None,
) -> dict[str, Any]:
    compat = check_baseline(meta, base_tel, current, now=now, max_age_days=max_age_days)
    errors = [c for c in compat if c["severity"] == "error"]
    cross = base_tel["host"]["os"]["family"] != current["host"]["os"]["family"]
    diffs: list[dict[str, Any]] = []
    indeterminate: list[dict[str, str]] = []
    parity: list[dict[str, Any]] = []
    if cross:
        bc, cc = observed_coverage(base_tel), observed_coverage(current)
        bn = {c: sum(1 for r in base_tel["records"] if r["category"] == c) for c in bc}
        cn = {c: sum(1 for r in current["records"] if r["category"] == c) for c in cc}
        for cat in sorted(set(bc) | set(cc)):
            b, c = bc.get(cat, "absent"), cc.get(cat, "absent")
            note = "same coverage status" if b == c else "coverage differs between the platforms"
            parity.append(
                {
                    "category": cat,
                    "baseline": {"status": b, "records": bn.get(cat, 0)},
                    "current": {"status": c, "records": cn.get(cat, 0)},
                    "note": note,
                }
            )
    elif not errors:
        try:
            cmp = compare_telemetry(base_tel, current, generated_at=utc_now())
        except CompareError as exc:
            errors.append(_issue("COMPARE_FAILED", "error", str(exc)))
        else:
            indeterminate = cmp["indeterminate"]
            for cat, block in sorted(cmp["categories"].items()):
                for change in ("added", "removed", "changed"):
                    diffs += [
                        _difference(meta, cat, change, it, block["determinate"])
                        for it in block[change]
                    ]
    unexpected = sum(1 for d in diffs if d["classification"] == "unexpected")
    if errors:
        status = "incompatible"
    elif unexpected:
        status = "unexpected_differences"
    elif indeterminate or cross:
        status = "incomplete"
    else:
        status = "ok"
    doc = {
        "schema_version": VALIDATION_SCHEMA_VERSION, "kind": "validation-baseline-diff", "generated_at": utc_now(),
        "mode": "cross_platform" if cross else "same_platform",
        "baseline": {"name": meta["name"], "captured_at": meta["captured_at"], "host_id": meta["host"]["host_id"], "os": meta["host"]["os"], "records": meta["source"]["records"]},
        "current": {"collection_id": current["collection"]["id"], "started_at": current["collection"]["started_at"], "host_id": current["host"]["host_id"], "os": current["host"]["os"], "records": current["summary"]["records"], "complete": current["summary"]["complete"]},
        "compatibility": compat, "differences": diffs, "indeterminate": indeterminate, "parity": parity,
        "summary": {"total": len(diffs), "expected": len(diffs) - unexpected, "unexpected": unexpected, "indeterminate_categories": len(indeterminate), "exit_status": status},
    }  # fmt: skip
    problems = validate(doc, "validation-baseline-diff.schema.json", limit=5)
    if problems:
        raise BaselineError(
            "internal error: baseline diff violates its schema: " + "; ".join(problems)
        )
    return doc
