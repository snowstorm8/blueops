"""Export detection results as JSON Lines or CSV (spreadsheet-safe)."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

CSV_COLUMNS = (
    "detection_id", "rule_id", "title", "severity", "confidence", "nature", "category", "host",
    "status", "attack", "nist", "contributing", "evidence", "remediation", "inputs_verified",
)  # fmt: skip
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection: values that start with a formula character
    get a leading apostrophe (attacker-influenced titles and paths end up in these files)."""
    text = "" if value is None else str(value).replace("\r", " ").replace("\n", " ")
    return "'" + text if text.startswith(_FORMULA) else text


def _verified_cell(results: dict[str, Any]) -> str:
    v = results.get("inputs_verified")
    return "unrecorded" if v is None else ("true" if v else "false")


def to_csv(results: dict[str, Any], cases: dict[str, dict[str, Any]] | None = None) -> str:
    buf = io.StringIO(newline="")
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_COLUMNS)
    for d in results["detections"]:
        c = (cases or {}).get(d["id"], {})
        w.writerow([
            csv_safe(x) for x in (
                d["id"], d["rule"]["id"], d["title"], d["severity"], d["confidence"], d["nature"], d["category"],
                d["host"]["hostname"], c.get("status", "new"),
                ";".join(f"{a['id']}({a['relationship']})" for a in d["references"]["attack"]),
                ";".join(n["id"] for n in d["references"]["nist"]),
                ";".join(x.get("id") or x.get("key", "") for x in d["contributing"]),
                ";".join(d["evidence"]), d["remediation"], _verified_cell(results),
            )
        ])  # fmt: skip
    return buf.getvalue()


def to_jsonl(results: dict[str, Any], cases: dict[str, dict[str, Any]] | None = None) -> str:
    lines = []
    for d in results["detections"]:
        item = dict(d)
        # Per-row copy of the run-level status: a row cut out of the file keeps its caveat.
        item["inputs_verified"] = results.get("inputs_verified")
        if cases and d["id"] in cases:
            item["investigation"] = cases[d["id"]]
        lines.append(json.dumps(item, sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")
