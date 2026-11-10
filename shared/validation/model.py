"""Scenario model: loading, schema and semantic validation of scenario packs.

A scenario is *data*: a telemetry dataset, the detections/coverage BlueOps is expected to report
for it, and (for live labs only) a closed set of harmless actions. Loading never runs anything.
Invalid scenarios are excluded and reported; valid ones still load, like rule packs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.schema_lite import validate
from shared.rules.conditions import ConditionError, compile_condition
from shared.rules.subjects import field_known
from shared.telemetry.model import CATEGORIES

VALIDATION_SCHEMA_VERSION = "1.0.0"
SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
MAX_PACK_BYTES = 8 * 1024 * 1024
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
CONFIDENCE_ORDER = ("low", "medium", "high")
KINDS = ("positive", "negative", "coverage")


@dataclass(frozen=True)
class Diagnostic:
    level: str  # error | warning
    where: str
    message: str

    def __str__(self) -> str:
        return f"{self.level}: {self.where}: {self.message}"


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    description: str
    objective: str
    kind: str
    platforms: tuple[str, ...]
    supported_versions: tuple[str, ...]
    tags: tuple[str, ...]
    preconditions: tuple[dict[str, Any], ...]
    dataset: dict[str, Any]
    baseline_dataset: dict[str, Any] | None
    rules_under_test: tuple[str, ...]
    expect: dict[str, Any]
    cleanup: dict[str, Any]
    lab: dict[str, Any] | None
    live_only: bool
    known_issue: dict[str, Any] | None
    limitations: tuple[str, ...]
    pack: str = ""
    sha256: str = ""
    source_dir: str = field(default="", compare=False)
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def dataset_platform(self) -> str:
        return str(self.dataset.get("platform") or self.platforms[0])

    @property
    def live_capable(self) -> bool:
        return bool(self.lab and self.lab.get("actions") is not None)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "kind": self.kind,
            "platforms": list(self.platforms),
            "pack": self.pack,
            "rules": list(self.rules_under_test),
            "live": self.live_capable,
            "live_only": self.live_only,
            "tags": list(self.tags),
        }


@dataclass
class ScenarioSet:
    scenarios: dict[str, Scenario] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    packs: list[dict[str, Any]] = field(default_factory=list)

    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.level == "error"]

    def ordered(self) -> list[Scenario]:
        return [self.scenarios[k] for k in sorted(self.scenarios)]

    def select(
        self,
        ids: list[str] | None = None,
        platform: str | None = None,
        kind: str | None = None,
        tag: str | None = None,
    ) -> list[Scenario]:
        out = []
        for s in self.ordered():
            if ids and s.id not in ids:
                continue
            if platform and platform not in s.platforms:
                continue
            if kind and s.kind != kind:
                continue
            if tag and tag not in s.tags:
                continue
            out.append(s)
        return out


def canonical_sha256(obj: Any) -> str:
    text = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode()).hexdigest()


def _rng_ok(rng: dict[str, Any], order: tuple[str, ...]) -> bool:
    lo, hi = rng.get("min"), rng.get("max")
    return not (lo and hi and order.index(lo) > order.index(hi))


def _count_ok(c: Any) -> bool:
    if isinstance(c, dict):
        return not (("min" in c and "max" in c) and c["min"] > c["max"])
    return True


def _check_scenario(raw: dict[str, Any], where: str) -> list[Diagnostic]:  # noqa: PLR0912, PLR0915
    out: list[Diagnostic] = []
    sid = raw["id"]
    exp = raw["expect"]
    plat = raw["platforms"]

    def err(msg: str) -> None:
        out.append(Diagnostic("error", f"{where} ({sid})", msg))

    prefix = sid.split("-")[1]
    want = {"LNX": ["linux"], "WIN": ["windows"]}.get(prefix)
    if want is not None and plat != want:
        err(f"id prefix {prefix} and platforms {plat} disagree")
    if prefix == "ANY" and sorted(plat) != ["linux", "windows"]:
        err("an ANY scenario must list both platforms")
    ds = raw["dataset"]
    if "store" not in ds and "records" not in ds:
        err("dataset needs 'records' (synthetic) or 'store' (recorded)")
    if ds.get("platform") and ds["platform"] not in plat:
        err(f"dataset platform {ds['platform']} is not among the scenario platforms")
    kind = raw["kind"]
    dets, absent, indet = (
        exp.get("detections", []),
        exp.get("absent", []),
        exp.get("indeterminate", []),
    )
    if kind == "positive" and not dets:
        err("a positive scenario must expect at least one detection")
    if kind == "negative" and not (absent or exp.get("no_other_detections")):
        err("a negative scenario must list absent rules or set no_other_detections")
    if kind == "negative" and dets:
        err("a negative scenario cannot expect detections")
    if kind == "coverage" and not (exp.get("coverage") or indet):
        err("a coverage scenario must state expected coverage or indeterminate rules")
    clash = {d["rule"] for d in dets} & set(absent)
    if clash:
        err(f"rule(s) both expected and absent: {', '.join(sorted(clash))}")
    clash = ({d["rule"] for d in dets} | set(absent)) & {i["rule"] for i in indet}
    if clash:
        err(f"rule(s) both asserted and expected indeterminate: {', '.join(sorted(clash))}")
    for d in dets:
        if not _rng_ok(d.get("severity", {}), SEVERITY_ORDER):
            err(f"{d['rule']}: severity min is above max")
        if not _rng_ok(d.get("confidence", {}), CONFIDENCE_ORDER):
            err(f"{d['rule']}: confidence min is above max")
        if not _count_ok(d.get("count", 1)):
            err(f"{d['rule']}: count min is above max")
    for i, t in enumerate(exp.get("telemetry", [])):
        if t["category"] not in CATEGORIES:
            err(f"expect.telemetry[{i}]: unknown category {t['category']!r}")
        if not _count_ok(t.get("count", {"min": 1})):
            err(f"expect.telemetry[{i}]: count min is above max")
        if "where" in t:
            try:
                node = compile_condition(t["where"], f"expect.telemetry[{i}].where")
            except ConditionError as exc:
                err(str(exc))
                continue
            bad = sorted(f for f in node.fields if not field_known("telemetry", f))
            if bad:
                err(f"expect.telemetry[{i}].where: unknown field(s) {', '.join(bad)}")
    for cat in exp.get("coverage", {}):
        if cat not in CATEGORIES:
            err(f"expect.coverage: unknown category {cat!r}")
    lab = raw.get("lab")
    if raw.get("live_only") and lab is None:
        err("a live_only scenario needs a lab section")
    if lab is not None and not lab.get("actions") and not lab.get("collect_categories"):
        err("a lab section needs actions or collect_categories")
    return out


def load_pack_file(path: Path) -> tuple[list[Scenario], list[Diagnostic], dict[str, Any] | None]:
    try:
        doc, raw_bytes = load_json_strict(path, MAX_PACK_BYTES, "scenario pack")
    except JsonInputError as exc:
        return [], [Diagnostic("error", str(path), str(exc))], None
    problems = validate(doc, "validation-scenario.schema.json", limit=8)
    if problems:
        return [], [Diagnostic("error", path.name, p) for p in problems], None
    diags: list[Diagnostic] = []
    out: list[Scenario] = []
    seen: set[str] = set()
    pack = doc["pack"]["name"]
    for i, raw in enumerate(doc["scenarios"]):
        found = _check_scenario(raw, f"{path.name}:scenarios[{i}]")
        diags += found
        if found:
            continue
        if raw["id"] in seen:
            diags.append(Diagnostic("error", path.name, f"duplicate scenario id {raw['id']}"))
            continue
        seen.add(raw["id"])
        exp = raw["expect"]
        under = list(raw.get("rules_under_test", []))
        for rule in (
            [d["rule"] for d in exp.get("detections", [])]
            + list(exp.get("absent", []))
            + [x["rule"] for x in exp.get("indeterminate", [])]
        ):
            if rule not in under:
                under.append(rule)
        out.append(
            Scenario(
                id=raw["id"], title=raw["title"], description=raw["description"],
                objective=raw["objective"], kind=raw["kind"], platforms=tuple(raw["platforms"]),
                supported_versions=tuple(raw.get("supported_versions", ["any"])),
                tags=tuple(raw.get("tags", [])), preconditions=tuple(raw.get("preconditions", [])),
                dataset=raw["dataset"], baseline_dataset=raw.get("baseline_dataset"),
                rules_under_test=tuple(under), expect=exp, cleanup=raw.get("cleanup", {}),
                lab=raw.get("lab"), known_issue=raw.get("known_issue"), live_only=bool(raw.get("live_only")), limitations=tuple(raw["limitations"]), pack=pack,
                sha256=canonical_sha256(raw), raw=raw, source_dir=str(path.parent),
            )
        )  # fmt: skip
    info = {
        "name": pack,
        "version": doc["pack"]["version"],
        "scenarios": len(out),
        "source": path.name,
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }
    return out, diags, info


def pack_files(location: Path) -> list[Path]:
    if location.is_dir():
        return sorted(p for p in location.iterdir() if p.suffix == ".json" and p.is_file())
    if location.is_file():
        return [location]
    raise FileNotFoundError(f"{location}: no such scenario file or directory")


def load_scenarios(
    extra: list[str | Path] | None = None, *, include_library: bool = True
) -> ScenarioSet:
    """The built-in library plus ``extra`` files/directories. Ids may be defined once."""
    ss = ScenarioSet()
    locations = ([SCENARIO_DIR] if include_library else []) + [Path(p) for p in extra or []]
    for loc in locations:
        try:
            files = pack_files(loc)
        except (FileNotFoundError, OSError) as exc:
            ss.diagnostics.append(Diagnostic("error", str(loc), str(exc)))
            continue
        for f in files:
            scenarios, diags, info = load_pack_file(f)
            ss.diagnostics += diags
            if info:
                ss.packs.append(info)
            for s in scenarios:
                if s.id in ss.scenarios:
                    ss.diagnostics.append(
                        Diagnostic("error", f.name, f"scenario {s.id} is already defined")
                    )
                    continue
                ss.scenarios[s.id] = s
    return ss


def check_against_rules(ss: ScenarioSet, known_rules: set[str]) -> list[Diagnostic]:
    """Rules named by scenarios must exist: a typo would otherwise assert about nothing."""
    out = []
    for s in ss.ordered():
        for rule in s.rules_under_test:
            if rule not in known_rules:
                out.append(Diagnostic("error", s.id, f"unknown rule {rule}"))
    return out
