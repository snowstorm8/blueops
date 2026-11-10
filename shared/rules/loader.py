"""Load rule packs from disk (strict JSON, size caps), validate, merge, apply overrides."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.rules.model import Rule
from shared.rules.validate import Diagnostic, validate_pack

LIBRARY_DIR = Path(__file__).resolve().parent / "library"
MAX_PACK_BYTES = 1024 * 1024
MAX_PACKS = 100


@dataclass
class RuleSet:
    rules: dict[str, Rule] = field(default_factory=dict)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    packs: list[dict[str, Any]] = field(default_factory=list)

    @property
    def errors(self) -> list[Diagnostic]:
        return [d for d in self.diagnostics if d.level == "error"]

    def ordered(self) -> list[Rule]:
        return [self.rules[k] for k in sorted(self.rules)]


def load_pack_file(path: Path) -> tuple[list[Rule], list[Diagnostic], dict[str, Any] | None]:
    try:
        doc, raw = load_json_strict(path, MAX_PACK_BYTES, "rule pack")
    except JsonInputError as exc:
        return [], [Diagnostic("error", str(path), str(exc))], None
    rules, diags = validate_pack(doc, str(path))
    diags = [Diagnostic(d.level, f"{path.name}:{d.path}", d.message, d.rule) for d in diags]
    info = None
    if isinstance(doc, dict) and isinstance(doc.get("pack"), dict):
        info = {
            "name": doc["pack"].get("name"), "version": doc["pack"].get("version"),
            "source": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "rules": len(rules),
        }  # fmt: skip
    return rules, diags, info


def pack_files(location: Path) -> list[Path]:
    if location.is_file():
        return [location]
    if not location.is_dir():
        raise FileNotFoundError(f"rule location not found: {location}")
    files = sorted(p for p in location.iterdir() if p.suffix == ".json" and p.is_file())
    if len(files) > MAX_PACKS:
        raise ValueError(f"{location}: more than {MAX_PACKS} rule packs")
    return files


def load_rule_set(
    extra: list[str | Path] | None = None,
    *,
    include_library: bool = True,
    enable: list[str] | None = None,
    disable: list[str] | None = None,
) -> RuleSet:
    """Library plus ``extra`` files/directories. A rule id may be defined once; later duplicates
    are errors and are excluded (a pack cannot silently replace a library rule)."""
    rs = RuleSet()
    locations: list[Path] = [LIBRARY_DIR] if include_library else []
    locations += [Path(p) for p in extra or []]
    for loc in locations:
        try:
            files = pack_files(loc)
        except (FileNotFoundError, ValueError) as exc:
            rs.diagnostics.append(Diagnostic("error", str(loc), str(exc)))
            continue
        for f in files:
            rules, diags, info = load_pack_file(f)
            rs.diagnostics += diags
            if info:
                rs.packs.append(info)
            for r in rules:
                if r.id in rs.rules:
                    rs.diagnostics.append(
                        Diagnostic(
                            "error",
                            f.name,
                            f"rule id already defined in pack {rs.rules[r.id].pack!r}",
                            r.id,
                        )
                    )
                else:
                    rs.rules[r.id] = r
    for ids, state in ((enable or [], True), (disable or [], False)):
        for rid in ids:
            if rid not in rs.rules:
                rs.diagnostics.append(Diagnostic("error", "override", f"unknown rule id {rid!r}"))
            else:
                rs.rules[rid] = replace(rs.rules[rid], enabled=state)
    return rs
