"""Assessment profiles: named module selections (``profiles/<platform>/<name>.json``)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.engine.module import ModuleError
from shared.engine.registry import Registry
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.schema_lite import validate

PROFILES_DIR = Path(__file__).resolve().parent.parent.parent / "profiles"
MAX_PROFILE_BYTES = 64 * 1024
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")


class ProfileError(ModuleError):
    """A profile is missing, malformed or names modules that do not exist."""


@dataclass
class Profile:
    name: str
    platform: str
    modules: list[str]
    description: str = ""
    fail_on: str = "medium"
    timeout_seconds: int | None = None
    options: dict[str, Any] = field(default_factory=dict)
    source: str = ""

    def resolve(self, registry: Registry) -> list[str]:
        """Module ids this profile runs on its platform (``all`` expanded, unknown ids rejected)."""
        out: list[str] = []
        for mid in self.modules:
            if mid == "all":
                out += [m for m in registry.default_selection(self.platform) if m not in out]
                continue
            spec = registry.get(mid) if mid in registry else None
            if spec is None:
                raise ProfileError(f"profile {self.name}: unknown module {mid!r}")
            if spec.platform not in (self.platform, "any"):
                raise ProfileError(f"profile {self.name}: {mid} is not a {self.platform} module")
            if mid not in out:
                out.append(mid)
        return out


def load_profile_file(path: str | Path) -> Profile:
    p = Path(path)
    try:
        doc, _ = load_json_strict(p, MAX_PROFILE_BYTES, "profile")
    except JsonInputError as exc:
        raise ProfileError(str(exc)) from None
    problems = validate(doc, "assessment-profile.schema.json")
    if problems:
        raise ProfileError(f"{p}: invalid profile: {'; '.join(problems[:5])}")
    return Profile(
        name=doc["name"],
        platform=doc["platform"],
        modules=list(doc["modules"]),
        description=doc.get("description", ""),
        fail_on=doc.get("fail_on", "medium"),
        timeout_seconds=doc.get("timeout_seconds"),
        options=dict(doc.get("options", {})),
        source=str(p),
    )


def find_profile(name_or_path: str, platform: str, profiles_dir: Path = PROFILES_DIR) -> Profile:
    """A profile by file path, or by name in ``profiles/<platform>/``."""
    if _NAME_RE.match(name_or_path):
        path = profiles_dir / platform / f"{name_or_path}.json"
        if not path.is_file():
            raise ProfileError(
                f"no profile {name_or_path!r} for {platform} (available: "
                f"{', '.join(list_profiles(platform, profiles_dir)) or 'none'})"
            )
    else:
        path = Path(name_or_path)
    profile = load_profile_file(path)
    if profile.platform != platform:
        raise ProfileError(f"profile {profile.name} is for {profile.platform}, not {platform}")
    return profile


def list_profiles(platform: str, profiles_dir: Path = PROFILES_DIR) -> list[str]:
    d = profiles_dir / platform
    return sorted(p.stem for p in d.glob("*.json")) if d.is_dir() else []
