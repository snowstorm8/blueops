"""Module registry: built-in modules, plugin discovery, dependency planning.

Plugins are *declarative*: a ``<name>.module.json`` manifest (``shared/schemas/module-manifest.
schema.json``) beside the program it launches. Nothing is imported or evaluated, so loading a
manifest cannot run code; running the module can. Plugin directories are therefore operator
choices, and on POSIX a directory or manifest that other users can write to is refused, because
whoever can edit it can make the assessment run their command.
"""

from __future__ import annotations

from pathlib import Path

from shared.engine.builtin import builtin_modules
from shared.engine.module import DEFAULT_TIMEOUT, ModuleError, ModuleSpec
from shared.engine.trust import path_problems
from shared.reporting.jsonio import JsonInputError, load_json_strict
from shared.reporting.schema_lite import validate

MANIFEST_SUFFIX = ".module.json"
MAX_MANIFEST_BYTES = 64 * 1024
MAX_PLUGINS = 200


class PluginError(ModuleError):
    """A plugin directory or manifest was rejected."""


def load_manifest(path: Path) -> ModuleSpec:
    """Parse and validate one plugin manifest."""
    try:
        problems = path_problems(path, want="file")  # NTFS ACLs are not inspected (docs/plugins.md)
        if problems:
            raise PluginError(f"{path}: manifest is not trusted, refusing to load: {problems[0]}")
        doc, _ = load_json_strict(path, MAX_MANIFEST_BYTES, "module manifest")
    except JsonInputError as exc:
        raise PluginError(str(exc)) from None
    problems = validate(doc, "module-manifest.schema.json")
    if problems:
        raise PluginError(f"{path}: invalid manifest: {'; '.join(problems[:5])}")
    spec = ModuleSpec(
        id=doc["id"],
        title=doc["title"],
        description=doc.get("description", ""),
        version=doc.get("version", "1.0.0"),
        platform=doc["platform"],
        category=doc["category"],
        argv=tuple(doc["command"]),
        requires=tuple(doc.get("requires", [])),
        provides=tuple(doc.get("provides", [])),
        timeout_seconds=doc.get("timeout_seconds", DEFAULT_TIMEOUT),
        privilege=doc.get("privilege", "none"),
        output=doc.get("output", "run-dir"),
        source=str(path),
        plugin_dir=str(path.parent.resolve()),
    )
    try:
        spec.validate()
    except ModuleError as exc:
        raise PluginError(f"{path}: {exc}") from None
    return spec


class Registry:
    """The set of modules available to an assessment."""

    def __init__(self) -> None:
        self._modules: dict[str, ModuleSpec] = {}

    @classmethod
    def with_builtins(cls) -> Registry:
        reg = cls()
        for spec in builtin_modules():
            reg.register(spec)
        return reg

    def register(self, spec: ModuleSpec) -> None:
        spec.validate()
        if spec.id in self._modules:
            raise ModuleError(
                f"duplicate module id {spec.id!r} "
                f"(already provided by {self._modules[spec.id].source})"
            )
        self._modules[spec.id] = spec

    def discover(self, plugin_dir: str | Path) -> list[ModuleSpec]:
        """Register every ``*.module.json`` in ``plugin_dir`` (not recursive)."""
        root = Path(plugin_dir)
        if not root.is_dir():
            raise PluginError(f"plugin directory not found: {root}")
        problems = path_problems(root, want="dir")
        if problems:
            raise PluginError(f"{root}: plugin directory is not trusted: {problems[0]}")
        manifests = sorted(p for p in root.iterdir() if p.name.endswith(MANIFEST_SUFFIX))
        if len(manifests) > MAX_PLUGINS:
            raise PluginError(f"{root}: more than {MAX_PLUGINS} manifests")
        found = []
        for path in manifests:
            spec = load_manifest(path)
            self.register(spec)
            found.append(spec)
        return found

    def get(self, module_id: str) -> ModuleSpec:
        try:
            return self._modules[module_id]
        except KeyError:
            raise ModuleError(f"unknown module {module_id!r}") from None

    def __contains__(self, module_id: object) -> bool:
        return module_id in self._modules

    def all(self, platform: str | None = None) -> list[ModuleSpec]:
        mods = sorted(self._modules.values(), key=lambda m: m.id)
        if platform is None:
            return mods
        return [m for m in mods if m.platform in (platform, "any")]

    def check_dependencies(self) -> list[str]:
        """Problems across the whole registry: unknown dependencies and cycles."""
        problems = []
        for spec in self._modules.values():
            for dep in spec.requires:
                if dep not in self._modules:
                    problems.append(f"{spec.id} requires unknown module {dep}")
                elif self._modules[dep].platform not in (spec.platform, "any") and (
                    spec.platform != "any"
                ):
                    problems.append(f"{spec.id} requires {dep}, which is for another platform")
        try:
            self.plan(list(self._modules))
        except ModuleError as exc:
            problems.append(str(exc))
        return problems

    def plan(self, selected: list[str]) -> list[ModuleSpec]:
        """Execution order for ``selected``: dependencies first (added automatically), then the
        requested order. Raises on unknown modules, unknown dependencies and cycles."""
        order: list[ModuleSpec] = []
        state: dict[str, int] = {}  # 1 = in progress, 2 = done

        def visit(mid: str, chain: tuple[str, ...]) -> None:
            if state.get(mid) == 2:
                return
            if state.get(mid) == 1:
                cycle = " -> ".join((*chain[chain.index(mid) :], mid))
                raise ModuleError(f"dependency cycle: {cycle}")
            state[mid] = 1
            spec = self.get(mid) if not chain else self._dep(mid, chain[-1])
            for dep in spec.requires:
                visit(dep, (*chain, mid))
            state[mid] = 2
            order.append(spec)

        for mid in selected:
            visit(mid, ())
        return order

    def _dep(self, dep_id: str, owner: str) -> ModuleSpec:
        if dep_id not in self._modules:
            raise ModuleError(f"{owner} requires unknown module {dep_id!r}")
        return self._modules[dep_id]

    def default_selection(self, platform: str) -> list[str]:
        return [m.id for m in self.all(platform)]
