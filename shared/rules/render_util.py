"""Small Markdown helpers shared by the rule documentation and the detection reports."""

from __future__ import annotations

import re
from typing import Any

_SPECIAL = re.compile(r"([\\`*_{}\[\]<>()#+!|~&])")
_WS = re.compile(r"\s+")


def md_text(value: Any, limit: int = 600) -> str:
    """Escape for inline Markdown (single line, capped)."""
    text = _WS.sub(" ", "" if value is None else str(value)).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return _SPECIAL.sub(r"\\\1", text)


def md_code(value: Any, limit: int = 300) -> str:
    text = _WS.sub(" ", "" if value is None else str(value)).strip()[:limit]
    text = text.replace("<", "‹").replace(">", "›").replace("|", "｜")
    fence = "`" * (max((len(m) for m in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"
