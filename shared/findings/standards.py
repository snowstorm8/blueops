"""Technical-standard references attached to findings.

Two frameworks are referenced, both by identifiers that are stable and public:

* **MITRE ATT&CK** technique ids already emitted by the collectors (``T1136.001``). They are
  validated for shape and turned into the canonical ``attack.mitre.org`` URL; the technique
  *name* is deliberately not stored, because a wrong or stale name is worse than none.
* **NIST SP 800-53 Rev. 5** control families, mapped from the finding *category*. These
  mappings are indicative ("this area of the audit relates to that control"), not a statement
  that a finding proves non-compliance with the control. They are intentionally coarse.

No CIS Benchmark section numbers are listed: they differ per benchmark version and distribution,
and an invented number would be worse than a missing one.
"""

from __future__ import annotations

import re
from typing import Any

_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# category -> [(control id, control title)]; titles are the official Rev. 5 control names.
NIST_800_53_BY_CATEGORY: dict[str, list[tuple[str, str]]] = {
    "users": [("AC-2", "Account Management"), ("AC-6", "Least Privilege")],
    "auth": [("IA-5", "Authenticator Management"), ("AC-7", "Unsuccessful Logon Attempts")],
    "pam": [("IA-5", "Authenticator Management"), ("AC-7", "Unsuccessful Logon Attempts")],
    "processes": [("SI-4", "System Monitoring"), ("CM-7", "Least Functionality")],
    "network": [("SC-7", "Boundary Protection"), ("CM-7", "Least Functionality")],
    "firewall": [("SC-7", "Boundary Protection")],
    "services": [("CM-7", "Least Functionality"), ("CM-6", "Configuration Settings")],
    "persistence": [("SI-7", "Software, Firmware, and Information Integrity")],
    "autoruns": [("SI-7", "Software, Firmware, and Information Integrity")],
    "tasks": [
        ("CM-7", "Least Functionality"),
        ("SI-7", "Software, Firmware, and Information Integrity"),
    ],
    "filesystem": [
        ("AC-3", "Access Enforcement"),
        ("SI-7", "Software, Firmware, and Information Integrity"),
    ],
    "system": [("CM-2", "Baseline Configuration"), ("SI-2", "Flaw Remediation")],
    "config": [("CM-6", "Configuration Settings")],
    "security": [("CM-6", "Configuration Settings")],
    "logging": [("AU-2", "Event Logging"), ("AU-9", "Protection of Audit Information")],
    "eventlog": [("AU-2", "Event Logging"), ("AU-9", "Protection of Audit Information")],
    "groups": [("AC-2", "Account Management"), ("AC-6", "Least Privilege")],
}


def attack_url(technique: str) -> str:
    """Canonical ATT&CK URL for ``T1053`` / ``T1053.003``."""
    if not _ATTACK_RE.match(technique):
        raise ValueError(f"not an ATT&CK technique id: {technique!r}")
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def standards_for(category: str, mitre: list[str] | None) -> list[dict[str, Any]]:
    """Standards references for a finding, ordered ATT&CK first then NIST, no duplicates."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for t in mitre or []:
        if isinstance(t, str) and _ATTACK_RE.match(t) and ("MITRE ATT&CK", t) not in seen:
            seen.add(("MITRE ATT&CK", t))
            out.append({"framework": "MITRE ATT&CK", "id": t, "url": attack_url(t)})
    for cid, title in NIST_800_53_BY_CATEGORY.get(category, []):
        if ("NIST SP 800-53 Rev. 5", cid) not in seen:
            seen.add(("NIST SP 800-53 Rev. 5", cid))
            out.append({"framework": "NIST SP 800-53 Rev. 5", "id": cid, "title": title})
    return out
