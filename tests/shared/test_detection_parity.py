"""Parity between the legacy diff detections (``shared.reporting.detection``, ``BO-*``) and the
detection engine (``shared.rules``, ``DR-*``).

Nothing here assumes the two overlap. Each legacy scenario in ``test_detection.FIRE`` (a
baseline/current pair that must alert) and ``QUIET`` (a pair that must not) is fed to both systems:
the legacy tool sees the diff, the engine sees the current report as an assessment plus the
baseline as the previous snapshot. What fires is pinned below. A change on either side (a new
engine rule, a changed legacy rule) makes these tests fail, which is the cue to revisit the
migration decision in ``docs/detection-migration.md``.

``MAPPING`` is a judgement made by reading both rule definitions; the tests check it only where it
can be checked by running both systems (``none`` must stay silent on that rule's scenarios;
``predicate`` must fire). ``partial`` entries describe a different trigger (standing state,
findings, telemetry) that the legacy scenarios cannot exercise.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from functools import cache

import pytest
from test_detection import FIRE, QUIET, reports

from shared.engine.assessment import assessment_from_report
from shared.engine.cli import main
from shared.reporting import detect as legacy_cli
from shared.reporting import detection
from shared.rules.engine import detect
from shared.rules.history import Snap
from shared.rules.loader import load_rule_set

STAMP = "2026-03-02T00:00:00Z"
RS = load_rule_set()
NEW_IDS = set(RS.rules)

# class: predicate = same condition, different semantics; partial = overlaps but not the same
# trigger; none = no rule in the engine (assessment or telemetry packs) covers it.
MAPPING: dict[str, tuple[str, tuple[str, ...], str]] = {
    "BO-USR-001": ("predicate", ("DR-LNX-ACC-001",), "uid 0; standing state, high not critical"),
    "BO-USR-002": (
        "partial",
        ("DR-LNX-ACC-002",),
        "only the empty-password part; no new-account rule",
    ),
    "BO-USR-003": ("none", (), "service account given a login shell"),
    "BO-USR-004": ("none", (), "disabled account enabled (needs a change)"),
    "BO-USR-005": (
        "partial",
        ("DR-WIN-ACC-001",),
        "standing 'enabled without password'; not a removal",
    ),
    "BO-GRP-001": (
        "partial",
        ("DR-ANY-PRIV-001",),
        "sudo/wheel/admin only (no docker/lxd/disk); also fires on removal",
    ),
    "BO-PER-001": ("none", (), "authorized_keys additions are not in any assessment rule"),
    "BO-PER-002": ("partial", ("DR-LNX-PER-001", "DR-WIN-PER-001"), "finding-based, standing"),
    "BO-EXE-001": (
        "partial",
        ("DR-WIN-SVC-001", "DR-WIN-TSK-001", "DR-ANY-COR-001"),
        "Windows or finding-based",
    ),
    "BO-EXE-002": ("partial", ("DR-ANY-HTSK-001",), "needs telemetry"),
    "BO-SCH-001": ("partial", ("DR-ANY-COR-003",), "only in combination with account changes"),
    "BO-SCH-002": ("none", (), "hidden scheduled task"),
    "BO-SCH-003": ("none", (), "scheduled command changed"),
    "BO-SVC-001": ("partial", ("DR-ANY-HCHG-002", "DR-ANY-HSVC-002"), "needs telemetry"),
    "BO-SVC-002": ("none", (), "service binary or account changed"),
    "BO-SVC-003": (
        "partial",
        ("DR-LNX-SVC-001", "DR-ANY-NET-001"),
        "requires the service to be listening",
    ),
    "BO-SVC-004": (
        "partial",
        ("DR-ANY-COR-005", "DR-WIN-LOG-001", "DR-LNX-LOG-001"),
        "finding-based",
    ),
    "BO-NET-001": (
        "partial",
        ("DR-ANY-HCHG-001", "DR-ANY-NET-001"),
        "telemetry, or cleartext ports only",
    ),
    "BO-NET-002": ("partial", ("DR-ANY-HNET-001",), "needs telemetry"),
    "BO-NET-003": ("none", (), "listener ownership changed"),
    "BO-CFG-001": ("partial", ("DR-ANY-NET-002",), "only with a listening management/data port"),
    "BO-CFG-002": (
        "partial",
        ("DR-ANY-CHG-004",),
        "generic long-stable setting; needs 3 snapshots",
    ),
    "BO-CFG-003": ("none", (), "any new set-ID file"),
    "BO-CFG-004": ("partial", ("DR-LNX-FS-001",), "temporary/user-writable locations only"),
    "BO-CFG-005": ("none", (), "sudoers or PAM changes"),
    "BO-CFG-006": ("partial", ("DR-WIN-CRED-001",), "finding-based, standing"),
    "BO-CFG-007": ("none", (), "hosts file or DNS"),
    "BO-CFG-008": ("partial", ("DR-LNX-SSH-001",), "finding-based, standing"),
    "BO-CFG-009": ("none", (), "kernel modules"),
    "BO-CFG-010": (
        "partial",
        ("DR-ANY-NET-002", "DR-ANY-COR-002"),
        "needs listeners / a new listener",
    ),
    "BO-FND-001": (
        "partial",
        ("DR-ANY-CHG-003", "DR-ANY-CHG-001"),
        "escalation only, not 'appeared'",
    ),
}

# What the engine fires for the legacy scenarios (anything not listed fires nothing).
NEW_FIRES_ON_FIRE = {
    "uid0-added": {("DR-LNX-ACC-001", "high")},
    "uid0-by-modification": {("DR-LNX-ACC-001", "high")},
    "new-account-empty-password": {("DR-LNX-ACC-002", "high")},
    "sudo-member-added": {("DR-ANY-PRIV-001", "high")},
}
# Scenarios where the legacy tool must stay quiet but the engine does not.
NEW_FIRES_ON_QUIET = {
    "preexisting-second-uid0-is-baseline": {("DR-LNX-ACC-001", "high")},
    "privileged-member-removed": {("DR-ANY-PRIV-001", "high")},
}


def _family(base: list, cur: list) -> str:
    text = json.dumps(base + cur).lower()
    windows = any(t in text for t in ("s-1-5", "hklm", "defender", "\\\\"))
    return "windows" if windows else "linux"


@cache
def _engine(case_id: str, kind: str) -> frozenset[tuple[str, str]]:
    params = FIRE if kind == "fire" else QUIET
    p = next(p for p in params if p.id == case_id)
    base, cur = p.values[0], p.values[1]
    b, c = reports(base, cur, family=_family(base, cur))
    res = detect(
        assessment_from_report(c),
        RS,
        previous=[Snap(assessment_from_report(b), "baseline")],
        generated_at=STAMP,
    )
    assert res["rule_errors"] == []
    return frozenset((d["rule"]["id"], d["severity"]) for d in res["detections"])


def test_every_legacy_rule_is_classified_exactly_once() -> None:
    assert set(MAPPING) == {r.rule_id for r in detection.RULES}


def test_mapped_engine_rules_exist() -> None:
    for legacy, (_, targets, _) in MAPPING.items():
        missing = [t for t in targets if t not in NEW_IDS]
        assert not missing, f"{legacy} maps to unknown rule(s) {missing}"


def test_no_legacy_rule_has_a_drop_in_replacement() -> None:
    """The classes the mapping may use, and the honest totals: nothing is 'direct'."""
    counts: dict[str, int] = {}
    for cls, _, _ in MAPPING.values():
        counts[cls] = counts.get(cls, 0) + 1
    assert set(counts) <= {"predicate", "partial", "none"}
    assert counts == {"predicate": 1, "partial": 19, "none": 11}


@pytest.mark.parametrize("case", [pytest.param(p, id=p.id) for p in FIRE])
def test_what_the_engine_does_with_each_legacy_alert_scenario(case) -> None:  # type: ignore[no-untyped-def]
    legacy_rule = case.values[3]
    fired = _engine(case.id, "fire")
    assert fired == NEW_FIRES_ON_FIRE.get(case.id, set()), case.id
    cls, targets, _ = MAPPING[legacy_rule]
    if cls == "none":
        assert not fired, f"{legacy_rule} is classed 'none' but {sorted(fired)} fired"
    if cls == "predicate":
        assert {r for r, _ in fired} & set(targets), f"{legacy_rule}: mapped rule did not fire"
    assert {r for r, _ in fired} <= {t for _, ts, _ in MAPPING.values() for t in ts}, (
        "the engine fired a rule that no mapping entry accounts for"
    )


@pytest.mark.parametrize("case", [pytest.param(p, id=p.id) for p in QUIET])
def test_legacy_false_positive_scenarios_against_the_engine(case) -> None:  # type: ignore[no-untyped-def]
    """The legacy suite pins 14 benign changes that must not alert. The engine alerts on two:
    both are consequences of evaluating standing state / any membership change, not bugs."""
    assert _engine(case.id, "quiet") == NEW_FIRES_ON_QUIET.get(case.id, set()), case.id


def test_severity_differs_on_identical_data() -> None:
    legacy = next(p for p in FIRE if p.id == "uid0-added")
    assert legacy.values[4] == "critical"  # BO-USR-001
    assert _engine("uid0-added", "fire") == {("DR-LNX-ACC-001", "high")}


def test_identifier_namespaces_do_not_overlap() -> None:
    assert all(r.rule_id.startswith("BO-") for r in detection.RULES)
    assert all(i.startswith("DR-") for i in NEW_IDS)


def test_the_engine_has_no_accepted_change_allowlist() -> None:
    """The legacy tool has ``--accepted`` (expiring, scoped acceptance of known changes). The
    engine does not, so replacing the legacy tool today would remove that capability."""
    buf = io.StringIO()
    with redirect_stdout(buf), pytest.raises(SystemExit):
        legacy_cli.main(["--help"])
    assert "--accepted" in buf.getvalue()
    buf = io.StringIO()
    with redirect_stdout(buf), pytest.raises(SystemExit):
        main(["detect", "run", "--help"])
    assert "--accepted" not in buf.getvalue()
