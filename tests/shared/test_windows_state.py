"""Regression tests for attributing host-state differences (see windows_state.py)."""

from __future__ import annotations

from typing import Any

import pytest

from tests.shared.windows_state import explained_by_host, host_changes

PATH = "C:\\Windows\\System32\\svchost.exe -k netsvcs -p"
BITS_TEXT = (
    "The start type of the Background Intelligent Transfer Service service was changed "
    "from auto start to demand start."
)


def snap(
    services: list[str],
    at: str,
    changes: list[tuple[str, str]] | None = None,
    bits: str = "Stopped",
) -> dict[str, Any]:
    return {
        "services": services,
        "hosts": "abc",
        "diag": {
            "at": at,
            "bits_status": bits,
            "start_type_changes": [{"at": t, "message": m} for t, m in (changes or [])],
        },
    }


BEFORE = "2026-10-27T15:55:00.0000000Z"
AFTER = "2026-10-27T15:57:00.5000000Z"
INSIDE = "2026-10-27T15:55:07.1550000Z"


def run(before_svcs: list[str], after_svcs: list[str], events: list[tuple[str, str]]) -> dict:
    before = snap(before_svcs, BEFORE)
    after = snap(after_svcs, AFTER, events)
    changed = host_changes(before, after)
    notes = explained_by_host(changed, before, after)
    return {"changed": changed, "notes": notes}


def test_bits_self_demotion_logged_by_host_is_tolerated() -> None:
    r = run([f"BITS|Auto|{PATH}"], [f"BITS|Manual|{PATH}"], [(INSIDE, BITS_TEXT)])
    assert r["changed"] == {}
    assert r["notes"] and "event 7040" in r["notes"][0]


def test_same_difference_without_a_host_event_is_a_failure() -> None:
    r = run([f"BITS|Auto|{PATH}"], [f"BITS|Manual|{PATH}"], [])
    assert r["changed"]["services"]["removed"] == [f"BITS|Auto|{PATH}"]
    assert r["notes"] == []


def test_event_outside_the_window_does_not_explain_the_change() -> None:
    old = "2026-10-27T15:40:00.0000000Z"
    r = run([f"BITS|Auto|{PATH}"], [f"BITS|Manual|{PATH}"], [(old, BITS_TEXT)])
    assert "services" in r["changed"]


def test_the_opposite_transition_is_attributed_to_the_audit() -> None:
    # Starting BITS (what an audit calling Get-BitsTransfer on a stopped service would do)
    # flips demand start to automatic; that is never excused, even if an event exists.
    r = run([f"BITS|Manual|{PATH}"], [f"BITS|Auto|{PATH}"], [(INSIDE, BITS_TEXT)])
    assert r["changed"]["services"]["added"] == [f"BITS|Auto|{PATH}"]


@pytest.mark.parametrize("name", ["Spooler", "WinRM", "RemoteRegistry"])
def test_other_services_are_never_excused(name: str) -> None:
    r = run([f"{name}|Auto|{PATH}"], [f"{name}|Manual|{PATH}"], [(INSIDE, BITS_TEXT)])
    assert r["changed"]["services"]["removed"] == [f"{name}|Auto|{PATH}"]


def test_changed_image_path_is_not_excused() -> None:
    r = run([f"BITS|Auto|{PATH}"], ["BITS|Manual|C:\\evil.exe"], [(INSIDE, BITS_TEXT)])
    assert "services" in r["changed"]


def test_other_state_still_fails_next_to_an_excused_bits_change() -> None:
    before = snap([f"BITS|Auto|{PATH}"], BEFORE)
    after = snap([f"BITS|Manual|{PATH}"], AFTER, [(INSIDE, BITS_TEXT)])
    after["hosts"] = "changed"
    changed = host_changes(before, after)
    explained_by_host(changed, before, after)
    assert changed == {"hosts": "differs"}


def test_diag_key_is_never_compared() -> None:
    before = snap(["A|Auto|x"], BEFORE)
    after = snap(["A|Auto|x"], AFTER, [(INSIDE, "something")])
    assert host_changes(before, after) == {}


def test_a_running_service_after_the_change_is_not_a_self_demotion() -> None:
    # Demotion always stops BITS; a still-running service with the same diff is suspicious.
    before = snap([f"BITS|Auto|{PATH}"], BEFORE)
    after = snap([f"BITS|Manual|{PATH}"], AFTER, [(INSIDE, BITS_TEXT)], bits="Running")
    changed = host_changes(before, after)
    assert explained_by_host(changed, before, after) == []
    assert "services" in changed
