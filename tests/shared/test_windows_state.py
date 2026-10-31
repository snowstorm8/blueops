"""Regression tests for attributing host-state differences (see windows_state.py)."""

from __future__ import annotations

from typing import Any

import pytest

from tests.shared.windows_state import (
    explained_by_host,
    failure_message,
    host_changes,
    registry_differences,
)

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


LSA = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"


def reg_snap(
    values: dict[str, dict[str, Any]], at: str, last_write: str, digest: str = "d"
) -> dict:
    out = snap([], at)
    out[LSA] = f"{','.join(sorted(values))} sha256={digest}"
    out["diag"]["registry"] = {LSA: {"last_write": last_write, "values": values}}
    return out


def dword(n: int) -> dict[str, Any]:
    return {"type": "DWord", "length": len(str(n)), "sha256": f"h{n}", "data": str(n)}


def test_lsa_difference_names_value_type_and_both_sides() -> None:
    before = reg_snap(
        {"RunAsPPL": dword(0), "NoLMHash": dword(1)}, BEFORE, "2026-10-27T10:00:00Z", "a"
    )
    after = reg_snap(
        {"RunAsPPL": dword(1), "NoLMHash": dword(1)}, AFTER, "2026-10-27T15:56:00Z", "b"
    )
    changed = host_changes(before, after)
    assert changed == {LSA: "differs"}  # still a failure: nothing is excused
    text = "\n".join(registry_differences(changed, before, after))
    assert LSA in text and "RunAsPPL" in text
    assert "DWord '0' -> DWord '1'" in text
    assert "NoLMHash" not in text  # equal values are not listed
    assert "10:00:00Z -> 2026-10-27T15:56:00Z" in text


def test_added_and_removed_values_are_reported() -> None:
    before = reg_snap({"Old": dword(1)}, BEFORE, "t0", "a")
    after = reg_snap({"New": dword(2)}, AFTER, "t1", "b")
    text = "\n".join(registry_differences(host_changes(before, after), before, after))
    assert "'Old': DWord '1' -> absent" in text
    assert "'New': absent -> DWord '2'" in text


def test_data_is_withheld_for_credential_like_names_even_if_present() -> None:
    secret = {"type": "String", "length": 6, "sha256": "abc", "data": "hunter2"}
    before = reg_snap({"DefaultPassword": secret}, BEFORE, "t0", "a")
    after = reg_snap(
        {"DefaultPassword": {**secret, "sha256": "def", "data": "hunter3"}}, AFTER, "t1", "b"
    )
    msg = failure_message(host_changes(before, after), before, after)
    assert "hunter2" not in msg and "hunter3" not in msg
    assert "sha256=abc" in msg and "sha256=def" in msg


def test_binary_data_is_never_printed_and_long_strings_are_cut() -> None:
    blob = {"type": "Binary", "length": 8, "sha256": "x1", "data": "DE-AD-BE-EF"}
    long_text = {"type": "String", "length": 500, "sha256": "x2", "data": "A" * 500}
    before = reg_snap({"Bounds": blob, "Packages": long_text}, BEFORE, "t0", "a")
    after = reg_snap(
        {"Bounds": {**blob, "sha256": "y1"}, "Packages": {**long_text, "sha256": "y2"}},
        AFTER,
        "t1",
        "b",
    )
    msg = failure_message(host_changes(before, after), before, after)
    assert "DE-AD" not in msg
    assert "A" * 121 not in msg and "..." in msg


def test_missing_detail_is_stated_not_guessed() -> None:
    before, after = snap([], BEFORE), snap([], AFTER)
    before[LSA], after[LSA] = "x sha256=1", "x sha256=2"
    lines = registry_differences(host_changes(before, after), before, after)
    assert lines == [f"{LSA}: changed, but no value-level detail was recorded"]


def test_digest_only_difference_is_said_to_have_no_per_value_difference() -> None:
    values = {"RunAsPPL": dword(1)}
    before = reg_snap(values, BEFORE, "t0", "a")
    after = reg_snap(values, AFTER, "t0", "b")
    text = "\n".join(registry_differences(host_changes(before, after), before, after))
    assert "no per-value difference" in text


def test_registry_detail_is_never_compared_and_never_excused() -> None:
    before = reg_snap({"A": dword(1)}, BEFORE, "t0", "same")
    after = reg_snap({"A": dword(2)}, AFTER, "t1", "same")  # detail differs, headline digest equal
    changed = host_changes(before, after)
    assert changed == {}
    assert explained_by_host(changed, before, after) == []


def test_failure_message_carries_the_key_and_the_event_windows() -> None:
    before = reg_snap({"A": dword(1)}, BEFORE, "t0", "a")
    after = reg_snap({"A": dword(2)}, AFTER, "t1", "b")
    msg = failure_message(host_changes(before, after), before, after)
    assert LSA in msg and BEFORE in msg and AFTER in msg and "7040 events" in msg
