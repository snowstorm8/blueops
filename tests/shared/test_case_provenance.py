"""A case is only as trustworthy as every source it was observed from.

* provenance travels from the detection results into each ``observed`` event;
* a case is ``verified`` only if every observation was; one unverified or unknown source makes it
  unverified, and a later verified observation does not wash that out;
* a results document that records nothing about its inputs is ``unknown`` -> unverified;
* the status is shown by ``case show``, ``case list --json`` and the detection reports.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from rules_support import doc as rules_doc
from test_engine_integrity import build
from test_provenance import _rewrite, _unverifiable_copy
from test_rules_cli import TWO_HITS
from test_rules_investigation import BOTH, results

from shared.engine.cli import main as rules_main
from shared.engine.provenance import entries, mark, stamp
from shared.reporting.render_detections import render_detections_markdown
from shared.rules.investigation import FILE_NAME, CaseStore, case_summaries


def _with(res: dict[str, Any], *, verified: bool | None, path: str = "/in/a") -> dict[str, Any]:
    """``res`` carrying a provenance record: verified, unverified, or none at all."""
    res.pop("inputs", None)
    res.pop("inputs_verified", None)
    if verified is None:
        return res
    why = "" if verified else "bare file: it has no manifest to verify"
    src = mark({}, verified=verified, source=path, reason=why)
    return stamp(res, entries("assessment", src))


def _only(store: CaseStore) -> Any:
    return next(iter(store.cases().values()))


def test_verified_source_gives_a_verified_case(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    store.observe(_with(results(BOTH), verified=True))
    c = _only(store)
    assert c.verification == "verified" and c.provenance()["inputs_verified"] is True
    assert c.provenance()["unverified_inputs"] == []


def test_unverified_source_gives_an_unverified_case_with_the_reason(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    store.observe(_with(results(BOTH), verified=False, path="/in/bare.json"))
    p = _only(store).provenance()
    assert p["verification"] == "unverified" and p["inputs_verified"] is False
    assert p["unverified_observations"] == 1 and p["verified_observations"] == 0
    assert p["unverified_inputs"][0]["path"] == "/in/bare.json"
    assert "no manifest" in p["unverified_inputs"][0]["reason"]


def test_missing_provenance_is_unknown_and_counts_as_unverified(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    store.observe(_with(results(BOTH), verified=None))
    c = _only(store)
    assert c.verification == "unverified"  # unknown counts as unverified
    p = c.provenance()
    assert p["unknown_observations"] == 1 and p["inputs_verified"] is False
    assert c.observations[0]["verification"] == "unknown"


@pytest.mark.parametrize("order", [(True, False), (False, True)])
def test_mixed_sources_are_never_fully_verified_whatever_the_order(
    tmp_path: Path, order: tuple[bool, bool]
) -> None:
    store = CaseStore(tmp_path)
    for i, ok in enumerate(order):
        store.observe(_with(results(BOTH, aid=f"run-{i}"), verified=ok, path=f"/in/{i}"))
    c = _only(store)
    p = c.provenance()
    assert c.verification == "unverified" and p["inputs_verified"] is False
    assert (p["verified_observations"], p["unverified_observations"]) == (1, 1)
    assert p["sources"] == ["run-0", "run-1"]
    # a further verified observation does not restore the standing
    store.observe(_with(results(BOTH, aid="run-9"), verified=True))
    assert _only(store).verification == "unverified"


def test_verified_and_unknown_mix_is_unverified(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    store.observe(_with(results(BOTH, aid="a"), verified=True))
    store.observe(_with(results(BOTH, aid="b"), verified=None))
    assert _only(store).verification == "unverified"


def test_a_derived_unverified_input_taints_the_case(tmp_path: Path) -> None:
    """The results are marked verified overall only if every input was; one carried-over
    unverified entry is enough (provenance.status recomputes the summary)."""
    res = _with(results(BOTH), verified=True)
    res["inputs"].append({"role": "previous", "path": "/old", "verified": False, "reason": "x"})
    store = CaseStore(tmp_path)
    store.observe(res)  # inputs_verified still says true: the entry decides
    c = _only(store)
    assert c.verification == "unverified"
    assert c.provenance()["unverified_inputs"][0]["path"] == "/old"


def test_event_without_the_provenance_fields_reads_as_unknown(tmp_path: Path) -> None:
    """Case files written before provenance existed stay readable, and unverified."""
    store = CaseStore(tmp_path)
    store.observe(_with(results(BOTH), verified=True))
    path = tmp_path / FILE_NAME
    lines = [json.loads(x) for x in path.read_text("utf-8").splitlines()]
    # rewrite the chain without the new fields
    prev, out = "0" * 64, []
    for ev in lines:
        ev["data"].pop("verification", None)
        ev["data"].pop("unverified", None)
        ev["prev"] = prev
        raw = json.dumps(ev, sort_keys=True, separators=(",", ":")).encode()
        prev = hashlib.sha256(raw).hexdigest()
        out.append(raw)
    path.write_bytes(b"\n".join(out) + b"\n")
    assert _only(CaseStore(tmp_path)).verification == "unverified"
    assert _only(CaseStore(tmp_path)).observations[0]["verification"] == "unknown"


def test_summaries_carry_the_standing_and_do_not_vouch_for_untracked_detections(
    tmp_path: Path,
) -> None:
    store = CaseStore(tmp_path)
    bad = _with(results(BOTH), verified=False)
    store.observe(bad)
    summ = case_summaries(store, bad)
    assert all(v["verification"] == "unverified" and v["verified"] is False for v in summ.values())
    # without a store, a detection takes the standing of the results it is shown with
    assert all(v["verified"] is False for v in case_summaries(None, bad).values())
    good = _with(results(BOTH), verified=True)
    assert all(v["verified"] is True for v in case_summaries(None, good).values())
    assert all(
        v["verified"] is False
        for v in case_summaries(None, _with(results(BOTH), verified=None)).values()
    )


def test_the_case_commands_and_reports_show_unverified_sources(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = CaseStore(tmp_path)
    res = _with(results(BOTH), verified=False, path="/in/bare.json")
    store.observe(res)
    det = next(iter(store.cases()))
    capsys.readouterr()
    assert rules_main(["case", "show", det, "--state-dir", str(tmp_path)]) == 0
    text = capsys.readouterr().out
    assert "UNVERIFIED" in text and "/in/bare.json" in text
    assert rules_main(["case", "list", "--state-dir", str(tmp_path), "--json"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert all(c["provenance"]["inputs_verified"] is False for c in listed)
    md = render_detections_markdown(res, case_summaries(store, res))
    assert "case sources UNVERIFIED" in md
    ok = _with(results(BOTH), verified=True)
    other = CaseStore(tmp_path / "clean")
    other.observe(ok)
    assert "case sources UNVERIFIED" not in render_detections_markdown(
        ok, case_summaries(other, ok)
    )


def test_detect_run_registers_cases_with_the_real_standing_of_the_assessment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    verified_dir, _, _ = build(tmp_path / "v")
    _rewrite(verified_dir, rules_doc(TWO_HITS, aid="cur", started="2026-03-01T10:00:00Z"))
    plain = _unverifiable_copy(verified_dir, tmp_path / "plain")
    ok_state, bad_state = tmp_path / "ok", tmp_path / "bad"
    base = ["detect", "run", "--quiet", "--fail-on", "critical"]
    rc = rules_main([*base, str(verified_dir), "--state-dir", str(ok_state)])
    assert rc in (0, 4, 6)
    assert rules_main([*base, str(plain), "--state-dir", str(bad_state)]) == 3  # refused
    rc = rules_main([*base, str(plain), "--state-dir", str(bad_state), "--allow-unverified"])
    assert rc in (0, 4, 6)
    capsys.readouterr()
    good = CaseStore(ok_state).cases()
    bad = CaseStore(bad_state).cases()
    assert good and bad  # the fixture does produce detections
    assert {c.verification for c in good.values()} == {"verified"}
    assert {c.verification for c in bad.values()} == {"unverified"}
    # registering the unverified run into the verified state does not leave the case verified
    rc = rules_main([*base, str(plain), "--state-dir", str(ok_state), "--allow-unverified"])
    assert {c.verification for c in CaseStore(ok_state).cases().values()} == {"unverified"}
