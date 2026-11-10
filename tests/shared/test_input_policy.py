"""One policy for every input that can carry no manifest.

* verified   -> accepted;
* unverified -> refused unless ``--allow-unverified`` is given, then accepted and *marked*;
* invalid    -> refused always, ``--allow-unverified`` or not.

Covers raw telemetry streams, bare telemetry documents, stored detection results, and the
commands that read them.  Stores (directories) have no opt-out at all.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from telemetry_support import proc, stream
from test_verification_states import _results_file

from shared.engine.cli import main
from shared.engine.manifest import write_manifest
from shared.engine.provenance import status
from shared.telemetry import ingest


def _stream(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    p = tmp_path / "s.jsonl"
    p.write_bytes(stream([proc(1, "init", "/sbin/init")]))
    return p


def _telemetry_json(tmp_path: Path) -> Path:
    store = ingest.write_store(
        ingest.ingest_paths([_stream(tmp_path / "src")], allow_unverified=True),
        tmp_path / "stores",
        [],
    )
    bare = tmp_path / "bare"
    bare.mkdir()
    shutil.copy(store / "telemetry.json", bare / "telemetry.json")
    return bare / "telemetry.json"


def test_raw_streams_are_refused_by_default_and_marked_when_allowed(tmp_path: Path) -> None:
    s = _stream(tmp_path)
    with pytest.raises(ingest.IngestError, match="allow-unverified"):
        ingest.read_path(s)
    with pytest.raises(ingest.IngestError, match="allow-unverified"):
        ingest.ingest_paths([s])
    doc = ingest.ingest_paths([s], allow_unverified=True)
    assert status(doc)[0] is False


def test_bare_telemetry_documents_follow_the_same_policy(tmp_path: Path) -> None:
    t = _telemetry_json(tmp_path)
    with pytest.raises(ingest.IngestError, match="allow-unverified"):
        ingest.load_telemetry(t)
    assert status(ingest.load_telemetry(t, allow_unverified=True))[0] is False


@pytest.mark.parametrize("cmd", ["show", "query", "tree"])
def test_telemetry_readers_refuse_a_bare_document_without_the_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], cmd: str
) -> None:
    t = str(_telemetry_json(tmp_path))
    extra = ["--pid", "1"] if cmd == "tree" else []
    assert main(["telemetry", cmd, t, *extra]) == 3
    assert "allow-unverified" in capsys.readouterr().err
    assert main(["telemetry", cmd, t, *extra, "--allow-unverified"]) in (0, 6)
    assert "UNVERIFIED" in capsys.readouterr().out or cmd == "tree"


def test_telemetry_compare_and_report_follow_the_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = str(_telemetry_json(tmp_path))
    assert main(["telemetry", "compare", t, t]) == 3
    assert main(["telemetry", "report", t]) == 3
    capsys.readouterr()
    assert main(["telemetry", "compare", t, t, "--allow-unverified"]) in (0, 4, 6)
    assert json.loads(capsys.readouterr().out)["inputs_verified"] is False
    assert main(["telemetry", "report", t, "--allow-unverified"]) == 0
    assert "UNVERIFIED" in capsys.readouterr().out


def test_hunting_refuses_bare_telemetry_and_its_baseline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    t = str(_telemetry_json(tmp_path))
    assert main(["telemetry", "hunt", t, "--quiet"]) == 3
    assert main(["detect", "run", "--telemetry", t, "--quiet"]) == 3
    capsys.readouterr()


def test_a_verified_store_needs_no_flag_and_a_tampered_one_is_refused_with_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = ingest.write_store(
        ingest.ingest_paths([_stream(tmp_path / "src")], allow_unverified=True),
        tmp_path / "stores",
        [],
    )
    assert main(["telemetry", "show", str(store)]) == 0
    (store / "telemetry.json").write_text(
        (store / "telemetry.json").read_text("utf-8").replace("init", "evil"), encoding="utf-8"
    )
    capsys.readouterr()
    assert main(["telemetry", "show", str(store), "--allow-unverified"]) == 3
    assert "manifest verification" in capsys.readouterr().err


def test_a_lone_telemetry_file_in_a_verified_directory_is_verified(tmp_path: Path) -> None:
    store = ingest.write_store(
        ingest.ingest_paths([_stream(tmp_path / "src")], allow_unverified=True),
        tmp_path / "stores",
        [],
    )
    ok, inputs = status(ingest.load_telemetry(store / "telemetry.json"))
    # the file itself is verified by its directory's manifest; the store still records that the
    # stream it was imported from was not, so the whole is not "verified"
    assert any(i["role"] == "telemetry" and i["verified"] for i in inputs)
    assert ok is False and any(i["role"] == "stream" and not i["verified"] for i in inputs)
    (store / "telemetry.json").write_text("{}", encoding="utf-8")  # now the manifest disagrees
    with pytest.raises(ingest.IngestError, match="manifest"):
        ingest.load_telemetry(store / "telemetry.json", allow_unverified=True)


@pytest.mark.parametrize("cmd", ["show", "export", "report"])
def test_stored_detection_results_follow_the_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], cmd: str
) -> None:
    res = str(_results_file(tmp_path))
    first = json.loads(Path(res).read_text("utf-8"))["detections"]
    tail = [first[0]["id"] if first else "DT-none"] if cmd == "show" else []
    assert main(["detect", cmd, res, *tail]) == 3
    assert "allow-unverified" in capsys.readouterr().err
    # past the gate: show answers 2 when no detection matches the id, the others succeed
    assert main(["detect", cmd, res, *tail, "--allow-unverified"]) in ((0, 2) if tail else (0,))


def test_results_inside_a_verified_directory_are_verified_and_altered_ones_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    res = _results_file(tmp_path)
    box = tmp_path / "box"
    box.mkdir()
    kept = box / "res.json"
    shutil.copy(res, kept)
    meta = {
        "assessment": {
            "id": "A",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "exit_code": 0,
        }
    }
    write_manifest(box, meta)
    assert main(["detect", "export", str(kept)]) == 0
    kept.write_text(kept.read_text("utf-8") + " ", encoding="utf-8")
    capsys.readouterr()
    assert main(["detect", "export", str(kept), "--allow-unverified"]) == 3
    assert "manifest" in capsys.readouterr().err
