"""Telemetry model, ingestion, deduplication, coverage and malformed-input handling."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from telemetry_support import ALL_CATEGORIES, auth, coverage, proc, rec, stream

from shared.reporting.schema_lite import validate
from shared.telemetry import ingest
from shared.telemetry.model import normalise_record, parse_time, record_id


def doc_from(data: bytes, tmp_path: Path, name: str = "a.jsonl") -> dict:
    p = tmp_path / name
    p.write_bytes(data)
    return ingest.ingest_paths([p], generated_at="2026-03-01T11:00:00Z", allow_unverified=True)


# ------------------------------------------------------------------ time and ids


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-03-01T10:00:00Z", "2026-03-01T10:00:00Z"),
        ("2026-03-01T12:00:00+02:00", "2026-03-01T10:00:00Z"),
        ("2026-03-01T05:30:00-0430", "2026-03-01T10:00:00Z"),
        ("2026-03-01 10:00:00.250000Z", "2026-03-01T10:00:00.25Z"),
        ("2026-03-01T10:00:00", None),  # no zone: refused, never assumed UTC
        ("yesterday", None),
        ("2026-13-01T10:00:00Z", None),
        (None, None),
        (12345, None),
    ],
)
def test_parse_time(raw, expected):
    assert parse_time(raw) == expected


def test_record_id_is_stable_and_depends_on_host_category_and_key():
    a = record_id("H-1", "process", "k")
    assert a == record_id("H-1", "process", "k") and a.startswith("TEL-") and len(a) == 20
    assert (
        len(
            {
                a,
                record_id("H-2", "process", "k"),
                record_id("H-1", "user", "k"),
                record_id("H-1", "process", "k2"),
            }
        )
        == 4
    )


# ------------------------------------------------------------------ happy path


def test_stream_is_normalised_with_provenance(tmp_path):
    d = doc_from(stream([proc(1, 0, "init"), proc(2, 1, "bash", user="alice")]), tmp_path)
    assert validate(d, "telemetry.schema.json") == []
    assert d["summary"]["records"] == 2 and d["summary"]["complete"] is True
    r = d["records"][0]
    for field in (
        "record_id",
        "host_id",
        "category",
        "observed_at",
        "os_family",
        "collector",
        "source",
        "method",
        "attributes",
        "status",
        "limitations",
    ):
        assert field in r
    assert r["collector"] == {"name": "synthetic", "version": "1.0.0"}
    assert d["collection"]["imported_from"][0]["sha256"] and d["collection"]["mode"] == "import"
    # The host id equals the findings host id: telemetry and assessments of one host join.
    from shared.findings.model import host_id

    assert d["host"]["host_id"] == host_id("host01", "linux")


def test_same_input_gives_the_same_record_ids_across_collections(tmp_path):
    a = doc_from(stream([proc(1, 0, "init")], cid="one"), tmp_path, "a.jsonl")
    b = doc_from(
        stream(
            [proc(1, 0, "init")],
            cid="two",
            started="2026-03-02T10:00:00Z",
            ended="2026-03-02T10:01:00Z",
        ),
        tmp_path,
        "b.jsonl",
    )
    assert a["records"][0]["record_id"] == b["records"][0]["record_id"]


# ------------------------------------------------------------------ coverage semantics


def test_observed_absence_differs_from_not_collected(tmp_path):
    cov = coverage(["user"]) + coverage(["service"], "unavailable", "systemctl not found")
    d = doc_from(stream([rec("user", "u:root", {"name": "root"})], cov), tmp_path)
    by = {c["category"]: c for c in d["coverage"]}
    assert by["user"]["status"] == "complete"
    assert by["service"]["status"] == "unavailable" and by["service"]["records"] == 0
    assert "systemctl" in by["service"]["reason"] and d["summary"]["complete"] is False


def test_records_without_declared_coverage_are_partial_not_complete(tmp_path):
    d = doc_from(stream([rec("user", "u:root", {"name": "root"})], cov=[]), tmp_path)
    assert (
        d["coverage"][0]["status"] == "partial"
        and "declared no coverage" in d["coverage"][0]["reason"]
    )


def test_worst_status_within_one_input_wins(tmp_path):
    cov = coverage(["process"], "partial", "10 unreadable") + coverage(["process"])
    d = doc_from(stream([proc(1, 0, "init")], cov), tmp_path)
    assert [c["status"] for c in d["coverage"] if c["category"] == "process"] == ["partial"]


def test_truncated_stream_downgrades_complete_coverage(tmp_path):
    d = doc_from(stream([proc(1, 0, "init")], end=False), tmp_path)
    assert any(e["code"] == "TRUNCATED_STREAM" for e in d["errors"])
    assert [c["status"] for c in d["coverage"] if c["category"] == "process"] == ["partial"]
    assert d["summary"]["complete"] is False


def test_end_marker_count_mismatch_is_reported(tmp_path):
    d = doc_from(stream([proc(1, 0, "init")], count=5), tmp_path)
    assert any(e["code"] == "RECORD_COUNT_MISMATCH" for e in d["errors"])


def test_unknown_attributes_mark_the_record_partial(tmp_path):
    d = doc_from(
        stream([rec("process", "p", {"pid": 1, "name": "x", "exe": None}, unknown=("exe",))]),
        tmp_path,
    )
    r = d["records"][0]
    assert (
        r["status"] == "partial"
        and r["unknown_attributes"] == ["exe"]
        and r["attributes"]["exe"] is None
    )


# ------------------------------------------------------------------ malformed input


def test_malformed_lines_and_records_are_rejected_with_reasons_not_dropped(tmp_path):
    good = rec("user", "u:a", {"name": "a"})
    bad = [
        rec("nonsense", "k", {}),
        rec("user", "", {"name": "x"}),
        rec("user", "u:b", {}),  # missing required attribute
        {"type": "record", "category": "user", "key": "k", "attributes": "oops"},
        rec("user", "u:c", {"name": {"nested": 1}}),
    ]
    data = stream([good, *bad]).decode().splitlines()
    data.insert(3, "{not json")
    data.insert(4, json.dumps({"no": "type"}))
    data.insert(5, json.dumps({"type": "mystery"}))
    d = doc_from(("\n".join(data) + "\n").encode(), tmp_path)
    assert d["summary"]["records"] == 1 and d["summary"]["rejected"] >= 7
    reasons = " | ".join(r for x in d["rejected"] for r in x["reasons"])
    for needle in (
        "unknown category",
        "key is required",
        "missing required attribute",
        "attributes must be an object",
        "not valid JSON",
        "'type'",
        "unknown line type",
    ):
        assert needle in reasons
    # The origin (file:line) is recorded so the bad input can be found.
    assert all(":" in x["origin"] for x in d["rejected"])
    # Bad but not fatal: the nested attribute value is dropped with a note and the record kept? No:
    # a required attribute that cannot be represented makes the record unusable.
    assert not any(r["key"] == "u:c" for r in d["records"])


def test_control_characters_and_oversized_values_are_neutralised(tmp_path):
    nasty = "a\x1b[31mred\x00" + "x" * 9000
    d = doc_from(stream([rec("user", "u:a", {"name": "a", "comment": nasty})]), tmp_path)
    v = d["records"][0]["attributes"]["comment"]
    assert "\x1b" not in v and "\x00" not in v and len(v) <= 4096


def test_invalid_attribute_names_are_dropped_with_a_note():
    r, notes = normalise_record(
        {"category": "user", "key": "k", "attributes": {"name": "a", "Bad Name": 1, "ok_name": 2}},
        host_id="H", os_family="linux", observed_default="2026-03-01T10:00:00Z", collector={"name": "c", "version": "1"}, origin="t",
    )  # fmt: skip
    assert (
        r is not None
        and "Bad Name" not in r["attributes"]
        and any("invalid attribute name" in n for n in notes)
    )


def test_missing_event_time_is_a_visible_limitation(tmp_path):
    d = doc_from(
        stream([auth(None, "login_failure", "failure", "root", "203.0.113.5", key="e1")]), tmp_path
    )
    r = next(x for x in d["records"] if x["category"] == "auth_event")
    assert r["status"] == "partial" and any("event time" in x for x in r["limitations"])


def test_timestamp_without_zone_is_not_assumed_to_be_utc(tmp_path):
    d = doc_from(
        stream(
            [
                rec(
                    "auth_event",
                    "e",
                    {"action": "login_failure", "result": "failure", "user": "x"},
                    event_time="2026-03-01T10:00:00",
                )
            ]
        ),
        tmp_path,
    )
    r = next(x for x in d["records"] if x["category"] == "auth_event")
    assert "event_time" not in r and any(
        "without a time zone" in x or "unparsable" in x for x in r["limitations"]
    )


def test_unrecognised_auth_vocabulary_is_normalised_and_noted(tmp_path):
    d = doc_from(
        stream(
            [
                rec(
                    "auth_event",
                    "e",
                    {"action": "weird", "result": "maybe", "user": "x"},
                    event_time="2026-03-01T10:00:00Z",
                )
            ]
        ),
        tmp_path,
    )
    a = next(x for x in d["records"] if x["category"] == "auth_event")["attributes"]
    assert a["action"] == "other" and a["result"] == "unknown"


def test_utf8_bom_from_windows_powershell_is_accepted(tmp_path):
    d = doc_from(b"\xef\xbb\xbf" + stream([proc(1, 0, "init")]), tmp_path)
    assert d["summary"]["records"] == 1


def test_stream_without_header_is_refused(tmp_path):
    p = tmp_path / "x.jsonl"
    p.write_text(json.dumps(proc(1, 0, "init")) + "\n")
    with pytest.raises(ingest.IngestError):
        ingest.ingest_paths([p], allow_unverified=True)


def test_wrong_document_kinds_are_refused(tmp_path):
    p = tmp_path / "x.json"
    p.write_text(json.dumps({"kind": "something-else"}))
    with pytest.raises(ingest.IngestError):
        ingest.ingest_paths([p], allow_unverified=True)
    p.write_text("[1,2]")
    with pytest.raises(ingest.IngestError):
        ingest.ingest_paths([p], allow_unverified=True)
    with pytest.raises(ingest.IngestError):
        ingest.ingest_paths([tmp_path / "missing.json"], allow_unverified=True)


# ------------------------------------------------------------------ duplicates and conflicts


def test_identical_repeated_observations_are_merged_and_counted(tmp_path):
    e = auth("2026-03-01T09:00:00Z", "login_failure", "failure", "root", "203.0.113.5", key="same")
    d = doc_from(stream([e, dict(e), dict(e)]), tmp_path)
    ev = [r for r in d["records"] if r["category"] == "auth_event"]
    assert len(ev) == 1 and ev[0]["occurrences"] == 3 and d["summary"]["duplicates_merged"] == 2


def test_conflicting_observations_keep_newest_and_report_the_difference(tmp_path):
    a = stream(
        [
            rec(
                "service",
                "svc:x",
                {"name": "x", "state": "running"},
                observed_at="2026-03-01T10:00:00Z",
            )
        ],
        cid="a",
    )
    b = stream(
        [
            rec(
                "service",
                "svc:x",
                {"name": "x", "state": "stopped"},
                observed_at="2026-03-01T10:04:00Z",
            )
        ],
        cid="b",
    )
    (tmp_path / "a.jsonl").write_bytes(a)
    (tmp_path / "b.jsonl").write_bytes(b)
    d = ingest.ingest_paths([tmp_path / "a.jsonl", tmp_path / "b.jsonl"], allow_unverified=True)
    svc = [r for r in d["records"] if r["category"] == "service"]
    assert len(svc) == 1 and svc[0]["attributes"]["state"] == "stopped"
    assert d["conflicts"] == [
        {
            "record_id": svc[0]["record_id"],
            "category": "service",
            "differing_attributes": ["state"],
            "kept": "newest",
        }
    ]


def test_inputs_for_different_hosts_are_refused(tmp_path):
    (tmp_path / "a.jsonl").write_bytes(stream([proc(1, 0, "init")], host="h1"))
    (tmp_path / "b.jsonl").write_bytes(stream([proc(1, 0, "init")], host="h2"))
    with pytest.raises(ingest.IngestError, match="different host"):
        ingest.ingest_paths([tmp_path / "a.jsonl", tmp_path / "b.jsonl"], allow_unverified=True)


def test_best_coverage_across_inputs_wins(tmp_path):
    (tmp_path / "a.jsonl").write_bytes(stream([], coverage(["service"], "unavailable", "denied")))
    (tmp_path / "b.jsonl").write_bytes(
        stream([rec("service", "s", {"name": "s"})], coverage(["service"]))
    )
    d = ingest.ingest_paths([tmp_path / "a.jsonl", tmp_path / "b.jsonl"], allow_unverified=True)
    assert [c["status"] for c in d["coverage"] if c["category"] == "service"] == ["complete"]


# ------------------------------------------------------------------ derived records


def test_auth_summaries_are_derived_with_traceability(tmp_path):
    ev = [
        auth(f"2026-03-01T09:0{i}:00Z", "login_failure", "failure", u, "203.0.113.5")
        for i, u in enumerate(["root", "admin", "alice", "bob"])
    ]
    ev.append(auth("2026-03-01T09:30:00Z", "login_success", "success", "alice", "203.0.113.5"))
    d = doc_from(stream(ev), tmp_path)
    src = next(r for r in d["records"] if r["key"] == "source:203.0.113.5")
    a = src["attributes"]
    assert (
        a["failures"] == 4
        and a["successes"] == 1
        and a["users_targeted"] == 4
        and a["success_after_failure"] is True
    )
    assert src["source"]["type"] == "derived" and len(src["derived_from"]) == 5
    user = next(r for r in d["records"] if r["key"] == "user:alice")["attributes"]
    assert user["failures"] == 1 and user["success_after_failure"] is True


def test_auth_summary_does_not_claim_ordering_without_times(tmp_path):
    ev = [
        auth(None, "login_failure", "failure", "root", "203.0.113.5", key="a"),
        auth(None, "login_success", "success", "root", "203.0.113.5", key="b"),
    ]
    d = doc_from(stream(ev), tmp_path)
    s = next(r for r in d["records"] if r["key"] == "source:203.0.113.5")
    assert s["attributes"]["success_after_failure"] is None and s["status"] == "partial"


def test_summaries_are_recomputed_not_trusted_from_a_document(tmp_path):
    ev = [auth("2026-03-01T09:00:00Z", "login_failure", "failure", "root", "203.0.113.5")]
    d = doc_from(stream(ev), tmp_path)
    forged = json.loads(json.dumps(d))
    for r in forged["records"]:
        if r["category"] == "auth_summary":
            r["attributes"]["failures"] = 9999
    p = tmp_path / "forged.json"
    p.write_text(json.dumps(forged))
    again = ingest.ingest_paths([p], allow_unverified=True)
    s = next(
        r
        for r in again["records"]
        if r["category"] == "auth_summary" and r["key"] == "source:203.0.113.5"
    )
    assert s["attributes"]["failures"] == 1


# ------------------------------------------------------------------ store


def test_store_roundtrip_and_tamper_detection(tmp_path):
    src = tmp_path / "a.jsonl"
    src.write_bytes(stream([proc(1, 0, "init")]))
    d = ingest.ingest_paths([src], allow_unverified=True)
    root = ingest.write_store(d, tmp_path / "out", [("a.jsonl", src.read_bytes())])
    assert (root / "sources").is_dir() and (root / "manifest.json").is_file()
    assert (root.stat().st_mode & 0o777) == 0o700 or __import__("os").name != "posix"
    assert ingest.load_telemetry(root)["summary"]["records"] == 1
    (root / "telemetry.json").write_text(
        (root / "telemetry.json").read_text().replace("init", "evil")
    )
    with pytest.raises(ingest.IngestError, match="manifest"):
        ingest.load_telemetry(root)


def test_every_category_is_covered_by_schema_and_vocabulary():
    from shared.telemetry.model import CATEGORIES

    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "shared/schemas/telemetry.schema.json").read_text()
    )
    assert set(schema["$defs"]["category"]["enum"]) == set(CATEGORIES)
    assert set(ALL_CATEGORIES) <= set(CATEGORIES)


def test_store_accepts_fractional_second_timestamps_from_the_windows_collector(tmp_path):
    # Regression: the PowerShell collector writes millisecond timestamps; the manifest schema is
    # whole-seconds, so the store must still be writable, verifiable and loadable.
    data = stream(
        [proc(1, 0, "init")], started="2026-03-01T10:00:00.93Z", ended="2026-03-01T10:00:07.297Z"
    )
    p = tmp_path / "w.jsonl"
    p.write_bytes(data)
    d = ingest.ingest_paths([p], allow_unverified=True)
    assert d["collection"]["started_at"] == "2026-03-01T10:00:00.93Z"
    root = ingest.write_store(d, tmp_path / "out", [("w.jsonl", data)])
    assert ".93" not in root.name
    assert ingest.load_telemetry(root)["summary"]["records"] == 1
