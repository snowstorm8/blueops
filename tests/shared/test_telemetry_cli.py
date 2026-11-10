"""`python -m shared.engine telemetry ...` end to end on synthetic streams."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from engine_support import trust_fixtures
from telemetry_support import auth, coverage, proc, rec, stream

from shared.engine.cli import main
from shared.reporting.schema_lite import validate

ROOT = Path(__file__).resolve().parents[2]


def call(capsys, *argv):
    capsys.readouterr()
    try:
        rc = main(trust_fixtures([str(a) for a in argv]))
    except SystemExit as exc:
        rc = int(exc.code)
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


def host_records():
    return [
        proc(1, 0, "systemd"), proc(100, 1, "nginx", user="www-data"), proc(200, 100, "bash", user="www-data", cmdline="bash -i"),
        proc(300, 1, "sshd", exe="/usr/sbin/sshd"),
        rec("network_connection", "c1", {"protocol": "tcp", "state": "established", "local_address": "10.0.0.5", "local_port": 40000, "remote_address": "203.0.113.9", "remote_port": 4444, "pid": 200, "process": "bash"}),
        rec("service", "s1", {"name": "ssh.service", "path": "/usr/sbin/sshd -D"}),
        *[auth(f"2026-03-01T09:{i:02d}:00Z", "login_failure", "failure", u, "198.51.100.4") for i, u in enumerate(["root", "admin", "alice"] * 4)],
    ]  # fmt: skip


@pytest.fixture
def store(tmp_path, capsys):
    src = tmp_path / "s.jsonl"
    src.write_bytes(stream(host_records(), host="web01"))
    rc, out, err = call(
        capsys, "telemetry", "import", src, "--output-dir", tmp_path / "out", "--format", "json"
    )
    assert rc == 0, err
    return Path(json.loads(out)["store"])


# ------------------------------------------------------------------ import and show


def test_import_writes_a_verified_store_and_never_overwrites(tmp_path, capsys):
    src = tmp_path / "s.jsonl"
    src.write_bytes(stream(host_records(), host="web01"))
    rc, out, _ = call(capsys, "telemetry", "import", src, "--output-dir", tmp_path / "out")
    assert rc == 0 and "complete: yes" in out and "stored in" in out
    rc2, _, _ = call(
        capsys, "telemetry", "import", src, "--output-dir", tmp_path / "out", "--quiet"
    )
    assert rc2 == 0
    assert len(list((tmp_path / "out").glob("blueops-telemetry-*"))) == 2, (
        "a second import gets its own directory"
    )


def test_import_of_damaged_input_reports_gaps_and_exits_6(tmp_path, capsys):
    data = stream(host_records(), host="web01", end=False).decode().splitlines()
    data.insert(4, "{broken")
    src = tmp_path / "s.jsonl"
    src.write_text("\n".join(data) + "\n")
    rc, out, _ = call(capsys, "telemetry", "import", src, "--output-dir", tmp_path / "out")
    assert rc == 6 and "complete: NO" in out and "TRUNCATED_STREAM" in out and "rejected" in out


def test_import_errors_exit_3(tmp_path, capsys):
    assert (
        call(capsys, "telemetry", "import", tmp_path / "missing", "--output-dir", tmp_path / "o")[0]
        == 3
    )
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    assert call(capsys, "telemetry", "import", bad, "--output-dir", tmp_path / "o")[0] == 3


def test_a_tampered_store_is_refused_by_every_command(store, capsys):
    (store / "telemetry.json").write_text(
        (store / "telemetry.json").read_text().replace("nginx", "nginz")
    )
    for argv in (["show"], ["query"], ["tree", "--pid", "1"], ["hunt"]):
        rc, _, err = call(capsys, "telemetry", argv[0], store, *argv[1:])
        assert rc == 3 and "manifest" in err, argv


def test_show_json_is_the_schema_valid_document(store, capsys):
    rc, out, _ = call(capsys, "telemetry", "show", store, "--format", "json")
    assert rc == 0 and validate(json.loads(out), "telemetry.schema.json") == []


# ------------------------------------------------------------------ query


def test_query_filters(store, capsys):
    rc, out, _ = call(
        capsys, "telemetry", "query", store, "--category", "process", "--attr", "user=www-data"
    )
    assert rc == 0 and "2 of 2 matching" in out
    rc, out, _ = call(
        capsys,
        "telemetry",
        "query",
        store,
        "--category",
        "process",
        "--contains",
        "cmdline~-i",
        "--format",
        "json",
    )
    assert [r["attributes"]["name"] for r in json.loads(out)["records"]] == ["bash"]
    rc, out, _ = call(
        capsys,
        "telemetry",
        "query",
        store,
        "--category",
        "auth_event",
        "--since",
        "2026-03-01T09:05:00Z",
        "--until",
        "2026-03-01T09:07:00Z",
        "--format",
        "json",
    )
    assert json.loads(out)["total"] == 3
    rc, out, _ = call(capsys, "telemetry", "query", store, "--host", "other", "--format", "json")
    assert json.loads(out)["total"] == 0


def test_query_file_with_condition_and_limit(store, tmp_path, capsys):
    q = tmp_path / "q.json"
    q.write_text(
        json.dumps(
            {
                "category": ["process"],
                "where": {
                    "any": [
                        {"field": "process.parent_name", "op": "eq", "value": "nginx"},
                        {"field": "attrs.name", "op": "eq", "value": "sshd"},
                    ]
                },
                "sort": "key",
                "limit": 5,
            }
        )
    )
    rc, out, _ = call(capsys, "telemetry", "query", store, "--query", q, "--format", "json")
    assert rc == 0 and sorted(r["attributes"]["name"] for r in json.loads(out)["records"]) == [
        "bash",
        "sshd",
    ]


@pytest.mark.parametrize(
    "query",
    [
        {
            "where": {"field": "attrs.name", "op": "eval", "value": "x"}
        },  # unknown operator: no code evaluation
        {"where": {"field": "nope.field", "op": "eq", "value": "x"}},
        {
            "where": {"field": "attrs.name", "op": "regex", "value": "(a+)+$"}
        },  # catastrophic backtracking shape
        {"category": ["nonsense"]},
        {"limit": 0},
        {"limit": 10**9},
        {"since": "yesterday"},
        {"unexpected": 1},
        {"sort": "random"},
    ],
)
def test_malformed_or_dangerous_queries_are_rejected_before_running(store, tmp_path, capsys, query):
    q = tmp_path / "q.json"
    q.write_text(json.dumps(query))
    rc, _, err = call(capsys, "telemetry", "query", store, "--query", q)
    assert rc == 2 and "query:" in err


def test_attr_flag_syntax_errors_exit_2(store, capsys):
    assert call(capsys, "telemetry", "query", store, "--attr", "noequals")[0] == 2


# ------------------------------------------------------------------ tree


def test_tree_shows_ancestors_and_descendants(store, capsys):
    rc, out, _ = call(capsys, "telemetry", "tree", store, "--pid", "100")
    assert rc == 0
    lines = out.splitlines()
    assert (
        lines[0].startswith("systemd")
        and any("* nginx" in x for x in lines)
        and any("bash" in x for x in lines)
    )
    assert call(capsys, "telemetry", "tree", store, "--name", "nginx")[0] == 0
    assert call(capsys, "telemetry", "tree", store, "--pid", "9999")[0] == 6


def test_tree_survives_a_parent_cycle(tmp_path, capsys):
    src = tmp_path / "c.jsonl"
    src.write_bytes(stream([proc(10, 20, "a"), proc(20, 10, "b")], host="h"))
    assert (
        call(
            capsys, "telemetry", "import", src, "--output-dir", tmp_path / "o", "--format", "json"
        )[0]
        == 0
    )
    st = next((tmp_path / "o").glob("blueops-telemetry-*"))
    rc, out, _ = call(capsys, "telemetry", "tree", st, "--pid", "10")
    assert rc == 0 and len(out.splitlines()) < 50


# ------------------------------------------------------------------ compare


def test_compare_exit_codes_and_validity(tmp_path, capsys):
    def imp(name, recs, cov=None, **kw):
        p = tmp_path / f"{name}.jsonl"
        p.write_bytes(stream(recs, cov, host="web01", **kw))
        rc, out, _ = call(
            capsys, "telemetry", "import", p, "--output-dir", tmp_path / name, "--format", "json"
        )
        assert rc in (0, 6)
        return json.loads(out)["store"]

    a = imp("a", [rec("service", "s1", {"name": "a"})])
    same = imp(
        "same", [rec("service", "s1", {"name": "a"})], started="2026-03-02T10:00:00Z", cid="same"
    )
    diff = imp(
        "diff",
        [rec("service", "s1", {"name": "a"}), rec("service", "s2", {"name": "b"})],
        started="2026-03-03T10:00:00Z",
        cid="diff",
    )
    gap = imp(
        "gap",
        [],
        coverage(["service"], "unavailable", "denied"),
        started="2026-03-04T10:00:00Z",
        cid="gap",
    )
    assert call(capsys, "telemetry", "compare", a, same)[0] == 0
    rc, out, _ = call(capsys, "telemetry", "compare", a, diff)
    assert rc == 4 and validate(json.loads(out), "telemetry-comparison.schema.json") == []
    rc, out, _ = call(capsys, "telemetry", "compare", a, gap, "--format", "text")
    assert rc == 6 and "indeterminate service" in out and "denied" in out
    other = tmp_path / "o.jsonl"
    other.write_bytes(stream([rec("service", "s1", {"name": "a"})], host="another"))
    o = json.loads(
        call(
            capsys,
            "telemetry",
            "import",
            other,
            "--output-dir",
            tmp_path / "oo",
            "--format",
            "json",
        )[1]
    )["store"]
    assert call(capsys, "telemetry", "compare", a, o)[0] == 3


# ------------------------------------------------------------------ hunt, cases, reports


def test_hunt_exit_codes_formats_and_cases(store, tmp_path, capsys):
    state = tmp_path / "state"
    rc, out, err = call(
        capsys, "telemetry", "hunt", store, "--state-dir", state, "--actor", "alice"
    )
    res = json.loads(out)
    assert rc == 4 and validate(res, "detection-results.schema.json") == []
    assert {"DR-ANY-HPRC-001", "DR-ANY-HPRC-004", "DR-ANY-HAUTH-001"} <= {
        d["rule"]["id"] for d in res["detections"]
    }
    assert "cases:" in err
    rc, out, _ = call(
        capsys,
        "telemetry",
        "hunt",
        store,
        "--format",
        "text",
        "--quiet",
        "--min-severity",
        "high",
    )
    assert rc == 4 and "DR-ANY-HPRC-001" in out and "DR-ANY-HAUTH-001" not in out
    # nothing reaches critical, but some rules could not be evaluated (categories this stream did
    # not collect), so the contract is exit 6 (incomplete), not a clean 0
    assert call(capsys, "telemetry", "hunt", store, "--quiet", "--fail-on", "critical")[0] == 6
    rc, out, _ = call(capsys, "case", "list", "--state-dir", state, "--json")
    assert rc == 0 and len(json.loads(out)) == len(res["detections"])


def test_detect_run_accepts_telemetry_directly_and_the_flag_pairing_is_checked(store, capsys):
    rc, out, _ = call(capsys, "detect", "run", "--telemetry", store, "--quiet")
    assert rc == 4 and json.loads(out)["telemetry"]["records"] > 0
    rc, _, err = call(capsys, "detect", "run", "--telemetry-baseline", store, "--quiet")
    assert rc in (2, 3)
    assert call(capsys, "detect", "run")[0] == 2


def test_hunt_report_formats_and_overwrite_protection(store, tmp_path, capsys):
    res = tmp_path / "res.json"
    assert call(capsys, "telemetry", "hunt", store, "--quiet", "--output", res)[0] == 4
    md, html = tmp_path / "r.md", tmp_path / "r.html"
    assert call(capsys, "telemetry", "report", store, "--detections", res, "--output", md)[0] == 0
    assert (
        call(
            capsys,
            "telemetry",
            "report",
            store,
            "--detections",
            res,
            "--format",
            "html",
            "--output",
            html,
        )[0]
        == 0
    )
    text = md.read_text()
    assert "## Coverage" in text and "### Suspicious" in text and "Not proof" in text
    page = html.read_text()
    assert "Content-Security-Policy" in page and "<script" not in page.lower()
    assert call(capsys, "telemetry", "report", store, "--output", md)[0] == 3, (
        "never overwrites an existing report"
    )
    assert (
        call(capsys, "telemetry", "report", store, "--detections", store / "telemetry.json")[0] == 3
    )


def test_hunt_with_a_real_assessment_of_the_same_host(tmp_path, capsys):
    assessment = ROOT / "tests/fixtures/rules/linux-compromised.assessment.json"
    host = json.loads(assessment.read_text())["host"]["hostname"]
    src = tmp_path / "t.jsonl"
    src.write_bytes(
        stream(
            [proc(100, 1, "nginx", user="www-data"), proc(200, 100, "bash", user="www-data")],
            host=host,
        )
    )
    st = json.loads(
        call(
            capsys, "telemetry", "import", src, "--output-dir", tmp_path / "o", "--format", "json"
        )[1]
    )["store"]
    rc, out, _ = call(capsys, "telemetry", "hunt", st, "--assessment", assessment, "--quiet")
    ids = {d["rule"]["id"] for d in json.loads(out)["detections"]}
    assert rc == 4 and "DR-ANY-HPRC-001" in ids and any(i.startswith("DR-LNX-") for i in ids)
    other = tmp_path / "o.jsonl"
    other.write_bytes(stream([proc(1, 0, "x")], host="not-the-same-host"))
    st2 = json.loads(
        call(
            capsys,
            "telemetry",
            "import",
            other,
            "--output-dir",
            tmp_path / "o2",
            "--format",
            "json",
        )[1]
    )["store"]
    assert call(capsys, "telemetry", "hunt", st2, "--assessment", assessment, "--quiet")[0] == 3


# ------------------------------------------------------------------ collect preconditions


def test_collect_refuses_a_collector_for_another_platform_and_bad_arguments(tmp_path, capsys):
    other = "windows" if __import__("sys").platform != "win32" else "linux"
    rc, _, err = call(capsys, "telemetry", "collect", "--platform", other, "--output-dir", tmp_path)
    assert rc == 3 and "cannot inspect" in err
    assert (
        call(capsys, "telemetry", "collect", "--output-dir", tmp_path, "--since-hours", "0")[0] == 2
    )
    assert (
        call(capsys, "telemetry", "collect", "--output-dir", tmp_path, "--categories", "bogus")[0]
        == 2
    )


def test_example_stream_in_the_repository_stays_valid(tmp_path, capsys):
    example = ROOT / "examples" / "telemetry" / "web01-compromised.jsonl"
    rc, out, _ = call(
        capsys, "telemetry", "import", example, "--output-dir", tmp_path / "o", "--format", "json"
    )
    assert rc == 0 and json.loads(out)["rejected"] == 0
