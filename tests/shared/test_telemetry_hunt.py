"""Hunting through the detection engine: integration, honesty and false-positive guards."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from telemetry_support import auth, coverage, proc, rec, stream

from shared.engine.loader import load_assessment
from shared.reporting.schema_lite import validate
from shared.rules.engine import detect
from shared.rules.investigation import CaseStore
from shared.rules.loader import load_rule_set
from shared.telemetry import ingest
from shared.telemetry.adapter import raw_from_assessment_doc
from shared.telemetry.hunt import classification, shell_assessment

ROOT = Path(__file__).resolve().parents[2]
STAMP = "2026-03-02T00:00:00Z"
TEL_RULES = load_rule_set().only(lambda r: any(s.startswith("telemetry") for s in r.sources))


def make(tmp_path, records, cov=None, name="t.jsonl", **kw):
    p = tmp_path / name
    p.write_bytes(stream(records, cov, **kw))
    return ingest.ingest_paths([p], generated_at=STAMP, allow_unverified=True)


def run(doc, base=None, rs=TEL_RULES):
    res = detect(
        shell_assessment(doc), rs, generated_at=STAMP, telemetry=doc, telemetry_baseline=base
    )
    assert validate(res, "detection-results.schema.json") == []
    return res


def ids(res):
    return {d["rule"]["id"] for d in res["detections"]}


def benign_host():
    return [
        proc(1, 0, "systemd"),
        proc(100, 1, "sshd", exe="/usr/sbin/sshd"),
        proc(200, 100, "sshd", exe="/usr/sbin/sshd", user="alice"),
        proc(300, 200, "bash", user="alice"),
        proc(400, 1, "nginx", user="www-data", exe="/usr/sbin/nginx"),
        proc(401, 400, "nginx", user="www-data", exe="/usr/sbin/nginx"),
        rec(
            "listener",
            "l1",
            {
                "protocol": "tcp",
                "local_address": "0.0.0.0",
                "local_port": 22,
                "pid": 100,
                "process": "sshd",
            },
        ),
        rec(
            "network_connection",
            "c1",
            {
                "protocol": "tcp",
                "state": "established",
                "local_address": "10.0.0.5",
                "local_port": 22,
                "remote_address": "10.0.0.9",
                "remote_port": 50000,
                "pid": 200,
                "process": "sshd",
            },
        ),
        rec(
            "scheduled_task",
            "t1",
            {
                "name": "/etc/cron.daily/logrotate",
                "command": "/usr/sbin/logrotate /etc/logrotate.conf",
                "user": "root",
            },
            scope="cron",
        ),
        rec("service", "s1", {"name": "ssh.service", "path": "/usr/sbin/sshd -D"}),
        auth("2026-03-01T09:00:00Z", "login_success", "success", "alice", "10.0.0.9"),
        auth("2026-03-01T09:30:00Z", "login_failure", "failure", "alice", "10.0.0.9"),
    ]


def test_a_benign_host_produces_no_detections(tmp_path):
    doc = make(tmp_path, benign_host())
    res = run(doc)
    assert res["detections"] == [], [d["title"] for d in res["detections"]]


def test_every_detection_explains_itself_and_never_claims_proof(tmp_path):
    recs = [proc(100, 1, "nginx", user="www-data"), proc(200, 100, "bash", user="www-data")]
    res = run(make(tmp_path, recs))
    assert res["detections"]
    for d in res["detections"]:
        e = d["explanation"]
        assert d["nature"] in ("indicator", "correlated", "observation", "hypothesis")
        assert "proof" in e["disclaimer"].lower() or "not " in e["disclaimer"].lower()
        assert e["possible_benign_causes"] and e["why_flagged"] and e["why_correlated"]
        assert all(
            c["type"] == "telemetry" and c["id"].startswith("TEL-") for c in d["contributing"]
        )
        assert d["references"]["attack"], "a hunting rule maps to ATT&CK"
        assert all(a["relationship"] == "possible" for a in d["references"]["attack"])


def test_classification_never_says_confirmed():
    assert {
        classification(n) for n in ("observation", "indicator", "correlated", "hypothesis")
    } == {"unusual", "suspicious", "lead"}
    for rule in TEL_RULES.ordered():
        assert rule.nature != "hypothesis" or classification(rule.nature) == "lead"
        assert "confirmed" not in (rule.rationale + rule.name).lower()


def test_detections_trace_back_to_exact_telemetry_records(tmp_path):
    doc = make(
        tmp_path,
        [
            proc(100, 1, "nginx", user="www-data"),
            proc(200, 100, "bash", user="www-data", cmdline="bash -c id"),
        ],
    )
    d = next(x for x in run(doc)["detections"] if x["rule"]["id"] == "DR-ANY-HPRC-001")
    rid = d["contributing"][0]["id"]
    rec_ = next(r for r in doc["records"] if r["record_id"] == rid)
    assert rec_["attributes"]["name"] == "bash" and rec_["source"]["ref"] == "/proc/200"
    assert d["contributing"][0]["detail"]["attributes"]["cmdline"] == "bash -c id"


def test_missing_telemetry_makes_hunting_rules_not_applicable_not_indeterminate(tmp_path):
    cur = load_assessment(
        ROOT / "tests/fixtures/rules/linux-compromised.assessment.json", verify=False
    )
    res = detect(cur, load_rule_set(), generated_at=STAMP)
    hunting = [r for r in res["rule_results"] if "-H" in r["rule"] and r["rule"].startswith("DR-")]
    hunting = [r for r in hunting if r["rule"].split("-")[2].startswith("H")]
    assert len(hunting) == len(TEL_RULES.rules)
    assert {r["status"] for r in hunting} == {"not_applicable"}
    # platform-specific rules for the other OS are not applicable for that reason; the rest say why
    reasons = {r["rule"]: r.get("reason") for r in hunting}
    assert {v for k, v in reasons.items() if k.startswith("DR-ANY-")} <= {
        "no telemetry supplied",
        "no telemetry baseline supplied",
    }
    assert "telemetry" not in res


def test_change_rules_need_a_baseline_and_say_so(tmp_path):
    doc = make(tmp_path, benign_host())
    res = run(doc)
    chg = [r for r in res["rule_results"] if "HCHG" in r["rule"]]
    assert (
        chg
        and {r["status"] for r in chg} == {"not_applicable"}
        and {r["reason"] for r in chg} == {"no telemetry baseline supplied"}
    )


def test_unavailable_categories_are_indeterminate_and_carry_the_reason(tmp_path):
    cov = coverage(["process"]) + coverage(
        ["auth_event"], "unavailable", "auth.log is not readable"
    )
    res = run(make(tmp_path, [proc(1, 0, "systemd")], cov))
    ind = {i["rule"]["id"]: i["reason"] for i in res["indeterminate"]}
    assert "auth.log is not readable" in ind["DR-ANY-HAUTH-001"]
    assert (
        res["telemetry"]["unavailable"] == ["auth_event", "auth_summary"]
        and res["telemetry"]["complete"] is False
    )


def test_partial_coverage_lowers_confidence_and_says_why(tmp_path):
    recs = [proc(100, 1, "nginx", user="www-data"), proc(200, 100, "bash", user="www-data")]
    full = run(make(tmp_path, recs, coverage(["process"])))
    part = run(
        make(tmp_path, recs, coverage(["process"], "partial", "10 owners unknown"), name="p.jsonl")
    )
    f = next(d for d in full["detections"] if d["rule"]["id"] == "DR-ANY-HPRC-001")
    p = next(d for d in part["detections"] if d["rule"]["id"] == "DR-ANY-HPRC-001")
    order = ["low", "medium", "high"]
    assert order.index(p["confidence"]) < order.index(f["confidence"])
    assert any("10 owners unknown" in c for c in p["explanation"]["caveats"])


def test_hunting_requires_the_telemetry_to_be_for_the_same_host(tmp_path):
    cur = load_assessment(
        ROOT / "tests/fixtures/rules/linux-compromised.assessment.json", verify=False
    )
    doc = make(tmp_path, [proc(1, 0, "systemd")], host="some-other-host")
    with pytest.raises(ValueError, match="different host"):
        detect(cur, TEL_RULES, generated_at=STAMP, telemetry=doc)


def test_assessment_and_telemetry_of_one_host_join(tmp_path):
    cur = load_assessment(
        ROOT / "tests/fixtures/rules/linux-compromised.assessment.json", verify=False
    )
    doc = ingest.build_document([raw_from_assessment_doc(cur)], mode="assessment")
    res = detect(cur, load_rule_set(), generated_at=STAMP, telemetry=doc)
    assert res["telemetry"]["records"] == doc["summary"]["records"]
    assert any(d["rule"]["id"].startswith("DR-LNX-ACC") for d in res["detections"]), (
        "assessment rules still run"
    )


def test_auth_patterns_have_thresholds_and_ordering(tmp_path):
    fails = [
        auth(f"2026-03-01T09:{i:02d}:00Z", "login_failure", "failure", u, "203.0.113.5")
        for i, u in enumerate(["a", "b", "c"] * 4)
    ]
    assert "DR-ANY-HAUTH-001" in ids(run(make(tmp_path, fails)))
    assert "DR-ANY-HAUTH-001" not in ids(run(make(tmp_path, fails[:5], name="few.jsonl")))
    late = [
        *fails[:6],
        auth("2026-03-01T10:00:00Z", "login_success", "success", "a", "203.0.113.5"),
    ]
    early = [
        auth("2026-03-01T08:00:00Z", "login_success", "success", "a", "203.0.113.5"),
        *fails[:6],
    ]
    assert "DR-ANY-HAUTH-002" in ids(run(make(tmp_path, late, name="late.jsonl")))
    assert "DR-ANY-HAUTH-002" not in ids(run(make(tmp_path, early, name="early.jsonl")))


def test_process_tree_fields_survive_cycles_and_orphans(tmp_path):
    recs = [proc(10, 20, "nginx", user="www-data"), proc(20, 10, "bash"), proc(30, 999, "bash")]
    res = run(make(tmp_path, recs))  # a ppid cycle and an orphan must not hang or crash the engine
    assert res["rule_errors"] == []


def test_duplicate_events_do_not_inflate_thresholds(tmp_path):
    one = auth(
        "2026-03-01T09:00:00Z", "login_failure", "failure", "root", "203.0.113.5", key="same"
    )
    doc = make(tmp_path, [dict(one) for _ in range(30)])
    s = next(r for r in doc["records"] if r["key"] == "source:203.0.113.5")
    assert s["attributes"]["failures"] == 30 and s["attributes"]["users_targeted"] == 1
    assert "DR-ANY-HAUTH-001" not in ids(run(doc)), (
        "30 identical lines against one account are not a spray"
    )


# ------------------------------------------------------------------ snapshot rules


def snap(tmp_path, name, records, **kw):
    return make(tmp_path, records, name=name, **kw)


def test_new_listener_and_service_between_snapshots(tmp_path):
    base = snap(
        tmp_path,
        "b.jsonl",
        [
            rec(
                "listener",
                "l1",
                {
                    "protocol": "tcp",
                    "local_address": "0.0.0.0",
                    "local_port": 22,
                    "process": "sshd",
                },
            ),
            rec("service", "s1", {"name": "a.service", "path": "/usr/bin/a"}),
        ],
        cid="base",
        started="2026-03-01T10:00:00Z",
    )
    cur = snap(
        tmp_path,
        "c.jsonl",
        [
            rec(
                "listener",
                "l1",
                {
                    "protocol": "tcp",
                    "local_address": "0.0.0.0",
                    "local_port": 22,
                    "process": "sshd",
                },
            ),
            rec(
                "listener",
                "l2",
                {"protocol": "tcp", "local_address": "0.0.0.0", "local_port": 4444, "process": "x"},
            ),
            rec("service", "s1", {"name": "a.service", "path": "/usr/bin/a"}),
            rec("service", "s2", {"name": "b.service", "path": "/usr/bin/b"}),
        ],
        cid="cur",
        started="2026-03-02T10:00:00Z",
    )
    res = run(cur, base)
    assert {"DR-ANY-HCHG-001", "DR-ANY-HCHG-002"} <= ids(res)
    d = next(x for x in res["detections"] if x["rule"]["id"] == "DR-ANY-HCHG-001")
    assert "4444" in d["title"] and res["telemetry"]["compared_with"] == "base"


def test_change_rules_are_indeterminate_when_the_baseline_was_incomplete(tmp_path):
    base = snap(
        tmp_path, "b.jsonl", [], cov=coverage(["listener"], "unavailable", "denied"), cid="base"
    )
    cur = snap(
        tmp_path,
        "c.jsonl",
        [
            rec(
                "listener",
                "l2",
                {"protocol": "tcp", "local_address": "0.0.0.0", "local_port": 4444, "process": "x"},
            )
        ],
        cid="cur",
        started="2026-03-02T10:00:00Z",
    )
    res = run(cur, base)
    assert "DR-ANY-HCHG-001" not in ids(res)
    assert any(i["rule"]["id"] == "DR-ANY-HCHG-001" for i in res["indeterminate"])


def test_sensitive_file_hash_and_group_membership_changes(tmp_path):
    def integ(h):
        return rec("integrity", "i1", {"path": "/etc/sudoers", "sha256": h * 64, "mode": "440"})

    base = snap(
        tmp_path,
        "b.jsonl",
        [integ("a"), rec("group", "g", {"name": "sudo", "members": ["alice"]})],
        cid="base",
    )
    cur = snap(
        tmp_path,
        "c.jsonl",
        [integ("b"), rec("group", "g", {"name": "sudo", "members": ["alice", "mallory"]})],
        cid="cur",
        started="2026-03-02T10:00:00Z",
    )
    assert {"DR-ANY-HCHG-003", "DR-ANY-HCHG-004"} <= ids(run(cur, base))


# ------------------------------------------------------------------ cases and reports


def test_hunting_detections_become_investigation_cases(tmp_path):
    doc = make(
        tmp_path, [proc(100, 1, "nginx", user="www-data"), proc(200, 100, "bash", user="www-data")]
    )
    res = run(doc)
    store = CaseStore(str(tmp_path / "state"), "alice")
    reg = store.observe(res)
    assert len(reg["new"]) == len(res["detections"]) > 0
    det = res["detections"][0]["id"]
    assert store.set_status(det, "investigating").status == "investigating"
    with pytest.raises(Exception, match="note is required"):
        store.set_status(det, "dismissed")  # closing a case needs a stated reason
    assert (
        store.set_status(det, "dismissed", note="authorised maintenance shell").status
        == "dismissed"
    )
    again = CaseStore(str(tmp_path / "state"), "bob").observe(res)
    assert det in again["reappeared"], "a dismissed detection that is observed again is flagged"


def test_detection_ids_are_stable_for_the_same_telemetry(tmp_path):
    recs = [proc(100, 1, "nginx", user="www-data"), proc(200, 100, "bash", user="www-data")]
    a = {d["id"] for d in run(make(tmp_path, recs, name="a.jsonl")).get("detections", [])}
    b = {
        d["id"]
        for d in run(make(tmp_path, recs, name="b.jsonl", cid="other-run")).get("detections", [])
    }
    assert a == b and a


def test_hostile_content_is_escaped_in_every_report_format(tmp_path):
    evil = "<script>alert(1)</script>"
    recs = [
        proc(100, 1, "nginx", user="www-data"),
        proc(200, 100, "bash", user="www-data", cmdline=evil, exe=f"/tmp/{evil}"),
    ]
    doc = make(tmp_path, recs)
    res = run(doc)
    from shared.telemetry import render

    html = render.render_html(doc, res)
    md = render.render_markdown(doc, res)
    assert "<script>alert(1)</script>" not in html
    assert "<script>" not in md
    assert "Content-Security-Policy" in html


def test_rule_pack_documents_limitations_for_every_rule():
    for r in TEL_RULES.ordered():
        assert r.false_positives and r.investigation and r.remediation and r.confidence_reason
        assert "does not change the host" in r.remediation or "This tool does not" in r.remediation


def test_results_round_trip_through_json(tmp_path):
    res = run(
        make(
            tmp_path,
            [proc(100, 1, "nginx", user="www-data"), proc(200, 100, "bash", user="www-data")],
        )
    )
    assert json.loads(json.dumps(res)) == res
