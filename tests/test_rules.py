import json
from pathlib import Path

import pytest

from specgen import evidence, rules

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


@pytest.mark.parametrize("op, x, e, status", [
    (">=", 0.95, 0.9, "PASS"), (">=", 0.3, 0.9, "FAIL"), (">=", None, 0.9, "N/A"), (">=", True, 0.9, "N/A"),
    ("<=", 0, 0, "PASS"), ("<=", 3, 0, "FAIL"),
    ("==", "present", "present", "PASS"), ("==", "absent", "present", "FAIL"), ("==", None, "present", "N/A"),
    ("in", "b", ["a", "b"], "PASS"), ("in", "c", ["a", "b"], "FAIL"),
    ("empty", [], None, "PASS"), ("empty", ["telnetd"], None, "FAIL"), ("empty", None, None, "N/A"),
    ("not_empty", ["x"], None, "PASS"), ("not_empty", [], None, "FAIL"),
])
def test_operators(op, x, e, status):
    assert rules.check({"m": x}, {"evidence": "m", "op": op, "value": e}, {})["status"] == status


def test_all_true_and_thresholds():
    ev = {"d": [{"path": "/a", "canary": True, "pie": True}, {"path": "/b", "canary": True, "pie": False}]}
    res = rules.check(ev, {"evidence": "d", "op": "all_true", "value": ["canary", "pie"]}, {})
    assert (res["status"], res["observed"]) == ("FAIL", ["/b"])
    assert rules.check({"d": []}, {"evidence": "d", "op": "all_true", "value": ["canary"]}, {})["status"] == "N/A"
    assert rules.check({"m": 0.5}, {"evidence": "m", "op": ">=", "threshold": "t"}, {"t": 0.4})["status"] == "PASS"


def test_ruleset_on_fixtures(tmp_path):
    rs = rules.load()
    assert len(rs["rules"]) == 13
    for name in ("evidence_insecure.json", "evidence_hardened.json"):
        evidence.validate(load(name))
    bad = rules.evaluate(load("evidence_insecure.json"), rs)
    good = rules.evaluate(load("evidence_hardened.json"), rs)
    assert bad["summary"] == {"PASS": 0, "FAIL": 13, "N/A": 0}
    assert good["summary"] == {"PASS": 13, "FAIL": 0, "N/A": 0}
    f = next(f for f in bad["findings"] if f["rule_id"] == "MS-01")
    assert f["checks"][0]["evidence_ref"] == "/hardening/ratios/canary" and f["checks"][0]["observed"] == 0.3
    assert f["acceptance_test"] == "at least 90% of executables carry stack canaries"

    no_kev = load("evidence_hardened.json")
    no_kev["vulns"]["kev"] = None  # no KEV catalog: DH-02 only half ran, so it must not show PASS
    f = next(f for f in rules.evaluate(no_kev, rs)["findings"] if f["rule_id"] == "DH-02")
    assert f["status"] == "N/A"

    relaxed = tmp_path / "t.yaml"
    relaxed.write_text("min_canary_ratio: 0.1\n")
    f = next(f for f in rules.evaluate(load("evidence_insecure.json"), rules.load(thresholds=relaxed))["findings"]
             if f["rule_id"] == "MS-01")
    assert f["status"] == "PASS"
