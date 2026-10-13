import json
import shutil
from pathlib import Path

import pytest

from specgen import render, rules, tools

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def generated(tmp_path):
    rs = rules.load()
    targets = []
    for name in ("evidence_insecure.json", "evidence_hardened.json"):
        d = tmp_path / name.split(".")[0]
        d.mkdir()
        shutil.copy(FIX / name, d / "evidence.json")
        ev = json.loads((d / "evidence.json").read_text())
        targets.append((ev, rules.evaluate(ev, rs), d / "evidence.json"))
    rows = render.generate(targets, rs, baseline="fixture-hardened", out=tmp_path, policy=tmp_path / "policy")
    return tmp_path, rows


def test_outputs_render(generated):
    tmp, _ = generated
    checklist = (tmp / "evidence_insecure" / "procurement_checklist.md").read_text(encoding="utf-8")
    assert "- [ ] **REQ-MS-01**" in checklist and "IEC 62443-4-1:SI-2" in checklist
    report = (tmp / "acceptance_report.md").read_text(encoding="utf-8")
    for section in ("## 1. Targets", "## 2. Summary scorecard", "## 7. Traceability matrix", "`/usr/bin/iocheckd`"):
        assert section in report
    data = json.loads((tmp / "policy" / "gate_data.json").read_text())["icsspecgen"]
    assert data["baseline"]["name"] == "fixture-hardened" and len(data["rules"]) == 13
    assert {"gate_policy.rego", "gate_policy_test.rego"} <= {p.name for p in (tmp / "policy").iterdir()}


@pytest.mark.skipif(not tools.find("opa"), reason="opa not installed")
def test_opa_policy(generated):
    tmp, rows = generated
    opa, policy = tools.find("opa"), tmp / "policy"
    assert tools.run([opa, "check", "--strict", policy]).returncode == 0
    r = tools.run([opa, "test", policy, "-v"])
    assert r.returncode == 0, r.stdout + r.stderr
    bad, good = (row["decision"] for row in rows)
    assert not bad["allow"] and good["allow"]
    ids = {v["rule_id"] for v in bad["violations"]}
    assert ids == {r["id"] for r in rules.load()["rules"]} | {"REG-01", "REG-02"}
