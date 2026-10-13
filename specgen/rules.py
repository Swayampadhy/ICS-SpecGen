"""Ruleset loader and evaluator: evidence.json -> findings (PASS / FAIL / N/A with evidence pointers)."""
import yaml

from . import tools

RULESET = tools.ROOT / "rules" / "ruleset.yaml"
CHECK_KEYS = ("evidence", "op", "threshold", "value")


def is_num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


OPS = {  # op -> (applies to observed value?, passes?)
    ">=": (is_num, lambda x, e: x >= e),
    "<=": (is_num, lambda x, e: x <= e),
    "==": (lambda x: x is not None, lambda x, e: x == e),
    "in": (lambda x: x is not None, lambda x, e: x in e),
    "empty": (lambda x: isinstance(x, list), lambda x, e: not x),
    "not_empty": (lambda x: isinstance(x, list), lambda x, e: bool(x)),
}


def load(path=None, thresholds=None):
    with open(path or RULESET, encoding="utf-8") as f:
        rs = yaml.safe_load(f)
    if thresholds:
        with open(thresholds, encoding="utf-8") as f:
            rs["thresholds"].update(yaml.safe_load(f) or {})
    for r in rs["rules"]:
        r["checks"] = r.get("checks") or [{k: r[k] for k in CHECK_KEYS if k in r}]
    return rs


def lookup(doc, dotted):
    for k in dotted.split("."):
        if not isinstance(doc, dict) or k not in doc:
            return None
        doc = doc[k]
    return doc


def check(evidence, c, thresholds):
    x, op = lookup(evidence, c["evidence"]), c["op"]
    e = thresholds[c["threshold"]] if "threshold" in c else c.get("value")
    res = {"evidence_ref": "/" + c["evidence"].replace(".", "/"), "observed": x}
    if op == "all_true":
        bad = sorted(d.get("path", "?") for d in x or [] if not all(d.get(f) for f in e))
        res.update(expected=f"all have {', '.join(e)}", observed=bad,
                   status="N/A" if not isinstance(x, list) or not x else "FAIL" if bad else "PASS")
        return res
    applies, passes = OPS[op]
    res["expected"] = op if op in ("empty", "not_empty") else f"{op} {e}"
    res["status"] = "N/A" if not applies(x) else "PASS" if passes(x, e) else "FAIL"
    return res


def evaluate(evidence, ruleset):
    t = ruleset["thresholds"]
    findings = []
    for r in ruleset["rules"]:
        checks = [check(evidence, c, t) for c in r["checks"]]
        states = {c["status"] for c in checks}
        findings.append({
            "rule_id": r["id"], "category": r["category"], "severity": r["severity"],
            # a rule only passes when every check ran: a skipped check must not tick the box
            "status": "FAIL" if "FAIL" in states else "N/A" if "N/A" in states else "PASS",
            "checks": checks,
            "requirement": " ".join(r["requirement"].split()),
            "acceptance_test": r.get("acceptance_test", "").format(**t),
            "iec62443": r["iec62443"], "rationale": " ".join(r.get("rationale", "").split()),
        })
    summary = {s: sum(f["status"] == s for f in findings) for s in ("PASS", "FAIL", "N/A")}
    return {"target": evidence["target"]["name"], "ruleset_version": ruleset["version"],
            "thresholds": t, "summary": summary, "findings": findings}
