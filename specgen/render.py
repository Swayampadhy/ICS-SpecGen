"""Outputs: gate_data.json for the Rego gate, procurement checklists and the acceptance report."""
import json
import shutil
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from . import __version__, tools

POLICY_SRC = tools.ROOT / "policy"
CATEGORIES = {"memory_safety": "A. Memory-safety hardening", "dependency_hygiene": "B. Dependency hygiene",
              "crypto_integrity": "C. Cryptographic integrity", "secure_defaults": "D. Secure defaults"}


def gate_data(ruleset, baseline=None):
    rules = [{"id": r["id"], "category": r["category"], "severity": r["severity"], "iec62443": r["iec62443"],
              "checks": [{"evidence": c["evidence"], "path": c["evidence"].split("."),
                          "evidence_ref": "/" + c["evidence"].replace(".", "/"), "op": c["op"],
                          **({"threshold": c["threshold"]} if "threshold" in c else {"value": c.get("value", "")})}
                         for c in r["checks"]]}
             for r in ruleset["rules"]]
    base = {}
    if baseline:
        base = {"name": baseline["target"]["name"], "hardening": {"ratios": baseline["hardening"]["ratios"]},
                "vulns": {"critical": baseline["vulns"]["critical"]}}
    return {"icsspecgen": {"thresholds": ruleset["thresholds"], "rules": rules, "baseline": base}}


def gate(evidence_path, policy_dir):
    """OPA decision {allow, violations} for one evidence.json, or None if opa is not installed."""
    opa = tools.find("opa")
    if not opa:
        return None
    policy_dir = Path(policy_dir)
    r = tools.run([opa, "eval", "-f", "json", "-d", policy_dir / "gate_policy.rego", "-d", policy_dir / "gate_data.json",
                   "-i", evidence_path, "data.icsspecgen.gate.decision"])
    if r.returncode != 0:
        raise SystemExit(f"opa eval failed:\n{r.stderr}")
    d = json.loads(r.stdout)["result"][0]["expressions"][0]["value"]
    d["violations"] = sorted(d["violations"], key=lambda v: (v["rule_id"], v["msg"]))
    return d


def fmt(x):
    if isinstance(x, float):
        return f"{x:.4g}"  # ratios like 0.0365 vs 0.0534 must stay distinguishable
    if isinstance(x, list):
        return ", ".join(map(str, x[:8])) + (f" (+{len(x) - 8} more)" if len(x) > 8 else "") if x else "none"
    return "n/a" if x is None else str(x)


def env():
    e = Environment(loader=FileSystemLoader(tools.ROOT / "templates"), undefined=StrictUndefined,
                    trim_blocks=True, lstrip_blocks=True, keep_trailing_newline=True)
    e.filters["fmt"] = fmt
    return e


def generate(targets, ruleset, baseline=None, out="out", policy="policy"):
    """targets: list of (evidence dict, findings dict, evidence path). Writes every output."""
    out, policy = Path(out), Path(policy)
    out.mkdir(parents=True, exist_ok=True)
    policy.mkdir(parents=True, exist_ok=True)
    if policy.resolve() != POLICY_SRC.resolve():  # make a self-contained policy bundle elsewhere
        for f in POLICY_SRC.glob("*.rego"):
            shutil.copy(f, policy)
    base = next((ev for ev, _, _ in targets if ev["target"]["name"] == baseline), None)
    if baseline and not base:
        raise SystemExit(f"baseline {baseline!r} is not among the targets")
    (policy / "gate_data.json").write_text(json.dumps(gate_data(ruleset, base), indent=2), encoding="utf-8")

    e, rows = env(), []
    for ev, fd, path in targets:
        rows.append({"ev": ev, "fd": fd, "decision": gate(path, policy)})
        (Path(path).parent / "procurement_checklist.md").write_text(
            e.get_template("procurement_checklist.md.j2").render(ev=ev, fd=fd, categories=CATEGORIES, version=__version__),
            encoding="utf-8")
    (out / "acceptance_report.md").write_text(
        e.get_template("acceptance_report.md.j2").render(rows=rows, ruleset=ruleset, baseline=baseline,
                                                          categories=CATEGORIES, version=__version__),
        encoding="utf-8")
    return rows
