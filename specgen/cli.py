"""specgen command line: doctor | collect | evaluate | generate | run | gate."""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

from . import evidence, render, rules, tools, vulns

DEFAULT_KEV = tools.ROOT / "tools" / "kev.json"
FALLBACK = {"7z": "none - unpacking is impossible", "syft": "opkg/dpkg parser + version carving only",
            "grype": "CVE rules become N/A", "opa": "gate decisions are not evaluated"}


def doctor(_):
    ok = True
    for name in ("7z", "syft", "grype", "opa"):
        exe = tools.find(name)
        ok &= bool(exe)
        print(f"  {name:6} {'OK  ' + tools.version(name) + '  ' + exe if exe else 'MISSING -> ' + FALLBACK[name]}")
    built = vulns.db_built()
    print(f"  grype DB built: {built or 'no database - run: grype db update'}")
    print(f"  KEV catalog: {DEFAULT_KEV if DEFAULT_KEV.is_file() else 'missing - KEV check becomes N/A'}")
    for mod in ("elftools", "yaml", "jinja2", "jsonschema", "passlib"):
        found = importlib.util.find_spec(mod) is not None
        ok &= found
        print(f"  python:{mod:10} {'OK' if found else 'MISSING - pip install -r requirements.txt'}")
    return 0 if ok and built else 1


def collect_args(p):
    p.add_argument("--out", default="out", help="output root (default: out)")
    p.add_argument("--work", default="work", help="extraction scratch root; use a short path such as C:\\sg\\work")
    p.add_argument("--kev", default=str(DEFAULT_KEV) if DEFAULT_KEV.is_file() else None, help="CISA KEV JSON")
    p.add_argument("--vendor", default="")
    p.add_argument("--product", default="")


def collect(a):
    evidence.collect(a.image, a.name, a.out, a.work, a.signature, a.kev, a.vendor, a.product)
    return 0


def evaluate_one(evidence_path, ruleset):
    ev = json.loads(Path(evidence_path).read_text(encoding="utf-8"))
    evidence.validate(ev)
    fd = rules.evaluate(ev, ruleset)
    evidence.write(Path(evidence_path).parent / "findings.json", fd)
    return ev, fd


def evaluate(a):
    _, fd = evaluate_one(a.evidence, rules.load(thresholds=a.thresholds))
    for f in fd["findings"]:
        print(f"  {f['rule_id']:6} {f['status']:5} {f['severity']}")
    print(f"  {fd['summary']}")
    return 0


def generate(a):
    ruleset = rules.load(thresholds=a.thresholds)
    targets = []
    for t in a.targets:
        path = Path(t) / "evidence.json"
        ev, fd = evaluate_one(path, ruleset)
        targets.append((ev, fd, path))
    for row in render.generate(targets, ruleset, a.baseline, a.out, a.policy):
        d = row["decision"]
        verdict = "n/a (opa missing)" if d is None else "ALLOW" if d["allow"] else f"DENY ({len(d['violations'])} violations)"
        print(f"  {row['ev']['target']['name']:16} {row['fd']['summary']}  gate: {verdict}")
    print(f"  wrote {Path(a.out) / 'acceptance_report.md'}, {Path(a.policy) / 'gate_data.json'}, <target>/procurement_checklist.md")
    return 0


def run(a):
    names = a.names or [Path(i).stem for i in a.images]
    if len(names) != len(a.images):
        raise SystemExit("--names needs one name per image")
    for image, name in zip(a.images, names):
        evidence.collect(image, name, a.out, a.work, None, a.kev, a.vendor, a.product)
    a.targets = [str(Path(a.out) / n) for n in names]
    return generate(a)


def gate(a):
    d = render.gate(a.evidence, a.policy)
    if d is None:
        raise SystemExit("opa not found: put opa.exe in tools/bin or on PATH")
    print(json.dumps(d, indent=2))
    return 0 if d["allow"] else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="specgen", description="Evidence-driven supply-chain requirements for PLC firmware")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor", help="check external tools and fallbacks").set_defaults(fn=doctor)
    c = sub.add_parser("collect", help="unpack an image and collect evidence.json")
    c.add_argument("image")
    c.add_argument("--name", required=True)
    c.add_argument("--signature", help="detached vendor signature for the image, if one was published")
    collect_args(c)
    c.set_defaults(fn=collect)
    e = sub.add_parser("evaluate", help="apply the ruleset to evidence.json -> findings.json")
    e.add_argument("evidence")
    e.add_argument("--thresholds", help="YAML file overriding ruleset thresholds")
    e.set_defaults(fn=evaluate)
    g = sub.add_parser("generate", help="write checklist, Rego gate data and acceptance report")
    g.add_argument("--targets", nargs="+", required=True, help="out/<name> directories")
    g.add_argument("--baseline", help="name of the accepted baseline target")
    g.add_argument("--thresholds")
    g.add_argument("--out", default="out")
    g.add_argument("--policy", default="policy")
    g.set_defaults(fn=generate)
    r = sub.add_parser("run", help="collect + evaluate + generate for several images")
    r.add_argument("images", nargs="+")
    r.add_argument("--names", nargs="+")
    r.add_argument("--baseline")
    r.add_argument("--thresholds")
    r.add_argument("--policy", default="policy")
    collect_args(r)
    r.set_defaults(fn=run)
    gt = sub.add_parser("gate", help="evaluate the OPA gate; exit 0 = allow, 1 = deny")
    gt.add_argument("evidence")
    gt.add_argument("--policy", default="policy")
    gt.set_defaults(fn=gate)
    a = p.parse_args(argv)
    sys.exit(a.fn(a))
