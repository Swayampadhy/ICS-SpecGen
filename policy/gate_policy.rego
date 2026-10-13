package icsspecgen.gate

# input          = evidence.json of the candidate firmware
# data.icsspecgen = gate_data.json {thresholds, rules, baseline}, written by `specgen generate`
#
# The logic is generic: it interprets the checks of rules/ruleset.yaml carried in gate_data.json,
# so new thresholds, rules or a new accepted baseline mean new data, not a new policy.
# Missing or null evidence never produces a violation (it is N/A, as in findings.json).

default allow := false

allow if count(violations) == 0

t := data.icsspecgen.thresholds

b := data.icsspecgen.baseline

expected(c) := t[c.threshold] if c.threshold

expected(c) := c.value if not c.threshold

fails(op, x, e) if {
	op == ">="
	is_number(x)
	x < e
}

fails(op, x, e) if {
	op == "<="
	is_number(x)
	x > e
}

fails(op, x, e) if {
	op == "=="
	x != null
	x != e
}

fails(op, x, e) if {
	op == "in"
	x != null
	not x in e
}

fails(op, x, _) if {
	op == "empty"
	is_array(x)
	count(x) > 0
}

fails(op, x, _) if {
	op == "not_empty"
	is_array(x)
	count(x) == 0
}

ops := {">=", "<=", "==", "in", "empty", "not_empty", "all_true"}

valid(c) if {
	c.op in ops
	object.get(c, "threshold", null) == null
}

valid(c) if {
	c.op in ops
	_ = t[c.threshold]
}

# --- fail closed: a typo in gate_data.json must deny, not silently switch a rule off
violations contains v if {
	some r in data.icsspecgen.rules
	some c in r.checks
	not valid(c)
	v := {
		"rule_id": "CFG-01",
		"iec62443_refs": r.iec62443,
		"evidence_ref": c.evidence_ref,
		"msg": sprintf("rule %s: unknown operator %v or threshold %v in gate_data.json", [r.id, c.op, object.get(c, "threshold", null)]),
	}
}

refs(id) := r.iec62443 if {
	some r in data.icsspecgen.rules
	r.id == id
}

violations contains v if {
	some r in data.icsspecgen.rules
	some c in r.checks
	c.op != "all_true"
	x := object.get(input, c.path, null)
	fails(c.op, x, expected(c))
	v := {
		"rule_id": r.id,
		"iec62443_refs": r.iec62443,
		"evidence_ref": c.evidence_ref,
		"msg": sprintf("%s = %v, required %s %v", [c.evidence, x, c.op, expected(c)]),
	}
}

violations contains v if {
	some r in data.icsspecgen.rules
	some c in r.checks
	c.op == "all_true"
	some d in object.get(input, c.path, [])
	some f in c.value
	not d[f]
	v := {
		"rule_id": r.id,
		"iec62443_refs": r.iec62443,
		"evidence_ref": c.evidence_ref,
		"msg": sprintf("network daemon %s lacks %s", [d.path, f]),
	}
}

# --- no-regression: a candidate update must not be worse than the accepted baseline
violations contains v if {
	some k in ["canary", "pie", "relro_full", "nx"]
	x := input.hardening.ratios[k]
	base := b.hardening.ratios[k]
	is_number(x)
	is_number(base)
	x < base
	v := {
		"rule_id": "REG-01",
		"iec62443_refs": refs("MS-01"),
		"evidence_ref": sprintf("/hardening/ratios/%s", [k]),
		"msg": sprintf("regression in %s: %.4f < baseline %s %.4f", [k, x, b.name, base]),
	}
}

violations contains v if {
	is_number(input.vulns.critical)
	is_number(b.vulns.critical)
	input.vulns.critical > b.vulns.critical
	v := {
		"rule_id": "REG-02",
		"iec62443_refs": refs("DH-02"),
		"evidence_ref": "/vulns/critical",
		"msg": sprintf("%d critical CVEs, more than baseline %s (%d)", [input.vulns.critical, b.name, b.vulns.critical]),
	}
}

decision := {"allow": allow, "violations": violations}
