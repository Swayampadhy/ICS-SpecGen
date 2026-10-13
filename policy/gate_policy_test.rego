package icsspecgen.gate_test

# Run after `specgen generate` (needs gate_data.json in the same directory): opa test policy -v

import data.icsspecgen.gate

daemon_ok := {"path": "/usr/bin/goodd", "canary": true, "nx": true, "pie": true, "relro_full": true}

good := {
	"hardening": {
		"ratios": {"canary": 1, "nx": 1, "pie": 1, "relro_full": 1, "relro_partial": 0, "fortify": 1},
		"network_daemons": [daemon_ok],
	},
	"sbom": {"identified": 1, "eol_components": []},
	"vulns": {"critical": 0, "high": 0, "kev": 0, "network_facing_critical_high": 0},
	"integrity": {"image_signature": "present", "verified_update_mechanism": "present", "boot_integrity": "present"},
	"config": {
		"cleartext_services": [], "empty_password_accounts": [], "weak_hash_accounts": [],
		"default_password_accounts": [], "embedded_private_keys": [],
	},
}

bad := {
	"hardening": {
		"ratios": {"canary": 0.3, "nx": 0.9, "pie": 0.1, "relro_full": 0, "relro_partial": 0.9, "fortify": 0.2},
		"network_daemons": [{"path": "/usr/bin/iocheckd", "canary": false, "nx": true, "pie": false, "relro_full": false}],
	},
	"sbom": {"identified": 0.5, "eol_components": [{"name": "openssl", "version": "1.0.2q", "reason": "EOL"}]},
	"vulns": {"critical": 12, "high": 50, "kev": 3, "network_facing_critical_high": 9},
	"integrity": {"image_signature": "absent", "verified_update_mechanism": "absent", "boot_integrity": "absent"},
	"config": {
		"cleartext_services": ["telnetd"], "empty_password_accounts": [], "weak_hash_accounts": ["admin"],
		"default_password_accounts": ["root"], "embedded_private_keys": ["/etc/dropbear/dropbear_rsa_host_key"],
	},
}

baseline := {"name": "base", "hardening": {"ratios": {"canary": 1, "pie": 1, "relro_full": 1, "nx": 1}}, "vulns": {"critical": 0}}

test_good_allowed if {
	gate.allow with input as good with data.icsspecgen.baseline as {}
}

test_bad_denied if {
	not gate.allow with input as bad with data.icsspecgen.baseline as {}
}

test_bad_violates_every_rule if {
	vs := gate.violations with input as bad with data.icsspecgen.baseline as {}
	{v.rule_id | some v in vs} == {r.id | some r in data.icsspecgen.rules}
}

test_violations_are_traceable if {
	vs := gate.violations with input as bad with data.icsspecgen.baseline as baseline
	every v in vs {
		v.rule_id
		count(v.iec62443_refs) > 0
		startswith(v.evidence_ref, "/")
	}
}

test_missing_evidence_is_not_a_violation if {
	gate.allow with input as object.remove(good, ["vulns"]) with data.icsspecgen.baseline as {}
}

test_unknown_threshold_fails_closed if {
	vs := gate.violations with input as good with data.icsspecgen.baseline as {} with data.icsspecgen.thresholds as {}
	{v.rule_id | some v in vs} == {"CFG-01"}
}

test_downgrade_blocked_by_regression_rule if {
	worse := object.union(good, {"hardening": {"ratios": {"canary": 0.95, "nx": 1, "pie": 1, "relro_full": 1}}})
	vs := gate.violations with input as worse with data.icsspecgen.baseline as baseline
	{v.rule_id | some v in vs} == {"REG-01"}
}
