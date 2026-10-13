import json

from specgen import vulns

GRYPE = {"matches": [
    {"vulnerability": {"id": "GHSA-aaaa", "severity": "High", "cvss": [{"metrics": {"baseScore": 7.5}}],
                       "fix": {"versions": ["1.1.1"]}, "dataSource": "ghsa"},
     "relatedVulnerabilities": [{"id": "CVE-2024-0001"}], "artifact": {"name": "openssl", "version": "1.0.2q"}},
    # same CVE again through NVD: must count once
    {"vulnerability": {"id": "CVE-2024-0001", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.0.2q"}},
    {"vulnerability": {"id": "CVE-2021-3156", "severity": "Critical"}, "artifact": {"name": "sudo", "version": "1.8.27"}},
]}
KEV = ({"CVE-2021-3156"}, "2026.10.08")


def test_normalise_dedupes_and_tags():
    ms = vulns.normalise(GRYPE, {"openssl"}, KEV)
    assert [(m["cve"], m["severity"], m["kev"], m["network_facing"]) for m in ms] == \
        [("CVE-2021-3156", "critical", True, False), ("CVE-2024-0001", "high", False, True)]
    assert (ms[1]["cvss"], ms[1]["fix_version"], ms[1]["id"]) == (7.5, "1.1.1", "GHSA-aaaa")


def test_run_summary_and_missing_grype(tmp_path, monkeypatch):
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"catalogVersion": "2026.10.08", "vulnerabilities": [{"cveID": "CVE-2021-3156"}]}))
    monkeypatch.setattr(vulns.tools, "find", lambda name: "grype")
    monkeypatch.setattr(vulns.tools, "run", lambda args, **kw: type("R", (), {"returncode": 0, "stdout": json.dumps(GRYPE)})())
    _, s = vulns.run("sbom.json", ["openssl"], kev)
    assert (s["critical"], s["high"], s["kev"], s["network_facing_critical_high"]) == (1, 1, 1, 1)

    monkeypatch.setattr(vulns.tools, "find", lambda name: None)  # no grype: counts are N/A, not zero
    doc, s = vulns.run("sbom.json", [], None)
    assert (s["critical"], s["kev"], doc["error"]) == (None, None, "grype not found")
