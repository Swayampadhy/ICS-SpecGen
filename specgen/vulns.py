"""CVE matching with grype, normalised, with CISA KEV tagging."""
import json
from collections import Counter

from . import tools

SEVERITIES = ("critical", "high", "medium", "low", "negligible", "unknown")


def load_kev(path):
    if not path:
        return None
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    return {v["cveID"] for v in d["vulnerabilities"]}, d.get("catalogVersion")


def db_built():
    grype = tools.find("grype")
    r = tools.run([grype, "db", "status", "-o", "json"]) if grype else None
    return json.loads(r.stdout).get("built") if r and r.returncode == 0 else None


def normalise(grype_doc, network_components, kev):
    matches = {}
    for m in grype_doc.get("matches", []):
        v, a = m["vulnerability"], m["artifact"]
        ids = [v["id"]] + [x["id"] for x in m.get("relatedVulnerabilities", [])]
        cve = next((i for i in ids if i.startswith("CVE-")), v["id"])
        key = (cve, a["name"], a["version"])
        if key in matches:  # same CVE reached through several advisories (NVD, GHSA, distro)
            continue
        scores = [c.get("metrics", {}).get("baseScore") for c in v.get("cvss", [])]
        matches[key] = {
            "cve": cve, "id": v["id"], "component": a["name"], "version": a["version"],
            "severity": (v.get("severity") or "unknown").lower(),
            "cvss": max((s for s in scores if s is not None), default=None),
            "fix_version": (v.get("fix", {}).get("versions") or [None])[0],
            "source": v.get("dataSource"),
            "kev": bool(kev) and cve in kev[0],
            "network_facing": a["name"] in network_components,
        }
    rank = lambda m: (SEVERITIES.index(m["severity"]) if m["severity"] in SEVERITIES else 9, m["component"], m["cve"])
    return sorted(matches.values(), key=rank)


def run(sbom_path, network_components, kev_path):
    """Returns (vulns.json document, evidence summary). Counts are None (N/A) when grype is unavailable."""
    grype, kev = tools.find("grype"), load_kev(kev_path)
    r = tools.run([grype, f"sbom:{sbom_path}", "-o", "json", "-q"]) if grype else None
    ok = r is not None and r.returncode == 0
    ms = normalise(json.loads(r.stdout), set(network_components), kev) if ok else []
    sev = Counter(m["severity"] for m in ms)
    summary = {
        **{s: sev.get(s, 0) if ok else None for s in SEVERITIES},
        "kev": len({m["cve"] for m in ms if m["kev"]}) if ok and kev else None,
        "network_facing_critical_high": sum(m["network_facing"] and m["severity"] in ("critical", "high")
                                            for m in ms) if ok else None,
        "top_components": [{"component": c, "version": v, "cves": n}
                           for (c, v), n in Counter((m["component"], m["version"]) for m in ms).most_common(10)],
        "kev_hits": [{"cve": c, "component": p} for c, p in sorted({(m["cve"], m["component"]) for m in ms if m["kev"]})],
        "kev_catalog": kev[1] if kev else None,
        "ref": "vulns.json",
    }
    error = None if ok else ("grype not found" if not grype else r.stderr[-2000:])
    return {"error": error, "matches": ms}, summary
