"""Run every evidence module on one image and assemble the normalized, schema-validated evidence.json."""
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from . import __version__, config_audit, hardening, integrity, sbom, tools, unpack, vulns

SCHEMA = tools.ROOT / "schemas" / "evidence.schema.json"


def write(path, doc):
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")


def validate(doc):
    jsonschema.validate(doc, json.loads(SCHEMA.read_text(encoding="utf-8")))


def firmware_version(root, links):
    for rel, rx in (("etc/REVISIONS", r"FIRMWARE=(\S+)"), ("etc/os-release", r'PRETTY_NAME="?([^"\n]+)'),
                    ("etc/debian_version", r"(\S+)")):
        p = unpack.real(root, rel, links)
        if p and (m := re.search(rx, unpack.read_text(p))):
            return m.group(1)
    return "unknown"


def collect(image, name, out_root="out", work_root="work", signature=None, kev=None, vendor="", product=""):
    # the name becomes a folder that unpack() deletes first: "..", "." or "a/b" would delete outside work_root
    if not re.fullmatch(r"\w[\w.-]*", name):
        raise SystemExit(f"invalid name {name!r}: use letters, digits, '.', '-' or '_'")
    t0 = time.time()
    out = Path(out_root) / name
    out.mkdir(parents=True, exist_ok=True)
    work = Path(work_root) / name
    print(f"[{name}] unpacking {Path(image).name}")
    manifest, root, links = unpack.unpack(image, work)
    write(out / "unpack_manifest.json", manifest)
    write(out / "symlinks.json", dict(sorted(links.items())))
    if not root:
        raise SystemExit(f"[{name}] no Linux root filesystem found; see {out / 'unpack_manifest.json'}")
    print(f"[{name}] hardening")
    hard_doc, hard = hardening.run(root, links)
    write(out / "hardening.json", hard_doc)
    print(f"[{name}] sbom")
    sb = sbom.run(root, links, out, hard_doc["binaries"])
    print(f"[{name}] vulns")
    vul_doc, vul = vulns.run(out / "sbom.cdx.json", sb["network_components"], kev)
    write(out / "vulns.json", vul_doc)
    print(f"[{name}] integrity + config")
    layers = [str(work / l["out"]) for l in manifest["layers"] if (work / l["out"]).is_dir()]
    man, integ = integrity.run(image, manifest["hashes"]["sha256"], root, layers, hard_doc["binaries"], signature)
    write(out / "integrity_manifest.json", man)
    write(out / "integrity.json", integ)
    cfg = config_audit.run(root, links)
    write(out / "config.json", cfg)
    doc = {
        "schema_version": "1.0",
        "target": {
            "name": name, "vendor": vendor, "product": product, "version": firmware_version(root, links),
            "image_file": Path(image).name, "image_sha256": manifest["hashes"]["sha256"],
            "image_sha512": manifest["hashes"]["sha512"], "rootfs_layer": manifest["rootfs"],
            "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "collect_seconds": round(time.time() - t0, 1), "specgen_version": __version__,
            "tools": {"7z": tools.version("7z"), "syft": tools.version("syft"), "grype": tools.version("grype"),
                      "grype_db_built": vulns.db_built()},
        },
        "hardening": hard, "sbom": sb, "vulns": vul, "integrity": integ, "config": cfg,
    }
    validate(doc)
    write(out / "evidence.json", doc)
    print(f"[{name}] evidence -> {out / 'evidence.json'} ({doc['target']['collect_seconds']} s)")
    return out / "evidence.json"
