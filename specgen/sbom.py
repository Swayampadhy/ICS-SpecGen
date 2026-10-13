"""SBOM: syft as the base, plus opkg/ipkg/dpkg package databases and version carving, merged."""
import json
import os
import posixpath
import re
import sys
from collections import Counter

from . import tools
from .unpack import listdir, read_text, real

STATUS_FILES = ["usr/lib/opkg/status", "var/lib/opkg/status", "usr/lib/ipkg/status", "var/lib/dpkg/status"]
# PTXdist (WAGO) images ship license.<package>_<version>.txt[.xz] for every built package; newer
# WAGO images drop the opkg database, so these files are the only complete inventory left
LICENSE_DIR = "usr/share/licenses/oss"
LICENSE_FILE = re.compile(r"^license\.(.+)_([^_]+?)\.txt(?:\.xz)?$")
LIB_ALIAS = {"libssl": "openssl", "libcrypto": "openssl", "libz": "zlib", "libc": "glibc", "libexpat": "expat"}
# package name -> NVD (vendor, product) where they differ from the package name
CPE_MAP = {
    "openssl": ("openssl", "openssl"), "busybox": ("busybox", "busybox"), "kernel": ("linux", "linux_kernel"),
    "linux": ("linux", "linux_kernel"), "openssh": ("openbsd", "openssh"), "dropbear": ("dropbear_ssh_project", "dropbear_ssh"),
    "lighttpd": ("lighttpd", "lighttpd"), "curl": ("haxx", "curl"), "libcurl": ("haxx", "curl"), "zlib": ("zlib", "zlib"),
    "glibc": ("gnu", "glibc"), "bash": ("gnu", "bash"), "sudo": ("sudo_project", "sudo"), "libxml2": ("xmlsoft", "libxml2"),
    "sqlite": ("sqlite", "sqlite"), "sqlite3": ("sqlite", "sqlite"), "php": ("php", "php"), "nginx": ("f5", "nginx"),
    "openvpn": ("openvpn", "openvpn"), "dnsmasq": ("thekelleys", "dnsmasq"), "net-snmp": ("net-snmp", "net-snmp"),
    "strongswan": ("strongswan", "strongswan"), "pure-ftpd": ("pureftpd", "pure-ftpd"), "expat": ("libexpat_project", "libexpat"),
    "libmodbus": ("libmodbus", "libmodbus"), "ntp": ("ntp", "ntp"), "dbus": ("freedesktop", "dbus"), "rauc": ("pengutronix", "rauc"),
    "php7": ("php", "php"), "php5": ("php", "php"), "pureftpd": ("pureftpd", "pure-ftpd"), "libxslt": ("xmlsoft", "libxslt"),
    "mosquitto": ("eclipse", "mosquitto"), "wpa-supplicant": ("w1.fi", "wpa_supplicant"), "libpcap": ("tcpdump", "libpcap"),
    "gzip": ("gnu", "gzip"), "screen": ("gnu", "screen"), "ncurses": ("gnu", "ncurses"), "glib": ("gnome", "glib"),
    "iptables": ("netfilter", "iptables"), "python3": ("python", "python"), "util-linux": ("kernel", "util-linux"),
    "util-linux-ng": ("kernel", "util-linux"), "ppp": ("point-to-point_protocol_project", "point-to-point_protocol"),
    "rpcbind": ("rpcbind_project", "rpcbind"), "nfsutils": ("linux-nfs", "nfs-utils"), "libtirpc": ("libtirpc_project", "libtirpc"),
    "e2fsprogs": ("e2fsprogs_project", "e2fsprogs"),
}
CARVE = [  # (component, ELF file name regex, version regex)
    ("busybox", re.compile(r"^busybox"), re.compile(rb"BusyBox v(\d+\.\d+\.\d+)")),
    ("openssl", re.compile(r"^(libcrypto\.so|libssl\.so|openssl$)"), re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)")),
    # the runtime glibc comes from the toolchain; PTXdist's "glibc" package version can be unrelated
    ("glibc", re.compile(r"^libc[-.]"), re.compile(rb"GNU C Library[^\n\0]*? version (\d+\.\d+)")),
]
# shortcut: static EOL list as of 2026-10; replace with endoflife.date data if this needs to stay current
EOL = [
    (r"^(openssl|libssl.*|libcrypto.*)$", r"^(0\.|1\.)", "OpenSSL 1.x is past end of life (1.1.1 ended 2023-09-11)"),
    (r"^(openssl|libssl.*|libcrypto.*)$", r"^3\.[0-3]\.", "OpenSSL 3.0-3.3 are past end of life (3.0 LTS ended 2026-09-07)"),
    (r"^(linux|kernel|linux-kernel)$", r"^([23]\.|4\.|5\.[0-9]\.)", "Linux kernels before 5.10 are past upstream end of life"),
    (r"^python(2(\.\d+)?)?$", r"^2\.", "Python 2 is past end of life (2020-01-01)"),
]


def cpe_version(v):
    return re.sub(r"^\d+:", "", v).split("-")[0].split("+")[0]


def component(name, version, source, kind="generic"):
    vendor, product = CPE_MAP.get(name.lower(), (name.lower(), name.lower()))
    is_os = product == "linux_kernel"
    purl = f"pkg:deb/debian/{name}@{version}" if kind == "deb" else f"pkg:generic/{name}@{version}"
    # not "operating-system": grype reads that type as distro info and would skip matching the kernel
    c = {"type": "application" if is_os else "library", "name": name, "version": version,
         "purl": purl, "properties": [{"name": "specgen:source", "value": source}]}
    if version:
        c["cpe"] = f"cpe:2.3:{'o' if is_os else 'a'}:{vendor}:{product}:{cpe_version(version)}:*:*:*:*:*:*:*"
    return c


def parse_status(text):
    """(package, version) for installed packages in an opkg/ipkg/dpkg status file."""
    for para in re.split(r"\n\s*\n", text):
        f = dict(re.findall(r"^([\w-]+):[ \t]*(.*?)\s*$", para, re.M))
        if f.get("Package") and f.get("Status", "installed").split()[-1] == "installed":
            yield f["Package"], f.get("Version", "")


def packages(root, links):
    """Components from package databases, and {package: owned file paths} from info/<pkg>.list."""
    comps, owned = [], {}
    for rel in STATUS_FILES:
        p = real(root, rel, links)
        if not p:
            continue
        kind, source = ("deb", "dpkg") if "dpkg" in rel else ("generic", rel.split("/")[-2])
        info = posixpath.join(posixpath.dirname(rel), "info")
        for name, version in parse_status(read_text(p, 64 << 20)):
            comps.append(component(name, version, source, kind))
            lst = real(root, f"{info}/{name}.list", links)
            if lst:
                owned[name] = {l.split("\t")[0].rstrip("/") for l in read_text(lst).splitlines() if l.strip()}
    return comps, owned


def license_files(root, links):
    return [component(m.group(1), m.group(2), "license-files")
            for n in listdir(root, LICENSE_DIR, links) if (m := LICENSE_FILE.match(n))]


def network_by_name(comps, daemons):
    """Fallback when no package owns files: match daemon names and linked library names to components."""
    stems = {posixpath.basename(d["path"]) for d in daemons} | {re.sub(r"\.so.*$", "", n) for d in daemons for n in d["needed"]}
    stems |= {LIB_ALIAS[s] for s in stems if s in LIB_ALIAS}
    return {c["name"] for c in comps if c["name"].lower() in stems or "lib" + c["name"].lower() in stems}


def carve(root, links, binaries):
    found = []
    for b in binaries:
        base = posixpath.basename(b["path"])
        for name, file_rx, ver_rx in CARVE:
            if file_rx.search(base):
                with open(os.path.join(root, b["path"].lstrip("/")), "rb") as f:
                    m = ver_rx.search(f.read())
                if m:
                    found.append(component(name, m.group(1).decode(), "carved"))
    for d in ("lib/modules", "usr/lib/modules"):
        found += [component("linux", v, "carved") for v in listdir(root, d, links) if re.match(r"^\d+\.\d+", v)]
    return found


def keys(c):
    k = {(c["name"].lower(), c.get("version", ""))}
    if c.get("cpe"):
        k.add(tuple(c["cpe"].split(":")[3:6]))
    return k


def source(c):
    return next((p["value"] for p in c.get("properties", []) if p["name"] == "specgen:source"), "syft")


def run(root, links, out, binaries):
    """Writes sbom.cdx.json (and the raw syft SBOM). Returns the evidence summary."""
    doc, syft = None, tools.find("syft")
    raw = out / "sbom.syft.cdx.json"
    if syft:
        r = tools.run([syft, "scan", f"dir:{root}", "-q", "-o", f"cyclonedx-json@1.5={raw}"])
        if r.returncode == 0 and raw.is_file():
            doc = json.loads(raw.read_text(encoding="utf-8"))
        else:  # a smaller SBOM means fewer CVEs: never let that pass silently
            print(f"WARNING: syft failed (exit {r.returncode}), SBOM uses the built-in sources only:\n"
                  f"{r.stderr[-1000:]}", file=sys.stderr)
    doc = doc or {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {}, "components": []}
    doc["specVersion"] = "1.5"
    # package-database entries go first: they carry mapped CPEs and purls, while syft reads opkg status
    # as "deb" without a purl (often twice) and with name:name CPEs (e.g. kernel:kernel)
    pkg_comps, owned = packages(root, links)
    # license files can be stale leftovers of older builds: only use them when no package database exists
    meta = pkg_comps or license_files(root, links)
    carved = carve(root, links, binaries)
    binary_truth = {c["name"] for c in carved}  # a version read from the binary beats package metadata
    comps, seen = [], set()
    for c in carved + meta + doc.get("components", []):
        if c.get("type") == "file":
            comps.append(c)
        elif c["name"] in binary_truth and source(c) != "carved":
            continue
        else:  # dedupe by (name, version) and by CPE vendor:product:version
            if not keys(c) & seen:
                comps.append(c)
            seen |= keys(c)  # a dropped duplicate's aliases (e.g. "kernel" for "linux") count as seen too
    doc["components"] = comps
    doc.pop("dependencies", None)  # syft's graph references components dropped above
    (out / "sbom.cdx.json").write_text(json.dumps(doc, indent=1), encoding="utf-8")

    daemons = [b for b in binaries if b.get("network")]
    net_files = {d["path"] for d in daemons}
    net_libs = {n for d in daemons for n in d["needed"]}
    real_comps = [c for c in comps if c.get("type") != "file"]
    network = sorted({pkg for pkg, files in owned.items()
                      if any(f in net_files or posixpath.basename(f) in net_libs for f in files)}
                     | network_by_name(real_comps, daemons))
    n = len(real_comps)
    ratio = lambda pred: round(sum(map(pred, real_comps)) / n, 4) if n else 0.0
    eol = sorted({(c["name"], c.get("version", ""), reason) for c in real_comps for nrx, vrx, reason in EOL
                  if re.match(nrx, c["name"].lower()) and re.match(vrx, c.get("version", ""))})
    return {
        "format": "CycloneDX-1.5", "components": n,
        "with_version": ratio(lambda c: bool(c.get("version"))),
        "with_cpe_or_purl": ratio(lambda c: bool(c.get("purl") or c.get("cpe"))),
        "identified": ratio(lambda c: bool(c.get("version")) and bool(c.get("purl") or c.get("cpe"))),
        "by_source": dict(sorted(Counter(source(c) for c in real_comps).items())),
        "eol_components": [{"name": a, "version": v, "reason": r} for a, v, r in eol],
        "network_components": network,
        "ref": "sbom.cdx.json",
    }
