import json

from specgen import sbom

STATUS = """Package: openssl
Version: 1.0.2q
Status: install user installed
Architecture: armhf

Package: lighttpd
Version: 1.4.53
Status: install user installed

Package: oldpkg
Version: 0.1
Status: purge ok not-installed

Package: kernel
Version: 4.9.115-rt93
Status: install user installed

Package: glibc
Version: 2.23
Status: install user installed
"""


def test_parse_status_skips_uninstalled():
    assert list(sbom.parse_status(STATUS)) == \
        [("openssl", "1.0.2q"), ("lighttpd", "1.4.53"), ("kernel", "4.9.115-rt93"), ("glibc", "2.23")]


def test_component_ids():
    c = sbom.component("kernel", "4.9.115-rt93", "opkg")
    assert c["cpe"] == "cpe:2.3:o:linux:linux_kernel:4.9.115:*:*:*:*:*:*:*" and c["type"] == "application"
    assert sbom.component("dropbear", "2018.76", "opkg")["cpe"].startswith("cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2018.76:")
    assert sbom.component("libssl1.1", "1.1.1n-0+deb11u3", "dpkg", "deb")["purl"] == "pkg:deb/debian/libssl1.1@1.1.1n-0+deb11u3"


def test_license_files_inventory(tmp_path):
    d = tmp_path / "usr" / "share" / "licenses" / "oss"
    d.mkdir(parents=True)
    for n in ("license.php-pam_2.2.4.txt", "license.lighttpd_1.4.67+wago1.txt.xz", "generic"):
        (d / n).write_text("x")
    comps = {c["name"]: c for c in sbom.license_files(str(tmp_path), {})}
    assert set(comps) == {"php-pam", "lighttpd"} and comps["lighttpd"]["version"] == "1.4.67+wago1"
    assert comps["lighttpd"]["cpe"].startswith("cpe:2.3:a:lighttpd:lighttpd:1.4.67:")


def test_run_merges_dedupes_and_maps_network_components(tmp_path, monkeypatch):
    syft_doc = {"components": [{"type": "library", "name": "kernel", "version": "4.9.115-rt93",
                                "cpe": "cpe:2.3:a:kernel:kernel:4.9.115:*:*:*:*:*:*:*"}]}

    def fake_syft(args, **kw):  # syft reports the kernel under its package name with a useless CPE
        (tmp_path / "sbom.syft.cdx.json").write_text(json.dumps(syft_doc))
        return type("R", (), {"returncode": 0})()
    monkeypatch.setattr(sbom.tools, "find", lambda name: "syft")
    monkeypatch.setattr(sbom.tools, "run", fake_syft)
    info = tmp_path / "var" / "lib" / "opkg" / "info"
    info.mkdir(parents=True)
    (info.parent / "status").write_text(STATUS)
    (info / "lighttpd.list").write_text("/usr/sbin/lighttpd\t0100755\n/etc/lighttpd/\t040755\n")
    (info / "openssl.list").write_text("/usr/lib/libssl.so.1.0.0\t0100644\n")
    (tmp_path / "usr" / "lib" / "modules" / "4.9.115-rt93").mkdir(parents=True)  # carved kernel = same CPE as opkg
    (tmp_path / "usr" / "lib" / "libc-2.30.so").write_bytes(b"\0GNU C Library (GNU libc) stable release version 2.30.\n")
    lic = tmp_path / "usr" / "share" / "licenses" / "oss"
    lic.mkdir(parents=True)
    (lic / "license.libcurl_7.59.0.txt").write_text("stale")  # ignored: the package database is authoritative
    binaries = [{"path": "/usr/sbin/lighttpd", "network": True, "needed": ["libssl.so.1.0.0"]},
                {"path": "/usr/lib/libc-2.30.so", "network": False, "needed": []}]
    s = sbom.run(str(tmp_path), {}, tmp_path, binaries)
    comps = json.loads((tmp_path / "sbom.cdx.json").read_text())["components"]
    assert [(c["name"], c["version"]) for c in comps] == \
        [("glibc", "2.30"), ("linux", "4.9.115-rt93"), ("openssl", "1.0.2q"), ("lighttpd", "1.4.53")]
    assert s["components"] == 4 and s["identified"] == 1.0 and s["by_source"] == {"carved": 2, "opkg": 2}
    assert s["network_components"] == ["lighttpd", "openssl"]
    assert {(e["name"], e["version"]) for e in s["eol_components"]} == {("openssl", "1.0.2q"), ("linux", "4.9.115-rt93")}
