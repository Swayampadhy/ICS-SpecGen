import zipfile

import pytest
from passlib.hash import md5_crypt, sha512_crypt

from specgen import config_audit, evidence, integrity, tools, unpack


def write(root, rel, text, mode="w"):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text) if mode == "w" else p.write_bytes(text)
    return p


def test_resolve_follows_dir_and_leaf_links():
    links = {"sbin": "usr/sbin", "usr/sbin/init": "../bin/busybox", "etc/os-release": "../usr/lib/os-release"}
    assert unpack.resolve("/sbin/init", links) == "usr/bin/busybox"
    assert unpack.resolve("etc/os-release", links) == "usr/lib/os-release"
    assert unpack.resolve("usr/bin/x", links) == "usr/bin/x"
    assert unpack.resolve("usr/bin/../sbin/x", {}) == "usr/sbin/x"


def test_resolve_never_leaves_the_rootfs():
    # hostile firmware: links that climb above the root or name a Windows drive stay inside the tree
    assert unpack.resolve("etc/passwd", {"etc/passwd": "../../../../Users/me/secret"}) == "Users/me/secret"
    assert unpack.resolve("etc/REVISIONS", {"etc": "C:/Users/me"}) == "Users/me/REVISIONS"


@pytest.mark.parametrize("name", ["..", ".", "a/b", "a\\b", "-x", ""])
def test_collect_rejects_unsafe_names_before_touching_disk(tmp_path, name):
    keep = write(tmp_path, "work/keep.txt", "x")
    with pytest.raises(SystemExit):
        evidence.collect(tmp_path / "fw.img", name, tmp_path / "out", tmp_path / "work")
    assert keep.exists() and not (tmp_path / "out").exists()


@pytest.mark.skipif(not tools.find("7z"), reason="7-Zip not installed")
def test_unpack_recurses_into_nested_containers_and_picks_rootfs(tmp_path):
    inner = tmp_path / "rootfs.zip"
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_STORED) as z:  # stored + 1 MiB pad: big enough to recurse into
        for rel in ("etc/passwd", "usr/bin/sh", "usr/lib/libc.so.6", "sbin/init", "pad.bin"):
            z.writestr(rel, b"\0" * (1 << 20) if rel == "pad.bin" else b"x")
    outer = tmp_path / "fw.zip"
    with zipfile.ZipFile(outer, "w") as z:
        z.write(inner, "images/rootfs.zip")
    manifest, root, links = unpack.unpack(outer, tmp_path / "work")
    assert manifest["rootfs"] == "L1" and root.endswith("L1") and links == {}
    assert [(l["depth"], l["rootfs_score"]) for l in manifest["layers"]] == [(0, 0), (1, 5)]
    assert len(manifest["hashes"]["sha256"]) == 64 and manifest["errors"] == []


def test_default_password_check_is_na_when_a_hash_cannot_be_verified():
    yescrypt = "$y$j9T$abcdefghijklmnop$0123456789abcdefghijklmnopqrstuvwxyzABCDE"
    assert config_audit.audit_passwords({"pi": yescrypt})[2] is None
    assert config_audit.audit_passwords({"pi": yescrypt, "root": sha512_crypt.hash("wago")})[2] == ["root"]


def test_config_audit(tmp_path):
    write(tmp_path, "etc/shadow", "\n".join([
        f"root:{sha512_crypt.hash('wago')}:0:0:99999:7:::",       # documented default
        f"admin:{md5_crypt.hash('S3cret-long')}:0:0:99999:7:::",   # weak hash
        "guest::0:0:99999:7:::",                                   # empty
        "www:!:0:0:99999:7:::",                                    # locked
    ]))
    write(tmp_path, "etc/inetd.conf", "telnet stream tcp nowait root /usr/sbin/telnetd telnetd\n"
                                      "#tftp dgram udp wait nobody /sbin/tftpd tftpd\n")
    write(tmp_path, "etc/rc.d/S50_pureftpd", "")  # failed-symlink placeholder; the name is what counts
    write(tmp_path, "etc/lighttpd/lighttpd.conf", 'var.http_port = 80\ninclude "mode.conf"\n')
    write(tmp_path, "etc/lighttpd/mode_http.conf", "server.port = http_port\n")
    write(tmp_path, "etc/lighttpd/mode_https.conf", 'server.port = 443\nurl.redirect = ("^/(.*)" => "https://%1/$1")\n')
    write(tmp_path, "usr/sbin/dropbear", "ELF")
    write(tmp_path, "etc/dropbear/dropbear.conf", "ROOT_LOGIN=true\nPASSWORD_LOGIN=false\n")
    write(tmp_path, "etc/dropbear/dropbear_rsa_host_key", b"\x00\x00\x00\x07ssh-rsa", "wb")
    write(tmp_path, "etc/ssl/private/server.key", "-----BEGIN RSA PRIVATE KEY-----\n" + "MIIEowIBAAKCAQEA" * 4 + "\n")
    write(tmp_path, "usr/bin/ssh-keygen", b"\x7fELF...-----BEGIN OPENSSH PRIVATE KEY-----\n\0-----END", "wb")

    cfg = config_audit.run(str(tmp_path), {"etc/lighttpd/mode.conf": "mode_http.conf"})
    assert (cfg["default_password_accounts"], cfg["weak_hash_accounts"], cfg["empty_password_accounts"]) == \
        (["root"], ["admin"], ["guest"])
    assert cfg["cleartext_services"] == ["ftpd", "http", "telnetd"]
    assert (cfg["ssh_server"], cfg["ssh_root_login"], cfg["ssh_password_auth"]) == ("dropbear", True, False)
    assert cfg["embedded_private_keys"] == ["/etc/dropbear/dropbear_rsa_host_key", "/etc/ssl/private/server.key"]

    https = config_audit.cleartext_services(str(tmp_path), {"etc/lighttpd/mode.conf": "mode_https.conf"})
    assert "http" not in https


def test_integrity_indicators(tmp_path):
    root, boot = tmp_path / "L1", tmp_path / "L0"
    write(root, "etc/rauc/system.conf", "[system]\ncompatible=x\n[keyring]\npath=ca.cert.pem\n")
    write(root, "usr/sbin/fwupdate.sh", "#!/bin/sh\nopenssl dgst -sha256 -verify pub.pem -signature f.sig f\n")
    write(boot, "u-boot.dtb", b"key-name-hint\0dev\0sha256,rsa2048\0", "wb")
    image = write(tmp_path, "fw.img", "image")
    write(tmp_path, "fw.img.sig", "sig")
    manifest, s = integrity.run(image, "0" * 64, str(root), [str(boot), str(root)], [])
    assert (s["image_signature"], s["verified_update_mechanism"], s["boot_integrity"]) == ("present",) * 3
    assert {i["type"] for i in s["signature_indicators"]} == \
        {"detached_signature", "rauc_keyring", "update_script_verify", "fit_signature"}
    assert "/etc/rauc/system.conf" in manifest["files"]

    _, none = integrity.run(tmp_path / "other.img", "0" * 64, str(boot), [], [])
    assert (none["image_signature"], none["verified_update_mechanism"], none["boot_integrity"]) == ("absent",) * 3

    write(tmp_path, "fw_v1.1.img.sig", "sig")  # belongs to another release: must not count for fw_v1.img
    _, other = integrity.run(tmp_path / "fw_v1.img", "0" * 64, str(boot), [], [])
    assert other["image_signature"] == "absent"
