"""Digest manifest and heuristic signature / verified-update / boot-integrity indicators."""
import os
import re
from pathlib import Path

from .unpack import hashes, iter_files, read_text

SIG_EXT = (".sig", ".asc", ".p7s", ".sign")
UPDATE_PATH = re.compile(r"(?i)update|upgrade|fwup|firmware|rauc|swu")
VERIFY = re.compile(r"openssl\s+(?:dgst|smime|cms)\b[^\n]*-verify|\bgpgv\b|gpg2?\s[^\n]*--verify|signify\s+-V|minisign\s+-V")
BOOT_FILE = re.compile(r"(?i)\.(itb|fit|dtb)$|u-?boot|barebox|^(mlo|boot\.bin)$")
FIT_SIG = re.compile(rb"(sha1|sha256|sha384|sha512),(rsa\d+|ecdsa\d+)")
CMDLINE_FILE = re.compile(r"(?i)cmdline|uenv|boot\.scr|extlinux|loader/entries/|grub\.cfg")
CMDLINE_IND = re.compile(r"dm-verity|dm-mod\.create|\bverity\b|ima_appraise|ima_policy|module\.sig_enforce")


def sha256(path):
    return hashes(path, ("sha256",))["sha256"]


def run(image, image_sha256, root, layers, binaries, signature=None):
    """layers: extracted layer dirs (rootfs and e.g. the boot partition). Returns (manifest, summary)."""
    image = Path(image)
    files = {b["path"]: sha256(os.path.join(root, b["path"].lstrip("/"))) for b in binaries}
    files.update({"/" + rel: sha256(p) for rel, p in iter_files(root, "etc")})
    manifest = {"image": {"file": image.name, "sha256": image_sha256}, "files": dict(sorted(files.items()))}

    ind = []  # (indicator class, type, path, detail)
    sigs = [Path(signature)] if signature else []
    # exact names only: a prefix match would credit fw_v1.img with fw_v1.1.img.sig
    sigs += [image.with_name(image.name + e) for e in SIG_EXT] + [image.with_suffix(e) for e in SIG_EXT]
    ind += [("image", "detached_signature", p.name, "signature file next to the image") for p in sigs if p.is_file()]

    for rel, p in iter_files(root, "etc"):
        text = read_text(p) if os.path.getsize(p) < 1 << 20 else ""
        if rel.startswith("etc/rauc/") and "[keyring]" in text:
            ind.append(("update", "rauc_keyring", "/" + rel, "RAUC verifies bundle signatures against a keyring"))
        elif "swupdate" in rel and ("public-key" in text or rel.endswith(".pem")):
            ind.append(("update", "swupdate_key", "/" + rel, "SWUpdate public key / signed images"))
        elif rel.startswith("etc/opkg") and re.search(r"option\s+check_signature\s+1", text):
            ind.append(("update", "opkg_check_signature", "/" + rel, "opkg verifies package feed signatures"))
        elif rel.startswith("etc/ima/"):
            ind.append(("boot", "ima_policy", "/" + rel, "IMA/EVM policy present"))
    for rel, p in iter_files(root):
        if UPDATE_PATH.search(rel) and os.path.getsize(p) < 1 << 20:
            with open(p, "rb") as f:
                is_script = f.read(2) == b"#!"
            if is_script and (m := VERIFY.search(read_text(p))):
                ind.append(("update", "update_script_verify", "/" + rel, m.group(0)[:80]))
        if rel.endswith("/veritysetup"):
            ind.append(("boot", "dm_verity_tool", "/" + rel, "veritysetup present"))

    for layer in layers:
        for rel, p in iter_files(layer):
            name = rel.rsplit("/", 1)[-1]
            if BOOT_FILE.search(name) and os.path.getsize(p) < 64 << 20:
                with open(p, "rb") as f:
                    data = f.read()
                # key-name-hint only exists in real key/signature nodes, not in code that merely supports them
                if b"key-name-hint" in data and (m := FIT_SIG.search(data)):
                    ind.append(("boot", "fit_signature", f"{Path(layer).name}/{rel}", m.group(0).decode()))
            elif CMDLINE_FILE.search(rel) and os.path.getsize(p) < 1 << 20 and (m := CMDLINE_IND.search(read_text(p))):
                ind.append(("boot", "kernel_cmdline", f"{Path(layer).name}/{rel}", m.group(0)))

    ind = sorted(set(ind))
    present = lambda cls: "present" if any(i[0] == cls for i in ind) else "absent"
    return manifest, {
        "manifest_ref": "integrity_manifest.json", "manifest_entries": len(files),
        "image_sha256": image_sha256,
        "image_signature": present("image"),
        "verified_update_mechanism": present("update"),
        "boot_integrity": present("boot"),
        "signature_indicators": [{"class": c, "type": t, "path": p, "detail": d} for c, t, p, d in ind],
    }
