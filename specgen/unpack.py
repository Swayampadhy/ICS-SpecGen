"""Recursive firmware unpacking with 7-Zip, rootfs detection and filesystem helpers."""
import hashlib
import os
import posixpath
import shutil
import stat
from pathlib import Path

from . import tools

MAX_DEPTH = 4
MIN_CONTAINER = 1 << 20  # firmware containers are large; skips noise from small blobs
MAGIC = [  # (offset, signature, type) - detected by content, not by extension
    (0, b"PK\x03\x04", "zip"), (0, b"7z\xbc\xaf\x27\x1c", "7z"), (0, b"\x1f\x8b", "gzip"),
    (0, b"\xfd7zXZ\x00", "xz"), (0, b"hsqs", "squashfs"), (0, b"\x45\x3d\xcd\x28", "cramfs"),
    (257, b"ustar", "tar"), (1080, b"\x53\xef", "ext"), (510, b"\x55\xaa", "mbr/fat"),
]
INIT = ("sbin/init", "usr/sbin/init", "lib/systemd/systemd", "usr/lib/systemd/systemd")


def hashes(path, algos=("sha256", "sha512")):
    hs = [hashlib.new(a) for a in algos]
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            for h in hs:
                h.update(chunk)
    return {a: h.hexdigest() for a, h in zip(algos, hs)}


def kind(path):
    if os.path.getsize(path) < MIN_CONTAINER:
        return None
    with open(path, "rb") as f:
        head = f.read(1088)
    return next((t for off, sig, t in MAGIC if head[off:off + len(sig)] == sig), None)


def iter_files(root, sub=""):
    """Yield (posix path relative to root, absolute path) for every non-empty regular file under root/sub.

    Symlinks that 7-Zip could not create on Windows are left as empty files; skipping
    empty files skips them. Their targets live in the side table (see resolve)."""
    for dirpath, dirs, names in os.walk(os.path.join(root, sub)):
        dirs.sort()
        for n in sorted(names):
            p = os.path.join(dirpath, n)
            if os.path.isfile(p) and not os.path.islink(p) and os.path.getsize(p):
                yield os.path.relpath(p, root).replace(os.sep, "/"), p


def read_text(path, limit=1 << 20):
    with open(path, "rb") as f:
        return f.read(limit).decode("utf-8", "replace")


def resolve(rel, links, hops=16):
    """Resolve a rootfs-relative posix path through the symlink side table, component by component.

    Link targets come from untrusted firmware: ".." above the root and drive letters ("C:") are dropped,
    so a path always stays inside the extracted tree (like a chroot)."""
    # normpath from "/" collapses "a/../b" and clamps ".." at the root
    split = lambda path: [p for p in posixpath.normpath("/" + path).split("/") if p and ":" not in p]
    parts, i, cur = split(rel), 0, ""
    while i < len(parts):
        nxt = posixpath.join(cur, parts[i]) if cur else parts[i]
        if nxt in links and hops:
            hops -= 1
            t = links[nxt]
            base = "" if t.startswith("/") else posixpath.dirname(nxt)
            parts = split(posixpath.join(base, t.lstrip("/"))) + parts[i + 1:]
            i, cur = 0, ""
            continue
        cur, i = nxt, i + 1
    return cur


def real(root, rel, links):
    """Absolute path of a rootfs file after following side-table links, or None."""
    p = os.path.join(root, resolve(rel, links))
    return p if os.path.isfile(p) and os.path.getsize(p) else None


def listdir(root, rel, links):
    """Entry names of a rootfs directory, including symlinks that only exist in the side table."""
    d = resolve(rel, links)
    names = set(os.listdir(os.path.join(root, d))) if os.path.isdir(os.path.join(root, d)) else set()
    return sorted(names | {posixpath.basename(k) for k in links if posixpath.dirname(k) == d})


def symlinks(sevenzip, src):
    """Side table {path: target} of the symlinks inside an archive, from `7z l -slt`."""
    links, path = {}, None
    for line in tools.run([sevenzip, "l", "-slt", "-sccUTF-8", src]).stdout.splitlines():
        if line.startswith("Path = "):
            path = line[7:].replace("\\", "/")
        elif line.startswith("Symbolic Link = ") and line[16:] and path:
            links[path] = line[16:].replace("\\", "/")
    return links


def score(d, links):
    has = lambda rel: os.path.isdir(os.path.join(d, resolve(rel, links)))
    s = has("etc") + has("usr") + (has("bin") or has("usr/bin")) + (has("lib") or has("usr/lib"))
    return s + any(os.path.isfile(os.path.join(d, resolve(i, links))) or i in links for i in INIT)


def _force(func, path, _):
    os.chmod(path, stat.S_IWRITE)  # rootfs trees contain read-only files
    func(path)


def unpack(image, workdir):
    """Unpack image under workdir. Returns (manifest, rootfs path or None, rootfs symlink table)."""
    sevenzip = tools.find("7z")
    if not sevenzip:
        raise SystemExit("7z.exe not found: install 7-Zip or put 7z.exe in tools/bin")
    image, workdir = Path(image), Path(workdir)
    manifest = {"image": image.name, "hashes": hashes(image), "layers": [], "rootfs_candidates": [],
                "rootfs": None, "errors": []}
    if workdir.exists():
        shutil.rmtree(workdir, onerror=_force)
    queue, trees = [(image, 0, kind(image) or "raw")], []
    while queue:
        src, depth, typ = queue.pop(0)
        out = workdir / f"L{len(manifest['layers'])}"  # short names keep paths under MAX_PATH
        r = tools.run([sevenzip, "x", "-y", "-aou", "-sccUTF-8", f"-o{out}", src])
        links = symlinks(sevenzip, src)
        errs = [l for l in (r.stdout + r.stderr).splitlines() if l.startswith("ERROR:")]
        # symlink errors are expected without Developer Mode; the side table keeps their targets
        real_errs = [e for e in errs if "symbolic link" not in e and "Dangerous link" not in e]
        manifest["errors"] += [f"{src.name}: {e}" for e in real_errs[:20]]
        sc = score(out, links) if out.is_dir() else 0
        manifest["layers"].append({"source": str(src.relative_to(workdir)) if workdir in src.parents else src.name,
                                   "type": typ, "depth": depth, "out": out.name, "exit_code": r.returncode,
                                   "symlinks": len(links), "errors": len(real_errs), "rootfs_score": sc})
        if sc >= 4:  # a filesystem tree: analyse it, don't recurse into its contents
            trees.append((sc, sum(1 for _ in iter_files(out)), out, links))
        elif depth + 1 < MAX_DEPTH and out.is_dir():
            queue += [(Path(p), depth + 1, k) for _, p in iter_files(out) if (k := kind(p))]
    trees.sort(key=lambda t: (t[0], t[1]), reverse=True)
    manifest["rootfs_candidates"] = [{"layer": t[2].name, "score": t[0], "files": t[1]} for t in trees]
    if not trees:
        return manifest, None, {}
    manifest["rootfs"] = trees[0][2].name
    return manifest, str(trees[0][2]), trees[0][3]
