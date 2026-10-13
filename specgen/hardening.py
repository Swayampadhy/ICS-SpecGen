"""ELF hardening checks with pyelftools (our own checksec), per-binary and aggregated."""
import os
import re

from elftools.elf.constants import P_FLAGS
from elftools.elf.elffile import ELFFile

from .unpack import iter_files, read_text, real, resolve

DF_BIND_NOW, DF_1_NOW, DF_1_PIE = 0x8, 0x1, 0x08000000
CANARY = {"__stack_chk_fail", "__stack_chk_guard"}  # ARM toolchains often only reference the guard
FORTIFY = re.compile(r"^__\w+_chk$")
# server-side socket APIs; `bind` alone is left out because netlink tools (ip, tc, udevadm) use it
NET_IMPORTS = {"listen", "accept", "accept4", "recvfrom"}
LAUNCH_DIRS = ("etc/init.d", "etc/inetd.conf.d", "etc/systemd/system", "lib/systemd/system",
               "usr/lib/systemd/system")
LAUNCH_FILES = ("etc/inetd.conf", "etc/inittab")
# lines that start something: VAR=/path, start-stop-daemon, ExecStart=, inetd entries, bare /path commands
LAUNCH_LINE = re.compile(r"^\s*(?:local\s+)?\w+=|start-stop-daemon|ExecStart|^[^#\s]+\s+(?:stream|dgram)\s"
                         r"|^\s*(?:exec\s+)?/")
ABS_PATH = re.compile(r"/[\w.+-]+(?:/[\w.+-]+)+")
WRITABLE = ("/tmp", "/var/tmp", "/dev/shm", "/home")


def launched_paths(root, links):
    """(paths started by init scripts / systemd units / inetd, the subset started by inetd)."""
    started, inetd = set(), set()
    # follow the symlink table: some layouts link etc/init.d -> rc.d/init.d or link inetd.conf
    for src, p in [(d, p) for d in LAUNCH_DIRS for _, p in iter_files(root, resolve(d, links))] + \
                  [(r, p) for r in LAUNCH_FILES if (p := real(root, r, links))]:
        for line in read_text(p).splitlines():
            if not line.lstrip().startswith("#") and LAUNCH_LINE.search(line):
                found = {resolve(m, links) for m in ABS_PATH.findall(line)}
                started |= found
                if src.startswith("etc/inetd.conf"):
                    inetd |= found
    return started, inetd


def analyze(f, rel):
    """Hardening properties of one ELF file (open binary handle)."""
    elf = ELFFile(f)
    segs = list(elf.iter_segments())
    ptypes = {s["p_type"] for s in segs}
    stack = next((s for s in segs if s["p_type"] == "PT_GNU_STACK"), None)
    tags, names, imports = {}, set(), set()
    needed, rpath, runpath, soname = [], [], [], None
    for seg in segs:
        if seg["p_type"] != "PT_DYNAMIC":
            continue
        for t in seg.iter_tags():
            tags[t.entry.d_tag] = tags.get(t.entry.d_tag, 0) | (t.entry.d_val if isinstance(t.entry.d_val, int) else 0)
            if t.entry.d_tag == "DT_NEEDED":
                needed.append(t.needed)
            elif t.entry.d_tag == "DT_SONAME":
                soname = t.soname
            elif t.entry.d_tag == "DT_RPATH":
                rpath += t.rpath.split(":")
            elif t.entry.d_tag == "DT_RUNPATH":
                runpath += t.runpath.split(":")
        for s in seg.iter_symbols():
            names.add(s.name)
            if s["st_shndx"] == "SHN_UNDEF":
                imports.add(s.name)
    symtab = elf.get_section_by_name(".symtab")
    if symtab is not None:
        names |= {s.name for s in symtab.iter_symbols()}
    etype = elf["e_type"]
    if rel.endswith(".ko"):
        typ = "kmod"
    elif etype == "ET_EXEC" or (etype == "ET_DYN" and "PT_INTERP" in ptypes):
        typ = "exe"
    elif etype == "ET_DYN":
        typ = "lib"
    else:
        typ = "other"
    bind_now = "DT_BIND_NOW" in tags or tags.get("DT_FLAGS", 0) & DF_BIND_NOW or tags.get("DT_FLAGS_1", 0) & DF_1_NOW
    relro = ("full" if bind_now else "partial") if "PT_GNU_RELRO" in ptypes else "none"
    return {
        "path": "/" + rel, "type": typ, "arch": elf.get_machine_arch(),
        "nx": "unknown" if stack is None else not stack["p_flags"] & P_FLAGS.PF_X,
        "pie": typ == "exe" and (etype == "ET_DYN" or bool(tags.get("DT_FLAGS_1", 0) & DF_1_PIE)),
        "relro": relro,
        "canary": bool(names & CANARY),
        "fortify_source": any(FORTIFY.match(n) for n in names),
        "rpath": rpath, "runpath": runpath,
        "insecure_rpath": any(not p.startswith("/") or p.startswith(WRITABLE) for p in rpath + runpath),
        "symbols": symtab is not None,
        "net_imports": sorted(imports & NET_IMPORTS),
        "needed": needed, "soname": soname,
    }


def ratios(recs, keys=("canary", "nx", "pie", "relro_full", "relro_partial", "fortify")):
    test = {"canary": lambda r: r["canary"], "nx": lambda r: r["nx"] is True, "pie": lambda r: r["pie"],
            "relro_full": lambda r: r["relro"] == "full", "relro_partial": lambda r: r["relro"] == "partial",
            "fortify": lambda r: r["fortify_source"]}
    return {k: round(sum(map(test[k], recs)) / len(recs), 4) if recs else None for k in keys}


def run(root, links):
    """Returns (per-binary records, evidence summary)."""
    started, inetd = launched_paths(root, links)
    records, errors = [], []
    for rel, p in iter_files(root):
        with open(p, "rb") as f:
            if f.read(4) != b"\x7fELF":
                continue
            f.seek(0)
            try:
                records.append(analyze(f, rel))
            except Exception as e:  # truncated or exotic ELF: record, don't abort the run
                errors.append({"path": "/" + rel, "error": str(e)[:200]})
    # network-facing daemon: started at boot AND takes network input (inetd hands it the socket, or it
    # or a library it links imports a server socket API)
    # libraries are linked by soname; the soname symlink itself often could not be created on Windows
    net_libs = {r["soname"] or os.path.basename(r["path"]) for r in records if r["type"] == "lib" and r["net_imports"]}
    for r in records:
        rel = r["path"].lstrip("/")
        r["network"] = r["type"] == "exe" and rel in started and (
            rel in inetd or bool(r["net_imports"]) or any(n in net_libs for n in r["needed"]))
    exes = [r for r in records if r["type"] == "exe"]
    libs = [r for r in records if r["type"] == "lib"]
    daemons = [r for r in exes if r["network"]]
    summary = {
        "executables": len(exes), "shared_libs": len(libs),
        "kernel_modules": sum(r["type"] == "kmod" for r in records), "elf_errors": len(errors),
        "ratios": ratios(exes), "ratios_network": ratios(daemons),
        "ratios_libs": ratios(libs, ("canary", "nx", "relro_full", "relro_partial", "fortify")),
        "insecure_rpath": sorted(r["path"] for r in records if r["insecure_rpath"]),
        "network_daemons": [{"path": r["path"], "canary": r["canary"], "nx": r["nx"] is True, "pie": r["pie"],
                             "relro_full": r["relro"] == "full", "fortify": r["fortify_source"]} for r in daemons],
        "binaries_ref": "hardening.json",
    }
    return {"binaries": records, "errors": errors}, summary
