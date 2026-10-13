"""Builds tiny ELF32 ARM files with chosen hardening properties (no compiler needed on Windows).

Layout: one PT_LOAD maps the whole file at vaddr 0, so dynamic-table addresses equal file offsets.
There are no section headers (like an sstripped firmware binary), so .symtab is absent."""
import struct

PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 3, 0x6474E551, 0x6474E552
DT_NULL, DT_NEEDED, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT, DT_SONAME, DT_FLAGS = 0, 1, 4, 5, 6, 10, 11, 14, 30
DT_FLAGS_1 = 0x6FFFFFFB


def build(path, pie=True, canary=True, nx=True, relro="full", interp=True, imports=(), needed=("libc.so.6",),
          soname=None):
    libs = list(needed) + ([soname] if soname else [])
    syms = (["__stack_chk_fail"] if canary else []) + list(imports)
    dynstr, off = b"\0", {}
    for n in libs + syms:
        off[n], dynstr = len(dynstr), dynstr + n.encode() + b"\0"
    dynsym = b"\0" * 16 + b"".join(struct.pack("<IIIBBH", off[n], 0, 0, 0x12, 0, 0) for n in syms)
    nsym = len(syms) + 1
    hashtab = struct.pack(f"<{3 + nsym}I", 1, nsym, 0, *([0] * nsym))
    interp_s = b"/lib/ld-linux-armhf.so.3\0" if interp else b""

    nph = 3 + bool(interp) + (relro != "none") - (nx is None)
    blob_at = 52 + 32 * nph
    o_interp = blob_at
    o_str = o_interp + len(interp_s)
    o_sym = (o_str + len(dynstr) + 3) & ~3
    o_hash = o_sym + len(dynsym)
    o_dyn = o_hash + len(hashtab)
    tags = [(DT_NEEDED, off[n]) for n in needed] + ([(DT_SONAME, off[soname])] if soname else [])
    tags += [(DT_HASH, o_hash), (DT_STRTAB, o_str), (DT_SYMTAB, o_sym), (DT_STRSZ, len(dynstr)), (DT_SYMENT, 16)]
    if relro == "full":
        tags.append((DT_FLAGS, 0x8))  # DF_BIND_NOW
    if pie:
        tags.append((DT_FLAGS_1, 0x08000000))  # DF_1_PIE
    dynamic = b"".join(struct.pack("<iI", t, v) for t, v in tags + [(DT_NULL, 0)])
    size = o_dyn + len(dynamic)

    ph = [(PT_LOAD, 0, 0, size, 5)]
    if interp:
        ph.append((PT_INTERP, o_interp, o_interp, len(interp_s), 4))
    ph.append((PT_DYNAMIC, o_dyn, o_dyn, len(dynamic), 6))
    if nx is not None:
        ph.append((PT_GNU_STACK, 0, 0, 0, 6 if nx else 7))
    if relro != "none":
        ph.append((PT_GNU_RELRO, o_dyn, o_dyn, len(dynamic), 4))
    phdrs = b"".join(struct.pack("<IIIIIIII", t, o, v, v, s, s, fl, 4) for t, o, v, s, fl in ph)

    e_type = 3 if pie or not interp else 2  # ET_DYN for PIE executables and shared libs, else ET_EXEC
    ident = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\0" * 8
    header = ident + struct.pack("<HHIIIIIHHHHHH", e_type, 40, 1, 0, 52, 0, 0x05000400, 52, 32, len(ph), 40, 0, 0)
    body = header + phdrs + interp_s + dynstr
    body += b"\0" * (o_sym - len(body)) + dynsym + hashtab + dynamic
    with open(path, "wb") as f:
        f.write(body)
