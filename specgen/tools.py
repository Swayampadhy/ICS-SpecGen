"""Locate the external tools (7z, syft, grype, opa) and run them."""
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "tools" / "bin"
# winget installs 7-Zip here without touching PATH
EXTRA = {"7z": [r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"]}


def find(name):
    for p in (BIN / f"{name}.exe", BIN / name):
        if p.is_file():
            return str(p)
    return shutil.which(name) or next((p for p in EXTRA.get(name, []) if os.path.isfile(p)), None)


def run(args, **kw):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", **kw)


def version(name):
    exe = find(name)
    if not exe:
        return None
    out = run([exe] if name == "7z" else [exe, "version"]).stdout
    m = re.search(r"(?:Version:\s*|7-Zip\s+)(\S+)", out)
    return m.group(1) if m else "unknown"
