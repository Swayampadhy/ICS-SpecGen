import os

from elf_fixture import build
from specgen import hardening


def analyze(path):
    with open(path, "rb") as f:
        return hardening.analyze(f, os.path.basename(path))


def test_hardened_executable(tmp_path):
    p = tmp_path / "goodd"
    build(p, pie=True, canary=True, nx=True, relro="full", imports=["__memcpy_chk", "bind", "listen"])
    r = analyze(p)
    assert (r["type"], r["pie"], r["canary"], r["nx"], r["relro"], r["fortify_source"]) == ("exe", True, True, True, "full", True)
    assert r["net_imports"] and r["needed"] == ["libc.so.6"] and not r["symbols"]


def test_unhardened_executable(tmp_path):
    p = tmp_path / "badd"
    build(p, pie=False, canary=False, nx=False, relro="none")
    r = analyze(p)
    assert (r["type"], r["pie"], r["canary"], r["nx"], r["relro"], r["fortify_source"]) == ("exe", False, False, False, "none", False)
    assert not r["net_imports"]


def test_partial_relro_and_missing_stack_header(tmp_path):
    p = tmp_path / "x"
    build(p, pie=False, relro="partial", nx=None)
    r = analyze(p)
    assert r["relro"] == "partial" and r["nx"] == "unknown"


def test_shared_library(tmp_path):
    p = tmp_path / "libfoo.so"
    build(p, pie=False, interp=False)
    assert analyze(p)["type"] == "lib"


def test_run_follows_symlinked_init_dir(tmp_path):
    (tmp_path / "usr" / "bin").mkdir(parents=True)
    (tmp_path / "etc" / "rc.d" / "init.d").mkdir(parents=True)
    build(tmp_path / "usr" / "bin" / "netd", imports=["accept"])
    (tmp_path / "etc" / "rc.d" / "init.d" / "netd").write_text("DAEMON=/usr/bin/netd\n")
    _, summary = hardening.run(str(tmp_path), {"etc/init.d": "rc.d/init.d"})  # init.d is only a link
    assert [d["path"] for d in summary["network_daemons"]] == ["/usr/bin/netd"]


def test_run_network_daemons_need_boot_start_and_network_input(tmp_path):
    bin_, lib = tmp_path / "usr" / "bin", tmp_path / "usr" / "lib"
    for d in (bin_, lib, tmp_path / "etc" / "init.d"):
        d.mkdir(parents=True, exist_ok=True)
    build(bin_ / "netd", imports=["accept"])                     # started + server API -> daemon
    build(bin_ / "inetsvc", canary=False, pie=False)            # started by inetd -> daemon
    build(bin_ / "helper")                                      # started, no network input -> not
    build(bin_ / "client", imports=["accept"])                  # server API, never started -> not
    build(bin_ / "libuser", needed=["libc.so.6", "libnet.so.1"])  # started, socket API via its library -> daemon
    build(lib / "libnet.so.1.0", interp=False, imports=["listen"], soname="libnet.so.1")
    (tmp_path / "etc" / "init.d" / "svc").write_text(
        'DAEMON="/usr/bin/netd"\nHELPER=/usr/bin/helper\n  /usr/bin/libuser -d &\n# /usr/bin/client only in a comment\n')
    (tmp_path / "etc" / "inetd.conf").write_text("svc stream tcp nowait root /usr/bin/inetsvc inetsvc\n")
    doc, summary = hardening.run(str(tmp_path), {})
    assert [d["path"] for d in summary["network_daemons"]] == ["/usr/bin/inetsvc", "/usr/bin/libuser", "/usr/bin/netd"]
    assert summary["executables"] == 5 and summary["shared_libs"] == 1
    assert summary["ratios"]["canary"] == 0.8 and summary["ratios_network"]["canary"] == round(2 / 3, 4)
