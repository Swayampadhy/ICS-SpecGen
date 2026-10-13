"""Secure-defaults audit: accounts, clear-text services, SSH settings, embedded private keys."""
import fnmatch
import os
import posixpath
import re

from passlib.hash import des_crypt, md5_crypt, sha256_crypt, sha512_crypt

from .unpack import iter_files, listdir, read_text, real

# shortcut: documented defaults from public vendor manuals (WAGO root/admin "wago", user "user"; Raspberry Pi
# "raspberry"); extend this list per vendor before evaluating other products
DEFAULT_PASSWORDS = ["wago", "user", "admin", "root", "raspberry", "password", "123456", "plcnext"]
HASHERS = [("$1$", md5_crypt), ("$5$", sha256_crypt), ("$6$", sha512_crypt)]
DES = re.compile(r"^[./0-9A-Za-z]{13}$")
SERVICES = [("tftpd", r"tftp"), ("telnetd", r"telnet"), ("ftpd", r"(?<![st])ftp"),
            ("rsh", r"r(?:sh|login|exec)d|^(?:shell|login|exec)$")]
RC_DIRS = ["etc/rc.d"] + [f"etc/rc{x}.d" for x in "0123456S"]
SYSTEMD_DIRS = ["etc/systemd/system"]
# key material must follow the header: ssh/openssl binaries contain the bare header as a format constant
PEM_KEY = re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----\r?\n"
                     rb"(?:[\w-]+:[^\n]*\n)*\s*[A-Za-z0-9+/=]{40}")
HOST_KEY = re.compile(r"(?:dropbear_\w+_host_key|ssh_host_\w+_key)$")
WEAK_ALGOS = re.compile(r"cbc|arcfour|3des|hmac-md5|hmac-sha1\b|diffie-hellman-group1-")


def service(name):
    n = name.lower()
    return next((key for key, rx in SERVICES if re.search(rx, n)), None)


def accounts(root, links):
    """{user: hash field} from shadow, falling back to passwd for users without a shadow entry."""
    users = {}
    for rel in ("etc/passwd", "etc/shadow"):  # shadow last so it overrides
        p = real(root, rel, links)
        for line in read_text(p).splitlines() if p else []:
            f = line.split(":")
            if len(f) > 1 and f[0] and (rel == "etc/shadow" or f[1] not in ("x", "*")):
                users[f[0]] = f[1]
    return users


def audit_passwords(users):
    """Returns (empty, weak, default); default is None (N/A) if a usable hash could not be checked."""
    empty, weak, default, unchecked = [], [], [], False
    for user, h in sorted(users.items()):
        if h == "":
            empty.append(user)
            continue
        if h.startswith(("!", "*")):  # locked
            continue
        if h.startswith("$1$") or DES.match(h):
            weak.append(user)
        hasher = next((x for prefix, x in HASHERS if h.startswith(prefix)), des_crypt if DES.match(h) else None)
        if hasher is None:
            # yescrypt ($y$, Debian 11+) and bcrypt ($2) have no passlib verifier here: unknown is not a pass
            unchecked |= h.startswith("$")
        elif any(verify(hasher, pw, h) for pw in DEFAULT_PASSWORDS):
            default.append(user)
    return empty, weak, None if unchecked and not default else default


def verify(hasher, pw, h):
    try:
        return hasher.verify(pw, h)
    except ValueError:  # malformed hash in the image: not a usable credential
        return False


def include_chain(root, links, rel, seen):
    """Text of a lighttpd/nginx config plus everything it includes (following side-table symlinks)."""
    if rel in seen or len(seen) > 64:
        return ""
    seen.add(rel)
    p = real(root, rel, links)
    if not p:
        return ""
    text = read_text(p)
    for inc in re.findall(r'^\s*include\s+"?([^";\s]+)"?', text, re.M):
        inc = inc.lstrip("/") if inc.startswith("/") else posixpath.join(posixpath.dirname(rel), inc)
        d, pat = posixpath.split(inc)
        for name in fnmatch.filter(listdir(root, d, links), pat) if "*" in pat else [pat]:
            text += "\n" + include_chain(root, links, posixpath.join(d, name), seen)
    return text


def cleartext_services(root, links):
    found = set()
    for rel in ["etc/inetd.conf"] + [f"etc/inetd.conf.d/{n}" for n in listdir(root, "etc/inetd.conf.d", links)]:
        p = real(root, rel, links)
        for line in read_text(p).splitlines() if p else []:
            f = line.split()
            if len(f) >= 6 and not f[0].startswith("#"):
                s = service(f[0].split(":")[-1]) or service(posixpath.basename(f[5]))
                found |= {s} if s else set()
    for d in RC_DIRS:
        found |= {s for n in listdir(root, d, links) if n.startswith("S") and (s := service(n[1:]))}
    for d in SYSTEMD_DIRS:
        for wants in (w for w in listdir(root, d, links) if w.endswith(".wants")):
            found |= {s for n in listdir(root, f"{d}/{wants}", links) if (s := service(n))}
    web = include_chain(root, links, "etc/lighttpd/lighttpd.conf", set()) + \
        include_chain(root, links, "etc/nginx/nginx.conf", set())
    listens80 = re.search(r'server\.port\s*=\s*(?:80|http_port)\b|":80"|listen\s+(?:[\d.:\[\]]*:)?80\b', web)
    redirects = re.search(r'url\.redirect[^\n]*https://|return\s+30[1278]\s+https://', web)
    if listens80 and not redirects:
        found.add("http")
    return sorted(found)


def ssh(root, links):
    p = real(root, "etc/ssh/sshd_config", links)
    if p and (real(root, "usr/sbin/sshd", links) or real(root, "sbin/sshd", links)):
        cfg = {k.lower(): v.strip() for k, v in re.findall(r"^\s*(\w+)\s+(.+)$", read_text(p), re.M)}
        root_login = {"yes": True, "no": False, "prohibit-password": False, "without-password": False,
                      "forced-commands-only": False}.get(cfg.get("permitrootlogin", "").lower())
        weak = sorted({a for k in ("ciphers", "macs", "kexalgorithms") for a in cfg.get(k, "").split(",")
                       if WEAK_ALGOS.search(a)})
        return "openssh", root_login, cfg.get("passwordauthentication", "yes").lower() != "no", weak
    if real(root, "usr/sbin/dropbear", links) or real(root, "sbin/dropbear", links):
        conf = "\n".join(read_text(x) for rel in ("etc/default/dropbear", "etc/sysconfig/dropbear")
                         + tuple(f"etc/dropbear/{n}" for n in listdir(root, "etc/dropbear", links) if n.endswith(".conf"))
                         if (x := real(root, rel, links)))
        args = " ".join(re.findall(r"^\s*DROPBEAR_(?:EXTRA_)?ARGS\s*=\s*(.*)$", conf, re.M))
        root_login = not (re.search(r"^\s*ROOT_LOGIN\s*=\s*false", conf, re.M) or re.search(r"(?:^|\s)-[wg]\b", args))
        pw_auth = not (re.search(r"^\s*PASSWORD_LOGIN\s*=\s*false", conf, re.M) or re.search(r"(?:^|\s)-s\b", args))
        return "dropbear", root_login, pw_auth, []
    return None, None, None, []


def private_keys(root):
    keys = []
    for rel, p in iter_files(root):
        if HOST_KEY.search(rel):
            keys.append("/" + rel)
        elif os.path.getsize(p) <= 1 << 20:
            with open(p, "rb") as f:
                if PEM_KEY.search(f.read()):
                    keys.append("/" + rel)
    return keys


def run(root, links):
    empty, weak, default = audit_passwords(accounts(root, links))
    server, root_login, pw_auth, weak_algos = ssh(root, links)
    return {
        "empty_password_accounts": empty, "weak_hash_accounts": weak, "default_password_accounts": default,
        "cleartext_services": cleartext_services(root, links),
        "ssh_server": server, "ssh_root_login": root_login, "ssh_password_auth": pw_auth,
        "ssh_weak_algorithms": weak_algos,
        "embedded_private_keys": private_keys(root),
    }
