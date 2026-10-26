"""Junos helpers: SHA-512 crypt for local passwords, and IOS-style ACL entries rewritten as firewall filter terms.

Junos stores a local user's password as a crypt hash, and `set ... plain-text-password` asks for it interactively,
so OneConfig hashes the password itself (SHA-512 crypt, the "$6$" format Junos accepts)."""
import hashlib
import re
import secrets
from ipaddress import IPv4Address, IPv4Network

_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_ORDER = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48), (28, 49, 7),
          (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13), (56, 14, 35), (15, 36, 57),
          (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41)]


_ORDER256 = [(0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14), (15, 25, 5), (6, 16, 26), (27, 7, 17),
             (18, 28, 8), (9, 19, 29)]


def _sha_crypt(password: str, salt: str | None, algo: str) -> str:
    """glibc SHA-crypt core, 5000 rounds; algo is "sha512" ($6$) or "sha256" ($5$). Python 3.13 removed the crypt module."""
    n = 64 if algo == "sha512" else 32
    p = password.encode()
    s = (salt or "".join(secrets.choice(_B64) for _ in range(16))).encode()[:16]
    h = lambda b: hashlib.new(algo, b).digest()  # noqa: E731
    b = h(p + s + p)
    a = p + s + b * (len(p) // n) + b[:len(p) % n]
    i = len(p)
    while i:
        a += b if i & 1 else p
        i >>= 1
    c = h(a)
    pp = (h(p * len(p)) * (len(p) // n + 1))[:len(p)]
    ss = (h(s * (16 + c[0])) * (len(s) // n + 1))[:len(s)]
    for r in range(5000):
        c = h((pp if r & 1 else c) + (ss if r % 3 else b"") + (pp if r % 7 else b"") + (c if r & 1 else pp))
    enc = lambda w, k: "".join(_B64[(w >> 6 * j) & 63] for j in range(k))  # noqa: E731
    if n == 64:
        out = "".join(enc((c[x] << 16) | (c[y] << 8) | c[z], 4) for x, y, z in _ORDER) + enc(c[63], 2)
        return f"$6${s.decode()}${out}"
    out = "".join(enc((c[x] << 16) | (c[y] << 8) | c[z], 4) for x, y, z in _ORDER256) + enc((c[31] << 8) | c[30], 3)
    return f"$5${s.decode()}${out}"


def sha512_crypt(password: str, salt: str | None = None) -> str:
    """SHA-512 crypt ("$6$salt$hash"): Junos local passwords."""
    return _sha_crypt(password, salt, "sha512")


def sha256_crypt(password: str, salt: str | None = None) -> str:
    """SHA-256 crypt ("$5$salt$hash"): PAN-OS phash."""
    return _sha_crypt(password, salt, "sha256")


def sha512_verify(password: str, hashed: str) -> bool:
    m = re.match(r"^\$6\$([^$]{0,16})\$", hashed or "")
    return bool(m) and secrets.compare_digest(sha512_crypt(password, m.group(1)), hashed)


def sha256_verify(password: str, hashed: str) -> bool:
    m = re.match(r"^\$5\$([^$]{0,16})\$", hashed or "")
    return bool(m) and secrets.compare_digest(sha256_crypt(password, m.group(1)), hashed)


# ---------------------------------------------------------------- ACLs
PORTS = {"www": "http", "domain": "domain", "bgp": "bgp", "ssh": "ssh", "22": "ssh", "telnet": "telnet", "snmp": "snmp",
         "snmptrap": "snmptrap", "ntp": "ntp", "syslog": "syslog", "tacacs": "tacacs", "ftp": "ftp", "smtp": "smtp",
         "https": "https", "443": "https", "80": "http", "53": "domain", "bootps": "bootps", "bootpc": "bootpc"}
ICMP = {"echo": "echo-request", "echo-reply": "echo-reply", "unreachable": "unreachable",
        "time-exceeded": "time-exceeded", "packet-too-big": "unreachable"}
PROTOCOLS = {"ip", "tcp", "udp", "icmp", "ospf", "gre", "esp", "ahp", "pim"}


def _addr(w: list) -> str | None:
    """Pop one IOS address (any | host A | A/len | A wildcard) off the word list."""
    t = w.pop(0)
    if t == "any":
        return None
    if t == "host":
        return f"{IPv4Address(w.pop(0))}/32"
    if "/" in t:
        return str(IPv4Network(t, strict=False))
    wild = IPv4Address(w.pop(0))
    return str(IPv4Network(f"{t}/{IPv4Address(int(wild) ^ 0xFFFFFFFF)}", strict=False))


def _port(w: list) -> str | None:
    if w and w[0] == "eq":
        w.pop(0)
        p = w.pop(0)
        if not (p.isdigit() or p in PORTS):
            raise ValueError(f"unknown port name '{p}' (use the port number)")
        return PORTS.get(p, p)
    if w and w[0] == "range":
        w.pop(0)
        lo, hi = w.pop(0), w.pop(0)
        return f"{lo}-{hi}"
    if w and w[0] in ("gt", "lt", "neq"):
        raise ValueError(f"'{w[0]}' ports aren't supported on Junos filters; use 'eq' or 'range'")
    return None


def acl_terms(name: str, entries: list[str]) -> list[str]:
    """`set firewall family inet filter NAME term ...` lines for IOS-style ACL entries. Raises ValueError with the
    entry that can't be translated. Ends with an explicit deny, like the IOS implicit one."""
    out, n = [], 0
    for e in entries:
        w = e.split()
        action = w.pop(0)
        if action == "remark":
            continue
        try:
            proto = w.pop(0)
            if proto not in PROTOCOLS and not proto.isdigit():
                raise ValueError(f"unknown protocol '{proto}'")
            src, sport = _addr(w), _port(w)
            dst, dport = _addr(w), _port(w)
            flags = set(w)
            unknown = flags - {"log", "log-input", "established", "fragments"} - set(ICMP)
            if unknown:
                raise ValueError(f"can't translate '{' '.join(sorted(unknown))}'")
        except (IndexError, ValueError) as x:
            raise ValueError(f"ACL {name}: '{e}' can't be written as a Junos filter term ({x})") from None
        n += 1
        t = f"set firewall family inet filter {name} term T{n * 10}"
        frm = [f"source-address {src}"] * bool(src) + [f"destination-address {dst}"] * bool(dst)
        frm += [f"protocol {'ah' if proto == 'ahp' else proto}"] * (proto != "ip")
        frm += [f"source-port {sport}"] * bool(sport) + [f"destination-port {dport}"] * bool(dport)
        frm += ["tcp-established"] * ("established" in flags) + ["is-fragment"] * ("fragments" in flags)
        frm += [f"icmp-type {ICMP[f]}" for f in sorted(flags & set(ICMP))]
        out += [f"{t} from {f}" for f in frm]
        out += [f"{t} then syslog"] * bool(flags & {"log", "log-input"})
        out.append(f"{t} then {'accept' if action == 'permit' else 'discard'}")
    out.append(f"set firewall family inet filter {name} term IMPLICIT-DENY then discard")
    return out
