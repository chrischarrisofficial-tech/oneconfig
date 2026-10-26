"""DISA STIG checks for Cisco IOS-XE, driven by the official rule catalog in stig/catalog.json.

Statuses use STIG Viewer's vocabulary: open, not_a_finding, not_applicable, not_reviewed.
A rule is only marked not_a_finding when the config text proves it; anything that needs a person
(organization policy, `show` commands, topology OneConfig can't see) stays not_reviewed."""
import json
import re
from datetime import datetime
from functools import cached_property
from ipaddress import IPv4Network, collapse_addresses
from pathlib import Path

from .audit import blocks

CATALOG = json.loads((Path(__file__).parent / "stig" / "catalog.json").read_text())
BENCH = {s["id"]: s for s in CATALOG["stigs"]}
PLATFORMS = {"router": ["Router_NDM", "Router_RTR"],
             "l3switch": ["Switch_NDM", "Switch_L2S", "Switch_RTR"],
             "switch": ["Switch_NDM", "Switch_L2S", "Switch_RTR"]}
BENCHMARKS = {"ios-xe": PLATFORMS,
              **{nos: {"router": [f"{p}_NDM", f"{p}_RTR"], "l3switch": [f"{p}_NDM", f"{p}_L2S", f"{p}_RTR"],
                       "switch": [f"{p}_NDM", f"{p}_L2S", f"{p}_RTR"]} for nos, p in (("nx-os", "NXOS"), ("eos", "EOS"))},
              "junos": {"router": ["JUNOS_RTR_NDM", "JUNOS_RTR_RTR"],  # MX/SRX-class routers; EX STIGs for switches
                        "l3switch": ["JUNOS_EX_NDM", "JUNOS_EX_L2S", "JUNOS_EX_RTR"], "switch": ["JUNOS_EX_NDM", "JUNOS_EX_L2S", "JUNOS_EX_RTR"]},
              "asa": {"firewall": ["ASA_NDM", "ASA_FW", "ASA_IPS", "ASA_VPN"]},
              "panos": {"firewall": ["PAN_NDM", "PAN_ALG", "PAN_IDPS"]},
              "fortios": {"firewall": ["FORTI_NDM", "FORTI_FW"]}}  # DISA sunset the Palo Alto STIG 2026-07-10: last release
CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}
PASS, FAIL, NA, MANUAL = "not_a_finding", "open", "not_applicable", "not_reviewed"
ok = lambda d="": (PASS, d)  # noqa: E731
bad = lambda d: (FAIL, d)  # noqa: E731
na = lambda d: (NA, d)  # noqa: E731
manual = lambda d: (MANUAL, d)  # noqa: E731


class Lines:
    """A configuration as one line per value (PAN-OS, FortiOS); subclasses set self.lines."""
    def find(self, pat):
        rx = re.compile(pat)
        return [m for l in self.lines if (m := rx.match(l))]

    def has(self, pat):
        return bool(self.find(pat))

    def value(self, pat, default=None):
        m = self.find(pat)
        return m[0].group(1) if m else default

    def values(self, pat):
        return [m.group(1) for m in self.find(pat)]

_MON = {m: i for i, m in enumerate("jan feb mar apr may jun jul aug sep oct nov dec".split(), 1)}
_LOGICAL = re.compile(r"^(vlan|loopback|tunnel|null|port-channel|bdi|nve|virtual|appgigabit|mgmt|management)", re.I)
ALL_VLANS = frozenset(range(1, 4095))
ACL_BOGONS = [IPv4Network(n) for n in (  # CISC-RT-000270
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3", "240.0.0.0/4")]
BGP_BOGONS = [IPv4Network(n) for n in (  # CISC-RT-000490
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")]


def vlan_set(spec: str) -> set[int]:
    out = set()
    for part in spec.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-")
            out |= set(range(int(a), int(b) + 1))
        elif part:
            out.add(int(part))
    return out


def life_days(spec: str):
    """Days covered by a key lifetime: 'HH:MM:SS Mon D YYYY' then an end time, 'duration <seconds>' or 'infinite'."""
    t = spec.split()

    def at(i):
        mon, day = (t[i + 1], t[i + 2]) if t[i + 1].isalpha() else (t[i + 2], t[i + 1])
        return datetime(int(t[i + 3]), _MON[mon[:3].lower()], int(day), *map(int, t[i].split(":"))), i + 4
    try:
        start, i = at(0)
        if t[i] == "infinite":
            return float("inf")
        if t[i] == "duration":
            return int(t[i + 1]) / 86400
        return (at(i)[0] - start).total_seconds() / 86400
    except (IndexError, KeyError, ValueError):
        return None


def _wild(net, wild):
    try:
        return IPv4Network(f"{net}/{wild}")  # ipaddress accepts a hostmask after the slash
    except ValueError:
        return None


class Cfg:
    def __init__(self, text: str):
        self.text = text
        self.b = blocks(text)
        self.top = [p for p, _ in self.b]

    def has(self, pat):
        return any(re.search(pat, p) for p in self.top)

    def get(self, pat):
        return [(p, k) for p, k in self.b if re.match(pat, p)]

    @cached_property
    def ifs(self):
        return {p.split(None, 1)[1]: k for p, k in self.b if p.startswith("interface ")}

    def physical(self, name):
        return not _LOGICAL.match(name)

    @cached_property
    def access(self):
        return {n: k for n, k in self.ifs.items() if "switchport mode access" in k and "shutdown" not in k}

    @cached_property
    def trunks(self):
        return {n: k for n, k in self.ifs.items() if "switchport mode trunk" in k}

    @staticmethod
    def access_vlan(k):
        return next((int(x.split()[-1]) for x in k if x.startswith("switchport access vlan ") and x.split()[-1].isdigit()), 1)

    @staticmethod
    def native(k):
        return next((int(x.split()[-1]) for x in k if x.startswith("switchport trunk native vlan ") and x.split()[-1].isdigit()), 1)

    @staticmethod
    def allowed(k):
        cur = None
        for x in k:
            m = re.match(r"switchport trunk allowed vlan (?:(add|remove|except) )?(\S+)$", x)
            if not m:
                continue
            op, spec = m.groups()
            v = set(ALL_VLANS) if spec == "all" else set() if spec == "none" else vlan_set(spec)
            cur = (v if op is None else (cur or set()) | v if op == "add"
                   else (set(ALL_VLANS) if cur is None else cur) - v if op == "remove" else set(ALL_VLANS) - v)
        return set(ALL_VLANS) if cur is None else cur

    @cached_property
    def acls(self):
        out = {}
        for p, k in self.b:
            m = re.match(r"ip access-list (?:(?:extended|standard) )?(\S+)$", p)  # NX-OS and EOS omit the type
            if m:
                out[m.group(1)] = [re.sub(r"^\d+ ", "", x) for x in k]
            m = re.match(r"access-list (\d+) (.+)", p)
            if m:
                out.setdefault(m.group(1), []).append(m.group(2))
        return out

    @staticmethod
    def acl_on(k, direction):
        return next((x.split()[2] for x in k if re.match(rf"ip access-group \S+ {direction}$", x)), None)

    @cached_property
    def applied_acls(self):
        return {a for k in self.ifs.values() for d in ("in", "out") if (a := self.acl_on(k, d))}

    @cached_property
    def keychains(self):
        out = {}
        for p, k in self.b:
            m = re.match(r"key chain (\S+)( tcp)?$", p)
            if not m:
                continue
            keys = []
            for x in k:
                if re.match(r"key \d+$", x):
                    keys.append({})
                elif keys and x.startswith("cryptographic-algorithm "):
                    keys[-1]["alg"] = x.split()[1]
                elif keys and re.match(r"(send|accept)-lifetime ", x):
                    keys[-1][x.split("-")[0]] = life_days(x.split(None, 1)[1])
            out[m.group(1)] = {"tcp": bool(m.group(2)), "keys": keys}
        return out

    def chain_problem(self, name, tcp=False):
        kc = self.keychains.get(name)
        if not kc:
            return f"key chain {name} is not defined"
        if tcp and not kc["tcp"]:
            return f"key chain {name} is not a TCP-AO key chain (key chain {name} tcp)"
        if not kc["keys"]:
            return f"key chain {name} has no keys"
        for n, key in enumerate(kc["keys"], 1):
            if not re.match(FIPS_HMAC, key.get("alg", "")):
                return f"key {n} of {name} does not use a FIPS 198-1 HMAC (HMAC-SHA-1 or SHA-2)"
            for kind in ("send", "accept"):
                days = key.get(kind)
                if days is None:
                    return f"key {n} of {name} has no {kind}-lifetime"
                if days > 181:  # one day of overlap is normal practice for key rollover
                    return f"key {n} of {name} {kind}-lifetime is longer than 180 days"
        return None

    @cached_property
    def bgp(self):
        r = next(((p, k) for p, k in self.b if p.startswith("router bgp ")), None)
        if not r:
            return None
        asn = int(r[0].split()[2])
        nbrs, nested, cur = {}, {}, None
        for x in r[1]:
            m = re.match(r"neighbor (\S+) remote-as (\d+)", x)
            if m:
                nbrs[m.group(1)] = int(m.group(2))
            elif re.match(r"neighbor \S+$", x):  # NX-OS: the neighbor's settings follow on their own lines
                cur = x.split()[1]
                nested[cur] = []
            elif cur and re.match(r"(vrf|template) ", x):
                cur = None
            elif cur:
                nested[cur].append(x)
                if x.startswith("remote-as "):
                    nbrs[cur] = int(x.split()[1])

        def opts(n):
            return nested.get(n) or [x.split(None, 2)[2] for x in r[1] if x.startswith(f"neighbor {n} ")]
        nets = [_wild(*m.groups()) for x in r[1] if (m := re.match(r"network (\S+) mask (\S+)", x))]
        nets += [IPv4Network(m.group(1), strict=False) for x in r[1] if (m := re.match(r"network (\d+\.\d+\.\d+\.\d+/\d+)", x))]
        return {"asn": asn, "nbrs": nbrs, "opts": opts, "kids": r[1], "networks": nets}

    def prefix_list(self, name):
        out = []
        for p in self.top:
            m = re.match(rf"ip prefix-list {re.escape(name)} (?:seq \d+ )?(permit|deny) (\S+)(.*)", p)
            if m:
                out.append((m.group(1), IPv4Network(m.group(2), strict=False), m.group(3).strip()))
        return out


def _covered(required, nets):
    merged = list(collapse_addresses(nets))
    return [r for r in required if not any(r.subnet_of(m) for m in merged)]


def _acl_denies(entries):
    nets = []
    for e in entries:
        p = re.match(r"deny\s+ip\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+any", e)  # NX-OS / EOS prefix form
        if p:
            nets.append(IPv4Network(p.group(1), strict=False))
            continue
        m = re.match(r"deny\s+ip\s+(\S+)\s+(\S+)\s+any", e)
        if m:
            net = IPv4Network("0.0.0.0/0") if m.group(1) == "any" else (
                IPv4Network(f"{m.group(2)}/32") if m.group(1) == "host" else _wild(m.group(1), m.group(2)))
            if net:
                nets.append(net)
    return nets


CHECKS = {}
# FIPS 198-1 HMACs. SHA-1 is included: it is the only HMAC Junos OSPF key chains offer, so mixed networks use it.
FIPS_HMAC = r"hmac-sha-?(1|256|384|512)$"


# FIPS SSH algorithms NX-OS and EOS may offer: (allowed pattern, finding when unrestricted, finding prefix for weak ones)
SSH_FIPS = {"mac": (r"hmac-sha2-", "SSH MACs are not restricted to HMAC-SHA2.", "Non-FIPS SSH MACs: "),
            "cipher": (r"aes\d+-(ctr|gcm)", "SSH ciphers are not restricted to AES.", "Weak SSH ciphers: ")}


def ssh_algos(kind, line, algos):
    """line: the config line that restricts SSH MACs or ciphers (None when absent); algos: the algorithms it lists."""
    rx, missing, weak_msg = SSH_FIPS[kind]
    if not line:
        return bad(missing)
    weak = [a for a in algos if not re.match(rx, a)]
    return bad(weak_msg + " ".join(weak)) if weak else ok(line)


def dc_acl_fix(fix, indent):
    """IOS ACL fix text rewritten for NX-OS / EOS: no extended/standard keyword, prefix form, 'log', the OS's indent."""
    if not re.search(r"ip access-list (extended|standard) ", fix):
        return fix
    fix = re.sub(r"ip access-list (extended|standard) ", "ip access-list ", fix)
    fix = fix.replace(" log-input", " log").replace("<BOGON> <WILDCARD>", "<BOGON>/<LEN>")
    return re.sub(r"^ (?=\S)", indent, fix, flags=re.M)


def check(*ids, fix=""):
    def deco(fn):
        for i in ids:
            CHECKS[i] = (fn, fix)
        return fn
    return deco


def _lines(c, kind):
    """Usable console or VTY lines (VTY ranges with transport input none can't be logged into)."""
    return [(p, k) for p, k in c.get(rf"line {kind}") if "transport input none" not in k]


def _timeout_mins(k):
    m = next((x for x in k if x.startswith("exec-timeout ")), None)
    if not m:
        return 10  # IOS default
    parts = [int(v) for v in m.split()[1:]] + [0]
    return float("inf") if parts[0] == 0 and parts[1] == 0 else parts[0] + parts[1] / 60


# ---------------------------------------------------------------- NDM (management plane)
ARCHIVE = "archive\n log config\n  logging enable\n  logging size 1000\n  notify syslog contenttype plaintext\n  hidekeys"


def _archive(c):
    return any(p == "archive" and "logging enable" in k for p, k in c.b)


@check("CISC-ND-000090", "CISC-ND-000100", "CISC-ND-000110", "CISC-ND-000120", "CISC-ND-000330",
       "CISC-ND-000880", "CISC-ND-001250", "CISC-ND-001270", fix=ARCHIVE)
def nd_archive(c, x):
    return ok("archive log config logging enable") if _archive(c) else bad("Configuration change logging (archive log config) is not enabled.")


@check("CISC-ND-000210", fix="logging userinfo\n" + ARCHIVE)
def nd_admin_activity(c, x):
    missing = [n for n, v in (("logging userinfo", "logging userinfo" in c.top), ("archive log config", _archive(c))) if not v]
    return bad("Missing: " + ", ".join(missing)) if missing else ok("logging userinfo and archive log config")


@check("CISC-ND-000010", fix="line vty 0 1\n transport input ssh\nline vty 2 15\n transport input none")
def nd_sessions(c, x):
    vty = c.get("line vty")
    if not vty:
        return manual("No VTY line configuration found.")
    if "ip http secure-server" in c.top and not c.has(r"^ip http max-connections"):
        return bad("HTTPS management is enabled without ip http max-connections.")
    if any(any(z.startswith("session-limit") for z in k) or "transport input none" in k for _, k in vty):
        return ok("VTY sessions limited")
    return bad("Every VTY line accepts logins. Limit sessions with session-limit or transport input none on spare lines.")


@check("CISC-ND-000140", fix="ip access-list standard MGMT-ACCESS\n permit <MGMT-NET> <WILDCARD>\n deny any log\n"
                            "line vty 0 1\n access-class MGMT-ACCESS in")
def nd_vty_acl(c, x):
    vty = _lines(c, "vty")
    if not vty:
        return manual("No usable VTY lines found.")
    probs = []
    for p, k in vty:
        acl = next((z.split()[1] for z in k if z.startswith("access-class ") and z.endswith(" in")), None)
        if not acl:
            probs.append(f"{p} has no inbound access-class")
        elif acl not in c.acls:
            probs.append(f"{p} references undefined ACL {acl}")
    return bad("; ".join(probs)) if probs else ok("All usable VTY lines restricted by access-class")


@check("CISC-ND-000150", fix="login block-for 900 attempts 3 within 120")
def nd_lockout(c, x):
    m = re.search(r"^login block-for (\d+) attempts (\d+) within (\d+)", c.text, re.M)
    if not m:
        return bad("login block-for is not configured.")
    block, att, _ = map(int, m.groups())
    return ok(m.group(0)) if block >= 900 and att <= 3 else bad(f"Needs a 900-second lockout after 3 attempts; found: {m.group(0)}")


@check("CISC-ND-000160", fix="Turn on the DoD banner in OneConfig's Security settings, or configure\n"
                            "banner login ^<Standard Mandatory DoD Notice and Consent Banner>^")
def nd_banner(c, x):
    if "USG-authorized use only" in c.text and "See User Agreement for details" in c.text:
        return ok("Standard Mandatory DoD Notice and Consent Banner present")
    if c.has(r"^banner (login|motd)"):
        return bad("A banner is configured, but it is not the Standard Mandatory DoD Notice and Consent Banner.")
    return bad("No login banner configured.")


@check("CISC-ND-000280", fix="service timestamps log datetime localtime")
def nd_timestamps(c, x):
    return ok() if c.has(r"^service timestamps log datetime") else bad("Log timestamps do not include date and time.")


def _deny_log(c, word):
    acls = [a for a in c.applied_acls if a in c.acls]
    if not acls:
        return na("No ACLs are applied to interfaces.")
    missing = [f"{a}: {e}" for a in acls for e in c.acls[a] if e.startswith("deny") and word not in e.split()]
    return bad(f"Deny entries without {word}: " + "; ".join(missing[:5])) if missing else ok(f"All deny entries in applied ACLs use {word}")


@check("CISC-ND-000290", "CISC-RT-000210", "CISC-RT-000220", fix="ip access-list extended <ACL>\n deny ip any any log-input")
def deny_log_input(c, x):
    return _deny_log(c, "log-input")


@check("CISC-RT-000200", fix="ip access-list extended <ACL>\n deny ip any any log")
def rt_deny_log(c, x):
    acls = [a for a in c.applied_acls if a in c.acls]
    if not acls:
        return na("No ACLs are applied to interfaces.")
    missing = [f"{a}: {e}" for a in acls for e in c.acls[a]
               if e.startswith("deny") and not ({"log", "log-input"} & set(e.split()))]
    return bad("Deny entries that don't log: " + "; ".join(missing[:5])) if missing else ok("All deny entries log")


@check("CISC-ND-000380", "CISC-ND-000390", fix="file privilege 15")
def nd_persistent_logs(c, x):
    if not c.has(r"^logging persistent"):
        return na("Persistent logging is not enabled.")
    m = re.search(r"^file privilege (\d+)", c.text, re.M)
    return bad(f"File system access allowed at privilege {m.group(1)}.") if m and m.group(1) != "15" else ok()


@check("CISC-ND-000460", fix="file privilege 15")
def nd_file_priv(c, x):
    m = re.search(r"^file privilege (\d+)", c.text, re.M)
    return bad(f"File system access allowed at privilege {m.group(1)}.") if m and m.group(1) != "15" else ok("Privilege 15 required (default)")


NONSECURE = ["boot network", "ip boot server", "ip bootp server", "ip dns server", "ip identd", "ip finger",
             "ip http server", "ip rcmd rcp-enable", "ip rcmd rsh-enable", "service config", "service finger",
             "service tcp-small-servers", "service udp-small-servers", "service pad", "service call-home"]


@check("CISC-ND-000470", fix="\n".join("no " + s for s in NONSECURE))
def nd_services(c, x):
    found = [s for s in NONSECURE if any(p == s or p.startswith(s + " ") for p in c.top)]
    if found == ["service call-home"]:
        return manual("service call-home is enabled. Allowed only on legacy devices that need it for Smart Licensing.")
    return bad("Enabled: " + ", ".join(found)) if found else ok("No listed nonsecure services enabled")


@check("CISC-ND-000490", fix="username <ADMIN-USER> privilege 15 common-criteria-policy PASSWORD_POLICY algorithm-type scrypt secret <SECRET>\n"
                            "aaa authentication login default group <TACACS-OR-RADIUS-GROUP> local")
def nd_last_resort(c, x):
    users = sorted({p.split()[1] for p in c.top if p.startswith("username ")})
    login = re.search(r"^aaa authentication login default (.+)$", c.text, re.M)
    probs = []
    if len(users) != 1:
        probs.append(f"{len(users)} local accounts configured (need exactly one)")
    elif not any(p.startswith(f"username {users[0]} ") and "common-criteria-policy" in p for p in c.top):
        probs.append("the local account is not bound to a common-criteria password policy")
    methods = login.group(1).split() if login else []
    if "local" not in methods or "group" not in methods or methods.index("group") > methods.index("local"):
        probs.append("local must come after a TACACS+/RADIUS group in aaa authentication login default")
    return bad("; ".join(probs)) if probs else ok(f"One local account ({users[0]}) used as last resort")


def _cc_policy(c):
    for p, k in c.get(r"aaa common-criteria policy "):
        return {z.split()[0]: int(z.split()[1]) for z in k if len(z.split()) == 2 and z.split()[1].isdigit()}
    return None


for _id, _key, _min, _text in (("CISC-ND-000550", "min-length", 15, "minimum length 15"),
                               ("CISC-ND-000570", "upper-case", 1, "an uppercase character"),
                               ("CISC-ND-000580", "lower-case", 1, "a lowercase character"),
                               ("CISC-ND-000590", "numeric-count", 1, "a numeric character"),
                               ("CISC-ND-000600", "special-case", 1, "a special character"),
                               ("CISC-ND-000610", "char-changes", 8, "8 changed characters")):
    def _make(key=_key, need=_min, text=_text):
        def fn(c, x):
            pol = _cc_policy(c)
            if pol is None:
                return bad("No aaa common-criteria password policy is configured.")
            return ok(f"{key} {pol[key]}") if pol.get(key, 0) >= need else bad(f"Password policy does not require {text}.")
        return fn
    check(_id, fix=f"aaa common-criteria policy PASSWORD_POLICY\n {_key} {_min}")(_make())


@check("CISC-ND-000620", fix="service password-encryption")
def nd_pw_encrypt(c, x):
    if "service password-encryption" not in c.top:
        return bad("service password-encryption is not enabled.")
    if c.has(r"^enable password") or c.has(r"^username \S+ .*\bpassword 0 "):
        return bad("Reversible (type 0/7) passwords are configured. Use algorithm-type scrypt secret.")
    return ok("service password-encryption")


@check("CISC-ND-000720", fix="line con 0\n exec-timeout 5 0\nline vty 0 1\n exec-timeout 5 0")
def nd_idle(c, x):
    lines = _lines(c, "con") + _lines(c, "vty")
    if not lines:
        return manual("No console or VTY lines found.")
    long_ = [f"{p} ({'never' if t == float('inf') else f'{t:g} min'})" for p, k in lines if (t := _timeout_mins(k)) > 5]
    if "ip http secure-server" in c.top:
        m = re.search(r"^ip http timeout-policy idle (\d+)", c.text, re.M)
        if not m or int(m.group(1)) > 300:
            long_.append("HTTPS idle timeout over 300 s")
    return bad("Idle timeout over 5 minutes: " + ", ".join(long_)) if long_ else ok("All management sessions time out within 5 minutes")


@check("CISC-ND-000980", fix="logging buffered 64000 informational")
def nd_log_buffer(c, x):
    return ok() if c.has(r"^logging buffered \d+") else bad("No logging buffer size configured.")


@check("CISC-ND-001000", fix="logging trap critical")
def nd_log_trap(c, x):
    return bad("logging trap is disabled.") if "no logging trap" in c.top else ok("Syslog trap level includes critical")


@check("CISC-ND-001030", fix="ntp server <NTP-1>\nntp server <NTP-2>")
def nd_ntp(c, x):
    n = sum(1 for p in c.top if p.startswith("ntp server "))
    return ok(f"{n} NTP servers") if n >= 2 else bad(f"{n} NTP server(s); two or more are required.")


def _snmp(c):
    if not c.has(r"^snmp-server "):
        return na("SNMP is not enabled.")
    if c.has(r"^snmp-server community "):
        return bad("SNMPv1/v2c community strings are configured.")
    return None


@check("CISC-ND-001130", fix="snmp-server group <GROUP> v3 priv read <VIEW>\nsnmp-server user <USER> <GROUP> v3 auth sha <AUTH> priv aes 256 <PRIV>")
def nd_snmp_auth(c, x):
    if (r := _snmp(c)):
        return r
    groups = [p for p in c.top if re.match(r"snmp-server group \S+ v3 ", p)]
    if not groups or any(" v3 noauth" in g for g in groups):
        return bad("SNMP is not limited to SNMPv3 groups with authentication.")
    return ok("SNMPv3 auth groups (verify users with show snmp user)")


@check("CISC-ND-001140", fix="snmp-server group <GROUP> v3 priv read <VIEW>\nsnmp-server user <USER> <GROUP> v3 auth sha <AUTH> priv aes 256 <PRIV>")
def nd_snmp_priv(c, x):
    if (r := _snmp(c)):
        return r
    groups = [p for p in c.top if re.match(r"snmp-server group \S+ v3 ", p)]
    if not groups or not all(" v3 priv" in g for g in groups):
        return bad("SNMPv3 groups are not all set to priv (encryption).")
    return ok("SNMPv3 priv groups (verify AES with show snmp user)")


@check("CISC-ND-001150", fix="ntp authentication-key 1 hmac-sha2-256 <KEY>\nntp authenticate\nntp trusted-key 1\nntp server <NTP> key 1")
def nd_ntp_auth(c, x):
    servers = [p for p in c.top if p.startswith("ntp server ")]
    if not servers:
        return bad("No NTP servers configured.")
    probs = []
    if "ntp authenticate" not in c.top:
        probs.append("ntp authenticate missing")
    if not c.has(r"^ntp trusted-key "):
        probs.append("no ntp trusted-key")
    if not c.has(r"^ntp authentication-key \d+ (hmac-sha2-256|hmac-sha2-512|cmac-aes-128|sha2)"):
        probs.append("no SHA-2 ntp authentication-key")
    unkeyed = [s.split()[2] for s in servers if " key " not in s]
    if unkeyed:
        probs.append("servers without a key: " + ", ".join(unkeyed))
    return bad("; ".join(probs)) if probs else ok("NTP authenticated with SHA-2 keys")


@check("CISC-ND-001200", fix="ip ssh version 2\nip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256")
def nd_ssh_mac(c, x):
    m = re.search(r"^ip ssh server algorithm mac (.+)$", c.text, re.M)
    if not m:
        return bad("SSH MAC algorithms are not restricted, so hmac-sha1 is still offered.")
    weak = [a for a in m.group(1).split() if "sha2" not in a]
    return bad("Weak SSH MACs offered: " + ", ".join(weak)) if weak else ok(m.group(1))


@check("CISC-ND-001210", fix="ip ssh server algorithm encryption aes256-ctr aes192-ctr aes128-ctr")
def nd_ssh_enc(c, x):
    m = re.search(r"^ip ssh server algorithm encryption (.+)$", c.text, re.M)
    if not m:
        return bad("SSH ciphers are not restricted.")
    weak = [a for a in m.group(1).split() if not re.match(r"aes(128|192|256)-(ctr|gcm)", a)]
    return bad("Non-FIPS SSH ciphers offered: " + ", ".join(weak)) if weak else ok(m.group(1))


@check("CISC-ND-001260", fix="login on-failure log\nlogin on-success log")
def nd_login_log(c, x):
    missing = [z for z in ("login on-failure log", "login on-success log") if z not in c.top]
    return bad("Missing: " + ", ".join(missing)) if missing else ok()


def _aaa_servers(c):
    n = len([1 for p, k in c.b if re.match(r"(tacacs|radius) server ", p) and any(z.startswith("address ipv4") for z in k)])
    return n + sum(1 for p in c.top if re.match(r"(tacacs|radius)-server host ", p))


@check("CISC-ND-001370", fix="tacacs server TACACS-1\n address ipv4 <IP-1>\n key <KEY>\ntacacs server TACACS-2\n address ipv4 <IP-2>\n key <KEY>\n"
                            "aaa group server tacacs+ TACACS-SERVERS\n server name TACACS-1\n server name TACACS-2\n"
                            "aaa authentication login default group TACACS-SERVERS local")
def nd_aaa_servers(c, x):
    n = _aaa_servers(c)
    if n < 2:
        return bad(f"{n} TACACS+/RADIUS server(s) configured; two or more are required.")
    if not c.has(r"^aaa authentication login \S+ group "):
        return bad("Login authentication does not use the AAA servers first.")
    return ok(f"{n} AAA servers, used first for login")


@check("CISC-ND-001410", fix='event manager applet BACKUP_CONFIG\n event syslog pattern "%SYS-5-CONFIG_I"\n'
                            ' action 1 info type routername\n action 2 cli command "enable"\n'
                            ' action 3 cli command "copy run scp" pattern "remote host"\n'
                            ' action 4 cli command "<SCP-SERVER>" pattern "filename"\n'
                            ' action 5 cli command "$_info_routername-config"')
def nd_backup(c, x):
    ok_ = any(p.startswith("event manager applet") and any("copy run" in z for z in k) for p, k in c.b)
    return ok("EEM applet copies the config on change") if ok_ else bad("No automatic configuration backup on change.")


@check("CISC-ND-001440")
def nd_pki(c, x):
    return manual("Verify each trustpoint enrolls with a DoD-approved CA.") if c.has(r"^crypto pki trustpoint ") \
        else na("No public key certificates (no crypto pki trustpoint).")


@check("CISC-ND-001450", fix="logging host <SYSLOG-1>\nlogging host <SYSLOG-2>")
def nd_syslog(c, x):
    n = sum(1 for p in c.top if re.match(r"logging (host )?\d+\.\d+\.\d+\.\d+", p))
    return ok(f"{n} syslog servers") if n >= 2 else bad(f"{n} syslog server(s); two or more are required.")


@check("CISC-ND-001470")
def nd_release(c, x):
    v = re.search(r"^version (\S+)", c.text, re.M)
    return manual(f"Running {v.group(1) if v else 'an unknown release'}. Confirm with show version that Cisco still supports it.")


# ---------------------------------------------------------------- L2S (switching)
def _need_access(c):
    return None if c.access else na("No active access ports.")


def _ports_missing(c, test, what):
    if (r := _need_access(c)):
        return r
    miss = [n for n, k in c.access.items() if not test(k)]
    return bad(f"Access ports without {what}: " + ", ".join(miss[:8]) + (" …" if len(miss) > 8 else "")) if miss \
        else ok(f"{what} on all {len(c.access)} access ports")


@check("CISC-L2-000020", fix="aaa authentication dot1x default group RADIUS-SERVERS\ndot1x system-auth-control\n"
                            "interface <ACCESS-PORT>\n authentication port-control auto\n mab\n dot1x pae authenticator")
def l2_dot1x(c, x):
    if (r := _need_access(c)):
        return r
    if "dot1x system-auth-control" not in c.top:
        return bad("802.1X is not enabled (dot1x system-auth-control missing).")
    return _ports_missing(c, lambda k: any(re.match(r"(authentication|access-session) port-control auto", z) for z in k), "802.1X/MAB")


@check("CISC-L2-000030", fix="vtp mode off")
def l2_vtp(c, x):
    m = re.search(r"^vtp mode (\S+)", c.text, re.M)
    if m and m.group(1) == "off":
        return ok("VTP off")
    if c.has(r"^vtp password "):
        return ok("VTP password configured")
    return manual(f"VTP mode {m.group(1) if m else 'server (default)'}: verify a password with show vtp password, or set vtp mode off.")


@check("CISC-L2-000040", fix="class-map / policy-map with DSCP-based bandwidth reservations, applied with service-policy output")
def l2_qos(c, x):
    if any(any(z.startswith("service-policy output") for z in k) for k in c.ifs.values()):
        return manual("QoS policy applied; verify it matches the organization's QoS standard.")
    return bad("No QoS policy is applied to interfaces.")


@check("CISC-L2-000090", fix="interface <PORT-TO-ACCESS-SWITCH>\n spanning-tree guard root")
def l2_root_guard(c, x):
    down = x.get("downlinks")
    if down is None:
        guarded = [n for n, k in c.ifs.items() if "spanning-tree guard root" in k]
        return manual("Root Guard on " + ", ".join(guarded) + ". Confirm every port to an access switch is covered." if guarded
                      else "Identify ports that connect to access-layer switches and confirm Root Guard is on.")
    if not down:
        return na("No ports connect to access-layer switches.")
    miss = [n for n in down if "spanning-tree guard root" not in c.ifs.get(n, [])]
    return bad("Root Guard missing on: " + ", ".join(miss)) if miss else ok("Root Guard on " + ", ".join(down))


@check("CISC-L2-000100", fix="interface <ACCESS-PORT>\n spanning-tree bpduguard enable")
def l2_bpdu(c, x):
    if "spanning-tree portfast bpduguard default" in c.top:
        return ok("BPDU Guard enabled globally on PortFast ports")
    return _ports_missing(c, lambda k: "spanning-tree bpduguard enable" in k, "BPDU Guard")


@check("CISC-L2-000110", fix="spanning-tree loopguard default")
def l2_loopguard(c, x):
    return ok() if "spanning-tree loopguard default" in c.top else bad("STP Loop Guard is not enabled globally.")


@check("CISC-L2-000120", fix="interface <ACCESS-PORT>\n switchport block unicast")
def l2_uufb(c, x):
    return _ports_missing(c, lambda k: "switchport block unicast" in k, "Unknown Unicast Flood Blocking")


def _user_vlans(c):
    return {c.access_vlan(k) for k in c.access.values()}


@check("CISC-L2-000130", fix="ip dhcp snooping\nip dhcp snooping vlan <USER-VLANS>")
def l2_dhcp_snoop(c, x):
    if (r := _need_access(c)):
        return r
    m = re.search(r"^ip dhcp snooping vlan (\S+)", c.text, re.M)
    if "ip dhcp snooping" not in c.top or not m:
        return bad("DHCP snooping is not enabled.")
    miss = _user_vlans(c) - vlan_set(m.group(1))
    return bad("User VLANs without DHCP snooping: " + ",".join(map(str, sorted(miss)))) if miss else ok("Snooping on " + m.group(1))


@check("CISC-L2-000140", fix="interface <ACCESS-PORT>\n ip verify source")
def l2_ipsg(c, x):
    return _ports_missing(c, lambda k: any(z.startswith("ip verify source") for z in k), "IP Source Guard")


@check("CISC-L2-000150", fix="ip arp inspection vlan <USER-VLANS>")
def l2_dai(c, x):
    if (r := _need_access(c)):
        return r
    m = re.search(r"^ip arp inspection vlan (\S+)", c.text, re.M)
    if not m:
        return bad("Dynamic ARP Inspection is not enabled.")
    miss = _user_vlans(c) - vlan_set(m.group(1))
    return bad("User VLANs without DAI: " + ",".join(map(str, sorted(miss)))) if miss else ok("DAI on " + m.group(1))


@check("CISC-L2-000160", fix="interface <ACCESS-PORT>\n storm-control broadcast level 5.00")
def l2_storm(c, x):
    return _ports_missing(c, lambda k: any(z.startswith("storm-control broadcast") for z in k), "broadcast storm control")


@check("CISC-L2-000170", fix="ip igmp snooping")
def l2_igmp(c, x):
    off = [p for p in c.top if p.startswith("no ip igmp snooping")]
    return bad("IGMP snooping disabled: " + "; ".join(off)) if off else ok("IGMP snooping on (default)")


@check("CISC-L2-000180", fix="spanning-tree mode rapid-pvst")
def l2_rstp(c, x):
    return ok() if c.has(r"^spanning-tree mode (rapid-pvst|mst)") else bad("Spanning tree is not Rapid PVST+ or MST.")


@check("CISC-L2-000190", fix="udld enable")
def l2_udld(c, x):
    if c.has(r"^udld (enable|aggressive)") or any(any(z.startswith("udld port") for z in k) for k in c.ifs.values()):
        return ok("UDLD enabled")
    return manual("UDLD is off. This is a finding only if the switch has fiber links to neighbors.")


@check("CISC-L2-000200", fix="interface <TRUNK>\n switchport mode trunk\n switchport nonegotiate")
def l2_static_trunks(c, x):
    probs = [f"{n} is in dynamic mode" for n, k in c.ifs.items() if any(z.startswith("switchport mode dynamic") for z in k)]
    probs += [f"trunk {n} still negotiates DTP" for n, k in c.trunks.items() if "switchport nonegotiate" not in k]
    probs += [f"{n} has no switchport mode (defaults to dynamic)" for n, k in c.ifs.items()
              if c.physical(n) and "shutdown" not in k and "no switchport" not in k
              and not any(z.startswith("switchport mode") or z.startswith("vrf forwarding") for z in k)]
    return bad("; ".join(probs[:8])) if probs else ok("No interfaces negotiate trunking")


@check("CISC-L2-000210", fix="interface <UNUSED-PORT>\n switchport mode access\n switchport access vlan <PARKING-VLAN>\n shutdown")
def l2_parking(c, x):
    trunked = set().union(*(c.allowed(k) for k in c.trunks.values())) if c.trunks else set()
    probs = []
    for n, k in c.ifs.items():
        if not c.physical(n) or (k and "shutdown" not in k):
            continue
        if "shutdown" not in k:
            probs.append(f"{n} is unconfigured and not shut down")
            continue
        v = c.access_vlan(k)
        if v == 1 or v in trunked:
            probs.append(f"{n} is parked in VLAN {v}, which is {'the default VLAN' if v == 1 else 'carried on a trunk'}")
    if probs:
        return bad("; ".join(probs[:8]))
    return ok("Unused ports are shut down in an inactive VLAN" if any("shutdown" in k for k in c.ifs.values())
              else "No unused ports in this config. Shut down spare ports and put them in the parking VLAN.")


@check("CISC-L2-000220", fix="interface <ACCESS-PORT>\n switchport access vlan <USER-VLAN>")
def l2_no_vlan1_access(c, x):
    if (r := _need_access(c)):
        return r
    bad_ = [n for n, k in c.access.items() if c.access_vlan(k) == 1]
    return bad("Access ports in VLAN 1: " + ", ".join(bad_)) if bad_ else ok("No access ports in VLAN 1")


@check("CISC-L2-000230", fix="interface <TRUNK>\n switchport trunk allowed vlan <LIST-WITHOUT-1>")
def l2_prune_vlan1(c, x):
    if not c.trunks:
        return na("No trunks.")
    bad_ = [n for n, k in c.trunks.items() if 1 in c.allowed(k)]
    return bad("VLAN 1 allowed on: " + ", ".join(bad_)) if bad_ else ok("VLAN 1 pruned from all trunks")


@check("CISC-L2-000240", fix="interface Vlan1\n no ip address\n shutdown\ninterface Vlan<MGMT>\n ip address <IP> <MASK>")
def l2_mgmt_vlan(c, x):
    k = c.ifs.get("Vlan1", [])
    return bad("Interface Vlan1 has an IP address and is up.") if any(z.startswith("ip address") for z in k) and "shutdown" not in k \
        else ok("VLAN 1 is not used for management")


@check("CISC-L2-000250")
def l2_user_trunks(c, x):
    return manual("Confirm that no user-facing or untrusted ports are trunks: " + (", ".join(c.trunks) or "no trunks configured") + ".")


@check("CISC-L2-000260", fix="interface <TRUNK>\n switchport trunk native vlan <UNUSED-VLAN>")
def l2_native(c, x):
    if not c.trunks:
        return na("No trunks.")
    bad_ = [n for n, k in c.trunks.items() if c.native(k) == 1]
    return bad("Native VLAN 1 on: " + ", ".join(bad_)) if bad_ else ok("Native VLAN is not VLAN 1 on any trunk")


@check("CISC-L2-000270", fix="interface <ACCESS-PORT>\n switchport access vlan <NON-NATIVE-VLAN>")
def l2_access_not_native(c, x):
    natives = {c.native(k) for k in c.trunks.values()}
    bad_ = [n for n, k in c.access.items() if c.access_vlan(k) in natives]
    return bad("Access ports in a native VLAN: " + ", ".join(bad_)) if bad_ else ok("No access ports in the native VLAN")


# ---------------------------------------------------------------- RTR (routing)
@check("CISC-RT-000050", fix="key chain OSPF-KEYS\n key 1\n  key-string <KEY>\n  cryptographic-algorithm hmac-sha-256\n"
                            "  send-lifetime <START> <START+180d>\n  accept-lifetime <START> <START+180d>\n"
                            "interface <IF>\n ip ospf authentication key-chain OSPF-KEYS\n"
                            "key chain BGP-AS<N> tcp\n key 1\n  send-id 1\n  recv-id 1\n  key-string <KEY>\n"
                            "  cryptographic-algorithm hmac-sha-256\n  send-lifetime …\n  accept-lifetime …\n"
                            "router bgp <ASN>\n neighbor <IP> ao BGP-AS<N>")
def rt_routing_auth(c, x):
    probs, seen = [], []
    for proto in ("eigrp", "rip", "isis"):
        if c.has(rf"^router {proto}\b"):
            seen.append(proto.upper())
            probs.append(f"{proto.upper()} cannot use FIPS HMAC keys with a 180-day lifetime; DISA treats it as a permanent finding (use OSPF or BGP)")
    ospf = next(((p, k) for p, k in c.b if p.startswith("router ospf ")), None)
    if ospf:
        seen.append("OSPF")
        pdefault = "passive-interface default" in ospf[1]
        active = {z.split()[-1] for z in ospf[1] if z.startswith("no passive-interface ")}
        passive = {z.split()[-1] for z in ospf[1] if z.startswith("passive-interface ") and z != "passive-interface default"}
        uses_net = any(z.startswith("network ") for z in ospf[1])
        for n, k in c.ifs.items():
            in_ospf = any(re.match(r"ip ospf \d+ area", z) for z in k) or (uses_net and any(z.startswith("ip address ") for z in k))
            if not in_ospf or n.lower().startswith("loopback") or (n in passive) or (pdefault and n not in active):
                continue
            kc = next((z.split()[-1] for z in k if z.startswith("ip ospf authentication key-chain ")), None)
            if kc:
                if (pr := c.chain_problem(kc)):
                    probs.append(f"OSPF on {n}: {pr}")
            elif any(z.startswith("ip ospf message-digest-key") or z == "ip ospf authentication message-digest" for z in k):
                probs.append(f"OSPF on {n} uses MD5, which is not FIPS 198-1")
            else:
                probs.append(f"OSPF on {n} has no authentication")
    b = c.bgp
    if b:
        seen.append("BGP")
        for n in b["nbrs"]:
            o = b["opts"](n)
            ao = next((z.split()[1] for z in o if z.startswith("ao ")), None)
            if ao:
                if (pr := c.chain_problem(ao, tcp=True)):
                    probs.append(f"BGP {n}: {pr}")
            elif any(z.startswith("password ") for z in o):
                probs.append(f"BGP {n} uses an MD5 password; DISA requires TCP-AO (neighbor ao <key chain>)")
            else:
                probs.append(f"BGP {n} has no authentication")
    if not seen:
        return na("No dynamic routing protocols configured.")
    return bad("; ".join(probs)) if probs else ok(" and ".join(seen) + " authenticated with HMAC-SHA keys of 180 days or less")


@check("CISC-RT-000060", fix="interface <UNUSED-IF>\n shutdown")
def rt_inactive(c, x):
    idle = [n for n, k in c.ifs.items() if c.physical(n) and "shutdown" not in k and not [z for z in k if not z.startswith("description")]]
    return bad("Unconfigured interfaces that are not shut down: " + ", ".join(idle[:8])) if idle else ok("No idle interfaces left enabled")


@check("CISC-RT-000090", fix="no service config\nno boot network\nno cns config initial\nno cns exec")
def rt_zero_touch(c, x):
    found = [p for p in c.top if re.match(r"(service config|boot network|cns )", p)]
    return bad("Auto-configuration enabled: " + "; ".join(found)) if found else ok("No auto-configuration or zero-touch features")


@check("CISC-RT-000120", fix="Routers: class-maps, a policy-map with policers, then\ncontrol-plane\n service-policy input COPP\n"
                            "Catalyst switches: tune policy-map system-cpp-policy rates")
def rt_copp(c, x):
    if x.get("platform") != "router":
        if "policy-map system-cpp-policy" in c.top or x.get("generated"):
            return ok("system-cpp-policy (built into Catalyst 9000). Verify rates with show policy-map control-plane.")
        return bad("policy-map system-cpp-policy is not in the running config.")
    cp = next((k for p, k in c.b if p == "control-plane"), [])
    return ok("Control-plane policy applied. Verify policer rates against organization standards.") \
        if any(z.startswith("service-policy input") for z in cp) else bad("No control-plane policing (CoPP) policy applied.")


@check("CISC-RT-000150", fix="no ip gratuitous-arps")
def rt_garp(c, x):
    return bad("ip gratuitous-arps is enabled.") if "ip gratuitous-arps" in c.top else ok()


@check("CISC-RT-000160", fix="interface <IF>\n no ip directed-broadcast")
def rt_directed(c, x):
    bad_ = [n for n, k in c.ifs.items() if "ip directed-broadcast" in k]
    return bad("Directed broadcast on: " + ", ".join(bad_)) if bad_ else ok()


def _edge_ifs(c, x):
    ext = x.get("external")
    if ext is None:  # unknown: hold every addressed interface to the external standard
        return [n for n, k in c.ifs.items() if any(z.startswith("ip address ") for z in k)], " (external interfaces unknown, so every addressed interface was checked)"
    return ext, ""


@check("CISC-RT-000170", fix="interface <EXTERNAL-IF>\n no ip unreachables\ninterface Null0\n no ip unreachables")
def rt_unreach(c, x):
    ifs, note = _edge_ifs(c, x)
    if c.has(r"^ip route .* Null0"):
        ifs = ifs + ["Null0"]
    if not ifs:
        return na("No external interfaces and no Null0 routes.")
    bad_ = [n for n in ifs if "no ip unreachables" not in c.ifs.get(n, [])]
    return bad("ICMP unreachables still sent from: " + ", ".join(bad_) + note) if bad_ else ok("Unreachables disabled" + note)


@check("CISC-RT-000180", fix="interface <EXTERNAL-IF>\n no ip mask-reply")
def rt_mask(c, x):
    ifs, note = _edge_ifs(c, x)
    if not ifs:
        return na("No external interfaces.")
    bad_ = [n for n in ifs if "ip mask-reply" in c.ifs.get(n, [])]
    return bad("ip mask-reply on: " + ", ".join(bad_)) if bad_ else ok("Mask replies off (default)" + note)


@check("CISC-RT-000190", fix="interface <EXTERNAL-IF>\n no ip redirects")
def rt_redirects(c, x):
    ifs, note = _edge_ifs(c, x)
    if not ifs:
        return na("No external interfaces.")
    bad_ = [n for n in ifs if "no ip redirects" not in c.ifs.get(n, [])]
    return bad("ICMP redirects still sent from: " + ", ".join(bad_) + note) if bad_ else ok("Redirects disabled" + note)


@check("CISC-RT-000230", fix="line aux 0\n no exec\n transport input none")
def rt_aux(c, x):
    aux = next((k for p, k in c.b if p.startswith("line aux")), None)
    if aux is None:
        return na("No auxiliary port in this configuration.")
    return ok("Aux port disabled") if "no exec" in aux else bad("Auxiliary port allows exec sessions.")


@check("CISC-RT-000235", fix="ip cef")
def rt_cef(c, x):
    return bad("CEF is disabled.") if "no ip cef" in c.top else ok("CEF enabled (default)")


@check("CISC-RT-000236")
def rt_ra_hops(c, x):
    return manual("IPv6 routing is enabled; verify the RA hop limit is at least 32.") if c.has(r"^ipv6 unicast-routing") \
        else na("IPv6 routing is not enabled.")


@check("CISC-RT-000237", fix="Remove FEC0::/10 site-local addresses")
def rt_site_local(c, x):
    return bad("IPv6 site-local (FEC0::/10) addresses configured.") if re.search(r"ipv6 address fec[0-9a-f]:", c.text, re.I) else ok()


def _perimeter(fn):
    """Perimeter rules need to know which interfaces are external."""
    def wrapped(c, x):
        ext = x.get("external")
        if ext is None:
            return manual("Mark the external interfaces in OneConfig to check this automatically.")
        if not ext:
            return na("Not a perimeter device (no external interfaces).")
        return fn(c, x, ext)
    return wrapped


def _ext_acl(c, n, d="in"):
    a = c.acl_on(c.ifs.get(n, []), d)
    return a, c.acls.get(a, []) if a else []


@check("CISC-RT-000240", fix="ip access-list extended EXTERNAL-IN\n permit <ALLOWED-TRAFFIC>\n deny ip any any log-input\n"
                            "interface <EXTERNAL-IF>\n ip access-group EXTERNAL-IN in")
@_perimeter
def rt_default_deny(c, x, ext):
    probs = []
    for n in ext:
        a, e = _ext_acl(c, n)
        if not a:
            probs.append(f"{n} has no inbound ACL")
        elif not e or not re.match(r"deny\s+ip\s+any\s+any", e[-1]):
            probs.append(f"{a} on {n} does not end with deny ip any any")
    return bad("; ".join(probs)) if probs else ok("Inbound ACLs on external interfaces deny by default")


@check("CISC-RT-000270", fix="ip access-list extended EXTERNAL-IN\n deny ip <BOGON> <WILDCARD> any log-input  (each DISA bogon prefix)")
@_perimeter
def rt_bogon_acl(c, x, ext):
    probs = []
    for n in ext:
        a, e = _ext_acl(c, n)
        if not a:
            probs.append(f"{n} has no inbound ACL")
            continue
        miss = _covered(ACL_BOGONS, _acl_denies(e))
        if miss:
            probs.append(f"{a} doesn't block " + ", ".join(map(str, miss)))
    return bad("; ".join(probs)) if probs else ok("All DISA bogon source prefixes blocked")


@check("CISC-RT-000310", fix="interface <INTERNAL-IF>\n ip verify unicast source reachable-via rx")
@_perimeter
def rt_urpf(c, x, ext):
    internal = x.get("internal") or []
    bad_ = [n for n in internal if not any(z.startswith("ip verify unicast source") for z in c.ifs.get(n, []))
            and not c.acl_on(c.ifs.get(n, []), "in")]
    return bad("Internal interfaces without uRPF or an egress filter: " + ", ".join(bad_)) if bad_ \
        else ok("uRPF or egress filtering on internal interfaces" if internal else "No internal routed interfaces")


@check("CISC-RT-000330", fix="interface <EXTERNAL-IF>\n ip access-group EXTERNAL-IN in")
@_perimeter
def rt_ingress(c, x, ext):
    bad_ = [n for n in ext if not _ext_acl(c, n)[0]]
    return bad("No inbound ACL on: " + ", ".join(bad_)) if bad_ else ok("Inbound ACL on every external interface")


@check("CISC-RT-000340", fix="interface <INTERNAL-IF>\n ip access-group EGRESS-FILTER in")
@_perimeter
def rt_egress(c, x, ext):
    internal = x.get("internal") or []
    bad_ = [n for n in internal if not c.acl_on(c.ifs.get(n, []), "in")]
    return bad("No inbound egress filter on: " + ", ".join(bad_)) if bad_ else ok("Egress filters on internal interfaces")


@check("CISC-RT-000350", fix="ip access-list extended EXTERNAL-IN\n 5 deny ip any any option any-options")
@_perimeter
def rt_ip_options(c, x, ext):
    if c.has(r"^ip options drop"):
        return ok("ip options drop")
    bad_ = [n for n in ext if not any(re.match(r"deny\s+ip\s+any\s+any\s+option\s+any-options", e) for e in _ext_acl(c, n)[1])]
    return bad("IP options not dropped on: " + ", ".join(bad_)) if bad_ else ok("Packets with IP options dropped")


@check("CISC-RT-000360", fix="interface <EXTERNAL-IF>\n no lldp transmit")
@_perimeter
def rt_lldp(c, x, ext):
    if "lldp run" not in c.top:
        return ok("LLDP disabled globally")
    bad_ = [n for n in ext if "no lldp transmit" not in c.ifs.get(n, [])]
    return bad("LLDP transmit on: " + ", ".join(bad_)) if bad_ else ok("LLDP off on external interfaces")


@check("CISC-RT-000370", fix="interface <EXTERNAL-IF>\n no cdp enable")
@_perimeter
def rt_cdp(c, x, ext):
    if "no cdp run" in c.top:
        return ok("CDP disabled globally")
    bad_ = [n for n in ext if "no cdp enable" not in c.ifs.get(n, [])]
    return bad("CDP on: " + ", ".join(bad_)) if bad_ else ok("CDP off on external interfaces")


@check("CISC-RT-000380", fix="interface <EXTERNAL-IF>\n no ip proxy-arp")
@_perimeter
def rt_proxy_arp(c, x, ext):
    bad_ = [n for n in ext if "no ip proxy-arp" not in c.ifs.get(n, [])]
    return bad("Proxy ARP on: " + ", ".join(bad_)) if bad_ else ok("Proxy ARP off on external interfaces")


MGMT_PORTS = ("tacacs", "22", "snmp", "snmptrap", "syslog")


@check("CISC-RT-000390", fix="ip access-list extended EXTERNAL-OUT\n deny tcp any any eq tacacs log-input\n deny tcp any any eq 22 log-input\n"
                            " deny udp any any eq snmp log-input\n deny udp any any eq snmptrap log-input\n deny udp any any eq syslog log-input\n"
                            " permit ip any any\ninterface <EXTERNAL-IF>\n ip access-group EXTERNAL-OUT out")
@_perimeter
def rt_mgmt_out(c, x, ext):
    probs = []
    for n in ext:
        a, e = _ext_acl(c, n, "out")
        if not a:
            probs.append(f"{n} has no outbound ACL")
            continue
        miss = [p for p in MGMT_PORTS if not any(z.startswith("deny") and f"eq {p}" in z for z in e)]
        if miss:
            probs.append(f"{a} doesn't block " + ", ".join(miss))
    return bad("; ".join(probs)) if probs else ok("Management traffic blocked outbound")


def _v6_perimeter(c, x, ext):
    if not any(any(z.startswith("ipv6 ") for z in c.ifs.get(n, [])) for n in ext):
        return na("IPv6 is not enabled on external interfaces.")
    return manual("IPv6 is enabled on an external interface; review the IPv6 filtering rules.")


for _id in ("CISC-RT-000391", "CISC-RT-000392", "CISC-RT-000393", "CISC-RT-000394", "CISC-RT-000395",
            "CISC-RT-000396", "CISC-RT-000397", "CISC-RT-000398"):
    check(_id)(_perimeter(_v6_perimeter))


def _needs_bgp(fn):
    def wrapped(c, x):
        return fn(c, x, c.bgp) if c.bgp else na("BGP is not configured.")
    return wrapped


def _ebgp(b):
    return [n for n, a in b["nbrs"].items() if a != b["asn"]]


@check("CISC-RT-000470", fix="router bgp <ASN>\n neighbor <EBGP-PEER> ttl-security hops 1")
@_needs_bgp
def rt_gtsm(c, x, b):
    e = _ebgp(b)
    if not e:
        return na("No eBGP neighbors.")
    bad_ = [n for n in e if not any(z.startswith("ttl-security") for z in b["opts"](n))]
    return bad("No GTSM on: " + ", ".join(bad_)) if bad_ else ok("GTSM on all eBGP neighbors")


@check("CISC-RT-000480", fix="Use a separate key chain or password for each peer AS")
@_needs_bgp
def rt_unique_keys(c, x, b):
    keys = {}
    for n, asn in b["nbrs"].items():
        k = next((z for z in b["opts"](n) if z.startswith(("ao ", "password "))), None)
        if k:
            keys.setdefault(k, set()).add(asn)
    shared = [k.split()[1] for k, ases in keys.items() if len(ases) > 1]
    return bad("Key shared across autonomous systems: " + ", ".join(shared)) if shared else ok("Each peer AS uses its own key")


def _in_filter(b, n):
    return next((z.split()[1] for z in b["opts"](n) if re.match(r"prefix-list \S+ in$", z)), None)


@check("CISC-RT-000490", fix="ip prefix-list BGP-IN deny <BOGON> le 32  (each DISA bogon)\nip prefix-list BGP-IN permit 0.0.0.0/0 ge 8 le 24\n"
                            "router bgp <ASN>\n address-family ipv4\n  neighbor <EBGP-PEER> prefix-list BGP-IN in")
@_needs_bgp
def rt_bgp_bogons(c, x, b):
    e = _ebgp(b)
    if not e:
        return na("No eBGP neighbors.")
    probs = []
    for n in e:
        pl = _in_filter(b, n)
        if not pl:
            probs.append(f"{n} has no inbound prefix-list")
            continue
        miss = _covered(BGP_BOGONS, [net for act, net, _ in c.prefix_list(pl) if act == "deny"])
        if miss:
            probs.append(f"{pl} doesn't reject " + ", ".join(map(str, miss)))
    return bad("; ".join(probs)) if probs else ok("Bogon prefixes rejected from all eBGP peers")


@check("CISC-RT-000500", fix="ip prefix-list BGP-IN deny <LOCAL-PREFIX> le 32")
@_needs_bgp
def rt_bgp_own(c, x, b):
    e, own = _ebgp(b), [n for n in b["networks"] if n]
    if not e:
        return na("No eBGP neighbors.")
    if not own:
        return manual("No locally originated prefixes in the BGP config; confirm the local AS's address space is filtered inbound.")
    probs = []
    for n in e:
        pl = _in_filter(b, n)
        miss = _covered(own, [net for act, net, _ in c.prefix_list(pl) if act == "deny"]) if pl else own
        if miss:
            probs.append(f"{n} accepts the local prefixes " + ", ".join(map(str, miss)))
    return bad("; ".join(probs)) if probs else ok("Local AS prefixes rejected inbound")


@check("CISC-RT-000520", fix="ip prefix-list BGP-OUT permit <LOCAL-PREFIX>\nrouter bgp <ASN>\n address-family ipv4\n  neighbor <EBGP-PEER> prefix-list BGP-OUT out")
@_needs_bgp
def rt_bgp_out(c, x, b):
    e = _ebgp(b)
    if not e:
        return na("No eBGP neighbors.")
    bad_ = [n for n in e if not any(re.match(r"(prefix-list|route-map) \S+ out$", z) for z in b["opts"](n))]
    return bad("No outbound filter on: " + ", ".join(bad_)) if bad_ else ok("Outbound advertisements filtered")


@check("CISC-RT-000540", fix="router bgp <ASN>\n bgp enforce-first-as")
@_needs_bgp
def rt_first_as(c, x, b):
    return bad("bgp enforce-first-as is disabled.") if "no bgp enforce-first-as" in b["kids"] else ok("enforce-first-as on (default)")


@check("CISC-RT-000560", fix="router bgp <ASN>\n neighbor <EBGP-PEER> maximum-prefix <N>")
@_needs_bgp
def rt_max_prefix(c, x, b):
    e = _ebgp(b)
    if not e:
        return na("No eBGP neighbors.")
    bad_ = [n for n in e if not any(z.startswith("maximum-prefix") for z in b["opts"](n))]
    return bad("No maximum-prefix on: " + ", ".join(bad_)) if bad_ else ok("maximum-prefix on all eBGP neighbors")


@check("CISC-RT-000570", fix="ip prefix-list BGP-IN permit 0.0.0.0/0 ge 8 le 24\n(and apply it inbound to each eBGP neighbor)")
@_needs_bgp
def rt_prefix_len(c, x, b):
    e = _ebgp(b)
    if not e:
        return na("No eBGP neighbors.")
    probs = []
    for n in e:
        pl = _in_filter(b, n)
        permits = [o for act, _, o in c.prefix_list(pl) if act == "permit"] if pl else None
        if not pl:
            probs.append(f"{n} has no inbound prefix-list")
        elif not permits or any(not re.search(r"le (\d+)", o) or int(re.search(r"le (\d+)", o).group(1)) > 24 for o in permits):
            probs.append(f"{pl} permits prefixes longer than /24")
    return bad("; ".join(probs)) if probs else ok("Inbound prefixes limited to /24")


@check("CISC-RT-000580", fix="router bgp <ASN>\n neighbor <IBGP-PEER> update-source Loopback0")
@_needs_bgp
def rt_ibgp_loopback(c, x, b):
    i = [n for n, a in b["nbrs"].items() if a == b["asn"]]
    if not i:
        return na("No iBGP neighbors.")
    bad_ = [n for n in i if not any(re.match(r"update-source loopback", z, re.I) for z in b["opts"](n))]
    return bad("iBGP without loopback source: " + ", ".join(bad_)) if bad_ else ok("iBGP sourced from loopback")


def _feature_gate(pattern, absent):
    def fn(c, x):
        return manual("Feature is in use; review this rule manually.") if re.search(pattern, c.text, re.M | re.I) else na(absent)
    return fn


_gates = {
    ("590", "600", "610", "620"): (r"^[ \t]*mpls ", "MPLS is not configured."),
    tuple(str(n) for n in range(630, 790, 10)): (r"^(vrf definition|ip vrf|[ \t]*mpls )", "Not a PE router (no VRFs or MPLS)."),
    tuple(str(n) for n in range(790, 900, 10)): (r"^(ip multicast-routing|[ \t]*ip pim )", "Multicast routing is not enabled."),
    tuple(str(n) for n in range(900, 960, 10)): (r"^ip msdp ", "MSDP is not configured."),
}
for _nums, (_pat, _why) in _gates.items():
    for _n in _nums:
        check(f"CISC-RT-000{_n}")(_feature_gate(_pat, _why))


# ---------------------------------------------------------------- report
MANUAL_WHY = {
    "CISC-RT-000010": "Verify routing and ACL policy matches the organization's information flow control policy.",
    "CISC-RT-000250": "Verify the perimeter ACLs match the approved interconnection policy.",
    "CISC-RT-000260": "Verify inbound perimeter rules permit only authorized sources to authorized destinations.",
    "CISC-RT-000280": "Applies only to an enclave connected to an alternate gateway.",
    "CISC-RT-000290": "Applies only to an enclave connected to an alternate gateway.",
    "CISC-RT-000300": "Applies only to an enclave connected to an alternate gateway.",
    "CISC-RT-000320": "Verify inbound filtering follows DoD Instruction 8551.1 (PPSM).",
    "CISC-RT-000510": "Applies to provider routers peering with customer edge (CE) routers.",
    "CISC-RT-000530": "Applies to provider routers that must hide IP core prefixes.",
    "CISC-RT-000550": "Applies to provider routers peering with customer edge (CE) routers.",
    **{f"CISC-RT-000{n}": "Applies only to an out-of-band management (OOBM) gateway router." for n in (400, 410, 420, 430, 440, 450, 460)},
}
def stig_audit(cfg: str, platform: str, ctx: dict | None = None, nos: str = "ios-xe") -> dict:
    """platform is the device role (router / l3switch / switch / firewall); nos is the operating system."""
    if nos not in BENCHMARKS:
        raise ValueError(f"OS must be one of {', '.join(BENCHMARKS)}")
    if platform not in BENCHMARKS[nos]:
        raise ValueError(f"for {nos}, the role must be one of {', '.join(BENCHMARKS[nos])}")
    checks, why = _registry()[nos]
    c = _registry()[f"{nos}-parser"](cfg) if nos in ("junos", "asa", "panos", "fortios") else Cfg(cfg)
    x = {"platform": platform, **(ctx or {})}
    results, benches = [], []
    for bid in BENCHMARKS[nos][platform]:
        b = BENCH[bid]
        benches.append({"id": bid, "file": b["file"], "version": b["version"], "release": b["release"]})
        for stig_id, vuln, rule, sev, title in b["rules"]:
            fix = ""
            if platform == "switch" and bid.endswith("_RTR"):
                status, detail = na("Layer 2 switch with no routing functions.")
            elif stig_id in checks:
                fn, fix = checks[stig_id]
                status, detail = fn(c, x)
            else:
                status, detail = manual(why.get(stig_id, "Needs a manual review (organization policy or network design)."))
            results.append({"stig": bid, "id": stig_id, "vuln": vuln, "rule": rule, "cat": CAT[sev], "title": title,
                            "status": status, "detail": detail, "fix": fix if status == FAIL else ""})
    count = lambda s: sum(r["status"] == s for r in results)  # noqa: E731
    passed, failed = count(PASS), count(FAIL)
    return {
        "platform": platform, "os": nos, "benchmarks": benches, "results": results,
        "summary": {"open": {cat: sum(r["status"] == FAIL and r["cat"] == cat for r in results) for cat in CAT.values()},
                    PASS: passed, NA: count(NA), MANUAL: count(MANUAL),
                    "compliance": round(100 * passed / (passed + failed)) if passed + failed else 100},
    }


def _registry():
    """Checks per OS. Built on first use because the per-OS modules import this one, so any of them can load first."""
    global _REG
    if not _REG:
        from . import stig_asa, stig_eos, stig_fortios, stig_junos, stig_nxos, stig_panos
        _REG = {"ios-xe": (CHECKS, MANUAL_WHY), "nx-os": (stig_nxos.CHECKS, stig_nxos.MANUAL_WHY),
                "eos": (stig_eos.CHECKS, stig_eos.MANUAL_WHY), "junos": (stig_junos.CHECKS, stig_junos.MANUAL_WHY),
                "asa": (stig_asa.CHECKS, stig_asa.MANUAL_WHY), "panos": (stig_panos.CHECKS, stig_panos.MANUAL_WHY),
                "fortios": (stig_fortios.CHECKS, stig_fortios.MANUAL_WHY), "fortios-parser": stig_fortios.Fos,
                "junos-parser": stig_junos.J, "asa-parser": stig_asa.Asa, "panos-parser": stig_panos.Pan}
    return _REG


_REG = None


def __getattr__(name):  # `from oneconfig.stig import REGISTRY` keeps working
    if name == "REGISTRY":
        return {k: v for k, v in _registry().items() if not k.endswith("-parser")}
    raise AttributeError(name)
