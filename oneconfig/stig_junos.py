"""DISA STIG checks for Juniper Junos: Juniper Router NDM V3R2 / RTR V3R2 (role router) and Juniper EX Series
Switches NDM V2R5 / L2S V2R5 / RTR V2R1 (roles l3switch and switch). Rule IDs are JUNI-* and JUEX-*.

Checks read the configuration in `display set` form. A pasted `show configuration` (braces) is flattened first."""
import re
from datetime import date, datetime
from functools import cached_property
from ipaddress import IPv4Network

from .stig import ACL_BOGONS, _covered, _feature_gate, _perimeter, bad, manual, na, ok

CHECKS, MANUAL_WHY = {}, {}


def check(*ids, fix=""):
    def deco(fn):
        for i in ids:
            CHECKS[i] = (fn, fix)
        return fn
    return deco


def flatten(text: str) -> list[str]:
    """`show configuration` (braces) -> display-set statements without the leading "set ". Lines already in set form
    pass through. Inactive statements and comments are dropped."""
    if re.search(r"^[ \t]*set\s", text, re.M):
        return [l.strip()[4:] for l in text.splitlines() if l.strip().startswith("set ")]
    out, path = [], []
    # An unclosed quote ends at its line and an unclosed comment at the end of the text: retrying the scan from every
    # character after one made a broken config take quadratic time.
    toks = []
    for m in re.finditer(r'"(?:\\.|[^"\\\n])*(")?(?:(?=\n)|\Z)?|/\*.*?(?:\*/|\Z)|#[^\n]*|[{};\[\]]|[^\s{};\[\]"]+', text, re.S):
        if m[0].startswith('"') and not m[1]:  # unclosed: its value and its statement end at the first ; { or }
            toks += [re.split(r"[;{}]", m[0])[0], ";"]
        else:
            toks.append(m[0])
    words, inlist = [], None
    for t in toks:
        if t.startswith(("/*", "#")):
            continue
        if t == "{":
            path.append(words); words = []
        elif t == "}":
            if path:
                path.pop()
        elif t == "[":
            inlist = []
        elif t == "]":
            words.append(inlist); inlist = None
        elif t == ";":
            lists = [w for w in words if isinstance(w, list)]
            flat = [w for w in words if not isinstance(w, list)]
            full = [x for p in path for x in p] + flat
            if not any(str(w).startswith("inactive:") for p in path for w in p) and not str(words[0] if words else "").startswith("inactive:"):
                for item in (lists[0] if lists else [None]):
                    out.append(" ".join(full + ([item] if item else [])))
            words = []
        elif inlist is not None:
            inlist.append(t)
        else:
            words.append(t)
    return [re.sub(r"^(\S+ )*?protect: ", "", l) for l in out if l]


class J:
    """A Junos configuration as display-set statements."""

    def __init__(self, text: str):
        self.lines = flatten(text or "")
        self.text = "\n".join("set " + l for l in self.lines)

    def has(self, rx):
        return any(re.match(rx, l) for l in self.lines)

    def find(self, rx):
        return [m for l in self.lines if (m := re.match(rx, l))]

    def under(self, prefix):
        """Tails of every statement below a hierarchy prefix, e.g. under('system services ssh')."""
        p = prefix + " "
        return [l[len(p):] for l in self.lines if l.startswith(p)]

    # ---------------------------------------------------------------- structure
    @cached_property
    def ifs(self) -> dict:
        """Physical interface -> statements below it (irb units appear as irb.N)."""
        out = {}
        for m in self.find(r"interfaces (\S+) (.*)$"):
            name, rest = m.groups()
            u = re.match(r"unit (\d+) (.*)$", rest)
            if name == "irb" and u:
                out.setdefault(f"irb.{u.group(1)}", []).append(f"unit {u.group(1)} {u.group(2)}")
            elif name != "interface-range":
                out.setdefault(name, []).append(rest)
        for m in self.find(r"interfaces (\S+)$"):
            out.setdefault(m.group(1), [])
        return out

    def inet(self, name):
        """`family inet` statements of an interface's main unit (unit 0, or the irb unit)."""
        u = name.split(".")[1] if name.startswith("irb.") else "0"
        p = f"unit {u} family inet "
        return [z[len(p):] for z in self.ifs.get(name, []) if z.startswith(p)]

    def if_filters(self, name, direction="input"):
        out = []
        for z in self.inet(name):
            m = re.match(rf"filter {direction}(-list)? (\S+)$", z)
            if m:
                out.append(m.group(2))
        return out

    @cached_property
    def filters(self) -> dict:
        """Filter -> {term: {"from": [...], "then": [...]}} in configuration order."""
        out = {}
        for m in self.find(r"firewall (?:family inet )?filter (\S+) term (\S+)(?: (from|then) (.*))?$"):
            f, t, kind, rest = m.groups()
            term = out.setdefault(f, {}).setdefault(t, {"from": [], "then": []})
            if kind:
                term[kind].append(rest)
        return out

    @cached_property
    def prefix_lists(self) -> dict:
        out = {}
        for m in self.find(r"policy-options prefix-list (\S+) (\S+)$"):
            try:
                out.setdefault(m.group(1), []).append(IPv4Network(m.group(2), strict=False))
            except ValueError:
                pass
        return out

    @cached_property
    def policies(self) -> dict:
        out = {}
        for m in self.find(r"policy-options policy-statement (\S+) (?:term (\S+) )?(from|then) (.*)$"):
            p, t, kind, rest = m.groups()
            out.setdefault(p, {}).setdefault(t or "", {"from": [], "then": []})[kind].append(rest)
        return out

    @cached_property
    def bgp(self):
        if not self.has(r"protocols bgp "):
            return None
        groups = {}
        for m in self.find(r"protocols bgp group (\S+) (.*)$"):
            g, rest = m.groups()
            grp = groups.setdefault(g, {"opts": [], "nbrs": {}})
            n = re.match(r"neighbor (\S+)(?: (.*))?$", rest)
            if n:
                grp["nbrs"].setdefault(n.group(1), []).append(n.group(2) or "")
            else:
                grp["opts"].append(rest)
        asn = next((m.group(1) for m in self.find(r"routing-options autonomous-system (\d+)")), None)
        return {"asn": asn, "groups": groups, "global": self.under("protocols bgp")}

    def bgp_peers(self, external=None):
        """[(group, neighbor ip, group options + neighbor options)]"""
        b, out = self.bgp, []
        for g, grp in (b["groups"] if b else {}).items():
            typ = next((o.split()[1] for o in grp["opts"] if o.startswith("type ")), "external")
            if external is not None and (typ == "external") != external:
                continue
            for ip, opts in grp["nbrs"].items():
                out.append((g, ip, grp["opts"] + [o for o in opts if o]))
        return out

    @cached_property
    def ospf_ifs(self) -> dict:
        out = {}
        for m in self.find(r"protocols ospf area (\S+) interface (\S+)(?: (.*))?$"):
            out.setdefault(m.group(2), []).append(m.group(3) or "")
        return out

    @cached_property
    def keychains(self) -> dict:
        out = {}
        for m in self.find(r"security authentication-key-chains key-chain (\S+) key (\d+) (\S+) (.*)$"):
            out.setdefault(m.group(1), {}).setdefault(m.group(2), {})[m.group(3)] = m.group(4).strip('"')
        return out

    def syslog(self, kind):
        """{host or file name: [facility level ...]} for kind 'host' or 'file'."""
        out = {}
        for m in self.find(rf"system syslog {kind} (\S+) (.*)$"):
            out.setdefault(m.group(1), []).append(m.group(2))
        return out

    @cached_property
    def users(self):
        out = {}
        for m in self.find(r"system login user (\S+)(?: (.*))?$"):
            out.setdefault(m.group(1), []).append(m.group(2) or "")
        return out

    @cached_property
    def classes(self):
        out = {}
        for m in self.find(r"system login class (\S+)(?: (.*))?$"):
            out.setdefault(m.group(1), []).append(m.group(2) or "")
        return out


# ---------------------------------------------------------------- shared helpers
def _logs(c, facility, kinds=("host", "file")):
    """Syslog destinations recording a facility at info or more detail (or everything via 'any')."""
    levels = ("any", "info", "debug")
    hit = []
    for kind in kinds:
        for name, ents in c.syslog(kind).items():
            if any(re.match(rf"({facility}|any) ({'|'.join(levels)})$", e) for e in ents):
                hit.append(f"{kind} {name}")
    return hit


def _need_log(facility, what):
    def fn(c, x):
        hit = _logs(c, facility)
        return ok(f"{what}: " + ", ".join(hit)) if hit else bad(f"No syslog file or host records {facility} events at info level.")
    return fn


def _terms(c, filters):
    return [(f, t, d) for f in filters for t, d in c.filters.get(f, {}).items()]


def _discards(d):
    return any(t in ("discard", "reject") for t in d["then"])


def _last_denies(c, filters):
    """Does the last filter in the chain end with a term that matches everything and drops it?"""
    if not filters or filters[-1] not in c.filters:
        return False
    terms = list(c.filters[filters[-1]].values())
    return bool(terms) and not terms[-1]["from"] and _discards(terms[-1])


def _service(c, svc):
    return c.has(rf"system services {svc}( |$)")


# ---------------------------------------------------------------- NDM
@check("JUNI-ND-000010", "JUEX-NM-000010", fix="set system services ssh connection-limit 3\nset system services ssh max-sessions-per-connection 1")
def nd_sessions(c, x):
    m = c.find(r"system services ssh connection-limit (\d+)")
    return ok(f"ssh connection-limit {m[0].group(1)}") if m else bad("SSH sessions are not limited (system services ssh connection-limit).")


_CHANGE = ("JUNI-ND-000090", "JUNI-ND-000100", "JUNI-ND-000110", "JUNI-ND-000120", "JUNI-ND-000210", "JUNI-ND-000330",
           "JUNI-ND-000870", "JUNI-ND-001230", "JUNI-ND-001240", "JUEX-NM-000020")
check(*_CHANGE, fix="set system syslog file messages change-log info\nset system syslog host <SYSLOG> any info")(
    _need_log("change-log", "Configuration changes are logged to"))
check("JUNI-ND-000250", "JUNI-ND-001250", "JUNI-ND-001280", "JUEX-NM-000560", "JUEX-NM-000590",
      fix="set system syslog file messages authorization info")(_need_log("authorization", "Logons are logged to"))
check("JUNI-ND-000930", "JUNI-ND-001260", "JUEX-NM-000570",
      fix="set system syslog file messages interactive-commands info\nset system syslog file messages change-log info")(
    _need_log("interactive-commands", "Commands are logged to"))


def _re_filter_restricts(c, port):
    """The lo0 input filter accepts `port` only from listed sources and drops it from everyone else."""
    accept_limited = drop = False
    for f, t, d in _terms(c, c.if_filters("lo0")):
        hits = any(re.match(rf"(destination-)?port {port}$", z) for z in d["from"])
        sourced = any(z.startswith(("source-address", "source-prefix-list")) for z in d["from"])
        if hits and sourced and "accept" in d["then"]:
            accept_limited = True
        elif (hits and _discards(d)) or (not d["from"] and _discards(d)):
            drop = accept_limited
        elif hits and "accept" in d["then"] and not accept_limited:
            return False  # accepted from anywhere before any restriction
    return accept_limited and drop


@check("JUNI-ND-000140", "JUEX-NM-000070",
       fix="set policy-options prefix-list MGMT-NET <MGMT-NET>/<LEN>\n"
           "set firewall family inet filter PROTECT-RE term SSH from source-prefix-list MGMT-NET\n"
           "set firewall family inet filter PROTECT-RE term SSH from protocol tcp\n"
           "set firewall family inet filter PROTECT-RE term SSH from destination-port ssh\n"
           "set firewall family inet filter PROTECT-RE term SSH then accept\n"
           "set firewall family inet filter PROTECT-RE term DENY-SSH from protocol tcp\n"
           "set firewall family inet filter PROTECT-RE term DENY-SSH from destination-port ssh\n"
           "set firewall family inet filter PROTECT-RE term DENY-SSH then syslog\n"
           "set firewall family inet filter PROTECT-RE term DENY-SSH then discard\n"
           "set interfaces lo0 unit 0 family inet filter input PROTECT-RE")
def nd_mgmt_filter(c, x):
    if not c.if_filters("lo0"):
        return bad("lo0 has no input filter, so anyone who can reach the device can try to log in.")
    return ok("lo0 filter: SSH only from listed sources") if _re_filter_restricts(c, "ssh") else \
        bad("The lo0 filter does not limit SSH to management sources and drop the rest.")


@check("JUNI-ND-000150", "JUEX-NM-000080", fix="set system login retry-options tries-before-disconnect 3\nset system login retry-options lockout-period 15")
def nd_lockout(c, x):
    tries = c.find(r"system login retry-options tries-before-disconnect (\d+)")
    lock = c.find(r"system login retry-options lockout-period (\d+)")
    if tries and int(tries[0].group(1)) <= 3 and lock and int(lock[0].group(1)) >= 15:
        return ok(f"{tries[0].group(1)} tries, {lock[0].group(1)} minute lockout")
    return bad("Logins are not locked for 15 minutes after 3 failed attempts.")


@check("JUNI-ND-000160", "JUEX-NM-000090", fix='set system login message "<Standard Mandatory DoD Notice and Consent Banner>"\n'
                                              "(Or turn on the DoD banner in OneConfig's Security settings.)")
def nd_banner(c, x):
    m = c.find(r'system login message (.*)$')
    if not m:
        return bad("No login message configured.")
    t = m[0].group(1)
    return ok("Standard Mandatory DoD Notice and Consent Banner present") if "USG-authorized use only" in t and \
        "See User Agreement for details" in t else bad("A login message is configured, but it is not the DoD Notice and Consent Banner.")


def _class_denies(c, kind, text):
    return [n for n, k in c.classes.items() if any(z.startswith(f"{kind}") and text in z for z in k)]


@check("JUNI-ND-000380", "JUEX-NM-000190", "JUEX-NM-000210",
       fix='set system login class ENGINEER permissions all\nset system login class ENGINEER deny-configuration-regexps "system syslog .*"\n'
           "set system login class AUDITOR permissions configure\nset system login class AUDITOR permissions view\n"
           'set system login class AUDITOR allow-configuration-regexps "system syslog .*"\nset system login user remote class ENGINEER')
def nd_protect_logs(c, x):
    cls = _class_denies(c, "deny-configuration", "system syslog")
    return ok("Classes that can't change logging: " + ", ".join(cls)) if cls else bad("No login class keeps users from changing the syslog configuration.")


@check("JUNI-ND-000390", "JUEX-NM-000200", fix='set system login class ENGINEER deny-commands "(file delete)|(request system software)"')
def nd_protect_delete(c, x):
    cls = _class_denies(c, "deny-commands", "file delete")
    return ok("Classes that can't delete files: " + ", ".join(cls)) if cls else bad("No login class keeps users from deleting log files.")


@check("JUNI-ND-000460", "JUNI-ND-001060", "JUEX-NM-000220", "JUEX-NM-000450",
       fix='set system login class ENGINEER deny-commands "(file delete)|(request system software)"')
def nd_software(c, x):
    cls = _class_denies(c, "deny-commands", "request system software")
    return ok("Classes that can't install software: " + ", ".join(cls)) if cls else bad("No login class keeps users from installing software.")


NONSECURE = ("telnet", "finger", "ftp", "xnm-clear-text", "rlogin", "tftp", "tftp-server", "web-management http",
             "web-management", "rest http", "dhcp-local-server")


@check("JUNI-ND-000470", "JUEX-NM-000230", "JUNI-RT-000070", "JUEX-RT-000270", "JUEX-L2-000010",
       fix="delete system services telnet\ndelete system services finger\ndelete system services ftp\n"
           "delete system services xnm-clear-text\ndelete system services web-management")
def nd_services(c, x):
    on = sorted({s.split()[0] for s in NONSECURE if _service(c, s)})
    return bad("Insecure or unneeded services enabled: " + ", ".join(on)) if on else ok("No telnet, FTP, finger, clear-text XNM or web management")


@check("JUNI-ND-000490", "JUEX-NM-000240",
       fix="set system login user <ADMIN-USER> class ONECONFIG-ADMIN\nset system login user <ADMIN-USER> authentication encrypted-password \"<HASH>\"\n"
           "delete system login user <OTHER-USER> authentication\nset system services ssh root-login deny")
def nd_last_resort(c, x):
    local = [u for u, k in c.users.items() if any(z.startswith("authentication ") for z in k)]
    if len(local) != 1:
        return bad(f"{len(local)} local accounts have passwords; keep exactly one account of last resort.")
    if not c.has(r"system services ssh root-login deny"):
        return bad("root can log in over SSH (system services ssh root-login deny).")
    return ok(f"One local account ({local[0]}); root SSH login denied")


@check("JUEX-NM-000260", fix="set system services ssh protocol-version v2")
def nd_ssh_v2(c, x):
    v = c.find(r"system services ssh protocol-version (\S+)")
    return ok("SSH v2 only") if v and all(m.group(1) == "v2" for m in v) else bad("SSH is not limited to protocol version 2.")


def _ssh_list(c, what):
    return [m.group(1) for m in c.find(rf"system services ssh {what} (\S+)$")]


def _macs(c):
    m = _ssh_list(c, "macs")
    weak = [a for a in m if not a.startswith("hmac-sha2-")]
    return (None if m and not weak else ("SSH MACs are not restricted to HMAC-SHA2." if not m else "Non-FIPS SSH MACs: " + " ".join(weak)))


def _ciphers(c):
    m = _ssh_list(c, "ciphers")
    weak = [a for a in m if not re.match(r"aes\d+-(ctr|cbc|gcm)", a)]
    return (None if m and not weak else ("SSH ciphers are not restricted to AES." if not m else "Weak SSH ciphers: " + " ".join(weak)))


@check("JUNI-ND-000530", "JUNI-ND-001190", fix="set system services ssh protocol-version v2\nset system services ssh macs hmac-sha2-512\nset system services ssh macs hmac-sha2-256")
def nd_ssh_mac(c, x):
    p = _macs(c) or (None if c.has(r"system services ssh protocol-version v2") else "SSH is not limited to version 2.")
    return bad(p) if p else ok("SSH v2 with HMAC-SHA2 only")


@check("JUNI-ND-001200", fix="set system services ssh ciphers aes256-ctr\nset system services ssh ciphers aes128-ctr")
def nd_ssh_enc(c, x):
    p = _ciphers(c)
    return bad(p) if p else ok("SSH ciphers: " + " ".join(_ssh_list(c, "ciphers")))


def _pw(word, n, what):
    def fn(c, x):
        m = c.find(rf"system login password {word} (\d+)")
        return ok(f"{word} {m[0].group(1)}") if m and int(m[0].group(1)) >= n else bad(f"Passwords need not {what} (system login password {word} {n}).")
    return fn


for _ids, _word, _n, _what in ((("JUNI-ND-000550", "JUEX-NM-000270"), "minimum-length", 15, "be 15 characters long"),
                               (("JUNI-ND-000570", "JUEX-NM-000280"), "minimum-upper-cases", 1, "contain an uppercase letter"),
                               (("JUNI-ND-000580", "JUEX-NM-000290"), "minimum-lower-cases", 1, "contain a lowercase letter"),
                               (("JUNI-ND-000590", "JUEX-NM-000300"), "minimum-numerics", 1, "contain a number"),
                               (("JUNI-ND-000600", "JUEX-NM-000310"), "minimum-punctuations", 1, "contain a special character"),
                               (("JUEX-NM-000320",), "minimum-character-changes", 8, "change 8 characters")):
    check(*_ids, fix=f"set system login password {_word} {_n}")(_pw(_word, _n, _what))


@check("JUEX-NM-000330", fix="set system login password format sha512")
def nd_pw_format(c, x):
    m = c.find(r"system login password format (\S+)")
    fmt = m[0].group(1) if m else "sha512 (Junos default)"
    return bad(f"Password hashes use {fmt}.") if m and fmt not in ("sha256", "sha512") else ok(f"Passwords stored as {fmt}")


@check("JUEX-NM-000340", fix="set system login password format sha512\nset system services ssh ciphers aes256-ctr\n"
                             "set system services ssh macs hmac-sha2-512\nset system services ssh key-exchange ecdh-sha2-nistp256\nset system rng hmac-drbg")
def nd_fips_module(c, x):
    probs = [p for p in (_macs(c), _ciphers(c)) if p]
    if c.has(r"system login password format (md5|sha1|des)"):
        probs.append("Weak password hash format.")
    if not c.has(r"system rng hmac-drbg"):
        probs.append("The random number generator is not set to HMAC-DRBG (system rng hmac-drbg).")
    return bad(" ".join(probs)) if probs else ok("SHA-2 passwords, FIPS SSH algorithms, HMAC-DRBG")


@check("JUNI-ND-000710", "JUEX-NM-000360", fix="set system login class <CLASS> idle-timeout 5")
def nd_idle(c, x):
    if not c.classes:
        return bad("No login classes, so sessions use the predefined classes, which never time out.")
    slow = [n for n, k in c.classes.items() if not any(re.match(r"idle-timeout ([1-5])$", z) for z in k)]
    return bad("Classes without a 5-minute idle timeout: " + ", ".join(slow)) if slow else ok("All login classes time out within 5 minutes")


@check("JUEX-NM-000060", "JUEX-NM-000390", "JUEX-NM-000460", "JUEX-NM-000630", "JUEX-NM-000930",
       fix="set system login class <CLASS> permissions <PERMISSIONS>\nset system login user <USER> class <CLASS>")
def nd_rbac(c, x):
    nocls = [u for u, k in c.users.items() if not any(z.startswith("class ") for z in k)]
    if nocls:
        return bad("Users without a login class: " + ", ".join(nocls))
    limited = _class_denies(c, "deny-", "") or [n for n, k in c.classes.items() if not any(z == "permissions all" for z in k)]
    return ok("Users are assigned classes; restricted classes: " + ", ".join(limited)) if limited else \
        bad("Every class has full permissions, so roles don't limit anything.")


@check("JUEX-NM-000370", fix="set system syslog file messages archive no-world-readable\nset system login class <CLASS> deny-commands \"(file delete)\"")
def nd_file_access(c, x):
    if not c.has(r"system syslog (archive|file \S+ archive)( .*)? no-world-readable"):
        return bad("Log archives are world-readable (syslog archive no-world-readable).")
    return ok("Log archives are not world-readable") if _class_denies(c, "deny-", "") else bad("No login class restricts file or configuration access.")


def _content(year):
    def fn(c, x):
        if not _logs(c, "any"):
            return bad("No syslog file or host records all events (any info).")
        if year and not c.has(r"system syslog time-format (year|millisecond)"):
            return bad("Log time stamps lack the year (system syslog time-format year).")
        return ok("Events logged with date, time, source and outcome")
    return fn


check("JUEX-NM-000120", "JUEX-NM-000140", "JUEX-NM-000150", "JUEX-NM-000160", "JUEX-NM-000170",
      "JUNI-RT-000210", "JUNI-RT-000220", "JUEX-RT-000240", "JUEX-RT-000250",
      fix="set system syslog file messages any info\nset system syslog host <SYSLOG> any info")(_content(False))
check("JUEX-NM-000130", "JUEX-NM-000580", fix="set system syslog file messages any info\nset system syslog time-format year")(_content(True))


@check("JUNI-ND-000970", "JUEX-NM-000410", fix="set system syslog file messages archive size 1000000\nset system syslog file messages archive files 12")
def nd_log_storage(c, x):
    if c.has(r"system syslog (file \S+ )?archive (files|size) "):
        return ok("Log archive size and count set")
    return ok("Logs go to syslog servers: " + ", ".join(c.syslog("host"))) if len(c.syslog("host")) >= 2 else \
        bad("No log archive sizing and fewer than two syslog servers.")


@check("JUNI-ND-000990", fix="set system syslog host <SYSLOG> any critical")
def nd_audit_alert(c, x):
    hosts = [h for h, e in c.syslog("host").items() if any(re.match(r"any (any|info|notice|warning|error|critical|debug)$", z) for z in e)]
    return ok("Critical events reach " + ", ".join(hosts)) if hosts else bad("No syslog server receives critical events.")


@check("JUNI-ND-001020", "JUEX-NM-000430", fix="set system ntp server <NTP-1> prefer\nset system ntp server <NTP-2>")
def nd_ntp(c, x):
    s = {m.group(1) for m in c.find(r"system ntp server (\S+)")}
    return ok("NTP servers: " + ", ".join(sorted(s))) if len(s) >= 2 else bad(f"{len(s)} NTP server(s); configure two.")


@check("JUNI-ND-001030", "JUEX-NM-000440", fix="set system time-zone UTC")
def nd_utc(c, x):
    m = c.find(r"system time-zone (\S+)")
    return ok("time-zone " + (m[0].group(1) if m else "UTC (default)")) if not m or m[0].group(1) in ("UTC", "GMT", "Etc/UTC") \
        else bad(f"time-zone {m[0].group(1)}: log times don't map directly to UTC.")


def _snmp_users(c):
    return {m.group(1): m.group(2) for m in c.find(r"snmp v3 usm local-engine user (\S+) (\S+)")}


@check("JUNI-ND-001120", "JUEX-NM-000480",
       fix='set snmp v3 usm local-engine user <SNMP-USER> authentication-sha256 authentication-password "<KEY>"')
def nd_snmp_auth(c, x):
    if c.has(r"snmp community "):
        return bad("SNMPv1/v2c communities are configured (no message authentication).")
    if not c.has(r"snmp "):
        return na("SNMP is not configured.")
    u = c.find(r"snmp v3 usm local-engine user (\S+) authentication-(sha\d*)")
    weak = c.find(r"snmp v3 usm local-engine user (\S+) authentication-(md5|none)")
    return bad("SNMPv3 users without SHA: " + ", ".join(m.group(1) for m in weak)) if weak or not u else ok("SNMPv3 SHA authentication")


@check("JUNI-ND-001130", fix='set snmp v3 usm local-engine user <SNMP-USER> privacy-aes128 privacy-password "<KEY>"')
def nd_snmp_priv(c, x):
    if not c.has(r"snmp "):
        return na("SNMP is not configured.")
    weak = c.find(r"snmp v3 usm local-engine user (\S+) privacy-(des|3des|none)")
    aes = c.find(r"snmp v3 usm local-engine user (\S+) privacy-aes")
    return bad("SNMPv3 is not encrypted with AES.") if weak or not aes or c.has(r"snmp community ") else ok("SNMPv3 AES privacy")


@check("JUEX-NM-000510", fix="set snmp v3 usm local-engine user <SNMP-USER> authentication-sha256 authentication-password \"<KEY>\"\n"
                             "set system services ssh macs hmac-sha2-512\nset system services ssh macs hmac-sha2-256")
def nd_hmac_maint(c, x):
    p = _macs(c) or (nd_snmp_auth(c, x)[1] if nd_snmp_auth(c, x)[0] == "open" else None)
    return bad(p) if p else ok("SSH and SNMP use HMAC-SHA")


@check("JUEX-NM-000520", fix="set snmp v3 usm local-engine user <SNMP-USER> privacy-aes128 privacy-password \"<KEY>\"\n"
                             "set system services ssh ciphers aes256-ctr")
def nd_crypto_maint(c, x):
    p = _ciphers(c) or (nd_snmp_priv(c, x)[1] if nd_snmp_priv(c, x)[0] == "open" else None)
    return bad(p) if p else ok("SSH and SNMP are encrypted with AES")


@check("JUNI-ND-001140", "JUEX-NM-000490",
       fix='set system ntp authentication-key 1 type sha256\nset system ntp authentication-key 1 value "<KEY>"\n'
           "set system ntp trusted-key 1\nset system ntp server <NTP> key 1")
def nd_ntp_auth(c, x):
    keys = {m.group(1): m.group(2) for m in c.find(r"system ntp authentication-key (\d+) type (\S+)")}
    servers = c.find(r"system ntp server (\S+)( key (\d+))?")
    if not servers:
        return bad("No NTP servers.")
    if not keys or not c.has(r"system ntp trusted-key "):
        return bad("NTP is not authenticated.")
    unkeyed = {m.group(1) for m in servers} - {m.group(1) for m in c.find(r"system ntp server (\S+) key \d+")}
    if unkeyed:
        return bad("NTP servers without a key: " + ", ".join(sorted(unkeyed)))
    weak = [k for k, t in keys.items() if t not in ("sha1", "sha256")]
    return bad("NTP keys use MD5: " + ", ".join(weak)) if weak else ok("NTP authenticated with " + ", ".join(sorted(set(keys.values()))))


@check("JUNI-ND-001210", "JUNI-RT-000120", "JUEX-RT-000590",
       fix="set firewall policer CRITICAL if-exceeding bandwidth-limit 4m\nset firewall policer CRITICAL if-exceeding burst-size-limit 16k\n"
           "set firewall policer CRITICAL then discard\nset firewall family inet filter PROTECT-RE term <TERM> then policer CRITICAL\n"
           "set interfaces lo0 unit 0 family inet filter input PROTECT-RE")
def nd_copp(c, x):
    pol = [t for f, t, d in _terms(c, c.if_filters("lo0")) if any(z.startswith("policer ") for z in d["then"])]
    return ok(f"lo0 filter rate-limits {len(pol)} traffic classes") if pol else bad("Traffic to the routing engine is not rate-limited (no policers on the lo0 filter).")


@check("JUEX-NM-000530", fix="set system services ssh connection-limit 3\nset system services ssh rate-limit 4\n"
                             "set firewall family inet filter PROTECT-RE term SSH then policer IMPORTANT")
def nd_dos(c, x):
    if nd_copp(c, x)[0] == "not_a_finding":
        return nd_copp(c, x)
    return ok("SSH connections limited") if c.has(r"system services ssh (rate-limit|connection-limit) ") else bad("No DoS safeguards for management services.")


@check("JUNI-ND-001300", "JUEX-NM-000600", fix="set system syslog host <SYSLOG> any info")
def nd_offload(c, x):
    h = c.syslog("host")
    return ok("Logs sent to " + ", ".join(h)) if h else bad("Logs are not sent to a syslog server.")


@check("JUNI-ND-001440", "JUEX-NM-000670", fix="set system syslog host <SYSLOG-1> any info\nset system syslog host <SYSLOG-2> any info")
def nd_two_syslog(c, x):
    h = c.syslog("host")
    return ok("Syslog servers: " + ", ".join(h)) if len(h) >= 2 else bad(f"{len(h)} syslog server(s); configure two.")


@check("JUNI-ND-001340", "JUEX-NM-000620", fix="set system syslog file messages any info\nset system syslog file messages change-log info")
def nd_event_list(c, x):
    return ok("Selected events logged") if _logs(c, "any") or (_logs(c, "change-log") and _logs(c, "authorization")) \
        else bad("No log destination records the auditable events.")


def _auth_servers(c):
    return sorted({m.group(1) for m in c.find(r"system (?:tacplus|radius)-server (\S+)")})


@check("JUNI-ND-001360", "JUEX-NM-000640",
       fix='set system tacplus-server <AAA-1> secret "<KEY>"\nset system tacplus-server <AAA-2> secret "<KEY>"\nset system authentication-order tacplus')
def nd_aaa(c, x):
    s = _auth_servers(c)
    order = [m.group(1) for m in c.find(r"system authentication-order (\S+)")]
    if not any(o in ("tacplus", "radius") for o in order):
        return bad("Logins don't use an authentication server first (system authentication-order).")
    return ok("Authentication servers: " + ", ".join(s)) if len(s) >= 2 else bad(f"{len(s)} authentication server(s); configure two.")


@check("JUNI-ND-001400", "JUEX-NM-000650",
       fix="set system archival configuration transfer-on-commit\n"
           'set system archival configuration archive-sites "scp://<USER>@<SERVER>:/<PATH>" password "<PASSWORD>"')
def nd_backup(c, x):
    if c.has(r"system archival configuration transfer-on-commit") and c.has(r"system archival configuration archive-sites "):
        return ok("Configuration copied off the device on every commit")
    return bad("The configuration is not backed up when it changes (system archival configuration transfer-on-commit).")


MANUAL_WHY.update({
    "JUNI-ND-001430": "Check the CA profile and installed certificates (show security pki).",
    "JUEX-NM-000660": "Check the CA profile and installed certificates (show security pki).",
    "JUNI-ND-001460": "The master password is hidden from the configuration: run `show configuration system master-password` (expect password-configured).",
    "JUNI-ND-001470": "Check the Junos release against Juniper's end-of-support list (and the CVE tab).",
    "JUEX-NM-000680": "Check the Junos release against Juniper's end-of-support list (and the CVE tab).",
    "JUEX-NM-000420": "Configure disk-partition alarms and SNMP health monitoring to match the organization's alerting requirements.",
    "JUEX-NM-000910": "A process requirement: change the account of last resort's password when an administrator who knows it leaves.",
})


# ---------------------------------------------------------------- L2S (EX switches)
def _switching(c):
    """{interface: [ethernet-switching statements of unit 0]}"""
    out = {}
    for n, k in c.ifs.items():
        e = [z[len("unit 0 family ethernet-switching "):] for z in k if z.startswith("unit 0 family ethernet-switching")]
        if e or any(z.startswith("unit 0 family ethernet-switching") for z in k):
            out[n] = e
    return out


def _mode(e):
    return "trunk" if "interface-mode trunk" in e else "access"


def _members(e):
    return [z.split()[-1] for z in e if z.startswith("vlan members ")]


def _access(c, active_only=True):
    return {n: e for n, e in _switching(c).items() if _mode(e) == "access" and not (active_only and "disable" in c.ifs.get(n, []))}


def _trunks(c):
    return {n: e for n, e in _switching(c).items() if _mode(e) == "trunk"}


def _vlan_ids(c):
    """VLAN name -> id ('default' is 1)."""
    return {m.group(1): int(m.group(2)) for m in c.find(r"vlans (\S+) vlan-id (\d+)$")} | {"default": 1}


def _vid(c, member):
    return int(member) if member.isdigit() else _vlan_ids(c).get(member)


def _no_access(fn):
    def wrapped(c, x):
        return fn(c, x) if _access(c) else na("No active access ports.")
    return wrapped


@check("JUEX-L2-000020", "JUEX-L2-000070",
       fix='set access radius-server <RADIUS> secret "<KEY>"\nset access profile DOT1X authentication-order radius\n'
           "set access profile DOT1X radius authentication-server <RADIUS>\nset protocols dot1x authenticator authentication-profile-name DOT1X\n"
           "set protocols dot1x authenticator interface <ACCESS-PORT>.0 supplicant single-secure\n"
           "set protocols dot1x authenticator interface <ACCESS-PORT>.0 mac-radius")
@_no_access
def l2_dot1x(c, x):
    on = {m.group(1).split(".")[0] for m in c.find(r"protocols dot1x authenticator interface (\S+)")}
    if c.has(r"protocols dot1x authenticator interface all"):
        return ok("802.1X on all interfaces")
    missing = [n for n in _access(c) if n not in on]
    return bad("Access ports without 802.1X: " + ", ".join(missing)) if missing else ok("802.1X on every active access port")


@check("JUEX-L2-000030", fix="delete protocols mvrp")
def l2_mvrp(c, x):
    return bad("MVRP (dynamic VLAN registration) is enabled.") if c.has(r"protocols mvrp") else ok("MVRP is not configured")


@check("JUEX-L2-000080", fix="set protocols rstp interface <DOWNLINK> no-root-port")
def l2_root_guard(c, x):
    down = x.get("downlinks")
    if down is None:
        return manual("Check that every trunk to an access-layer switch has no-root-port.")
    if not down:
        return na("No trunks to access-layer switches.")
    have = {m.group(1) for m in c.find(r"protocols (?:rstp|mstp|vstp) interface (\S+) no-root-port")}
    miss = [n for n in down if n not in have]
    return bad("Downlinks without root protection: " + ", ".join(miss)) if miss else ok("Root protection on every downlink")


@check("JUEX-L2-000090", fix="set protocols rstp bpdu-block-on-edge\nset protocols rstp interface <ACCESS-PORT> edge")
@_no_access
def l2_bpdu(c, x):
    if not c.has(r"protocols (rstp|mstp|vstp) bpdu-block-on-edge"):
        return bad("BPDU protection is off (protocols rstp bpdu-block-on-edge).")
    edge = {m.group(1) for m in c.find(r"protocols (?:rstp|mstp|vstp) interface (\S+) edge")}
    miss = [n for n in _access(c) if n not in edge]
    return bad("Access ports not marked edge: " + ", ".join(miss)) if miss else ok("BPDU protection on every access port")


@check("JUEX-L2-000100", fix="set protocols rstp interface <UPLINK> bpdu-timeout-action block")
def l2_loop(c, x):
    tr = [n for n in _trunks(c) if n not in (x.get("downlinks") or [])]
    if not tr:
        return na("No uplink trunks.")
    guarded = {m.group(1) for m in c.find(r"protocols (?:rstp|mstp|vstp) interface (\S+) (bpdu-timeout-action block|no-root-port)")}
    miss = [n for n in tr if n not in guarded]
    return bad("Trunks without loop protection: " + ", ".join(miss)) if miss else ok("Loop protection on every uplink trunk")


def _user_vlans(c):
    names = {v: k for k, v in _vlan_ids(c).items()}
    out = set()
    for e in _access(c).values():
        out |= {names.get(_vid(c, m), m) for m in _members(e)}
    return sorted(out)


def _vlan_feature(feature, what):
    @_no_access
    def fn(c, x):
        miss = [v for v in _user_vlans(c) if not c.has(rf"vlans {re.escape(v)} forwarding-options dhcp-security{feature}")]
        return bad(f"User VLANs without {what}: " + ", ".join(miss)) if miss else ok(f"{what.capitalize()} on " + ", ".join(_user_vlans(c)))
    return fn


check("JUEX-L2-000120", fix="set vlans <USER-VLAN> forwarding-options dhcp-security")(_vlan_feature("", "DHCP snooping"))
check("JUEX-L2-000130", fix="set vlans <USER-VLAN> forwarding-options dhcp-security ip-source-guard")(_vlan_feature(" ip-source-guard", "IP source guard"))
check("JUEX-L2-000140", fix="set vlans <USER-VLAN> forwarding-options dhcp-security arp-inspection")(_vlan_feature(" arp-inspection", "ARP inspection"))


@check("JUEX-L2-000150", fix="set forwarding-options storm-control-profiles STORM-CONTROL all bandwidth-percentage 5\n"
                             "set interfaces <ACCESS-PORT> unit 0 family ethernet-switching storm-control STORM-CONTROL")
@_no_access
def l2_storm(c, x):
    miss = [n for n, e in _access(c).items() if not any(z.startswith("storm-control ") for z in e)]
    return bad("Access ports without storm control: " + ", ".join(miss)) if miss else ok("Storm control on every access port")


@check("JUEX-L2-000160", fix="set protocols igmp-snooping vlan all")
def l2_igmp(c, x):
    return ok("IGMP snooping configured") if c.has(r"protocols igmp-snooping vlan ") else bad("IGMP snooping is not configured.")


@check("JUEX-L2-000170", fix="set protocols rstp bpdu-block-on-edge")
def l2_rstp(c, x):
    return ok("Rapid or multiple spanning tree") if c.has(r"protocols (rstp|mstp|vstp)( |$)") else bad("Neither RSTP nor MSTP is configured.")


@check("JUEX-L2-000180", fix="set protocols oam ethernet link-fault-management interface <TRUNK>\n(or bundle the trunk into an aggregated interface with LACP)")
def l2_two_way(c, x):
    tr = _trunks(c)
    if not tr:
        return na("No trunks.")
    lfm = {m.group(1) for m in c.find(r"protocols oam ethernet link-fault-management interface (\S+)")}
    lacp = {n for n in tr if n.startswith("ae") and any("lacp" in z for z in c.ifs.get(n, []))}
    miss = [n for n in tr if n not in lfm | lacp]
    return bad("Trunks without OAM or LACP: " + ", ".join(miss)) if miss else ok("Every trunk runs OAM or LACP")


@check("JUEX-L2-000190", fix="set interfaces <UNUSED-PORT> disable\nset interfaces <UNUSED-PORT> unit 0 family ethernet-switching vlan members <UNUSED-VLAN>")
def l2_parking(c, x):
    off = {n: e for n, e in _access(c, active_only=False).items() if "disable" in c.ifs.get(n, [])}
    if not off:
        return na("No disabled access ports.")
    trunked = {_vid(c, m) for e in _trunks(c).values() for m in _members(e)}
    active = {_vid(c, m) for e in _access(c).values() for m in _members(e)}
    bad_ = [n for n, e in off.items() if any(_vid(c, m) in trunked | active | {1} for m in _members(e)) or not _members(e)]
    return bad("Disabled ports not in an unused VLAN: " + ", ".join(bad_)) if bad_ else ok("Disabled ports sit in an unused VLAN")


def _natives(c):
    return {int(m.group(2)) for m in c.find(r"interfaces (\S+) native-vlan-id (\d+)")}


@check("JUEX-L2-000200", fix="set interfaces <ACCESS-PORT> unit 0 family ethernet-switching vlan members <USER-VLAN>")
@_no_access
def l2_control_vlan(c, x):
    bad_ = [n for n, e in _access(c).items() if any(_vid(c, m) in {1} | _natives(c) for m in _members(e) or ["default"])]
    return bad("Access ports in the default or native VLAN: " + ", ".join(bad_)) if bad_ else ok("Access ports use user VLANs")


@check("JUEX-L2-000210", fix="delete interfaces <TRUNK> unit 0 family ethernet-switching vlan members default")
def l2_prune_default(c, x):
    tr = _trunks(c)
    if not tr:
        return na("No trunks.")
    bad_ = [n for n, e in tr.items() if any(m in ("default", "1", "all") for m in _members(e))]
    return bad("Trunks carrying the default VLAN: " + ", ".join(bad_)) if bad_ else ok("The default VLAN is pruned from every trunk")


@check("JUEX-L2-000220", fix="Move management to an irb on a VLAN other than default.")
def l2_mgmt_vlan(c, x):
    return bad("The default VLAN has a layer 3 interface (used for management).") if c.has(r"vlans default l3-interface ") \
        else ok("Management doesn't use the default VLAN")


@check("JUEX-L2-000230", fix="set interfaces <USER-PORT> unit 0 family ethernet-switching interface-mode access")
def l2_user_access(c, x):
    if not x.get("generated"):
        return manual("Check that every user-facing port is an access port.")
    return ok("Trunks connect only to other network devices in the OneConfig design")


@check("JUEX-L2-000240", fix="set interfaces <TRUNK> native-vlan-id <UNUSED-VLAN>")
def l2_native(c, x):
    n = _natives(c)
    return bad("VLAN 1 is a native VLAN.") if 1 in n else ok("Native VLAN: " + (", ".join(map(str, sorted(n))) if n else "none assigned"))


@check("JUEX-L2-000250", fix="set interfaces <ACCESS-PORT> unit 0 family ethernet-switching vlan members <USER-VLAN>")
def l2_access_native(c, x):
    n = _natives(c)
    bad_ = [p for p, e in _access(c, active_only=False).items() if any(_vid(c, m) in n for m in _members(e))]
    return bad("Access ports in a native VLAN: " + ", ".join(bad_)) if bad_ else ok("No access ports in a native VLAN")


MANUAL_WHY.update({
    "JUEX-L2-000040": "Verify class-of-service reserves capacity for mission-critical traffic per the organization's QoS policy.",
    "JUEX-L2-000050": "Analyzers (port mirroring) are configured only while a session is being captured.",
    "JUEX-L2-000060": "Analyzers (port mirroring) are configured only while a session is being captured.",
})


# ---------------------------------------------------------------- RTR
def _ospf_active(c):
    return {n: o for n, o in c.ospf_ifs.items() if not any("passive" in z for z in o) and not n.startswith("lo0")}


def _ospf_auth(o):
    for z in o:
        m = re.match(r"authentication (keychain|md5|simple-password)( (\S+))?", z)
        if m:
            return m.group(1), m.group(3)
        if z.startswith("ipsec-sa "):
            return "ipsec-sa", z.split()[1]
    return None, None


def _bgp_auth(opts):
    chain = next((z.split()[1] for z in opts if z.startswith("authentication-key-chain ")), None)
    alg = next((z.split()[1] for z in opts if z.startswith("authentication-algorithm ")), None)
    key = any(z.startswith("authentication-key ") for z in opts)
    return chain, alg, key


def _routing(c):
    """[(protocol, where, problem or None, algorithm, key chain)] for every authenticated routing adjacency."""
    out = []
    for n, o in _ospf_active(c).items():
        kind, name = _ospf_auth(o)
        out.append(("OSPF", n, None if kind else "no authentication", kind, name if kind == "keychain" else None))
    for g, ip, o in c.bgp_peers():
        chain, alg, key = _bgp_auth(o)
        out.append(("BGP", ip, None if chain or key else "no authentication", alg or ("md5" if key else None), chain))
    for proto in ("isis", "rip", "ldp"):
        if c.has(rf"protocols {proto} "):
            authed = c.has(rf"protocols {proto} .*authentication")
            out.append((proto.upper(), proto, None if authed else "no authentication", "md5" if authed else None, None))
    return out


def _needs_routing(fn):
    def wrapped(c, x):
        r = _routing(c)
        return fn(c, x, r) if r else na("No routing protocols with neighbors.")
    return wrapped


@check("JUNI-RT-000020", "JUEX-RT-000530",
       fix="set protocols ospf area <AREA> interface <IF> authentication keychain OSPF-KEYS\n"
           "set protocols bgp group <GROUP> neighbor <IP> authentication-key-chain BGP-AS<N>")
@_needs_routing
def rt_auth(c, x, r):
    miss = [f"{p} {w}" for p, w, prob, *_ in r if prob]
    return bad("Not authenticated: " + ", ".join(miss)) if miss else ok("Every routing adjacency is authenticated")


@check("JUNI-RT-000040", "JUEX-RT-000290", fix="set protocols ospf area <AREA> interface <IF> authentication keychain OSPF-KEYS")
@_needs_routing
def rt_auth_encrypted(c, x, r):
    simple = [f"OSPF {n}" for n, o in _ospf_active(c).items() if _ospf_auth(o)[0] == "simple-password"]
    miss = [f"{p} {w}" for p, w, prob, *_ in r if prob]
    return bad("Plain-text or no authentication: " + ", ".join(simple + miss)) if simple or miss else ok("Routing keys are hashed, not sent in clear text")


FIPS_ALGS = {"hmac-sha-1", "hmac-sha-1-96", "aes-128-cmac-96", "ipsec-sa"}


@check("JUNI-RT-000050", "JUEX-RT-000300",
       fix="set security authentication-key-chains key-chain OSPF-KEYS key 1 algorithm hmac-sha-1\n"
           "set protocols bgp group <GROUP> neighbor <IP> authentication-algorithm hmac-sha-1-96\n"
           "set protocols bgp group <GROUP> neighbor <IP> authentication-key-chain BGP-AS<N>")
@_needs_routing
def rt_fips(c, x, r):
    probs = []
    for p, w, prob, alg, chain in r:
        if prob:
            probs.append(f"{p} {w}: {prob}")
        elif p == "OSPF":
            kind = alg
            if kind == "keychain":
                kc = c.keychains.get(chain) or {}
                if not kc or any(k.get("algorithm") != "hmac-sha-1" for k in kc.values()):
                    probs.append(f"OSPF {w}: key chain {chain} does not use HMAC-SHA-1")
            elif kind != "ipsec-sa":
                probs.append(f"OSPF {w}: {kind} is not FIPS 198-1")
        elif alg not in FIPS_ALGS:
            probs.append(f"{p} {w}: {alg or 'md5'} is not FIPS 198-1")
    return bad("; ".join(probs)) if probs else ok("Routing protocols authenticate with FIPS 198-1 HMACs")


def _start(s):
    m = re.match(r"(\d{4})-(\d{1,2})-(\d{1,2})", s or "")
    return date(*map(int, m.groups())) if m else None


@check("JUNI-RT-000030", "JUEX-RT-000550",
       fix="set security authentication-key-chains key-chain <CHAIN> key <N> start-time <YYYY-MM-DD.HH:MM>\n"
           "(add the next key with a start-time no more than 180 days later)")
@_needs_routing
def rt_key_lifetime(c, x, r):
    chains = {chain for *_, chain in r if chain}
    if not chains:
        return bad("Routing keys have no lifetime (use key chains with start times).")
    probs, today = [], x.get("today") or datetime.now().date()
    for name in sorted(chains):
        starts = sorted(d for k in c.keychains.get(name, {}).values() if (d := _start(k.get("start-time"))))
        if not starts:
            probs.append(f"key chain {name} keys have no start-time")
        elif any((b - a).days > 180 for a, b in zip(starts, starts[1:])) or (today - starts[-1]).days > 180:
            probs.append(f"key chain {name} uses a key for more than 180 days")
    return bad("; ".join(probs)) if probs else ok("Every key chain rotates keys within 180 days")


@check("JUNI-RT-000060", "JUEX-RT-000160", fix="set interfaces <UNUSED-IF> disable")
def rt_inactive(c, x):
    idle = [n for n, k in c.ifs.items() if n != "lo0" and not n.startswith("irb") and "disable" not in k
            and not any(z.startswith(("unit ", "ether-options", "gigether-options", "aggregated-ether-options", "native-vlan-id")) for z in k)]
    return bad("Configured but unused interfaces not disabled: " + ", ".join(idle)) if idle else ok("No unused interfaces left enabled")


def _lo0_terms(c):
    return _terms(c, c.if_filters("lo0"))


@check("JUNI-RT-000130", "JUEX-RT-000380",
       fix="set firewall family inet filter PROTECT-RE term <ALLOWED> ... then accept\n"
           "set firewall family inet filter PROTECT-RE term DENY-ALL then syslog\nset firewall family inet filter PROTECT-RE term DENY-ALL then discard\n"
           "set interfaces lo0 unit 0 family inet filter input PROTECT-RE")
def rt_receive_path(c, x):
    f = c.if_filters("lo0")
    if not f:
        return bad("lo0 has no input filter.")
    return ok("lo0 filter " + " + ".join(f) + " ends with a default deny") if _last_denies(c, f) else bad("The lo0 filter does not end with a term that drops everything else.")


@check("JUNI-RT-000140", "JUEX-RT-000390",
       fix="set firewall family inet filter PROTECT-RE term ICMP-FRAGMENTS from protocol icmp\n"
           "set firewall family inet filter PROTECT-RE term ICMP-FRAGMENTS from is-fragment\n"
           "set firewall family inet filter PROTECT-RE term ICMP-FRAGMENTS then discard")
def rt_icmp_frag(c, x):
    for f, t, d in _lo0_terms(c):
        if "protocol icmp" in d["from"] and "is-fragment" in d["from"] and _discards(d):
            return ok(f"{f} term {t} drops fragmented ICMP")
        if "protocol icmp" in d["from"] and "accept" in d["then"]:
            break
    return bad("Fragmented ICMP to the device is not dropped before ICMP is accepted.")


def _edge(c, x):
    ext = x.get("external")
    if ext is None:
        return [n for n in c.ifs if any(z.startswith("address ") for z in c.inet(n)) and n != "lo0"], " (external interfaces unknown, so every addressed interface was checked)"
    return ext, ""


@check("JUNI-RT-000150", "JUEX-RT-000600", fix="delete interfaces <EXTERNAL-IF> unit 0 family inet gratuitous-arp-reply")
def rt_garp(c, x):
    ifs, note = _edge(c, x)
    on = [n for n in ifs if any("gratuitous-arp-reply" in z for z in c.ifs.get(n, []))]
    return bad("Gratuitous ARP replies on: " + ", ".join(on) + note) if on else ok("No gratuitous ARP replies on external interfaces" + note)


@check("JUNI-RT-000170", fix="set firewall family inet filter <EXTERNAL-IN> term DENY-ALL then discard   (discard, not reject)")
@_perimeter
def rt_unreachables(c, x, ext):
    probs = []
    for n in ext:
        for f, t, d in _terms(c, c.if_filters(n)):
            if "reject" in d["then"]:
                probs.append(f"{f} term {t} rejects (sends ICMP unreachable)")
    return bad("; ".join(probs)) if probs else ok("Dropped packets are discarded silently")


def _out_drops_icmp(c, n, icmp):
    return any("protocol icmp" in d["from"] and f"icmp-type {icmp}" in d["from"] and _discards(d) for f, t, d in _terms(c, c.if_filters(n, "output")))


@check("JUEX-RT-000620", fix="set firewall family inet filter EXTERNAL-OUT term ICMP-MASK-REDIRECT from icmp-type unreachable\n"
                             "set firewall family inet filter EXTERNAL-OUT term ICMP-MASK-REDIRECT then discard\n"
                             "set interfaces <EXTERNAL-IF> unit 0 family inet filter output EXTERNAL-OUT")
@_perimeter
def rt_out_unreach(c, x, ext):
    miss = [n for n in ext if not _out_drops_icmp(c, n, "unreachable")]
    return bad("ICMP unreachables can leave: " + ", ".join(miss)) if miss else ok("Outbound ICMP unreachables dropped")


@check("JUNI-RT-000180", "JUEX-RT-000630",
       fix="set firewall family inet filter PROTECT-RE term MASK-REQUEST from protocol icmp\n"
           "set firewall family inet filter PROTECT-RE term MASK-REQUEST from icmp-type mask-request\n"
           "set firewall family inet filter PROTECT-RE term MASK-REQUEST then discard")
def rt_mask(c, x):
    for f, t, d in _lo0_terms(c):
        if "icmp-type mask-request" in d["from"] and _discards(d):
            return ok(f"{f} term {t} drops mask requests")
        if "protocol icmp" in d["from"] and "accept" in d["then"] and not any(z.startswith("icmp-type") for z in d["from"]):
            break
    ext = x.get("external") or []
    if ext and all(_out_drops_icmp(c, n, "mask-reply") for n in ext):
        return ok("Outbound mask replies dropped on every external interface")
    return bad("ICMP mask requests to the device are not dropped.")


@check("JUNI-RT-000190", "JUEX-RT-000640", fix="set system no-redirects\nset interfaces <EXTERNAL-IF> unit 0 family inet no-redirects")
def rt_redirects(c, x):
    if c.has(r"system no-redirects$"):
        return ok("system no-redirects")
    ifs, note = _edge(c, x)
    on = [n for n in ifs if "no-redirects" not in c.inet(n)]
    return bad("ICMP redirects on: " + ", ".join(on) + note) if on else ok("No redirects on external interfaces" + note)


@check("JUNI-RT-000200", "JUEX-RT-000260", fix="set firewall family inet filter <FILTER> term <DENY-TERM> then syslog\nset system syslog file messages firewall any")
def rt_log_drops(c, x):
    quiet = [f"{f} {t}" for f, terms in c.filters.items() for t, d in terms.items() if _discards(d) and not ({"syslog", "log"} & set(d["then"]))
             and not d["from"]]
    if quiet:
        return bad("Default-deny terms that don't log: " + ", ".join(quiet))
    return ok("Dropped packets are logged") if _logs(c, "firewall") or c.has(r"system syslog file \S+ firewall ") else bad("Firewall log messages are not recorded (system syslog file messages firewall any).")


@check("JUNI-RT-000230", "JUEX-RT-000110", fix="set system ports auxiliary disable")
def rt_aux(c, x):
    if not c.has(r"system ports auxiliary"):
        return na("The auxiliary port is not configured.")
    return ok("auxiliary port disabled") if c.has(r"system ports auxiliary disable") else bad("The auxiliary port is enabled.")


@check("JUNI-RT-000240", "JUEX-RT-000370",
       fix="set firewall family inet filter EXTERNAL-IN term DENY-ALL then syslog\nset firewall family inet filter EXTERNAL-IN term DENY-ALL then discard")
@_perimeter
def rt_default_deny(c, x, ext):
    miss = [n for n in ext if not _last_denies(c, c.if_filters(n))]
    return bad("External interfaces without a default-deny inbound filter: " + ", ".join(miss)) if miss else ok("Inbound filters end with a default deny")


def _bogon_lists(c, f_terms):
    nets = []
    for f, t, d in f_terms:
        if _discards(d):
            for z in d["from"]:
                m = re.match(r"source-prefix-list (\S+)", z) or re.match(r"source-address (\S+)$", z)
                if m and m.re.pattern.startswith("source-prefix"):
                    nets += c.prefix_lists.get(m.group(1), [])
                elif m:
                    nets.append(IPv4Network(m.group(1), strict=False))
    return nets


@check("JUNI-RT-000270", "JUEX-RT-000740",
       fix="set policy-options prefix-list BOGONS <EACH-DISA-BOGON>\nset firewall family inet filter EXTERNAL-IN term BOGONS from source-prefix-list BOGONS\n"
           "set firewall family inet filter EXTERNAL-IN term BOGONS then syslog\nset firewall family inet filter EXTERNAL-IN term BOGONS then discard")
@_perimeter
def rt_bogons(c, x, ext):
    probs = []
    for n in ext:
        missing = _covered(ACL_BOGONS, _bogon_lists(c, _terms(c, c.if_filters(n))))
        if missing:
            probs.append(f"{n}: not dropped: " + ", ".join(map(str, missing)))
    return bad("; ".join(probs)) if probs else ok("Every DISA bogon source is dropped inbound")


@check("JUNI-RT-000280", "JUEX-RT-000170",
       fix="set firewall family inet filter EXTERNAL-IN term NOT-OUR-SITE from destination-address 0.0.0.0/0\n"
           "set firewall family inet filter EXTERNAL-IN term NOT-OUR-SITE from destination-address <SITE-NET> except\n"
           "set firewall family inet filter EXTERNAL-IN term NOT-OUR-SITE then discard")
@_perimeter
def rt_site_dest(c, x, ext):
    for n in ext:
        if not any("destination-address 0.0.0.0/0" in d["from"] and any(z.endswith(" except") for z in d["from"]) and _discards(d)
                   for f, t, d in _terms(c, c.if_filters(n))):
            return manual("Applies to an enclave behind an approved or alternate gateway: allow only the site's own destination addresses inbound.")
    return ok("Inbound traffic is limited to the site's own address space")


@check("JUNI-RT-000310", "JUEX-RT-000500", fix="set interfaces <INTERNAL-IF> unit 0 family inet rpf-check")
@_perimeter
def rt_urpf(c, x, ext):
    internal = x.get("internal") or []
    miss = [n for n in internal if "rpf-check" not in c.inet(n) and not c.if_filters(n)]
    return bad("Internal interfaces without uRPF or an egress filter: " + ", ".join(miss)) if miss else ok("Spoofed sources from inside are dropped")


@check("JUNI-RT-000330", "JUEX-RT-000410", fix="set interfaces <EXTERNAL-IF> unit 0 family inet filter input EXTERNAL-IN")
@_perimeter
def rt_ingress(c, x, ext):
    miss = [n for n in ext if not c.if_filters(n)]
    return bad("External interfaces without an inbound filter: " + ", ".join(miss)) if miss else ok("Inbound filters on every external interface")


@check("JUNI-RT-000340", "JUEX-RT-000420", fix="set interfaces <INTERNAL-IF> unit 0 family inet filter input EGRESS-FILTER")
@_perimeter
def rt_egress(c, x, ext):
    internal = x.get("internal")
    if internal is None:
        return manual("Mark internal interfaces to check this automatically.")
    miss = [n for n in internal if not c.if_filters(n)]
    return bad("Internal interfaces without an inbound egress filter: " + ", ".join(miss)) if miss else ok("Egress filters on every internal interface")


@check("JUNI-RT-000350", "JUEX-RT-000510",
       fix="set firewall family inet filter EXTERNAL-IN term IP-OPTIONS from ip-options any\nset firewall family inet filter EXTERNAL-IN term IP-OPTIONS then discard")
@_perimeter
def rt_ip_options(c, x, ext):
    miss = [n for n in ext if not any(any(z.startswith("ip-options") for z in d["from"]) and _discards(d) for f, t, d in _terms(c, c.if_filters(n)))]
    return bad("IP options not dropped on: " + ", ".join(miss)) if miss else ok("Packets with IP options are dropped inbound")


@check("JUNI-RT-000360", "JUEX-RT-000750", fix="set protocols lldp interface <EXTERNAL-IF> disable")
@_perimeter
def rt_lldp(c, x, ext):
    if not c.has(r"protocols lldp") or c.has(r"protocols lldp (disable|interface all disable)$"):
        return ok("LLDP is off")
    off = {m.group(1) for m in c.find(r"protocols lldp interface (\S+) disable")}
    on_all = c.has(r"protocols lldp interface all$")
    miss = [n for n in ext if n not in off and (on_all or c.has(rf"protocols lldp interface {re.escape(n)}$"))]
    return bad("LLDP on external interfaces: " + ", ".join(miss)) if miss else ok("LLDP disabled on external interfaces")


@check("JUNI-RT-000370", "JUEX-RT-000760", fix="delete interfaces <EXTERNAL-IF> unit 0 proxy-arp")
@_perimeter
def rt_proxy_arp(c, x, ext):
    on = [n for n in ext if any("proxy-arp" in z for z in c.ifs.get(n, []))]
    return bad("Proxy ARP on: " + ", ".join(on)) if on else ok("No proxy ARP on external interfaces")


@check("JUNI-RT-000380", "JUEX-RT-000770",
       fix="set firewall family inet filter EXTERNAL-OUT term BLOCK-TACACS from port tacacs\nset firewall family inet filter EXTERNAL-OUT term BLOCK-TACACS then discard\n"
           "set firewall family inet filter EXTERNAL-OUT term BLOCK-SNMP-SYSLOG from port snmp\nset firewall family inet filter EXTERNAL-OUT term BLOCK-SNMP-SYSLOG then discard\n"
           "set interfaces <EXTERNAL-IF> unit 0 family inet filter output EXTERNAL-OUT")
@_perimeter
def rt_out_mgmt(c, x, ext):
    probs = []
    for n in ext:
        dropped = {z.split()[-1] for f, t, d in _terms(c, c.if_filters(n, "output")) if _discards(d) for z in d["from"] if "port " in z}
        miss = {"tacacs", "snmp", "syslog"} - dropped
        if miss:
            probs.append(f"{n} lets out {', '.join(sorted(miss))}")
    return bad("; ".join(probs)) if probs else ok("Management traffic is blocked outbound")


@check("JUNI-RT-000460", "JUEX-RT-000720",
       fix="set firewall family inet filter EXTERNAL-IN term GTSM from protocol tcp\nset firewall family inet filter EXTERNAL-IN term GTSM from port bgp\n"
           "set firewall family inet filter EXTERNAL-IN term GTSM from ttl-except 255\nset firewall family inet filter EXTERNAL-IN term GTSM then discard\n"
           "set protocols bgp group <EBGP-GROUP> ttl 255")
def rt_gtsm(c, x):
    if not c.bgp_peers(external=True):
        return na("No eBGP neighbors.")
    gtsm = any("ttl-except 255" in d["from"] and _discards(d) for f, terms in c.filters.items() for t, d in terms.items())
    return ok("BGP packets with TTL below 255 are dropped") if gtsm else bad("No GTSM: eBGP packets are not required to arrive with TTL 255.")


@check("JUNI-RT-000470", "JUEX-RT-000540", fix="set protocols bgp group <GROUP> neighbor <IP> authentication-key-chain BGP-AS<N>  (one key chain per AS)")
def rt_unique_keys(c, x):
    peers = c.bgp_peers(external=True)
    if not peers:
        return na("No eBGP neighbors.")
    by_as = {}
    for g, ip, o in peers:
        asn = next((z.split()[1] for z in o if z.startswith("peer-as ")), g)
        chain, alg, key = _bgp_auth(o)
        if key and not chain:
            return manual("Keys are hashed in the configuration: confirm a different key is used for each AS.")
        by_as.setdefault(chain, set()).add(asn)
    shared = [ch for ch, ases in by_as.items() if ch and len(ases) > 1]
    return bad("Key chains shared between autonomous systems: " + ", ".join(shared)) if shared else ok("A separate key chain for each AS")


def _imports(c, opts):
    pol = []
    for z in opts:
        if z.startswith("import "):
            pol += z.split()[1:]
    return [p.strip("[]") for p in pol]


def _policy_rejects(c, pols, test):
    for p in pols:
        for t, d in c.policies.get(p, {}).items():
            if "reject" in d["then"] and any(test(z) for z in d["from"]):
                return True
    return False


def _ebgp_import(test, ok_msg, bad_msg):
    def fn(c, x):
        peers = c.bgp_peers(external=True)
        if not peers:
            return na("No eBGP neighbors.")
        miss = [ip for g, ip, o in peers if not _policy_rejects(c, _imports(c, o), test(c))]
        return bad(bad_msg + ": " + ", ".join(miss)) if miss else ok(ok_msg)
    return fn


def _bogon_test(c):
    def t(z):
        m = re.match(r"prefix-list(-filter)? (\S+)", z)
        return bool(m) and not _covered(ACL_BOGONS, c.prefix_lists.get(m.group(2), []))
    return t


check("JUNI-RT-000480", "JUEX-RT-000020",
      fix="set policy-options prefix-list BOGONS <EACH-DISA-BOGON>\n"
          "set policy-options policy-statement BGP-IN term REJECT-BOGONS from prefix-list-filter BOGONS orlonger\n"
          "set policy-options policy-statement BGP-IN term REJECT-BOGONS then reject\nset protocols bgp group <EBGP-GROUP> import BGP-IN")(
    _ebgp_import(_bogon_test, "Bogon routes are rejected from eBGP peers", "eBGP peers whose bogon routes are accepted"))


def _own_test(c):
    own = {str(p) for m in c.find(r"policy-options prefix-list OUR-PREFIXES (\S+)") for p in [m.group(1)]}
    exported = set()
    for m in c.find(r"policy-options policy-statement \S+ (?:term \S+ )?from prefix-list (\S+)"):
        exported.add(m.group(1))

    def t(z):
        m = re.match(r"prefix-list(-filter)? (\S+)", z)
        return bool(m) and (m.group(2) in exported or m.group(2) == "OUR-PREFIXES") and m.group(2) != "BOGONS"
    return t if own or exported else (lambda z: False)


@check("JUNI-RT-000490", "JUEX-RT-000030",
       fix="set policy-options policy-statement BGP-IN term REJECT-OURS from prefix-list-filter OUR-PREFIXES orlonger\n"
           "set policy-options policy-statement BGP-IN term REJECT-OURS then reject")
def rt_own_prefixes(c, x):
    if not c.bgp_peers(external=True):
        return na("No eBGP neighbors.")
    if not c.has(r"policy-options prefix-list OUR-PREFIXES "):
        return manual("List the local AS's prefixes in a prefix-list and reject them inbound from eBGP peers.")
    return _ebgp_import(_own_test, "The local AS's prefixes are rejected from eBGP peers", "eBGP peers allowed to send our own prefixes")(c, x)


@check("JUNI-RT-000510", "JUEX-RT-000050",
       fix="set policy-options policy-statement BGP-OUT term OURS from prefix-list OUR-PREFIXES\nset policy-options policy-statement BGP-OUT term OURS then accept\n"
           "set policy-options policy-statement BGP-OUT term REJECT-OTHER then reject\nset protocols bgp group <EBGP-GROUP> export BGP-OUT")
def rt_export(c, x):
    peers = c.bgp_peers(external=True)
    if not peers:
        return na("No eBGP neighbors.")
    miss = []
    for g, ip, o in peers:
        ex = [p.strip("[]") for z in o if z.startswith("export ") for p in z.split()[1:]]
        last = list(c.policies.get(ex[-1], {}).values())[-1:] if ex else []
        if not (last and not last[0]["from"] and "reject" in last[0]["then"]):
            miss.append(ip)
    return bad("eBGP peers without an export policy ending in reject: " + ", ".join(miss)) if miss else ok("Only listed prefixes are advertised")


@check("JUNI-RT-000530", "JUEX-RT-000060", fix="set protocols bgp enforce-first-as")
def rt_first_as(c, x):
    peers = c.bgp_peers(external=True)
    if not peers:
        return na("No eBGP neighbors.")
    if c.has(r"protocols bgp enforce-first-as$"):
        return ok("enforce-first-as")
    miss = [ip for g, ip, o in peers if "enforce-first-as" not in o]
    return bad("enforce-first-as is off for: " + ", ".join(miss)) if miss else ok("enforce-first-as on every eBGP group")


@check("JUNI-RT-000540", "JUEX-RT-000650", fix="set protocols bgp group <EBGP-GROUP> neighbor <IP> family inet unicast prefix-limit maximum <N>\n"
                                               "set protocols bgp group <EBGP-GROUP> neighbor <IP> family inet unicast prefix-limit teardown")
def rt_max_prefix(c, x):
    peers = c.bgp_peers(external=True)
    if not peers:
        return na("No eBGP neighbors.")
    miss = [ip for g, ip, o in peers if not any(z.startswith("family inet unicast prefix-limit maximum ") for z in o)]
    return bad("No prefix limit for: " + ", ".join(miss)) if miss else ok("Prefix limits on every eBGP neighbor")


@check("JUNI-RT-000550", "JUEX-RT-000660",
       fix="set policy-options policy-statement BGP-IN term NO-LONG-PREFIXES from route-filter 0.0.0.0/0 prefix-length-range /25-/32\n"
           "set policy-options policy-statement BGP-IN term NO-LONG-PREFIXES then reject")
def rt_long_prefixes(c, x):
    return _ebgp_import(lambda c: lambda z: bool(re.match(r"route-filter 0\.0\.0\.0/0 prefix-length-range /(2[5-9]|3[0-2])-/32", z)),
                        "Prefixes longer than /24 are rejected", "eBGP peers that can send prefixes longer than /24")(c, x)


@check("JUNI-RT-000560", "JUEX-RT-000880", fix="set protocols bgp group IBGP local-address <LOOPBACK-IP>")
def rt_ibgp_source(c, x):
    peers = c.bgp_peers(external=False)
    if not peers:
        return na("No iBGP neighbors.")
    lo = {z.split()[1].split("/")[0] for z in c.inet("lo0") if z.startswith("address ")}
    if not lo:
        return bad("No loopback address to source iBGP sessions from.")
    miss = [ip for g, ip, o in peers if not any(z.startswith("local-address ") and z.split()[1] in lo for z in o)]
    return bad("iBGP peers not sourced from lo0: " + ", ".join(miss)) if miss else ok("iBGP sourced from the loopback")


@check("JUEX-RT-000280", fix="delete system phone-home")
def rt_phone_home(c, x):
    return bad("phone-home is configured.") if c.has(r"system phone-home") else ok("No call-home feature")


@check("JUEX-RT-000580", fix="delete system auto-configuration\ndelete system phone-home")
def rt_ztp(c, x):
    on = [f for f in ("auto-configuration", "phone-home") if c.has(rf"system {f}")]
    return bad("Zero-touch features configured: " + ", ".join(on)) if on else ok("No zero-touch provisioning")


@check("JUEX-RT-000610", fix="delete interfaces <IF> unit <N> family inet targeted-broadcast")
def rt_directed_bcast(c, x):
    on = [n for n in c.ifs if "targeted-broadcast" in c.inet(n)]
    return bad("Directed broadcast on: " + ", ".join(on)) if on else ok("No directed broadcast")


MANUAL_WHY.update({
    **{i: "Verify filters match the organization's information flow control policy." for i in ("JUNI-RT-000010", "JUEX-RT-000010")},
    **{i: "Verify the perimeter filters match the approved interconnection policy." for i in ("JUNI-RT-000250", "JUEX-RT-000120")},
    **{i: "Verify inbound rules permit only authorized sources to authorized destinations." for i in ("JUNI-RT-000260", "JUEX-RT-000730")},
    **{i: "Applies only to an enclave connected to an alternate gateway." for i in ("JUNI-RT-000290", "JUNI-RT-000300", "JUEX-RT-000180", "JUEX-RT-000190")},
    **{i: "Verify inbound filtering follows DoD Instruction 8551.1 (PPSM)." for i in ("JUNI-RT-000320", "JUEX-RT-000400")},
    **{i: "Applies to provider routers peering with customer edge (CE) routers." for i in ("JUNI-RT-000500", "JUNI-RT-000535", "JUEX-RT-000040", "JUEX-RT-000100")},
    **{i: "Applies to provider routers that must hide IP core prefixes." for i in ("JUNI-RT-000520", "JUEX-RT-000430")},
    **{i: "Applies only to an out-of-band management (OOBM) gateway router." for i in
       ("JUNI-RT-000390", "JUNI-RT-000400", "JUNI-RT-000410", "JUNI-RT-000420", "JUNI-RT-000430", "JUNI-RT-000440", "JUNI-RT-000450",
        "JUEX-RT-000200", "JUEX-RT-000210", "JUEX-RT-000460", "JUEX-RT-000470", "JUEX-RT-000480", "JUEX-RT-000490")},
    "JUEX-RT-001020": "Verify the device follows every DoD security configuration guide that applies to it.",
})

# Rules for features OneConfig doesn't generate: not applicable until the feature appears in the configuration.
_GATES = [
    (("JUNI-RT-000570", "JUNI-RT-000580", "JUNI-RT-000590", "JUNI-RT-000600", "JUNI-RT-000750", "JUEX-RT-000320",
      "JUEX-RT-000350", "JUEX-RT-000360", "JUEX-RT-000890", "JUEX-RT-000900", "JUEX-RT-000910"),
     r"^set protocols (mpls|ldp|rsvp)", "MPLS is not configured."),
    (tuple(f"JUNI-RT-{n:06d}" for n in (610, 620, 630, 640, 650, 660, 680, 690, 700, 710, 720, 730, 740, 770)) +
     tuple(f"JUEX-RT-{n:06d}" for n in (310, 330, 340, 440, 450, 520, 560, 670, 920, 930, 940, 950, 960, 970)),
     r"^set routing-instances \S+ instance-type (vrf|vpls|l2vpn|evpn|virtual-switch)", "Not a PE router (no VRF, VPLS or L2VPN instances)."),
    (tuple(f"JUNI-RT-{n:06d}" for n in range(780, 890, 10)) +
     tuple(f"JUEX-RT-{n:06d}" for n in (130, 140, 150, 220, 230, 680, 690, 700, 710, 780, 790)),
     r"^set protocols pim ", "Multicast routing (PIM) is not enabled."),
    (tuple(f"JUNI-RT-{n:06d}" for n in range(890, 950, 10)) + tuple(f"JUEX-RT-{n:06d}" for n in (70, 80, 90, 570, 800, 980)),
     r"^set protocols msdp ", "MSDP is not configured."),
    (tuple(f"JUNI-RT-{n:06d}" for n in (235, 381, 382, 383, 384, 385, 386, 387)) +
     tuple(f"JUEX-RT-{n:06d}" for n in (810, 820, 830, 840, 850, 860, 870, 990)) + ("JUEX-RT-001000", "JUEX-RT-001010"),
     r"^set interfaces .* family inet6", "IPv6 is not configured."),
]
for _ids, _pat, _why in _GATES:
    for _id in _ids:
        CHECKS[_id] = (_feature_gate(_pat, _why), "")
