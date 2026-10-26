"""Hierarchy-aware diff between a OneConfig candidate config and a device's running config.

Merge-safe by design: OneConfig only adds or changes what it generated. Settings it doesn't manage
(licenses, certificates, platform defaults, unused ports) are never touched. The one exception is an
opt-in list of stale items (old SNMP communities, users, NTP/syslog servers...) the user can choose to remove."""
import re
from dataclasses import dataclass, field

SKIP = re.compile(r"^(!|end$|Building configuration|Current configuration|version |Load for |Time source )")
# A "no X" line in the candidate is already satisfied when X is simply absent and X is off by default.
DEFAULT_OFF = {"service config", "ip dns server", "ip mask-reply", "ip directed-broadcast", "boot network",
               "shutdown", "lldp transmit", "lldp receive", "service finger", "service tcp-small-servers",
               "service udp-small-servers", "ip identd", "ip finger"}
# Lines that carry a secret. The key is the line minus the secret, so "username admin privilege 15 secret 9 $9$..."
# on the device matches the candidate's "username admin privilege 15 algorithm-type scrypt secret <x>", while a
# change to anything else on the line (privilege, password policy) still gets pushed.
SECRET = [re.compile(p) for p in (
    r"^(username \S+.*?) (?:algorithm-type \S+ )?(?:secret|password) .*$",
    r"^(enable) (?:algorithm-type \S+ )?secret .*$",
    r"^(key-string) .*$",
    r"^(key) (?!\d+$).*$",  # tacacs/radius key (not "key 1" inside a key chain)
    r"^(ntp authentication-key \d+ \S+) .*$",
    r"^(authentication mode hmac-sha-256) .*$",
    r"^(neighbor \S+ password) .*$",
    r"^((?:tacacs|radius)-server host \S+) key .*$",  # NX-OS / EOS server keys
    r"^(password) \d+ .*$",  # NX-OS BGP neighbor password (inside the neighbor block)
    r"^(ip ospf message-digest-key \d+ \S+) .*$",  # EOS
    r"^(snmp-server user \S+) .*$",  # NX-OS / EOS show SNMPv3 users (localized keys) in the config
    r"^(enable password) .*$",  # ASA shows every secret as *****
    r"^(failover key) .*$",
    r"^(ospf message-digest-key \d+ md5) .*$",
)]
# Ordered lists that must match exactly: replaced wholesale when they differ.
OWNED_BLOCK = re.compile(r"^ip access-list (standard|extended) \S+$")
OWNED_PREFIX_LIST = re.compile(r"^ip prefix-list (\S+) ")
# Stale top-level items offered for removal (opt-in), with the command that removes each.
STALE = [(re.compile(p), r) for p, r in (
    (r"^snmp-server community (\S+)", "no snmp-server community {0}"),
    (r"^snmp-server host (.+)", "no snmp-server host {0}"),
    (r"^snmp-server group (\S+ v\S+)", "no snmp-server group {0}"),
    (r"^username (\S+)", "no username {0}"),
    (r"^enable password", "no enable password"),
    (r"^ntp server (\S+)", "no ntp server {0}"),
    (r"^logging host (\S+)", "no logging host {0}"),
    (r"^logging (\d+\.\d+\.\d+\.\d+)$", "no logging {0}"),
    (r"^tacacs server (\S+)$", "no tacacs server {0}"),
    (r"^tacacs-server host (\S+)", "no tacacs-server host {0}"),
    (r"^radius server (\S+)$", "no radius server {0}"),
    (r"^radius-server host (\S+)", "no radius-server host {0}"),
    (r"^ip route (.+)$", "no ip route {0}"),
    (r"^ip access-list (standard|extended) (\S+)$", "no ip access-list {0} {1}"),
    (r"^ip http (secure-)?server$", "no ip http {0}server"),
    (r"^service (pad|config|finger|tcp-small-servers|udp-small-servers|call-home)$", "no service {0}"),
)]


@dataclass
class Node:
    line: str
    children: list = field(default_factory=list)
    eof: bool = False  # EOS banner: text lines end with a line "EOF" instead of a delimiter

    def find(self, line):
        return next((c for c in self.children if c.line == line), None)


def _norm(line: str) -> str:
    line = re.sub(r"\s+", " ", line.strip())
    return re.sub(r"^\d+ (permit|deny|remark) ", r"\1 ", line)  # ACL sequence numbers


def tree(text: str) -> Node:
    root, stack = Node("<root>"), []
    lines = (text or "").replace("\r", "").split("\n")
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        if not raw.strip() or SKIP.match(raw.strip()):
            continue
        if re.match(r"^banner (login|motd)$", raw.strip()):  # EOS: no delimiter, text ends at a line "EOF"
            body = []
            while i < len(lines) and lines[i].strip() != "EOF":
                body.append(lines[i])
                i += 1
            i += 1
            root.children.append(Node(raw.strip(), [Node("\n".join(body).strip())], eof=True))
            stack = []
            continue
        m = re.match(r"^banner (\w+) (\^C|\S)(.*)$", raw.strip())
        if m:  # banners span lines until the delimiter; store as one node with the text
            kind, delim, rest = m.groups()
            body = [rest]
            while delim not in body[-1] and i < len(lines):
                body.append(lines[i])
                i += 1
            text_ = "\n".join(body).split(delim)[0].strip()
            root.children.append(Node(f"banner {kind}", [Node(text_)]))
            stack = []
            continue
        depth = len(raw) - len(raw.lstrip(" "))
        node = Node(_norm(raw))
        while stack and stack[-1][0] >= depth:
            stack.pop()
        (stack[-1][1] if stack else root).children.append(node)
        stack.append((depth, node))
    return root


def _secret_key(line):
    for rx in SECRET:
        m = rx.match(line)
        if m:
            return m.group(1)
    return None


def _satisfied(line, parent: Node, rotate=False):
    if parent.find(line):
        return True
    key = _secret_key(line)
    if key and not rotate and any(_secret_key(c.line) == key for c in parent.children):
        return True
    if line == "no shutdown":
        return not parent.find("shutdown")
    if line.startswith("no "):
        return line[3:] in DEFAULT_OFF and not parent.find(line[3:])
    return False


def _render(node: Node, depth: int) -> list[str]:
    out = [" " * depth + node.line]
    for c in node.children:
        out += _render(c, depth + 1)
    return out


class _Out:
    """Collects commands, writing each parent context line once per run of children."""
    def __init__(self):
        self.lines, self.ctx = [], ()

    def emit(self, path, lines):
        path = tuple(path)
        keep = 0
        while keep < min(len(path), len(self.ctx)) and path[keep] == self.ctx[keep]:
            keep += 1
        self.lines += [" " * i + p for i, p in enumerate(path) if i >= keep]
        self.lines += lines
        self.ctx = path

    def top(self, lines):
        self.lines += lines
        self.ctx = ()


def _missing(cand: Node, run: Node, path: list, out: _Out, rotate: bool):
    for c in cand.children:
        if not path and c.line.startswith("banner "):
            have = run.find(c.line)
            if not have or [x.line for x in have.children] != [x.line for x in c.children]:
                out.top([c.line, c.children[0].line, "EOF"] if c.eof else [f"{c.line} ^C", c.children[0].line, "^C"])
            continue
        if not path and OWNED_BLOCK.match(c.line):
            have = run.find(c.line)
            if not have or [x.line for x in have.children] != [x.line for x in c.children]:
                out.top(([f"no {c.line}"] if have else []) + _render(c, 0))
            continue
        have = run.find(c.line)
        if have is not None:
            if c.children:
                _missing(c, have, path + [c.line], out, rotate)
            continue
        if not c.children and _satisfied(c.line, run, rotate):
            continue
        pre = []
        m = re.match(r"neighbor (\S+) ao ", c.line)
        if m and any(x.line.startswith(f"neighbor {m.group(1)} password ") for x in run.children):
            pre = [" " * len(path) + f"no neighbor {m.group(1)} password"]  # MD5 and TCP-AO can't coexist
        out.emit(path, pre + _render(c, len(path)))


def snmp_users(show_snmp_user: str) -> set:
    return set(re.findall(r"^User name: (\S+)", show_snmp_user or "", re.M))


def plan(candidate: str, running: str, login_user: str = "", rotate_secrets: bool = False, known_snmp_users=()) -> dict:
    """Commands to push, plus opt-in removals. Lines are indented so each one's parent context is explicit.
    SNMPv3 users never appear in a running config, so pass the names from `show snmp user` as known_snmp_users."""
    cand, run = tree(candidate), tree(running)
    if not rotate_secrets:
        cand.children = [c for c in cand.children
                         if not (c.line.startswith("snmp-server user ") and c.line.split()[2] in known_snmp_users)]
    out = _Out()
    # prefix-lists are ordered top-level entries: if ours differ from the device's, replace the whole list
    for name in sorted({m.group(1) for c in cand.children if (m := OWNED_PREFIX_LIST.match(c.line))}):
        mine = [c.line for c in cand.children if c.line.startswith(f"ip prefix-list {name} ")]
        theirs = [c.line for c in run.children if c.line.startswith(f"ip prefix-list {name} ")]
        if mine != theirs:
            out.top(([f"no ip prefix-list {name}"] if theirs else []) + mine)
    cand.children = [c for c in cand.children if not OWNED_PREFIX_LIST.match(c.line)]
    _missing(cand, run, [], out, rotate_secrets)

    wanted = {c.line for c in tree(candidate).children}
    remove = []
    for c in run.children:
        if c.line in wanted or f"no {c.line}" in wanted:  # already handled by the push itself
            continue
        for rx, cmd in STALE:
            m = rx.match(c.line)
            if m:
                if rx.pattern.startswith("^username") and m.group(1) == login_user:
                    break  # never remove the account we're logged in with
                if rx.pattern.startswith("^username") and any(w.startswith(f"username {m.group(1)} ") for w in wanted):
                    break
                if rx.pattern.startswith("^ip access-list") and re.search(  # still used by NAT, a route-map, an interface...
                        rf"^(?!ip access-list ).*(?<![\w-]){re.escape(m.group(2))}(?![\w-])", running, re.M):
                    break
                remove.append(cmd.format(*[g or "" for g in m.groups()]))
                break
    return {"add": out.lines, "remove": list(dict.fromkeys(remove))}


# ---------------------------------------------------------------- Junos (display set)
# A line with a secret matches when everything before the secret matches: Junos shows secrets as $9$ / $6$ hashes.
J_SECRET = re.compile(r'^(set .*? (?:secret|authentication-key|authentication-password|privacy-password|encrypted-password|value|'
                      r'password|ascii-text|hexadecimal)) "?[^"\s]+"?$')
# Ordered objects OneConfig owns: if the device's copy differs at all, it is deleted and written again (one commit).
J_OWNED = re.compile(r"^set ((?:firewall family inet filter|firewall policer|policy-options policy-statement|policy-options prefix-list|"
                     r"security authentication-key-chains key-chain) \S+)")
J_STALE = [(re.compile(p), r) for p, r in (
    (r"^set system services (telnet|finger|ftp|xnm-clear-text|rlogin|tftp-server|web-management)( |$)", "delete system services {0}"),
    (r"^set snmp community (\S+)", "delete snmp community {0}"),
    (r"^set system login user (\S+) ", "delete system login user {0}"),
    (r"^set system ntp server (\S+)", "delete system ntp server {0}"),
    (r"^set system syslog host (\S+)", "delete system syslog host {0}"),
    (r"^set system (tacplus|radius)-server (\S+)", "delete system {0}-server {1}"),
    (r"^set routing-options static route (\S+)", "delete routing-options static route {0}"),
    (r"^set system (phone-home|auto-configuration)( |$)", "delete system {0}"),
)]


def _jset(text):
    return [re.sub(r"\s+", " ", l.strip()) for l in (text or "").splitlines() if l.strip().startswith("set ")]


def junos_plan(candidate: str, running: str, login_user: str = "", rotate_secrets: bool = False) -> dict:
    """Junos version of plan(): `set` lines to add (with `delete` first for owned objects that differ) and opt-in removals."""
    cand, run = _jset(candidate), _jset(running)
    have, keys = set(run), {m.group(1) for l in run if (m := J_SECRET.match(l))}
    owned = {}
    for l in cand:
        m = J_OWNED.match(l)
        if m:
            owned.setdefault(m.group(1), []).append(l)
    add = []
    for obj, mine in owned.items():
        theirs = [l for l in run if l == "set " + obj or l.startswith(f"set {obj} ")]
        key = lambda l: J_SECRET.match(l).group(1) if J_SECRET.match(l) and not rotate_secrets else l  # noqa: E731
        terms = lambda ls: list(dict.fromkeys(re.findall(r" term (\S+)", " ".join(ls))))  # noqa: E731  only term order matters
        same = sorted(map(key, mine)) == sorted(map(key, theirs)) and terms(mine) == terms(theirs)
        if not same:
            add += ([f"delete {obj}"] if theirs else []) + mine
    for l in cand:
        if J_OWNED.match(l) or l in have:
            continue
        m = J_SECRET.match(l)
        if m and not rotate_secrets and m.group(1) in keys:
            continue
        add.append(l)
    wanted = set(cand)
    remove = []
    for l in run:
        if l in wanted:
            continue
        for rx, cmd in J_STALE:
            m = rx.match(l)
            if m:
                if rx.pattern.startswith("^set system login user") and (m.group(1) == login_user or any(
                        w.startswith(f"set system login user {m.group(1)} ") for w in wanted)):
                    break
                if rx.pattern.startswith("^set system ntp server") and any(w.startswith(f"set system ntp server {m.group(1)} ") for w in wanted):
                    break
                if rx.pattern.startswith("^set system syslog host") and any(w.startswith(f"set system syslog host {m.group(1)} ") for w in wanted):
                    break
                if rx.pattern.startswith("^set system (tacplus") and any(w.startswith(f"set system {m.group(1)}-server {m.group(2)} ") for w in wanted):
                    break
                if rx.pattern.startswith("^set routing-options static") and any(w.startswith(f"set routing-options static route {m.group(1)} ") for w in wanted):
                    break
                remove.append(cmd.format(*[g or "" for g in m.groups()]).strip())
                break
    return {"add": add, "remove": list(dict.fromkeys(remove))}


# ---------------------------------------------------------------- Cisco ASA
# Flat, ordered statements handled as whole lists; everything else goes through the IOS tree diff.
A_FLAT = re.compile(r"^(banner |access-list |nat \(|access-group )")
A_STALE = [(re.compile(p), r) for p, r in (
    (r"^snmp-server community (\S+)", "no snmp-server community {0}"),
    (r"^snmp-server host (\S+ \S+)", "no snmp-server host {0}"),
    (r"^username (\S+) ", "no username {0}"),
    (r"^(telnet \S+ \S+ \S+)$", "no {0}"),
    (r"^(ssh \d\S* \S+ \S+)$", "no {0}"),
    (r"^(http \d\S* \S+ \S+)$", "no {0}"),
    (r"^http server enable", "no http server enable"),
    (r"^ntp server (\S+)", "no ntp server {0}"),
    (r"^logging host (\S+ \S+)", "no logging host {0}"),
    (r"^(route \S+ \S+ \S+ \S+)", "no {0}"),
)]


def _asa_split(text):
    keep = [l.rstrip() for l in (text or "").replace("\r", "").split("\n")
            if l.strip() and not l.startswith((":", "!")) and not re.match(r"(ASA Version|Cryptochecksum)", l)]
    flat = lambda p: [re.sub(r"\s+", " ", l.strip()) for l in keep if l.startswith(p)]  # noqa: E731
    return flat("banner "), flat("access-list "), flat("nat ("), flat("access-group "), "\n".join(l for l in keep if not A_FLAT.match(l))


def asa_plan(candidate: str, running: str, login_user: str = "", rotate_secrets: bool = False) -> dict:
    """ASA version of plan(). Access lists, NAT and banners are ordered lists; an access list that differs is cleared and
    written again (its access-group with it, since clearing unbinds it). Commands come in an order the ASA accepts."""
    c_ban, c_acl, c_nat, c_grp, c_rest = _asa_split(candidate)
    r_ban, r_acl, r_nat, r_grp, r_rest = _asa_split(running)
    cand, run, out = tree(c_rest), tree(r_rest), _Out()
    _missing(cand, run, [], out, rotate_secrets)
    for c in cand.children:  # groups are allow-lists: members the device has and we don't are removed
        have = run.find(c.line)
        if c.line.startswith("object-group ") and have:
            extra = [x.line for x in have.children if not c.find(x.line)]
            if extra:
                out.emit([c.line], [" no " + x for x in extra])
    name = lambda l: l.split()[1]  # noqa: E731
    rebind = set()
    for acl in dict.fromkeys(map(name, c_acl)):
        mine, theirs = [l for l in c_acl if name(l) == acl], [l for l in r_acl if name(l) == acl]
        if mine != theirs:
            out.top(([f"clear configure access-list {acl}"] if theirs else []) + mine)
            rebind.add(acl)
    out.top([l for l in c_nat if l not in r_nat])
    out.top([l for l in c_grp if l not in r_grp or l.split()[1] in rebind])
    if c_ban != r_ban:
        out.top((["no banner login"] if r_ban else []) + c_ban)
    remove = [f"no {l}" for l in r_nat if l not in c_nat]
    rebound = {l.split()[-1] for l in c_grp}
    for acl in dict.fromkeys(map(name, r_acl)):
        refs = [l for l in running.splitlines() if re.search(rf"(?<![\w-]){re.escape(acl)}(?![\w-])", l) and not l.startswith("access-list ")]
        if acl not in map(name, c_acl) and all(re.match(r"access-group \S+ in interface (\S+)", r) and r.split()[-1] in rebound for r in refs):
            remove.append(f"clear configure access-list {acl}")  # only bound where our access lists take over
    wanted = {x.line for x in cand.children}
    for c in run.children:
        if c.line in wanted:
            continue
        for rx, cmd in A_STALE:
            m = rx.match(c.line)
            if m:
                if rx.pattern.startswith("^username") and (m.group(1) == login_user or any(w.startswith(f"username {m.group(1)} ") for w in wanted)):
                    break
                head = " ".join(c.line.split()[:3 if c.line.startswith("ntp") else 4])
                if rx.pattern.startswith(("^ntp server", "^logging host")) and any(w == head or w.startswith(head + " ") for w in wanted):
                    break  # same server, other options: the add above updates it
                remove.append(cmd.format(*m.groups()))
                break
    return {"add": out.lines, "remove": list(dict.fromkeys(remove))}


# ---------------------------------------------------------------- PAN-OS (set form)
# Secrets come back encrypted ("-AQ==..." or a hash), so a secret line matches when everything before the secret matches.
P_SECRET = re.compile(r"^(set .*? (?:phash|secret|key|authentication-key|password|authpwd|privpwd)) \S+$")
# Objects whose lists and fields OneConfig owns: if the device's copy differs, it is deleted and written again.
P_OWNED = re.compile(r"^set ((?:shared )?(?:rulebase (?:security|nat) rules|address-group|service-group|zone|profile-group|"
                     r"profiles (?:virus|spyware|vulnerability|dos-protection)|network profiles zone-protection-profile) \S+)( |$)")
P_STALE = [(re.compile(p), r) for p, r in (
    (r"^set rulebase (security|nat) rules (\S+) ", "delete rulebase {0} rules {1}"),
    (r"^set mgt-config users (\S+) ", "delete mgt-config users {0}"),
    (r"^set deviceconfig system snmp-setting access-setting version v2c", "delete deviceconfig system snmp-setting access-setting version v2c"),
    (r"^set network virtual-router (\S+) routing-table ip static-route (\S+) ", "delete network virtual-router {0} routing-table ip static-route {1}"),
    (r"^set (?:shared )?log-settings syslog (\S+) server (\S+) ", "delete shared log-settings syslog {0} server {1}"),
    (r"^set network dns-proxy (\S+)", "delete network dns-proxy {0}"),
)]


def _pset(text):
    """set lines, quotes dropped and [ a b ] lists expanded to one line per member, for comparison."""
    out = []
    for l in (text or "").splitlines():
        l = re.sub(r"\s+", " ", l.strip())
        if not l.startswith("set "):
            continue
        l = l.replace('"', "")
        m = re.match(r"^(.*?) \[ (.*) \]$", l)
        out += [f"{m[1]} {x}" for x in m[2].split()] if m else [l]
    return out


def _pkey(l, rotate=False):
    m = P_SECRET.match(l)
    return m[1] + " <secret>" if m and not rotate else l


def pan_plan(candidate: str, running: str, login_user: str = "", rotate_secrets: bool = False) -> dict:
    """PAN-OS version of plan(): set lines to add (owned objects that differ are deleted and written again, and
    OneConfig's rules are then moved into its order), plus opt-in removals."""
    cand_lines = [l.strip() for l in (candidate or "").splitlines() if l.strip().startswith("set ")]
    have = {_pkey(l, rotate_secrets) for l in _pset(running)}
    run = _pset(running)
    add, redone = [], set()
    owned = {}
    for l in cand_lines:
        m = P_OWNED.match(l)
        if m:
            owned.setdefault(m[1], []).append(l)
    for obj, mine in owned.items():
        theirs = {_pkey(l, rotate_secrets) for l in run if l.startswith(f"set {obj} ") or l == f"set {obj}"}
        if {_pkey(l, rotate_secrets) for l in _pset("\n".join(mine))} != theirs:
            add += ([f"delete {obj}"] if theirs else []) + mine
            redone.add(obj)
    for l in cand_lines:
        if not P_OWNED.match(l) and not all(_pkey(x, rotate_secrets) in have for x in _pset(l)):
            add.append(l)
    for kind in ("security", "nat"):  # first match wins, so keep OneConfig's rule order
        mine = list(dict.fromkeys(m[1] for l in cand_lines if (m := re.match(rf"^set rulebase {kind} rules (\S+) ", l))))
        order = [m[1] for l in run if (m := re.match(rf"^set rulebase {kind} rules (\S+) ", l))]
        theirs = [r for r in dict.fromkeys(order) if r in mine]
        if theirs != mine or any(o.startswith(f"rulebase {kind} rules ") for o in redone):
            add += [f"move rulebase {kind} rules {r} bottom" for r in mine]
    remove = []
    for l in run:
        for rx, cmd in P_STALE:
            m = rx.match(l)
            if not m:
                continue
            cmd = cmd.format(*m.groups())
            target = "set " + cmd[len("delete "):]
            if any(c.startswith(target + " ") or c == target for c in cand_lines):
                break  # OneConfig manages it
            if rx.pattern.startswith("^set mgt-config users") and m[1] == login_user:
                break  # never remove the account we're logged in with
            remove.append(cmd)
            break
    return {"add": add, "remove": list(dict.fromkeys(remove))}


# ---------------------------------------------------------------- FortiOS
F_SECRET = {"password", "passwd", "key", "key-string", "secret", "auth-pwd", "priv-pwd", "psksecret", "secondary-key", "secondary-secret"}
# Numbered tables: an entry is the same entry when this field matches, whatever its number on the device
F_NATURAL = {"firewall policy": "name", "firewall central-snat-map": "comments", "firewall DoS-policy": "name", "router static": "dst",
             "system ntp ntpserver": "server", "router ospf network": "prefix", "router bgp network": "prefix"}
F_DEFAULT = {"router static": ["0.0.0.0", "0.0.0.0"]}  # a route without dst is the default route
F_ORDERED = ("firewall policy", "firewall central-snat-map")  # first match wins
# Entries OneConfig offers to remove when its own config doesn't have them: table -> field that names them for you
F_STALE = {"firewall policy": "name", "firewall central-snat-map": "comments", "router static": "dst", "system admin": None,
           "system snmp community": "name", "firewall vip": None, "user tacacs+": None, "user radius": None}


def _fnode():
    return {"sets": {}, "unset": set(), "subs": {}, "entries": None}


def fos_tree(text: str) -> dict:
    """A FortiOS config as nested blocks: sets (field -> (values, line)), sub-blocks, and table entries. The VDOM-mode
    wrapper (config vdom / edit root, config global) is read through."""
    import shlex
    root = _fnode()
    stack = [(root, "root")]
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            words = shlex.split(line)
        except ValueError:
            words = line.split()
        cmd, args, (cur, kind) = words[0], words[1:], stack[-1]
        if cmd == "config":
            if kind == "root" and args[:1] in (["vdom"], ["global"]):
                stack.append((cur, "wrap"))
                continue
            sub = cur["subs"].setdefault(" ".join(args), _fnode())
            stack.append((sub, "config"))
        elif cmd == "edit":
            if kind == "wrap":
                stack.append((cur, "wrap-edit"))
                continue
            cur["entries"] = cur["entries"] if cur["entries"] is not None else {}
            stack.append((cur["entries"].setdefault(args[0] if args else "", _fnode()), "edit"))
        elif cmd == "next":
            if kind in ("edit", "wrap-edit"):
                stack.pop()
        elif cmd == "end":
            if kind in ("edit", "wrap-edit") and len(stack) > 1:
                stack.pop()
            if len(stack) > 1:
                stack.pop()
        elif cmd in ("set", "append") and args:
            cur["sets"][args[0]] = (args[1:], line)
        elif cmd == "unset" and args:
            cur["unset"].add(args[0])
            cur["sets"].pop(args[0], None)
    return root


def _q(k):
    return k if re.fullmatch(r"\d+", k) else '"' + k.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _remap(cand, run, path):
    """Give numbered candidate entries the numbers their twins already have on the device; new ones get free numbers."""
    for name, sub in cand["subs"].items():
        p = f"{path} {name}".strip()
        twin = (run or {}).get("subs", {}).get(name) if run else None
        if sub["entries"] is not None and p in F_NATURAL:
            field, theirs, dflt = F_NATURAL[p], (twin or {}).get("entries") or {}, F_DEFAULT.get(p, [])
            by = {tuple(e["sets"].get(field, (dflt, ""))[0]): k for k, e in theirs.items()}
            used = {int(k) for k in theirs if k.isdigit()}
            out = {}
            for k, e in sub["entries"].items():
                nk = by.get(tuple(e["sets"].get(field, (dflt, ""))[0]))
                if nk is None or nk in out:
                    nk = str(max(used | {int(x) for x in out if x.isdigit()} | {0}) + 1)
                out[nk] = e
            sub["entries"] = out
        for k, e in (sub["entries"] or {}).items():
            _remap(e, (((twin or {}).get("entries") or {}).get(k)), p)
        if sub["entries"] is None:
            _remap(sub, twin, p)


def _fdiff(cand, run, rotate):
    body = []
    have = run["sets"] if run else {}
    for f, (vals, line) in cand["sets"].items():
        if f in F_SECRET and f in have and not rotate:
            continue  # already set on the device: left alone unless secrets are rotated
        if f not in have or have[f][0] != vals:
            body.append(line)
    for f in sorted(cand["unset"]):
        if run and have.get(f, ([], ""))[0] not in ([], [""]):
            body.append(f"unset {f}")
    for name, sub in cand["subs"].items():
        inner = _fblock(sub, (run or {}).get("subs", {}).get(name) if run else None, rotate)
        if inner:
            body += [f"config {name}", *("    " + x for x in inner), "end"]
    return body


def _fblock(cand, run, rotate):
    body = _fdiff(cand, run, rotate)
    theirs = ((run or {}).get("entries") or {}) if run else {}
    for k, e in (cand["entries"] or {}).items():
        inner = _fdiff(e, theirs.get(k), rotate)
        if inner or k not in theirs:
            body += [f"edit {_q(k)}", *("    " + x for x in inner), "next"]
    return body


def fos_plan(candidate: str, running: str, login_user: str = "", rotate_secrets: bool = False) -> dict:
    """FortiOS version of plan(): config blocks with only what differs, plus opt-in removals written as
    `delete <table> <entry> (<name>)` (push turns each into its config / delete / end block)."""
    cand, run = fos_tree(candidate), fos_tree(running)
    _remap(cand, run, "")
    add = []
    for name, sub in cand["subs"].items():
        inner = _fblock(sub, run["subs"].get(name), rotate_secrets)
        if inner:
            add += [f"config {name}", *("    " + x for x in inner), "end"]
    for name in F_ORDERED:  # keep OneConfig's order whenever its entries changed or new ones were added
        mine = list(((cand["subs"].get(name) or {}).get("entries") or {}))
        if len(mine) > 1 and f"config {name}" in add:
            add += [f"config {name}", *(f"    move {b} after {a}" for a, b in zip(mine, mine[1:])), "end"]
    remove = []
    for name, label in F_STALE.items():
        mine = set(((cand["subs"].get(name) or {}).get("entries") or {}))
        for k, e in ((run["subs"].get(name) or {}).get("entries") or {}).items():
            if k in mine or (name == "system admin" and k == login_user):
                continue  # never remove the account we're logged in with
            what = " ".join(e["sets"].get(label, (F_DEFAULT.get(name, []), ""))[0]) if label else ""
            if name == "router static":
                what += " via " + " ".join(e["sets"].get("gateway", ([], ""))[0])
            remove.append(f"delete {name} {k}" + (f" ({what})" if what else ""))
    return {"add": add, "remove": remove}


def fos_removal(item: str) -> list[str]:
    """`delete firewall policy 7 (allow-all)` -> the CLI block that removes it."""
    m = re.match(r"^delete (.+?) (\S+)(?: \(.*\))?$", item)
    return [f"config {m[1]}", f"    delete {_q(m[2])}", "end"]
