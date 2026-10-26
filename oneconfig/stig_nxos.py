"""DISA STIG checks for Cisco NX-OS (Cisco NX-OS Switch NDM V3R6, L2S V3R4, RTR V3R4).

Most rule IDs mean the same as in the IOS-XE STIGs and many checks are shared; this module overrides the ones
whose NX-OS syntax differs. Commands come from DISA's NX-OS fix text."""
import re

from .stig import CHECKS as IOS
from .stig import (MANUAL_WHY as IOS_WHY, FIPS_HMAC, _ebgp, dc_acl_fix, ssh_algos, _edge_ifs, _ext_acl, _feature_gate, _needs_bgp, _perimeter, bad, manual,
                   na, ok)

CHECKS = {k: v for k, v in IOS.items() if not k.startswith("CISC-RT-000") or int(k[-3:]) < 590}  # NX-OS gates below
MANUAL_WHY = dict(IOS_WHY)


def check(*ids, fix=""):
    def deco(fn):
        for i in ids:
            CHECKS[i] = (fn, fix)
        return fn
    return deco


def _vty(c):
    return next((k for p, k in c.b if p == "line vty"), [])


def _mins(k):
    m = next((x for x in k if x.startswith("exec-timeout ")), None)
    return int(m.split()[1]) if m else None


# ---------------------------------------------------------------- NDM
@check("CISC-ND-000010", fix="line vty\n  session-limit 2")
def nd_sessions(c, x):
    m = next((z for z in _vty(c) if z.startswith("session-limit ")), None)
    return ok(m) if m else bad("line vty has no session-limit.")


ACCOUNTING = "aaa accounting default group TACACS-SERVERS"


@check("CISC-ND-000090", "CISC-ND-000100", "CISC-ND-000110", "CISC-ND-000120", "CISC-ND-000210", "CISC-ND-000330",
       "CISC-ND-000880", "CISC-ND-000940", "CISC-ND-001240", "CISC-ND-001250", "CISC-ND-001270", fix=ACCOUNTING)
def nd_accounting(c, x):
    m = next((p for p in c.top if re.match(r"aaa accounting default group \S+", p)), None)
    return ok(m) if m else bad("AAA accounting to an authentication server is not configured.")


@check("CISC-ND-000140", fix="ip access-list MGMT-ACCESS\n  10 permit ip <MGMT-NET>/<LEN> any\n  20 deny ip any any log\n"
                            "line vty\n  access-class MGMT-ACCESS in")
def nd_vty_acl(c, x):
    a = next((z.split()[1] for z in _vty(c) if re.match(r"access-class \S+ in$", z)), None)
    if not a:
        return bad("line vty has no inbound access-class.")
    e = c.acls.get(a)
    if not e:
        return bad(f"access-class {a} refers to an ACL that is not defined.")
    return ok(f"access-class {a} in") if re.match(r"deny\s+ip\s+any\s+any", e[-1]) else bad(f"{a} does not end with deny ip any any.")


@check("CISC-ND-000150", fix="ssh login-attempts 3")
def nd_lockout(c, x):
    m = re.search(r"^ssh login-attempts (\d+)", c.text, re.M)
    return ok(m.group(0)) if m and int(m.group(1)) <= 3 else bad("SSH login attempts are not limited to 3.")


@check("CISC-ND-000290", fix="ip access-list <ACL>\n  deny ip any any log\nlogging ip access-list cache entries 8000")
def nd_acl_log(c, x):
    nolog = [a for a, e in c.acls.items() if any(z.startswith("deny") and not z.endswith(" log") for z in e)]
    if nolog:
        return bad("Deny statements without log in: " + ", ".join(nolog))
    return ok("Denies are logged") if c.has(r"^logging ip access-list cache entries") else bad("Optimized ACL logging is not enabled.")


NONSECURE = ("telnet", "wccp", "nxapi", "imp", "http-server")


@check("CISC-ND-000470", fix="\n".join("no feature " + f for f in NONSECURE))
def nd_services(c, x):
    on = [f for f in NONSECURE if f"feature {f}" in c.top]
    if "feature dhcp" in c.top and not c.has(r"^ip dhcp snooping") and not re.search(r"^[ \t]+ip dhcp relay", c.text, re.M):
        on.append("dhcp (enabled but not used)")
    return bad("Enabled: feature " + ", feature ".join(on)) if on else ok("No unnecessary features enabled")


@check("CISC-ND-000490", fix="username <ADMIN-USER> password <SECRET> role network-admin\naaa authentication login default fallback error local")
def nd_last_resort(c, x):
    users = [p.split()[1] for p in c.top if p.startswith("username ")]
    if len(users) != 1:
        return bad(f"{len(users)} local accounts ({', '.join(users) or 'none'}); keep exactly one account of last resort.")
    if "no aaa authentication login default fallback error local" in c.top:
        return bad("Fallback to the local account is disabled.")
    return ok(f"One local account: {users[0]}")


@check("CISC-ND-000530", "CISC-ND-001200", fix="ssh macs hmac-sha2-256 hmac-sha2-512")
def nd_ssh_mac(c, x):
    m = re.search(r"^ssh macs (.+)$", c.text, re.M)
    return ssh_algos("mac", m and m.group(0), m and m.group(1).split())


@check("CISC-ND-001210", fix="ssh ciphers aes256-ctr aes128-ctr")
def nd_ssh_enc(c, x):
    m = re.search(r"^ssh ciphers (.+)$", c.text, re.M)
    return ssh_algos("cipher", m and m.group(0), m and m.group(1).split())


@check("CISC-ND-000570", "CISC-ND-000580", "CISC-ND-000590", "CISC-ND-000600", fix="password strength-check")
def nd_strength(c, x):
    return bad("password strength-check is disabled.") if "no password strength-check" in c.top else ok("password strength-check (on by default)")


@check("CISC-ND-000720", fix="line console\n  exec-timeout 5\nline vty\n  exec-timeout 5")
def nd_idle(c, x):
    probs = []
    for line in ("line console", "line vty"):
        k = next((k for p, k in c.b if p == line), [])
        t = _mins(k)
        if t is None or t == 0 or t > 5:
            probs.append(f"{line} exec-timeout is {t if t else 'not set'}")
    return bad("; ".join(probs)) if probs else ok("Console and VTY time out after 5 minutes")


@check("CISC-ND-000980", fix="logging logfile messages 6 size 4096")
def nd_logfile(c, x):
    m = re.search(r"^logging logfile \S+ \d+ size \d+", c.text, re.M)
    return ok(m.group(0)) if m else bad("No logfile size configured.")


@check("CISC-ND-001000", "CISC-ND-001310", fix="logging server <SYSLOG> 6")
def nd_syslog_one(c, x):
    m = next((p for p in c.top if p.startswith("logging server ")), None)
    return ok(m) if m else bad("No remote syslog server.")


@check("CISC-ND-001030", fix="ntp server <NTP-1>\nntp server <NTP-2>")
def nd_ntp(c, x):
    n = sum(p.startswith("ntp server ") for p in c.top)
    return ok(f"{n} NTP servers") if n >= 2 else bad(f"{n} NTP server(s); two are required.")


@check("CISC-ND-001050")
def nd_utc(c, x):
    m = re.search(r"^clock timezone .*", c.text, re.M)
    return ok(m.group(0) + " (offset from UTC)" if m else "UTC (default)")


@check("CISC-ND-001130", "CISC-ND-001140", fix="snmp-server user <USER> auth sha <AUTH> priv aes-128 <PRIV>")
def nd_snmp(c, x):
    if c.has(r"^snmp-server community "):
        return bad("SNMP community strings are configured.")
    users = [p for p in c.top if p.startswith("snmp-server user ")]
    weak = [p.split()[2] for p in users if not re.search(r"\bauth sha", p) or not re.search(r"\bpriv (aes-128|aes)", p)]
    if weak:
        return bad("SNMP users without SHA authentication and AES privacy: " + ", ".join(weak))
    return ok("SNMPv3 with SHA and AES") if users else na("SNMP is not configured.")


@check("CISC-ND-001150", fix="ntp authentication-key 1 md5 <KEY>\nntp trusted-key 1\nntp authenticate\nntp server <NTP> key 1")
def nd_ntp_auth(c, x):
    servers = [p for p in c.top if p.startswith("ntp server ")]
    if not servers:
        return bad("No NTP servers.")
    if "ntp authenticate" not in c.top or not c.has(r"^ntp trusted-key "):
        return bad("NTP authentication is not enabled.")
    nokey = [p.split()[2] for p in servers if " key " not in p]
    return bad("NTP servers without a key: " + ", ".join(nokey)) if nokey else ok("NTP authenticated")


@check("CISC-ND-001260", "CISC-ND-001280", fix="logging level authpriv 6")
def nd_authpriv(c, x):
    m = re.search(r"^logging level authpriv (\d)", c.text, re.M)
    return ok(m.group(0)) if m and int(m.group(1)) >= 6 else bad("authpriv messages are not logged at level 6.")


@check("CISC-ND-001370", fix="tacacs-server host <IP-1> key <KEY>\ntacacs-server host <IP-2> key <KEY>\n"
                            "aaa group server tacacs+ TACACS-SERVERS\n  server <IP-1>\n  server <IP-2>\n"
                            "aaa authentication login default group TACACS-SERVERS")
def nd_aaa_servers(c, x):
    m = re.search(r"^aaa authentication login default group (\S+)", c.text, re.M)
    if not m:
        return bad("Logins are not authenticated by a server group.")
    grp = next((k for p, k in c.b if re.match(rf"aaa group server \S+ {re.escape(m.group(1))}$", p)), [])
    n = sum(z.startswith("server ") for z in grp)
    return ok(f"{m.group(1)} has {n} servers") if n >= 2 else bad(f"{m.group(1)} has {n} server(s); two are required.")


@check("CISC-ND-001410", fix='event manager applet BACKUP_CONFIG\n  event syslog pattern "SYSLOG_CONFIG_I"\n'
                            '  action 1 cli copy running-config scp://<USER>@<SERVER>/<HOST>.cfg vrf management')
def nd_backup(c, x):
    for p, k in c.b:
        if p.startswith("event manager applet ") and any("CONFIG_I" in z for z in k) and any(re.search(r"cli .*copy ", z) for z in k):
            return ok(p)
    return bad("No EEM applet backs up the configuration after changes.")


@check("CISC-ND-001450", fix="logging server <SYSLOG-1> 6\nlogging server <SYSLOG-2> 6")
def nd_syslog(c, x):
    n = sum(p.startswith("logging server ") for p in c.top)
    return ok(f"{n} syslog servers") if n >= 2 else bad(f"{n} syslog server(s); two are required.")


@check("CISC-ND-001220", "CISC-RT-000120", fix="copp profile strict")
def nd_copp(c, x):
    m = re.search(r"^copp profile (strict|moderate|lenient|dense)", c.text, re.M)
    if m:
        return ok(f"{m.group(0)}. Verify its rates meet the organization's needs with show policy-map interface control-plane.")
    if c.has(r"^control-plane") or c.has(r"^policy-map type control-plane "):
        return manual("A custom CoPP policy is configured; verify it classifies and rate-limits traffic.")
    return bad("No CoPP profile in the configuration.")


# ---------------------------------------------------------------- L2S
@check("CISC-L2-000020", "CISC-L2-000080", fix="feature dot1x\naaa authentication dot1x default group RADIUS-SERVERS\n"
                                              "interface <ACCESS-PORT>\n  dot1x port-control auto\n  dot1x mac-auth-bypass")
def l2_dot1x(c, x):
    if not c.access:
        return na("No active access ports.")
    if "feature dot1x" not in c.top:
        return bad("feature dot1x is not enabled.")
    miss = [n for n, k in c.access.items() if "dot1x port-control auto" not in k]
    return bad("Access ports without 802.1X: " + ", ".join(miss[:8])) if miss else ok(f"802.1X on all {len(c.access)} access ports")


@check("CISC-L2-000030", fix="no feature vtp")
def l2_vtp(c, x):
    if "feature vtp" not in c.top:
        return ok("VTP is not enabled")
    return ok("VTP password configured") if c.has(r"^vtp password ") else bad("VTP is enabled without a password.")


@check("CISC-L2-000060", "CISC-L2-000070")
def l2_span(c, x):
    return ok("NX-OS supports SPAN: monitor session <n> / source interface <port> both / destination interface <port>")


@check("CISC-L2-000100", fix="interface <ACCESS-PORT>\n  spanning-tree bpduguard enable")
def l2_bpdu(c, x):
    if not c.access:
        return na("No active access ports.")
    if "spanning-tree port type edge bpduguard default" in c.top:
        return ok("BPDU Guard on all edge ports by default")
    miss = [n for n, k in c.access.items() if "spanning-tree bpduguard enable" not in k]
    return bad("Access ports without BPDU Guard: " + ", ".join(miss[:8])) if miss else ok(f"BPDU Guard on all {len(c.access)} access ports")


@check("CISC-L2-000190", fix="feature udld")
def l2_udld(c, x):
    if "feature udld" in c.top:
        off = [n for n, k in c.ifs.items() if "udld disable" in k]
        return bad("UDLD disabled on: " + ", ".join(off)) if off else ok("feature udld")
    return manual("UDLD is off. This is a finding only if the switch has fiber links to neighbors.")


# ---------------------------------------------------------------- RTR
def _ospf_ifs(c):
    return {n: k for n, k in c.ifs.items() if any(re.match(r"ip router ospf \S+ area", z) for z in k)
            and not n.lower().startswith("loopback")}


def _ospf_active(c, n, k):
    r = next((k2 for p, k2 in c.b if p.startswith("router ospf ")), [])
    return not ("passive-interface default" in r and "no ip ospf passive-interface" not in k) and "ip ospf passive-interface" not in k


@check("CISC-RT-000020", "CISC-RT-000040", fix="key chain OSPF-KEYS\n  key 1\n    key-string <KEY>\n    cryptographic-algorithm hmac-sha-256\n"
                                              "interface <IF>\n  ip ospf authentication key-chain OSPF-KEYS\n"
                                              "router bgp <ASN>\n  neighbor <IP>\n    password <KEY>")
def rt_auth(c, x):
    probs, seen = [], []
    for n, k in _ospf_ifs(c).items():
        seen.append("OSPF")
        if _ospf_active(c, n, k) and not any(z.startswith(("ip ospf authentication", "ip ospf message-digest-key")) for z in k):
            probs.append(f"OSPF on {n} has no authentication")
    for n, k in c.ifs.items():
        if any(z.startswith("ip router eigrp ") for z in k):
            seen.append("EIGRP")
            if not any(z.startswith("ip authentication key-chain eigrp") for z in k):
                probs.append(f"EIGRP on {n} has no authentication")
    b = c.bgp
    if b:
        seen.append("BGP")
        probs += [f"BGP {n} has no password" for n in b["nbrs"] if not any(z.startswith("password ") for z in b["opts"](n))]
    if not seen:
        return na("No dynamic routing protocols configured.")
    return bad("; ".join(probs)) if probs else ok("Neighbors of " + ", ".join(sorted(set(seen))) + " are authenticated")


@check("CISC-RT-000030", fix="key chain <NAME>\n  key 1\n    send-lifetime <START> <START+180d>\n    accept-lifetime <START> <START+180d>")
def rt_key_life(c, x):
    if not c.keychains:
        return na("No key chains.")
    probs = []
    for name, kc in c.keychains.items():
        for i, key in enumerate(kc["keys"], 1):
            for kind in ("send", "accept"):
                d = key.get(kind)
                if d is None or d > 181:
                    probs.append(f"key {i} of {name}: {kind}-lifetime {'missing' if d is None else 'over 180 days'}")
    return bad("; ".join(probs)) if probs else ok("All keys expire within 180 days")


@check("CISC-RT-000050", fix="key chain OSPF-KEYS\n  key 1\n    cryptographic-algorithm hmac-sha-256\n"
                            "interface <IF>\n  ip ospf authentication key-chain OSPF-KEYS")
def rt_fips(c, x):
    probs, seen = [], []
    for n, k in _ospf_ifs(c).items():
        if not _ospf_active(c, n, k):
            continue
        seen.append("OSPF")
        kc = next((z.split()[-1] for z in k if z.startswith("ip ospf authentication key-chain ")), None)
        if not kc:
            probs.append(f"OSPF on {n} does not use a key chain")
            continue
        chain = c.keychains.get(kc)
        if not chain or not chain["keys"] or any(not re.match(FIPS_HMAC, key.get("alg", "")) for key in chain["keys"]):
            probs.append(f"key chain {kc} (OSPF on {n}) does not use a FIPS 198-1 HMAC (HMAC-SHA-1 or SHA-2)")
    if any(any(z.startswith("ip router eigrp ") for z in k) for k in c.ifs.values()):
        seen.append("EIGRP")
        probs.append("NX-OS EIGRP supports only MD5 authentication, which is not FIPS 198-1 (use OSPF or BGP)")
    if not seen:
        return na("No OSPF or EIGRP adjacencies.") if not c.bgp else \
            manual("BGP on NX-OS authenticates with MD5; DISA's NX-OS examples accept it (CISC-RT-000040). Review with your ISSO.")
    return bad("; ".join(probs)) if probs else ok("OSPF authenticated with HMAC-SHA-256 key chains")


@check("CISC-RT-000080", fix="callhome\n  no enable")
def rt_callhome(c, x):
    ch = next((k for p, k in c.b if p == "callhome"), None)
    return bad("Call Home is enabled.") if ch and "enable" in ch else ok("Call Home is not enabled")


@check("CISC-RT-000140", fix="ip access-list EXTERNAL-IN\n  deny icmp any any fragments log")
@_perimeter
def rt_icmp_frag(c, x, ext):
    bad_ = [n for n in ext if not any(re.match(r"deny\s+icmp\s+.*fragments", z) for z in _ext_acl(c, n)[1])]
    return bad("ICMP fragments not dropped on: " + ", ".join(bad_)) if bad_ else ok("Fragmented ICMP dropped inbound")


@check("CISC-RT-000150", fix="interface <EXTERNAL-IF>\n  no ip arp gratuitous request")
@_perimeter
def rt_garp(c, x, ext):
    bad_ = [n for n in ext if "no ip arp gratuitous request" not in c.ifs.get(n, [])]
    return bad("Gratuitous ARP accepted on: " + ", ".join(bad_)) if bad_ else ok("Gratuitous ARP off on external interfaces")


@check("CISC-RT-000170", fix="interface <EXTERNAL-IF>\n  no ip unreachables")
def rt_unreach(c, x):
    ifs, note = _edge_ifs(c, x)  # DISA's NX-OS fix covers interfaces only (no Null0 step as on IOS)
    if not ifs:
        return na("No external interfaces.")
    bad_ = [n for n in ifs if "no ip unreachables" not in c.ifs.get(n, [])]
    return bad("ICMP unreachables still sent from: " + ", ".join(bad_) + note) if bad_ else ok("Unreachables disabled" + note)


@check("CISC-RT-000350", fix="no ip source-route")
def rt_source_route(c, x):
    return ok("no ip source-route") if "no ip source-route" in c.top else bad("IP source routing is not disabled.")


@check("CISC-RT-000360", fix="interface <EXTERNAL-IF>\n  no lldp transmit")
@_perimeter
def rt_lldp(c, x, ext):
    if "feature lldp" not in c.top:
        return ok("LLDP is not enabled")
    bad_ = [n for n in ext if "no lldp transmit" not in c.ifs.get(n, [])]
    return bad("LLDP transmit on: " + ", ".join(bad_)) if bad_ else ok("LLDP off on external interfaces")


@check("CISC-RT-000370", fix="interface <EXTERNAL-IF>\n  no cdp enable")
@_perimeter
def rt_cdp(c, x, ext):
    if "no cdp enable" in c.top:
        return ok("CDP disabled globally")
    bad_ = [n for n in ext if "no cdp enable" not in c.ifs.get(n, [])]
    return bad("CDP on: " + ", ".join(bad_)) if bad_ else ok("CDP off on external interfaces")


@check("CISC-RT-000380", fix="interface <EXTERNAL-IF>\n  no ip proxy-arp")
@_perimeter
def rt_proxy_arp(c, x, ext):
    bad_ = [n for n in ext if "ip proxy-arp" in c.ifs.get(n, [])]  # off by default on NX-OS
    return bad("Proxy ARP on: " + ", ".join(bad_)) if bad_ else ok("Proxy ARP off on external interfaces")


@check("CISC-RT-000470", fix="router bgp <ASN>\n  neighbor <EBGP-PEER>\n    no disable-connected-check")
@_needs_bgp
def rt_connected_check(c, x, b):
    e = _ebgp(b)
    if not e:
        return na("No eBGP neighbors.")
    bad_ = [n for n in e if "disable-connected-check" in b["opts"](n)]
    return bad("Connected check disabled for: " + ", ".join(bad_)) if bad_ else ok("Single-hop eBGP peers must be directly connected")


@check("CISC-RT-000540", fix="router bgp <ASN>\n  enforce-first-as")
@_needs_bgp
def rt_first_as(c, x, b):
    return ok("enforce-first-as") if "enforce-first-as" in b["kids"] else bad("enforce-first-as is not configured.")


@check("CISC-RT-000780")
def rt_qos(c, x):
    return manual("Verify a QoS policy limits the effect of packet floods per the organization's QoS standard.")


_gates = {
    ("590", "600", "610", "620"): (r"^(feature mpls|mpls )", "MPLS is not configured."),
    tuple(str(n) for n in range(630, 780, 10)): (r"^(vrf context (?!management$)|feature mpls)", "Not a PE switch (no customer VRFs or MPLS)."),
    tuple(str(n) for n in range(790, 900, 10)): (r"^(feature pim|ip pim |[ \t]+ip pim )", "Multicast routing (PIM) is not enabled."),
    tuple(str(n) for n in range(900, 960, 10)): (r"^(feature msdp|ip msdp )", "MSDP is not configured."),
}
for _nums, (_pat, _why) in _gates.items():
    for _n in _nums:
        check(f"CISC-RT-000{_n}")(_feature_gate(_pat, _why))


# IOS fix text inherited above, in NX-OS syntax
CHECKS.update({k: (fn, dc_acl_fix(f, "  ")) for k, (fn, f) in CHECKS.items()})
CHECKS["CISC-ND-000160"] = (CHECKS["CISC-ND-000160"][0], "Turn on the DoD banner in OneConfig's Security settings, or configure\n"
                            "banner motd ^<Standard Mandatory DoD Notice and Consent Banner>^")
CHECKS["CISC-RT-000580"] = (CHECKS["CISC-RT-000580"][0], "router bgp <ASN>\n  neighbor <IBGP-PEER>\n    update-source loopback0")
