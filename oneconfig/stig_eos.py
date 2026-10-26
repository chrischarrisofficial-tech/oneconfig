"""DISA STIG checks for Arista EOS (Arista MLS EOS 4.X NDM V2R2, L2S V2R3, Router V2R2).

Rule IDs are Arista's own (ARST-*). Where a rule matches an IOS-XE rule, the IOS check body is reused;
commands come from DISA's Arista fix text."""
import re

from .stig import CHECKS as IOS
from .stig import _ebgp, _ext_acl, dc_acl_fix, ssh_algos, _feature_gate, _needs_bgp, _perimeter, bad, manual, na, ok

CHECKS, MANUAL_WHY = {}, {}


def check(*ids, fix=""):
    def deco(fn):
        for i in ids:
            CHECKS[i] = (fn, fix)
        return fn
    return deco


def reuse(ios_id, *ids, fix=None):
    fn, ios_fix = IOS[ios_id]
    for i in ids:
        CHECKS[i] = (fn, fix or dc_acl_fix(ios_fix, "   "))


def _mgmt(c, name):
    return next((k for p, k in c.b if p == f"management {name}"), None)


# ---------------------------------------------------------------- NDM
@check("ARST-ND-000010", fix="management ssh\n   connection limit 5")
def nd_sessions(c, x):
    m = next((z for z in _mgmt(c, "ssh") or [] if z.startswith("connection limit ")), None)
    return ok(m) if m else bad("SSH sessions are not limited (management ssh / connection limit).")


@check("ARST-ND-000110", fix="ip access-list MGMT-ACCESS\n   10 permit ip <MGMT-NET>/<LEN> any\n   20 deny ip any any log\n"
                            "management ssh\n   ip access-group MGMT-ACCESS in")
def nd_mgmt_acl(c, x):
    a = next((z.split()[2] for z in _mgmt(c, "ssh") or [] if re.match(r"ip access-group \S+ in$", z)), None)
    if not a:
        return bad("SSH access is not limited by an ACL (management ssh / ip access-group).")
    e = c.acls.get(a)
    if not e:
        return bad(f"ip access-group {a} refers to an ACL that is not defined.")
    return ok(f"ip access-group {a} in") if re.match(r"deny\s+ip\s+any\s+any", e[-1]) else bad(f"{a} does not end with deny ip any any.")


@check("ARST-ND-000120", fix="aaa authentication policy lockout failure 3 duration 900")
def nd_lockout(c, x):
    m = re.search(r"^aaa authentication policy lockout failure (\d+)(?:.*?duration (\d+))?", c.text, re.M)
    if not m:
        return bad("No account lockout policy.")
    return ok(m.group(0)) if int(m.group(1)) <= 3 and int(m.group(2) or 0) >= 900 else bad("Needs lockout after 3 failures for 900 seconds: " + m.group(0))


reuse("CISC-ND-000160", "ARST-ND-000130", fix="Turn on the DoD banner in OneConfig's Security settings, or configure\n"
      "banner login\n<Standard Mandatory DoD Notice and Consent Banner>\nEOF")


@check("ARST-ND-000150", fix="aaa authentication policy on-success log\naaa authentication policy on-failure log\n"
                            "aaa accounting commands all default start-stop logging group TACACS-SERVERS")
def nd_audit(c, x):
    miss = [p for p in ("aaa authentication policy on-success log", "aaa authentication policy on-failure log") if p not in c.top]
    if not c.has(r"^aaa accounting commands all default start-stop"):
        miss.append("aaa accounting commands all default start-stop …")
    return bad("Missing: " + "; ".join(miss)) if miss else ok("Logins and all commands are logged")


@check("ARST-ND-000340", fix="management telnet\n   shutdown\nmanagement api http-commands\n   shutdown")
def nd_services(c, x):
    on = [n for n in ("telnet", "api http-commands") if (k := _mgmt(c, n)) is not None and "no shutdown" in k]
    return bad("Enabled: management " + ", management ".join(on)) if on else ok("Telnet and the HTTP API are off")


@check("ARST-ND-000350", fix="username <ADMIN-USER> privilege 15 role network-admin secret <SECRET>\nno username admin")
def nd_last_resort(c, x):
    users = [p.split()[1] for p in c.top if p.startswith("username ")]
    return ok(f"One local account: {users[0]}") if len(users) == 1 else \
        bad(f"{len(users)} local accounts ({', '.join(users) or 'none'}); keep exactly one account of last resort.")


@check("ARST-ND-000380", fix="management security\n   password minimum length 15")
def nd_pw_len(c, x):
    m = next((z for z in _mgmt(c, "security") or [] if z.startswith("password minimum length ")), None)
    return ok(m) if m and int(m.split()[-1]) >= 15 else bad("Minimum password length is not 15.")


@check("ARST-ND-000470", fix="management ssh\n   fips restrictions")
def nd_fips(c, x):
    return ok("fips restrictions") if "fips restrictions" in (_mgmt(c, "ssh") or []) else bad("SSH is not restricted to FIPS algorithms.")


@check("ARST-ND-000490", fix="management console\n   idle-timeout 5\nmanagement ssh\n   idle-timeout 5")
def nd_idle(c, x):
    probs = []
    for n in ("console", "ssh"):
        m = next((z for z in _mgmt(c, n) or [] if z.startswith("idle-timeout ")), None)
        if not m or int(m.split()[1]) == 0 or int(m.split()[1]) > 10:
            probs.append(f"management {n} idle-timeout is {m.split()[1] if m else 'not set'}")
    return bad("; ".join(probs)) if probs else ok("Console and SSH sessions time out")


@check("ARST-ND-000550")
def nd_rbac(c, x):
    return manual("Verify roles on the device and the AAA server enforce the organization's role-based access policy.")


@check("ARST-ND-000600", fix="ntp authentication-key 1 sha1 <KEY>\nntp trusted-key 1\nntp authenticate servers\n"
                            "ntp server <NTP-1> key 1\nntp server <NTP-2> key 1")
def nd_ntp(c, x):
    servers = [p for p in c.top if p.startswith("ntp server ")]
    if len(servers) < 2:
        return bad(f"{len(servers)} NTP server(s); two are required.")
    if not c.has(r"^ntp authenticate") or not c.has(r"^ntp trusted-key "):
        return bad("NTP authentication is not enabled.")
    nokey = [p.split()[2] for p in servers if " key " not in p]
    return bad("NTP servers without a key: " + ", ".join(nokey)) if nokey else ok("Two authenticated NTP servers")


@check("ARST-ND-000660", fix="snmp-server user <USER> <GROUP> v3 auth sha256 <AUTH> priv aes256 <PRIV>")
def nd_snmp(c, x):
    if c.has(r"^snmp-server community "):
        return bad("SNMP community strings are configured.")
    users = [p for p in c.top if p.startswith("snmp-server user ")]
    weak = [p.split()[2] for p in users if not re.search(r"\bauth sha", p) or not re.search(r"\bpriv aes", p)]
    if weak:
        return bad("SNMP users without SHA authentication and AES privacy: " + ", ".join(weak))
    return ok("SNMPv3 with SHA and AES") if users else na("SNMP is not configured.")


@check("ARST-ND-000690", fix="management ssh\n   mac hmac-sha2-512 hmac-sha2-256")
def nd_ssh_mac(c, x):
    m = next((z for z in _mgmt(c, "ssh") or [] if z.startswith("mac ")), None)
    return ssh_algos("mac", m, m and m.split()[1:])


@check("ARST-ND-000700", fix="management ssh\n   cipher aes256-ctr aes192-ctr aes128-ctr")
def nd_ssh_enc(c, x):
    m = next((z for z in _mgmt(c, "ssh") or [] if z.startswith("cipher ")), None)
    return ssh_algos("cipher", m, m and m.split()[1:])


@check("ARST-ND-000790", fix="logging buffered informational\nlogging trap informational")
def nd_log_level(c, x):
    return ok("Logging at informational") if c.has(r"^logging trap (informational|debugging)") else bad("Syslog is not sent at informational level.")


@check("ARST-ND-000810", fix="aaa authentication login default group TACACS-SERVERS local")
def nd_auth_server(c, x):
    m = re.search(r"^aaa authentication login default group \S+", c.text, re.M)
    return ok(m.group(0)) if m else bad("Logins are not authenticated by a server.")


@check("ARST-ND-000820", fix="event-handler CFG_BACKUP\n   trigger on-startup-config\n   action bash <copy the startup-config>")
def nd_backup(c, x):
    for p, k in c.b:
        if p.startswith("event-handler ") and "trigger on-startup-config" in k and any(z.startswith("action ") for z in k):
            return ok(p)
    return bad("No event-handler backs up the configuration when it is saved.")


@check("ARST-ND-000840")
def nd_pki(c, x):
    return manual("Verify certificates come from a DoD-approved certificate authority.")


@check("ARST-ND-000850", fix="logging host <SYSLOG>")
def nd_syslog(c, x):
    m = next((p for p in c.top if p.startswith("logging host ")), None)
    return ok(m) if m else bad("No remote syslog server.")


@check("ARST-ND-000860")
def nd_release(c, x):
    return manual("Verify the EOS release is still supported by Arista (and check its CVEs in OneConfig).")


# ---------------------------------------------------------------- L2S
def _ports(c, test, what):
    if not c.access:
        return na("No active access ports.")
    miss = [n for n, k in c.access.items() if not test(k)]
    return bad(f"Access ports without {what}: " + ", ".join(miss[:8])) if miss else ok(f"{what} on all {len(c.access)} access ports")


@check("ARST-L2-000020", fix="aaa authentication dot1x default group RADIUS-SERVERS\ndot1x system-auth-control\n"
                            "interface <ACCESS-PORT>\n   dot1x pae authenticator\n   dot1x port-control auto")
def l2_dot1x(c, x):
    if c.access and "dot1x system-auth-control" not in c.top:
        return bad("802.1X is not enabled (dot1x system-auth-control).")
    return _ports(c, lambda k: "dot1x port-control auto" in k, "802.1X")


@check("ARST-L2-000030", fix="interface <ACCESS-PORT>\n   storm-control broadcast level pps 5000")
def l2_storm(c, x):
    return _ports(c, lambda k: any(z.startswith("storm-control broadcast") for z in k), "storm control")


reuse("CISC-L2-000090", "ARST-L2-000050")


@check("ARST-L2-000060", fix="interface <ACCESS-PORT>\n   spanning-tree bpduguard enable")
def l2_bpdu(c, x):
    if "spanning-tree edge-port bpduguard default" in c.top:
        return ok("BPDU Guard on all edge ports by default")
    return _ports(c, lambda k: "spanning-tree bpduguard enable" in k, "BPDU Guard")


@check("ARST-L2-000070", fix="spanning-tree guard loop default")
def l2_loop(c, x):
    return ok() if "spanning-tree guard loop default" in c.top else bad("STP Loop Guard is not enabled globally.")


reuse("CISC-L2-000130", "ARST-L2-000090")
reuse("CISC-L2-000140", "ARST-L2-000100")
reuse("CISC-L2-000150", "ARST-L2-000110")
reuse("CISC-L2-000170", "ARST-L2-000130")


@check("ARST-L2-000140", fix="spanning-tree mode rapid-pvst")
def l2_rstp(c, x):
    m = re.search(r"^spanning-tree mode (\S+)", c.text, re.M)
    mode = m.group(1) if m else "mstp"  # EOS default
    return ok(f"spanning-tree mode {mode}") if mode in ("mstp", "rapid-pvst") else bad(f"spanning-tree mode {mode} is not a rapid STP.")


@check("ARST-L2-000160")
def l2_static_trunks(c, x):
    return ok("EOS does not negotiate trunking (no DTP); trunks are static")


reuse("CISC-L2-000210", "ARST-L2-000170")
reuse("CISC-L2-000220", "ARST-L2-000180")
reuse("CISC-L2-000230", "ARST-L2-000190")
reuse("CISC-L2-000240", "ARST-L2-000200")
reuse("CISC-L2-000250", "ARST-L2-000210")
reuse("CISC-L2-000260", "ARST-L2-000220")
reuse("CISC-L2-000270", "ARST-L2-000230")


# ---------------------------------------------------------------- Router
reuse("CISC-RT-000490", "ARST-RT-000020")
reuse("CISC-RT-000500", "ARST-RT-000030")
reuse("CISC-RT-000520", "ARST-RT-000050", "ARST-RT-000390")
reuse("CISC-RT-000060", "ARST-RT-000150")
reuse("CISC-RT-000200", "ARST-RT-000230")
reuse("CISC-RT-000240", "ARST-RT-000330")
reuse("CISC-RT-000330", "ARST-RT-000370")
reuse("CISC-RT-000310", "ARST-RT-000450")
reuse("CISC-RT-000480", "ARST-RT-000470")
reuse("CISC-RT-000160", "ARST-RT-000520")
reuse("CISC-RT-000570", "ARST-RT-000570")
reuse("CISC-RT-000270", "ARST-RT-000620")
reuse("CISC-RT-000390", "ARST-RT-000650")
reuse("CISC-RT-000580", "ARST-RT-000690")
reuse("CISC-RT-000237", "ARST-RT-000790")

for _id, _why in {
    "ARST-RT-000010": "Verify ACLs and routing policy match the organization's information flow control policy.",
    "ARST-RT-000040": "Applies to provider routers peering with customer edge (CE) routers.",
    "ARST-RT-000100": "Applies to provider routers peering with customer edge (CE) routers.",
    "ARST-RT-000110": "Verify the perimeter ACLs match the approved interconnection policy.",
    "ARST-RT-000160": "Applies only to an enclave connected to an alternate gateway.",
    "ARST-RT-000170": "Applies only to an enclave connected to an alternate gateway.",
    "ARST-RT-000180": "Applies only to an enclave connected to an alternate gateway.",
    "ARST-RT-000260": "Verify unneeded services and capabilities are disabled (see DISA's list in this rule).",
    "ARST-RT-000490": "Verify with show zerotouch that Zero Touch Provisioning is disabled (OneConfig doesn't push it: it can reload the switch).",
    "ARST-RT-000610": "Verify inbound perimeter rules permit only authorized sources to authorized destinations.",
    "ARST-RT-000830": "Verify the perimeter drops packets with IP options (inbound ACL or platform setting).",
    **{f"ARST-RT-000{n}": "Applies only to an out-of-band management (OOBM) gateway router." for n in (190, 200, 420, 430, 440)},
}.items():
    MANUAL_WHY[_id] = _why


@check("ARST-RT-000060", fix="router bgp <ASN>\n   bgp enforce-first-as")
@_needs_bgp
def rt_first_as(c, x, b):
    return ok("bgp enforce-first-as") if "bgp enforce-first-as" in b["kids"] else bad("bgp enforce-first-as is not configured.")


@check("ARST-RT-000280", fix="interface <IF>\n   ip ospf authentication message-digest\n   ip ospf message-digest-key 1 sha256 <KEY>\n"
                            "management security\n   session shared-secret profile <PROFILE>\n      secret <N> <KEY> <LIFETIME>\n"
                            "router bgp <ASN>\n   neighbor <IP> password shared-secret profile <PROFILE> algorithm aes-128-cmac-96")
def rt_routing_auth(c, x):
    probs, seen = [], []
    for n, k in c.ifs.items():
        if any(z.startswith("ip ospf area ") for z in k) and not n.lower().startswith("loopback"):
            seen.append("OSPF")
            r = next((k2 for p, k2 in c.b if p.startswith("router ospf ")), [])
            if "passive-interface default" in r and f"no passive-interface {n}" not in r:
                continue
            if not any(re.match(r"ip ospf message-digest-key \d+ sha(1|256|384|512)\b", z) for z in k):
                probs.append(f"OSPF on {n} is not authenticated with a FIPS 198-1 HMAC (SHA-1 or SHA-2)")
    b = c.bgp
    if b:
        seen.append("BGP")
        for n in b["nbrs"]:
            o = b["opts"](n)
            if any(z.startswith("password shared-secret") for z in o):
                continue
            probs.append(f"BGP {n} uses an MD5 password; DISA wants a shared-secret profile" if any(z.startswith("password ") for z in o)
                         else f"BGP {n} has no authentication")
    if not seen:
        return na("No OSPF or BGP configured.")
    return bad("; ".join(probs)) if probs else ok(" and ".join(sorted(set(seen))) + " authenticated with SHA-2")


@check("ARST-RT-000340")
def rt_copp(c, x):
    return ok("EOS applies the system control-plane policy (copp-system-policy) by default. Verify its rates.")


@check("ARST-RT-000350", fix="ip access-list EXTERNAL-IN\n   deny icmp any any fragments log")
@_perimeter
def rt_frag(c, x, ext):
    bad_ = [n for n in ext if not any(re.match(r"deny\s+(icmp|ip)\s+.*fragments", z) for z in _ext_acl(c, n)[1])]
    return bad("Fragments not dropped on: " + ", ".join(bad_)) if bad_ else ok("Fragmented ICMP dropped inbound")


@check("ARST-RT-000380", fix="interface <EXTERNAL-IF>\n   ip access-group EXTERNAL-OUT out")
@_perimeter
def rt_egress_out(c, x, ext):
    bad_ = [n for n in ext if not _ext_acl(c, n, "out")[0]]
    return bad("No outbound filter on: " + ", ".join(bad_)) if bad_ else ok("Outbound filter on every external interface")


@check("ARST-RT-000510", fix="interface <EXTERNAL-IF>\n   no arp gratuitous accept")
@_perimeter
def rt_garp(c, x, ext):
    bad_ = [n for n in ext if "no arp gratuitous accept" not in c.ifs.get(n, [])]
    return bad("Gratuitous ARP accepted on: " + ", ".join(bad_)) if bad_ else ok("Gratuitous ARP off on external interfaces")


@check("ARST-RT-000530", fix="ip icmp rate-limit-unreachable 0")
def rt_unreach(c, x):
    return ok("ip icmp rate-limit-unreachable 0") if "ip icmp rate-limit-unreachable 0" in c.top else bad("ICMP unreachables are still sent.")


def _out_denies(icmp_type):
    @_perimeter
    def fn(c, x, ext):
        bad_ = [n for n in ext if not any(re.match(rf"deny\s+icmp\s+any\s+any\s+{icmp_type}", z) for z in _ext_acl(c, n, "out")[1])]
        return bad(f"ICMP {icmp_type} not blocked outbound on: " + ", ".join(bad_)) if bad_ else ok(f"ICMP {icmp_type} blocked outbound")
    return fn


CHECKS["ARST-RT-000540"] = (_out_denies("mask-reply"), "ip access-list EXTERNAL-OUT\n   deny icmp any any mask-reply log")
CHECKS["ARST-RT-000550"] = (_out_denies("redirect"), "ip access-list EXTERNAL-OUT\n   deny icmp any any redirect log")


@check("ARST-RT-000560", fix="router bgp <ASN>\n   neighbor <EBGP-PEER> maximum-routes <N>")
@_needs_bgp
def rt_max_routes(c, x, b):
    e = _ebgp(b)
    if not e:
        return na("No eBGP neighbors.")
    bad_ = [n for n in e if not any(z.startswith(("maximum-routes", "maximum-accepted-routes")) for z in b["opts"](n))]
    return bad("No maximum-routes on: " + ", ".join(bad_)) if bad_ else ok("maximum-routes on all eBGP neighbors")


@check("ARST-RT-000600", fix="router bgp <ASN>\n   neighbor <EBGP-PEER> ttl maximum-hops 1")
@_needs_bgp
def rt_gtsm(c, x, b):
    e = _ebgp(b)
    if not e:
        return na("No eBGP neighbors.")
    bad_ = [n for n in e if not any(z.startswith("ttl maximum-hops") for z in b["opts"](n))]
    return bad("No GTSM on: " + ", ".join(bad_)) if bad_ else ok("GTSM on all eBGP neighbors")


@check("ARST-RT-000630", fix="interface <EXTERNAL-IF>\n   no lldp transmit\n   no lldp receive")
@_perimeter
def rt_lldp(c, x, ext):
    if "no lldp run" in c.top:
        return ok("LLDP disabled globally")
    bad_ = [n for n in ext if "no lldp transmit" not in c.ifs.get(n, [])]
    return bad("LLDP transmit on: " + ", ".join(bad_)) if bad_ else ok("LLDP off on external interfaces")


@check("ARST-RT-000640", fix="interface <EXTERNAL-IF>\n   no ip proxy-arp")
@_perimeter
def rt_proxy_arp(c, x, ext):
    bad_ = [n for n in ext if "ip proxy-arp" in c.ifs.get(n, [])]  # off by default on EOS
    return bad("Proxy ARP on: " + ", ".join(bad_)) if bad_ else ok("Proxy ARP off on external interfaces")


def _v6(c, x):
    return manual("IPv6 is configured; review this IPv6 rule.") if re.search(r"^[ \t]+ipv6 address ", c.text, re.M) else na("IPv6 is not configured.")


for _id in ("ARST-RT-000780", "ARST-RT-000800"):
    check(_id)(_v6)

_gates = {
    ("070", "080", "090", "680", "770"): (r"^router msdp", "MSDP is not configured."),
    ("120", "130", "140", "210", "580", "590", "660", "670"): (r"^(router (multicast|pim)|[ \t]+pim ipv4)", "Multicast routing (PIM) is not enabled."),
    ("290", "480", "700", "710", "720"): (r"^mpls ", "MPLS is not configured."),
    ("300", "310", "320", "400", "410", "730", "740", "750", "760", "840"): (r"^(vrf instance |mpls )", "Not a PE router (no customer VRFs or MPLS)."),
}
for _nums, (_pat, _why) in _gates.items():
    for _n in _nums:
        check(f"ARST-RT-000{_n}")(_feature_gate(_pat, _why))
