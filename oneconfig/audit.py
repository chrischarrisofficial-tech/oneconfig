"""Audit any Cisco IOS / IOS-XE, NX-OS, Cisco ASA, Palo Alto PAN-OS, Arista EOS or Juniper Junos config text (generated or pasted from a live device).
Each rule returns findings with severity, why it matters, and the commands that fix it."""
import re

WEIGHT = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}


def blocks(cfg: str) -> list[tuple[str, list[str]]]:
    """Split config into (parent line, [child lines])."""
    out = []
    for line in cfg.splitlines():
        if not line.strip() or line.startswith("!"):
            continue
        if line[0] == " " and out:
            out[-1][1].append(line.strip())
        else:
            out.append((line.strip(), []))
    return out


def _f(sev, cat, title, why, fix, where=""):
    return {"severity": sev, "category": cat, "title": title, "why": why, "fix": fix, "where": where}


def _score(found):
    order = list(WEIGHT)
    found.sort(key=lambda f: order.index(f["severity"]))
    return {"score": max(0, 100 - sum(WEIGHT[f["severity"]] for f in found)), "findings": found}


def _audit_dc(cfg: str, nos: str) -> dict:
    """NX-OS and EOS: the same risks as the IOS rules, in each OS's own syntax."""
    b = blocks(cfg)
    top = [p for p, _ in b]
    kids = lambda parent: next((k for p, k in b if p == parent), None)  # noqa: E731
    found = []
    add = lambda *a: found.append(_f(*a))  # noqa: E731
    nx, ind = nos == "nx-os", "  " if nos == "nx-os" else "   "
    for p in top:
        m = re.match(r"^snmp-server community (\S+)(.*)", p)
        if m:
            rw = " rw" in m.group(2).lower()
            add("critical" if rw else "high", "security", f"SNMP community string{' with write access' if rw else ''}",
                "SNMPv1/v2c sends the community in cleartext.", f"no {p}", p)
    telnet = "feature telnet" in top if nx else "no shutdown" in (kids("management telnet") or [])
    if telnet:
        add("high", "security", "Telnet enabled", "Telnet sends credentials in cleartext.",
            "no feature telnet" if nx else "management telnet\n   shutdown")
    vty = kids("line vty") or [] if nx else kids("management ssh") or []
    if not any(re.match(r"(access-class|ip access-group) \S+ in", k) for k in vty):
        add("medium", "security", "Management access not limited to a management subnet",
            "Anyone who can reach the device can attempt to log in.",
            "ip access-list MGMT-ACCESS\n  10 permit ip <MGMT-NET> any\n  20 deny ip any any log\n" +
            ("line vty\n  access-class MGMT-ACCESS in" if nx else "management ssh\n   ip access-group MGMT-ACCESS in"))
    t = next((k.split()[1] for k in vty if k.startswith(("exec-timeout ", "idle-timeout "))), None)
    if t in (None, "0"):
        add("medium", "security", "Sessions don't time out", "Idle sessions stay open for anyone at the terminal.",
            "line vty\n  exec-timeout 5" if nx else "management ssh\n   idle-timeout 5")
    if not any(p.startswith(("logging server", "logging host")) for p in top):
        add("low", "security", "No remote syslog", "Logs are lost on reboot and can be wiped by an attacker.",
            "logging server <SYSLOG-IP> 6" if nx else "logging host <SYSLOG-IP>")
    if not any(p.startswith("ntp server") for p in top):
        add("low", "security", "No NTP server", "Log timestamps cannot be correlated across devices.", "ntp server <NTP-IP>")
    if not any(p.startswith("banner ") for p in top):
        add("low", "security", "No login banner", "Legal warning banners support prosecution of unauthorized access.",
            "banner motd ^Authorized access only.^" if nx else "banner login\nAuthorized access only.\nEOF")
    bpdu_default = any(p.startswith(("spanning-tree port type edge bpduguard default", "spanning-tree edge-port bpduguard default")) for p in top)
    for p, k in b:
        if not p.startswith("interface") or "shutdown" in k:
            continue
        if "switchport mode access" in k:
            if not bpdu_default and "spanning-tree bpduguard enable" not in k:
                add("medium", "security", "Access port without BPDU Guard",
                    "A rogue switch on this port could take over spanning tree.", f"{p}\n{ind}spanning-tree bpduguard enable", p)
            if not any(z.startswith(("switchport port-security", "dot1x port-control")) for z in k):
                add("low", "security", "Access port without port security or 802.1X", "Unlimited MACs can attach (MAC flooding).",
                    f"{p}\n{ind}switchport port-security", p)
        if "switchport mode trunk" in k:
            if not any(z.startswith("switchport trunk native vlan") for z in k):
                add("medium", "security", "Trunk uses native VLAN 1", "Enables double-tagging VLAN hopping attacks.",
                    f"{p}\n{ind}switchport trunk native vlan 999", p)
            if not any(z.startswith("switchport trunk allowed vlan") for z in k):
                add("low", "design", "Trunk allows all VLANs", "Prune to the VLANs actually needed.",
                    f"{p}\n{ind}switchport trunk allowed vlan <LIST>", p)
    router = next((k for p, k in b if p.startswith("router ospf ")), [])
    pdefault = "passive-interface default" in router

    def active(p, k):  # passive interfaces form no adjacencies, so they need no authentication
        if nx:
            return "ip ospf passive-interface" not in k and (not pdefault or "no ip ospf passive-interface" in k)
        return not pdefault or f"no passive-interface {p.split(None, 1)[1]}" in router
    ospf_ifs = [p for p, k in b if p.startswith("interface") and any(re.match(r"ip (router ospf \S+|ospf) area", z) for z in k)
                and not any(z.startswith(("ip ospf authentication", "ip ospf message-digest-key")) for z in k)
                and not p.lower().startswith("interface loopback") and active(p, k)]
    for p in ospf_ifs:
        add("medium", "security", "OSPF without authentication", "Anyone on the segment can inject routes.",
            f"{p}\n{ind}ip ospf authentication key-chain OSPF-KEYS" if nx else f"{p}\n{ind}ip ospf authentication message-digest\n"
            f"{ind}ip ospf message-digest-key 1 sha256 <KEY>", p)
    from .stig import Cfg  # one BGP parser for both OSes
    bgp = Cfg(cfg).bgp
    if bgp:
        for n in sorted(bgp["nbrs"]):
            if not any(z.startswith("password ") for z in bgp["opts"](n)):
                add("medium", "security", f"BGP neighbor {n} without authentication", "Session can be reset or hijacked.",
                    f"router bgp {bgp['asn']}\n  neighbor {n}\n    password <KEY>" if nx else f"router bgp {bgp['asn']}\n   neighbor {n} password <KEY>")
    if re.search(r"<[A-Z0-9][A-Z0-9.-]*>", cfg):
        add("info", "deploy", "Placeholders still present", "Replace every <ANGLE-BRACKET> value before deploying.", "")
    return _score(found)


def _audit_junos(cfg: str) -> dict:
    """Junos (display set or braces): the same risks as the other OSes, in Junos terms."""
    from .stig_junos import J, _access, _members, _ospf_active, _ospf_auth, _re_filter_restricts, _trunks
    c, found = J(cfg), []
    add = lambda *a: found.append(_f(*a))  # noqa: E731
    for m in c.find(r"snmp community (\S+)(.*)$"):
        rw = "read-write" in m.group(2)
        add("critical" if rw else "high", "security", f"SNMP community string{' with write access' if rw else ''}",
            "SNMPv1/v2c sends the community in cleartext.", f"delete snmp community {m.group(1)}", "set snmp community " + m.group(1))
    if c.has(r"system services telnet"):
        add("high", "security", "Telnet enabled", "Telnet sends credentials in cleartext.", "delete system services telnet")
    if not c.has(r"system services ssh root-login deny"):
        add("high", "security", "root can log in over SSH", "The root account is the first one attackers try.",
            "set system services ssh root-login deny")
    if not _re_filter_restricts(c, "ssh"):
        add("medium", "security", "Management access not limited to a management subnet",
            "Anyone who can reach the device can attempt to log in.",
            "set policy-options prefix-list MGMT-NET <MGMT-NET>\nset firewall family inet filter PROTECT-RE term SSH from source-prefix-list MGMT-NET\n"
            "set firewall family inet filter PROTECT-RE term SSH from destination-port ssh\nset firewall family inet filter PROTECT-RE term SSH then accept\n"
            "set firewall family inet filter PROTECT-RE term DENY-ALL then discard\nset interfaces lo0 unit 0 family inet filter input PROTECT-RE")
    if not c.classes or any(not any(z.startswith("idle-timeout ") for z in k) for k in c.classes.values()):
        add("medium", "security", "Sessions don't time out", "Idle sessions stay open for anyone at the terminal.",
            "set system login class <CLASS> idle-timeout 5")
    if not c.syslog("host"):
        add("low", "security", "No remote syslog", "Logs are lost on reboot and can be wiped by an attacker.", "set system syslog host <SYSLOG-IP> any info")
    if not c.has(r"system ntp server "):
        add("low", "security", "No NTP server", "Log timestamps cannot be correlated across devices.", "set system ntp server <NTP-IP>")
    if not c.has(r"system login message "):
        add("low", "security", "No login banner", "Legal warning banners support prosecution of unauthorized access.",
            'set system login message "Authorized access only."')
    edge = {m.group(1) for m in c.find(r"protocols (?:rstp|mstp|vstp) interface (\S+) edge")}
    bpdu = c.has(r"protocols (rstp|mstp|vstp) bpdu-block-on-edge")
    secured = {m.group(1).split(".")[0] for m in c.find(r"(?:switch-options interface|protocols dot1x authenticator interface) (\S+)")}
    for n in _access(c):
        if not (bpdu and n in edge):
            add("medium", "security", "Access port without BPDU protection", "A rogue switch on this port could take over spanning tree.",
                f"set protocols rstp bpdu-block-on-edge\nset protocols rstp interface {n} edge", f"interfaces {n}")
        if n not in secured:
            add("low", "security", "Access port without MAC limit or 802.1X", "Unlimited MACs can attach (MAC flooding).",
                f"set switch-options interface {n}.0 interface-mac-limit 1", f"interfaces {n}")
    for n, e in _trunks(c).items():
        if "all" in _members(e):
            add("low", "design", "Trunk allows all VLANs", "Prune to the VLANs actually needed.",
                f"delete interfaces {n} unit 0 family ethernet-switching vlan members all", f"interfaces {n}")
    for n, o in _ospf_active(c).items():
        if not _ospf_auth(o)[0]:
            add("medium", "security", "OSPF without authentication", "Anyone on the segment can inject routes.",
                f"set protocols ospf area <AREA> interface {n} authentication keychain OSPF-KEYS", f"protocols ospf interface {n}")
    for g, ip, o in c.bgp_peers():
        if not any(z.startswith(("authentication-key", "authentication-key-chain")) for z in o):
            add("medium", "security", f"BGP neighbor {ip} without authentication", "Session can be reset or hijacked.",
                f"set protocols bgp group {g} neighbor {ip} authentication-key-chain BGP-AS<N>")
    if re.search(r"<[A-Z0-9][A-Z0-9.-]*>", cfg):
        add("info", "deploy", "Placeholders still present", "Replace every <ANGLE-BRACKET> value before deploying.", "")
    return _score(found)


def _audit_asa(cfg: str) -> dict:
    """Cisco ASA (and FTD's ASA-style config): the same management risks, plus the firewall's own rules."""
    from .stig_asa import Asa
    c, found = Asa(cfg), []
    add = lambda *a: found.append(_f(*a))  # noqa: E731
    for p in c.top:
        if p.startswith("snmp-server community") or re.match(r"snmp-server host .* community ", p):
            add("high", "security", "SNMP community string", "SNMPv1/v2c sends the community in cleartext.", f"no {p}", p)
        if re.match(r"telnet \d", p):
            add("high", "security", "Telnet enabled", "Telnet sends credentials in cleartext.", f"no {p}", p)
        if re.match(r"(ssh|http) 0\.0\.0\.0 0\.0\.0\.0 ", p):
            add("medium", "security", "Management open to any address", "Anyone who can reach the interface can attempt to log in.",
                f"no {p}\n{p.split()[0]} <MGMT-NET> <MASK> {p.split()[-1]}", p)
    if "http server enable" in c.top:
        add("low", "security", "ASDM (HTTPS) management enabled", "Another management service to patch and protect; disable it if ASDM isn't used.",
            "no http server enable")
    if not c.has(r"^ssh \d"):
        add("medium", "security", "SSH not limited to a management subnet", "Without ssh lines nobody can manage the firewall remotely; with 0.0.0.0 everyone can try.",
            "ssh <MGMT-NET> <MASK> <NAMEIF>")
    if int(c.value(r"^console timeout (\d+)$", 0)) == 0 or int(c.value(r"^ssh timeout (\d+)$", 5)) > 5:
        add("medium", "security", "Sessions don't time out quickly", "Idle sessions stay open for anyone at the terminal.", "ssh timeout 5\nconsole timeout 5")
    if not c.has(r"^logging host "):
        add("low", "security", "No remote syslog", "Logs are lost on reboot and can be wiped by an attacker.", "logging host <NAMEIF> <SYSLOG-IP> 6/1514\nlogging permit-hostdown")
    elif c.has(r"^logging host .* (6|tcp)/") and "logging permit-hostdown" not in c.top:
        add("high", "availability", "TCP syslog without permit-hostdown", "If every log server is down, the ASA stops passing new connections.",
            "logging permit-hostdown")
    if not c.has(r"^ntp server "):
        add("low", "security", "No NTP server", "Log timestamps cannot be correlated across devices.", "ntp server <NTP-IP> key 1")
    if not c.has(r"^banner (login|motd) "):
        add("low", "security", "No login banner", "Legal warning banners support prosecution of unauthorized access.", "banner login Authorized access only.")
    for n, (ifname, lvl, mgmt) in c.nameifs.items():
        if not mgmt and n not in c.groups:
            add("medium", "security", f"Interface {n} has no access list", "Traffic from it is allowed to every lower security level by default.",
                f"access-list {n.upper()}_IN extended deny ip any any log\naccess-group {n.upper()}_IN in interface {n}", f"interface {ifname}")
    for a, es in c.acls.items():
        for e in es:
            if re.match(r"permit ip any4? any4?( log)?$", e):
                add("high", "security", f"{a} permits all traffic", "A permit ip any any turns the firewall into a router.", f"no access-list {a} extended {e}", a)
    if c.has(r"^router ospf ") and not re.search(r"^[ \t]+ospf (message-digest-key|authentication)", cfg, re.M):
        add("medium", "security", "OSPF without authentication", "Anyone on the segment can inject routes.",
            "interface <IF>\n ospf message-digest-key 1 md5 <KEY>\n ospf authentication message-digest")
    for m in re.finditer(r"^[ \t]+neighbor (\S+) remote-as ", cfg, re.M):
        if not re.search(rf"^[ \t]+neighbor {re.escape(m[1])} password ", cfg, re.M):
            add("medium", "security", f"BGP neighbor {m[1]} without authentication", "Session can be reset or hijacked.",
                f"router bgp <ASN>\n address-family ipv4 unicast\n  neighbor {m[1]} password <KEY>")
    if c.has(r"^failover lan unit ") and not c.has(r"^failover (key|ipsec pre-shared-key) "):
        add("medium", "security", "Failover link not protected", "Failover messages, including the config sync, cross the link in cleartext.",
            "failover key <FAILOVER-KEY>")
    if re.search(r"<[A-Z0-9][A-Z0-9.-]*>", cfg):
        add("info", "deploy", "Placeholders still present", "Replace every <ANGLE-BRACKET> value before deploying.", "")
    return _score(found)


def _audit_panos(cfg: str) -> dict:
    """PAN-OS (set or brace form): management risks plus the policy problems a firewall review looks for first."""
    from .stig_panos import Pan, _allow, _rule_profiles
    c, found = Pan(cfg), []
    add = lambda *a: found.append(_f(*a))  # noqa: E731
    for l in c.lines:
        if re.match(r"deviceconfig system service disable-(telnet|http) no$", l) or re.match(r"network profiles interface-management-profile \S+ (telnet|http) yes$", l):
            add("high", "security", "Cleartext management enabled", "Telnet and HTTP send credentials in cleartext.",
                "set deviceconfig system service disable-telnet yes\nset deviceconfig system service disable-http yes", l)
    if c.has(r"deviceconfig system snmp-setting access-setting version v2c"):
        add("high", "security", "SNMP v2c", "SNMPv1/v2c sends the community in cleartext.", "set deviceconfig system snmp-setting access-setting version v3")
    if not c.has(r"deviceconfig system permitted-ip "):
        add("medium", "security", "Management not limited to a management subnet", "Anyone who can reach the management port can attempt to log in.",
            "Device > Setup > Interfaces > Management > Permitted IP Addresses: <MGMT-NET>")
    if not c.has(r"deviceconfig setting management idle-timeout ([1-9]|10)$"):
        add("medium", "security", "Sessions don't time out quickly", "Idle sessions stay open for anyone at the terminal.",
            "set deviceconfig setting management idle-timeout 10")
    if not c.has(r"(?:shared )?log-settings syslog \S+ server \S+ server "):
        add("low", "security", "No remote syslog", "Logs are lost on reboot and can be wiped by an attacker.",
            "set shared log-settings syslog SYSLOG-SERVERS server SYSLOG-1 server <SYSLOG-IP>")
    if not c.has(r"deviceconfig system ntp-servers "):
        add("low", "security", "No NTP server", "Log timestamps cannot be correlated across devices.",
            "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <NTP-IP>")
    if not c.has(r"deviceconfig system login-banner "):
        add("low", "security", "No login banner", "Legal warning banners support prosecution of unauthorized access.",
            'set deviceconfig system login-banner "Authorized access only."')
    if c.has(r"mgt-config users admin "):
        add("medium", "security", "Default admin account present", "admin is the first account attackers try.",
            "Create your own superuser, log in with it, then: delete mgt-config users admin")
    for n, f in _allow(c).items():
        if all(f.get(k) == ["any"] for k in ("source", "destination", "application", "service")):
            add("high", "security", f"Rule {n} allows everything", "An allow-all rule turns the firewall into a router.",
                f"Narrow rulebase security rules {n} to the applications and addresses it needs", n)
        elif not all(_rule_profiles(c, f, k) for k in ("virus", "spyware", "vulnerability")):
            add("medium", "security", f"Rule {n} allows traffic without threat inspection",
                "Allowed traffic isn't scanned for exploits, malware or command-and-control.",
                f"set rulebase security rules {n} profile-setting group <PROFILE-GROUP>", n)
    if c.value(r"rulebase default-security-rules rules interzone-default action (\S+)$") == "allow":
        add("high", "security", "Interzone default allows traffic", "Anything no rule matches crosses zones.",
            "set rulebase default-security-rules rules interzone-default action deny")
    if c.has(r"network virtual-router \S+ protocol ospf enable yes") and not c.has(r"network virtual-router \S+ protocol ospf area \S+ interface \S+ authentication "):
        add("medium", "security", "OSPF without authentication", "Anyone on the segment can inject routes.",
            "set network virtual-router default protocol ospf auth-profile OSPF-AUTH md5 1 key <KEY>")
    for m in c.find(r"network virtual-router \S+ protocol bgp peer-group (\S+) peer (\S+) peer-address ip (\S+)$"):
        if not c.has(rf"network virtual-router \S+ protocol bgp peer-group {re.escape(m[1])} peer {re.escape(m[2])} connection-options authentication "):
            add("medium", "security", f"BGP neighbor {m[3]} without authentication", "Session can be reset or hijacked.",
                f"set network virtual-router default protocol bgp peer-group {m[1]} peer {m[2]} connection-options authentication <AUTH-PROFILE>")
    if re.search(r"<[A-Z0-9][A-Z0-9.-]*>", cfg):
        add("info", "deploy", "Placeholders still present", "Replace every <ANGLE-BRACKET> value before deploying.", "")
    return _score(found)


def _audit_fortios(cfg: str) -> dict:
    """FortiOS (`show full-configuration` is best): management risks plus the policy problems a firewall review looks for first."""
    from .stig_fortios import Fos
    c, found = Fos(cfg), []
    add = lambda *a: found.append(_f(*a))  # noqa: E731
    for name, f in c.interfaces.items():
        plain = sorted(set(f.get("allowaccess", [])) & {"http", "telnet"})
        if plain:
            add("high", "security", f"Cleartext management on {name}", "Telnet and HTTP send credentials in cleartext.",
                f"config system interface\n    edit {name}\n        set allowaccess ping https ssh\n    next\nend", name)
    if c.table("system snmp community"):
        add("high", "security", "SNMP v1/v2c community", "SNMPv1/v2c sends the community in cleartext.",
            "config system snmp community\n    delete <ID>\nend")
    admins = c.table("system admin")
    if admins and not all(f.get("trusthost1") for f in admins.values()):
        add("medium", "security", "Management not limited to a management subnet", "Anyone who can reach a management interface can attempt to log in.",
            "config system admin\n    edit <ADMIN>\n        set trusthost1 <MGMT-NET> <MASK>\n    next\nend")
    t = c.num(r"system global admintimeout (\d+)$")
    if not t or t > 10:
        add("medium", "security", "Sessions don't time out quickly", "Idle sessions stay open for anyone at the terminal.",
            "config system global\n    set admintimeout 10\nend")
    if not c.has(r"log (syslogd\d?|fortianalyzer\d?) setting status enable$"):
        add("low", "security", "No remote logging", "Logs are lost on reboot and can be wiped by an attacker.",
            "config log syslogd setting\n    set status enable\n    set server <SYSLOG-IP>\nend")
    if not c.has(r"system ntp type custom$"):
        add("low", "security", "No NTP server of your own", "Log timestamps cannot be correlated across devices.",
            "config system ntp\n    set type custom\n    config ntpserver\n        edit 1\n            set server <NTP-IP>\n        next\n    end\nend")
    if not c.has(r"system global pre-login-banner enable$"):
        add("low", "security", "No login banner", "Legal warning banners support prosecution of unauthorized access.",
            "config system global\n    set pre-login-banner enable\nend")
    if "admin" in admins:
        add("medium", "security", "Default admin account present", "admin is the first account attackers try.",
            "Create your own super_admin account, log in with it, then: config system admin / delete admin / end")
    for k, f in c.policies.items():
        n = f.get("name", [k])[0]
        if f.get("action") != ["accept"] or f.get("status") == ["disable"]:
            continue
        if f.get("srcaddr") == ["all"] and f.get("dstaddr") == ["all"] and f.get("service") == ["ALL"]:
            add("high", "security", f"Policy {n} allows everything", "An allow-all policy turns the firewall into a router.",
                f"Narrow firewall policy {k} to the addresses and services it needs", n)
        elif f.get("utm-status") != ["enable"] or not (f.get("ips-sensor") and f.get("av-profile")):
            add("medium", "security", f"Policy {n} allows traffic without threat inspection",
                "Allowed traffic isn't scanned for exploits or malware.",
                f'config firewall policy\n    edit {k}\n        set utm-status enable\n        set ips-sensor "default"\n        set av-profile "default"\n    next\nend', n)
    ospf_ifs = c.table("router ospf ospf-interface")
    if c.has(r"router ospf router-id ") and not any(f.get("authentication", ["none"])[0] != "none" for f in ospf_ifs.values()):
        add("medium", "security", "OSPF without authentication", "Anyone on the segment can inject routes.",
            "config router ospf\n    config ospf-interface\n        edit <IF>\n            set authentication message-digest\n        next\n    end\nend")
    for ip, f in c.table("router bgp neighbor").items():
        if not f.get("password"):
            add("medium", "security", f"BGP neighbor {ip} without authentication", "Session can be reset or hijacked.",
                f'config router bgp\n    config neighbor\n        edit "{ip}"\n            set password <KEY>\n        next\n    end\nend')
    if re.search(r"<[A-Z0-9][A-Z0-9.-]*>", cfg):
        add("info", "deploy", "Placeholders still present", "Replace every <ANGLE-BRACKET> value before deploying.", "")
    return _score(found)


def audit(cfg: str, nos: str = "ios-xe") -> dict:
    if nos == "fortios":
        return _audit_fortios(cfg)
    if nos == "panos":
        return _audit_panos(cfg)
    if nos == "junos":
        return _audit_junos(cfg)
    if nos == "asa":
        return _audit_asa(cfg)
    if nos in ("nx-os", "eos"):
        return _audit_dc(cfg, nos)
    b = blocks(cfg)
    top = [p for p, _ in b]
    has = lambda pat: any(re.search(pat, p) for p in top)  # noqa: E731
    found = []
    add = lambda *a: found.append(_f(*a))  # noqa: E731

    # --- management plane ---
    for p, kids in b:
        if not p.startswith("line vty"):
            continue
        ti = next((k for k in kids if k.startswith("transport input")), None)
        if ti is None:
            add("medium", "security", "VTY transport not restricted", "Older IOS defaults allow Telnet on VTY lines.",
                "transport input ssh", p)
        elif re.search(r"\b(telnet|all)\b", ti):
            add("high", "security", "Telnet allowed on VTY", "Telnet sends credentials in cleartext.",
                "transport input ssh", p)
        if ti != "transport input none" and not any(k.startswith("access-class") for k in kids):
            add("medium", "security", "VTY lines not limited to a management subnet",
                "Anyone who can reach the device can attempt to log in.",
                "ip access-list standard MGMT-ACCESS\n permit <MGMT-NET> <WILDCARD>\n deny any log\n"
                f"{p}\n access-class MGMT-ACCESS in", p)
    for p, kids in b:
        if p.startswith("line ") and "exec-timeout 0 0" in kids:
            add("medium", "security", "Session never times out", "Idle sessions stay open for anyone at the terminal.",
                f"{p}\n exec-timeout 10 0", p)
    if has(r"^enable password"):
        add("high", "security", "enable password uses reversible encryption",
            "Type 0/7 passwords are recoverable in seconds.",
            "no enable password\nenable algorithm-type scrypt secret <ENABLE-SECRET>")
    for p in top:
        if re.match(r"^username \S+ .*\bpassword\b", p):
            user = p.split()[1]
            add("high", "security", f"Local user {user} uses a reversible password", "Type 0/7 passwords are recoverable.",
                f"username {user} privilege 15 algorithm-type scrypt secret <SECRET>", p)
    for p in top:
        m = re.match(r"^snmp-server community (\S+)(.*)", p)
        if m:
            rw = " RW" in m.group(2).upper()
            add("critical" if rw else "high", "security", f"SNMP community string{' with write access' if rw else ''}",
                "SNMPv1/v2c sends the community in cleartext" + ("; RW lets an attacker change config." if rw else "."),
                f"no {p}\nsnmp-server group RO v3 priv\nsnmp-server user <USER> RO v3 auth sha <AUTH> priv aes 128 <PRIV>", p)
    if "ip http server" in top:
        add("high", "security", "HTTP server enabled", "Unencrypted web management interface.", "no ip http server")
    if "ip http secure-server" in top:
        add("low", "security", "HTTPS server enabled", "Disable web management unless you use it.", "no ip http secure-server")
    if "aaa new-model" not in top:
        add("medium", "security", "AAA not enabled", "No central authentication, authorization, or login lockout options.",
            "aaa new-model\naaa authentication login default local\naaa authorization exec default local")
    if "ip ssh version 2" not in top:
        add("medium", "security", "SSH version 2 not enforced", "SSHv1 has known cryptographic weaknesses.", "ip ssh version 2")
    if "service password-encryption" not in top:
        add("low", "security", "Password encryption service off", "Any remaining type 0 passwords show in plaintext.",
            "service password-encryption")
    if not has(r"^login block-for"):
        add("low", "security", "No login brute-force protection", "Unlimited password guessing is allowed.",
            "login block-for 120 attempts 3 within 60")
    if not has(r"^banner (login|motd)"):
        add("low", "security", "No login banner", "Legal warning banners support prosecution of unauthorized access.",
            "banner login %Authorized access only.%")
    if "no ip source-route" not in top:
        add("low", "security", "IP source routing not disabled", "Lets senders choose the path packets take.",
            "no ip source-route")
    if not has(r"^logging host"):
        add("low", "security", "No remote syslog", "Logs are lost on reboot and can be wiped by an attacker.",
            "logging host <SYSLOG-IP>\nlogging trap informational")
    if not has(r"^ntp server"):
        add("low", "security", "No NTP server", "Log timestamps cannot be correlated across devices.", "ntp server <NTP-IP>")

    # --- switching ---
    bpdu_default = "spanning-tree portfast bpduguard default" in top
    for p, kids in b:
        if not p.startswith("interface") or "shutdown" in kids:
            continue
        if "switchport mode access" in kids:
            if not bpdu_default and "spanning-tree bpduguard enable" not in kids:
                add("medium", "security", "Access port without BPDU Guard",
                    "A rogue switch on this port could take over spanning tree.", f"{p}\n spanning-tree bpduguard enable", p)
            if "switchport port-security" not in kids:
                add("low", "security", "Access port without port security", "Unlimited MACs can attach (MAC flooding).",
                    f"{p}\n switchport port-security maximum 2\n switchport port-security violation restrict\n"
                    " switchport port-security", p)
        if "switchport mode trunk" in kids:
            if "switchport nonegotiate" not in kids:
                add("low", "security", "Trunk still negotiates DTP", "DTP can be abused for switch spoofing.",
                    f"{p}\n switchport nonegotiate", p)
            if not any(k.startswith("switchport trunk native vlan") for k in kids):
                add("medium", "security", "Trunk uses native VLAN 1", "Enables double-tagging VLAN hopping attacks.",
                    f"{p}\n switchport trunk native vlan 999", p)
            if not any(k.startswith("switchport trunk allowed vlan") for k in kids):
                add("low", "design", "Trunk allows all VLANs", "Prune to the VLANs actually needed to limit broadcast scope.",
                    f"{p}\n switchport trunk allowed vlan <LIST>", p)
        if any(k.startswith("switchport mode dynamic") for k in kids):
            add("medium", "security", "Port in dynamic DTP mode", "Port can be negotiated into a trunk by an attacker.",
                f"{p}\n switchport mode access\n switchport nonegotiate", p)
    if any("switchport" in k for _, ks in b for k in ks) and not has(r"^spanning-tree mode (rapid-pvst|mst)"):
        add("low", "design", "Legacy spanning tree", "802.1D converges in 30-50 s; Rapid PVST+ converges in about a second.",
            "spanning-tree mode rapid-pvst")

    # --- routing ---
    for p, kids in b:
        if p.startswith("router ospf"):
            if not any("ip ospf authentication" in k for _, ks in b for k in ks) and \
                    not any("area" in k and "authentication" in k for k in kids):
                add("medium", "security", "OSPF without authentication", "Anyone on a segment can inject routes.",
                    "key chain OSPF-KEYS\n key 1\n  key-string <KEY>\n  cryptographic-algorithm hmac-sha-256\n"
                    "interface <IF>\n ip ospf authentication key-chain OSPF-KEYS", p)
            if not any(k.startswith("passive-interface default") for k in kids):
                add("low", "design", "OSPF not passive by default", "Hellos are sent out user-facing ports.",
                    f"{p}\n passive-interface default\n no passive-interface <TRANSIT-IF>", p)
            if not any(k.startswith("auto-cost reference-bandwidth") for k in kids):
                add("low", "design", "Default OSPF reference bandwidth",
                    "1G, 10G and 100G links all get cost 1, so OSPF cannot prefer faster paths.",
                    f"{p}\n auto-cost reference-bandwidth 100000", p)
        if p.startswith("router bgp"):
            nbrs = {k.split()[1] for k in kids if re.match(r"neighbor \S+ remote-as", k)}
            authed = {k.split()[1] for k in kids if re.match(r"neighbor \S+ (password|ao) ", k)}
            for n in sorted(nbrs - authed):
                add("medium", "security", f"BGP neighbor {n} without authentication", "Session can be reset or hijacked.",
                    f"{p}\n neighbor {n} password <BGP-PASSWORD>", p)
    if re.search(r"<[A-Z0-9][A-Z0-9.-]*>", cfg):
        add("info", "deploy", "Placeholders still present", "Replace every <ANGLE-BRACKET> value before deploying.", "")

    return _score(found)
