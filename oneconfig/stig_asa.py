"""DISA STIG checks for Cisco ASA (Cisco ASA NDM V2R5, Firewall V2R1, IPS V2R1, VPN V2R2; also used for FTD's ASA-style config).

Rule IDs are CASA-*. Commands come from DISA's ASA fix text. IPS rules are FirePOWER-module GUI checks and VPN
rules apply only when a VPN is configured, so both are gated."""
import re
from functools import cached_property

from .stig import BENCH, Cfg, bad, manual, na, nd_banner, ok

CHECKS, MANUAL_WHY = {}, {}
LEVELS = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3, "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7}
MGMT = {"snmp": ("snmp", "161"), "snmptrap": ("snmptrap", "162"), "ntp": ("ntp", "123"), "syslog": ("syslog", "514"),
        "ssh": ("ssh", "22"), "tacacs": ("tacacs", "49")}


def check(*ids, fix=""):
    def deco(fn):
        for i in ids:
            CHECKS[i] = (fn, fix)
        return fn
    return deco


class Asa(Cfg):
    @cached_property
    def nameifs(self):
        """nameif -> (interface, security level, management-only)."""
        out = {}
        for n, k in self.ifs.items():
            name = next((z.split()[1] for z in k if z.startswith("nameif ")), None)
            if name and "shutdown" not in k:
                lvl = next((int(m[1]) for z in k if (m := re.match(r"security-level (\d+)", z))), 0)  # a pasted config may say anything
                out[name] = (n, lvl, "management-only" in k or n.lower().startswith("management"))
        return out

    @cached_property
    def acls(self):
        out = {}
        for p in self.top:
            m = re.match(r"access-list (\S+) (?:extended )?(permit|deny) (.*)$", p)
            if m:
                out.setdefault(m[1], []).append(f"{m[2]} {m[3]}")
        return out

    @cached_property
    def groups(self):
        return {m[2]: m[1] for p in self.top if (m := re.match(r"access-group (\S+) in interface (\S+)$", p))}

    def value(self, pat, default=None):
        m = re.search(pat, self.text, re.M)
        return m.group(1) if m else default


def _sides(c, x):
    """(external nameifs, internal nameifs) of interfaces that carry traffic."""
    live = {n: v for n, v in c.nameifs.items() if not v[2]}
    ext_ifs = x.get("external")
    ext = {n for n, v in live.items() if (v[0] in ext_ifs if x.get("generated") or ext_ifs else v[1] == 0)}
    return ext, set(live) - ext


# ---------------------------------------------------------------- NDM
LOGGING = "logging enable\nlogging buffered informational"


@check("CASA-ND-000090", "CASA-ND-000100", "CASA-ND-000110", "CASA-ND-000120", "CASA-ND-000210", "CASA-ND-000240",
       "CASA-ND-000260", "CASA-ND-000280", "CASA-ND-000290", "CASA-ND-000300", "CASA-ND-000320", "CASA-ND-000910",
       "CASA-ND-001200", "CASA-ND-001210", "CASA-ND-001220", "CASA-ND-001230", "CASA-ND-001250", fix=LOGGING)
def nd_logging(c, x):
    lvl = c.value(r"^logging buffered (\S+)$")
    if "logging enable" not in c.top:
        return bad("Logging is not enabled (logging enable).")
    if LEVELS.get(lvl, int(lvl) if (lvl or "").isdigit() else -1) < 6:
        return bad(f"Buffered logging must be informational or more detailed (now: {lvl or 'off'}).")
    return ok(f"logging enable; logging buffered {lvl}")


@check("CASA-ND-001240", fix=LOGGING + "\nlogging timestamp")
def nd_logging_times(c, x):
    s, d = nd_logging(c, x)
    return (s, d) if s != "not_a_finding" else ok(d + "; logging timestamp") if "logging timestamp" in c.top else bad("No logging timestamp.")


@check("CASA-ND-000270", "CASA-ND-000970", "CASA-FW-000050", fix="logging timestamp")
def nd_timestamp(c, x):
    return ok("logging timestamp") if "logging timestamp" in c.top else bad("Log messages carry no timestamp (logging timestamp).")


@check("CASA-ND-000010", fix="quota management-session 5")
def nd_sessions(c, x):
    q = c.value(r"^(quota management-session .+)$")
    return ok(q) if q else bad("Concurrent management sessions are not limited (quota management-session).")


@check("CASA-ND-000140", fix="ssh <MGMT-NET> <MASK> <NAMEIF>")
def nd_mgmt_scope(c, x):
    lines = [p for p in c.top if re.match(r"(ssh|http) \d+\.\d+\.\d+\.\d+ \d+\.\d+\.\d+\.\d+ \S+$", p)]
    wide = [p for p in lines if " 0.0.0.0 0.0.0.0 " in p]
    if wide:
        return bad("Management is open to any address: " + "; ".join(wide))
    return ok("; ".join(lines)) if any(p.startswith("ssh ") for p in lines) else bad("No ssh line limits management to a subnet.")


check("CASA-ND-000160", fix="banner login <Standard Mandatory DoD Notice and Consent Banner, one line per banner login command>")(nd_banner)


@check("CASA-ND-000430", "CASA-FW-000130", fix="no http server enable\nno telnet <IP> <MASK> <NAMEIF>")
def nd_services(c, x):
    on = [p for p in c.top if p.startswith("http server enable") or re.match(r"telnet \d", p)]
    return bad("Enabled: " + "; ".join(on) + " (http server is allowed only if ASDM is approved)") if on else ok("No HTTP server or Telnet")


@check("CASA-ND-000450", fix="username <ADMIN-USER> password <SECRET> privilege 15\n"
                            "aaa authentication ssh console <AAA-GROUP> LOCAL\naaa authentication serial console <AAA-GROUP> LOCAL")
def nd_last_resort(c, x):
    users = sorted({p.split()[1] for p in c.top if p.startswith("username ")})
    probs = [] if len(users) == 1 else [f"{len(users)} local accounts configured (need exactly one)"]
    for m in ("ssh", "serial"):
        if not re.search(rf"^aaa authentication {m} console (?!LOCAL\b)\S+ LOCAL$", c.text, re.M):
            probs.append(f"{m} logins don't try an AAA group before LOCAL")
    return bad("; ".join(probs)) if probs else ok(f"One local account ({users[0]}) used as last resort")


def _fips(c):
    return "fips enable" in c.top


@check("CASA-ND-000470", fix="fips enable\nssh cipher encryption fips\nssh key-exchange group dh-group14-sha256")
def nd_ssh_kex(c, x):
    miss = [m for m, good in (("fips enable", _fips(c)), ("ssh cipher encryption fips", "ssh cipher encryption fips" in c.top),
                              ("ssh key-exchange group dh-group14 or stronger", bool(c.value(r"^ssh key-exchange group (dh-group1[4-9]|dh-group2\d|ecdh)"))))
            if not good]
    return bad("Missing: " + "; ".join(miss)) if miss else ok("FIPS mode, FIPS SSH ciphers, DH group 14+")


def _snmp(c):
    return [p for p in c.top if p.startswith(("snmp-server group", "snmp-server user", "snmp-server host", "snmp-server community"))]


@check("CASA-ND-001140", fix="fips enable\nssh cipher encryption fips\nssh cipher integrity fips\n"
                            "snmp-server user <SNMP-USER> <GROUP> v3 auth sha256 <AUTH-PASS> priv aes 256 <PRIV-PASS>")
def nd_hmac(c, x):
    probs = [] if _fips(c) else ["fips enable is missing"]
    if "ssh cipher integrity fips" not in c.top and "ssh cipher encryption fips" not in c.top:
        probs.append("SSH is not limited to FIPS ciphers")
    probs += [f"SNMP user without SHA authentication: {p}" for p in c.top
              if p.startswith("snmp-server user") and not re.search(r" auth sha\d*\b", p)]
    return bad("; ".join(probs)) if probs else ok("FIPS mode; SSH and SNMP use FIPS HMACs")


@check("CASA-ND-001150", fix="fips enable\nssh cipher encryption fips")
def nd_ssh_enc(c, x):
    miss = [m for m in ("fips enable", "ssh cipher encryption fips") if m not in c.top]
    return bad("Missing: " + "; ".join(miss)) if miss else ok("FIPS mode with FIPS SSH ciphers")


def _policy(key, need, word):
    def fn(c, x):
        v = c.value(rf"^password-policy {key} (\d+)$")
        return ok(f"password-policy {key} {v}") if v and int(v) >= need else bad(f"Passwords need {word} (password-policy {key} {need}).")
    return fn


for _id, _key, _need, _word in (("490", "minimum-length", 15, "at least 15 characters"), ("520", "minimum-uppercase", 1, "an uppercase letter"),
                                ("530", "minimum-lowercase", 1, "a lowercase letter"), ("550", "minimum-numeric", 1, "a number"),
                                ("570", "minimum-special", 1, "a special character"), ("580", "minimum-changes", 8, "8 changed characters")):
    check(f"CASA-ND-000{_id}", fix=f"password-policy {_key} {_need}")(_policy(_key, _need, _word))


@check("CASA-ND-000690", fix="ssh timeout 5\nconsole timeout 5\nhttp server idle-timeout 5")
def nd_idle(c, x):
    t = {"ssh timeout": int(c.value(r"^ssh timeout (\d+)$", 5)), "console timeout": int(c.value(r"^console timeout (\d+)$", 0)),
         "http server idle-timeout": int(c.value(r"^http server idle-timeout (\d+)$", 20))}
    long_ = [f"{k} {v}{' (never)' if v == 0 else ''}" for k, v in t.items() if v == 0 or v > 5]
    return bad("Longer than 5 minutes: " + "; ".join(long_)) if long_ else ok("SSH, console and ASDM sessions end after 5 idle minutes")


@check("CASA-ND-000920", fix="logging flash-bufferwrap\nlogging flash-maximum-allocation <KB>\nlogging flash-minimum-free <KB>")
def nd_log_storage(c, x):
    have = [p for p in c.top if p.startswith(("logging flash-maximum-allocation", "logging flash-minimum-free"))]
    return ok("; ".join(have) + " (confirm the sizes meet your policy)") if len(have) == 2 else bad("Log storage on flash is not sized.")


def _hosts(c):
    return [p for p in c.top if p.startswith("logging host ")]


@check("CASA-ND-000930", fix="logging trap critical\nlogging host <NAMEIF> <SYSLOG-IP> 6/1514")
def nd_alerts(c, x):
    trap = c.value(r"^logging trap (\S+)$")
    return ok(f"logging trap {trap} to {len(_hosts(c))} host(s)") if trap and _hosts(c) else bad("Critical events are not sent to a log server.")


@check("CASA-ND-000940", fix="ntp server <NTP-1> key 1 prefer\nntp server <NTP-2> key 1")
def nd_ntp(c, x):
    n = [p for p in c.top if p.startswith("ntp server ")]
    return ok(f"{len(n)} NTP servers") if len(n) >= 2 else bad(f"{len(n)} NTP server(s); need two.")


@check("CASA-ND-001050", fix="snmp-server group <GROUP> v3 priv\nsnmp-server user <SNMP-USER> <GROUP> v3 auth sha256 <AUTH-PASS> priv aes 256 <PRIV-PASS>")
def nd_snmp_auth(c, x):
    if not _snmp(c):
        return na("SNMP is not configured.")
    weak = [p for p in _snmp(c) if p.startswith("snmp-server community") or (p.startswith("snmp-server group") and not re.search(r" v3 (auth|priv)$", p))
            or (p.startswith("snmp-server user") and not re.search(r" v3 .*auth sha", p))]
    return bad("Not SNMPv3 with SHA: " + "; ".join(weak)) if weak else ok("SNMPv3 with SHA authentication")


@check("CASA-ND-001070", fix="snmp-server group <GROUP> v3 priv\nsnmp-server user <SNMP-USER> <GROUP> v3 auth sha256 <AUTH-PASS> priv aes 256 <PRIV-PASS>")
def nd_snmp_priv(c, x):
    if not _snmp(c):
        return na("SNMP is not configured.")
    weak = [p for p in _snmp(c) if (p.startswith("snmp-server group") and not p.endswith(" v3 priv"))
            or (p.startswith("snmp-server user") and " priv aes" not in p) or p.startswith("snmp-server community")]
    return bad("Not encrypted with AES: " + "; ".join(weak)) if weak else ok("SNMPv3 encrypted with AES")


@check("CASA-ND-001080", fix="ntp authenticate\nntp authentication-key 1 sha256 <NTP-KEY>\nntp trusted-key 1\nntp server <NTP-IP> key 1")
def nd_ntp_auth(c, x):
    servers = [p for p in c.top if p.startswith("ntp server ")]
    if not servers:
        return bad("No NTP servers.")
    probs = [] if "ntp authenticate" in c.top else ["ntp authenticate is missing"]
    if not c.value(r"^ntp authentication-key \d+ (sha1|sha256|sha512) "):
        probs.append("no NTP key with a FIPS algorithm (sha1, sha256 or sha512)")
    probs += [f"unkeyed: {p}" for p in servers if " key " not in p]
    return bad("; ".join(probs)) if probs else ok("NTP authenticated with a SHA key")


@check("CASA-ND-001180", "CASA-FW-000150", fix="threat-detection basic-threat")
def nd_threat(c, x):
    return ok("threat-detection basic-threat") if "threat-detection basic-threat" in c.top else bad("Basic threat detection is off.")


@check("CASA-ND-001310", fix="aaa-server <GROUP> protocol tacacs+\naaa-server <GROUP> (<NAMEIF>) host <AAA-1>\n key <KEY>\n"
                            "aaa-server <GROUP> (<NAMEIF>) host <AAA-2>\n key <KEY>\naaa authentication ssh console <GROUP> LOCAL\n"
                            "aaa authentication serial console <GROUP> LOCAL")
def nd_aaa_servers(c, x):
    groups = {m[1] for m in re.finditer(r"^aaa authentication (?:ssh|serial) console (\S+)", c.text, re.M)} - {"LOCAL"}
    if not groups:
        return bad("SSH and console logins don't use an authentication server group.")
    counts = {g: len(re.findall(rf"^aaa-server {re.escape(g)} \(\S+\) host ", c.text, re.M)) for g in groups}
    few = [f"{g} has {n}" for g, n in counts.items() if n < 2]
    return bad("Need two servers per group: " + "; ".join(few)) if few else ok(", ".join(f"{g}: {n} servers" for g, n in counts.items()))


@check("CASA-ND-001350", fix='event manager applet BACKUP_CONFIG\n event syslog id 111010\n'
                            ' action 1 cli command "copy /noconfirm running-config scp://<USER>:<PASS>@<SERVER>/<FILE>"')
def nd_backup(c, x):
    for p, k in c.get(r"event manager applet "):
        if any(z.startswith("event syslog id 111010") for z in k) and any("copy " in z for z in k):
            return ok(p + " copies the config on every change")
    return bad("No EEM applet backs up the configuration after changes.")


@check("CASA-ND-001370")
def nd_pki(c, x):
    return manual("Verify the trustpoint's CA is DoD-approved (show crypto ca certificates).") if c.has(r"^crypto ca trustpoint ") \
        else na("PKI certificates are not used.")


@check("CASA-ND-001410", fix="logging host <NAMEIF> <SYSLOG-1> 6/1514\nlogging host <NAMEIF> <SYSLOG-2> 6/1514\nlogging trap notifications")
def nd_syslog(c, x):
    h = _hosts(c)
    return ok(f"{len(h)} log servers") if len(h) >= 2 else bad(f"{len(h)} log server(s); need two.")


@check("CASA-ND-001420")
def nd_release(c, x):
    v = c.value(r"^(?:ASA )?[Vv]ersion (\S+)")
    return manual(f"Running {v or 'an unknown release'}. Confirm with show version that Cisco still supports it.")


# ---------------------------------------------------------------- Firewall
def _bound(c, names):
    return {n: c.groups.get(n) for n in names}


@check("CASA-FW-000010", fix="access-list <INSIDE>_IN extended permit tcp <LAN> any eq https\naccess-list <INSIDE>_IN extended deny ip any any log\n"
                            "access-group <INSIDE>_IN in interface <INSIDE>")
def fw_outbound(c, x):
    _, internal = _sides(c, x)
    probs = [f"{n} has no inbound access list" for n, a in _bound(c, internal).items() if not a]
    probs += [f"{a}: {e}" for n, a in _bound(c, internal).items() if a for e in c.acls.get(a, [])
              if re.match(r"permit ip \S+(?: \S+)? any4?(?: log.*)?$", e)]
    return bad("Outbound traffic is not limited to approved services: " + "; ".join(probs)) if probs else \
        ok("Every internal interface filters by service") if internal else na("No internal interfaces.")


@check("CASA-FW-000020", fix="no asp rule-engine transactional-commit access-group")
def fw_commit(c, x):
    return bad("asp rule-engine transactional-commit access-group delays rule updates.") \
        if c.has(r"^asp rule-engine transactional-commit access-group") else ok("Rule changes take effect at once")


@check("CASA-FW-000040", fix="logging enable\naccess-list <ACL> extended deny ip any any log")
def fw_deny_log(c, x):
    quiet = [f"{a}: {e}" for a, es in c.acls.items() for e in es if e.startswith("deny") and not re.search(r" log( |$)", e)]
    if "logging enable" not in c.top:
        quiet.insert(0, "logging enable is missing")
    return bad("; ".join(quiet[:6])) if quiet else ok("Every deny is logged")


@check("CASA-FW-000090", fix="logging buffered informational\nlogging queue 8192")
def fw_queue(c, x):
    q = c.value(r"^logging queue (\d+)$")
    return ok(f"logging queue {q}") if q and c.has(r"^logging buffered ") else bad("Logs are not queued locally (logging buffered + logging queue 8192).")


@check("CASA-FW-000100", fix="logging host <NAMEIF> <SYSLOG-IP> 6/1514\nlogging permit-hostdown")
def fw_tcp_syslog(c, x):
    h = _hosts(c)
    udp = [p for p in h if not re.search(r" (6|tcp)/\d+", p)]
    if not h:
        return bad("No log servers.")
    if udp:
        return bad("Not over TCP: " + "; ".join(udp))
    return ok("TCP syslog with permit-hostdown") if "logging permit-hostdown" in c.top else \
        bad("TCP syslog without logging permit-hostdown blocks new connections when the log servers are down.")


@check("CASA-FW-000170")
def fw_inbound_ppsm(c, x):
    ext, _ = _sides(c, x)
    miss = [n for n, a in _bound(c, ext).items() if not a]
    return bad("No inbound access list on " + ", ".join(miss)) if miss else \
        manual("Verify the inbound rules permit only ports and services approved in the PPSM CAL.") if ext else na("No external interfaces.")


@check("CASA-FW-000200", fix="logging host <NAMEIF> <SYSLOG-IP> 6/1514\nlogging trap notifications")
def fw_deny_to_server(c, x):
    trap = c.value(r"^logging trap (\S+)$")
    if not _hosts(c):
        return bad("No log servers.")
    return ok(f"logging trap {trap}") if LEVELS.get(trap, -1) >= 4 else \
        bad(f"Denied-traffic messages (level 4) don't reach the log server (logging trap {trap or 'off'}).")


MAIL = "logging mail errors\nlogging from-address <FIREWALL-EMAIL>\nlogging recipient-address <ADMIN-EMAIL> level errors\nsmtp-server <SMTP-IP>"


def _mail(c, max_level):
    lvl = c.value(r"^logging mail (\S+)$")
    n = LEVELS.get(lvl, int(lvl) if (lvl or "").isdigit() else -1)
    if n < 0 or not c.has(r"^logging recipient-address ") or not c.has(r"^smtp-server "):
        return "E-mail alerts are not set up (logging mail, recipient-address, smtp-server)."
    return None if n >= max_level else f"logging mail {lvl} misses the alerts this rule needs."


@check("CASA-FW-000210", fix=MAIL)
def fw_mail_lost(c, x):
    p = _mail(c, 3)  # %ASA-3-201008: log server lost
    return bad(p) if p else ok("Administrators are e-mailed when the log server is lost")


@check("CASA-FW-000300", fix="threat-detection scanning-threat\n" + MAIL)
def fw_mail_dos(c, x):
    p = _mail(c, 3) or (None if c.has(r"^threat-detection scanning-threat") else "Scanning threat detection is off.")
    return bad(p) if p else ok("Threat detection alerts are e-mailed")


@check("CASA-FW-000220", fix="threat-detection scanning-threat shun")
def fw_scanning(c, x):
    return ok(c.value(r"^(threat-detection scanning-threat.*)$")) if c.has(r"^threat-detection scanning-threat") else bad("Scanning threat detection is off.")


@check("CASA-FW-000230", fix="access-list OUTSIDE_IN extended permit tcp any host <SERVER> eq https\naccess-list OUTSIDE_IN extended deny ip any any log\n"
                            "access-group OUTSIDE_IN in interface <OUTSIDE>")
def fw_external_in(c, x):
    ext, _ = _sides(c, x)
    if not ext:
        return na("No external interfaces.")
    probs = []
    for n, a in _bound(c, ext).items():
        es = c.acls.get(a or "", [])
        if not a:
            probs.append(f"{n} has no inbound access list")
        elif not es or not re.match(r"deny ip any4? any4? log", es[-1]):
            probs.append(f"{a} does not end with deny ip any any log")
    return bad("; ".join(probs)) if probs else ok("Every external interface filters inbound traffic")


@check("CASA-FW-000240", fix="access-group <INSIDE>_IN in interface <INSIDE>")
def fw_internal_in(c, x):
    _, internal = _sides(c, x)
    miss = [n for n, a in _bound(c, internal).items() if not a]
    return bad("No inbound access list on " + ", ".join(miss)) if miss else ok("Every internal interface filters") if internal else na("No internal interfaces.")


@check("CASA-FW-000250", fix="\n".join(f"access-list <INSIDE>_IN extended deny {'tcp' if k in ('ssh', 'tacacs') else 'udp'} any any eq {k} log"
                                       for k in MGMT) + "\n(before the rules that permit traffic to the outside)")
def fw_mgmt_out(c, x):
    ext, internal = _sides(c, x)
    if not ext or not internal:
        return na("Not a perimeter firewall (needs internal and external interfaces).")
    probs = []
    for n, a in _bound(c, internal).items():
        es = c.acls.get(a or "", [])
        miss = [k for k, words in MGMT.items() if not any(re.match(rf"deny (tcp|udp|tcp-udp) .* eq ({'|'.join(words)})\b", e) for e in es)]
        if miss:
            probs.append(f"{a or n + ' (no access list)'} does not block outbound {', '.join(miss)}")
    return bad("; ".join(probs)) if probs else ok("Internal interfaces block outbound management traffic")


@check("CASA-FW-000260")
def fw_mgmt_ipsec(c, x):
    return manual("If the firewall is managed across an untrusted network, verify management traffic to the NOC runs in an IPsec tunnel.")


@check("CASA-FW-000270", fix="service-policy global_policy global")
def fw_inspect(c, x):
    sp = c.value(r"^service-policy (\S+) global$")
    pm = next((k for p, k in c.get(rf"policy-map {re.escape(sp)}$")), []) if sp else []
    return ok(f"service-policy {sp} global") if sp and any(z.startswith("inspect ") for z in pm) else bad("No global inspection policy.")


@check("CASA-FW-000280", fix="policy-map type inspect ipv6 IPV6_MAP\n parameters\n  verify-header type\n  verify-header order\n"
                            "policy-map global_policy\n class inspection_default\n  inspect ipv6 IPV6_MAP")
def fw_ipv6(c, x):
    if not re.search(r"^[ \t]*ipv6 (address|enable)", c.text, re.M):
        return na("IPv6 is not enabled.")
    return ok("inspect ipv6") if re.search(r"^[ \t]+inspect ipv6", c.text, re.M) and "no verify-header" not in c.text else bad("IPv6 extension headers are not inspected.")


@check("CASA-FW-000290", fix="ip verify reverse-path interface <INSIDE>")
def fw_urpf(c, x):
    _, internal = _sides(c, x)
    miss = [n for n in internal if f"ip verify reverse-path interface {n}" not in c.top]
    return bad("No uRPF on " + ", ".join(miss) + " (or verify its access list only permits internal sources)") if miss else \
        ok("uRPF on every internal interface") if internal else na("No internal interfaces.")


# ---------------------------------------------------------------- gated benchmarks
VPN = r"^(crypto map \S+ interface|crypto ikev[12] enable|webvpn|tunnel-group \S+ type)"


def _gate(pattern, absent, what):
    def fn(c, x):
        return manual(f"{what} is configured; review this rule manually.") if re.search(pattern, c.text, re.M) else na(absent)
    return fn


_VPN = _gate(VPN, "No VPN is configured.", "A VPN")
_IPS = _gate(r"^[ \t]+(sfr|ips) (fail-open|fail-close|inline|promiscuous)", "No IPS / FirePOWER module inspects traffic.", "IPS inspection")
CHECKS["CASA-FW-000030"] = (_VPN, "")
for _bid, _fn in (("ASA_VPN", _VPN), ("ASA_IPS", _IPS)):
    for _r in BENCH[_bid]["rules"]:
        CHECKS[_r[0]] = (_fn, "")
