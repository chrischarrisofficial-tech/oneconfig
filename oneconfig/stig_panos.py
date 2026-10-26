"""DISA STIG checks for Palo Alto Networks PAN-OS (NDM V3R4, ALG V3R4, IDPS V3R2; DISA sunset these on 2026-07-10, so they
are the last release). DISA writes PAN-OS checks as web-interface steps; each check here reads the same setting from the
configuration in `set` form (`set cli config-output-format set`, then `show config running`). A pasted brace-format
configuration is flattened first."""
import re
from functools import cached_property
from ipaddress import ip_address, ip_interface

from .stig import BENCH, Lines, bad, manual, na, nd_banner, ok
from .stig_junos import flatten

CHECKS, MANUAL_WHY = {}, {}
_ROOT = re.compile(r"^config (?:devices \S+ (?:vsys \S+ )?)?")


def check(*ids, fix=""):
    def deco(fn):
        for i in ids:
            CHECKS[i] = (fn, fix)
        return fn
    return deco


class Pan(Lines):
    """A PAN-OS configuration as one line per value: lists like [ a b ] become one line per member."""

    def __init__(self, text: str):
        self.text = text
        lines = []
        for l in flatten(text):
            l = _ROOT.sub("", l.replace('"', ""))
            m = re.match(r"^(.*?) \[ (.*) \]$", l)
            lines += [f"{m[1]} {x}" for x in m[2].split()] if m else [l]
        self.lines = lines

    @cached_property
    def zones(self):
        """zone -> interfaces."""
        out = {}
        for m in self.find(r"zone (\S+) network layer3 (\S+)$"):
            out.setdefault(m[1], []).append(m[2])
        return out

    @cached_property
    def rules(self):
        """rule name -> {field: [values]} for security rules, in config order."""
        out = {}
        for m in self.find(r"rulebase security rules (\S+) (.+)$"):
            f = out.setdefault(m[1], {})
            words = m[2].split()
            key, val = (" ".join(words[:2]), words[2]) if words[0] == "profile-setting" and len(words) > 2 else (words[0], " ".join(words[1:]))
            f.setdefault(key, []).append(val)
        return out

    def profile(self, kind, name):
        return [l for l in self.lines if l.startswith(f"profiles {kind} {name} ") or l.startswith(f"shared profiles {kind} {name} ")]


def _parsed(kind, text):
    """An address from a config value, or None when a pasted config holds something that isn't one."""
    try:
        return kind(text)
    except ValueError:
        return None


def _ext(c, x):
    """External zones: zones of interfaces marked external (OneConfig's own configs), else zones that hold the
    default route's next hop or are named like an untrusted zone."""
    if x.get("generated") or x.get("external"):
        return {z for z, ifs in c.zones.items() if set(ifs) & set(x.get("external") or [])}
    ips = {m[2] or m[1]: n.network for m in c.find(r"network interface \S+ (\S+) layer3 (?:units (\S+) )?ip (\d+\.\d+\.\d+\.\d+/\d+)$")
           if (n := _parsed(ip_interface, m[3]))}
    hops = [a for h in c.values(r"network virtual-router \S+ routing-table ip static-route \S+ nexthop ip-address (\S+)$")
            if (a := _parsed(ip_address, h))
            and c.has(r"network virtual-router \S+ routing-table ip static-route \S+ destination 0\.0\.0\.0/0$")]
    return {z for z, ifs in c.zones.items() if re.match(r"(?i)(untrust|outside|internet|external|wan)", z)
            or any(i in ips and h in ips[i] for i in ifs for h in hops)}


def _allow(c):
    return {n: f for n, f in c.rules.items() if f.get("action") == ["allow"]}


def _groups(c, kind):
    """Names of profile groups that carry a profile of this kind (virus, spyware, vulnerability)."""
    return {m[1] for m in c.find(rf"(?:shared )?profile-group (\S+) {kind} \S+$")}


def _rule_profiles(c, f, kind):
    names = f.get("profile-setting profiles", [])
    direct = [v.split()[1] for v in names if v.startswith(kind + " ")]
    via = [g for g in f.get("profile-setting group", []) if g in _groups(c, kind)]
    return direct or via


# ---------------------------------------------------------------- NDM
def _admin_profiles(c):
    """Authentication profiles of local administrators (the account of last resort)."""
    local = {m[1] for m in c.find(r"(?:shared )?authentication-profile (\S+) method local-database$")}
    users = {m[1]: m[2] for m in c.find(r"mgt-config users (\S+) authentication-profile (\S+)$")}
    return {u: p for u, p in users.items() if p in local}


@check("PANW-NM-000015", fix="set shared authentication-profile LAST-RESORT method local-database\n"
                            "set shared authentication-profile LAST-RESORT lockout failed-attempts 3\n"
                            "set mgt-config users <ADMIN-USER> authentication-profile LAST-RESORT")
def nm_lockout(c, x):
    profs = _admin_profiles(c)
    if not profs:
        return bad("The account of last resort has no authentication profile with a lockout.")
    tries = {p: int(c.value(rf"(?:shared )?authentication-profile {re.escape(p)} lockout failed-attempts (\d+)$", 0)) for p in profs.values()}
    weak = [p for p, n in tries.items() if not 1 <= n <= 3]
    return bad("Lockout must be at most 3 failed attempts: " + ", ".join(weak)) if weak else ok(f"{', '.join(profs)}: locked after 3 failures")


@check("PANW-NM-000092", fix="set shared authentication-profile LAST-RESORT lockout lockout-time 0")
def nm_lock_until_release(c, x):
    profs = set(_admin_profiles(c).values())
    if not profs:
        return bad("The account of last resort has no authentication profile with a lockout.")
    weak = [p for p in profs if c.value(rf"(?:shared )?authentication-profile {re.escape(p)} lockout lockout-time (\d+)$") != "0"]
    return bad("Lockout time must be 0 (locked until an admin unlocks it): " + ", ".join(weak)) if weak else ok("Locked until an administrator unlocks it")


@check("PANW-NM-000016", fix='set deviceconfig system login-banner "<Standard Mandatory DoD Notice and Consent Banner>"')
def nm_banner(c, x):
    b = c.value(r"deviceconfig system login-banner (.+)$")
    if not b:
        return bad("No login banner configured.")
    return nd_banner(c, x) if "USG-authorized use only" not in b else ok("Standard Mandatory DoD Notice and Consent Banner present")


def _syslog_to(c, kind):
    return c.has(rf"(?:shared )?log-settings {kind} match-list \S+ send-syslog \S+$")


@check("PANW-NM-000024", "PANW-NM-000128", "PANW-IP-000039", "PANW-IP-000058", "PANW-AG-000094",
       fix="set shared log-settings syslog SYSLOG-SERVERS server SYSLOG-1 server <SYSLOG-IP>\n"
           "set shared log-settings system match-list ALL-SYSTEM send-syslog SYSLOG-SERVERS\n"
           "set shared log-settings config match-list ALL-CONFIG send-syslog SYSLOG-SERVERS")
def nm_syslog(c, x):
    if not c.has(r"(?:shared )?log-settings syslog \S+ server \S+ server \S+$"):
        return bad("No syslog server profile.")
    miss = [k for k in ("system", "config") if not _syslog_to(c, k)]
    return bad("Not forwarded to syslog: " + ", ".join(miss) + " logs") if miss else ok("System and configuration logs go to syslog")


@check("PANW-AG-000144", fix="set shared log-settings profiles default match-list TRAFFIC log-type traffic\n"
                            "set shared log-settings profiles default match-list TRAFFIC send-syslog SYSLOG-SERVERS\n"
                            "(the same for threat), and log-setting default on every security rule")
def ag_offload_traffic(c, x):
    fwd = {m[1]: set() for m in c.find(r"(?:shared )?log-settings profiles (\S+) ")}
    for m in c.find(r"(?:shared )?log-settings profiles (\S+) match-list (\S+) log-type (\S+)$"):
        if c.has(rf"(?:shared )?log-settings profiles {re.escape(m[1])} match-list {re.escape(m[2])} send-syslog "):
            fwd[m[1]].add(m[3])
    good = {p for p, t in fwd.items() if {"traffic", "threat"} <= t}
    unlogged = [n for n, f in c.rules.items() if not set(f.get("log-setting", [])) & good]
    if not good:
        return bad("No log forwarding profile sends traffic and threat logs to syslog.")
    return bad("Rules without that log forwarding profile: " + ", ".join(unlogged)) if unlogged else ok("Traffic and threat logs go to syslog")


@check("PANW-NM-000029", "PANW-IP-000007", fix="set deviceconfig system hostname <UNIQUE-NAME>")
def nm_hostname(c, x):
    h = c.value(r"deviceconfig system hostname (\S+)$")
    return manual(f"Hostname {h}. Confirm Device > Setup > Management > Logging and Reporting > Send Hostname In Syslog is set.") if h \
        else bad("No hostname.")


@check("PANW-NM-000046", fix="delete network dns-proxy <NAME>\nset deviceconfig system service disable-telnet yes\nset deviceconfig system service disable-http yes")
def nm_services(c, x):
    on = [l for l in c.lines if re.match(r"deviceconfig system service disable-(telnet|http) no$", l) or l.startswith("network dns-proxy ")]
    on += [l for l in c.lines if re.match(r"network profiles interface-management-profile \S+ (telnet|http|userid-service|userid-syslog-listener-\S+|http-ocsp) yes$", l)]
    return bad("Enabled: " + "; ".join(sorted(set(on))[:6])) if on else ok("No Telnet, HTTP, DNS proxy or User-ID listeners")


@check("PANW-NM-000051", fix="set shared server-profile ldap <NAME> ssl yes")
def nm_ldap_tls(c, x):
    ldap = {m[1] for m in c.find(r"(?:shared )?server-profile ldap (\S+) ")}
    if not ldap:
        return na("No LDAP server profile.")
    plain = [p for p in ldap if not c.has(rf"(?:shared )?server-profile ldap {re.escape(p)} ssl yes$")]
    return bad("LDAP without SSL/TLS: " + ", ".join(plain)) if plain else ok("LDAP over SSL/TLS")


def _complexity(key, need, word):
    def fn(c, x):
        if not c.has(r"mgt-config password-complexity enabled yes$"):
            return bad("Minimum password complexity is not enabled.")
        v = c.value(rf"mgt-config password-complexity {key} (\d+)$")
        return ok(f"{key} {v}") if v and int(v) >= need else bad(f"Passwords need {word} (password-complexity {key} {need}).")
    return fn


for _id, _key, _need, _word in (("53", "minimum-length", 15, "at least 15 characters"), ("55", "minimum-uppercase-letters", 1, "an uppercase letter"),
                                ("56", "minimum-lowercase-letters", 1, "a lowercase letter"), ("57", "minimum-numeric-letters", 1, "a number"),
                                ("58", "minimum-special-characters", 1, "a special character"),
                                ("59", "new-password-differs-by-characters", 8, "8 changed characters")):
    check(f"PANW-NM-0000{_id}", fix=f"set mgt-config password-complexity enabled yes\nset mgt-config password-complexity {_key} {_need}")(
        _complexity(_key, _need, _word))


@check("PANW-NM-000061", "PANW-NM-000117", fix="set deviceconfig system service disable-telnet yes\nset deviceconfig system service disable-http yes")
def nm_cleartext(c, x):
    on = [l for l in c.lines if re.match(r"deviceconfig system service disable-(telnet|http) no$", l)
          or re.match(r"network profiles interface-management-profile \S+ (telnet|http) yes$", l)]
    return bad("Cleartext management: " + "; ".join(on)) if on else ok("No Telnet or HTTP management")


@check("PANW-NM-000069", fix="set deviceconfig setting management idle-timeout 10")
def nm_idle(c, x):
    v = c.value(r"deviceconfig setting management idle-timeout (\d+)$")
    return ok(f"idle-timeout {v}") if v and 0 < int(v) <= 10 else bad(f"Management sessions must end after 10 idle minutes (now {v or 'the default, 60'}).")


@check("PANW-NM-000098", "PANW-NM-000099", "PANW-NM-000100", fix="set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <NTP-1>\n"
                                                              "set deviceconfig system ntp-servers secondary-ntp-server ntp-server-address <NTP-2>")
def nm_ntp(c, x):
    n = [k for k in ("primary", "secondary") if c.has(rf"deviceconfig system ntp-servers {k}-ntp-server ntp-server-address \S+$")]
    return ok("Primary and secondary NTP servers") if len(n) == 2 else bad("Configure both a primary and a secondary NTP server.")


@check("PANW-NM-000145", fix="set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key key-id 1\n"
                            "set deviceconfig system ntp-servers primary-ntp-server authentication-type symmetric-key algorithm sha1 authentication-key <KEY>\n"
                            "(the same for secondary-ntp-server)")
def nm_ntp_auth(c, x):
    servers = [k for k in ("primary", "secondary") if c.has(rf"deviceconfig system ntp-servers {k}-ntp-server ntp-server-address \S+$")]
    if not servers:
        return bad("No NTP servers.")
    weak = [k for k in servers if not c.has(rf"deviceconfig system ntp-servers {k}-ntp-server authentication-type (symmetric-key|autokey)")]
    return bad("NTP without authentication: " + ", ".join(weak)) if weak else ok("NTP sources are authenticated")


@check("PANW-NM-000101", fix="set deviceconfig system timezone UTC")
def nm_timezone(c, x):
    tz = c.value(r"deviceconfig system timezone (\S+)$")
    return ok(f"timezone {tz}") if tz in ("UTC", "GMT", "Etc/UTC", "Etc/GMT", "UCT", "Universal", "Zulu") else bad(f"Use UTC or GMT (now {tz or 'not set'}).")


@check("PANW-NM-000118", fix="set deviceconfig system snmp-setting access-setting version v3")
def nm_snmp(c, x):
    if c.has(r"deviceconfig system snmp-setting access-setting version v2c") or c.has(r"(?:shared )?log-settings snmptrap \S+ version v2c"):
        return bad("SNMP v2c is configured.")
    return ok("SNMPv3 only") if c.has(r"deviceconfig system snmp-setting access-setting version v3") else \
        bad("Set SNMP to v3 (the factory default is v2c).")


@check("PANW-NM-000131", fix="set shared log-settings snmptrap <PROFILE> version v3 server <NAME> manager <IP>\n"
                            "set shared log-settings profiles default match-list THREAT log-type threat\n"
                            "set shared log-settings profiles default match-list THREAT send-snmptrap <PROFILE>")
def nm_alerts(c, x):
    sent = c.find(r"(?:shared )?log-settings profiles \S+ match-list \S+ send-(snmptrap|email|syslog) \S+$")
    threat = c.has(r"(?:shared )?log-settings profiles \S+ match-list \S+ log-type threat$")
    if not (sent and threat):
        return bad("No log forwarding profile sends threat logs to an alerting server.")
    return manual("Threat logs are forwarded; confirm the method (SNMP, e-mail or syslog) reaches the points of contact.")


@check("PANW-NM-000136", fix="set shared server-profile tacplus TACACS-SERVERS server TACACS-1 address <IP>\n"
                            "set shared authentication-profile REMOTE-ADMIN method tacplus server-profile TACACS-SERVERS\n"
                            "then select REMOTE-ADMIN under Device > Setup > Management > Authentication Settings")
def nm_central_auth(c, x):
    p = c.values(r"(?:shared )?authentication-profile (\S+) method (?:tacplus|radius|ldap|kerberos|saml-idp) ")
    return manual(f"{', '.join(sorted(set(p)))} uses a central server; confirm it is selected under Authentication Settings.") if p \
        else bad("No authentication profile uses a central authentication server.")


@check("PANW-NM-000142", fix="delete mgt-config password-profile <NAME>")
def nm_password_profiles(c, x):
    p = sorted({m[1] for m in c.find(r"mgt-config password-profile (\S+)")})
    return bad("Password profiles configured: " + ", ".join(p)) if p else ok("No password profiles")


@check("PANW-NM-000144", fix="set deviceconfig setting management enable-log-high-dp-load yes")
def nm_dp_load(c, x):
    return ok("Log on high DP load") if c.has(r"deviceconfig setting management enable-log-high-dp-load yes$") else bad("Log on High DP Load is off.")


def _local_users(c):
    remote = {m[1] for m in c.find(r"(?:shared )?authentication-profile (\S+) method (?!local-database)")}
    users = {m[1] for m in c.find(r"mgt-config users (\S+) ")}
    profile = {m[1]: m[2] for m in c.find(r"mgt-config users (\S+) authentication-profile (\S+)$")}
    return sorted(u for u in users if profile.get(u) not in remote)


@check("PANW-NM-000048", fix="delete mgt-config users <EXTRA-USER>")
def nm_one_local(c, x):
    u = _local_users(c)
    return ok(f"One local account: {u[0]}") if len(u) == 1 else bad(f"{len(u)} local accounts ({', '.join(u) or 'none'}); keep exactly one.")


@check("PANW-NM-000143", fix="delete mgt-config users admin (after creating your own superuser)")
def nm_default_admin(c, x):
    return manual("The default admin account exists; confirm its password was changed, or delete it.") if c.has(r"mgt-config users admin ") \
        else ok("No default admin account")


@check("PANW-NM-000096", "PANW-NM-000097")
def nm_alarms(c, x):
    return manual("Check Device > Log Settings > Alarms: alarms enabled, every log database threshold 75%.")


@check("PANW-NM-999999")
def nm_release(c, x):
    v = c.value(r"(?:deviceconfig system )?sw-version (\S+)")
    return manual(f"Running {v or 'an unknown release'}. Confirm with show system info that Palo Alto Networks still supports it.")


# ---------------------------------------------------------------- ALG / IDPS
TLS = r"^(rulebase decryption rules|global-protect|network ike|network tunnel ipsec)"


def _gate(what):
    def fn(c, x):
        return manual(f"{what} is configured; review this rule manually.") if any(re.match(TLS[1:], l) for l in c.lines) else \
            na("Not a TLS decryption point or VPN concentrator.")
    return fn


for _n in ("015", "016", "017", "020", "044", "078", "079", "101", "141", "143"):
    CHECKS[f"PANW-AG-000{_n}"] = (_gate("Decryption or VPN"), "")


@check("PANW-AG-000024", fix="set rulebase security rules <RULE> log-end yes\nset rulebase security rules <RULE> log-setting default")
def ag_log_denies(c, x):
    quiet = [n for n, f in c.rules.items() if f.get("action", ["allow"])[0] != "allow" and f.get("log-end") != ["yes"] and f.get("log-start") != ["yes"]]
    if c.value(r"rulebase default-security-rules rules interzone-default log-end (\S+)$") != "yes":
        quiet.append("interzone-default")
    return bad("Denies that aren't logged: " + ", ".join(quiet)) if quiet else ok("Every deny is logged")


@check("PANW-AG-000035", fix="delete zone <EXTERNAL-ZONE> enable-user-identification")
def ag_userid(c, x):
    ext = _ext(c, x)
    on = [z for z in ext if c.has(rf"zone {re.escape(z)} enable-user-identification yes$")]
    return bad("User-ID on untrusted zones: " + ", ".join(on)) if on else ok("User-ID is off on untrusted zones")


@check("PANW-AG-000036")
def ag_wmi(c, x):
    return bad("WMI probing is enabled.") if c.has(r".*enable-probing yes$") else ok("WMI probing is off")


@check("PANW-AG-000037", fix="delete network dns-proxy <NAME>")
def ag_dns_proxy(c, x):
    return bad("A DNS proxy is configured.") if c.has(r"network dns-proxy ") else ok("No DNS proxy")


def _zp(c, zone, opt):
    profs = c.values(rf"zone {re.escape(zone)} network zone-protection-profile (\S+)$")
    return any(c.has(rf"network profiles zone-protection-profile {re.escape(p)} {opt}") for p in profs)


def _zones_missing(c, zones, opt):
    return [z for z in zones if not _zp(c, z, opt)]


@check("PANW-AG-000047", "PANW-AG-000102", fix="set network profiles zone-protection-profile ONECONFIG-ZP flood tcp-syn enable yes\n"
                                               "(also udp, icmp, icmpv6, other-ip)\nset zone <ZONE> network zone-protection-profile ONECONFIG-ZP")
def ag_flood(c, x):
    if not c.zones:
        return bad("No layer 3 zones.")
    miss = [z for z in c.zones if not all(_zp(c, z, rf"flood {f} enable yes") for f in ("tcp-syn", "udp", "icmp", "other-ip"))]
    return bad("Zones without flood protection: " + ", ".join(miss)) if miss else ok("Flood protection on every zone")


@check("PANW-AG-000049", fix="set profiles spyware <PROFILE> botnet-domains lists default-paloalto-dns action sinkhole\n"
                            "and attach the profile (or a profile group with it) to the rules toward the internet")
def ag_phone_home(c, x):
    good = {m[1] for m in c.find(r"(?:shared )?profiles spyware (\S+) botnet-domains lists \S+ action (sinkhole|block)$")}
    ext = _ext(c, x)
    out = [n for n, f in _allow(c).items() if set(f.get("to", [])) & ext]
    weak = [n for n in out if not set(_rule_profiles(c, c.rules[n], "spyware")) & (good | {g for g in _groups(c, "spyware")
                                                                                         if any(c.has(rf"(?:shared )?profile-group {re.escape(g)} spyware {re.escape(p)}$") for p in good)})]
    if not good:
        return bad("No anti-spyware profile blocks or sinkholes malicious DNS.")
    return bad("Outbound rules without DNS sinkholing: " + ", ".join(weak)) if weak else ok("Outbound rules sinkhole malicious DNS")


@check("PANW-AG-000050", fix="set network profiles zone-protection-profile ONECONFIG-ZP discard-ip-spoof yes")
def ag_spoof(c, x):
    zones = [z for z in c.zones if z not in _ext(c, x)]
    miss = _zones_missing(c, zones, "discard-ip-spoof yes")
    return bad("No anti-spoofing on: " + ", ".join(miss)) if miss else ok("Spoofed sources dropped on internal zones") if zones else na("No internal zones.")


@check("PANW-IP-000030", fix="set network profiles zone-protection-profile ONECONFIG-ZP discard-icmp-error yes")
def ip_icmp_error(c, x):
    zones = [z for z in c.zones if z not in _ext(c, x)]
    miss = _zones_missing(c, zones, "discard-icmp-error yes")
    return bad("ICMP error messages not dropped on: " + ", ".join(miss)) if miss else ok("ICMP error messages dropped on internal zones") if zones else na("No internal zones.")


@check("PANW-AG-000051", fix="delete rulebase security rules <ALLOW-ALL-RULE>\nset rulebase default-security-rules rules interzone-default action deny")
def ag_default_deny(c, x):
    wide = [n for n, f in _allow(c).items() if all(f.get(k) == ["any"] for k in ("source", "destination", "application", "service"))]
    if c.value(r"rulebase default-security-rules rules interzone-default action (\S+)$", "deny") == "allow":
        wide.append("interzone-default")
    return bad("Rules that allow everything: " + ", ".join(wide)) if wide else ok("Deny by default, allow by exception")


@check("PANW-AG-000052", fix="Device > Setup > Session > Session Timeouts: TCP 900")
def ag_tcp_timeout(c, x):
    v = c.value(r"deviceconfig setting session timeout-tcp (\d+)$")
    return ok(f"TCP timeout {v}") if v and int(v) <= 900 else bad(f"TCP sessions must time out after 900 seconds (now {v or 'the default, 3600'}).")


@check("PANW-AG-000060", "PANW-AG-000065", "PANW-IP-000024", "PANW-IP-000029",
       fix="set deviceconfig system update-schedule threats recurring every-30-mins action download-and-install\n"
           "set deviceconfig system update-schedule anti-virus recurring hourly action download-and-install")
def ag_updates(c, x):
    miss = [k for k in ("threats", "anti-virus") if not c.has(rf"deviceconfig system update-schedule {k} recurring \S+ action download-and-install$")]
    return bad("Not installed automatically: " + ", ".join(miss)) if miss else ok("Threat and antivirus updates install automatically")


def _profiled(c, kind, test):
    """(profiles of this kind that pass test, allow rules that don't use one of them)."""
    good = {m[1] for m in c.find(rf"(?:shared )?profiles {kind} (\S+) ") if test(c.profile(kind, m[1]))}
    grp = {g for g in _groups(c, kind) if any(c.has(rf"(?:shared )?profile-group {re.escape(g)} {kind} {re.escape(p)}$") for p in good)}
    missing = [n for n, f in _allow(c).items() if not set(_rule_profiles(c, f, kind)) & (good | grp)]
    return good, missing


DECODERS = ("ftp", "http", "http2", "imap", "pop3", "smb", "smtp")


def _av_blocks(lines):
    acts = {m[1]: m[2] for l in lines if (m := re.search(r" decoder (\S+) action (\S+)$", l))}
    return all(acts.get(d) in ("reset-both", "reset-server", "reset-client", "drop") for d in DECODERS)


@check("PANW-AG-000062", "PANW-AG-000063", "PANW-AG-000073", "PANW-AG-000074", "PANW-IP-000020", "PANW-IP-000026",
       fix="set profiles virus ONECONFIG-AV decoder <DECODER> action reset-both (every decoder)\nset profile-group ONECONFIG virus ONECONFIG-AV")
def ag_antivirus(c, x):
    good, missing = _profiled(c, "virus", _av_blocks)
    if not good:
        return bad("No antivirus profile blocks malware on every decoder.")
    return bad("Allow rules without it: " + ", ".join(missing)) if missing else ok("Antivirus blocks malware on every allowed flow")


def _blocks_severe(lines):
    sev = {}
    for l in lines:
        m = re.search(r" rules (\S+) (action|severity) (\S+)$", l)
        if m:
            sev.setdefault(m[1], {}).setdefault(m[2], []).append(m[3])
    blocked = {s for r in sev.values() if (r.get("action") or [""])[0] in ("reset-both", "drop", "block-ip", "reset-server", "reset-client")
               for s in r.get("severity", [])}
    return {"critical", "high", "medium"} <= blocked or "any" in blocked


@check("PANW-AG-000080", "PANW-AG-000081", "PANW-AG-000105", "PANW-IP-000032", "PANW-IP-000033", "PANW-IP-000043",
       fix="set profiles vulnerability ONECONFIG-VP rules BLOCK-CRIT-HIGH-MED action reset-both\n"
           "set profiles vulnerability ONECONFIG-VP rules BLOCK-CRIT-HIGH-MED severity [ critical high medium ]\nset profile-group ONECONFIG vulnerability ONECONFIG-VP")
def ag_vulnerability(c, x):
    good, missing = _profiled(c, "vulnerability", _blocks_severe)
    if not good:
        return bad("No vulnerability protection profile blocks critical, high and medium threats.")
    return bad("Allow rules without it: " + ", ".join(missing)) if missing else ok("Vulnerability protection on every allowed flow")


@check("PANW-IP-000001", "PANW-AG-000115", "PANW-AG-000116", "PANW-IP-000049", "PANW-IP-000050", "PANW-AG-000147", "PANW-AG-000148", "PANW-AG-000149",
       fix="set profile-group ONECONFIG virus ONECONFIG-AV\nset profile-group ONECONFIG spyware ONECONFIG-AS\n"
           "set profile-group ONECONFIG vulnerability ONECONFIG-VP\nset rulebase security rules <RULE> profile-setting group ONECONFIG")
def ip_profiles(c, x):
    miss = [n for n, f in _allow(c).items() if not all(_rule_profiles(c, f, k) for k in ("virus", "spyware", "vulnerability"))]
    return bad("Allow rules without antivirus, anti-spyware and vulnerability profiles: " + ", ".join(miss)) if miss else \
        ok("Every allow rule inspects traffic") if _allow(c) else na("No allow rules.")


@check("PANW-IP-000008", fix="set profiles virus <AV> packet-capture yes\nset profiles spyware <AS> rules <RULE> packet-capture extended-capture\n"
                            "set profiles vulnerability <VP> rules <RULE> packet-capture extended-capture")
def ip_pcap(c, x):
    av = c.has(r"(?:shared )?profiles virus \S+ packet-capture yes$")
    ext = {k: c.has(rf"(?:shared )?profiles {k} \S+ rules \S+ packet-capture extended-capture$") for k in ("spyware", "vulnerability")}
    miss = (["antivirus packet capture"] if not av else []) + [f"{k} extended capture" for k, v in ext.items() if not v]
    return bad("Missing: " + ", ".join(miss)) if miss else ok("Malicious traffic is captured")


@check("PANW-IP-000018", "PANW-IP-000041", fix="set profiles dos-protection ONECONFIG-DOS type classified\nset profiles dos-protection ONECONFIG-DOS flood tcp-syn enable yes")
def ip_dos_profile(c, x):
    p = sorted({m[1] for m in c.find(r"(?:shared )?profiles dos-protection (\S+) ")})
    return ok("DoS protection profile " + ", ".join(p)) if p else bad("No DoS protection profile.")


@check("PANW-AG-000127", "PANW-IP-000031", fix="set rulebase security rules BLOCK-ICMP-PROBES from <EXTERNAL> to [ <INTERNAL> <DMZ> ] "
                                               "application [ icmp ipv6-icmp traceroute ] action deny")
def ag_icmp_probes(c, x):
    ext = _ext(c, x)
    for n, f in c.rules.items():
        if f.get("action", [""])[0] in ("deny", "drop", "reset-both") and set(f.get("from", [])) & ext and \
                {"icmp", "ipv6-icmp", "traceroute"} <= set(f.get("application", [])):
            return ok(f"{n} blocks ICMP probes and traceroute from untrusted zones")
    return bad("No rule denies icmp, ipv6-icmp and traceroute from untrusted zones.") if ext else na("No external zones.")


@check("PANW-AG-000111", "PANW-IP-000045", fix="Device > Server Profiles > NetFlow: add a profile, then set it as the Netflow Profile on monitored interfaces")
def ag_netflow(c, x):
    used = c.find(r"network interface .* netflow-profile (\S+)$")
    return ok("NetFlow export on " + ", ".join(sorted({m[1] for m in used}))) if used else bad("No interface exports NetFlow to the IDS.")


@check("PANW-AG-000064", "PANW-AG-000114", "PANW-AG-000118", "PANW-AG-000119", "PANW-AG-000120", "PANW-AG-000122",
       "PANW-IP-000028", "PANW-IP-000048", "PANW-IP-000051", "PANW-IP-000052", "PANW-IP-000053", "PANW-IP-000056",
       fix="Log forwarding profile with a threat match list that sends to e-mail, SNMP or syslog, used by every allow rule")
def ag_threat_alerts(c, x):
    return nm_alerts(c, x)


@check("PANW-IP-000010")
def ip_logdb(c, x):
    return manual("Confirm Device > Setup > Management > Logging and Reporting: Stop Traffic when LogDb Full is cleared (the default).")


@check("PANW-AG-000121", "PANW-IP-000055")
def ag_dos_alerts(c, x):
    return manual("Confirm a DoS protection policy (or zone protection) sends its logs through a log forwarding profile.")


MANUAL_WHY.update({
    "PANW-NM-000075": "Confirm no person holds more than one administrator account or role.",
    "PANW-NM-000110": "Confirm DoD CA certificates and a certificate profile for CAC/PIV login (Device > Certificate Management).",
    "PANW-NM-000141": "Confirm the device certificate comes from the DoD PKI or a DoD-approved PKI.",
    "PANW-AG-000038": "Confirm the security rules allow only the applications, ports and protocols in the PPSM CAL.",
    "PANW-AG-000107": "Confirm inbound rules allow only organization-approved sources and destinations.",
    "PANW-AG-000109": "Confirm User-ID maps users on trusted zones so prohibited activity is logged by user.",
    **{k: "Needs the list of prohibited network services from the ISSM; add deny rules that log them."
       for k in ("PANW-AG-000112", "PANW-AG-000113", "PANW-IP-000046", "PANW-IP-000047")},
})
for _bid in ("PAN_NDM", "PAN_ALG", "PAN_IDPS"):
    for _r in BENCH[_bid]["rules"]:
        MANUAL_WHY.setdefault(_r[0], "Depends on organization policy or the web interface; review manually.")
