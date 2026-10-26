"""DISA STIG checks for Fortinet FortiGate (FortiGate Firewall NDM V1R6, Firewall V1R5). DISA writes many FortiGate
checks as web-interface steps; each check here reads the same setting from the CLI configuration. Settings left at
their default are only listed by `show full-configuration`, so audit that output: a rule is only marked Not a finding
when the configuration shows the setting."""
import re
from functools import cached_property
from .stig import BENCH, Lines, bad, manual, na, ok

CHECKS, MANUAL_WHY = {}, {}


def check(*ids, fix=""):
    def deco(fn):
        for i in ids:
            CHECKS[i] = (fn, fix)
        return fn
    return deco


def flatten(text: str) -> list[str]:
    """FortiOS `config` / `edit` / `set` blocks as one line per value: `firewall policy 1 srcintf INSIDE`.
    Parsed by diff.fos_tree, so the push plan and the checks read a config the same way."""
    from .diff import fos_tree
    out = []

    def walk(node, path):
        for f, (vals, _) in node["sets"].items():
            vals = vals or [""]
            if f in ("password", "key", "secret", "auth-pwd", "priv-pwd", "key-string", "passwd") and vals[0] == "ENC":
                vals = ["ENC " + " ".join(vals[1:])]
            out.extend(" ".join(path + [f, v]).strip() for v in vals)
        for name, sub in node["subs"].items():
            walk(sub, path + name.split())
        for k, e in (node["entries"] or {}).items():
            walk(e, path + [k])
    walk(fos_tree(text), [])
    return out


class Fos(Lines):
    def __init__(self, text: str):
        self.text = text
        self.lines = flatten(text)

    def table(self, path):
        """Entries of a table: key -> {field: [values]}, in config order."""
        out = {}
        for m in self.find(rf"{re.escape(path)} (\S+) (\S+) ?(.*)$"):
            out.setdefault(m[1], {}).setdefault(m[2], []).append(m[3])
        return out

    def num(self, pat, default=None):
        v = self.value(pat)
        return int(v) if v and v.isdigit() else default

    @cached_property
    def policies(self):
        return self.table("firewall policy")

    @cached_property
    def interfaces(self):
        return self.table("system interface")

    @cached_property
    def zones(self):
        """zone -> member interfaces."""
        return {z: f.get("interface", []) for z, f in self.table("system zone").items()}


def _ext(c, x):
    """External zones or interfaces: those holding interfaces marked external (OneConfig's own configs), else
    interfaces with the WAN role or the default route's device."""
    if x.get("generated") or x.get("external"):
        ext = set(x.get("external") or [])
    else:
        dev = {d for f in c.table("router static").values() if f.get("dst", ["0.0.0.0", "0.0.0.0"]) == ["0.0.0.0", "0.0.0.0"]
               for d in f.get("device", [])}
        ext = {i for i, f in c.interfaces.items() if f.get("role") == ["wan"]} | dev
    return ext | {z for z, ifs in c.zones.items() if set(ifs) & ext}


def _offload(c):
    """Enabled remote log destinations: (kind, server)."""
    out = []
    for kind in ("syslogd", "syslogd2", "syslogd3", "syslogd4", "fortianalyzer", "fortianalyzer2", "fortianalyzer3"):
        if c.has(rf"log {kind} setting status enable$"):
            out.append((kind, c.value(rf"log {kind} setting server (\S+)$", "?")))
    return out


# ---------------------------------------------------------------- NDM
def _events(*cats):
    def fn(c, x):
        off = [k for k in cats if not c.has(rf"log eventfilter {k} enable$")]
        return bad("Event logging not enabled for: " + ", ".join(off) + ".") if off else ok("Event logging on: " + ", ".join(cats))
    return fn


for _i in ("005", "020", "040", "060", "065", "070", "075", "080", "085", "090"):
    CHECKS[f"FGFW-ND-000{_i}"] = (_events("event", "system"), "config log eventfilter\n    set event enable\n    set system enable\nend")
CHECKS["FGFW-ND-000010"] = (_events("event", "system", "user"), "config log eventfilter\n    set event enable\n    set system enable\n    set user enable\nend")


def _local_admins(c):
    return [a for a, f in c.table("system admin").items() if f.get("remote-auth") != ["enable"]]


@check("FGFW-ND-000030", fix="config system admin\n    delete <EXTRA-LOCAL-ADMIN>\nend")
def nd_one_local(c, x):
    u = _local_admins(c)
    return ok(f"One local account: {u[0]}") if len(u) == 1 else bad(f"{len(u)} local administrator accounts ({', '.join(u) or 'none'}); keep exactly one.")


@check("FGFW-ND-000045", fix="config system global\n    set admin-lockout-threshold 3\n    set admin-lockout-duration 900\nend")
def nd_lockout(c, x):
    t, d = c.num(r"system global admin-lockout-threshold (\d+)$"), c.num(r"system global admin-lockout-duration (\d+)$")
    if t is None or not 1 <= t <= 3:
        return bad(f"Lockout threshold is {t if t is not None else 'not set'}; it must be at most 3.")
    if d is None or d < 900:
        return bad(f"Lockout lasts {d if d is not None else 'an unset number of'} seconds; DISA's fix uses 900.")
    return ok(f"Locked out for {d} s after {t} failures")


@check("FGFW-ND-000050", "FGFW-ND-000055", fix='config system global\n    set pre-login-banner enable\nend\n'
       'config system replacemsg admin "pre_admin-disclaimer-text"\n    set buffer "<DoD Notice and Consent Banner>"\nend')
def nd_banner(c, x):
    if not c.has(r"system global pre-login-banner enable$"):
        return bad("The pre-login banner is off.")
    text = " ".join(c.values(r"system replacemsg admin pre_admin-disclaimer-text buffer (.*)$"))
    if "USG-authorized use only" in text and "See User Agreement for details" in text:
        return ok("Standard Mandatory DoD Notice and Consent Banner, shown before login")
    return bad("The pre-login banner is on, but its text is not the Standard Mandatory DoD Notice and Consent Banner.")


@check("FGFW-ND-000095", fix="config log setting\n    set user-anonymize disable\nend")
def nd_anonymize(c, x):
    return ok("Logs keep user identities") if c.has(r"log setting user-anonymize disable$") else bad("Log user anonymization is not disabled.")


@check("FGFW-ND-000100", fix="config system global\n    set cli-audit-log enable\nend")
def nd_cli_audit(c, x):
    return ok("CLI commands are logged") if c.has(r"system global cli-audit-log enable$") else bad("CLI audit logging is off.")


@check("FGFW-ND-000105", fix="config log disk setting\n    set status enable\n    set diskfull overwrite\n    set max-log-file-size 100\nend")
def nd_log_storage(c, x):
    if not c.has(r"log disk setting status enable$"):
        return bad("Disk logging is off.")
    size = c.num(r"log disk setting max-log-file-size (\d+)$")
    return ok(f"Disk logging, {size} MB log files") if size else bad("No log file size is set for disk logging.")


@check("FGFW-ND-000110", "FGFW-ND-000295", "FNFG-FW-000100",
       fix="config log syslogd setting\n    set status enable\n    set server <SYSLOG-SERVER>\n    set mode reliable\nend")
def nd_offload(c, x):
    dest = _offload(c)
    return ok("Logs sent to " + ", ".join(f"{s} ({k})" for k, s in dest)) if dest else bad("No syslog server or FortiAnalyzer receives the logs.")


@check("FGFW-ND-000115", "FNFG-FW-000105", fix="Security Fabric > Automation: a stitch on log-server and log-disk failures with an Email action "
       "to the SA and ISSO (needs your mail server and addresses)")
def nd_alert_stitch(c, x):
    email = [k for k, f in c.table("system automation-action").items() if f.get("action-type") == ["email"]]
    stitches = c.table("system automation-stitch")
    if email and stitches:
        return manual("Automation stitches with e-mail actions exist; confirm they trigger on audit and log-server failures.")
    return bad("No automation stitch e-mails the SA and ISSO when logging fails.")


@check("FGFW-ND-000120", fix="config system ntp\n    set ntpsync enable\n    set type custom\n    config ntpserver\n"
       "        edit 1\n            set server <NTP-1>\n        next\n        edit 2\n            set server <NTP-2>\n        next\n    end\nend")
def nd_ntp(c, x):
    servers = c.values(r"system ntp ntpserver \S+ server (\S+)$")
    if not (c.has(r"system ntp ntpsync enable$") and c.has(r"system ntp type custom$")):
        return bad("NTP is not synchronizing to your own servers.")
    return ok("NTP servers: " + ", ".join(servers)) if len(servers) >= 2 else bad(f"{len(servers)} NTP server; DISA requires redundant sources.")


@check("FGFW-ND-000215", fix="config system ntp\n    config ntpserver\n        edit <ID>\n            set authentication enable\n"
       "            set key-id 1\n            set key <NTP-KEY>\n        next\n    end\nend")
def nd_ntp_auth(c, x):
    servers = c.table("system ntp ntpserver")
    weak = [f.get("server", [k])[0] for k, f in servers.items() if f.get("authentication") != ["enable"]]
    if not servers:
        return bad("No NTP servers are configured.")
    return bad("NTP servers without authentication: " + ", ".join(weak)) if weak else ok("Every NTP server is authenticated")


@check("FGFW-ND-000165", fix="config user ldap\n    edit <LDAP>\n        set server <LDAP-SERVER>\n        set secure ldaps\n    next\nend\n"
       "config system admin\n    edit <REMOTE-ADMIN>\n        set remote-auth enable\n        set remote-group <GROUP>\n    next\nend")
def nd_ldap(c, x):
    remote = [a for a, f in c.table("system admin").items() if f.get("remote-auth") == ["enable"]]
    if not remote:
        return bad("No administrator authenticates against a central server.")
    if c.table("user ldap"):
        return ok("Administrators authenticate through LDAP")
    return manual("Administrators authenticate through TACACS+ or RADIUS. DISA's rule names LDAP; confirm with your ISSM.")


@check("FGFW-ND-000245", fix="config user ldap\n    edit <LDAP>\n        set secure ldaps\n    next\nend")
def nd_ldaps(c, x):
    ldap = c.table("user ldap")
    if not ldap:
        return na("No LDAP servers are configured.")
    plain = [k for k, f in ldap.items() if f.get("secure") != ["ldaps"]]
    return bad("LDAP without LDAPS: " + ", ".join(plain)) if plain else ok("Every LDAP server uses LDAPS")


@check("FGFW-ND-000170")
def nd_release(c, x):
    m = re.search(r"^#config-version=[^-\s]+-(\d+\.\d+\.\d+)", c.text, re.M)
    v = m[1] if m else None
    return manual(f"Confirm with get system status that Fortinet still supports {'FortiOS ' + v if v else 'this FortiOS release'}.")


@check("FGFW-ND-000180", "FGFW-ND-000185", fix="config system global\n    set revision-backup-on-logout enable\nend")
def nd_backup(c, x):
    return ok("A configuration revision is saved at each logout") if c.has(r"system global revision-backup-on-logout enable$") \
        else bad("Configuration revisions are not saved on logout.")


_FWD = ("dhcp-relay-service", "pptp-client", "arpforward", "broadcast-forward", "l2forward", "icmp-send-redirect", "vlanforward",
        "stpforward", "lldp-transmission")


@check("FGFW-ND-000200", "FNFG-FW-000065", fix="config system interface\n    edit <INTERFACE>\n        unset allowaccess (or: set allowaccess ping https ssh)\n"
       + "".join(f"        set {o} disable\n" for o in _FWD) + "    next\nend")
def nd_services(c, x):
    problems = []
    for name, f in c.interfaces.items():
        if f.get("type") == ["loopback"]:
            continue
        insecure = sorted(set(f.get("allowaccess", [])) & {"http", "telnet"})
        on = [o for o in _FWD if f.get(o) == ["enable"]]
        if insecure or on:
            problems.append(f"{name}: {', '.join(insecure + on)}")
    return bad("Unneeded or cleartext services: " + "; ".join(problems)) if problems else ok("No cleartext management or unneeded forwarding")


@check("FGFW-ND-000205", fix="config system global\n    set admin-https-ssl-versions tlsv1-2 tlsv1-3\n    set ssl-min-proto-version TLSv1-2\n"
       "    set admin-ssh-v1 disable\nend")
def nd_tls(c, x):
    versions = set(c.values(r"system global admin-https-ssl-versions (\S+)$"))
    if not versions or versions - {"tlsv1-2", "tlsv1-3"}:
        return bad(f"Admin HTTPS allows {', '.join(sorted(versions)) or 'the default TLS versions'}; allow only TLS 1.2 and 1.3.")
    if not c.has(r"system global admin-ssh-v1 disable$"):
        return bad("SSH version 1 is not disabled.")
    return ok("Admin access over TLS 1.2/1.3 and SSHv2 only")


@check("FGFW-ND-000210", fix="config system snmp user\n    edit <SNMP-USER>\n        set security-level auth-priv\n        set auth-proto sha256\n    next\nend\n"
       "config system snmp community\n    delete <ID>\nend")
def nd_snmp(c, x):
    if c.table("system snmp community"):
        return bad("SNMPv1/v2c communities are configured.")
    users = c.table("system snmp user")
    if not users:
        return na("SNMP is not configured.")
    weak = [u for u, f in users.items() if f.get("auth-proto", ["sha"])[0] not in ("sha256", "sha384", "sha512")
            or f.get("security-level", ["no-auth-no-priv"])[0] == "no-auth-no-priv"]
    return bad("SNMPv3 users without SHA-2 authentication: " + ", ".join(weak)) if weak else ok("SNMPv3 with SHA-2 authentication")


_PW = {"FGFW-ND-000220": ("minimum-length", 15, "a minimum length of 15"), "FGFW-ND-000225": ("min-upper-case-letter", 1, "an uppercase letter"),
       "FGFW-ND-000230": ("min-lower-case-letter", 1, "a lowercase letter"), "FGFW-ND-000235": ("min-number", 1, "a number"),
       "FGFW-ND-000240": ("min-non-alphanumeric", 1, "a special character")}


def _pw(field, least, what):
    def fn(c, x):
        if not (c.has(r"system password-policy status enable$") and c.has(r"system password-policy apply-to admin-password$")):
            return bad("The administrator password policy is not enabled.")
        n = c.num(rf"system password-policy {field} (\d+)$", 0)
        return ok(f"{field} {n}") if n >= least else bad(f"Passwords don't require {what} ({field} {n}).")
    return fn


for _id, (_f, _n, _w) in _PW.items():
    CHECKS[_id] = (_pw(_f, _n, _w), f"config system password-policy\n    set status enable\n    set apply-to admin-password\n    set {_f} {_n}\nend")


@check("FGFW-ND-000311", fix="config system password-policy\n    set min-change-characters 8\nend\n"
       "(FortiOS 7.0 to 7.6.2; later releases have no CLI setting for it, so record a risk acceptance)")
def nd_pw_change(c, x):
    if c.has(r"system password-policy change-8-characters enable$") or c.num(r"system password-policy min-change-characters (\d+)$", 0) >= 8:
        return ok("A new password must change at least 8 characters")
    return bad("Passwords don't have to change 8 characters.")


@check("FGFW-ND-000250", fix="config system admin\n    delete admin\nend (after creating your own super_admin account)")
def nd_default_admin(c, x):
    return manual("The default admin account exists; confirm its password was changed, or delete it.") if "admin" in c.table("system admin") \
        else ok("No default admin account")


@check("FGFW-ND-000255", "FGFW-ND-000280", fix="config system fips-cc\n    set status enable\nend\n"
       "Enabling FIPS-CC mode reboots the FortiGate and resets its configuration: plan it with console access.")
def nd_fips(c, x):
    return ok("FIPS-CC mode") if c.has(r"system fips-cc status enable$") else bad("FIPS-CC mode is not enabled.")


@check("FGFW-ND-000260", "FGFW-ND-000265", fix="config system interface\n    edit <INTERFACE>\n        set allowaccess ping https ssh\n    next\nend")
def nd_mgmt_crypto(c, x):
    plain = [n for n, f in c.interfaces.items() if set(f.get("allowaccess", [])) & {"http", "telnet"}]
    return bad("Cleartext management on: " + ", ".join(plain)) if plain else ok("Management only over HTTPS and SSH")


@check("FGFW-ND-000270", "FGFW-ND-000275", fix="config system global\n    set admintimeout 10\nend")
def nd_idle(c, x):
    t = c.num(r"system global admintimeout (\d+)$")
    return ok(f"Idle sessions end after {t} minutes") if t and t <= 10 else bad(f"Idle timeout is {t or 'not set'}; it must be 10 minutes or less.")


def _dos(c):
    """interface or zone -> anomalies blocked by an enabled DoS policy."""
    out = {}
    for k, f in c.table("firewall DoS-policy").items():
        if f.get("status") == ["disable"]:
            continue
        blocked = {m[1] for m in c.find(rf"firewall DoS-policy {re.escape(k)} anomaly (\S+) action block$")}
        enabled = {m[1] for m in c.find(rf"firewall DoS-policy {re.escape(k)} anomaly (\S+) status enable$")}
        for i in f.get("interface", []):
            out.setdefault(i, set()).update(blocked & enabled)
    return out


def _dos_rule(need, what):
    def fn(c, x):
        dos = _dos(c)
        if not dos:
            return bad("No DoS policy blocks anomalies.")
        used = {i for f in c.policies.values() for i in f.get("srcintf", [])}
        bare = sorted(i for i in used if not need <= dos.get(i, set()))
        return bad(f"No DoS policy blocking {what} on: " + ", ".join(bare)) if bare else ok(f"{what.capitalize()} blocked on every ingress")
    return fn


_DOS_FIX = ('config firewall DoS-policy\n    edit <ID>\n        set interface <ZONE>\n        set srcaddr "all"\n        set dstaddr "all"\n'
            '        set service "ALL"\n        config anomaly\n            edit "tcp_syn_flood"\n                set status enable\n'
            '                set action block\n            next\n        end\n    next\nend')
CHECKS["FGFW-ND-000290"] = (_dos_rule({"tcp_syn_flood"}, "SYN floods"), _DOS_FIX)
CHECKS["FNFG-FW-000070"] = (_dos_rule({"tcp_syn_flood", "udp_flood", "icmp_flood"}, "floods"), _DOS_FIX)
CHECKS["FNFG-FW-000075"] = (_dos_rule({"tcp_syn_flood", "udp_flood", "icmp_flood"}, "floods"), _DOS_FIX)
CHECKS["FNFG-FW-000110"] = (_dos_rule({"tcp_syn_flood", "udp_flood", "icmp_flood", "tcp_port_scan", "udp_scan", "icmp_sweep"},
                                      "floods, scans and sweeps"), _DOS_FIX)


@check("FGFW-ND-000300", fix="config system global\n    set admin-concurrent disable\nend")
def nd_concurrent(c, x):
    return ok("Concurrent sessions per administrator are blocked") if c.has(r"system global admin-concurrent disable$") \
        else bad("An administrator can log in from several places at once.")


# ---------------------------------------------------------------- Firewall
@check("FNFG-FW-000005", fix="config firewall policy\n    edit <ID>\n        set srcaddr <SOURCES>\n        set dstaddr <DESTINATIONS>\n"
       "        set service <SERVICES>\n    next\nend")
def fw_filters(c, x):
    if not c.policies:
        return bad("No firewall policies are configured.")
    wide = [f.get("name", [k])[0] for k, f in c.policies.items() if f.get("action") == ["accept"] and f.get("srcaddr") == ["all"]
            and f.get("dstaddr") == ["all"] and f.get("service") == ["ALL"]]
    return bad("Policies accept everything: " + ", ".join(wide)) if wide else ok("Every accept policy names addresses or services")


@check("FNFG-FW-000020", "FNFG-FW-000025", "FNFG-FW-000030", "FNFG-FW-000035", "FNFG-FW-000040",
       fix="config firewall policy\n    edit <ID>\n        set logtraffic all\n    next\nend\nconfig log eventfilter\n    set event enable\nend")
def fw_traffic_log(c, x):
    quiet = [f.get("name", [k])[0] for k, f in c.policies.items() if f.get("logtraffic") != ["all"]]
    if quiet:
        return bad("Policies that don't log all sessions: " + ", ".join(quiet))
    return ok("Every policy logs all sessions") if c.has(r"log eventfilter event enable$") else bad("Event logging is off.")


@check("FNFG-FW-000045", fix="config log disk setting\n    set status enable\n    set diskfull overwrite\nend")
def fw_queue(c, x):
    if not _offload(c):
        return bad("No remote log server is configured.")
    if c.has(r"log disk setting status enable$") and c.has(r"log disk setting diskfull overwrite$"):
        return ok("Logs are kept on disk while the log server is unreachable")
    return bad("Disk logging (overwrite when full) is not on, so logs are lost while the log server is unreachable.")


@check("FNFG-FW-000050", "FNFG-FW-000150", fix="config log syslogd setting\n    set mode reliable\n    set enc-algorithm high\n    set port 6514\nend")
def fw_syslog_tls(c, x):
    syslog = [k for k, _ in _offload(c) if k.startswith("syslogd")]
    if not syslog:
        return manual("Logs go to FortiAnalyzer only; confirm its connection is reliable and encrypted.") if _offload(c) \
            else bad("No remote log server is configured.")
    weak = [k for k in syslog if not (c.has(rf"log {k} setting mode reliable$") and c.value(rf"log {k} setting enc-algorithm (\S+)$") in ("high", "high-medium"))]
    return bad("Syslog without reliable TLS: " + ", ".join(weak)) if weak else ok("Syslog over reliable TLS")


@check("FNFG-FW-000090", fix="config ips global\n    set fail-open disable\nend\nconfig system global\n    set av-failopen off\n"
       "    set av-failopen-session disable\nend")
def fw_fail_closed(c, x):
    miss = [what for what, pat in (("IPS fail-open", r"ips global fail-open disable$"), ("AV fail-open", r"system global av-failopen off$"),
                                   ("AV session fail-open", r"system global av-failopen-session disable$")) if not c.has(pat)]
    return bad("Not failing closed: " + ", ".join(miss)) if miss else ok("Inspection fails closed")


def _ingress(internal):
    def fn(c, x):
        ext = _ext(c, x)
        zones = set(c.zones) or {i for i, f in c.interfaces.items() if f.get("ip")}
        want = sorted((zones - ext) if internal else (zones & ext))
        if not want:
            return na("No internal interfaces." if internal else "No external interfaces.")
        src = {i for f in c.policies.values() for i in f.get("srcintf", [])}
        miss = [z for z in want if z not in src]
        return bad("No policy filters traffic entering from: " + ", ".join(miss)) if miss else ok("Policies filter traffic from " + ", ".join(want))
    return fn


CHECKS["FNFG-FW-000115"] = (_ingress(False), "config firewall policy\n    edit <ID>\n        set srcintf <EXTERNAL>\n        ...\n    next\nend")
CHECKS["FNFG-FW-000120"] = (_ingress(True), "config firewall policy\n    edit <ID>\n        set srcintf <INTERNAL>\n        ...\n    next\nend")


@check("FNFG-FW-000015", "FNFG-FW-000130")
def fw_vpn(c, x):
    vpn = c.table("vpn ipsec phase1-interface") or c.table("vpn ipsec phase1") or c.has(r"vpn ssl settings status enable$")
    return manual("A VPN is configured; review its policies manually.") if vpn else na("No VPN is configured.")


@check("FNFG-FW-000125")
def fw_premise_mgmt(c, x):
    if not _ext(c, x):
        return na("Not a premise firewall (no external interface).")
    return manual("Confirm deny policies stop traffic from the management network leaving through the external interfaces.")


@check("FNFG-FW-000135")
def fw_helpers(c, x):
    names = set(c.values(r"system session-helper \S+ name (\S+)$"))
    return ok(f"{len(names)} session helpers inspect application protocols") if names \
        else manual("Session helpers are not in this configuration; check show full-configuration system session-helper.")


@check("FNFG-FW-000145", fix="config system settings\n    set asymroute disable\n    set asymroute-icmp disable\n    set asymroute6 disable\nend")
def fw_asym(c, x):
    on = [k for k in ("asymroute", "asymroute-icmp", "asymroute6") if not c.has(rf"system settings {k} disable$")]
    return bad("Asymmetric routing not disabled: " + ", ".join(on)) if on else ok("Asymmetric routing is off")


@check("FNFG-FW-000160", "FNFG-FW-000165", fix="config log setting\n    set fwpolicy-implicit-log enable\nend\n"
       "config firewall policy\n    edit <ID>\n        set logtraffic all\n    next\nend")
def fw_deny_log(c, x):
    if not c.has(r"log setting fwpolicy-implicit-log enable$"):
        return bad("Traffic denied by the implicit deny policy is not logged.")
    quiet = [f.get("name", [k])[0] for k, f in c.policies.items() if f.get("logtraffic") != ["all"]]
    return bad("Policies that don't log all sessions: " + ", ".join(quiet)) if quiet else ok("Denied traffic is logged")


MANUAL_WHY.update({
    "FGFW-ND-000035": "Confirm only ISSM-approved people or roles hold super_admin.",
    "FGFW-ND-000125": "Open a log entry and confirm its time zone maps to GMT.",
    "FGFW-ND-000175": "Confirm the event and traffic log settings match your locally developed list of auditable events.",
    "FGFW-ND-000190": "Confirm administrator profiles limit maintenance functions (sysgrp) to authorized people.",
    "FGFW-ND-000195": "Confirm certificates come from DoD-approved certificate authorities.",
    "FGFW-ND-000285": "Confirm only authorized administrators have profiles that can change the configuration.",
    "FGFW-ND-000305": "Confirm firmware is installed only from Fortinet-signed images.",
    "FNFG-FW-000085": "Confirm the policies allow only the traffic in the PPSM CAL and vulnerability assessments.",
    "FNFG-FW-000155": "Confirm only authorized administrators can run packet captures.",
})
for _bid in ("FORTI_NDM", "FORTI_FW"):
    for _r in BENCH[_bid]["rules"]:
        MANUAL_WHY.setdefault(_r[0], "Depends on organization policy or the web interface; review manually.")
