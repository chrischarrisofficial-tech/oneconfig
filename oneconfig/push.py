"""Safe config push for Cisco IOS-XE (and NX-OS, Arista EOS, Juniper Junos; see APPLY). Cisco ASA: plan only (PLAN_ONLY).

1. plan_device: read the running config, diff it against OneConfig's candidate, and flag anything that
   could lock you out before a single command is sent.
2. apply_device: back up (local file + on-device archive), then apply inside IOS-XE's Configuration
   Rollback Confirmed Change (`configure terminal revert timer`). The device undoes the change by itself
   if OneConfig loses contact. OneConfig then logs in again on a fresh session and compares health
   counters. Only if everything checks out does it send `configure confirm` (and optionally write memory).
   Otherwise it sends `configure revert now`.
3. rollback_device: put back the pre-change archive with `configure replace`."""
import hashlib
import re
import threading
import time
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path

from .diff import asa_plan, fos_plan, fos_removal, fos_tree, junos_plan, pan_plan
from .diff import plan as diff_plan
from .diff import snmp_users, tree
from .render import render

PLACEHOLDER = re.compile(r"<([A-Z0-9][A-Z0-9.-]*)>")
IDENTIFIERS = {"ADMIN-USER", "SNMP-USER", "BACKUP-USER"}  # placeholders that name things rather than hide them
MIN_SECRET = 8  # shorter values can't be masked reliably in the plan (and every STIG wants longer ones)
BACKUPS = Path.home() / ".oneconfig" / "backups"
RETRIES, RETRY_WAIT = 12, 20  # FortiOS rollback reboots the firewall: up to 4 minutes to log in again
FOS_DISARM = ["config system global", "set cfg-save automatic", "end"]  # FortiOS saves revert mode, so it survives a reboot
ERROR = re.compile(r"^[ \t]*(% ?(Invalid|Incomplete|Ambiguous|Unknown|Error|Bad )|error:|syntax error|unknown command|missing argument)", re.I | re.M)
HASHED = {".SHA512": "sha512_crypt", ".SHA256": "sha256_crypt"}  # <NAME.SHA512>: the crypt hash of NAME's value (Junos; .SHA256 PAN-OS)
# A value goes into a config line as typed. A newline would add commands, ? opens the CLI's help, and a space, quote
# or backslash ends or breaks the line on IOS, NX-OS, EOS, ASA, Junos and PAN-OS. FortiOS takes every value in double
# quotes and fill() escapes quotes and backslashes there, so it only refuses control characters and ?.
BAD_VALUE = re.compile(r"[^\x21-\x7e]|[?\"'\\]")
BAD_VALUE_QUOTED = re.compile(r"[^\x20-\x7e]|\?")
BAD_VALUE_HELP = "spaces, quotes, backslashes, ? or characters outside printable ASCII"


def bad_values(values: dict, names, nos: str = "") -> list[str]:
    """Names whose value can't go into this OS's config line safely."""
    rx = BAD_VALUE_QUOTED if nos == "fortios" else BAD_VALUE
    return [n for n in names if values.get(n) and rx.search(values[n])]


class PushError(Exception):
    pass


def _config_lines(text: str) -> str:  # comments aren't sent (OneConfig writes ## comments on Junos, : on ASA)
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(("!", "##", ":")))


def placeholders(text: str) -> list[str]:
    return sorted({re.sub(r"\.SHA(512|256)$", "", p) for p in PLACEHOLDER.findall(_config_lines(text))})


def fill(text: str, values: dict, nos: str = "") -> str:
    from . import junos
    text = _config_lines(text)
    missing = [p for p in placeholders(text) if not values.get(p)]
    if missing:
        raise PushError("Missing values for: " + ", ".join(missing))
    if bad := bad_values(values, placeholders(text), nos):
        raise PushError(f"These values can't contain {BAD_VALUE_HELP}: " + ", ".join(bad))
    # FortiOS takes every value inside double quotes, so a quote or backslash in a secret must be escaped
    esc = (lambda v: v.replace("\\", "\\\\").replace('"', '\\"')) if nos == "fortios" else (lambda v: v)

    def one(m):
        suffix = m[1][-7:]
        return getattr(junos, HASHED[suffix])(values[m[1][:-7]]) if suffix in HASHED else esc(values[m[1]])
    return PLACEHOLDER.sub(one, text)


def mask(lines: list[str], values: dict) -> list[str]:
    """Show secrets as <NAME> again, so they never reach the browser."""
    forms = lambda v: {v, v.replace("\\", "\\\\").replace('"', '\\"')}  # noqa: E731  as typed, and as fill() escapes it for FortiOS
    secrets = sorted(((f, k) for k, v in values.items() if k not in IDENTIFIERS and v for f in forms(v)), key=lambda x: -len(x[0]))
    out = []
    for line in lines:
        for v, k in secrets:
            line = line.replace(v, f"<{k}>")
        out.append(re.sub(r'(encrypted-password|phash) "\$[^"]+"', r'\1 "<HASHED>"', line))
    return out


def shown_removal(line: str) -> str:
    """A running-config line as the browser may see it: secrets scrubbed, plus a fingerprint when something was."""
    from .ai import mask as scrub
    out = scrub(line)
    return out if out == line else f"{out}  (#{hashlib.sha256(line.encode()).hexdigest()[:6]})"


DEVICE_TYPE = {"ios-xe": "cisco_ios", "nx-os": "cisco_nxos", "eos": "arista_eos", "junos": "juniper_junos", "asa": "cisco_asa", "panos": "paloalto_panos", "fortios": "fortinet"}  # netmiko drivers
PLAN_ONLY = {"asa": "Cisco ASA has no automatic rollback (no commit-confirm or revert timer), so OneConfig plans the change but does not push it. Apply the plan yourself in a maintenance window, with console access to both units."}
SHOW_RUN = {"junos": "show configuration | display set", "panos": "show config running", "fortios": "show full-configuration"}
FORTI_ERROR = re.compile(r"^.*(Command fail|command parse error|value parse error|entry not found|Unknown action|node_check_object fail|"
                         r"Attribute '\S+' MUST be set|not found in datasource).*$", re.M | re.I)  # every other OS: show running-config


def connect(ip, login: dict, port=22, timeout=20, nos="ios-xe"):
    from netmiko import ConnectHandler

    from .discover import FORTI_KEX, ssh_host_keys
    c = ConnectHandler(device_type=DEVICE_TYPE[nos], host=str(ip), port=port, username=login["username"],
                       password=login["password"], secret=login.get("secret") or "", conn_timeout=timeout,
                       auth_timeout=timeout, banner_timeout=timeout, fast_cli=False, **ssh_host_keys(ip, port, timeout, learned := []),
                       **({"disabled_algorithms": FORTI_KEX} if nos == "fortios" else {}))
    c.oneconfig_first_contact = bool(learned)  # this connection trusted a host key it had never seen
    if nos == "panos":
        c.send_command("set cli config-output-format set")  # show config running prints set lines, like the plan
    elif login.get("secret") and not c.check_enable_mode():
        c.enable()
    return c


def _connect(ip, login, nos="ios-xe"):
    return globals()["connect"](ip, login, nos=nos)  # looked up at call time so tests can swap it


# Lines that change on every read: IOS change stamps, NX-OS / EOS print the current time, FortiOS shows who's logged in
_VOLATILE = re.compile(r"^(! Last configuration change|! NVRAM config last updated|!Time:|! Time:|!Running configuration last done at:|#config-version=).*$", re.M)


def _sha(text: str) -> str:
    """Fingerprint of a running config, blind to what changes between two reads of the same config."""
    text = re.sub(r"\bENC \S+", "ENC", _VOLATILE.sub("", text))  # FortiOS re-encrypts every stored secret each time it shows them
    return hashlib.sha256(text.encode()).hexdigest()


def _local_ip(c):
    try:
        return c.remote_conn.get_transport().sock.getsockname()[0]
    except Exception:  # serial or unusual transports
        return None


def health(c, nos="ios-xe") -> dict:
    """Counters that must not drop because of a change."""
    from .discover import NTC, _parse
    run = lambda cmd: _parse(cmd, c.send_command(cmd), NTC[nos])  # noqa: E731
    if nos == "fortios":
        bgp = c.send_command("get router info bgp summary")
        return {"interfaces up": len(re.findall(r"^[ \t]*status:\s*up\b", c.send_command("get system interface physical"), re.M)),
                "OSPF neighbors": len(re.findall(r"\sFull/", c.send_command("get router info ospf neighbor"))),
                "BGP sessions": len(re.findall(r"^\d+\.\d+\.\d+\.\d+\s+4\s+.*\s\d+\s*$", bgp, re.M))}  # a prefix count = Established
    if nos == "panos":
        ifs = run("show interface all")
        ospf = c.send_command("show routing protocol ospf neighbor")
        return {"interfaces up": sum(r.get("state") == "up" for r in ifs),
                "OSPF neighbors": len(re.findall(r"^[ \t]*status:\s+full", ospf, re.M | re.I)),
                "BGP sessions": sum(1 for r in run("show routing protocol bgp summary") if r.get("accepted_pfx", "") != "")}
    if nos == "junos":
        terse = c.send_command("show interfaces terse")
        return {"interfaces up": len(re.findall(r"^\S+\s+up\s+up\b", terse, re.M)),
                "OSPF neighbors": sum(r.get("state", "").lower() == "full" for r in run("show ospf neighbor")),
                "BGP sessions": sum(r.get("state", "").lower().startswith("establ") for r in run("show bgp summary"))}
    up, ospf, bgp = run("show ip interface brief"), run("show ip ospf neighbor"), run("show ip bgp summary")
    is_up = (lambda r: r.get("proto", "") == "protocol-up") if nos == "nx-os" else \
        (lambda r: r.get("status", "").lower() == "up" and (r.get("proto") or r.get("protocol") or "").lower() == "up")
    return {"interfaces up": sum(map(is_up, up)),
            "OSPF neighbors": sum(r.get("state", "").upper().startswith("FULL") for r in ospf),
            "BGP sessions": sum(str(r.get("state_or_prefixes_received") or r.get("state_pfxrcd") or "").isdigit()
                                for r in bgp)}  # a prefix count = Established


def _asa_warnings(cand, running):
    """Changes that cut through an ASA's references or its failover pair."""
    nameif = lambda t: dict(re.findall(r"^interface (\S+)\n(?: .*\n)*? nameif (\S+)", t + "\n", re.M))  # noqa: E731
    have, want = nameif(running), nameif(cand)
    out = [f"{i}: nameif {have[i]} becomes {z}. The ASA deletes every command that names {have[i]} (routes, access-groups, NAT, "
           "ssh, logging), so add them back in the same session." for i, z in want.items() if i in have and have[i] != z]
    if re.search(r"^failover", cand, re.M) and re.findall(r"^failover.*$", cand, re.M) != re.findall(r"^failover.*$", running, re.M):
        out.append("Changes failover settings. Make them on the active unit with the standby reachable from the console; "
                   "a wrong failover key or link splits the pair.")
    return out


def _fos_warnings(running, add):
    run = fos_tree(running)
    out = ["FortiOS rolls back by rebooting. OneConfig applies the change as one transaction under the revert timer "
           "(cfg-save revert), logs in again and checks health, then saves. If health drops or the session is lost, the "
           "firewall reboots to its saved configuration (an HA pair reboots both units); OneConfig then logs in again and "
           "turns revert mode off. If it can't, set cfg-save automatic under config system global yourself."]
    nat = run["subs"].get("system settings", {}).get("sets", {}).get("central-nat", (["disable"], ""))[0]
    vips = set((run["subs"].get("firewall vip") or {}).get("entries") or {})
    pols = (run["subs"].get("firewall policy") or {}).get("entries") or {}
    if nat != ["enable"] and any(e["sets"].get("nat", ([], ""))[0] == ["enable"] or set(e["sets"].get("dstaddr", ([], ""))[0]) & vips
                                 for e in pols.values()):
        out.append("This firewall uses policy NAT; OneConfig turns on central NAT. Existing policies stop translating "
                   "by themselves, and policies that name a virtual IP must be removed first, or the commit fails and nothing changes.")
    if "config system ha" in add:
        out.append("Changes HA (FGCP) settings. A different group name or password splits the pair; change both units together.")
    return out


def _fos_blockers(cand, running):
    t, run = fos_tree(cand), fos_tree(running)
    services = set((run["subs"].get("firewall service custom") or {}).get("entries") or {})
    taken = sorted(set((t["subs"].get("firewall service group") or {}).get("entries") or {}) & services)
    return [f"This FortiGate already has a service named {', '.join(taken)} (FortiGates come with predefined services), "
            "so a service group can't use that name. Rename the group."] if taken else []


def latest_archive(show_archive: str):
    m = re.search(r"^[ \t]*\d+\s+(\S+)\s+<- Most Recent", show_archive or "", re.M)
    return m.group(1) if m else None


def plan_device(dev, net, login: dict, values: dict) -> dict:
    """Read-only: nothing is changed on the device."""
    if not dev.mgmt_ip:
        return {"hostname": dev.hostname, "blockers": ["No management IP. Set it on the General tab or run Discover."]}
    cand, nos = fill(render(dev, net), values, dev.platform), dev.platform
    with _connect(dev.mgmt_ip, login, nos) as c:
        running = c.send_command(SHOW_RUN.get(nos, "show running-config"), read_timeout=120)
        users = snmp_users(c.send_command("show snmp user")) if nos == "ios-xe" else set()  # NX-OS/EOS list them in the config
        status = c.send_command("get system status") if nos == "fortios" else ""
        me = _local_ip(c)
        first = getattr(c, "oneconfig_first_contact", False)
    contact = [f"First contact with {dev.mgmt_ip}: OneConfig trusted and saved its SSH host key, so from now on an impostor "
               "is refused. Check this really is the device you meant before pushing."] if first else []
    fwarn = []
    if nos == "fortios" and re.search(r"^Log hard disk: Not available", status, re.M):  # small models log to memory only
        cand = re.sub(r"^config log disk setting\n.*?^end\n", "", cand, flags=re.M | re.S)
        fwarn.append("This model has no log disk, so OneConfig leaves out disk logging: logs wait in memory only while the "
                     "log server is unreachable (STIG FNFG-FW-000045 stays open).")
    p = fos_plan(cand, running, login_user=login["username"]) if nos == "fortios" else \
        junos_plan(cand, running, login_user=login["username"]) if nos == "junos" else \
        asa_plan(cand, running, login_user=login["username"]) if nos == "asa" else \
        pan_plan(cand, running, login_user=login["username"]) if nos == "panos" else \
        diff_plan(cand, running, login_user=login["username"], known_snmp_users=users)
    blockers, warnings = [], contact + ([PLAN_ONLY[nos]] if nos in PLAN_ONLY else [])
    if nos == "asa":
        warnings += _asa_warnings(cand, running)
    s = net.security
    if nos == "nx-os" and (copp := [x for x in p["add"] if x.startswith("copp profile ")]):
        p["add"] = [x for x in p["add"] if x not in copp]  # NX-OS asks "Proceed (y/n)?" for this one
        warnings.append(f"Set CoPP by hand (it asks for confirmation and briefly disrupts control traffic): {copp[0]}")
    if s.mgmt_subnet and re.search(r"(access-class|ip access-group) MGMT-ACCESS in|source-prefix-list MGMT-NET|set trusthost1 ", cand) and me:
        try:
            outside = ip_address(me) not in ip_network(str(s.mgmt_subnet))
        except ValueError:
            outside = False
        if outside:
            blockers.append(f"This computer ({me}) is outside the management subnet {s.mgmt_subnet}. After the push it "
                            "could not log in again. Run OneConfig from inside that subnet or change the subnet.")
    vlan1 = tree(running).find("interface Vlan1")
    if re.search(r"^interface Vlan1$", cand, re.M) and vlan1 and any(x.line.startswith("ip address ") for x in vlan1.children):
        blockers.append("This switch has an IP address on Vlan1, and the STIG config shuts Vlan1 down. If you manage it "
                        "through Vlan1, the push would cut you off. Move management to another VLAN first.")
    if login["username"] != values.get("ADMIN-USER") and not (s.tacacs_servers or s.radius_servers):
        warnings.append(f"You're logged in as '{login['username']}', but OneConfig's local account is "
                        f"'{values.get('ADMIN-USER')}'. Make sure '{login['username']}' still works after the push.")
    if any(re.match(r"\s*(no )?ip route ", x) for x in p["add"] + p["remove"]):
        warnings.append("This changes static routes. If the management path depends on them, the device rolls back by itself.")
    if any(x.startswith("aaa new-model") for x in p["add"]):
        warnings.append("Turns on AAA. Logins will use TACACS+/RADIUS first, then the local account.")
    if nos == "junos" and "authentication keychain OSPF-KEYS" in cand:
        warnings.append("Junos OSPF key chains (HMAC-SHA-1) need Junos 23.4R1 or later; on older releases the commit fails and nothing changes.")
    if nos == "fortios":
        warnings += fwarn + _fos_warnings(running, p["add"])
        blockers += _fos_blockers(cand, running)
    if nos == "panos":
        warnings.append("PAN-OS has no commit-confirm timer. OneConfig saves a named snapshot, commits, logs in again and checks "
                        "health, and loads the snapshot back if anything got worse. If the session is lost after the commit, "
                        "restore the snapshot yourself (load config from <snapshot>, then commit).")
    if nos == "nx-os":
        warnings.append("NX-OS: OneConfig applies the change, captures it to bootflash, rolls back, then re-applies it with "
                        "configure replace … commit-timeout. For those few seconds the change is live without a timer.")
    return {"hostname": dev.hostname, "os": nos, "ip": str(dev.mgmt_ip), "running_sha": _sha(running), "add": p["add"],
            "remove": p["remove"], "add_shown": mask(p["add"], values), "remove_shown": [shown_removal(x) for x in p["remove"]],
            "archive": bool(re.search(r"^archive\n(?: .*\n)*? path ", running, re.M)),
            "blockers": blockers, "warnings": warnings, "candidate": cand, "plan_only": nos in PLAN_ONLY}


def _errors(output: str) -> list[str]:
    return [line.strip() for line in output.splitlines() if ERROR.match(line)]


def _ios_apply(c, cmds, host, planned, minutes, log):
    """IOS-XE: archive snapshot, then Configuration Rollback Confirmed Change (revert timer)."""
    if not planned.get("archive"):
        out = c.send_config_set(["archive", " path flash:oneconfig-archive", " maximum 14"], cmd_verify=False)
        if _errors(out):
            raise PushError("Could not set up the config archive: " + "; ".join(_errors(out)))
        log(f"{host}: configured archive path flash:oneconfig-archive (needed for rollback)")
    out = c.send_command("archive config")
    snapshot = latest_archive(c.send_command("show archive"))
    if _errors(out) or not snapshot:
        raise PushError("Could not take an archive snapshot, so a safe rollback isn't possible. Nothing was changed.")
    log(f"{host}: snapshot {snapshot}")
    c.config_mode(config_command=f"configure terminal revert timer {int(minutes)}")
    log(f"{host}: entered configure terminal revert timer {minutes}. The device will undo the change by itself unless OneConfig confirms it")
    try:
        out = c.send_config_set(cmds, enter_config_mode=False, exit_config_mode=True, cmd_verify=False, read_timeout=180)
    except Exception as e:
        raise PushError(f"Connection dropped while applying ({type(e).__name__}). The device will roll itself back within {minutes} minutes.")

    def revert(why):
        c.send_command("configure revert now", expect_string=r"#", read_timeout=60)
        return f"{why} The change was rolled back."
    return snapshot, out, "configure confirm", revert


def _eos_apply(c, cmds, host, planned, minutes, log):
    """EOS: a configuration session committed with a timer. The switch rolls it back unless it is confirmed."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapshot, session = f"flash:oneconfig-{stamp}.cfg", f"oneconfig-{stamp}"
    out = c.send_command(f"copy running-config {snapshot}")
    if _errors(out):
        raise PushError("Could not save a snapshot to flash, so a safe rollback isn't possible. Nothing was changed: " + "; ".join(_errors(out)))
    log(f"{host}: snapshot {snapshot}")
    c.config_mode(config_command=f"configure session {session}")
    try:
        out = c.send_config_set(cmds, enter_config_mode=False, exit_config_mode=False, cmd_verify=False, read_timeout=180)
    except Exception as e:
        raise PushError(f"Connection dropped before the commit ({type(e).__name__}). Nothing was changed; the uncommitted session expires on its own.")
    if _errors(out):
        c.send_command("abort", expect_string=r"#")  # still inside the session: nothing was applied
        raise PushError("The switch rejected: " + "; ".join(_errors(out)[:5]) + ". Nothing was changed (the session was aborted).")
    out += c.send_command(f"commit timer 00:{int(minutes):02d}:00", expect_string=r"#")
    log(f"{host}: committed session {session} with a {minutes} minute timer. The switch will roll it back unless OneConfig confirms it")

    def revert(why):
        r = c.send_command(f"configure session {session} abort", expect_string=r"#")
        if _errors(r) or re.search(r"^[ \t]*%", r, re.M):  # any % reply means the abort didn't happen
            return f"{why} The switch rolls the change back by itself when the {minutes} minute commit timer ends."
        return f"{why} The change was rolled back."
    return snapshot, out, f"configure session {session} commit", revert


def _nxos_apply(c, cmds, host, planned, minutes, log):
    """NX-OS has a commit timer only for configure replace, which needs a complete config file. So the switch
    builds that file itself: checkpoint, apply, copy running-config to bootflash, roll back to the checkpoint,
    then configure replace with commit-timeout."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapshot, target, secs = f"oneconfig-pre-{stamp}", f"bootflash:oneconfig-target-{stamp}.cfg", max(30, min(3600, int(minutes) * 60))
    out = c.send_command(f"checkpoint {snapshot}", read_timeout=120)
    if _errors(out):
        raise PushError("Could not create a checkpoint, so a safe rollback isn't possible. Nothing was changed: " + "; ".join(_errors(out)))
    log(f"{host}: checkpoint {snapshot}")
    try:
        out = c.send_config_set(cmds, cmd_verify=False, read_timeout=180)
    except Exception as e:
        raise PushError(f"Connection dropped while applying ({type(e).__name__}). Roll back from the console with: "
                        f"rollback running-config checkpoint {snapshot}")
    back = lambda: c.send_command(f"rollback running-config checkpoint {snapshot}", read_timeout=300)  # noqa: E731
    if _errors(out):
        r = back()
        raise PushError("The switch rejected: " + "; ".join(_errors(out)[:5]) + "." +
                        (" The change was rolled back." if "successful" in r.lower() else f" Roll back with: rollback running-config checkpoint {snapshot}"))
    for cmd in (f"copy running-config {target}", None):
        r = c.send_command(cmd, read_timeout=120) if cmd else back()
        if _errors(r) or (cmd is None and "successful" not in r.lower()):
            back()
            raise PushError(f"Could not prepare the timed replace ({(_errors(r) or [r.strip()[-120:]])[0]}). The change was rolled back.")
    log(f"{host}: captured the new config to {target} and rolled back; re-applying it with a {secs} s commit timeout")
    out = c.send_command(f"configure replace {target} verbose commit-timeout {secs}", read_timeout=600)
    if _errors(out) or re.search(r"\bfail", out, re.I):
        raise PushError("configure replace failed: " + ((_errors(out) or [out.strip()[-200:]])[0]) +
                        ". The switch keeps or restores its previous config; check show config-replace log verify.")

    def revert(why):
        return f"{why} The switch rolls the change back by itself when the {secs} s commit timeout ends."
    return snapshot, out, "configure replace commit", revert


KEEP = 3  # OneConfig snapshots kept on the device, newest first (IOS-XE: archive maximum does this)
# per OS: (list command, what OneConfig created, delete command, how many to keep). Names hold a timestamp,
# so sorting puts the newest last. The NX-OS replace target is only needed during a push, so none are kept.
TIDY = {"eos": [("dir flash:", r"oneconfig-\d{8}-\d{6}\.cfg", "delete flash:{}", KEEP)],
        "junos": [("file list /var/tmp/", r"oneconfig-\d{8}-\d{6}\.conf", "file delete /var/tmp/{}", KEEP)],
        "nx-os": [("show checkpoint summary", r"oneconfig-pre-\d{8}-\d{6}", "no checkpoint {}", KEEP),
                  ("dir bootflash:", r"oneconfig-target-\d{8}-\d{6}\.cfg", "delete bootflash:{} no-prompt", 0)]}


def _tidy(c, nos, log):
    """Delete older OneConfig snapshots so checkpoints and flash don't fill up. Best-effort: the push already succeeded."""
    for show, rx, rm, keep in TIDY.get(nos, ()):
        try:
            names = sorted(set(re.findall(rx, c.send_command(show, read_timeout=60))))
            for n in names[:len(names) - keep]:
                r = c.send_command(rm.format(n), read_timeout=60)
                log(f"{n}: could not delete ({_errors(r)[0]})" if _errors(r) else f"deleted old snapshot {n}")
        except Exception as e:
            log(f"cleanup skipped ({type(e).__name__}); delete old oneconfig-* files by hand if space runs low")


def _junos_apply(c, cmds, host, planned, minutes, log):
    """Junos: save the configuration to /var/tmp, load the change in an exclusive session, `commit check`, then
    `commit confirmed N`. Junos rolls back by itself unless OneConfig commits again within N minutes."""
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    snapshot = f"/var/tmp/oneconfig-{stamp}.conf"
    out = c.send_command(f"show configuration | save {snapshot}")
    if _errors(out) or "Wrote" not in out:
        raise PushError("Could not save a snapshot to /var/tmp, so a safe rollback isn't possible. Nothing was changed: " + out.strip()[-160:])
    log(f"{host}: snapshot {snapshot}")
    c.config_mode(config_command="configure exclusive")

    def discard(why):
        c.send_command("rollback 0")
        c.exit_config_mode()
        raise PushError(why + " Nothing was changed (the uncommitted change was discarded).")
    try:
        out = c.send_config_set(cmds, enter_config_mode=False, exit_config_mode=False, cmd_verify=False, read_timeout=180)
    except Exception as e:
        raise PushError(f"Connection dropped before the commit ({type(e).__name__}). Nothing was changed; Junos drops uncommitted changes.")
    if _errors(out):
        discard("The device rejected: " + "; ".join(_errors(out)[:5]) + ".")
    chk = c.send_command("commit check", read_timeout=300)
    if _errors(chk) or "succeeds" not in chk:
        discard("commit check failed: " + "; ".join(_errors(chk)[:5] or [chk.strip()[-200:]]) + ".")
    out += c.send_command(f'commit confirmed {int(minutes)} comment "oneconfig"', read_timeout=300)
    if "commit complete" not in out:
        discard("commit confirmed failed: " + "; ".join(_errors(out)[:5] or [out.strip()[-200:]]) + ".")
    log(f"{host}: committed with commit confirmed {minutes}. Junos rolls it back unless OneConfig confirms it")

    def revert(why):
        r = c.send_command("rollback 1") + c.send_command('commit comment "oneconfig revert"', read_timeout=300)
        if _errors(r) or "commit complete" not in r:
            return f"{why} Junos rolls the change back by itself when the {minutes} minute commit confirmed timer ends."
        return f"{why} The change was rolled back."
    return snapshot, out, 'commit comment "oneconfig confirmed"', revert


def _panos_apply(c, cmds, host, planned, minutes, log):
    """PAN-OS: refuse if someone else has uncommitted changes, save a named snapshot, load the change into the
    candidate, commit. A rejected line or failed commit reverts the candidate, so nothing changes. PAN-OS has no
    commit-confirm timer: the revert loads the snapshot and commits."""
    snapshot = f"oneconfig-{datetime.now():%Y%m%d-%H%M%S}.xml"
    c.config_mode()
    diff = c.send_command("show config diff", read_timeout=120)
    if re.search(r"^[+-]", diff, re.M):
        c.exit_config_mode()
        raise PushError("The firewall has uncommitted changes from someone else (show config diff). Nothing was changed.")
    out = c.send_command(f"save config to {snapshot}", read_timeout=120)
    if "saved" not in out.lower():
        c.exit_config_mode()
        raise PushError("Could not save a snapshot, so a safe rollback isn't possible. Nothing was changed: " + out.strip()[-160:])
    log(f"{host}: snapshot {snapshot}")

    def discard(why):
        c.send_command("revert config", read_timeout=120)
        c.exit_config_mode()
        raise PushError(why + " Nothing was changed (the candidate was reverted).")
    try:
        out = c.send_config_set(cmds, enter_config_mode=False, exit_config_mode=False, cmd_verify=False, read_timeout=180)
    except Exception as e:
        raise PushError(f"Connection dropped before the commit ({type(e).__name__}). Nothing was committed, but the candidate "
                        "may hold part of the change: log in and run `revert config` before pushing again.")
    bad = re.findall(r"^.*(?:Invalid syntax|Unknown command|Server error|is not a valid).*$", out, re.M | re.I) or _errors(out)
    if bad:
        discard("The firewall rejected: " + "; ".join(x.strip() for x in bad[:5]) + ".")
    try:
        out += c.commit(read_timeout=600)
    except ValueError as e:
        c.config_mode()
        discard("The commit failed: " + str(e).strip()[-300:])
    log(f"{host}: committed")

    def revert(why):
        c.config_mode()
        r = c.send_command(f"load config from {snapshot}", read_timeout=120)
        try:
            c.commit(read_timeout=600)
        except ValueError:
            return f"{why} The rollback commit failed; restore {snapshot} yourself (load config from {snapshot}, then commit)."
        return f"{why} The change was rolled back." if "loaded" in r.lower() else f"{why} Restore {snapshot} yourself (load config from {snapshot}, then commit)."
    return snapshot, out, None, revert


def _fortios_apply(c, cmds, host, planned, minutes, log):
    """FortiOS: a named flash revision, then the change as one transaction committed under the revert timer. The
    firewall reboots to its saved configuration unless OneConfig saves the change (execute cfg save)."""
    stamp, secs = datetime.now().strftime("%Y%m%d-%H%M%S"), max(60, int(minutes) * 60)
    lines = [y for x in cmds for y in (fos_removal(x) if x.startswith("delete ") else [x])]
    errors = lambda out: [m[0].strip() for m in FORTI_ERROR.finditer(out)]  # noqa: E731
    out = c.send_command(f'execute backup config flash "oneconfig-{stamp}"', read_timeout=120)
    rev = re.search(rf"^[ \t]*(\d+)\s.*oneconfig-{stamp}", c.send_command("execute revision list config", read_timeout=60), re.M)
    if errors(out) or not rev:
        raise PushError("Could not save a configuration revision to flash, so a safe rollback isn't possible. Nothing was changed.")
    snapshot = rev[1]
    log(f"{host}: saved revision {snapshot} (oneconfig-{stamp})")
    disarm = FOS_DISARM
    out = c.send_config_set(["config system global", "set cfg-save revert", f"set cfg-revert-timeout {secs}", "end"], cmd_verify=False)
    if errors(out):
        raise PushError("Could not arm the revert timer: " + "; ".join(errors(out)[:3]) + ". Nothing was changed.")
    out = c.send_command(f"execute config-transaction start {int(minutes) + 5}")
    if errors(out):
        c.send_config_set(disarm, cmd_verify=False)
        raise PushError("Could not start a configuration transaction (FortiOS 6.2 or later): " + "; ".join(errors(out)[:3]) + ". Nothing was changed.")
    try:
        out = c.send_config_set(lines, cmd_verify=False, read_timeout=300)
    except Exception as e:
        raise PushError(f"Connection dropped before the commit ({type(e).__name__}). Nothing was committed: the transaction "
                        "expires by itself. Then set cfg-save automatic under config system global.")

    def discard(why):
        c.send_command("execute config-transaction abort")
        c.send_config_set(disarm, cmd_verify=False)
        raise PushError(why + " Nothing was changed (the transaction was aborted).")
    if errors(out):
        discard("The firewall rejected: " + "; ".join(errors(out)[:5]) + ".")
    r = c.send_command("execute config-transaction commit", read_timeout=300)
    if errors(r):
        discard("The commit failed: " + "; ".join(errors(r)[:5]) + ".")
    log(f"{host}: committed under a {secs} second revert timer. The firewall reboots to its saved configuration unless OneConfig saves it")

    def confirm():
        r = c.send_command("execute cfg save", read_timeout=120)
        c.send_config_set(disarm, cmd_verify=False)
        return r

    def revert(why):
        r = c.send_command_timing("execute cfg reload", read_timeout=60)
        r += c.send_command_timing("y", read_timeout=60) if "(y/n)" in r else ""
        revert.rebooting = "(y/n)" in r and not FORTI_ERROR.search(r)  # read by _apply_device's fail()
        if not revert.rebooting:
            return (f"{why} execute cfg reload didn't run ({' '.join(r.split())[-120:]}), so the change is still live until the "
                    f"{secs} second revert timer reboots the firewall. Then set cfg-save automatic under config system global.")
        return f"{why} The firewall is rebooting to its saved configuration, which undoes the change."
    return snapshot, out + r, confirm, revert


APPLY = {"fortios": _fortios_apply, "ios-xe": _ios_apply, "eos": _eos_apply, "nx-os": _nxos_apply, "junos": _junos_apply, "panos": _panos_apply}


def _apply_device(planned: dict, values: dict, login: dict, removals=(), save=True, revert_minutes=5,
                 allow_health_drop=False, force=False, log=print) -> dict:
    host, ip, nos = planned["hostname"], planned.get("ip"), planned.get("os", "ios-xe")
    if nos in PLAN_ONLY:
        raise PushError(PLAN_ONLY[nos])
    if planned.get("blockers") and not force:
        raise PushError("Blocked: " + " ".join(planned["blockers"]))
    cmds = planned["add"] + [x for x in planned["remove"] if x in set(removals)]  # only removals the user ticked
    if not cmds:
        log(f"{host}: already matches. Nothing to push.")
        return {"hostname": host, "status": "unchanged"}
    # the push may set a new local password for the account we log in with: verify with what the device will expect
    after_login = dict(login)
    if login["username"] == values.get("ADMIN-USER") and values.get("ADMIN-SECRET") and \
            any(x.startswith((f"username {login['username']} ", f"set system login user {login['username']} ",
                              f"set shared local-user-database user {login['username']} ")) for x in cmds):
        after_login["password"] = values["ADMIN-SECRET"]
    if nos == "fortios" and login["username"] == values.get("ADMIN-USER") and values.get("ADMIN-SECRET") and \
            re.search(rf'^config system admin\n(?:    .*\n)*?    edit "{re.escape(login["username"])}"\n(?:        .*\n)*?        set password ', "\n".join(cmds) + "\n", re.M):
        after_login["password"] = values["ADMIN-SECRET"]
    if values.get("ENABLE-SECRET") and any(x.startswith("enable ") for x in cmds):
        after_login["secret"] = values["ENABLE-SECRET"]

    c = _connect(ip, login, nos)
    snapshot, revert = None, None

    def fail(why):
        try:
            msg = revert(why)
        except Exception:  # we may have lost the session; the device's own timer still protects it (not on PAN-OS)
            msg = (f"{why} OneConfig lost the session, and PAN-OS has no rollback timer: restore {snapshot} (load config from "
                   f"{snapshot}, then commit)." if nos == "panos" else
                   f"{why} OneConfig lost the session, so the firewall reboots to its saved configuration within {revert_minutes} "
                   "minutes (the revert timer)." if nos == "fortios" else
                   f"{why} OneConfig lost the session, so the device will roll itself back within {revert_minutes} minutes.")
        else:
            if nos == "fortios" and getattr(revert, "rebooting", False):  # it reboots into its saved config, which still has revert mode on
                def disarm(c2):  # only once the change is gone: on a firewall still running it, cfg-save automatic would save it
                    # shortcut: a push that only removed things leaves nothing to look for, so it gets the manual note
                    if not fos_plan(planned["candidate"], c2.send_command(SHOW_RUN[nos], read_timeout=120), login_user=login["username"])["add"]:
                        return False
                    c2.send_config_set(FOS_DISARM, cmd_verify=False)
                    return True
                back = _login_again(ip, (login, after_login), nos, disarm)
                msg += (" It came back, and OneConfig turned revert mode off (cfg-save automatic)." if back else
                        " Once it's back, set cfg-save automatic under config system global.")
        log(f"{host}: {msg}")
        raise PushError(msg)

    try:
        running = c.send_command(SHOW_RUN.get(nos, "show running-config"), read_timeout=120)
        if _sha(running) != planned["running_sha"]:
            raise PushError("The running config changed after the plan was made. Plan again.")
        from .seal import seal
        from . import private
        data, encrypted = seal(running, encrypted_before=any(BACKUPS.glob("*.enc")) if BACKUPS.is_dir() else False)
        backup = private.write(BACKUPS / f"{host}-{datetime.now():%Y%m%d-%H%M%S}.cfg{'.enc' if encrypted else ''}", data)
        log(f"{host}: saved a{'n encrypted' if encrypted else ''} backup of the running config to {backup}" +
            ("" if encrypted else " (no OS keychain here, so it isn't encrypted; the folder is private to your account)"))
        before = health(c, nos)
        log(f"{host}: health before: {before}")
        snapshot, out, confirm, revert = APPLY[nos](c, cmds, host, planned, revert_minutes, log)
        if _errors(out):
            fail("The device rejected: " + "; ".join(_errors(out)[:5]) + ".")
        log(f"{host}: applied {len(cmds)} lines")
        try:
            c2 = _connect(ip, after_login, nos)
        except Exception as e:
            fail(f"Could not log in again on a new session ({type(e).__name__}).")
        with c2:
            after = health(c2, nos)
            new_running = c2.send_command(SHOW_RUN.get(nos, "show running-config"), read_timeout=120)
            users = snmp_users(c2.send_command("show snmp user")) if nos == "ios-xe" else set()
        log(f"{host}: health after: {after}")
        drops = {k: f"{before[k]} -> {after[k]}" for k in before if after[k] < before[k]}
        if drops and not allow_health_drop:
            fail("Health got worse: " + ", ".join(f"{k} {v}" for k, v in drops.items()) + ".")
        left = (fos_plan(planned["candidate"], new_running, login_user=login["username"]) if nos == "fortios" else
                junos_plan(planned["candidate"], new_running, login_user=login["username"]) if nos == "junos" else
                pan_plan(planned["candidate"], new_running, login_user=login["username"]) if nos == "panos" else
                diff_plan(planned["candidate"], new_running, login_user=login["username"], known_snmp_users=users))["add"]
        if callable(confirm):  # FortiOS: execute cfg save, then turn the revert timer off
            r = confirm()
            if FORTI_ERROR.search(r):
                fail("execute cfg save failed: " + r.strip()[-160:])
            log(f"{host}: confirmed the change (execute cfg save, cfg-save automatic)")
        elif confirm:  # PAN-OS: the commit already made it permanent
            r = c.send_command(confirm, read_timeout=120) if nos == "junos" else c.send_command(confirm, expect_string=r"#", read_timeout=120)
            if _errors(r) or (nos == "junos" and "commit complete" not in r):
                fail(f"{confirm} failed: " + "; ".join(_errors(r) or [r.strip()[-160:]]) + ".")
            if nos == "junos":
                c.exit_config_mode()
            log(f"{host}: confirmed the change ({confirm})")
        _tidy(c, nos, lambda m: log(f"{host}: {m}"))
        if save and nos not in ("junos", "panos", "fortios"):  # a Junos or PAN-OS commit is already persistent; FortiOS saved above
            c.save_config()
            log(f"{host}: saved to startup-config")
        return {"hostname": host, "status": "pushed", "os": nos, "snapshot": snapshot, "backup": str(backup), "lines": len(cmds),
                "health": {"before": before, "after": after}, "not_applied": mask(left, values), "login": after_login}
    except PushError:
        raise
    except Exception as e:  # anything unexpected: say whether the device is protected
        state = "after the change was applied, so the device will roll itself back" if revert else "before any change was made"
        raise PushError(f"{type(e).__name__}: {str(e)[:200]} (happened {state}).")
    finally:
        try:
            c.disconnect()
        except Exception:
            pass


ROLLBACK = {"ios-xe": ("configure replace {s} force", r"Rollback Done"),
            "eos": ("configure replace {s}", None),
            "nx-os": ("rollback running-config checkpoint {s}", r"successful"),
            "junos": ("load override {s}", r"commit complete"),  # inside configure exclusive, then commit
            "panos": ("load config from {s}", r"committed successfully"),  # inside configure, then commit
            "fortios": ("execute restore config flash {s}", None)}  # the firewall reboots with that revision


def _rollback_device(ip, login: dict, snapshot: str, save=True, log=print, fallback_login=None, nos="ios-xe") -> dict:
    """Restore a pre-change snapshot. The restore can also restore old passwords, so the follow-up login
    tries the current credentials and then the ones used before the push."""
    cmd, ok_text = ROLLBACK[nos]
    with _connect(ip, login, nos) as c:
        if nos == "junos":
            c.config_mode(config_command="configure exclusive")
            out = c.send_command(cmd.format(s=snapshot), read_timeout=300) + c.send_command('commit comment "oneconfig rollback"', read_timeout=300)
            c.exit_config_mode()
        elif nos == "panos":
            c.config_mode()
            out = c.send_command(cmd.format(s=snapshot), read_timeout=300)
            if "loaded" not in out.lower():  # don't commit (and report success) when the snapshot didn't load
                raise PushError(f"{cmd.format(s=snapshot)} failed: " + out.strip()[-200:])
            try:
                out += c.commit(read_timeout=600)
            except ValueError as e:
                out += str(e)
        elif nos == "fortios":
            out = c.send_command_timing(cmd.format(s=snapshot), read_timeout=120)
            if "(y/n)" in out:
                out += c.send_command_timing("y", read_timeout=120)
            if FORTI_ERROR.search(out):
                raise PushError(f"{cmd.format(s=snapshot)} failed: " + out.strip()[-200:])
        else:
            out = c.send_command(cmd.format(s=snapshot), read_timeout=300)
        if _errors(out) or (ok_text and not re.search(ok_text, out, re.I)):
            raise PushError(f"{cmd.format(s=snapshot)} failed: " + ("; ".join(_errors(out)) or out.strip()[-200:]))
        log(f"{ip}: restored {snapshot}")
        if save and nos not in ("junos", "panos", "fortios"):
            c.save_config()
            log(f"{ip}: saved to startup-config")
    if nos == "fortios":
        log(f"{ip}: the firewall reboots with revision {snapshot}; waiting for it to come back")
    who = _login_again(ip, (login, fallback_login), nos)
    if not who:
        raise PushError("The rollback finished, but OneConfig couldn't log in again. Check the device from its console.")
    log(f"{ip}: logged in again after the rollback as {who['username']}")
    return {"status": "rolled back", "snapshot": snapshot}


def _login_again(ip, logins, nos, then=lambda c: True):
    """The first login that works (the restore may have put old passwords back), retried while a FortiGate reboots,
    until `then` accepts that session (False: not back yet, try again). None when that never happens."""
    for creds in [x for x in logins if x] * (RETRIES if nos == "fortios" else 1):
        try:
            with _connect(ip, creds, nos) as c:
                if then(c):
                    return creds
        except Exception:  # try the next set of credentials (a rebooting FortiGate: try again shortly)
            pass
        if nos == "fortios":
            time.sleep(RETRY_WAIT)
    return None


_BUSY: dict[str, threading.Lock] = {}
_BUSY_LOCK = threading.Lock()


def _one_at_a_time(ip, name) -> threading.Lock:
    """A device takes one push or rollback at a time: two config sessions at once would interleave their changes."""
    with _BUSY_LOCK:
        lock = _BUSY.setdefault(str(ip), threading.Lock())
    if not lock.acquire(blocking=False):
        raise PushError(f"{name}: another push or rollback is still running on this device. Wait for it to finish, then plan again.")
    return lock


def apply_device(planned: dict, values: dict, login: dict, log=print, **kw) -> dict:
    """_apply_device, one at a time per device, with secrets scrubbed from anything the device echoes back
    (FortiOS quotes the value it rejected)."""
    hide = lambda m: mask([str(m)], values)[0]  # noqa: E731
    lock = _one_at_a_time(planned.get("ip"), planned["hostname"])
    try:
        return _apply_device(planned, values, login, log=lambda m: log(hide(m)), **kw)
    except PushError as e:
        raise PushError(hide(e)) from None
    finally:
        lock.release()


def rollback_device(ip, login: dict, snapshot: str, **kw) -> dict:
    lock = _one_at_a_time(ip, ip)
    try:
        return _rollback_device(ip, login, snapshot, **kw)
    finally:
        lock.release()
