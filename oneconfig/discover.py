"""Network discovery: TCP sweep, SSH with a CDP/LLDP walk, SNMP (CDP-MIB), and serial console.

Safety rules: nothing is contacted outside the `scope` networks the user typed, scans are capped
(`MAX_HOSTS`), and credentials are used in memory only. Parsing uses ntc-templates (TextFSM)."""
import asyncio
import errno
import os
import re
import threading
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Interface, ip_address, ip_network
from pathlib import Path

from ntc_templates.parse import parse_output

MAX_HOSTS = 4096
KNOWN_HOSTS = Path.home() / ".oneconfig" / "known_hosts"
_KNOWN_LOCK = threading.Lock()  # the walk connects in parallel; each read-add-write must not drop another's key
SWEEP_PORTS = (22, 23, 80, 161, 443, 830)  # 161 is UDP-only in practice; probed so SNMP-over-TCP agents show up too
COMMANDS = {"version": "show version", "cdp": "show cdp neighbors detail",
            "lldp": "show lldp neighbors detail", "config": "show running-config"}
# Junos: no CDP, the LLDP summary table, and the configuration in set form. "| no-more" stops paging.
JUNOS_COMMANDS = {"lldp": "show lldp neighbors | no-more", "config": "show configuration | display set | no-more"}
ASA_COMMANDS = {"config": "show running-config"}  # ASA speaks neither CDP nor LLDP
# PAN-OS has no `show version`: identity comes from `show system info`, the config in set form.
PANOS_COMMANDS = {"version": "show system info", "config": "show config running"}
PANOS_SETUP = ("set cli pager off", "set cli config-output-format set")
# FortiOS has no `show version` either; netmiko's FortiGate driver turns paging off for the session and back on after.
FORTIOS_COMMANDS = {"version": "get system status", "config": "show full-configuration"}
FORTI_KEX = {"kex": ["diffie-hellman-group1-sha1"]}
_SHORT = {"gi": "GigabitEthernet", "te": "TenGigabitEthernet", "tw": "TwoGigabitEthernet", "twe": "TwentyFiveGigE",
          "fi": "FiveGigabitEthernet", "fo": "FortyGigabitEthernet", "hu": "HundredGigE", "fa": "FastEthernet",
          "et": "Ethernet", "eth": "Ethernet", "po": "Port-channel", "lo": "Loopback", "vl": "Vlan", "ap": "AppGigabitEthernet"}
_SWITCH_HW = re.compile(r"^(C9[2-6]|WS-C|C3[0-9]{3}|C2960|IE-|C1000|N\dK|Nexus|DCS-|CCS-|vEOS|cEOS|EX\d|QFX)", re.I)
FIREWALL_OS = ("asa", "panos", "fortios")
NTC = {"ios-xe": "cisco_ios", "nx-os": "cisco_nxos", "eos": "arista_eos", "junos": "juniper_junos", "asa": "cisco_asa", "panos": "paloalto_panos", "fortios": "fortinet"}  # ntc-templates platform per OS


def os_from(text: str) -> str:
    """'nx-os', 'eos', 'junos', 'asa' or 'ios-xe' from show version, an SNMP sysDescr, or a CDP/LLDP description."""
    if re.search(r"\bJUNOS\b|\bJunos\b|Juniper Networks", text or ""):
        return "junos"
    if re.search(r"Adaptive Security Appliance|Firepower Threat Defense", text or ""):  # FTD's CLI is ASA underneath
        return "asa"
    if re.search(r"^sw-version:|Palo Alto Networks|PAN-OS", text or "", re.M):
        return "panos"
    if re.search(r"^Version: Forti|FortiGate|FortiOS", text or "", re.M):
        return "fortios"
    if re.search(r"NX-OS|Nexus Operating System", text or ""):
        return "nx-os"
    return "eos" if re.search(r"Arista", text or "") else "ios-xe"


def _ipv4(s):
    try:
        return str(IPv4Address((s or "").strip()))
    except ValueError:  # EOS can report a MAC as the management address
        return None


# ---------------------------------------------------------------- scope
def parse_scope(text: str) -> list:
    nets = [ip_network(x.strip(), strict=False) for x in re.split(r"[,\s]+", text or "") if x.strip()]
    if not nets:
        raise ValueError("Enter at least one network or address to stay within, e.g. 10.99.0.0/24")
    total = sum(n.num_addresses for n in nets)
    if total > MAX_HOSTS:
        raise ValueError(f"Scope covers {total} addresses; the limit is {MAX_HOSTS}. Narrow it down.")
    return nets


def in_scope(ip, scope) -> bool:
    try:
        a = ip_address(str(ip))
    except ValueError:
        return False
    return any(a in n for n in scope)


# ---------------------------------------------------------------- normalizing what devices report
def full_ifname(name: str) -> str:
    m = re.match(r"^([A-Za-z-]+)(\d[\d/.:]*)$", (name or "").strip())  # IOS names never contain spaces ("Port 1" is a phone)
    if not m:
        return (name or "").strip()
    pre, num = m.group(1).lower(), m.group(2)
    if pre in _SHORT:
        return _SHORT[pre] + num
    full = next((v for v in dict.fromkeys(_SHORT.values()) if v.lower().startswith(pre)), None)
    return (full or m.group(1)) + num


def short_host(name: str) -> str:
    """'EDGE-R1.corp.local' or 'SW1(FOC123)' -> a hostname OneConfig accepts."""
    h = re.sub(r"\(.*?\)", "", name or "").split(".")[0].strip()
    h = re.sub(r"[^A-Za-z0-9._-]", "-", h).strip("-.")[:63]
    return h or "unknown"


def role_from(caps: str = "", platform: str = "", config: str = "") -> str | None:
    """router / l3switch / switch, or None for phones, printers, APs and other endpoints."""
    words = set(re.split(r"[\s,]+", (caps or "").strip()))
    is_router = "Router" in words or "R" in words
    is_switch = "Switch" in words or "B" in words or bool(_SWITCH_HW.match((platform or "").replace("cisco ", "")))
    routing = bool(re.search(r"^(ip routing|router (ospf|eigrp|bgp)|set protocols (ospf|bgp) )", config or "", re.M))
    if is_switch and (routing or (is_router and _SWITCH_HW.match((platform or "").replace("cisco ", "")))):
        return "l3switch"
    if is_router and not is_switch:
        return "router"
    if is_router:  # routers often advertise "Router Switch" because of onboard switch modules
        return "router"
    return "switch" if is_switch else None


MAX_LINE = 1000


def _parse(cmd, text, platform="cisco_ios"):
    if not text or text.lstrip().startswith("%"):
        return []
    # Some TextFSM templates backtrack badly on a long line (4 KB of digits: 24 s in IOS "show ip ospf neighbor"),
    # and a broken or hostile device can send one. Real show output lines are well under this.
    text = "\n".join(line for line in text.splitlines() if len(line) <= MAX_LINE)
    try:
        return parse_output(platform=platform, command=cmd, data=text)
    except Exception:  # TextFSM raises on unexpected output; treat as "no data" rather than failing the device
        return []


def _first(v):
    return (v[0] if v else "") if isinstance(v, list) else (v or "")


def _nbr_role(caps, platform, desc):
    """Capabilities when the neighbor sends them; otherwise a network OS in its description means a switch."""
    return role_from(caps, platform) or (role_from("Switch", platform) if caps is None and re.search(
        r"NX-OS|Nexus|Arista|Cisco IOS", desc or "") else None)


def node_from_cli(raw: dict, ip=None) -> dict:
    nos = os_from(raw.get("version"))
    plat = NTC[nos]
    ver = (_parse({"panos": "show system info", "fortios": "get system status"}.get(nos, "show version"), raw.get("version"), plat) or [{}])[0]
    if nos == "fortios":  # "FortiGate-100F v7.4.4,build2662,240514 (GA.M)"
        m = re.match(r"(\S+) v(\d+\.\d+\.\d+)", ver.get("version", ""))
        ver.update(model=m[1], version=m[2]) if m else None
        ver["serial"] = ver.get("serial_number", "")
    config = raw.get("config") or ""
    hostname = ver.get("hostname") or next(iter(re.findall(r"^(?:set system host-name|hostname|set deviceconfig system hostname) (\S+)", config, re.M)), None) or str(ip)
    hw = _first(ver.get("hardware")) or ver.get("platform") or ver.get("model") or ""  # IOS / NX-OS / EOS / Junos field names
    hw = hw.split(",")[0] if nos == "asa" else hw  # "ASA5516, 8192 MB RAM, CPU ..."
    nbrs = []
    for n in _parse("show lldp neighbors", raw.get("lldp"), plat) if nos == "junos" else []:
        # The summary has no capabilities or address: a neighbor port named like slot/port is a network device.
        port = n.get("neighbor_interface", "")
        nbrs.append({"local": n.get("local_interface", "").split(".")[0], "host": short_host(n.get("neighbor_name") or n.get("chassis_id")),
                     "port": full_ifname(port.split(".")[0]), "ip": None, "platform": "",
                     "os": "junos" if re.match(r"(ge|xe|et|mge)-\d", port) else "ios-xe",
                     "role": "switch" if re.search(r"\d/\d", port) else None, "version": "", "via": "lldp"})
    for n in _parse("show cdp neighbors detail", raw.get("cdp"), plat) if nos in ("ios-xe", "nx-os") else []:
        nbrs.append({"local": full_ifname(n.get("local_interface")), "host": short_host(n.get("neighbor_name") or n.get("chassis_id")),
                     "port": full_ifname(n.get("neighbor_interface")), "ip": _ipv4(n.get("mgmt_address")),
                     "platform": n.get("platform", ""), "role": role_from(n.get("capabilities"), n.get("platform")),
                     "version": _version(n.get("neighbor_description")), "os": os_from(n.get("neighbor_description")), "via": "cdp"})
    seen = {(x["local"], x["host"]) for x in nbrs}
    for n in _parse("show lldp neighbors detail", raw.get("lldp"), plat) if nos not in ("junos", "asa", "panos", "fortios") else []:
        desc = n.get("neighbor_description")
        e = {"local": full_ifname(n.get("local_interface")), "host": short_host(n.get("neighbor_name") or n.get("chassis_id")),
             "port": full_ifname(n.get("neighbor_port_id") or n.get("neighbor_interface")), "ip": _ipv4(n.get("mgmt_address")),
             "platform": "", "role": _nbr_role(n.get("capabilities"), "", desc), "version": _version(desc), "os": os_from(desc),
             "via": "lldp"}
        if (e["local"], e["host"]) not in seen:
            nbrs.append(e)
    return {"hostname": short_host(hostname), "mgmt_ip": str(ip) if ip else None, "platform": hw, "os": nos,
            "version": ver.get("version") or ver.get("os") or ver.get("image") or ver.get("junos_version") or "",
            "serial": _first(ver.get("serial")) or ver.get("serial_number") or "",
            "role": "firewall" if nos in FIREWALL_OS else role_from("", hw, config) or ("router" if not _SWITCH_HW.match(hw) else "switch"),
            "config": config, "neighbors": nbrs, "reached": True}


def _version(desc):
    m = re.search(r"[Vv]ersion:? ([\w.()]+)", desc or "") or re.search(r"\(NX-OS\) Software ([\w.()]+)", desc or "") or \
        re.search(r"\bJUNOS ([\w.-]+?),", desc or "")
    return m.group(1).rstrip(",") if m else ""


# ---------------------------------------------------------------- 1. TCP sweep
async def _open(ip, port, timeout):
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(str(ip), port), timeout)
        w.close()
        return True
    except asyncio.TimeoutError:
        return False
    except OSError as e:
        if e.errno in (errno.EMFILE, errno.ENFILE):  # our limit, not the host's answer
            raise
        return False


def _socket_budget(want):
    """Open sockets we can afford. macOS starts programs with only 256 file handles, so raise the soft limit."""
    try:
        import resource
    except ImportError:  # Windows: no per-process handle limit that matters here
        return want
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = want + 128 if hard == resource.RLIM_INFINITY else min(hard, want + 128)
    if soft < target:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
        except (ValueError, OSError):
            pass
    return max(16, min(want, soft - 128))


def sweep(scope, ports=SWEEP_PORTS, timeout=1.0, concurrency=512, log=print) -> list[dict]:
    """TCP-connect probe (no root needed, unlike ping). Returns hosts with at least one open port.
    `concurrency` counts open connections, not hosts."""
    hosts = [h for n in scope for h in (n.hosts() if n.num_addresses > 2 else n)]
    log(f"Sweeping {len(hosts)} addresses on TCP {', '.join(map(str, ports))}")
    budget = _socket_budget(concurrency)

    async def run():
        sem = asyncio.Semaphore(budget)

        async def probe(ip, port):
            async with sem:
                return await _open(ip, port, timeout)

        async def one(ip):
            res = await asyncio.gather(*(probe(ip, p) for p in ports))
            return {"ip": str(ip), "ports": [p for p, ok in zip(ports, res) if ok]}
        return [r for r in await asyncio.gather(*(one(h) for h in hosts)) if r["ports"]]
    found = asyncio.run(run())
    log(f"{len(found)} hosts answered")
    return found


# ---------------------------------------------------------------- 2. SSH (and serial) via netmiko
def ssh_host_keys(host, port=22, timeout=15, learned=None) -> dict:
    """Trust on first use: remember a device's SSH host key the first time; netmiko then refuses a changed key,
    so an impostor on the management network never receives the login or the pushed secrets. A key seen for the
    first time is appended to `learned`, so the caller can say so: that first contact is the one moment it trusts blindly."""
    import paramiko
    name = str(host) if port == 22 else f"[{host}]:{port}"
    with _KNOWN_LOCK:
        keys = paramiko.HostKeys(str(KNOWN_HOSTS)) if KNOWN_HOSTS.exists() else paramiko.HostKeys()
        known = keys.lookup(name)
    if not known:
        t = paramiko.Transport((str(host), port))
        try:
            t.start_client(timeout=timeout)
            key = t.get_remote_server_key()
        finally:
            t.close()
        with _KNOWN_LOCK:
            keys = paramiko.HostKeys(str(KNOWN_HOSTS)) if KNOWN_HOSTS.exists() else paramiko.HostKeys()
            keys.add(name, key.get_name(), key)
            from . import private
            tmp = private.touch(KNOWN_HOSTS.with_suffix(".tmp"))
            keys.save(str(tmp))
            os.replace(tmp, KNOWN_HOSTS)  # atomic: a parallel connection never reads a half-written file
        if learned is not None:
            learned.append(name)
    return {"ssh_strict": True, "system_host_keys": False, "alt_host_keys": True, "alt_key_file": str(KNOWN_HOSTS)}


def cli_collect(host=None, username="", password="", secret="", port=22, device_type="cisco_ios",
                serial=None, timeout=15) -> dict:
    from netmiko import ConnectHandler
    params = dict(device_type=device_type, username=username, password=password, secret=secret or "",
                  conn_timeout=timeout, auth_timeout=timeout, banner_timeout=timeout, fast_cli=False)
    learned = []
    if serial:
        params.update(device_type="cisco_ios_serial", serial_settings=serial)
    else:
        params.update(host=str(host), port=port, **ssh_host_keys(host, port, timeout, learned))
    first = {"first_contact": bool(learned)}
    with ConnectHandler(**params) as c:
        if secret and not c.check_enable_mode():
            c.enable()
        c.send_command("terminal pager 0")  # ASA pages long output and netmiko's IOS driver can't turn that off; elsewhere a harmless error
        out = {"version": c.send_command(COMMANDS["version"], read_timeout=90)}
        if re.search(r"Unknown command|Invalid syntax", out["version"]):  # PAN-OS: no `show version`
            for cmd in PANOS_SETUP:
                c.send_command(cmd)
            return {k: c.send_command(cmd, read_timeout=120) for k, cmd in PANOS_COMMANDS.items()} | first
        forti = re.search(r"Command fail|Unknown action|command parse error", out["version"])
        if not forti:
            cmds = {"junos": JUNOS_COMMANDS, "asa": ASA_COMMANDS}.get(os_from(out["version"]), COMMANDS)
            return out | {k: c.send_command(cmd, read_timeout=90) for k, cmd in cmds.items() if k != "version"} | first
    # FortiOS: log in again with its own driver (paging). That driver offers only old SHA-1 key exchanges unless told
    # otherwise, which a FortiGate with strong-crypto refuses; allow the modern ones and drop only group1.
    with ConnectHandler(**(params | {"device_type": "fortinet", "disabled_algorithms": FORTI_KEX})) as c:
        return {k: c.send_command(cmd, read_timeout=180) for k, cmd in FORTIOS_COMMANDS.items()} | first


def ssh_walk(seeds, scope, creds: dict, max_devices=200, workers=8, log=print, collect=None) -> dict:
    """Breadth-first walk over CDP/LLDP management addresses, never leaving `scope`."""
    collect = collect or cli_collect  # looked up at call time so it can be swapped out
    nodes, tried, queue = {}, set(), deque(str(s) for s in seeds)
    with ThreadPoolExecutor(workers) as pool:
        while queue and len([n for n in nodes.values() if n["reached"]]) < max_devices:
            batch = []
            while queue and len(batch) < workers:
                ip = queue.popleft()
                if ip in tried:
                    continue
                tried.add(ip)
                if not in_scope(ip, scope):
                    log(f"{ip}: outside scope, not contacted")
                    continue
                batch.append(ip)
            for ip, fut in [(ip, pool.submit(collect, ip, **creds)) for ip in batch]:
                try:
                    raw = fut.result()
                    node = node_from_cli(raw, ip)
                except Exception as e:  # one bad device must not stop the walk
                    log(f"{ip}: {type(e).__name__}: {str(e).splitlines()[0][:160] if str(e) else 'failed'}")
                    continue
                if node["hostname"] in nodes and nodes[node["hostname"]]["reached"]:
                    log(f"{ip}: same device as {node['hostname']}, skipped")
                    continue
                nodes[node["hostname"]] = node
                if raw.get("first_contact"):
                    log(f"{ip}: first contact, so its SSH host key was trusted and saved; a different key there is refused from now on")
                log(f"{ip}: {node['hostname']} {node['platform']} {node['version']}, {len(node['neighbors'])} neighbors")
                for n in node["neighbors"]:
                    if n["role"] and n["ip"] and n["ip"] not in tried:
                        queue.append(n["ip"])
    _add_unreached(nodes)
    return nodes


def _add_unreached(nodes):
    """Neighbors we only heard about over CDP/LLDP still go on the map, marked unreached."""
    for node in list(nodes.values()):
        for n in node["neighbors"]:
            if n["role"] and n["host"] not in nodes:
                nodes[n["host"]] = {"hostname": n["host"], "mgmt_ip": n["ip"], "platform": n["platform"], "os": n.get("os", "ios-xe"),
                                    "version": n["version"], "serial": "", "role": n["role"], "config": "",
                                    "neighbors": [], "reached": False}


# ---------------------------------------------------------------- 3. SNMP (CDP-MIB)
OID = {"sysDescr": "1.3.6.1.2.1.1.1.0", "sysName": "1.3.6.1.2.1.1.5.0", "ipForwarding": "1.3.6.1.2.1.4.1.0", "ifName": "1.3.6.1.2.1.31.1.1.1.1",
       "cdpAddr": "1.3.6.1.4.1.9.9.23.1.2.1.1.4", "cdpId": "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
       "cdpPort": "1.3.6.1.4.1.9.9.23.1.2.1.1.7", "cdpPlatform": "1.3.6.1.4.1.9.9.23.1.2.1.1.8",
       "cdpCaps": "1.3.6.1.4.1.9.9.23.1.2.1.1.9"}
_CDP_BITS = {0x01: "Router", 0x02: "Switch", 0x04: "Switch", 0x08: "Switch", 0x10: "Host"}


def cdp_caps(raw: bytes) -> str:
    v = int.from_bytes(raw[-4:], "big") if raw else 0
    return " ".join(dict.fromkeys(name for bit, name in _CDP_BITS.items() if v & bit))


def cdp_addr(raw: bytes):
    return str(IPv4Address(raw[-4:])) if len(raw) >= 4 else None


def node_from_snmp(ip, sys_name, sys_descr, if_names: dict, cdp: dict, forwarding=False) -> dict:
    """cdp maps (ifIndex, devIndex) -> {column: raw bytes}. Pure function so it can be tested without an agent."""
    platform = next(iter(re.findall(r"\b(C9\d{3}\S*|ISR\d+\S*|ASR\d+\S*|C8\d{3}\S*|WS-C\S+|N\dK\S*|DCS-\S+|vEOS|cEOS\S*|"
                                    r"(?i:mx\d+|ex\d+\S*|qfx\d+\S*|srx\d+|vmx|vsrx))", sys_descr)), "")
    nbrs = []
    for (ifindex, _), row in sorted(cdp.items()):
        caps = cdp_caps(row.get("cdpCaps", b""))
        plat = row.get("cdpPlatform", b"").decode(errors="replace")
        nbrs.append({"local": full_ifname(if_names.get(ifindex, f"ifIndex{ifindex}")),
                     "host": short_host(row.get("cdpId", b"").decode(errors="replace")),
                     "port": full_ifname(row.get("cdpPort", b"").decode(errors="replace")),
                     "ip": cdp_addr(row.get("cdpAddr", b"")), "platform": plat,
                     "role": role_from(caps, plat), "version": "", "via": "snmp-cdp"})
    return {"hostname": short_host(sys_name or str(ip)), "mgmt_ip": str(ip), "platform": platform, "os": os_from(sys_descr),
            "version": _version(sys_descr), "serial": "",
            "role": "firewall" if os_from(sys_descr) in FIREWALL_OS else role_from("Router" if forwarding else "", platform) or "router",
            "config": "", "neighbors": nbrs, "reached": True}


def snmp_collect(ip, community=None, user=None, auth_key=None, priv_key=None, priv="aes256", timeout=2, port=161,
                 context="") -> dict:
    from pysnmp.hlapi.v3arch.asyncio import (CommunityData, ContextData, ObjectIdentity, ObjectType, SnmpEngine,
                                             UdpTransportTarget, UsmUserData, get_cmd, usmAesCfb128Protocol,
                                             usmAesCfb256Protocol, usmHMACSHAAuthProtocol, walk_cmd)
    if user:
        auth = UsmUserData(user, auth_key, priv_key, authProtocol=usmHMACSHAAuthProtocol,
                           privProtocol=usmAesCfb256Protocol if priv == "aes256" else usmAesCfb128Protocol)
    elif community:
        auth = CommunityData(community, mpModel=1)
    else:
        raise ValueError("SNMP needs a community string or SNMPv3 credentials")

    async def run():
        eng, ctx = SnmpEngine(), ContextData(contextName=context)
        target = await UdpTransportTarget.create((str(ip), port), timeout=timeout, retries=1)
        err, status, _, binds = await get_cmd(eng, auth, target, ctx, ObjectType(ObjectIdentity(OID["sysName"])),
                                              ObjectType(ObjectIdentity(OID["sysDescr"])),
                                              ObjectType(ObjectIdentity(OID["ipForwarding"])))
        if err or status:
            raise ConnectionError(str(err or status.prettyPrint()))
        sys_name, sys_descr, fwd = (str(v) for _, v in binds)

        async def walk(oid):
            out = {}
            async for err, status, _, row in walk_cmd(eng, auth, target, ctx, ObjectType(ObjectIdentity(oid)),
                                                      lexicographicMode=False):
                if err or status:
                    break
                for name, val in row:
                    out[tuple(name)[len(oid.split(".")):]] = val.asOctets() if hasattr(val, "asOctets") else val
            return out
        if_names = {k[0]: v.decode(errors="replace") if isinstance(v, bytes) else str(v)
                    for k, v in (await walk(OID["ifName"])).items()}
        cdp = {}
        for col in ("cdpAddr", "cdpId", "cdpPort", "cdpPlatform", "cdpCaps"):
            for idx, v in (await walk(OID[col])).items():
                cdp.setdefault(idx[:2], {})[col] = bytes(v)
        eng.close_dispatcher()
        return node_from_snmp(ip, sys_name, sys_descr, if_names, cdp, forwarding=fwd == "1")
    return asyncio.run(run())


def snmp_discover(targets, scope, creds: dict, log=print, collect=None) -> dict:
    collect = collect or snmp_collect
    nodes = {}
    for ip in targets:
        if not in_scope(ip, scope):
            log(f"{ip}: outside scope, not contacted")
            continue
        try:
            node = collect(ip, **creds)
        except Exception as e:
            log(f"{ip}: {type(e).__name__}: {str(e)[:160] or 'no response'}")
            continue
        nodes[node["hostname"]] = node
        log(f"{ip}: {node['hostname']} {node['platform']} {node['version']}, {len(node['neighbors'])} CDP neighbors")
    _add_unreached(nodes)
    return nodes


# ---------------------------------------------------------------- 4. serial console
def serial_ports() -> list[dict]:
    from serial.tools import list_ports
    return [{"device": p.device, "description": p.description} for p in list_ports.comports()]


def serial_discover(port, baud=9600, creds=None, log=print, collect=None) -> dict:
    collect = collect or cli_collect
    log(f"Opening {port} at {baud} baud")
    node = node_from_cli(collect(serial={"port": port, "baudrate": int(baud)}, **(creds or {})))
    node["mgmt_ip"] = None
    log(f"{port}: {node['hostname']} {node['platform']} {node['version']}, {len(node['neighbors'])} neighbors")
    nodes = {node["hostname"]: node}
    _add_unreached(nodes)
    return nodes


# ---------------------------------------------------------------- into OneConfig's model
def _junos_interfaces(node, out):
    from .stig_junos import J, _members, _mode, _switching, _vid
    c = J(node["config"])
    sw = _switching(c)
    for name, k in c.ifs.items():
        inet = c.inet(name)
        addr = next((z.split()[1] for z in inet if z.startswith("address ")), None)
        if name not in out and name not in sw and not addr:
            continue
        i = out.setdefault(name, {"name": name})
        desc = next((z.split(None, 1)[1].strip('"') for z in k if z.startswith(("description ", f"unit {name.split('.')[-1]} description "))), None)
        if desc:
            i["description"] = re.sub(r"[%^\r\n\"]", "", desc)[:200]
        if name in sw:
            e = sw[name]
            if _mode(e) == "trunk":
                vl = ",".join(str(_vid(c, m) or m) for m in _members(e) if m.isdigit() or _vid(c, m))
                i.update(mode="trunk", **({"trunk_vlans": vl} if vl else {}))
            else:
                i.update(mode="access", access_vlan=next((_vid(c, m) for m in _members(e)), 1) or 1)
        if addr:
            i.update(mode="routed", ip=str(IPv4Interface(addr)))
        if "disable" in k:
            i["shutdown"] = True


def _asa(node) -> dict:
    """ASA: every interface with a nameif becomes a zone; failover pairs keep their standby addresses."""
    from .stig_asa import Asa
    c, ifs, levels = Asa(node["config"]), [], {}
    fo = re.search(r"^failover lan interface (\S+) (\S+)$", node["config"], re.M)
    fo_ip = fo and re.search(rf"^failover interface ip {re.escape(fo[1])} (\S+) (\S+) standby (\S+)$", node["config"], re.M)
    paired = bool(fo_ip and re.search(r"^failover$", node["config"], re.M))
    for name, k in c.ifs.items():
        i = {"name": name, "mode": "routed"}
        desc = next((z.split(None, 1)[1] for z in k if z.startswith("description ")), None)
        if desc:
            i["description"] = re.sub(r"[%^\r\n]", "", desc)[:200]
        m = next((re.match(r"ip address (\S+) (\S+)(?: standby (\S+))?$", z) for z in k if z.startswith("ip address ")), None)
        zone = next((z.split()[1] for z in k if z.startswith("nameif ")), None)
        if m and zone:
            levels[zone] = next((int(z.split()[1]) for z in k if z.startswith("security-level ")), 0)
            i.update(ip=str(IPv4Interface(f"{m[1]}/{m[2]}")), zone=zone, external=levels[zone] == 0 and not name.lower().startswith("management"),
                     **({"standby_ip": m[3]} if m[3] and paired else {}))
        if "shutdown" in k:
            i["shutdown"] = True
        ifs.append(i)
    out = {"interfaces": ifs, "zones": [{"name": z, "security_level": v} for z, v in levels.items()]}
    if paired and fo[2] in c.ifs:
        unit = re.search(r"^failover lan unit (primary|secondary)$", node["config"], re.M)
        out["failover"] = {"interface": fo[2], "ip": str(IPv4Interface(f"{fo_ip[1]}/{fo_ip[2]}")), "peer_ip": fo_ip[3],
                           "unit": unit[1] if unit else "primary"}
    return out


def _panos(node) -> dict:
    """PAN-OS: layer 3 interfaces with their zones; an HA pair keeps its HA1 link."""
    from .stig_panos import Pan, _ext
    c = Pan(node["config"])
    zone_of = {i: z for z, ifs in c.zones.items() for i in ifs}
    ext = _ext(c, {})
    ifs = {}
    for m in c.find(r"network interface (?:ethernet|aggregate-ethernet) (\S+) layer3 (?:units (\S+) )?ip (\d+\.\d+\.\d+\.\d+/\d+)$"):
        name = m[2] or m[1]
        i = ifs.setdefault(name, {"name": name, "mode": "routed", "ip": str(IPv4Interface(m[3]))})
        if name in zone_of:
            i.update(zone=zone_of[name], external=zone_of[name] in ext)
    for m in c.find(r"network interface (?:ethernet|aggregate-ethernet) (\S+) comment (.+)$"):
        if m[1] in ifs:
            ifs[m[1]]["description"] = re.sub(r"[%^\r\n]", "", m[2])[:200]
    for name in ifs:  # an interface in no zone carries no traffic; OneConfig needs a zone for every addressed one
        ifs[name].setdefault("zone", "UNASSIGNED")
    zones = sorted({i["zone"] for i in ifs.values()})
    out = {"interfaces": list(ifs.values()), "zones": [{"name": z, "security_level": 0 if z in ext else 100} for z in zones]}
    port, ip, mask = (c.value(rf"deviceconfig high-availability interface ha1 {k} (\S+)$") for k in ("port", "ip-address", "netmask"))
    peer = c.value(r"deviceconfig high-availability group (?:group-id \d+ )?peer-ip (\S+)$")
    if port and ip and mask and peer and c.has(r"deviceconfig high-availability enabled yes$"):
        out["interfaces"].append({"name": port, "mode": "routed", "description": "HA1"})
        out["failover"] = {"interface": port, "ip": str(IPv4Interface(f"{ip}/{mask}")), "peer_ip": peer}
    return out


def _fortios(node) -> dict:
    """FortiOS: interfaces with addresses and their zones; an FGCP pair keeps its first heartbeat link."""
    from .model import IF_KINDS
    from .stig_fortios import Fos, _ext
    c = Fos(node["config"])
    zone_of = {i: z for z, ifs in c.zones.items() for i in ifs}
    ext = _ext(c, {})
    ifs = {}
    for name, f in c.interfaces.items():
        ip = f.get("ip", [])
        if len(ip) != 2 or ip[0] == "0.0.0.0" or not re.match(IF_KINDS["fortios"], name, re.I):
            continue  # unaddressed, or a kind OneConfig doesn't model (VLAN10, a named loopback): left off the map
        zone = zone_of.get(name, "UNASSIGNED")  # an interface in no zone: OneConfig needs one for every addressed interface
        i = ifs[name] = {"name": name, "mode": "routed", "ip": str(IPv4Interface(f"{ip[0]}/{ip[1]}")), "zone": zone,
                         "external": name in ext or zone in ext}
        if f.get("description"):
            i["description"] = re.sub(r"[%^\r\n]", "", f["description"][0])[:200]
        if f.get("status") == ["down"]:
            i["shutdown"] = True
    zones = sorted({i["zone"] for i in ifs.values()})
    out = {"interfaces": list(ifs.values()), "zones": [{"name": z, "security_level": 0 if z in ext else 100} for z in zones]}
    hb = c.values(r"system ha hbdev (\S+)$")
    if c.value(r"system ha mode (\S+)$") in ("a-p", "a-a") and hb:
        out["interfaces"].append({"name": hb[0], "mode": "routed", "description": "HA heartbeat"})
        out["failover"] = {"interface": hb[0]}
    return out


def _interfaces(node):
    """Interfaces worth drawing: those with neighbors, plus what the running config says about them."""
    if node.get("os") == "junos":
        out = {n["local"]: {"name": n["local"], "description": f"to {n['host']}"} for n in node["neighbors"] if n["role"]}
        _junos_interfaces(node, out)
        for i in out.values():
            i.setdefault("mode", "routed" if node["role"] == "router" else "trunk")
            if node["role"] == "router":
                i["mode"] = "routed"
                i.pop("access_vlan", None), i.pop("trunk_vlans", None)
        return list(out.values())
    from .stig import Cfg
    c, out = Cfg(node["config"]), {}
    for n in node["neighbors"]:
        if n["role"]:
            out[n["local"]] = {"name": n["local"], "description": f"to {n['host']}"}
    for name, k in c.ifs.items():
        if name not in out and not any(z.startswith(("ip address ", "switchport mode access", "switchport mode trunk")) for z in k):
            continue  # skip unconfigured ports; they'd clutter the map
        i = out.setdefault(name, {"name": name})
        desc = next((z.split(None, 1)[1] for z in k if z.startswith("description ")), None)
        if desc:
            i["description"] = re.sub(r"[%^\r\n]", "", desc)[:200]
        if "switchport mode access" in k:
            i.update(mode="access", access_vlan=c.access_vlan(k))
        elif "switchport mode trunk" in k:
            vl = next((z.split()[-1] for z in k if re.match(r"switchport trunk allowed vlan \d", z)), "")
            i.update(mode="trunk", **({"trunk_vlans": vl} if vl else {}))
        m = next((re.match(r"ip address (\S+) (\S+)$", z) for z in k if re.match(r"ip address \S+ \S+$", z)), None)
        p = next((re.match(r"ip address (\d+\.\d+\.\d+\.\d+/\d+)$", z) for z in k if re.match(r"ip address \S+/\d+$", z)), None)
        if m or p:  # IOS "address mask" or NX-OS / EOS "address/len"
            i.update(mode="routed", ip=str(IPv4Interface(p.group(1) if p else f"{m.group(1)}/{m.group(2)}")))
        if "shutdown" in k:
            i["shutdown"] = True
    for i in out.values():
        i.setdefault("mode", "routed" if node["role"] == "router" else "trunk")
        if node["role"] == "router":
            i["mode"] = "routed"
    return list(out.values())


def to_fragment(nodes: dict) -> dict:
    """Devices and links in OneConfig's network JSON shape, laid out in tiers (routers, L3, access)."""
    tiers = {"firewall": 0, "router": 0, "l3switch": 1, "switch": 2}
    devices, links, seen = [], [], set()
    by_tier = {}
    for n in nodes.values():
        by_tier.setdefault(tiers[n["role"]], []).append(n)
    for t, group in sorted(by_tier.items()):
        for k, n in enumerate(sorted(group, key=lambda z: z["hostname"])):
            devices.append({"hostname": n["hostname"], "role": n["role"], "platform": n.get("os", "ios-xe"), "x": 140 + k * 190 + (t % 2) * 60,
                            "y": 110 + t * 210,
                            **({"asa": _asa, "panos": _panos, "fortios": _fortios}[n["os"]](n) if n.get("os") in FIREWALL_OS and n["config"]
                               else {"interfaces": [] if n.get("os") in FIREWALL_OS else _interfaces(n)}),
                            **({"mgmt_ip": n["mgmt_ip"]} if n["mgmt_ip"] else {}),
                            **({"os_version": n["version"]} if n["version"] else {}),
                            **({"model": m} if (m := re.sub(r"[^ -$&-\]_-~]", "", n.get("platform") or "").strip()[:200]) else {})})  # what the model's Line accepts
    ifaces = {d["hostname"]: {i["name"] for i in d["interfaces"]} for d in devices}
    for n in nodes.values():
        for nb in n["neighbors"]:
            if nb["host"] not in ifaces or not nb["role"]:
                continue
            key = frozenset({(n["hostname"], nb["local"]), (nb["host"], nb["port"])})
            if key in seen:
                continue
            seen.add(key)
            if nb["port"] not in ifaces[nb["host"]]:  # far end only known from our side
                d = next(x for x in devices if x["hostname"] == nb["host"])
                d["interfaces"].append({"name": nb["port"], "description": f"to {n['hostname']}",
                                        "mode": "routed" if {d["role"], n["role"]} & {"router", "firewall"} else "trunk"})
                ifaces[nb["host"]].add(nb["port"])
            links.append({"a": n["hostname"], "a_if": nb["local"], "b": nb["host"], "b_if": nb["port"]})
    return {"devices": devices, "links": links}


def summarize(nodes: dict) -> list[dict]:
    """Per-device rows for the UI, with STIG and best-practice results for every config we pulled."""
    from .audit import audit
    from .stig import stig_audit
    rows = []
    for n in sorted(nodes.values(), key=lambda z: (not z["reached"], z["hostname"])):
        row = {k: n[k] for k in ("hostname", "mgmt_ip", "platform", "version", "serial", "role", "reached")}
        row["os"] = n.get("os", "ios-xe")
        row["neighbors"] = len(n["neighbors"])
        if n["config"]:
            row["stig"] = stig_audit(n["config"], n["role"], nos=row["os"])
            row["audit"] = audit(n["config"], row["os"])
        rows.append(row)
    return rows
