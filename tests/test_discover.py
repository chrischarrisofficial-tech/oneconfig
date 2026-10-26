import socket
import sys
from ipaddress import ip_network
from pathlib import Path

import pytest

from oneconfig import discover as D
from oneconfig.model import Network

FIX = Path(__file__).parent / "fixtures"


def test_parse_core_cli():
    node = D.node_from_cli({"version": (FIX / "core_version.txt").read_text(), "cdp": (FIX / "core_cdp.txt").read_text(),
                            "lldp": (FIX / "core_lldp.txt").read_text(), "config": "hostname CORE-SW1\nip routing\n"}, "10.99.0.1")
    assert (node["hostname"], node["platform"], node["version"], node["role"]) == ("CORE-SW1", "C9300-48P", "17.9.4a", "l3switch")
    nb = {(n["local"], n["host"]): n for n in node["neighbors"]}
    assert nb[("GigabitEthernet1/0/1", "EDGE-R1")]["role"] == "router"
    assert nb[("GigabitEthernet1/0/2", "ACC-SW1")]["port"] == "GigabitEthernet1/0/47"
    acc2 = nb[("GigabitEthernet1/0/4", "ACC-SW2")]  # from LLDP, short names expanded
    assert (acc2["port"], acc2["ip"], acc2["role"], acc2["via"]) == ("GigabitEthernet1/0/48", "10.99.0.12", "switch", "lldp")
    assert nb[("GigabitEthernet1/0/10", "SEP001122334455")]["role"] is None  # IP phone
    assert nb[("GigabitEthernet1/0/20", "printer-2f")]["role"] is None


@pytest.mark.parametrize("short,full", [("Gi1/0/4", "GigabitEthernet1/0/4"), ("Te1/1/1", "TenGigabitEthernet1/1/1"),
                                        ("Tw1/0/1", "TwoGigabitEthernet1/0/1"), ("Twe1/0/1", "TwentyFiveGigE1/0/1"),
                                        ("Po1", "Port-channel1"), ("GigabitEthernet0/0/1", "GigabitEthernet0/0/1"),
                                        ("Gig1/0/2", "GigabitEthernet1/0/2"), ("Port 1", "Port 1")])
def test_interface_names(short, full):
    assert D.full_ifname(short) == full


def test_scope_limits():
    with pytest.raises(ValueError):
        D.parse_scope("10.0.0.0/16")
    with pytest.raises(ValueError):
        D.parse_scope("  ")
    scope = D.parse_scope("10.99.0.0/24, 192.0.2.7")
    assert D.in_scope("10.99.0.200", scope) and D.in_scope("192.0.2.7", scope) and not D.in_scope("10.0.0.1", scope)


def test_sweep_finds_open_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    found = D.sweep([ip_network("127.0.0.1/32")], ports=(port,), timeout=0.5, log=lambda *_: None)
    assert found == [{"ip": "127.0.0.1", "ports": [port]}]
    srv.close()


@pytest.fixture(scope="module")
def ssh_lab():
    from fakelab import lab, start_ssh
    devs = lab()
    return {ip: start_ssh(d) for ip, d in devs.items()}


def test_ssh_walk_over_real_ssh_stays_in_scope(ssh_lab):
    from fakelab import PASSWORD, USER
    log = []

    def collect(ip, **creds):  # map each device's management IP to its fake server
        return D.cli_collect("127.0.0.1", port=ssh_lab[ip], **creds)
    nodes = D.ssh_walk(["10.99.0.1"], D.parse_scope("10.99.0.0/24"), {"username": USER, "password": PASSWORD},
                       log=log.append, collect=collect)
    reached = sorted(h for h, n in nodes.items() if n["reached"])
    assert reached == ["ACC-SW1", "ACC-SW2", "CORE-SW1"], log
    assert not nodes["EDGE-R1"]["reached"] and nodes["EDGE-R1"]["role"] == "router"
    assert any("10.0.0.1: outside scope" in x for x in log)
    assert "SEP001122334455" not in nodes and "printer-2f" not in nodes

    frag = D.to_fragment(nodes)
    links = {frozenset({(l["a"], l["a_if"]), (l["b"], l["b_if"])}) for l in frag["links"]}
    assert frozenset({("CORE-SW1", "GigabitEthernet1/0/2"), ("ACC-SW1", "GigabitEthernet1/0/47")}) in links
    assert frozenset({("CORE-SW1", "GigabitEthernet1/0/4"), ("ACC-SW2", "GigabitEthernet1/0/48")}) in links
    assert len(frag["links"]) == 4  # both sides report the same links; no duplicates
    net = Network.model_validate({"devices": frag["devices"], "links": frag["links"]})  # the fragment is a valid network
    acc1 = next(d for d in net.devices if d.hostname == "ACC-SW1")
    assert str(acc1.mgmt_ip) == "10.99.0.11" and acc1.os_version == "17.9.4a"
    assert next(i for i in acc1.interfaces if i.name == "GigabitEthernet1/0/1").access_vlan == 10


def test_bad_password_is_logged_not_fatal(ssh_lab):
    log = []
    nodes = D.ssh_walk(["10.99.0.11"], D.parse_scope("10.99.0.0/24"), {"username": "admin", "password": "wrong"},
                       log=log.append, collect=lambda ip, **c: D.cli_collect("127.0.0.1", port=ssh_lab[ip], timeout=5, **c))
    assert nodes == {} and "Authentication" in log[0]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="pty console test uses Linux ptys")
def test_serial_console_login(monkeypatch):
    from fakelab import PASSWORD, USER, lab, start_console
    import netmiko.base_connection
    monkeypatch.setattr(netmiko.base_connection, "check_serial_port", lambda name: name)  # ptys aren't listed as COM ports
    port = start_console(lab()["10.99.0.11"])
    nodes = D.serial_discover(port, 9600, {"username": USER, "password": PASSWORD}, log=lambda *_: None)
    assert nodes["ACC-SW1"]["reached"] and nodes["ACC-SW1"]["mgmt_ip"] is None
    assert nodes["CORE-SW1"]["role"] == "l3switch" and not nodes["CORE-SW1"]["reached"]


def test_snmp_cdp_decoding():
    cdp = {(10, 1): {"cdpAddr": bytes([10, 0, 0, 1]), "cdpId": b"EDGE-R1.corp.local", "cdpPort": b"GigabitEthernet0/0/1",
                     "cdpPlatform": b"cisco ISR4331/K9", "cdpCaps": bytes([0, 0, 0, 0x29])},
           (11, 2): {"cdpAddr": bytes([10, 20, 0, 50]), "cdpId": b"SEP0011", "cdpPort": b"Port 1",
                     "cdpPlatform": b"Cisco IP Phone 8851", "cdpCaps": bytes([0, 0, 0x04, 0x90])}}
    node = D.node_from_snmp("10.99.0.1", "CORE-SW1.corp.local",
                            "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE",
                            {10: "Gi1/0/1", 11: "Gi1/0/10"}, cdp)
    assert node["hostname"] == "CORE-SW1" and node["version"] == "17.9.4a"
    edge, phone = node["neighbors"]
    assert (edge["local"], edge["host"], edge["ip"], edge["role"]) == ("GigabitEthernet1/0/1", "EDGE-R1", "10.0.0.1", "router")
    assert phone["role"] is None


def test_snmp_and_ssh_respect_scope():
    log = []
    called = []
    D.snmp_discover(["10.0.0.1"], D.parse_scope("10.99.0.0/24"), {}, log=log.append, collect=lambda *a, **k: called.append(a))
    assert called == [] and "outside scope" in log[0]


@pytest.fixture(scope="module")
def snmp_agent(tmp_path_factory):
    """A real SNMP agent (snmpsim) serving CORE-SW1's CDP-MIB, with v2c community 'core' and a v3 AES-256 user."""
    import os
    import shutil
    import subprocess
    import time
    exe = shutil.which("snmpsim-command-responder")
    if not exe:
        pytest.skip("snmpsim not installed")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    root = ["--process-user=nobody", "--process-group=nogroup"] if os.geteuid() == 0 else []
    proc = subprocess.Popen([exe, *root, "--v3-engine-id", "auto", "--v3-user", "lab-user", "--v3-auth-key", "Auth-Key-12345",
                             "--v3-auth-proto", "SHA", "--v3-priv-key", "Priv-Key-12345", "--v3-priv-proto", "AES256",
                             f"--data-dir={FIX / 'snmp'}", f"--agent-udpv4-endpoint=127.0.0.1:{port}"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.5)
    yield port
    proc.terminate()


def _check_core(node):
    assert (node["hostname"], node["platform"], node["version"], node["role"]) == ("CORE-SW1", "C9300-48P", "17.9.4a", "l3switch")
    nb = {n["host"]: n for n in node["neighbors"]}
    assert (nb["EDGE-R1"]["local"], nb["EDGE-R1"]["ip"], nb["EDGE-R1"]["role"]) == ("GigabitEthernet1/0/1", "10.0.0.1", "router")
    assert nb["ACC-SW1"]["port"] == "GigabitEthernet1/0/47" and nb["SEP001122334455"]["role"] is None


def test_snmp_v2c_against_real_agent(snmp_agent):
    _check_core(D.snmp_collect("127.0.0.1", community="core", port=snmp_agent))


def test_snmp_v3_aes256_against_real_agent(snmp_agent):
    # snmpsim only serves v3 data under a named context; real Cisco agents answer the default empty one
    _check_core(D.snmp_collect("127.0.0.1", user="lab-user", auth_key="Auth-Key-12345", priv_key="Priv-Key-12345",
                               priv="aes256", port=snmp_agent, context="core"))


def test_snmp_wrong_community_times_out(snmp_agent):
    with pytest.raises(ConnectionError):
        D.snmp_collect("127.0.0.1", community="nope", port=snmp_agent, timeout=1)


def test_sweep_fails_loudly_when_out_of_sockets(monkeypatch):
    """'Too many open files' is our limit, not a closed port: it must never be reported as 'no host'."""
    import errno

    async def out_of_sockets(*a, **k):
        raise OSError(errno.EMFILE, "Too many open files")
    monkeypatch.setattr(D.asyncio, "open_connection", out_of_sockets)
    with pytest.raises(OSError, match="Too many open files"):
        D.sweep([ip_network("127.0.0.1/32")], log=lambda *_: None)
    assert 16 <= D._socket_budget(512) <= 512


def test_changed_ssh_host_key_is_refused(ssh_lab):
    import paramiko
    from fakelab import PASSWORD, USER
    port = ssh_lab["10.99.0.11"]
    assert D.cli_collect("127.0.0.1", USER, PASSWORD, port=port)["config"]  # first use: key learned
    assert D.KNOWN_HOSTS.stat().st_mode & 0o077 == 0
    keys = paramiko.HostKeys(str(D.KNOWN_HOSTS))
    keys.add(f"[127.0.0.1]:{port}", "ssh-rsa", paramiko.RSAKey.generate(1024))  # as if an impostor answered
    keys.save(str(D.KNOWN_HOSTS))
    with pytest.raises(Exception, match="(?i)host key"):
        D.cli_collect("127.0.0.1", USER, PASSWORD, port=port, timeout=5)


def test_ssh_walk_mixed_nxos_and_eos():
    from fakelab import PASSWORD, USER, dc_lab, start_ssh
    ports = {ip: start_ssh(d) for ip, d in dc_lab().items()}
    nodes = D.ssh_walk(["10.99.1.1"], D.parse_scope("10.99.1.0/24"), {"username": USER, "password": PASSWORD}, log=lambda *_: None,
                       collect=lambda ip, **c: D.cli_collect("127.0.0.1", port=ports[ip], **c))
    assert {h: (n["os"], n["role"], n["version"], n["reached"]) for h, n in nodes.items()} == {
        "DC-SPINE1": ("nx-os", "l3switch", "10.3(4a)", True), "DC-LEAF1": ("eos", "l3switch", "4.31.2F", True)}
    frag = D.to_fragment(nodes)
    net = Network.model_validate(frag)
    leaf = next(d for d in net.devices if d.hostname == "DC-LEAF1")
    assert leaf.platform == "eos" and str(next(i.ip for i in leaf.interfaces if i.name == "Ethernet1")) == "10.0.1.1/31"
    assert [(l.a_if, l.b_if) for l in net.links] in ([("Ethernet1/1", "Ethernet1")], [("Ethernet1", "Ethernet1/1")])
    rows = {r["hostname"]: r for r in D.summarize(nodes)}
    assert rows["DC-SPINE1"]["stig"]["benchmarks"][0]["id"] == "NXOS_NDM" and rows["DC-LEAF1"]["stig"]["os"] == "eos"


def test_os_from_banners_and_snmp():
    assert D.os_from("Cisco Nexus Operating System (NX-OS) Software") == "nx-os"
    assert D.os_from("Arista Networks EOS version 4.31.2F running on an Arista Networks DCS-7050") == "eos"
    assert D.os_from("Cisco IOS XE Software, Version 17.09.04a") == "ios-xe"
    n = D.node_from_snmp("10.99.1.11", "DC-LEAF1", "Arista Networks EOS version 4.31.2F running on an Arista Networks DCS-7050SX3-48YC8",
                         {}, {}, forwarding=True)
    assert (n["os"], n["platform"], n["version"]) == ("eos", "DCS-7050SX3-48YC8", "4.31.2F")


def test_ssh_walk_reads_junos():
    from fakelab import PASSWORD, USER, junos_lab, start_ssh
    ports = {ip: start_ssh(d) for ip, d in junos_lab().items()}
    nodes = D.ssh_walk(["10.99.2.1", "10.99.2.11"], D.parse_scope("10.99.2.0/24"), {"username": USER, "password": PASSWORD},
                       log=lambda *_: None, collect=lambda ip, **c: D.cli_collect("127.0.0.1", port=ports[ip], **c))
    assert {h: (n["os"], n["role"], n["platform"], n["version"]) for h, n in nodes.items()} == {
        "JUN-EDGE1": ("junos", "router", "mx240", "21.4R3-S5.4"), "JUN-ACC1": ("junos", "switch", "ex4550-32f", "22.4R3.25")}  # no AP
    net = Network.model_validate(D.to_fragment(nodes))
    acc = next(d for d in net.devices if d.hostname == "JUN-ACC1")
    ifs = {i.name: i for i in acc.interfaces}
    assert acc.platform == "junos" and ifs["ge-0/0/0"].access_vlan == 10 and ifs["ge-0/0/47"].trunk_vlans == "10" and ifs["ge-0/0/5"].shutdown
    edge = next(d for d in net.devices if d.hostname == "JUN-EDGE1")
    assert str(next(i.ip for i in edge.interfaces if i.name == "ge-0/0/1")) == "10.0.2.1/30"
    assert [sorted([(l.a, l.a_if), (l.b, l.b_if)]) for l in net.links] == [[("JUN-ACC1", "ge-0/0/47"), ("JUN-EDGE1", "ge-0/0/1")]]
    rows = {r["hostname"]: r for r in D.summarize(nodes)}
    assert rows["JUN-EDGE1"]["stig"]["benchmarks"][0]["id"] == "JUNOS_RTR_NDM" and rows["JUN-ACC1"]["stig"]["os"] == "junos"


def test_os_from_junos():
    assert D.os_from((Path(__file__).parent / "fixtures" / "junos" / "ex_version.txt").read_text()) == "junos"
    n = D.node_from_snmp("10.99.2.11", "JUN-ACC1", "Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 22.4R3.25, "
                         "Build date: 2024-01-10 UTC Copyright (c) 1996-2024 Juniper Networks, Inc.", {}, {})
    assert (n["os"], n["platform"], n["version"]) == ("junos", "ex4300-48t", "22.4R3.25")


def test_ssh_walk_reads_an_asa_pair():
    """The ASA answers no CDP or LLDP, so it is a seed. Its zones, addresses, standby addresses and failover link come
    from the running config; the audits flag the brownfield problems."""
    from fakelab import PASSWORD, USER, start_ssh
    F = Path(__file__).parent / "fixtures" / "asa"
    dev = {"hostname": "EDGE-FW1", "show version": (F / "show_version.txt").read_text(),
           "show running-config": (F / "running_config.txt").read_text()}
    port = start_ssh(dev)
    nodes = D.ssh_walk(["10.99.2.5"], D.parse_scope("10.99.2.0/24"), {"username": USER, "password": PASSWORD}, log=lambda *_: None,
                       collect=lambda ip, **c: D.cli_collect("127.0.0.1", port=port, **c))
    n = nodes["EDGE-FW1"]
    assert (n["os"], n["role"], n["platform"], n["version"], n["serial"]) == ("asa", "firewall", "ASA5516", "9.18(4)22", "JAD2049011T")
    fw = Network.model_validate(D.to_fragment(nodes)).devices[0]
    ifs = {i.name: i for i in fw.interfaces}
    assert fw.platform == "asa" and {z.name: z.security_level for z in fw.zones} == {"outside": 0, "inside": 100, "management": 100}
    assert ifs["GigabitEthernet1/1"].external and str(ifs["GigabitEthernet1/2"].standby_ip) == "10.0.0.2" and ifs["GigabitEthernet1/3"].shutdown
    assert fw.failover.interface == "GigabitEthernet1/8" and str(fw.failover.peer_ip) == "10.255.255.2"
    row = D.summarize(nodes)[0]
    opened = {r["id"] for r in row["stig"]["results"] if r["status"] == "open"}
    assert {"CASA-ND-000430", "CASA-ND-000690", "CASA-ND-001050", "CASA-FW-000230"} <= opened
    assert {"SNMP community string", "inside_access_in permits all traffic", "Failover link not protected"} <= {f["title"] for f in row["audit"]["findings"]}


def test_os_from_asa_and_ftd():
    assert D.os_from("Cisco Adaptive Security Appliance Version 9.18(4)22") == "asa"
    assert D.os_from("Cisco Firepower Threat Defense for VMware v7.4.1 (build 172)") == "asa"
    n = D.node_from_snmp("10.99.2.5", "EDGE-FW1", "Cisco Adaptive Security Appliance Version 9.18(4)22", {}, {})
    assert (n["os"], n["role"], n["version"]) == ("asa", "firewall", "9.18(4)22")


def test_ssh_walk_reads_panos():
    """PAN-OS has no `show version`: OneConfig falls back to `show system info` and reads the config in set form."""
    from fakelab import PASSWORD, USER, start_ssh
    F = Path(__file__).parent / "fixtures" / "panos"
    dev = {"hostname": "EDGE-FW2", "prompt": "admin@EDGE-FW2>", "show version": "Unknown command: version",
           "set cli pager off": "", "set cli config-output-format set": "",
           "show system info": (F / "show_system_info.txt").read_text(), "show config running": (F / "running_set.txt").read_text()}
    port = start_ssh(dev)
    nodes = D.ssh_walk(["10.99.2.7"], D.parse_scope("10.99.2.0/24"), {"username": USER, "password": PASSWORD}, log=lambda *_: None,
                       collect=lambda ip, **c: D.cli_collect("127.0.0.1", port=port, **c))
    n = nodes["EDGE-FW2"]
    assert (n["os"], n["role"], n["platform"], n["version"], n["serial"]) == ("panos", "firewall", "PA-440", "11.1.4-h7", "012801055231")
    fw = Network.model_validate(D.to_fragment(nodes)).devices[0]
    ifs = {i.name: i for i in fw.interfaces}
    assert fw.platform == "panos" and ifs["ethernet1/1"].external and ifs["ethernet1/3.30"].zone == "trust"
    assert {z.name: z.security_level for z in fw.zones} == {"trust": 100, "untrust": 0} and fw.failover.interface == "ethernet1/8"
    row = D.summarize(nodes)[0]
    opened = {r["id"] for r in row["stig"]["results"] if r["status"] == "open"}
    assert {"PANW-NM-000101", "PANW-NM-000118", "PANW-AG-000051", "PANW-AG-000102", "PANW-NM-000015"} <= opened
    assert {"SNMP v2c", "Rule allow-all allows everything"} <= {f["title"] for f in row["audit"]["findings"]}


def test_ssh_walk_reads_fortios():
    """FortiOS answers `show version` with an error: OneConfig logs in again with netmiko's FortiGate driver (which turns
    paging off for the session and back on after), then reads get system status and show full-configuration."""
    from fakelab import PASSWORD, USER, start_ssh
    F = Path(__file__).parent / "fixtures" / "fortios"
    dev = {"hostname": "EDGE-FW2", "prompt": "EDGE-FW2 # ", "show version": "command parse error before 'version'\nCommand fail. Return code -61",
           "get system status | grep Virtual": "Virtual domain configuration: disable",
           "get system status | grep Version": "Version: FortiGate-100F v7.4.4,build2662,240514 (GA.M)",
           "get system console": "mode                : line\nbaudrate            : 9600\noutput              : more\nlogin               : enable",
           "config system console": "", "set output standard": "", "set output more": "", "end": "", "exit": "",
           "get system status": (F / "get_system_status.txt").read_text(), "show full-configuration": (F / "running.conf").read_text()}
    port = start_ssh(dev)
    nodes = D.ssh_walk(["10.99.2.8"], D.parse_scope("10.99.2.0/24"), {"username": USER, "password": PASSWORD}, log=lambda *_: None,
                       collect=lambda ip, **c: D.cli_collect("127.0.0.1", port=port, **c))
    n = nodes["EDGE-FW2"]
    assert (n["os"], n["role"], n["platform"], n["version"], n["serial"]) == ("fortios", "firewall", "FortiGate-100F", "7.4.4", "FG100FTK20012345")
    fw = Network.model_validate(D.to_fragment(nodes)).devices[0]
    ifs = {i.name: i for i in fw.interfaces}
    assert fw.platform == "fortios" and ifs["port1"].external and ifs["port2"].zone == "INSIDE" and not ifs["port2"].external
    assert {z.name: z.security_level for z in fw.zones} == {"OUTSIDE": 0, "INSIDE": 100, "DMZ": 100} and fw.failover.interface == "port8"
    row = D.summarize(nodes)[0]
    opened = {r["id"] for r in row["stig"]["results"] if r["status"] == "open"}
    assert {"FGFW-ND-000045", "FGFW-ND-000210", "FNFG-FW-000005", "FGFW-ND-000270"} <= opened
    assert {"SNMP v1/v2c community", "Policy allow-all allows everything"} <= {f["title"] for f in row["audit"]["findings"]}


def test_fortigate_vlan_interfaces_dont_break_discovery():
    """FortiGates name VLAN interfaces freely (VLAN10): those are left off the map rather than making the device invalid."""
    cfg = (Path(__file__).parent / "fixtures" / "fortios" / "running.conf").read_text().replace("config system zone", (
        'config system interface\n    edit "VLAN10"\n        set ip 10.10.0.1 255.255.255.0\n        set interface "port2"\n'
        '        set vlanid 10\n    next\nend\nconfig system zone'), 1)
    node = {"hostname": "EDGE-FW2", "mgmt_ip": "10.99.2.8", "platform": "FortiGate-100F", "os": "fortios", "version": "7.4.4",
            "serial": "", "role": "firewall", "config": cfg, "neighbors": [], "reached": True}
    fw = Network.model_validate(D.to_fragment({"EDGE-FW2": node})).devices[0]
    assert {i.name for i in fw.interfaces} == {"port1", "port2", "port3", "port8"}


def test_first_contact_is_logged_once(ssh_lab):
    from fakelab import PASSWORD, USER

    def walk():
        log = []
        D.ssh_walk(["10.99.0.11"], D.parse_scope("10.99.0.11/32"), {"username": USER, "password": PASSWORD}, log=log.append,
                   collect=lambda ip, **c: D.cli_collect("127.0.0.1", port=ssh_lab[ip], **c))
        return log
    assert any("10.99.0.11: first contact" in x for x in walk())
    assert not any("first contact" in x for x in walk())  # the saved key is used from now on


def test_discovered_model_names_are_cleaned_to_what_the_network_accepts():
    node = {"hostname": "SW9", "mgmt_ip": "10.99.0.9", "platform": "Catalyst\u00ae 9300-48P\n%rev^2", "os": "ios-xe", "version": "",
            "serial": "", "role": "switch", "config": "", "neighbors": [], "reached": True}
    frag = D.to_fragment({"SW9": node})
    assert frag["devices"][0]["model"] == "Catalyst 9300-48Prev2"
    Network.model_validate(frag)  # builds: nothing in it the model refuses
