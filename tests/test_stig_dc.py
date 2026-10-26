"""DISA STIG checks for NX-OS and Arista EOS: generated configs pass, and breaking one control opens that rule."""
import re

import pytest

from oneconfig.render import context, render
from oneconfig.stig import BENCH, stig_audit
from platforms import example


def _audit(platform, host, mutate=None):
    net = example(platform)
    d = next(x for x in net.devices if x.hostname == host)
    cfg = render(d, net)
    if mutate:
        old, new = mutate
        assert re.search(old, cfg, re.M), f"{old!r} not in the generated {platform} config"
        cfg = re.sub(old, new, cfg, flags=re.M)
    return stig_audit(cfg, d.role, context(d, net), platform)


@pytest.mark.parametrize("platform", ["nx-os", "eos"])
def test_generated_configs_pass_every_automated_rule(platform):
    for host in ("EDGE-R1", "CORE-SW1", "ACC-SW1", "ACC-SW2"):
        r = _audit(platform, host)
        opened = [f"{x['id']} {x['detail']}" for x in r["results"] if x["status"] == "open"]
        known = {"ARST-RT-000280"} if platform == "eos" and host == "EDGE-R1" else set()  # BGP shared-secret profile: see README
        assert {o.split()[0] for o in opened} == known, opened


def test_catalog_counts_match_disa():
    assert {b: len(BENCH[b]["rules"]) for b in ("NXOS_NDM", "NXOS_L2S", "NXOS_RTR", "EOS_NDM", "EOS_L2S", "EOS_RTR")} == \
        {"NXOS_NDM": 42, "NXOS_L2S": 22, "NXOS_RTR": 78, "EOS_NDM": 21, "EOS_L2S": 18, "EOS_RTR": 75}


@pytest.mark.parametrize("platform,host,mutate,rule", [
    ("nx-os", "ACC-SW1", (r"^ssh login-attempts 3\n", ""), "CISC-ND-000150"),
    ("nx-os", "ACC-SW1", (r"^ssh macs .*", "ssh macs hmac-sha1"), "CISC-ND-001200"),
    ("nx-os", "ACC-SW1", (r"^  session-limit 2\n", ""), "CISC-ND-000010"),
    ("nx-os", "ACC-SW1", (r"^no feature telnet", "feature telnet"), "CISC-ND-000470"),
    ("nx-os", "ACC-SW1", (r"^  exec-timeout 5\n", "  exec-timeout 30\n"), "CISC-ND-000720"),
    ("nx-os", "ACC-SW1", (r"^  spanning-tree bpduguard enable\n", ""), "CISC-L2-000100"),
    ("nx-os", "ACC-SW1", (r"^  switchport trunk native vlan 999\n", ""), "CISC-L2-000260"),
    ("nx-os", "EDGE-R1", (r"^    password 0 .*\n", ""), "CISC-RT-000020"),
    ("nx-os", "EDGE-R1", (r"^      maximum-prefix .*\n", ""), "CISC-RT-000560"),
    ("nx-os", "EDGE-R1", (r"^  enforce-first-as\n", ""), "CISC-RT-000540"),
    ("nx-os", "EDGE-R1", (r"^    cryptographic-algorithm hmac-sha-256\n", ""), "CISC-RT-000050"),
    ("nx-os", "EDGE-R1", (r"(lifetime 00:00:00 \w+ \d+ \d{4} 00:00:00 \w+ \d+) \d{4}", r"\1 2099"), "CISC-RT-000030"),
    ("nx-os", "EDGE-R1", (r"^  deny ip 10\.0\.0\.0/8 any log\n", ""), "CISC-RT-000270"),
    ("nx-os", "EDGE-R1", (r"^  deny icmp any host \S+ fragments log\n", ""), "CISC-RT-000140"),
    ("eos", "ACC-SW1", (r"^   connection limit 5\n", ""), "ARST-ND-000010"),
    ("eos", "ACC-SW1", (r"lockout failure 3", "lockout failure 5"), "ARST-ND-000120"),
    ("eos", "ACC-SW1", (r"^   fips restrictions\n", ""), "ARST-ND-000470"),
    ("eos", "ACC-SW1", (r"^management telnet\n   shutdown", "management telnet\n   no shutdown"), "ARST-ND-000340"),
    ("eos", "ACC-SW1", (r"^   dot1x port-control auto\n", ""), "ARST-L2-000020"),
    ("eos", "ACC-SW1", (r"^   storm-control broadcast .*\n", ""), "ARST-L2-000030"),
    ("eos", "ACC-SW1", (r"^spanning-tree guard loop default\n", ""), "ARST-L2-000070"),
    ("eos", "EDGE-R1", (r"^   neighbor \S+ ttl maximum-hops 1\n", ""), "ARST-RT-000600"),
    ("eos", "EDGE-R1", (r"^   neighbor \S+ maximum-routes .*\n", ""), "ARST-RT-000560"),
    ("eos", "EDGE-R1", (r"^ip icmp rate-limit-unreachable 0\n", ""), "ARST-RT-000530"),
    ("eos", "EDGE-R1", (r"^   deny icmp any any redirect log\n", ""), "ARST-RT-000550"),
    ("eos", "EDGE-R1", (r"^   bgp enforce-first-as\n", ""), "ARST-RT-000060"),
    ("eos", "EDGE-R1", (r"^   deny ip 192\.168\.0\.0/16 any log\n", ""), "ARST-RT-000620"),
])
def test_breaking_a_control_opens_its_rule(platform, host, mutate, rule):
    r = _audit(platform, host, mutate)
    status = {x["id"]: x["status"] for x in r["results"]}
    assert status[rule] == "open", next(x for x in r["results"] if x["id"] == rule)


def test_best_practice_audit_speaks_each_os():
    from oneconfig.audit import audit
    for platform in ("nx-os", "eos"):
        net = example(platform)
        assert all(audit(render(d, net), platform)["score"] == 100 for d in net.devices)
    nx = "hostname X\nfeature telnet\nsnmp-server community public rw\ninterface Ethernet1/1\n  switchport mode access\n" \
         "interface Ethernet1/2\n  switchport mode trunk\nrouter bgp 1\n  neighbor 1.1.1.1\n    remote-as 2\n"
    titles = {f["title"] for f in audit(nx, "nx-os")["findings"]}
    assert {"Telnet enabled", "SNMP community string with write access", "Access port without BPDU Guard",
            "Trunk uses native VLAN 1", "BGP neighbor 1.1.1.1 without authentication"} <= titles
    eos = "hostname X\nmanagement telnet\n   no shutdown\nrouter bgp 1\n   neighbor 1.1.1.1 remote-as 2\n"
    assert {"Telnet enabled", "BGP neighbor 1.1.1.1 without authentication"} <= {f["title"] for f in audit(eos, "eos")["findings"]}
    assert "AAA not enabled" not in titles  # an IOS-only rule must not fire on NX-OS


@pytest.mark.parametrize("platform,strip", [("nx-os", r"^  ip ospf authentication key-chain OSPF-KEYS\n"),
                                            ("eos", r"^   ip ospf (authentication message-digest|message-digest-key .*)\n")])
def test_audit_flags_only_active_ospf_without_auth(platform, strip):
    from oneconfig.audit import audit
    net = example(platform)
    core = next(d for d in net.devices if d.hostname == "CORE-SW1")
    found = audit(re.sub(strip, "", render(core, net), flags=re.M), platform)["findings"]
    assert [f["where"] for f in found if f["title"].startswith("OSPF")] == ["interface " + core.interfaces[0].name]


@pytest.mark.parametrize("nos", ["nx-os", "eos"])
def test_fix_text_uses_the_os_own_syntax(nos):
    from oneconfig.stig import REGISTRY
    ios_only = re.compile(r"ip access-list (extended|standard) |log-input|banner login \^")
    bad = {k: f for k, (_, f) in REGISTRY[nos][0].items() if ios_only.search(f)}
    assert not bad, bad
