from datetime import date
from pathlib import Path

import pytest

from oneconfig.model import Network
from oneconfig.render import _lifetime, context, render
from oneconfig.stig import BENCH, CATALOG, Cfg, life_days, stig_audit

EXAMPLE = Path(__file__).parents[1] / "oneconfig" / "examples" / "campus.json"


def net():
    return Network.model_validate_json(EXAMPLE.read_text())


def status(report, rule):
    return {r["id"]: r["status"] for r in report["results"]}[rule]


def test_catalog_matches_disa_release():
    got = {s["id"]: (s["version"], s["release"], len(s["rules"])) for s in CATALOG["stigs"]}
    assert got == {"Router_NDM": (3, 7, 42), "Router_RTR": (3, 5, 97), "Switch_NDM": (3, 6, 42),
                   "Switch_L2S": (3, 2, 22), "Switch_RTR": (3, 4, 88),
                   "NXOS_NDM": (3, 6, 42), "NXOS_L2S": (3, 4, 22), "NXOS_RTR": (3, 4, 78),
                   "EOS_NDM": (2, 2, 21), "EOS_L2S": (2, 3, 18), "EOS_RTR": (2, 2, 75),
                   "JUNOS_RTR_NDM": (3, 2, 49), "JUNOS_RTR_RTR": (3, 2, 96),
                   "JUNOS_EX_NDM": (2, 5, 55), "JUNOS_EX_L2S": (2, 5, 24), "JUNOS_EX_RTR": (2, 1, 102),
                   "ASA_NDM": (2, 5, 47), "ASA_FW": (2, 1, 21), "ASA_IPS": (2, 1, 23), "ASA_VPN": (2, 2, 41),
                   "PAN_NDM": (3, 4, 35), "PAN_ALG": (3, 4, 50), "PAN_IDPS": (3, 2, 29),  # Palo Alto: sunset by DISA 2026-07-10
                   "FORTI_NDM": (1, 6, 60), "FORTI_FW": (1, 5, 29)}
    assert CATALOG["zips"]["U_Cisco_IOS-XE_Router_Y26M04_STIG.zip"]["sha256"].startswith("01900ad0")
    assert CATALOG["zips"]["U_Cisco_NX-OS_Switch_Y26M07_STIG.zip"]["sha256"].startswith("dceba5b8")
    assert CATALOG["zips"]["U_Arista_MLS_EOS_4-X_Y25M07_STIG.zip"]["sha256"].startswith("e6e2c54b")
    assert CATALOG["zips"]["U_Juniper_Router_Y25M01_STIG.zip"]["sha256"].startswith("44a4ae16")
    assert CATALOG["zips"]["U_Juniper_EX_Switches_Y26M07_STIG.zip"]["sha256"].startswith("e3051eaa")
    assert CATALOG["zips"]["U_Cisco_ASA_Y26M07_STIG.zip"]["sha256"].startswith("3953975d")
    assert CATALOG["zips"]["U_PAN_Y26M07_STIG.zip"]["sha256"].startswith("6d955317")
    assert CATALOG["zips"]["U_FN_FortiGate_Firewall_Y26M10_STIG.zip"]["sha256"].startswith("3e214047")


def test_every_check_maps_to_a_real_rule():
    from oneconfig.stig import REGISTRY
    ids = {r[0] for st in CATALOG["stigs"] for r in st["rules"]}  # catches typos; NX-OS inherits IOS checks that never run there
    for nos, (checks, _) in REGISTRY.items():
        assert set(checks) <= ids, (nos, set(checks) - ids)


def test_generated_network_has_no_open_findings_except_org_defined_qos():
    n = net()
    for d in n.devices:
        r = stig_audit(render(d, n), d.role, context(d, n))
        opened = [x["id"] for x in r["results"] if x["status"] == "open"]
        assert opened == ([] if d.role == "router" else ["CISC-L2-000040"]), (d.hostname, opened)


def test_l2_switch_skips_routing_stig():
    n = net()
    d = next(x for x in n.devices if x.role == "switch")
    r = stig_audit(render(d, n), "switch", context(d, n))
    assert all(x["status"] == "not_applicable" for x in r["results"] if x["stig"] == "Switch_RTR")


INSECURE_ROUTER = """version 17.9
hostname OLD
service pad
ip http server
enable password cisco
username admin privilege 15 password 0 cisco
username backup privilege 15 secret 9 $9$x
aaa new-model
aaa authentication login default local
snmp-server community public RO
ntp server 10.0.0.1
logging host 10.0.0.2
key chain OSPF
 key 1
  key-string x
interface GigabitEthernet0/0/0
 ip address 203.0.113.2 255.255.255.252
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 x
 ip ospf 1 area 0
 ip directed-broadcast
interface GigabitEthernet0/0/1
router ospf 1
router bgp 65000
 neighbor 203.0.113.1 remote-as 64500
 neighbor 203.0.113.1 password x
line con 0
 exec-timeout 0 0
line aux 0
line vty 0 4
 transport input telnet ssh
"""


def test_insecure_router_fails_the_right_rules():
    r = stig_audit(INSECURE_ROUTER, "router", {"external": ["GigabitEthernet0/0/0"], "internal": []})
    for rule in ("CISC-ND-000010", "CISC-ND-000090", "CISC-ND-000140", "CISC-ND-000150", "CISC-ND-000160",
                 "CISC-ND-000470", "CISC-ND-000490", "CISC-ND-000550", "CISC-ND-000620", "CISC-ND-000720",
                 "CISC-ND-001030", "CISC-ND-001130", "CISC-ND-001150", "CISC-ND-001200", "CISC-ND-001210",
                 "CISC-ND-001370", "CISC-ND-001450", "CISC-RT-000050", "CISC-RT-000060", "CISC-RT-000120",
                 "CISC-RT-000160", "CISC-RT-000170", "CISC-RT-000190", "CISC-RT-000230", "CISC-RT-000240",
                 "CISC-RT-000370", "CISC-RT-000390", "CISC-RT-000470", "CISC-RT-000490", "CISC-RT-000560"):
        assert status(r, rule) == "open", rule
    detail = {x["id"]: x["detail"] for x in r["results"]}
    assert "MD5" in detail["CISC-RT-000050"] and "TCP-AO" in detail["CISC-RT-000050"]
    assert r["summary"]["open"]["CAT I"] >= 5


def test_perimeter_rules_wait_for_external_interfaces():
    r = stig_audit(INSECURE_ROUTER, "router")  # pasted config, nothing marked external
    assert status(r, "CISC-RT-000240") == "not_reviewed"


INSECURE_SWITCH = """hostname SW
vtp mode server
spanning-tree mode pvst
no ip igmp snooping
interface Vlan1
 ip address 10.1.1.1 255.255.255.0
interface GigabitEthernet1/0/1
 switchport mode access
interface GigabitEthernet1/0/2
 switchport mode dynamic desirable
interface GigabitEthernet1/0/3
interface GigabitEthernet1/0/24
 switchport mode trunk
"""


def test_insecure_switch_fails_layer2_rules():
    r = stig_audit(INSECURE_SWITCH, "switch")
    for rule in ("CISC-L2-000020", "CISC-L2-000100", "CISC-L2-000110", "CISC-L2-000120", "CISC-L2-000130",
                 "CISC-L2-000160", "CISC-L2-000170", "CISC-L2-000180", "CISC-L2-000200", "CISC-L2-000210",
                 "CISC-L2-000220", "CISC-L2-000230", "CISC-L2-000240", "CISC-L2-000260", "CISC-L2-000270"):
        assert status(r, rule) == "open", rule
    assert status(r, "CISC-L2-000030") == "not_reviewed"  # VTP password isn't visible in a running config


@pytest.mark.parametrize("spec,days", [
    ("00:00:00 Jan 1 2026 00:00:00 Jun 30 2026", 180),
    ("00:00:00 1 Jan 2026 00:00:00 Jul 1 2026", 181),
    ("00:00:00 Jan 1 2026 duration 15552000", 180),
    ("00:00:00 Jan 1 2026 infinite", float("inf")),
    ("garbage", None),
])
def test_key_lifetime_parsing(spec, days):
    assert life_days(spec) == days


def test_generated_lifetime_is_180_days():
    assert life_days(_lifetime(date(2026, 10, 17))) == 180


def test_key_chain_over_180_days_fails():
    cfg = "key chain K\n key 1\n  cryptographic-algorithm hmac-sha-256\n  send-lifetime 00:00:00 Jan 1 2026 infinite\n" \
          "  accept-lifetime 00:00:00 Jan 1 2026 infinite\n"
    assert "longer than 180 days" in Cfg(cfg).chain_problem("K")


@pytest.mark.parametrize("lines,has1", [
    (["switchport trunk allowed vlan 10,20"], False),
    (["switchport trunk allowed vlan except 1"], False),
    (["switchport trunk allowed vlan 10", "switchport trunk allowed vlan add 1"], True),
    ([], True),
])
def test_trunk_allowed_vlans(lines, has1):
    assert (1 in Cfg.allowed(lines)) == has1


def test_report_counts_add_up():
    r = stig_audit(INSECURE_ROUTER, "router")
    s = r["summary"]
    assert sum(s["open"].values()) + s["not_a_finding"] + s["not_applicable"] + s["not_reviewed"] == \
        len(BENCH["Router_NDM"]["rules"]) + len(BENCH["Router_RTR"]["rules"])


def test_bad_platform_rejected():
    with pytest.raises(ValueError):
        stig_audit("hostname X", "firewall")
