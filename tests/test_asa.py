"""Cisco ASA firewall: model checks, zone rules as per-interface access lists, NAT and failover."""
import json
import re

import pytest

from oneconfig import asa
from oneconfig.model import Network
from oneconfig.render import render
from platforms import EXAMPLE

EDGE = json.loads((EXAMPLE.parent / "edge.json").read_text())


def net(**changes):
    data = json.loads(json.dumps(EDGE))
    data["devices"][0].update(changes)
    return Network.model_validate(data)


def fw(**changes):
    return net(**changes).devices[0]


def test_any_toward_a_closed_zone_means_its_networks_and_open_zones_come_after_a_deny_of_them():
    _, acls = asa.policy(fw())
    inside = [l for l in acls if l.startswith("access-list INSIDE_IN extended")]
    assert inside[0].startswith("access-list INSIDE_IN extended permit object-group WEB object INSIDE-NETS object-group DMZ-SERVERS")
    deny_dmz = inside.index("access-list INSIDE_IN extended deny ip any4 object-group ZONE-DMZ-NETS log")
    to_internet = inside.index("access-list INSIDE_IN extended permit object-group WEB object INSIDE-NETS any4 log")
    ssh_out = inside.index("access-list INSIDE_IN extended deny tcp any4 any4 eq ssh log")  # STIG CASA-FW-000250
    assert deny_dmz < ssh_out < to_internet and inside[-1] == "access-list INSIDE_IN extended deny ip any any log"
    assert "access-group OUTSIDE_IN in interface OUTSIDE" in acls and not any("MANAGEMENT" in l for l in acls)
    assert not any("OUTSIDE_IN extended deny tcp any4 any4 eq ssh" in l for l in acls)  # only inward-facing zones


def test_any_toward_a_closed_zone_uses_its_subnet_and_static_routes():
    d = fw(rules=[{"name": "TO-DMZ", "from_zone": "INSIDE", "to_zone": "DMZ", "service": ["HTTPS"]}],
           static_routes=EDGE["devices"][0]["static_routes"] + [{"prefix": "172.16.20.0/24", "next_hop": "172.16.10.254"}])
    groups, acls = asa.policy(d)
    i = groups.index("object-group network ZONE-DMZ-NETS")
    assert groups[i + 1:i + 3] == [" network-object 172.16.10.0 255.255.255.0", " network-object 172.16.20.0 255.255.255.0"]
    assert "access-list INSIDE_IN extended permit object HTTPS any4 object-group ZONE-DMZ-NETS log" in acls


def test_several_objects_become_a_rule_group_and_clashes_are_refused():
    rule = {"name": "R1", "from_zone": "INSIDE", "to_zone": "DMZ", "source": ["INSIDE-NETS", "DNS-SRV"],
            "destination": ["WEB-SRV"], "service": ["HTTP", "HTTPS"], "action": "deny", "log": False}
    groups, acls = asa.policy(fw(rules=[rule]))
    assert "access-list INSIDE_IN extended deny object-group R1-SVC object-group R1-SRC object WEB-SRV" in acls
    assert groups[groups.index("object-group network R1-SRC") + 1] == " network-object object INSIDE-NETS"
    clash = fw(rules=[rule], address_groups=EDGE["devices"][0]["address_groups"] + [{"name": "R1-SRC", "members": ["WEB-SRV"]}])
    with pytest.raises(ValueError, match="R1-SRC clashes"):
        asa.policy(clash)


def test_nat_puts_static_first_and_pat_after_auto():
    assert asa.nat(fw()) == ["nat (DMZ,OUTSIDE) source static WEB-SRV WEB-PUBLIC service HTTPS HTTPS",
                             "nat (INSIDE,OUTSIDE) after-auto source dynamic INSIDE-NETS interface",
                             "nat (DMZ,OUTSIDE) after-auto source dynamic DMZ-SERVERS interface"]


def test_servers_are_reached_through_the_right_interface():
    d = fw()
    assert asa.zone_for(d, net().security.syslog_servers[0]) == "MANAGEMENT"  # connected
    from ipaddress import IPv4Address
    assert asa.zone_for(d, IPv4Address("198.51.100.7")) == "OUTSIDE"  # default route


def test_render_has_failover_standby_addresses_and_secondary_bootstrap():
    n = net()
    cfg = render(n.devices[0], n)
    assert " ip address 203.0.113.2 255.255.255.248 standby 203.0.113.3" in cfg
    assert "failover interface ip FOLINK 10.255.255.1 255.255.255.252 standby 10.255.255.2" in cfg
    assert "!   failover lan unit secondary" in cfg and "route OUTSIDE 0.0.0.0 0.0.0.0 203.0.113.1 1" in cfg
    assert "logging host MANAGEMENT 10.99.0.20 6/1514" in cfg and "ssh 10.99.0.0 255.255.255.0 MANAGEMENT" in cfg


@pytest.mark.parametrize("change, error", [
    ({"platform": "ios-xe"}, "needs a firewall platform"),
    ({"role": "router"}, "is a firewall platform"),
    ({"rules": [{"name": "X", "from_zone": "INSIDE", "to_zone": "NOWHERE"}]}, "zone NOWHERE is not defined"),
    ({"rules": [{"name": "X", "from_zone": "INSIDE", "to_zone": "DMZ", "service": ["SSH"]}]}, "SSH is not defined"),
    ({"rules": [{"name": "X", "from_zone": "INSIDE", "to_zone": "DMZ", "source": ["any", "WEB-SRV"]}]}, "can't be combined"),
    ({"rules": [{"name": "X", "from_zone": "MANAGEMENT", "to_zone": "DMZ"}]}, "management-only"),
    ({"address_groups": [{"name": "G", "members": ["LATER"]}, {"name": "LATER", "members": ["WEB-SRV"]}]}, "earlier address group"),
    ({"services": [{"name": "BAD", "protocol": "tcp"}]}, "need a port"),
    ({"nat": [{"name": "N", "kind": "dynamic", "from_zone": "INSIDE", "to_zone": "OUTSIDE", "source": "INSIDE-NETS", "service": "HTTPS"}]}, "only static NAT"),
    ({"failover": {"interface": "GigabitEthernet0/1", "ip": "10.255.255.1/30", "peer_ip": "10.255.255.2"}}, "failover link must be"),
    ({"static_routes": [{"prefix": "0.0.0.0/0", "next_hop": "192.0.2.1"}]}, "next hop must be an address on a zone"),
    ({"zones": EDGE["devices"][0]["zones"] + [{"name": "inside"}]}, "duplicate zone"),
    ({"rules": [{"name": "X", "from_zone": "DMZ", "to_zone": "DMZ"}]}, "within one zone"),
    ({"interfaces": EDGE["devices"][0]["interfaces"][:3] + [{"name": "GigabitEthernet0/3", "ip": "192.0.2.1/24"}] + EDGE["devices"][0]["interfaces"][4:]},
     "put the interface in a zone"),
])
def test_bad_firewall_models_are_refused(change, error):
    with pytest.raises(ValueError, match=error):
        fw(**change)


def test_one_interface_per_zone_and_standby_needs_failover():
    ifs = EDGE["devices"][0]["interfaces"]
    with pytest.raises(ValueError, match="one interface in each zone"):
        fw(interfaces=ifs[:3] + [{"name": "GigabitEthernet0/3", "zone": "DMZ", "ip": "172.16.11.1/24"}] + ifs[4:])
    with pytest.raises(ValueError, match="standby IP needs failover"):
        fw(failover=None)


def test_non_firewalls_take_no_zones():
    data = json.loads(json.dumps(EDGE))
    data["devices"][1]["interfaces"][0]["zone"] = "INSIDE"
    with pytest.raises(ValueError, match="for firewalls"):
        Network.model_validate(data)


# ---------------------------------------------------------------- STIG
from oneconfig.render import context  # noqa: E402
from oneconfig.stig import BENCH, stig_audit  # noqa: E402

KNOWN_OPEN = {"CASA-FW-000210", "CASA-FW-000300"}  # e-mail alerts need your SMTP server and addresses


def _stig(mutate=None, cfg=None):
    n = net()
    d = n.devices[0]
    cfg = cfg or render(d, n)
    if mutate:
        old, new = mutate
        assert re.search(old, cfg, re.M), f"{old!r} not in the generated config"
        cfg = re.sub(old, new, cfg, flags=re.M)
    return stig_audit(cfg, "firewall", context(d, n), "asa")


def test_catalog_counts_match_disa():
    assert {b: len(BENCH[b]["rules"]) for b in ("ASA_NDM", "ASA_FW", "ASA_IPS", "ASA_VPN")} == \
        {"ASA_NDM": 47, "ASA_FW": 21, "ASA_IPS": 23, "ASA_VPN": 41}


def test_generated_config_passes_every_automated_rule():
    r = _stig()
    assert {x["id"] for x in r["results"] if x["status"] == "open"} == KNOWN_OPEN
    gated = {x["stig"] for x in r["results"] if x["status"] == "not_applicable"}
    assert {"ASA_IPS", "ASA_VPN"} <= gated


@pytest.mark.parametrize("mutate,rule", [
    ((r"^quota management-session 5\n", ""), "CASA-ND-000010"),
    ((r"^ssh 10\.99\.0\.0 255\.255\.255\.0", "ssh 0.0.0.0 0.0.0.0"), "CASA-ND-000140"),
    ((r"^banner login You are accessing.*\n", ""), "CASA-ND-000160"),
    ((r"^logging buffered informational", "logging buffered warnings"), "CASA-ND-000090"),
    ((r"^logging timestamp\n", ""), "CASA-ND-000270"),
    ((r"^http server idle-timeout 5\n", "http server enable\nhttp server idle-timeout 5\n"), "CASA-ND-000430"),
    ((r"^username (\S+) password", r"username second password x privilege 15\nusername \1 password"), "CASA-ND-000450"),
    ((r"^fips enable\n", ""), "CASA-ND-000470"),
    ((r"^password-policy minimum-length 15", "password-policy minimum-length 8"), "CASA-ND-000490"),
    ((r"^password-policy minimum-changes 8\n", ""), "CASA-ND-000580"),
    ((r"^console timeout 5\n", ""), "CASA-ND-000690"),
    ((r"^logging flash-minimum-free .*\n", ""), "CASA-ND-000920"),
    ((r"^ntp server 10\.99\.0\.11.*\n", ""), "CASA-ND-000940"),
    ((r" auth sha256 ", " auth md5 "), "CASA-ND-001050"),
    ((r" priv aes 256 ", " "), "CASA-ND-001070"),
    ((r"authentication-key 1 sha256", "authentication-key 1 md5"), "CASA-ND-001080"),
    ((r"^ssh cipher (encryption|integrity) fips\n", ""), "CASA-ND-001140"),
    ((r"^threat-detection basic-threat\n", ""), "CASA-ND-001180"),
    ((r"^aaa-server TACACS-SERVERS \(MANAGEMENT\) host 10\.99\.0\.41\n key .*\n", ""), "CASA-ND-001310"),
    ((r"^ event syslog id 111010\n", ""), "CASA-ND-001350"),
    ((r"^logging host MANAGEMENT 10\.99\.0\.21 .*\n", ""), "CASA-ND-001410"),
    ((r"^access-list INSIDE_IN extended permit object-group WEB object INSIDE-NETS any4 log",
      "access-list INSIDE_IN extended permit ip object INSIDE-NETS any4"), "CASA-FW-000010"),
    ((r"^(access-list \S+ extended deny ip any any) log", r"\1"), "CASA-FW-000040"),
    ((r"^logging queue 8192\n", ""), "CASA-FW-000090"),
    ((r"^logging permit-hostdown\n", ""), "CASA-FW-000100"),
    ((r"^logging trap notifications", "logging trap errors"), "CASA-FW-000200"),
    ((r"^threat-detection scanning-threat shun\n", ""), "CASA-FW-000220"),
    ((r"^access-list OUTSIDE_IN extended deny ip any any log\n", ""), "CASA-FW-000230"),
    ((r"^access-group DMZ_IN in interface DMZ\n", ""), "CASA-FW-000240"),
    ((r"^access-list DMZ_IN extended deny udp any4 any4 eq syslog log\n", ""), "CASA-FW-000250"),
    ((r"^service-policy global_policy global\n", ""), "CASA-FW-000270"),
    ((r"^ip verify reverse-path interface INSIDE\n", ""), "CASA-FW-000290"),
])
def test_breaking_a_control_opens_its_rule(mutate, rule):
    r = _stig(mutate)
    hit = next(x for x in r["results"] if x["id"] == rule)
    assert hit["status"] == "open" and hit["fix"], hit


def test_vpn_and_ips_rules_wake_up_when_configured():
    r = _stig((r"^service-policy global_policy global", "crypto ikev2 enable OUTSIDE\npolicy-map global_policy\n class inspection_default\n"
                                                         "  sfr fail-open\nservice-policy global_policy global"))
    status = {x["stig"]: x["status"] for x in r["results"] if x["stig"] in ("ASA_VPN", "ASA_IPS")}
    assert status == {"ASA_VPN": "not_reviewed", "ASA_IPS": "not_reviewed"}


def test_pasted_config_without_context_treats_level_0_as_external():
    cfg = render(net().devices[0], net()).replace("access-group OUTSIDE_IN in interface OUTSIDE\n", "")
    r = stig_audit(cfg, "firewall", None, "asa")
    assert next(x for x in r["results"] if x["id"] == "CASA-FW-000230")["status"] == "open"


def test_best_practice_audit_for_asa():
    from oneconfig.audit import audit
    n = net()
    cfg = render(n.devices[0], n)
    assert [f["title"] for f in audit(cfg, "asa")["findings"]] == ["Placeholders still present"]
    bad = (cfg.replace("logging permit-hostdown\n", "").replace("access-group DMZ_IN in interface DMZ\n", "")
           .replace("  neighbor 203.0.113.1 password <BGP-KEY>\n", "") + "telnet 10.0.0.0 255.0.0.0 INSIDE\n"
           "access-list INSIDE_IN extended permit ip any any\n")
    titles = {f["title"] for f in audit(bad, "asa")["findings"]}
    assert {"TCP syslog without permit-hostdown", "Interface DMZ has no access list", "BGP neighbor 203.0.113.1 without authentication",
            "Telnet enabled", "INSIDE_IN permits all traffic"} <= titles


# ---------------------------------------------------------------- plan only
def test_plan_reads_the_asa_and_apply_refuses(monkeypatch, tmp_path):
    from fakelab import PASSWORD, USER, start_ssh
    from oneconfig import push
    run = (EXAMPLE.parents[2] / "tests" / "fixtures" / "asa" / "running_config.txt").read_text()
    dev = {"hostname": "EDGE-FW1", "show running-config": run, "show version": "Cisco Adaptive Security Appliance Software Version 9.18(4)22"}
    port = start_ssh(dev)
    real = push.connect
    monkeypatch.setattr(push, "connect", lambda ip, login, **kw: real("127.0.0.1", login, port=port, timeout=8, nos=kw.get("nos")))
    n = net()
    d = n.devices[0]
    login = {"username": USER, "password": PASSWORD, "secret": ""}
    values = {p: f"Lab{p.replace('-', '')}Value9!" for p in push.placeholders(render(d, n))} | {"ADMIN-USER": USER, "SNMP-USER": "snmpops"}
    p = push.plan_device(d, n, login, values)
    assert p["os"] == "asa" and not p["blockers"] and "no snmp-server community public" in p["remove"]
    assert "no telnet" not in " ".join(p["remove"]) and "clear configure access-list INSIDE_IN" not in p["add"]
    assert p["add"].index("access-list INSIDE_IN extended deny ip any any log") < p["add"].index("access-group INSIDE_IN in interface INSIDE")
    assert any("no automatic rollback" in w for w in p["warnings"]) and any("Changes failover" in w for w in p["warnings"])
    assert not any(v in "\n".join(p["add_shown"]) for k, v in values.items() if k not in push.IDENTIFIERS)
    with pytest.raises(push.PushError, match="plans the change but does not push it"):
        push.apply_device(p, values, login, log=lambda *_: None)


def test_plan_replaces_a_changed_access_list_and_rebinds_it():
    from oneconfig.diff import asa_plan
    n = net()
    cand = render(n.devices[0], n)
    run = cand.replace("access-list DMZ_IN extended deny tcp any4 any4 eq ssh log\n", "").replace(" network-object object WEB-SRV\n",
                                                                                             " network-object object WEB-SRV\n network-object host 192.0.2.66\n")
    run = run.replace("nameif INSIDE", "nameif inside")
    p = asa_plan(cand, run + "access-list OLD_IN extended permit ip any any\naccess-group OLD_IN in interface inside\n")
    i = p["add"].index("clear configure access-list DMZ_IN")
    assert p["add"][i + 1].startswith("access-list DMZ_IN ") and "access-group DMZ_IN in interface DMZ" in p["add"][i:]
    assert ["object-group network DMZ-SERVERS", " no network-object host 192.0.2.66"] == p["add"][p["add"].index("object-group network DMZ-SERVERS"):][:2]
    assert "clear configure access-list OLD_IN" not in p["remove"]  # still bound to 'inside', which we don't rebind
    from oneconfig.push import _asa_warnings
    assert any("nameif inside becomes INSIDE" in w for w in _asa_warnings(cand, run))


def test_a_new_firewall_without_interfaces_still_renders():
    n = Network.model_validate({"security": {"syslog_servers": ["10.99.0.20"], "mgmt_subnet": "10.99.0.0/24"},
                                "devices": [{"hostname": "FW1", "role": "firewall", "platform": "asa", "zones": [{"name": "INSIDE", "security_level": 100}]}]})
    cfg = render(n.devices[0], n)
    assert "logging host INSIDE 10.99.0.20 6/1514" in cfg and "access-group" not in cfg
