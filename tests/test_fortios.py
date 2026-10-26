"""Fortinet FortiGate (FortiOS 7.4.4+): model checks, NAT and policies in FortiOS terms, the DISA STIGs, and the audit."""
import json
import re

import pytest

from oneconfig import fortios
from oneconfig.audit import audit
from oneconfig.model import Network
from oneconfig.render import context, render
from oneconfig.stig import BENCH, stig_audit
from oneconfig.stig_fortios import flatten
from fakelab import FIX
from platforms import example

KNOWN_OPEN = {"FGFW-ND-000115", "FNFG-FW-000105",  # alert e-mails: need your mail server and addresses
              "FGFW-ND-000255", "FGFW-ND-000280",  # FIPS-CC mode: enabling it reboots and resets the configuration
              "FGFW-ND-000311"}  # 8 changed characters: no CLI setting on FortiOS 7.6.3+
BROWNFIELD = (FIX / "fortios" / "running.conf").read_text()


def fw(**changes):
    data = json.loads(example("fortios").model_dump_json())
    data["devices"][0].update(changes)
    return Network.model_validate(data).devices[0]


def _stig(mutate=None):
    n = example("fortios")
    d = n.devices[0]
    cfg = render(d, n)
    if mutate:
        old, new = mutate
        assert re.search(old, cfg, re.M), f"{old!r} not in the generated config"
        cfg = re.sub(old, new, cfg, flags=re.M)
    return stig_audit(cfg, "firewall", context(d, n), "fortios")


def test_nat_is_central_snat_plus_vips():
    vips, pools, snat = fortios.nat(fw())
    assert vips == [{"name": "WEB-PUBLISH", "extip": "203.0.113.4", "mappedip": "172.16.10.10", "extintf": "port1", "protocol": "tcp", "port": "443"}]
    assert pools == [] and [(x["srcintf"], x["dstintf"], x["orig"], x["pool"]) for x in snat] == \
        [("INSIDE", "OUTSIDE", "INSIDE-NETS", None), ("DMZ", "OUTSIDE", "DMZ-SERVERS", None)]


def test_one_to_one_nat_gets_a_vip_and_a_one_to_one_pool():
    nat = [{"name": "WEB-STATIC", "kind": "static", "from_zone": "DMZ", "to_zone": "OUTSIDE", "source": "WEB-SRV", "translated": "WEB-PUBLIC"}]
    vips, pools, snat = fortios.nat(fw(nat=nat))
    assert vips[0]["extip"] == "203.0.113.4" and "port" not in vips[0]
    assert pools == [{"name": "WEB-STATIC", "type": "one-to-one", "start": vips and pools[0]["start"], "end": pools[0]["end"]}]
    assert snat[0]["pool"] == "WEB-STATIC"


def test_render_has_zones_policies_and_ha():
    n = example("fortios")
    cfg = render(n.devices[0], n)
    for block in ('    edit "OUTSIDE"\n        set interface "port1"\n        set intrazone deny',
                  '        set srcintf "INSIDE"\n        set dstintf "DMZ"\n        set srcaddr "INSIDE-NETS"',
                  '    set hbdev "port8" 50', "    set central-nat enable", '        set ips-sensor "default"'):
        assert block in cfg, block
    assert "standby" not in cfg and "GigabitEthernet" not in cfg


@pytest.mark.parametrize("change, error", [
    ({"interfaces": [{"name": "port1", "zone": "OUTSIDE", "ip": "203.0.113.2/29", "standby_ip": "203.0.113.3"}]}, "shares its addresses"),
    ({"interfaces": [{"name": "ethernet1/1", "zone": "OUTSIDE", "ip": "203.0.113.2/29"}]}, "not a fortios interface"),
    ({"nat": [{"name": "WEB-SRV", "kind": "dynamic", "from_zone": "INSIDE", "to_zone": "OUTSIDE", "source": "INSIDE-NETS"}]}, "NAT names can't match"),
])
def test_bad_fortios_models_are_refused(change, error):
    with pytest.raises(ValueError, match=error):
        fw(**change)


def test_static_nat_of_a_group_is_refused():
    nat = [{"name": "PUB", "kind": "static", "from_zone": "DMZ", "to_zone": "OUTSIDE", "source": "DMZ-SERVERS", "translated": "WEB-PUBLIC"}]
    with pytest.raises(ValueError, match="not a group"):
        fortios.nat(fw(nat=nat))


def test_flatten_reads_nested_blocks_and_the_vdom_wrapper():
    text = 'config vdom\nedit root\nconfig router bgp\n    set as 65001\n    config neighbor\n        edit "192.0.2.1"\n' \
           '            set remote-as 65002\n            set password ENC abc==\n        next\n    end\nend\nnext\nend\n'
    assert flatten(text) == ["router bgp as 65001", "router bgp neighbor 192.0.2.1 remote-as 65002", "router bgp neighbor 192.0.2.1 password ENC abc=="]


# ---------------------------------------------------------------- STIG
def test_catalog_release():
    assert {b: (BENCH[b]["version"], BENCH[b]["release"], len(BENCH[b]["rules"])) for b in ("FORTI_NDM", "FORTI_FW")} == \
        {"FORTI_NDM": (1, 6, 60), "FORTI_FW": (1, 5, 29)}


def test_generated_config_passes_every_automated_rule():
    r = _stig()
    assert {x["id"] for x in r["results"] if x["status"] == "open"} == KNOWN_OPEN
    assert {x["status"] for x in r["results"] if x["id"] == "FGFW-ND-000245"} == {"not_applicable"}  # no LDAP


@pytest.mark.parametrize("mutate,rule", [
    ((r"^    set admin-lockout-threshold 3", "    set admin-lockout-threshold 5"), "FGFW-ND-000045"),
    ((r"^    set pre-login-banner enable", "    set pre-login-banner disable"), "FGFW-ND-000050"),
    ((r"^    set event enable\n", ""), "FGFW-ND-000005"),
    ((r"^    set user enable\n", ""), "FGFW-ND-000010"),
    ((r"^    set user-anonymize disable", "    set user-anonymize enable"), "FGFW-ND-000095"),
    ((r"^    set cli-audit-log enable", "    set cli-audit-log disable"), "FGFW-ND-000100"),
    ((r"^config log syslogd2? setting\n    set status enable", "config log syslogd setting\n    set status disable"), "FNFG-FW-000050"),
    ((r"^    set revision-backup-on-logout enable\n", ""), "FGFW-ND-000180"),
    ((r"^        set allowaccess ping$", "        set allowaccess ping https ssh http"), "FGFW-ND-000200"),
    ((r"^        set arpforward disable", "        set arpforward enable"), "FNFG-FW-000065"),
    ((r"^    set admin-https-ssl-versions tlsv1-2 tlsv1-3", "    set admin-https-ssl-versions tlsv1-1 tlsv1-2"), "FGFW-ND-000205"),
    ((r"^        set auth-proto sha256", "        set auth-proto sha"), "FGFW-ND-000210"),
    ((r"^            set authentication enable\n", ""), "FGFW-ND-000215"),
    ((r"^    set minimum-length 15", "    set minimum-length 8"), "FGFW-ND-000220"),
    ((r"^    set min-non-alphanumeric 1", "    set min-non-alphanumeric 0"), "FGFW-ND-000240"),
    ((r"^    set admintimeout 10", "    set admintimeout 30"), "FGFW-ND-000270"),
    ((r"^    set admin-concurrent disable", "    set admin-concurrent enable"), "FGFW-ND-000300"),
    ((r'^            edit "tcp_syn_flood"\n                set status enable', '            edit "tcp_syn_flood"\n                set status disable'), "FGFW-ND-000290"),
    ((r'^            edit "icmp_sweep"\n                set status enable', '            edit "icmp_sweep"\n                set status disable'), "FNFG-FW-000110"),
    ((r'^(        set srcaddr )"DNS-SRV"(\n.*\n.*\n.*\n        set service )"DNS-ALL"', r'\1"all"\2"ALL"'), "FNFG-FW-000005"),
    ((r"^        set logtraffic all", "        set logtraffic utm"), "FNFG-FW-000020"),
    ((r"^    set diskfull overwrite", "    set diskfull nolog"), "FNFG-FW-000045"),
    ((r"^    set fail-open disable", "    set fail-open enable"), "FNFG-FW-000090"),
    ((r"^    set asymroute disable", "    set asymroute enable"), "FNFG-FW-000145"),
    ((r"^    set fwpolicy-implicit-log enable", "    set fwpolicy-implicit-log disable"), "FNFG-FW-000160"),
])
def test_breaking_a_control_opens_its_rule(mutate, rule):
    hit = next(x for x in _stig(mutate)["results"] if x["id"] == rule)
    assert hit["status"] == "open" and hit["fix"], hit


def test_wide_open_policy_needs_all_three_wide():
    hit = next(x for x in _stig((r'^        set srcaddr "DNS-SRV"', '        set srcaddr "all"'))["results"] if x["id"] == "FNFG-FW-000005")
    assert hit["status"] == "not_a_finding"  # still limited to DNS


def test_brownfield_config_is_audited():
    r = stig_audit(BROWNFIELD, "firewall", None, "fortios")
    st = {x["id"]: x["status"] for x in r["results"]}
    for rule in ("FGFW-ND-000045", "FGFW-ND-000050", "FGFW-ND-000200", "FGFW-ND-000210", "FGFW-ND-000270", "FNFG-FW-000005", "FGFW-ND-000290"):
        assert st[rule] == "open", rule
    assert st["FGFW-ND-000250"] == "not_reviewed" and st["FNFG-FW-000115"] == "open"  # nothing filters what enters from OUTSIDE (WAN role)
    assert "FortiOS 7.4.4" in next(x["detail"] for x in r["results"] if x["id"] == "FGFW-ND-000170")
    titles = {f["title"] for f in audit(BROWNFIELD, "fortios")["findings"]}
    assert {"SNMP v1/v2c community", "Policy allow-all allows everything", "Default admin account present",
            "Cleartext management on port1", "Management not limited to a management subnet"} <= titles


def test_best_practice_audit_for_fortios():
    n = example("fortios")
    cfg = render(n.devices[0], n)
    assert [f["title"] for f in audit(cfg, "fortios")["findings"]] == ["Placeholders still present"]
    worse = cfg.replace('            set password "<BGP-KEY>"\n', "").replace('        set ips-sensor "default"\n', "", 1)
    titles = {f["title"] for f in audit(worse, "fortios")["findings"]}
    assert {"BGP neighbor 203.0.113.1 without authentication", "Policy INSIDE-TO-DMZ-WEB allows traffic without threat inspection"} <= titles


def test_external_interfaces_given_for_a_pasted_config_are_used():
    cfg = BROWNFIELD.replace("set role wan", "set role lan")
    cfg = re.sub(r'    edit 1\n        set gateway 203.0.113.1\n        set device "port1"\n    next\n', "", cfg)  # no default route either
    st = lambda ext: {x["id"]: x["status"] for x in stig_audit(cfg, "firewall", ext, "fortios")["results"]}["FNFG-FW-000115"]  # noqa: E731
    assert st(None) == "not_applicable" and st({"external": ["port1"]}) == "open"  # nothing filters what enters from port1
