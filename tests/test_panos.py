"""Palo Alto PAN-OS firewall: model checks, rules and NAT in PAN-OS terms, the sunset DISA STIG, and the best-practice audit."""
import json
import re
import subprocess

import pytest

from oneconfig import panos
from oneconfig.audit import audit
from oneconfig.junos import sha256_crypt
from oneconfig.model import Network
from oneconfig.render import context, render
from oneconfig.stig import BENCH, stig_audit
from fakelab import FIX
from platforms import example

KNOWN_OPEN = {"PANW-AG-000052",  # TCP session timeout: set it in the web interface (no Palo Alto source shows its CLI path)
              "PANW-AG-000111", "PANW-IP-000045"}  # NetFlow to the IDS: needs your collector


def fw(**changes):
    data = json.loads(example("panos").model_dump_json())
    data["devices"][0].update(changes)
    return Network.model_validate(data).devices[0]


def _stig(mutate=None):
    n = example("panos")
    d = n.devices[0]
    cfg = render(d, n)
    if mutate:
        old, new = mutate
        assert re.search(old, cfg, re.M), f"{old!r} not in the generated config"
        cfg = re.sub(old, new, cfg, flags=re.M)
    return stig_audit(cfg, "firewall", context(d, n), "panos")


def test_sha256_crypt_matches_openssl_and_palo_altos_example():
    # live.paloaltonetworks.com "Tool to generate 'phash' style hashed passwords?": this hash committed on a PA-VM
    assert sha256_crypt("Password123", "sampleSALT") == "$5$sampleSALT$g.faXa7FXwSPDL6dW6fkoNQt7kueN/yfSV3moRtUxE6"
    for pw in ("x" * 70, "S3cret-Value!"):
        out = subprocess.run(["openssl", "passwd", "-5", "-salt", "Ab1", pw], capture_output=True, text=True).stdout.strip()
        if not out:
            pytest.skip("this openssl can't make SHA-256 crypt hashes (macOS LibreSSL)")
        assert sha256_crypt(pw, "Ab1") == out


def test_icmp_services_become_an_application_rule_and_published_servers_use_their_public_address():
    d = fw(services=json.loads(example("panos").model_dump_json())["devices"][0]["services"] + [{"name": "PING", "protocol": "icmp"}],
           rules=[{"name": "WEB-AND-PING", "from_zone": "INSIDE", "to_zone": "DMZ", "service": ["HTTPS", "PING"]},
                  {"name": "INTERNET-TO-WEB", "from_zone": "OUTSIDE", "to_zone": "DMZ", "destination": ["WEB-SRV"], "service": ["HTTPS"]}])
    r = {x["name"]: x for x in panos.rules(d)}
    assert r["WEB-AND-PING"]["service"] == ["HTTPS"] and r["WEB-AND-PING-ICMP"]["application"] == ["icmp", "ping", "traceroute"]
    assert r["INTERNET-TO-WEB"]["destination"] == ["WEB-PUBLIC"]  # PAN-OS matches the address before NAT


def test_nat_port_forward_is_destination_nat_and_statics_come_first():
    rows = panos.nat(fw())
    assert [x["name"] for x in rows] == ["WEB-PUBLISH", "INSIDE-PAT", "DMZ-PAT"]
    web = rows[0]
    assert (web["from"], web["to"], web["destination"], web["service"]) == ("OUTSIDE", "OUTSIDE", "WEB-PUBLIC", "HTTPS")
    assert web["xlate"] == ["destination-translation translated-address WEB-SRV", "destination-translation translated-port 443"]


def test_render_has_ha_zones_and_the_hashed_admin():
    n = example("panos")
    cfg = render(n.devices[0], n)
    for line in ("set zone OUTSIDE network layer3 ethernet1/1", "set network interface ethernet ethernet1/8 ha",
                 "set deviceconfig high-availability interface ha1 port ethernet1/8",
                 'set shared local-user-database user <ADMIN-USER> phash "<ADMIN-SECRET.SHA256>"',
                 "set rulebase default-security-rules rules interzone-default action deny"):
        assert line in cfg, line


@pytest.mark.parametrize("change, error", [
    ({"interfaces": [{"name": "ethernet1/1", "zone": "OUTSIDE", "ip": "203.0.113.2/29", "standby_ip": "203.0.113.3"}]}, "shares its addresses"),
    ({"interfaces": [{"name": "GigabitEthernet0/0", "zone": "OUTSIDE", "ip": "203.0.113.2/29"}]}, "not a panos interface"),
])
def test_bad_panos_models_are_refused(change, error):
    with pytest.raises(ValueError, match=error):
        fw(**change)


def test_two_interfaces_may_share_a_zone_on_panos():
    d = fw(interfaces=json.loads(example("panos").model_dump_json())["devices"][0]["interfaces"] +
           [{"name": "ethernet1/5", "zone": "DMZ", "ip": "172.16.20.1/24"}])
    n = example("panos")
    n.devices[0] = d
    assert "set zone DMZ network layer3 [ ethernet1/3 ethernet1/5 ]" in render(d, n)


# ---------------------------------------------------------------- STIG
def test_catalog_is_the_sunset_release():
    assert {b: (BENCH[b]["version"], BENCH[b]["release"], len(BENCH[b]["rules"])) for b in ("PAN_NDM", "PAN_ALG", "PAN_IDPS")} == \
        {"PAN_NDM": (3, 4, 35), "PAN_ALG": (3, 4, 50), "PAN_IDPS": (3, 2, 29)}


def test_generated_config_passes_every_automated_rule():
    r = _stig()
    assert {x["id"] for x in r["results"] if x["status"] == "open"} == KNOWN_OPEN
    assert {x["status"] for x in r["results"] if x["id"] == "PANW-AG-000015"} == {"not_applicable"}  # no decryption or VPN


@pytest.mark.parametrize("mutate,rule", [
    ((r"^(set shared authentication-profile LAST-RESORT lockout failed-attempts) 3", r"\1 5"), "PANW-NM-000015"),
    ((r"^(set shared authentication-profile LAST-RESORT lockout lockout-time) 0", r"\1 30"), "PANW-NM-000092"),
    ((r"^set deviceconfig system login-banner .*", 'set deviceconfig system login-banner "Hi"'), "PANW-NM-000016"),
    ((r"^set shared log-settings system match-list ALL-SYSTEM send-syslog .*\n", ""), "PANW-NM-000024"),
    ((r"^set mgt-config password-complexity minimum-length 15", "set mgt-config password-complexity minimum-length 8"), "PANW-NM-000053"),
    ((r"^set mgt-config password-complexity enabled yes\n", ""), "PANW-NM-000055"),
    ((r"^set deviceconfig setting management idle-timeout 10", "set deviceconfig setting management idle-timeout 60"), "PANW-NM-000069"),
    ((r"^set network profiles interface-management-profile ALLOW-PING ping yes", "set network profiles interface-management-profile ALLOW-PING telnet yes"),
     "PANW-NM-000061"),
    ((r"^set deviceconfig system ntp-servers secondary-ntp-server .*\n", ""), "PANW-NM-000100"),
    ((r"^set deviceconfig system ntp-servers primary-ntp-server authentication-type .*\n", ""), "PANW-NM-000145"),
    ((r"^set deviceconfig system timezone UTC", "set deviceconfig system timezone US/Pacific"), "PANW-NM-000101"),
    ((r"version v3$", "version v2c"), "PANW-NM-000118"),
    ((r"^set deviceconfig setting management enable-log-high-dp-load yes\n", ""), "PANW-NM-000144"),
    ((r"^(set mgt-config users <ADMIN-USER> permissions .*)$", r"\1\nset mgt-config users admin permissions role-based superuser yes"), "PANW-NM-000048"),
    ((r"^set rulebase security rules BLOCK-ICMP-PROBES log-end yes\n", ""), "PANW-AG-000024"),
    ((r"^set network profiles zone-protection-profile ONECONFIG-ZP flood udp enable yes\n", ""), "PANW-AG-000102"),
    ((r"^set profiles spyware ONECONFIG-AS botnet-domains lists default-paloalto-dns action sinkhole",
      "set profiles spyware ONECONFIG-AS botnet-domains lists default-paloalto-dns action alert"), "PANW-AG-000049"),
    ((r"^set network profiles zone-protection-profile ONECONFIG-ZP discard-ip-spoof yes\n", ""), "PANW-AG-000050"),
    ((r"^set network profiles zone-protection-profile ONECONFIG-ZP discard-icmp-error yes\n", ""), "PANW-IP-000030"),
    ((r"^(set rulebase security rules DNS-TO-INTERNET) (source|destination|service) \S+$", r"\1 \2 any"), "PANW-AG-000051"),
    ((r"^set deviceconfig system update-schedule threats recurring every-30-mins action download-and-install\n", ""), "PANW-AG-000060"),
    ((r"^set profiles virus ONECONFIG-AV decoder smtp action reset-both", "set profiles virus ONECONFIG-AV decoder smtp action alert"), "PANW-AG-000062"),
    ((r"^set profiles vulnerability ONECONFIG-VP rules BLOCK-CRIT-HIGH-MED severity \[ critical high medium \]",
      "set profiles vulnerability ONECONFIG-VP rules BLOCK-CRIT-HIGH-MED severity [ critical high ]"), "PANW-AG-000080"),
    ((r"^set rulebase security rules DNS-TO-INTERNET profile-setting group ONECONFIG\n", ""), "PANW-IP-000001"),
    ((r"^set profiles virus ONECONFIG-AV packet-capture yes\n", ""), "PANW-IP-000008"),
    ((r"^set profiles dos-protection ONECONFIG-DOS .*\n", ""), "PANW-IP-000018"),
    ((r"^(set rulebase security rules BLOCK-ICMP-PROBES application) .*", r"\1 [ icmp ]"), "PANW-AG-000127"),
    ((r"^set rulebase security rules DNS-TO-INTERNET log-setting default\n", ""), "PANW-AG-000144"),
])
def test_breaking_a_control_opens_its_rule(mutate, rule):
    hit = next(x for x in _stig(mutate)["results"] if x["id"] == rule)
    assert hit["status"] == "open" and hit["fix"], hit


def test_pasted_brace_config_is_audited():
    text = """config {
  mgt-config { users { admin { phash $1$x$y; permissions { role-based { superuser yes; } } } } }
  devices { localhost.localdomain {
    deviceconfig { system { hostname FW9; timezone US/Pacific; snmp-setting { access-setting { version { v2c { snmp-community-string public; } } } } } }
    network { interface { ethernet { ethernet1/1 { layer3 { ip { 198.51.100.2/30; } } } } }
              virtual-router { default { routing-table { ip { static-route { D { destination 0.0.0.0/0; nexthop { ip-address 198.51.100.1; } } } } } } } }
    vsys { vsys1 {
      zone { WAN { network { layer3 [ ethernet1/1 ]; } } }
      rulebase { security { rules { ANY { from any; to any; source any; destination any; application any; service any; action allow; } } } }
    } } } } }"""
    r = stig_audit(text, "firewall", None, "panos")
    st = {x["id"]: x["status"] for x in r["results"]}
    assert st["PANW-NM-000101"] == st["PANW-NM-000118"] == st["PANW-AG-000051"] == st["PANW-AG-000102"] == "open"
    titles = {f["title"] for f in audit(text, "panos")["findings"]}
    assert {"SNMP v2c", "Rule ANY allows everything", "Default admin account present"} <= titles


def test_best_practice_audit_for_panos():
    n = example("panos")
    cfg = render(n.devices[0], n)
    assert [f["title"] for f in audit(cfg, "panos")["findings"]] == ["Management not limited to a management subnet", "Placeholders still present"]
    worse = (cfg.replace("set network virtual-router default protocol bgp peer-group EBGP peer PEER-203-0-113-1 connection-options authentication BGP-AUTH\n", "")
             .replace("set rulebase default-security-rules rules interzone-default action deny", "set rulebase default-security-rules rules interzone-default action allow")
             .replace("set rulebase security rules DMZ-TO-INTERNET-WEB profile-setting group ONECONFIG\n", ""))
    titles = {f["title"] for f in audit(worse, "panos")["findings"]}
    assert {"BGP neighbor 203.0.113.1 without authentication", "Interzone default allows traffic",
            "Rule DMZ-TO-INTERNET-WEB allows traffic without threat inspection"} <= titles


def test_external_interfaces_given_for_a_pasted_config_are_used():
    from oneconfig.stig_panos import Pan, _ext
    c = Pan((FIX / "panos" / "running_set.txt").read_text())
    assert _ext(c, {}) == {"untrust"} and _ext(c, {"external": [next(i for i in c.zones["trust"])]}) == {"trust"}
