"""Juniper Junos: password hashing, ACL translation, model checks, and DISA STIG checks (generated configs pass,
breaking one control opens that rule)."""
import re
import subprocess

import pytest
from pydantic import ValidationError

from oneconfig.junos import acl_terms, sha512_crypt, sha512_verify
from oneconfig.model import Device
from oneconfig.render import context, render
from oneconfig.stig import stig_audit
from oneconfig.stig_junos import J
from platforms import example


def test_sha512_crypt_matches_the_reference():
    # the test vector from Ulrich Drepper's SHA-crypt specification
    assert sha512_crypt("Hello world!", "saltstring") == \
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    h = sha512_crypt("Corr3ct-Horse!")
    assert sha512_verify("Corr3ct-Horse!", h) and not sha512_verify("wrong", h) and h != sha512_crypt("Corr3ct-Horse!")


def test_sha512_crypt_matches_openssl_for_long_passwords():
    pw = "Long-Pass-" * 9  # over 64 bytes takes a different branch of the algorithm
    try:
        ref = subprocess.run(["openssl", "passwd", "-6", "-salt", "AbCdEfGh12345678", pw], capture_output=True, text=True).stdout.strip()
    except FileNotFoundError:
        pytest.skip("openssl not installed")
    if not ref:
        pytest.skip("this openssl can't make SHA-512 crypt hashes (macOS LibreSSL)")
    assert sha512_crypt(pw, "AbCdEfGh12345678") == ref


def test_acl_entries_become_filter_terms():
    t = acl_terms("WEB", ["remark web servers", "permit tcp any host 10.1.1.10 eq 443", "permit udp 10.0.0.0 0.0.0.255 any eq 53",
                          "deny ip any any log"])
    assert "set firewall family inet filter WEB term T10 from destination-address 10.1.1.10/32" in t
    assert "set firewall family inet filter WEB term T20 from source-address 10.0.0.0/24" in t
    assert "set firewall family inet filter WEB term T20 from destination-port domain" in t
    assert t[-3:] == ["set firewall family inet filter WEB term T30 then syslog", "set firewall family inet filter WEB term T30 then discard",
                      "set firewall family inet filter WEB term IMPLICIT-DENY then discard"]


@pytest.mark.parametrize("entry", ["permit tcp any any gt 1023", "permit ip any any reflect FOO", "permit bogus any any"])
def test_untranslatable_acl_entries_are_rejected(entry):
    with pytest.raises(ValidationError, match="can't be written as a Junos filter term"):
        Device(hostname="J1", platform="junos", role="router", acls=[{"name": "X", "entries": [entry]}])


def test_junos_rejects_eigrp_and_ios_names():
    with pytest.raises(ValidationError, match="Junos does not run EIGRP"):
        Device(hostname="J1", platform="junos", role="router", eigrp={"asn": 1})
    with pytest.raises(ValidationError, match="not a junos interface name"):
        Device(hostname="J1", platform="junos", role="router", interfaces=[{"name": "GigabitEthernet0/0/0"}])


def test_brace_config_is_flattened_to_set_lines():
    text = """system {
    host-name R1;
    services {
        ssh {
            ciphers [ aes256-ctr aes128-ctr ];
        }
        inactive: telnet;
    }
    login {
        message "a { b } ; c";  /* comment */
    }
}
interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                address 10.0.0.1/30;
            }
        }
    }
}"""
    assert J(text).lines == ["system host-name R1", "system services ssh ciphers aes256-ctr", "system services ssh ciphers aes128-ctr",
                             'system login message "a { b } ; c"', "interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/30"]


def _audit(host, mutate=None, net=None):
    net = net or example("junos")
    d = next(x for x in net.devices if x.hostname == host)
    cfg = render(d, net)
    if mutate:
        old, new = mutate
        assert re.search(old, cfg, re.M), f"{old!r} not in the generated config"
        cfg = re.sub(old, new, cfg, flags=re.M)
    return stig_audit(cfg, d.role, context(d, net), "junos")


def test_generated_configs_pass_every_automated_rule():
    for host in ("EDGE-R1", "CORE-SW1", "ACC-SW1", "ACC-SW2"):
        r = _audit(host)
        assert [f"{x['id']} {x['detail']}" for x in r["results"] if x["status"] == "open"] == []
        assert {b["id"] for b in r["benchmarks"]} == ({"JUNOS_RTR_NDM", "JUNOS_RTR_RTR"} if host == "EDGE-R1" else
                                                      {"JUNOS_EX_NDM", "JUNOS_EX_L2S", "JUNOS_EX_RTR"})


ADD = r"^(set system host-name .*)$"  # anchor for adding a line
LOCKOUT = r"^set system login retry-options lockout-period 15\n"


@pytest.mark.parametrize("host,mutate,rule", [
    ("EDGE-R1", (r"^set system services ssh connection-limit 3\n", ""), "JUNI-ND-000010"),
    ("EDGE-R1", (LOCKOUT, ""), "JUNI-ND-000150"),
    ("EDGE-R1", (r"^set system login message .*$", 'set system login message "Keep out"'), "JUNI-ND-000160"),
    ("EDGE-R1", (ADD, r"\1\nset system services telnet"), "JUNI-ND-000470"),
    ("EDGE-R1", (ADD, r'\1\nset system login user extra authentication encrypted-password "$6$x$y"'), "JUNI-ND-000490"),
    ("EDGE-R1", (ADD, r"\1\nset system services ssh macs hmac-sha1"), "JUNI-ND-001190"),
    ("EDGE-R1", (r"^set interfaces lo0 unit 0 family inet filter input PROTECT-RE\n", ""), "JUNI-ND-000140"),
    ("EDGE-R1", (r"^set interfaces lo0 unit 0 family inet filter input PROTECT-RE\n", ""), "JUNI-RT-000130"),
    ("EDGE-R1", (r"^set firewall family inet filter PROTECT-RE term ICMP-FRAGMENTS .*\n", ""), "JUNI-RT-000140"),
    ("EDGE-R1", (r"^set firewall family inet filter PROTECT-RE term SSH from source-prefix-list MGMT-NET\n", ""), "JUNI-ND-000140"),
    ("EDGE-R1", (r"key-chain OSPF-KEYS key 1 algorithm hmac-sha-1", "key-chain OSPF-KEYS key 1 algorithm md5"), "JUNI-RT-000050"),
    ("EDGE-R1", (r"(key-chain OSPF-KEYS key 1 start-time) \S+", r"\1 2020-01-01.00:00"), "JUNI-RT-000030"),
    ("EDGE-R1", (r"^set protocols ospf area \S+ interface ge-0/0/1.0 authentication .*\n", ""), "JUNI-RT-000020"),
    ("EDGE-R1", (r"^set firewall family inet filter EXTERNAL-IN term BOGONS .*\n", ""), "JUNI-RT-000270"),
    ("EDGE-R1", (r"^set firewall family inet filter EXTERNAL-IN term IP-OPTIONS .*\n", ""), "JUNI-RT-000350"),
    ("EDGE-R1", (r"^set firewall family inet filter EXTERNAL-IN term DENY-ALL .*\n", ""), "JUNI-RT-000240"),
    ("EDGE-R1", (r"term DENY-ALL then discard", "term DENY-ALL then reject"), "JUNI-RT-000170"),
    ("EDGE-R1", (r"^set firewall family inet filter EXTERNAL-IN term GTSM .*\n", ""), "JUNI-RT-000460"),
    ("EDGE-R1", (r"^set firewall family inet filter EXTERNAL-OUT term BLOCK-TACACS .*\n", ""), "JUNI-RT-000380"),
    ("EDGE-R1", (r"^.*prefix-limit.*\n", ""), "JUNI-RT-000540"),
    ("EDGE-R1", (r"^set protocols bgp enforce-first-as\n", ""), "JUNI-RT-000530"),
    ("EDGE-R1", (r"^set policy-options policy-statement BGP-IN term REJECT-BOGONS .*\n", ""), "JUNI-RT-000480"),
    ("EDGE-R1", (r"^set policy-options policy-statement BGP-IN term NO-LONG-PREFIXES .*\n", ""), "JUNI-RT-000550"),
    ("EDGE-R1", (r"^set protocols lldp interface ge-0/0/0 disable\n", ""), "JUNI-RT-000360"),
    ("EDGE-R1", (r"^set interfaces ge-0/0/1 unit 0 family inet rpf-check\n.*filter input EGRESS-FILTER\n", ""), "JUNI-RT-000310"),
    ("EDGE-R1", (ADD, r"\1\nset snmp community public authorization read-only"), "JUNI-ND-001120"),
    ("EDGE-R1", (r"ntp authentication-key 1 type sha256", "ntp authentication-key 1 type md5"), "JUNI-ND-001140"),
    ("EDGE-R1", (r"^set system login class AUDITOR idle-timeout 5\n", ""), "JUNI-ND-000710"),
    ("EDGE-R1", (r"^set system archival configuration transfer-on-commit\n", ""), "JUNI-ND-001400"),
    ("EDGE-R1", (r"^set system syslog host 10\.99\.0\.21 .*\n", ""), "JUNI-ND-001440"),
    ("ACC-SW1", (r"^set protocols dot1x authenticator interface ge-0/0/0\.0 .*\n", ""), "JUEX-L2-000020"),
    ("ACC-SW1", (r"^set protocols rstp bpdu-block-on-edge\n", ""), "JUEX-L2-000090"),
    ("ACC-SW1", (r"^set interfaces ge-0/0/0 unit 0 family ethernet-switching storm-control .*\n", ""), "JUEX-L2-000150"),
    ("ACC-SW1", (r"^set vlans \S+ forwarding-options dhcp-security.*\n", ""), "JUEX-L2-000120"),  # DAI alone turns snooping on
    ("ACC-SW1", (r"^set vlans \S+ forwarding-options dhcp-security arp-inspection\n", ""), "JUEX-L2-000140"),
    ("ACC-SW1", (r"^(set interfaces ae1 unit 0 family ethernet-switching interface-mode trunk)$", r"\1\nset interfaces ae1 unit 0 family ethernet-switching vlan members default"), "JUEX-L2-000210"),
    ("ACC-SW1", (r"^set protocols rstp interface ae1 bpdu-timeout-action block\n", ""), "JUEX-L2-000100"),
    ("ACC-SW1", (r"^set system rng hmac-drbg\n", ""), "JUEX-NM-000340"),
    ("ACC-SW1", (r"^set system syslog time-format (year|millisecond)\n", ""), "JUEX-NM-000130"),
    ("ACC-SW1", (r"^set system login password minimum-character-changes 8\n", ""), "JUEX-NM-000320"),
    ("CORE-SW1", (ADD, r"\1\nset system phone-home server https://example.net"), "JUEX-RT-000280"),
    ("CORE-SW1", (r"^set protocols oam ethernet link-fault-management interface ge-0/0/3\n", ""), "JUEX-L2-000180"),
    ("CORE-SW1", (r"^set protocols rstp interface ge-0/0/3 no-root-port\n", ""), "JUEX-L2-000080"),
])
def test_breaking_a_control_opens_its_rule(host, mutate, rule):
    r = _audit(host, mutate)
    status = {x["id"]: x["status"] for x in r["results"]}
    assert status[rule] == "open", next(x for x in r["results"] if x["id"] == rule)


def test_pasted_brace_config_is_audited():
    text = "system {\n    services {\n        telnet;\n        ssh {\n            protocol-version v2;\n        }\n    }\n}\n"
    r = stig_audit(text, "router", None, "junos")
    status = {x["id"]: x["status"] for x in r["results"]}
    assert status["JUNI-ND-000470"] == "open" and status["JUNI-RT-000240"] == "not_reviewed"  # perimeter rules wait for external ifs


def test_mixed_network_uses_hmac_sha1_for_ospf_everywhere():
    """Junos OSPF key chains only offer HMAC-SHA-1, so the Cisco side of a Junos OSPF link must match."""
    net = example("ios-xe")
    ios_core = next(d for d in net.devices if d.hostname == "CORE-SW1")
    assert "cryptographic-algorithm hmac-sha-256" in render(ios_core, net).split("key chain OSPF-KEYS")[1][:120]
    jnet = example("junos")
    mixed = net.model_copy(deep=True)
    mixed.devices[0] = jnet.devices[0]  # a Junos EDGE-R1 running OSPF with the IOS core
    mixed = type(net).model_validate(mixed.model_dump(mode="json") | {"links": []})
    cfg = render(next(d for d in mixed.devices if d.hostname == "CORE-SW1"), mixed)
    assert "cryptographic-algorithm hmac-sha-1\n" in cfg.split("key chain OSPF-KEYS")[1][:120]
    d = next(x for x in mixed.devices if x.hostname == "CORE-SW1")
    r = stig_audit(cfg, d.role, context(d, mixed))
    assert {x["id"]: x["status"] for x in r["results"]}["CISC-RT-000050"] == "not_a_finding"


def test_best_practice_audit_for_junos():
    from oneconfig.audit import audit
    net = example("junos")
    assert all(audit(render(d, net), "junos")["score"] == 100 for d in net.devices)
    bad = "set system services telnet\nset snmp community public authorization read-write\n" \
          "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode access\n" \
          "set protocols ospf area 0.0.0.0 interface ge-0/0/2.0\nset protocols bgp group X neighbor 1.1.1.1 peer-as 2\n"
    titles = {f["title"] for f in audit(bad, "junos")["findings"]}
    assert {"Telnet enabled", "SNMP community string with write access", "root can log in over SSH", "Access port without BPDU protection",
            "OSPF without authentication", "BGP neighbor 1.1.1.1 without authentication"} <= titles
    assert "AAA not enabled" not in titles  # IOS-only rules must not fire on Junos


def test_junos_diff_ignores_display_order_but_not_term_order():
    from oneconfig.diff import junos_plan
    kc = ['set security authentication-key-chains key-chain K key 1 secret "x"', "set security authentication-key-chains key-chain K key 1 start-time 2026-10-19.00:00",
          "set policy-options prefix-list P 10.0.0.0/8", "set policy-options prefix-list P 192.168.0.0/16"]
    shown = [kc[1], 'set security authentication-key-chains key-chain K key 1 secret "$9$hashed"', kc[3], kc[2]]  # Junos's own order
    assert junos_plan("\n".join(kc), "\n".join(shown))["add"] == []
    f = ["set firewall family inet filter F term A then accept", "set firewall family inet filter F term B then discard"]
    p = junos_plan("\n".join(f), "\n".join(reversed(f)))["add"]
    assert p == ["delete firewall family inet filter F", *f]  # term order changes what the filter does


def test_snmp_still_answers_without_a_management_subnet():
    net = example("junos")
    net.security.mgmt_subnet = None
    cfg = render(net.devices[0], net)
    assert "term SNMP from destination-port snmp" in cfg and "term SNMP from source-prefix-list" not in cfg


def test_push_keeps_lines_that_start_with_one_hash():
    from oneconfig.push import fill
    assert fill("banner login\n#1 rule: no unauthorized use\nEOF\n## a Junos comment", {}) == "banner login\n#1 rule: no unauthorized use\nEOF"
