"""Run with `pytest` or `python tests/test_oneconfig.py`."""
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from oneconfig.audit import audit
from oneconfig.model import Network
from oneconfig.render import render_all

EXAMPLE = Path(__file__).parents[1] / "oneconfig" / "examples" / "campus.json"


def net():
    return Network.model_validate_json(EXAMPLE.read_text())


def test_example_renders_expected_features():
    cfgs = render_all(net())
    r1, core, acc = cfgs["EDGE-R1"], cfgs["CORE-SW1"], cfgs["ACC-SW1"]
    assert "router bgp 65010" in r1 and "neighbor 203.0.113.1 ttl-security hops 1" in r1
    assert "ip access-group EXTERNAL-IN in" in r1 and "neighbor 203.0.113.1 ao BGP-AS64500" in r1
    assert "no passive-interface GigabitEthernet0/0/1" in r1
    assert "ip routing" in core and "channel-group 1 mode active" in core
    assert " no passive-interface Vlan10" not in core  # SVIs stay passive
    assert "vlan 999\n name NATIVE-UNUSED" in acc
    assert "spanning-tree bpduguard enable" in acc and "switchport voice vlan 20" in acc
    assert "ip route 0.0.0.0 0.0.0.0 10.99.0.1" in acc


def test_generated_configs_pass_audit():
    for host, cfg in render_all(net()).items():
        r = audit(cfg)
        bad = [f["title"] for f in r["findings"] if f["severity"] != "info"]
        assert not bad, f"{host}: {bad}"
        assert r["score"] == 100


def test_audit_catches_insecure_config():
    cfg = """hostname OLD
enable password cisco
username admin password 0 cisco
snmp-server community public RO
snmp-server community private RW
ip http server
interface GigabitEthernet0/1
 switchport mode access
interface GigabitEthernet0/2
 switchport mode trunk
line vty 0 4
 transport input telnet ssh
 exec-timeout 0 0
"""
    titles = {f["title"]: f["severity"] for f in audit(cfg)["findings"]}
    assert titles["Telnet allowed on VTY"] == "high"
    assert titles["SNMP community string with write access"] == "critical"
    assert "enable password uses reversible encryption" in titles
    assert "Access port without BPDU Guard" in titles
    assert "Trunk uses native VLAN 1" in titles
    assert audit(cfg)["score"] == 0


def test_newline_injection_rejected():
    d = json.loads(EXAMPLE.read_text())
    d["devices"][0]["interfaces"][0]["description"] = "x\nusername evil privilege 15 secret 0 x"
    with pytest.raises(ValidationError):
        Network.model_validate(d)


def test_bad_references_rejected():
    d = json.loads(EXAMPLE.read_text())
    d["links"][0]["a_if"] = "GigabitEthernet9/9/9"
    with pytest.raises(ValidationError):
        Network.model_validate(d)


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))


@pytest.mark.parametrize("sep", ["\n", "\r", " ", " ", "\x0b", "\x0c", "\x85", "\x1e"])
def test_no_line_break_of_any_kind_reaches_a_config(sep):
    """str.splitlines() (used by push) splits on all of these, so each would become its own command."""
    from pydantic import ValidationError
    from oneconfig.model import Acl, Interface
    with pytest.raises(ValidationError):
        Interface(name="Gi1/0/1", description=f"uplink{sep}username backdoor privilege 15 secret 0 x")
    with pytest.raises(ValidationError):
        Acl(name="X", entries=[f"permit ip any any{sep}username backdoor secret 0 x"])
    assert Interface(name="Gi1/0/1", description="Uplink to CORE-SW1 (Te1/1/1) #1 & #2 [lab]").description


@pytest.mark.parametrize("platform", ["nx-os", "eos"])
def test_ios_interface_names_rejected_on_other_platforms(platform):
    data = json.loads(EXAMPLE.read_text())
    d = next(x for x in data["devices"] if x["role"] == "router")
    d["platform"] = platform
    with pytest.raises(ValidationError, match=f"not a {platform} interface name"):
        Network.model_validate(data)
