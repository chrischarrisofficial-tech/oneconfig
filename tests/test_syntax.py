"""Generated configs for every platform: golden files catch unintended changes, and for NX-OS / EOS / Junos / ASA / PAN-OS / FortiOS every line
must be accepted by Batfish's own parser for that OS, match a command in DISA's fix text for that vendor, or be
listed (with its source) in syntax/allow_<os>.txt."""
import os
import re
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "syntax"))
from bfcheck import available, rejected  # noqa: E402
import fosspec  # noqa: E402
import panspec  # noqa: E402
from shapes import shape  # noqa: E402

from oneconfig.render import render  # noqa: E402
from platforms import example  # noqa: E402

GOLDEN = Path(__file__).parent / "fixtures" / "golden"
SYN = Path(__file__).parent / "syntax"
KEY = {"nx-os": "nxos", "eos": "eos", "junos": "junos", "asa": "asa"}
SAMPLE = {"ADMIN-USER": "netadmin1", "SNMP-USER": "snmpops1", "BACKUP-USER": "backup1"}


@pytest.mark.parametrize("platform", ["ios-xe", "nx-os", "eos", "junos", "asa", "panos", "fortios"])
def test_golden(platform):
    """Set ONECONFIG_UPDATE_GOLDEN=1 to accept intended changes, then review the diff."""
    net = example(platform)
    for d in net.devices:
        cfg = render(d, net, today=date(2026, 10, 17))
        f = GOLDEN / platform / f"{d.hostname}.cfg"
        if os.environ.get("ONECONFIG_UPDATE_GOLDEN"):
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(cfg)
        assert cfg == f.read_text(), f"{f} changed; rerun with ONECONFIG_UPDATE_GOLDEN=1 if intended"


def _allowed(key):
    disa = set((SYN / f"disa_{key}_shapes.txt").read_text().splitlines())
    doc = {shape(l.split(" | ")[0]) for l in (SYN / f"allow_{key}.txt").read_text().splitlines() if l and not l.startswith("#")}
    return disa | doc


@pytest.mark.skipif(not available(), reason="Batfish parser not built: run tests/syntax/build_parser.sh")
@pytest.mark.parametrize("platform", ["nx-os", "eos", "junos", "asa"])
def test_every_line_is_known_good_syntax(platform):
    key, ok, net = KEY[platform], _allowed(KEY[platform]), example(platform)
    unknown = []
    for d in (x for x in net.devices if x.platform == platform):
        cfg = re.sub(r"<([A-Z0-9][A-Z0-9.-]*)>", lambda m: SAMPLE.get(m[1], "Sample7Value9"), render(d, net))
        unknown += [f"{d.hostname}: {line.strip()}  ({why[:70]})" for line, why in rejected(key, cfg) if shape(line) not in ok]
    assert not unknown, "Lines neither Batfish nor DISA nor a cited doc vouch for:\n" + "\n".join(unknown)


@pytest.mark.skipif(not panspec.available(), reason="PAN-OS specs not fetched: run tests/syntax/build_panspec.sh")
def test_every_panos_line_is_known_good_syntax():
    """PAN-OS: Palo Alto's own config specs accept the line, or Palo Alto's Iron-Skillet configs or a cited doc show it.
    (Batfish's Palo Alto grammar skips whole sections without checking them, so it isn't used here.)"""
    tree, net = panspec.build(), example("panos")
    ok = {l for l in (SYN / "vendor_panos_shapes.txt").read_text().splitlines() if l and not l.startswith("#")} | \
        {shape(l.split(" | ")[0]) for l in (SYN / "allow_panos.txt").read_text().splitlines() if l and not l.startswith("#")}
    unknown = []
    for d in (x for x in net.devices if x.platform == "panos"):
        for line in render(d, net).splitlines():
            line = re.sub(r"<([A-Z0-9][A-Z0-9.-]*)>", lambda m: SAMPLE.get(m[1], "Sample7Value9"), line)
            if line.startswith("set ") and (why := panspec.check(tree, line)) and shape(line) not in ok:
                unknown.append(f"{d.hostname}: {line}  ({why[:70]})")
    assert not unknown, "Lines neither Palo Alto's specs nor Iron-Skillet nor a cited doc vouch for:\n" + "\n".join(unknown)
    assert panspec.check(tree, "set rulebase security rules R action alow") and panspec.check(tree, "set zone Z network layer4 ethernet1/1")


@pytest.mark.skipif(not fosspec.available(), reason="FortiOS schema not fetched: run tests/syntax/build_fosspec.sh")
def test_every_fortios_line_is_known_good_syntax():
    """FortiOS: Fortinet's own configuration schema has every table, field and value, on 7.4.4 and on 7.6 (first and
    newest release it knows); or a cited source vouches for the block (syntax/allow_fortios.txt)."""
    spec, net = fosspec.load(), example("fortios")
    allow = {l.split(" | ")[0] for l in (SYN / "allow_fortios.txt").read_text().splitlines() if l and not l.startswith("#")}
    for d in (x for x in net.devices if x.platform == "fortios"):
        cfg = re.sub(r"<([A-Z0-9][A-Z0-9.-]*)>", lambda m: SAMPLE.get(m[1], "Sample7Value9"), render(d, net))
        assert fosspec.check(spec, cfg, allow) == [], d.hostname
    bad = fosspec.check(spec, "config system global\n    set admintimeout ten\n    set admin-lockout-treshold 3\nend\n"
                              "config firewall policy\n    edit 1\n        set action alow\n    next\nend\n")
    assert [b.split(":")[0] for b in bad] == ["line 2", "line 3", "line 7"], bad


@pytest.mark.skipif(not available(), reason="Batfish parser not built: run tests/syntax/build_parser.sh")
def test_checker_catches_bad_syntax():
    bad = rejected("eos", "hostname X\ninterface Ethernet1\n   switchport mode acess\n   no shutdown\nrouter bgp 1\n   neighbor 1.1.1.1 remot-as 2\n")
    assert [l.strip() for l, _ in bad] == ["switchport mode acess", "neighbor 1.1.1.1 remot-as 2"]
    assert rejected("nxos", "hostname X\nfeature bgp\nrouter bgp 1\n  neighbor 1.1.1.1\n    remote-as 2\n") == []
    assert [l for l, _ in rejected("junos", "set system host-name X\nset protocols ospf area 0.0.0.0 intrface ge-0/0/0.0\n")] == \
        ["set protocols ospf area 0.0.0.0 intrface ge-0/0/0.0"]


@pytest.mark.skipif(not available(), reason="Batfish parser not built: run tests/syntax/build_parser.sh")
@pytest.mark.parametrize("platform", ["ios-xe", "nx-os", "eos"])
def test_hmac_sha1_ospf_for_mixed_networks_is_valid_syntax(platform):
    """With a Junos device running OSPF, the other vendors switch their OSPF keys to HMAC-SHA-1."""
    from oneconfig.model import Network
    net, j = example(platform), example("junos")
    data = net.model_dump(mode="json")
    data["devices"][0], data["links"] = j.model_dump(mode="json")["devices"][0], []
    mixed = Network.model_validate(data)
    core = next(d for d in mixed.devices if d.hostname == "CORE-SW1")
    cfg = re.sub(r"<([A-Z0-9][A-Z0-9.-]*)>", lambda m: SAMPLE.get(m[1], "Sample7Value9"), render(core, mixed))
    assert re.search(r"cryptographic-algorithm hmac-sha-1$|message-digest-key 1 sha1 ", cfg, re.M)
    if platform != "ios-xe":
        ok = _allowed(KEY[platform])
        assert [l for l, _ in rejected(KEY[platform], cfg) if shape(l) not in ok] == []
