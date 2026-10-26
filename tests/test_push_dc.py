"""Safe push to NX-OS and Arista EOS against simulated devices that implement each OS's rollback mechanism:
EOS configuration sessions with a commit timer, NX-OS checkpoints plus configure replace with commit-timeout."""
import re
import time
from ipaddress import ip_network
from pathlib import Path

import pytest

from fakelab import PASSWORD, USER, FakeDevice, start_ssh

from oneconfig import push
from oneconfig.seal import unseal
from oneconfig.diff import plan as diff_plan
from oneconfig.render import render
from platforms import example

LOGIN = {"username": USER, "password": PASSWORD, "secret": ""}
BROWNFIELD = {
    "nx-os": "hostname ACC-SW1\nfeature telnet\nsnmp-server community public group network-operator\n"
             "interface Ethernet1/1\n  switchport\n  switchport mode access\n  switchport access vlan 10\n"
             "interface Vlan99\n  ip address 10.99.0.11/24\nline vty\n  exec-timeout 30\n",
    "eos": "hostname ACC-SW1\nsnmp-server community public ro\ninterface Ethernet1\n   switchport mode access\n"
           "   switchport access vlan 10\ninterface Vlan99\n   ip address 10.99.0.11/24\nmanagement ssh\n   idle-timeout 60\n",
}
FLAVOR = {"nx-os": "nxos", "eos": "eos"}


@pytest.fixture(params=["nx-os", "eos"])
def lab(request, monkeypatch, tmp_path):
    nos = request.param
    monkeypatch.setattr(push, "BACKUPS", tmp_path)
    dev = FakeDevice("ACC-SW1", BROWNFIELD[nos], seconds_per_minute=6, flavor=FLAVOR[nos])  # 1 minute = 6 s
    port = start_ssh(dev)
    real = push.connect
    monkeypatch.setattr(push, "connect", lambda ip, login, **kw: real("127.0.0.1", login, port=port, timeout=8, nos=kw.get("nos", "ios-xe")))
    net = example(nos)
    net.security.mgmt_subnet = ip_network("127.0.0.0/8")  # the test client connects from 127.0.0.1
    d = next(x for x in net.devices if x.hostname == "ACC-SW1")
    d.mgmt_ip = "10.99.0.11"
    values = {p: f"Lab{p.replace('-', '')}Value9" for p in push.placeholders(render(d, net))}
    values.update({"ADMIN-USER": USER, "SNMP-USER": "snmpops"})
    return nos, dev, net, d, values


def test_push_confirms_converges_and_saves(lab):
    nos, dev, net, d, values = lab
    before = dev.cfg.text()
    p = push.plan_device(d, net, LOGIN, values)
    assert not p["blockers"] and p["add"] and dev.cfg.text() == before  # planning changes nothing
    assert not any(v in "\n".join(p["add_shown"]) for k, v in values.items() if k not in push.IDENTIFIERS)
    community = next(x for x in p["remove"] if "community" in x)
    old = [f"oneconfig-2026010{i}-120000" for i in range(1, 5)]  # four earlier pushes, plus a file OneConfig didn't make
    store = dev.files if nos == "eos" else dev.checkpoints
    store.update({(f"flash:{o}.cfg" if nos == "eos" else o.replace("oneconfig-", "oneconfig-pre-")): "" for o in old})
    dev.files.update({"flash:mine.cfg": "", "bootflash:mine.cfg": ""})
    if nos == "nx-os":
        dev.files["bootflash:oneconfig-target-20260101-120000.cfg"] = ""  # left over from a push that failed midway
    r = push.apply_device(p, values, LOGIN, removals=[community], log=lambda *_: None)
    assert r["status"] == "pushed" and r["os"] == nos and dev.pre is None and dev.startup == dev.cfg.text()
    run = dev.cfg.text()
    assert "snmp-server community" not in run and before in unseal(Path(r["backup"]).read_bytes())  # what the device showed, under its !Command / !Time header
    left = diff_plan(p["candidate"], run, login_user=USER)["add"]
    assert left == [] if nos == "eos" else left == ["copp profile strict"], left  # NX-OS: CoPP is set by hand (it prompts)
    cmds = [c.strip() for c in dev.commands]
    if nos == "eos":
        assert r["snapshot"].startswith("flash:oneconfig-")
        assert any(re.match(r"configure session oneconfig-\S+$", c) for c in cmds) and "commit timer 00:05:00" in cmds
        assert any(re.match(r"configure session oneconfig-\S+ commit$", c) for c in cmds)
    else:
        order = [next(i for i, c in enumerate(cmds) if re.match(pat, c)) for pat in (
            r"checkpoint oneconfig-pre-", r"copy running-config bootflash:oneconfig-target-", r"rollback running-config checkpoint",
            r"configure replace bootflash:\S+ verbose commit-timeout 300$", r"configure replace commit$")]
        assert order == sorted(order), cmds
    kept = sorted(k for k in store if "oneconfig-" in k)
    assert len(kept) == push.KEEP and r["snapshot"].removeprefix("flash:") in "".join(kept), kept  # newest kept, incl. this push
    assert not any("oneconfig-target-" in f for f in dev.files) and {"flash:mine.cfg", "bootflash:mine.cfg"} <= set(dev.files)
    assert dev.authorize(USER, values["ADMIN-SECRET"])  # the new local password is what the verify login used


def test_rejected_line_changes_nothing(lab):
    nos, dev, net, d, values = lab
    before = dev.cfg.text()
    p = push.plan_device(d, net, LOGIN, values)
    p["add"].append("bogus command")
    with pytest.raises(push.PushError, match="rejected.*Invalid input" + (".*Nothing was changed" if nos == "eos" else ".*rolled back")):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert dev.cfg.text() == before


def test_health_drop_is_rolled_back_by_the_device_timer(lab):
    nos, dev, net, d, values = lab
    before = dev.cfg.text()
    next(i for i in d.interfaces if i.name == "Vlan99").shutdown = True  # would take the management SVI down
    p = push.plan_device(d, net, LOGIN, values)
    with pytest.raises(push.PushError, match="Health got worse: interfaces up.*(commit timer|commit timeout)"):
        push.apply_device(p, values, LOGIN, revert_minutes=1 if nos == "eos" else 5, log=lambda *_: None)
    assert dev.pre is not None  # change still live, timer running: the device rolls back on its own
    for _ in range(80):
        if dev.pre is None:
            break
        time.sleep(0.5)
    assert dev.cfg.text() == before


def test_manual_rollback_restores_the_snapshot(lab):
    nos, dev, net, d, values = lab
    p = push.plan_device(d, net, LOGIN, values)
    community = next(x for x in p["remove"] if "community" in x)
    r = push.apply_device(p, values, LOGIN, removals=[community], log=lambda *_: None)
    assert "community" not in dev.cfg.text()
    push.rollback_device("10.99.0.11", r["login"], r["snapshot"], log=lambda *_: None, fallback_login=LOGIN, nos=nos)
    assert "snmp-server community public" in dev.cfg.text() and dev.authorize(USER, PASSWORD)
