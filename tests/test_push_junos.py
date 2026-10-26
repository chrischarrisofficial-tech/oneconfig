"""Safe push to Junos against a simulated device: exclusive candidate, commit check, commit confirmed with its timer,
rollback, and saved configurations in /var/tmp."""
import time
from ipaddress import ip_network
from pathlib import Path

import pytest

from fakelab import PASSWORD, USER, FakeJunos, start_ssh

from oneconfig import push
from oneconfig.seal import unseal
from oneconfig.diff import junos_plan
from oneconfig.render import render
from platforms import example

LOGIN = {"username": USER, "password": PASSWORD, "secret": ""}
BROWNFIELD = """set system host-name ACC-SW1
set system services telnet
set system services ssh
set snmp community public authorization read-only
set interfaces ge-0/0/0 unit 0 family ethernet-switching interface-mode access
set interfaces irb unit 99 family inet address 10.99.0.11/24
"""


@pytest.fixture
def lab(monkeypatch, tmp_path):
    monkeypatch.setattr(push, "BACKUPS", tmp_path)
    dev = FakeJunos("ACC-SW1", BROWNFIELD, seconds_per_minute=1)  # 1 minute = 1 s
    port = start_ssh(dev)
    real = push.connect
    monkeypatch.setattr(push, "connect", lambda ip, login, **kw: real("127.0.0.1", login, port=port, timeout=8, nos=kw.get("nos", "ios-xe")))
    net = example("junos")
    net.security.mgmt_subnet = ip_network("127.0.0.0/8")  # the test client connects from 127.0.0.1
    d = next(x for x in net.devices if x.hostname == "ACC-SW1")
    d.mgmt_ip = "10.99.0.11"
    values = {p: f"Lab{p.replace('-', '')}Value9!" for p in push.placeholders(render(d, net))}
    values.update({"ADMIN-USER": USER, "SNMP-USER": "snmpops"})
    return dev, net, d, values


def test_hashed_placeholders_are_filled_with_sha512_crypt():
    from oneconfig.junos import sha512_verify
    text = 'set system login user <ADMIN-USER> authentication encrypted-password "<ADMIN-SECRET.SHA512>"'
    assert push.placeholders(text) == ["ADMIN-SECRET", "ADMIN-USER"]
    out = push.fill(text, {"ADMIN-USER": "ops", "ADMIN-SECRET": "S3cret-Value!"})
    assert sha512_verify("S3cret-Value!", out.split('"')[1]) and "S3cret" not in out
    assert push.mask([out], {"ADMIN-SECRET": "S3cret-Value!"}) == ['set system login user ops authentication encrypted-password "<HASHED>"']


def test_push_commits_confirmed_then_confirms(lab):
    dev, net, d, values = lab
    before = dev.text()
    p = push.plan_device(d, net, LOGIN, values)
    assert not p["blockers"] and p["os"] == "junos" and dev.text() == before  # planning changes nothing
    assert "delete system services telnet" in p["remove"] and "delete snmp community public" in p["remove"]
    assert not any(v in "\n".join(p["add_shown"]) for k, v in values.items() if k not in push.IDENTIFIERS)
    dev.files.update({f"/var/tmp/oneconfig-2026010{i}-120000.conf": [] for i in range(1, 5)} | {"/var/tmp/mine.conf": []})
    r = push.apply_device(p, values, LOGIN, removals=p["remove"], log=lambda *_: None)
    assert r["status"] == "pushed" and r["os"] == "junos" and dev.pre is None and dev.timer is not None and not dev.timer.is_alive()
    run = dev.text()
    assert "set system services telnet" not in run and "snmp community" not in run and unseal(Path(r["backup"]).read_bytes()) == before
    assert junos_plan(p["candidate"], run, login_user=USER)["add"] == []
    order = [next(i for i, c in enumerate(dev.commands) if c.startswith(x)) for x in (
        "show configuration | save /var/tmp/oneconfig-", "configure exclusive", "commit check", "commit confirmed 5", 'commit comment "oneconfig confirmed"')]
    assert order == sorted(order), dev.commands
    assert dev.authorize(USER, values["ADMIN-SECRET"]) and not dev.authorize(USER, PASSWORD)  # the hashed password works
    assert not dev.authorize(USER, values["ADMIN-SECRET"], client="192.0.2.9")  # and the lo0 filter keeps outsiders away
    kept = sorted(f for f in dev.files if "oneconfig-" in f)
    assert len(kept) == push.KEEP and r["snapshot"] in kept and "/var/tmp/mine.conf" in dev.files


def test_rejected_line_changes_nothing(lab):
    dev, net, d, values = lab
    before = dev.text()
    p = push.plan_device(d, net, LOGIN, values)
    p["add"].append("set bogus statement")
    with pytest.raises(push.PushError, match="rejected.*syntax error.*Nothing was changed"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert dev.text() == before and dev.pre is None


def test_health_drop_is_rolled_back_at_once(lab):
    dev, net, d, values = lab
    before = dev.text()
    next(i for i in d.interfaces if i.name == "irb.99").shutdown = True  # would take the management interface down
    p = push.plan_device(d, net, LOGIN, values)
    with pytest.raises(push.PushError, match="Health got worse: interfaces up.*The change was rolled back"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert dev.text() == before


def test_lost_session_is_rolled_back_by_the_timer(lab):
    dev, net, d, values = lab
    before = dev.text()
    p = push.plan_device(d, net, LOGIN, values)
    real = push._junos_apply

    def apply_then_drop(c, *a):
        snap, out, confirm, revert = real(c, *a)
        def gone(why):
            raise OSError("session lost")
        return snap, out, confirm, gone
    push.APPLY["junos"] = apply_then_drop
    try:
        p["add"].append('set system login user ' + USER + ' authentication encrypted-password "$6$x$y"')  # locks the verify login out
        with pytest.raises(push.PushError, match="roll itself back within 1 minutes"):
            push.apply_device(p, values, LOGIN, revert_minutes=1, log=lambda *_: None)
    finally:
        push.APPLY["junos"] = real
    assert dev.pre is not None
    for _ in range(40):
        if dev.pre is None:
            break
        time.sleep(0.25)
    assert dev.text() == before


def test_manual_rollback_restores_the_snapshot(lab):
    dev, net, d, values = lab
    p = push.plan_device(d, net, LOGIN, values)
    r = push.apply_device(p, values, LOGIN, removals=["delete snmp community public"], log=lambda *_: None)
    assert "snmp community" not in dev.text()
    push.rollback_device("10.99.0.11", r["login"], r["snapshot"], log=lambda *_: None, fallback_login=LOGIN, nos="junos")
    assert "set snmp community public authorization read-only" in dev.text() and dev.authorize(USER, PASSWORD)
