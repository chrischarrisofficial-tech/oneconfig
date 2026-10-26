"""Safe push to PAN-OS against a simulated firewall: named snapshot, candidate + commit, health check, rollback by
loading the snapshot, and refusing to touch a candidate someone else is editing."""
from ipaddress import ip_network

import pytest

from fakelab import FIX, PASSWORD, USER, FakePan, start_ssh

from oneconfig import push
from oneconfig.diff import pan_plan
from oneconfig.render import render
from platforms import example

LOGIN = {"username": USER, "password": PASSWORD, "secret": ""}


@pytest.fixture
def lab(monkeypatch, tmp_path):
    monkeypatch.setattr(push, "BACKUPS", tmp_path)
    dev = FakePan("EDGE-FW1", (FIX / "panos" / "running_set.txt").read_text().replace("EDGE-FW2", "EDGE-FW1"))
    port = start_ssh(dev)
    real = push.connect
    monkeypatch.setattr(push, "connect", lambda ip, login, **kw: real("127.0.0.1", login, port=port, timeout=8, nos=kw.get("nos", "ios-xe")))
    net = example("panos")
    net.security.mgmt_subnet = ip_network("127.0.0.0/8")
    d = net.devices[0]
    d.mgmt_ip = "10.99.2.7"
    values = {p: f"Lab{p.replace('-', '')}Value9!" for p in push.placeholders(render(d, net))}
    values.update({"ADMIN-USER": USER, "SNMP-USER": "snmpops"})
    return dev, net, d, values


def test_push_snapshots_commits_and_converges(lab):
    dev, net, d, values = lab
    before = dev.text()
    p = push.plan_device(d, net, LOGIN, values)
    assert not p["blockers"] and p["os"] == "panos" and dev.text() == before and any("no commit-confirm" in w for w in p["warnings"])
    assert "delete rulebase security rules allow-all" in p["remove"]
    assert not any(v in "\n".join(p["add_shown"]) for k, v in values.items() if k not in push.IDENTIFIERS)
    r = push.apply_device(p, values, LOGIN, removals=["delete rulebase security rules allow-all"], log=lambda *_: None)
    assert r["status"] == "pushed" and r["snapshot"] in dev.files and dev.files[r["snapshot"]] == before.strip().splitlines()
    assert "set rulebase security rules allow-all action allow" not in dev.running
    assert pan_plan(p["candidate"], dev.text(), login_user=USER)["add"] == []
    order = [next(i for i, c in enumerate(dev.commands) if c.startswith(x)) for x in ("configure", "show config diff", "save config to", "commit")]
    assert order == sorted(order), dev.commands
    rules = list(dict.fromkeys(l.split()[4] for l in dev.running if l.startswith("set rulebase security rules ")))
    assert rules[0] == "BLOCK-ICMP-PROBES" and rules[-1] == "DMZ-TO-INTERNET-WEB"  # OneConfig's order
    assert dev.authorize(USER, values["ADMIN-SECRET"]) and not dev.authorize(USER, PASSWORD)  # the SHA-256 phash works


def test_rejected_line_reverts_the_candidate(lab):
    dev, net, d, values = lab
    before = dev.text()
    p = push.plan_device(d, net, LOGIN, values)
    p["add"].append("set bogus statement")
    with pytest.raises(push.PushError, match="rejected.*Invalid syntax.*Nothing was changed"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert dev.text() == before


def test_someone_elses_uncommitted_changes_block_the_push(lab):
    dev, net, d, values = lab
    p = push.plan_device(d, net, LOGIN, values)
    dev.dirty = dev.running + ["set address THEIRS ip-netmask 192.0.2.9"]
    with pytest.raises(push.PushError, match="uncommitted changes from someone else"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert "set address THEIRS ip-netmask 192.0.2.9" not in dev.running


def test_health_drop_loads_the_snapshot_back(lab):
    dev, net, d, values = lab
    before = dev.text()
    next(i for i in d.interfaces if i.name == "ethernet1/2").shutdown = True
    p = push.plan_device(d, net, LOGIN, values)
    with pytest.raises(push.PushError, match="Health got worse: interfaces up.*rolled back"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert dev.text() == before


def test_manual_rollback_restores_the_snapshot(lab):
    dev, net, d, values = lab
    before = dev.text()
    p = push.plan_device(d, net, LOGIN, values)
    r = push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert dev.text() != before
    push.rollback_device("10.99.2.7", r["login"], r["snapshot"], log=lambda *_: None, fallback_login=LOGIN, nos="panos")
    assert dev.text() == before and dev.authorize(USER, PASSWORD)


def test_failed_snapshot_load_is_not_reported_as_rolled_back(lab):
    dev, net, d, values = lab
    dev.files = type("Forgetful", (dict,), {"__setitem__": lambda self, k, v: None})()  # "saved", but the file is gone
    next(i for i in d.interfaces if i.name == "ethernet1/2").shutdown = True
    p = push.plan_device(d, net, LOGIN, values)
    with pytest.raises(push.PushError, match="Restore oneconfig-.*yourself") as e:
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert "was rolled back" not in str(e.value)
    with pytest.raises(push.PushError, match="load config from .* failed"):
        new = {**LOGIN, "password": values["ADMIN-SECRET"]}  # the change stayed, and it set a new admin password
        push.rollback_device("10.99.2.7", new, "oneconfig-missing.xml", log=lambda *_: None, nos="panos")
