"""Safe push to FortiOS against a simulated FortiGate: flash revision, one transaction committed under the revert
timer, health check on a new session, then execute cfg save; anything wrong reboots the firewall to its saved config."""
from ipaddress import ip_network

import pytest

from fakelab import FIX, PASSWORD, USER, FakeForti, start_ssh

from oneconfig import push
from oneconfig.diff import fos_plan
from oneconfig.render import render
from platforms import example

LOGIN = {"username": USER, "password": PASSWORD, "secret": ""}
RUNNING = (FIX / "fortios" / "running.conf").read_text().replace("EDGE-FW2", "EDGE-FW1")


@pytest.fixture
def lab(monkeypatch, tmp_path):
    monkeypatch.setattr(push, "BACKUPS", tmp_path)
    monkeypatch.setattr(push, "RETRY_WAIT", 0)
    dev = FakeForti("EDGE-FW1", RUNNING.replace('    edit "DNS"\n        set tcp-portrange 53\n        set udp-portrange 53\n    next\n', ""))
    port = start_ssh(dev)
    real = push.connect
    monkeypatch.setattr(push, "connect", lambda ip, login, **kw: real("127.0.0.1", login, port=port, timeout=8, nos=kw.get("nos", "ios-xe")))
    net = example("fortios")
    net.security.mgmt_subnet = ip_network("127.0.0.0/8")
    d = net.devices[0]
    d.mgmt_ip = "10.99.2.8"
    values = {p: f"Lab{p.replace('-', '')}Value9!" for p in push.placeholders(render(d, net))}
    values.update({"ADMIN-USER": USER, "SNMP-USER": "snmpops"})
    return dev, net, d, values


def test_push_commits_in_a_transaction_and_saves(lab):
    dev, net, d, values = lab
    before = dev.text()
    p = push.plan_device(d, net, LOGIN, values)
    assert not p["blockers"] and p["os"] == "fortios" and push._sha(dev.text()) == push._sha(before)  # nothing changed (ENC values differ per read)
    assert any("rolls back by rebooting" in w for w in p["warnings"]) and any("policy NAT" in w for w in p["warnings"])
    assert "delete firewall policy 7 (allow-all)" in p["remove"] and not any(v in "\n".join(p["add_shown"]) for k, v in values.items() if k not in push.IDENTIFIERS)
    r = push.apply_device(p, values, LOGIN, removals=["delete firewall policy 7 (allow-all)"], log=lambda *_: None)
    assert r["status"] == "pushed" and r["snapshot"] == "1" and dev.revisions[0][0].startswith("oneconfig-")
    assert fos_plan(p["candidate"], dev.text(), login_user=USER)["add"] == []
    order = [next(i for i, c in enumerate(dev.commands) if c.startswith(x)) for x in
             ("execute backup config flash", "set cfg-save revert", "execute config-transaction start", "execute config-transaction commit", "execute cfg save")]
    assert order == sorted(order), dev.commands
    assert dev.get(["system global"], "cfg-save") == ["automatic"] and dev.saved == dev.running  # saved, timer off
    names = [e["sets"]["name"][0][0] for e in dev.running["subs"]["firewall policy"]["entries"].values()]
    assert names == ["INSIDE-TO-DMZ-WEB", "INSIDE-TO-INTERNET-WEB", "DNS-TO-INTERNET", "INTERNET-TO-WEB", "DMZ-TO-INTERNET-WEB"]
    assert dev.authorize(USER, PASSWORD)  # a password already on the firewall is left alone (secrets are set once)


def test_rejected_line_aborts_the_transaction(lab):
    dev, net, d, values = lab
    before = dev.text()
    p = push.plan_device(d, net, LOGIN, values)
    p["add"] += ["config system global", "    set bogus 1", "end"]
    with pytest.raises(push.PushError, match="rejected.*bogus.*Nothing was changed"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert "execute config-transaction abort" in dev.commands and dev.get(["system global"], "cfg-save") == ["automatic"]
    assert fos_plan(before, dev.text())["add"] == [] and "INSIDE-TO-DMZ-WEB" not in dev.text()  # only the timer settings were touched


def test_health_drop_reboots_to_the_saved_config(lab):
    dev, net, d, values = lab
    saved = dev.text()
    next(i for i in d.interfaces if i.name == "port2").shutdown = True
    p = push.plan_device(d, net, LOGIN, values)
    with pytest.raises(push.PushError, match="Health got worse: interfaces up.*rebooting to its saved configuration.*turned revert mode off"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert dev.reboots == 1 and "cfg-revert-timeout" not in saved and dev.get(["system interface", "port2"], "status") != ["down"]
    assert dev.get(["system global"], "cfg-save") == ["automatic"] == dev.saved["subs"]["system global"]["sets"]["cfg-save"][0]


def test_unconfirmed_change_is_lost_when_the_revert_timer_reboots(lab):
    dev, net, d, values = lab
    p = push.plan_device(d, net, LOGIN, values)
    p_confirm = push._fortios_apply
    seen = {}

    def no_confirm(*a, **kw):  # stop after the commit, as if OneConfig lost the session
        snap, out, confirm, revert = p_confirm(*a, **kw)
        seen["running"] = dev.text()
        raise push.PushError("session lost")
    push.APPLY["fortios"] = no_confirm
    try:
        with pytest.raises(push.PushError):
            push.apply_device(p, values, LOGIN, log=lambda *_: None)
    finally:
        push.APPLY["fortios"] = p_confirm
    assert "INSIDE-TO-DMZ-WEB" in seen["running"]  # committed and live, but not saved
    dev.reboot()  # the revert timer runs out
    assert "INSIDE-TO-DMZ-WEB" not in dev.text()


def test_manual_rollback_restores_the_revision(lab):
    dev, net, d, values = lab
    original = dev.text()
    p = push.plan_device(d, net, LOGIN, values)
    r = push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert "INSIDE-TO-DMZ-WEB" in dev.text()
    push.rollback_device("10.99.2.8", r["login"], r["snapshot"], log=lambda *_: None, fallback_login=LOGIN, nos="fortios")
    assert "INSIDE-TO-DMZ-WEB" not in dev.text() and dev.reboots == 1 and dev.authorize(USER, PASSWORD)
    assert fos_plan(original, dev.text())["add"] == []


def test_predefined_service_name_blocks_the_plan(lab):
    dev, net, d, values = lab
    dev.running["subs"]["firewall service custom"]["entries"] = {"WEB": {"sets": {}, "unset": set(), "subs": {}, "entries": None}}
    p = push.plan_device(d, net, LOGIN, values)
    assert any("already has a service named WEB" in b for b in p["blockers"])


def test_model_without_a_log_disk_skips_disk_logging(lab):
    dev, net, d, values = lab
    dev.disk = False
    p = push.plan_device(d, net, LOGIN, values)
    assert "config log disk setting" not in p["add"] and any("no log disk" in w for w in p["warnings"])


def test_reload_that_does_not_reboot_never_saves_the_change(lab, monkeypatch):
    """If execute cfg reload doesn't run, the change is still live: OneConfig must not turn revert mode off (that would
    save it); the revert timer reboots the firewall instead."""
    import fakelab
    dev, net, d, values = lab
    real = fakelab._FortiSession.reply
    monkeypatch.setattr(fakelab._FortiSession, "reply", lambda self, line: "Unknown action 0\nCommand fail. Return code -1"
                        if line.strip() == "execute cfg reload" else real(self, line))
    next(i for i in d.interfaces if i.name == "port2").shutdown = True
    p = push.plan_device(d, net, LOGIN, values)
    with pytest.raises(push.PushError, match="didn't run.*still live until the 300 second revert timer"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert dev.get(["system global"], "cfg-save") == ["revert"]  # still armed: the timer will undo it
    assert dev.saved["subs"]["system interface"]["entries"]["port2"]["sets"].get("status", ([], ""))[0] != ["down"]
    dev.reboot()  # the revert timer runs out
    assert dev.get(["system interface", "port2"], "status") != ["down"]
