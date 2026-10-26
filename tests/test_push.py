from pathlib import Path

import pytest

from fakelab import PASSWORD, USER, FakeDevice, start_ssh

from oneconfig import push
from oneconfig.seal import unseal
from oneconfig.diff import plan as diff_plan
from oneconfig.model import Network
from oneconfig.render import render

FIX = Path(__file__).parent / "fixtures"
EXAMPLE = Path(__file__).parents[1] / "oneconfig" / "examples" / "campus.json"
LOGIN = {"username": USER, "password": PASSWORD, "secret": ""}


@pytest.fixture
def lab(monkeypatch, tmp_path):
    """ACC-SW1 as a brownfield fake device reachable over real SSH; returns (device, net, values)."""
    monkeypatch.setattr(push, "BACKUPS", tmp_path)
    dev = FakeDevice("ACC-SW1", (FIX / "brownfield_acc1.cfg").read_text(), seconds_per_minute=12)  # 5 min timer = 60 s
    port = start_ssh(dev)
    real = push.connect
    monkeypatch.setattr(push, "connect", lambda ip, login, **kw: real("127.0.0.1", login, port=port, timeout=8, nos=kw.get("nos", "ios-xe")))
    data = __import__("json").loads(EXAMPLE.read_text())
    data["security"]["mgmt_subnet"] = "127.0.0.0/8"  # the test client connects from 127.0.0.1
    net = Network.model_validate(data)
    d = next(x for x in net.devices if x.hostname == "ACC-SW1")
    d.mgmt_ip = "10.99.0.11"
    values = {p: f"Lab-{p}-Value-9" for p in push.placeholders(render(d, net))}
    values.update({"ADMIN-USER": "admin", "SNMP-USER": "oneconfig"})
    return dev, net, values


def _acc(net):
    return next(x for x in net.devices if x.hostname == "ACC-SW1")


def test_successful_push_converges_and_saves(lab):
    dev, net, values = lab
    before = dev.cfg.text()
    p = push.plan_device(_acc(net), net, LOGIN, values)
    assert not p["blockers"] and p["add"]
    assert dev.cfg.text() == before  # planning changes nothing
    assert not any(v in "\n".join(p["add_shown"]) for k, v in values.items() if k not in push.IDENTIFIERS)  # masked
    r = push.apply_device(p, values, LOGIN, removals=p["remove"], log=lambda *_: None)
    assert r["status"] == "pushed" and r["snapshot"] == "flash:oneconfig-archive-1" and r["not_applied"] == []
    assert dev.startup == dev.cfg.text() and dev.pre is None  # confirmed and saved
    assert r["backup"].endswith(".cfg.enc") and b"snmp-server" not in Path(r["backup"]).read_bytes()  # encrypted at rest
    assert unseal(Path(r["backup"]).read_bytes()) == before
    assert Path(r["backup"]).stat().st_mode & 0o077 == 0  # holds type-7 passwords: this user only
    run = dev.cfg.text()
    assert "snmp-server community" not in run and "license boot level" in run
    assert diff_plan(p["candidate"], run, login_user="admin", known_snmp_users=dev.cfg.snmp_users)["add"] == []
    assert dev.authorize("admin", values["ADMIN-SECRET"])  # the new local password is what the verify login used


def test_lockout_is_blocked_and_forced_push_reverts(lab):
    dev, net, values = lab
    net.security.mgmt_subnet = __import__("ipaddress").ip_network("10.99.0.0/24")  # excludes this computer
    p = push.plan_device(_acc(net), net, LOGIN, values)
    assert any("outside the management subnet" in b for b in p["blockers"])
    with pytest.raises(push.PushError, match="Blocked"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    with pytest.raises(push.PushError, match="Could not log in again.*rolled back"):
        push.apply_device(p, values, LOGIN, force=True, log=lambda *_: None)
    assert "access-class MGMT-ACCESS" not in dev.cfg.text() and dev.authorize(USER, PASSWORD)


def test_health_drop_reverts(lab):
    dev, net, values = lab
    vlan99 = next(i for i in _acc(net).interfaces if i.name == "Vlan99")
    vlan99.shutdown = True  # would take the management SVI down
    p = push.plan_device(_acc(net), net, LOGIN, values)
    with pytest.raises(push.PushError, match="Health got worse: interfaces up"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert "shutdown" not in str([k for line, k in dev.cfg.root if line == "interface Vlan99"])


def test_device_rejection_reverts(lab):
    dev, net, values = lab
    p = push.plan_device(_acc(net), net, LOGIN, values)
    p["add"].append("bogus command")
    with pytest.raises(push.PushError, match="rejected.*Invalid input.*rolled back"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)
    assert "vtp mode off" not in dev.cfg.text()


def test_stale_plan_refused(lab):
    dev, net, values = lab
    p = push.plan_device(_acc(net), net, LOGIN, values)
    dev.cfg.apply(["ntp server 10.1.1.1"])  # someone else changed the switch
    with pytest.raises(push.PushError, match="changed after the plan"):
        push.apply_device(p, values, LOGIN, log=lambda *_: None)


def test_dropped_session_leaves_device_to_roll_itself_back(lab, monkeypatch):
    import time
    dev, net, values = lab
    p = push.plan_device(_acc(net), net, LOGIN, values)
    real = push.connect

    def flaky(ip, login, **kw):
        c = real(ip, login, **kw)
        send = c.send_config_set

        def boom(cmds, **k):
            if k.get("enter_config_mode", True):  # the archive setup step goes through normally
                return send(cmds, **k)
            send(cmds[:5], **k)  # part of the change lands, then the link dies
            raise OSError("Socket is closed")
        c.send_config_set = boom
        return c
    monkeypatch.setattr(push, "connect", flaky)
    dev.scale = 0.3  # 1 "minute" = 0.3 s so the device's own timer fires during the test
    with pytest.raises(push.PushError, match="roll itself back within 1 minutes"):
        push.apply_device(p, values, LOGIN, revert_minutes=1, log=lambda *_: None)
    time.sleep(0.6)  # the fake device's timer: 1 "minute" = 0.3 s
    assert dev.pre is None and "spanning-tree mode pvst" in dev.cfg.text()


def test_manual_rollback_restores_snapshot(lab):
    dev, net, values = lab
    p = push.plan_device(_acc(net), net, LOGIN, values)
    r = push.apply_device(p, values, LOGIN, removals=p["remove"], log=lambda *_: None)
    push.rollback_device("10.99.0.11", r["login"], r["snapshot"], log=lambda *_: None, fallback_login=LOGIN)
    assert "snmp-server community public RO" in dev.cfg.text()
    assert dev.authorize(USER, PASSWORD)  # old password back after rollback


def test_fill_and_mask():
    vals = {"ADMIN-USER": "admin", "ENABLE-SECRET": "Very-Secret-123"}
    assert push.fill("username <ADMIN-USER> x\nenable secret <ENABLE-SECRET>", vals) == "username admin x\nenable secret Very-Secret-123"
    assert push.mask(["enable secret Very-Secret-123", "username admin"], vals) == ["enable secret <ENABLE-SECRET>", "username admin"]
    with pytest.raises(push.PushError, match="Missing values for: TACACS-KEY"):
        push.fill("key <TACACS-KEY>", vals)
    assert push.placeholders("! Replace every <ANGLE-BRACKET> placeholder\nkey <TACACS-KEY>") == ["TACACS-KEY"]


def test_only_ticked_removals_are_pushed(lab):
    dev, net, values = lab
    p = push.plan_device(_acc(net), net, LOGIN, values)
    assert {"no snmp-server community public", "no snmp-server community private"} <= set(p["remove"])
    push.apply_device(p, values, LOGIN, removals=["no snmp-server community public", "not a planned line"], log=lambda *_: None)
    run = dev.cfg.text()
    assert "snmp-server community public" not in run and "snmp-server community private" in run


def test_management_on_vlan1_blocks_the_push(lab):
    dev, net, values = lab
    dev.cfg.apply(["interface Vlan1", " ip address 10.99.0.11 255.255.255.0"])
    p = push.plan_device(_acc(net), net, LOGIN, values)
    assert any("Vlan1" in b for b in p["blockers"])


def test_mask_hides_fortios_escaped_secrets():
    """fill() escapes quotes and backslashes for FortiOS; the plan the browser sees must still hide the value."""
    vals = {"ADMIN-SECRET": 'Pa"ss-1234', "NTP-KEY": "back\\slash99"}
    lines = push.fill('    set password "<ADMIN-SECRET>"\n    set key "<NTP-KEY>"', vals, "fortios").splitlines()
    assert push.mask(lines, vals) == ['    set password "<ADMIN-SECRET>"', '    set key "<NTP-KEY>"']


@pytest.mark.parametrize("a,b", [
    ("!Command: show running-config\n!Running configuration last done at: Fri Oct 23 10:00:00 2026\n!Time: Fri Oct 23 15:00:01 2026\nhostname S1\n",
     "!Command: show running-config\n!Running configuration last done at: Fri Oct 23 10:00:00 2026\n!Time: Fri Oct 23 15:02:44 2026\nhostname S1\n"),
    ("! Command: show running-config\n! Time: Fri Oct 23 15:00:01 2026\nhostname L1\n", "! Command: show running-config\n! Time: Fri Oct 23 15:09:59 2026\nhostname L1\n"),
    ('#config-version=FGT100F-7.4.4:user=admin\n    set password ENC SH2nlSm9QL9t\n', '#config-version=FGT100F-7.4.4:user=ops\n    set password ENC SH2Xq81kKdPz\n'),
])
def test_drift_check_ignores_what_changes_on_every_read(a, b):
    """NX-OS and EOS print the current time; FortiOS re-encrypts secrets each read. Same config, same fingerprint."""
    assert push._sha(a) == push._sha(b) and push._sha(a) != push._sha(a.replace("hostname", "hostname X") + "x")


@pytest.mark.parametrize("bad", ["two words-9", "Line-one\nno aaa new-model", "what?Secret-9", 'Quote"Secret-9', "Back\\slash-9", "Tab\tSecret-9", "Ünïcode-Secret"])
def test_values_that_could_break_a_config_line_are_refused(bad):
    """A newline would add commands; a space, ?, quote or backslash breaks the line on at least one OS."""
    cfg = "username <ADMIN-USER> privilege 15 secret <ADMIN-SECRET>\n"
    assert push.bad_values({"ADMIN-USER": "admin", "ADMIN-SECRET": bad}, ["ADMIN-USER", "ADMIN-SECRET"]) == ["ADMIN-SECRET"]
    with pytest.raises(push.PushError, match="ADMIN-SECRET"):
        push.fill(cfg, {"ADMIN-USER": "admin", "ADMIN-SECRET": bad})
    assert push.fill(cfg, {"ADMIN-USER": "admin", "ADMIN-SECRET": "Fine-Secret!9#"}).endswith("secret Fine-Secret!9#")


def test_fortios_takes_quoted_values_but_not_control_characters_or_help():
    cfg = 'set password "<ADMIN-SECRET>"'
    assert push.fill(cfg, {"ADMIN-SECRET": 'Two words "q" \\9'}, "fortios") == 'set password "Two words \\"q\\" \\\\9"'
    for bad in ("Line\nset x", "Why?Secret-9"):
        with pytest.raises(push.PushError):
            push.fill(cfg, {"ADMIN-SECRET": bad}, "fortios")


def test_removals_reach_the_browser_masked_but_distinct(lab):
    dev, net, values = lab
    p = push.plan_device(_acc(net), net, LOGIN, values)
    shown = "\n".join(p["remove_shown"])
    assert "no snmp-server community public" in p["remove"] and "public" not in shown and "private" not in shown
    pub = p["remove_shown"][p["remove"].index("no snmp-server community public")]
    prv = p["remove_shown"][p["remove"].index("no snmp-server community private")]
    assert pub.startswith("no snmp-server community <redacted>") and pub != prv  # a fingerprint tells them apart
    assert push.shown_removal("no vtp mode") == "no vtp mode"  # nothing secret: shown as is


def test_first_contact_is_called_out_in_the_plan(lab):
    dev, net, values = lab
    first = push.plan_device(_acc(net), net, LOGIN, values)
    assert any(w.startswith("First contact with 10.99.0.11") for w in first["warnings"])
    again = push.plan_device(_acc(net), net, LOGIN, values)  # the key is known now
    assert not any(w.startswith("First contact") for w in again["warnings"])


def test_one_push_or_rollback_per_device_at_a_time(monkeypatch):
    monkeypatch.setattr(push, "_apply_device", lambda *a, **kw: {"status": "pushed"})
    planned = {"hostname": "CORE-SW1", "ip": "10.0.0.9"}
    held = push._one_at_a_time("10.0.0.9", "CORE-SW1")  # a push already running on this device
    try:
        with pytest.raises(push.PushError, match="another push or rollback"):
            push.apply_device(planned, {}, LOGIN, log=lambda *_: None)
        with pytest.raises(push.PushError, match="another push or rollback"):
            push.rollback_device("10.0.0.9", LOGIN, "snap")
        assert push.apply_device({"hostname": "R2", "ip": "10.0.0.2"}, {}, LOGIN)["status"] == "pushed"  # other devices aren't held
    finally:
        held.release()
    assert push.apply_device(planned, {}, LOGIN, log=lambda *_: None)["status"] == "pushed"  # free again afterwards


def test_secrets_the_device_echoes_back_are_scrubbed(monkeypatch):
    def device_says(planned, values, login, log, **kw):
        log("FW1: value parse error before 'Psk-Value-That-Is-Long-9'")
        raise push.PushError("The device rejected: value parse error before 'Psk-Value-That-Is-Long-9'.")
    monkeypatch.setattr(push, "_apply_device", device_says)
    seen = []
    with pytest.raises(push.PushError) as e:
        push.apply_device({"hostname": "FW1", "ip": "10.0.0.3"}, {"IPSEC-PSK": "Psk-Value-That-Is-Long-9"}, LOGIN, log=seen.append)
    assert "Psk-Value" not in str(e.value) + " ".join(seen) and "<IPSEC-PSK>" in str(e.value)
