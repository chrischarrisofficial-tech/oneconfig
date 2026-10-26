import re
from pathlib import Path

from fakelab import FakeConfig

from oneconfig.diff import plan, snmp_users, tree
from oneconfig.model import Network
from oneconfig.render import render

FIX = Path(__file__).parent / "fixtures"
EXAMPLE = Path(__file__).parents[1] / "oneconfig" / "examples" / "campus.json"
VALUES = {"ADMIN-USER": "admin", "SNMP-USER": "oneconfig"}


def candidate(host):
    net = Network.model_validate_json(EXAMPLE.read_text())
    text = render(next(d for d in net.devices if d.hostname == host), net)
    return re.sub(r"<([A-Z0-9][A-Z0-9.-]*)>", lambda m: VALUES.get(m.group(1), f"Secret-{m.group(1)}-123"), text)


def converge(cand, dev, login="admin"):
    """Push the plan into a fake device and re-plan; returns the second plan."""
    p = plan(cand, dev.text(), login_user=login, known_snmp_users=dev.snmp_users)
    dev.apply(p["add"] + p["remove"])
    return plan(cand, dev.text(), login_user=login, known_snmp_users=dev.snmp_users)


def test_blank_device_converges_in_one_push():
    for host in ("EDGE-R1", "CORE-SW1", "ACC-SW1"):
        again = converge(candidate(host), FakeConfig(""))
        assert again == {"add": [], "remove": []}, (host, again)


def test_brownfield_plan_is_merge_safe():
    dev = FakeConfig((FIX / "brownfield_acc1.cfg").read_text())
    p = plan(candidate("ACC-SW1"), dev.text(), login_user="admin")
    added = "\n".join(p["add"])
    for keep in ("license", "crypto pki", "vrf definition", "redundancy", "GigabitEthernet0/0\n", "platform punt",
                 "switch 1 provision", "interface GigabitEthernet1/0/2\n"):
        assert keep not in added  # never touches what OneConfig doesn't manage
    assert "aaa new-model" in p["add"] and "vtp mode off" in p["add"]
    assert "interface GigabitEthernet1/0/1" in p["add"] and " switchport block unicast" in p["add"]
    # admin exists but isn't bound to the password policy, so its line is pushed (with the stored secret)
    assert any(x.startswith("username admin privilege 15 common-criteria-policy") for x in p["add"])
    assert set(p["remove"]) == {"no snmp-server community public", "no snmp-server community private", "no username olduser",
                                "no enable password", "no ip route 192.168.50.0 255.255.255.0 10.99.0.1", "no service call-home"}


def test_brownfield_converges_and_keeps_login_account():
    dev = FakeConfig((FIX / "brownfield_acc1.cfg").read_text())
    again = converge(candidate("ACC-SW1"), dev)
    assert again == {"add": [], "remove": []}, again
    run = dev.text()
    assert "username admin " in run and "olduser" not in run and "snmp-server community" not in run
    assert "license boot level" in run and "crypto pki trustpoint" in run  # untouched


def test_login_user_is_never_removed():
    p = plan("hostname X\n", "hostname X\nusername ops privilege 15 secret 9 $9$x\nusername temp secret 9 $9$y\n", login_user="ops")
    assert p["remove"] == ["no username temp"]


def test_existing_secret_not_rotated_unless_asked():
    run = "enable secret 9 $9$abc\nntp authentication-key 1 hmac-sha2-256 7 1234\n"
    cand = "enable algorithm-type scrypt secret NewOne-123\nntp authentication-key 1 hmac-sha2-256 Key-123\n"
    assert plan(cand, run)["add"] == []
    assert plan(cand, run, rotate_secrets=True)["add"] == cand.strip().split("\n")


def test_acl_replaced_wholesale_when_entries_differ():
    run = "ip access-list standard MGMT-ACCESS\n 10 permit 10.1.0.0 0.0.255.255\n 20 deny any log\n"
    cand = "ip access-list standard MGMT-ACCESS\n permit 10.99.0.0 0.0.0.255\n deny any log\n"
    assert plan(cand, run)["add"] == ["no ip access-list standard MGMT-ACCESS", "ip access-list standard MGMT-ACCESS",
                                      " permit 10.99.0.0 0.0.0.255", " deny any log"]
    assert plan(cand, cand.replace(" permit", " 10 permit").replace(" deny", " 20 deny"))["add"] == []  # sequence numbers ignored


def test_bgp_md5_removed_before_tcp_ao():
    run = "router bgp 65010\n neighbor 203.0.113.1 remote-as 64500\n neighbor 203.0.113.1 password 7 0822\n"
    cand = "router bgp 65010\n neighbor 203.0.113.1 remote-as 64500\n neighbor 203.0.113.1 ao BGP-AS64500\n"
    assert plan(cand, run)["add"] == ["router bgp 65010", " no neighbor 203.0.113.1 password", " neighbor 203.0.113.1 ao BGP-AS64500"]


def test_parent_context_written_once_per_group():
    run = "interface Gi1\n description x\n"
    cand = "interface Gi1\n description x\n no ip redirects\n no ip proxy-arp\ninterface Gi2\n no ip redirects\n"
    assert plan(cand, run)["add"] == ["interface Gi1", " no ip redirects", " no ip proxy-arp", "interface Gi2", " no ip redirects"]


def test_banner_parsing_and_change():
    run = "banner login ^C\nOld text\n^C\n"
    assert tree(run).find("banner login").children[0].line == "Old text"
    assert plan("banner login ^\nNew text\n^\n", run)["add"] == ["banner login ^C", "New text", "^C"]
    assert plan("banner login ^Old text^\n", run)["add"] == []


def test_snmp_users_from_show_command():
    out = "User name: oneconfig\nEngine ID: 800000090300\nstorage-type: nonvolatile active\n\nUser name: ops\n"
    assert snmp_users(out) == {"oneconfig", "ops"}
    cand = "snmp-server user oneconfig RO v3 auth sha a priv aes 256 b\n"
    assert plan(cand, "", known_snmp_users={"oneconfig"})["add"] == []
    assert plan(cand, "")["add"] == [cand.strip()]


def test_acl_still_in_use_is_never_offered_for_removal():
    running = """ip access-list extended NAT-ACL
 permit ip 10.10.0.0 0.0.255.255 any
ip access-list extended OLD-JUNK
 deny ip any any
ip access-list extended NAT-ACL-2
 permit ip any any
ip nat inside source list NAT-ACL interface GigabitEthernet0/0/0 overload
"""
    rm = plan("hostname X", running)["remove"]
    assert "no ip access-list extended OLD-JUNK" in rm and "no ip access-list extended NAT-ACL-2" in rm
    assert "no ip access-list extended NAT-ACL" not in rm
