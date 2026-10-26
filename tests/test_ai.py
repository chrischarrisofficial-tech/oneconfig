import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from oneconfig import ai, cve
from oneconfig.model import Network
from oneconfig.render import render

FIX = Path(__file__).parent / "fixtures"
EXAMPLE = Path(__file__).parents[1] / "oneconfig" / "examples" / "campus.json"


def net():
    return Network.model_validate_json(EXAMPLE.read_text())


def test_mask_leaves_no_secret_behind():
    n = net()
    sentinels = {}

    def val(m):  # a unique, recognizable value for every placeholder that is a secret
        name = m.group(1)
        if name in ("ADMIN-USER", "SNMP-USER"):
            return name.lower()
        sentinels[name] = f"Zq{abs(hash(name)) % 10**8}Leak"
        return sentinels[name]
    text = "\n".join(l if l.startswith("!") else re.sub(r"<([A-Z0-9][A-Z0-9.-]*)>", val, l)  # as push.fill does
                     for d in n.devices for l in render(d, n).splitlines())
    text += (FIX / "brownfield_acc1.cfg").read_text() + "\nip ospf message-digest-key 1 md5 7 0822455D0A16\n" \
        "crypto isakmp key Isakmp-Leak-1 address 0.0.0.0\n neighbor 1.1.1.1 password 7 Bgp-Leak-2\n" \
        "tacacs-server host 10.1.1.1 key 7 Tac-Leak-3\nradius-server host 10.1.1.2 key Rad-Leak-4\n" \
        "aaa group server tacacs+ T\n server-private 10.1.1.3 key 7 Priv-Leak-5\n"
    masked = ai.mask(text)
    for leak in [*sentinels.values(), "cisco123", "oldhasholdhash", "0822455D0A16", "public RO", "private RW", "Isakmp-Leak-1", "Bgp-Leak-2", "Tac-Leak-3", "Rad-Leak-4", "Priv-Leak-5", "$9$"]:
        assert leak not in masked, leak
    for keep in ("key chain OSPF-KEYS", " key 1\n", "hostname ACC-SW1", "ip address 10.99.0.11 255.255.255.0", "snmp-server community <redacted>"):
        assert keep in masked, keep


def test_prompt_has_findings_cves_and_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(cve, "CACHE", tmp_path / "c.json")
    cve.lookup("17.9.4a", get=lambda *a, **k: json.loads((FIX / "cve" / "nvd_iosxe_17.9.4a.json").read_text()))
    n = net()
    for d in n.devices:
        d.os_version = "17.9.4a"
    system, user = ai.build_prompt(n, "explain", focus="ACC-SW1")
    assert "Explain the open findings" in system
    assert "## ACC-SW1" in user and "## CORE-SW1" not in user  # focus keeps it to one device's details
    assert "CISC-L2-000040" in user  # the one open STIG finding on generated switches
    assert "CVE-2026-20272" in user and "Known vulnerabilities (NVD, 66 total" in user
    assert "<ENABLE-SECRET>" in user  # placeholders, never values
    s2, u2 = ai.build_prompt(n, "ask", "Which switches carry VLAN 20?")
    assert "User request: Which switches carry VLAN 20?" in s2 and "## EDGE-R1" in u2


def test_prompt_validation():
    with pytest.raises(ValueError, match="Type a question"):
        ai.build_prompt(net(), "draft", "  ")
    with pytest.raises(ValueError, match="mode must be"):
        ai.build_prompt(net(), "hack")
    with pytest.raises(ValueError, match="No device named"):
        ai.build_prompt(net(), "design", focus="NOPE")


@pytest.fixture
def fake_api():
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
            if self.path == "/v1/messages":
                if self.headers.get("x-api-key") != "sk-good":
                    return self._send(401, {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}})
                return self._send(200, {"type": "message", "content": [{"type": "text", "text": "Fix CAT I first."}],
                                        "stop_reason": "max_tokens" if body["max_tokens"] and body["system"] == "LONG" else "end_turn"})
            if self.path == "/v1/chat/completions":
                if body["model"] == "missing":
                    return self._send(404, {"error": {"message": "model 'missing' not found"}})
                return self._send(200, {"choices": [{"message": {"role": "assistant", "content": "Local answer."},
                                                     "finish_reason": "length" if body["model"] == "tiny" else "stop"}]})

        def _send(self, code, obj):
            raw = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    srv.shutdown()


def test_claude_request_shape(fake_api):
    url, seen = fake_api
    out = ai.complete({"kind": "claude", "api_key": "sk-good", "model": "claude-sonnet-5-5", "url": url + "/v1/messages"}, "SYS", "USER")
    assert out == "Fix CAT I first."
    _, headers, body = seen[0]
    assert headers["anthropic-version"] == "2023-06-01" and headers["x-api-key"] == "sk-good"
    assert body == {"model": "claude-sonnet-5-5", "max_tokens": 4096, "system": "SYS", "messages": [{"role": "user", "content": "USER"}]}
    cut = ai.complete({"kind": "claude", "api_key": "sk-good", "url": url + "/v1/messages"}, "LONG", "U")
    assert cut == "Fix CAT I first." + ai.CUT
    with pytest.raises(ConnectionError, match="401.*invalid x-api-key"):
        ai.complete({"kind": "claude", "api_key": "sk-bad", "url": url + "/v1/messages"}, "S", "U")


def test_openai_compatible_request_shape(fake_api):
    url, seen = fake_api
    out = ai.complete({"kind": "openai", "base_url": url + "/v1/", "model": "llama3.1"}, "SYS", "USER")
    assert out == "Local answer."
    _, headers, body = seen[0]
    assert "authorization" not in headers and body["messages"][0] == {"role": "system", "content": "SYS"}
    assert ai.complete({"kind": "openai", "base_url": url + "/v1", "model": "tiny"}, "S", "U").endswith(ai.CUT)
    with pytest.raises(ConnectionError, match="404.*model 'missing' not found"):
        ai.complete({"kind": "openai", "base_url": url + "/v1", "model": "missing"}, "S", "U")
    with pytest.raises(ConnectionError, match="Can't reach"):
        ai.complete({"kind": "openai", "base_url": "http://127.0.0.1:9/v1"}, "S", "U", timeout=2)


def test_mask_covers_junos():
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from platforms import example
    from oneconfig.push import fill, placeholders
    n = example("junos")
    leaks = {}
    for d in n.devices:
        cfg = render(d, n)
        leaks |= {p: f"Zq{abs(hash(p)) % 10**8}Leak!" for p in placeholders(cfg) if p not in ("ADMIN-USER", "SNMP-USER", "BACKUP-USER")}
    text = "\n".join(fill(render(d, n), {**leaks, "ADMIN-USER": "ops", "SNMP-USER": "snmpops", "BACKUP-USER": "bk"}) for d in n.devices)
    text += '\nset snmp community Comm-Leak-1 authorization read-only\nset system tacplus-server 10.1.1.1 secret "$9$Tac-Leak-2"\n' \
            'set security ipsec security-association SA manual direction bidirectional authentication key ascii-text "Ipsec-Leak-3"\n'
    masked = ai.mask(text)
    for leak in [*leaks.values(), "Comm-Leak-1", "Tac-Leak-2", "Ipsec-Leak-3", "$6$", "$9$"]:
        assert leak not in masked, leak
    assert "set system host-name EDGE-R1" in masked and "set snmp community <redacted>" in masked


def test_mask_covers_asa():
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from platforms import example
    from oneconfig.push import fill, placeholders
    n = example("asa")
    d = n.devices[0]
    cfg = render(d, n)
    leaks = {p: f"Zq{abs(hash(p)) % 10**8}Leak!" for p in placeholders(cfg) if p not in ("ADMIN-USER", "SNMP-USER", "BACKUP-USER")}
    text = fill(cfg, {**leaks, "ADMIN-USER": "ops", "SNMP-USER": "snmpops", "BACKUP-USER": "bk"}) + "\nsnmp-server community Comm-Leak-1\n"
    out = ai.mask(text)
    assert not [v for v in [*leaks.values(), "Comm-Leak-1"] if v in out], out


def test_mask_covers_panos():
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from platforms import example
    from oneconfig.push import fill, placeholders
    n = example("panos")
    cfg = render(n.devices[0], n)
    leaks = {p: f"Zq{abs(hash(p)) % 10**8}Leak!" for p in placeholders(cfg) if p not in ("ADMIN-USER", "SNMP-USER", "BACKUP-USER")}
    text = fill(cfg, {**leaks, "ADMIN-USER": "ops", "SNMP-USER": "snmpops"}) + \
        "\nset deviceconfig system snmp-setting access-setting version v2c snmp-community-string Comm-Leak-1\n"
    out = ai.mask(text)
    assert not [v for v in [*leaks.values(), "Comm-Leak-1", "$5$"] if v in out], out


def test_mask_covers_fortios():
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from platforms import example
    from oneconfig.push import fill, placeholders
    n = example("fortios")
    cfg = render(n.devices[0], n)
    leaks = {p: f"Zq {abs(hash(p)) % 10**8} Leak!" for p in placeholders(cfg) if p not in ("ADMIN-USER", "SNMP-USER", "BACKUP-USER")}
    text = fill(cfg, {**leaks, "ADMIN-USER": "ops", "SNMP-USER": "snmpops"}, nos="fortios") + \
        '\nconfig system snmp community\n    edit 1\n        set name "Comm-Leak-1"\n    next\nend\n' \
        "config system admin\n    edit admin\n        set password ENC SH2nlSm9QL9tapcHPXIqAXvX7v\n    next\nend\n"
    out = ai.mask(text)
    assert not [v for v in [*leaks.values(), "Comm-Leak-1", "SH2nlSm9"] if v in out], out
    assert "    edit 1\n        set name <redacted>" in out and 'set name "INSIDE-TO-DMZ-WEB"' in out  # only community names


@pytest.mark.parametrize("url,key,ok", [("http://localhost:11434/v1", True, True), ("http://127.0.0.1:8000/v1", True, True),
                                        ("https://llm.example.com/v1", True, True), ("http://192.168.1.50:11434/v1", False, True),
                                        ("http://llm.example.com/v1", True, False), ("file:///etc/passwd", False, False),
                                        ("ftp://llm.example.com/v1", False, False)])
def test_api_key_only_goes_over_https_or_to_this_computer(url, key, ok):
    if ok:
        ai.check_base_url(url, key)
    else:
        with pytest.raises(ValueError):
            ai.check_base_url(url, key)
