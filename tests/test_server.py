import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from oneconfig import discover as D
from oneconfig import server


@pytest.fixture(scope="module")
def url():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def call(url, path, body=None, headers=None):
    req = urllib.request.Request(url + path, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "X-OneConfig-Token": server.TOKEN, **(headers or {})})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


@pytest.mark.parametrize("headers", [{"Content-Type": "text/plain"}, {"Origin": "https://evil.example"},
                                     {"Origin": "http://127.0.0.1.evil.example:8470"}])
def test_csrf_guard_blocks_cross_site_posts(url, headers):
    code, body = call(url, "/api/discover", {"method": "sweep", "scope": "127.0.0.1"}, headers)
    assert code == 403 and body["error"] == "forbidden origin"


def test_same_origin_post_allowed(url):
    code, _ = call(url, "/api/audit", {"config": "hostname X"}, {"Origin": url})
    assert code == 200


def test_bad_discovery_input_rejected_up_front(url):
    assert call(url, "/api/discover", {"method": "sweep", "scope": "10.0.0.0/8"})[0] == 400
    assert call(url, "/api/discover", {"method": "ssh", "scope": "10.99.0.0/24", "seeds": "", "username": "a"})[0] == 400
    assert call(url, "/api/discover", {"method": "telnet-everything"})[0] == 400


def test_ssh_discovery_job_end_to_end(url, monkeypatch):
    from fakelab import PASSWORD, USER, lab, start_ssh
    ports = {ip: start_ssh(d) for ip, d in lab().items()}
    real = D.cli_collect
    monkeypatch.setattr(D, "cli_collect", lambda host=None, **kw: real("127.0.0.1", port=ports[str(host)], **kw))
    code, body = call(url, "/api/discover", {"method": "ssh", "seeds": "10.99.0.1", "scope": "10.99.0.0/24",
                                             "username": USER, "password": PASSWORD})
    assert code == 200
    for _ in range(100):
        job = call(url, f"/api/jobs/{body['job']}")[1]
        if job["done"]:
            break
        time.sleep(0.2)
    assert job["error"] is None, job
    rows = {r["hostname"]: r for r in job["result"]["rows"]}
    assert rows["CORE-SW1"]["reached"] and not rows["EDGE-R1"]["reached"]
    assert "stig" in rows["ACC-SW1"] and rows["ACC-SW1"]["stig"]["platform"] == "switch"
    assert len(job["result"]["fragment"]["links"]) == 4
    assert PASSWORD not in json.dumps(job)  # credentials never come back to the browser


def _wait(url, job):
    for _ in range(200):
        j = call(url, f"/api/jobs/{job}")[1]
        if j["done"]:
            return j
        time.sleep(0.05)
    raise AssertionError("job never finished")


def _example():
    from pathlib import Path
    return json.loads((Path(server.__file__).parent / "examples" / "campus.json").read_text())


def test_ai_preview_is_exact_and_masked(url):
    code, pv = call(url, "/api/ai/preview", {"network": _example(), "mode": "design"})
    assert code == 200 and "## EDGE-R1" in pv["user"] and pv["chars"] == len(pv["system"]) + len(pv["user"])
    assert pv["tokens"] == pv["chars"] // 4
    assert call(url, "/api/ai/preview", {"network": _example(), "mode": "ask"})[1]["errors"] == ["Type a question or the change you want"]


def test_ai_ask_job_sends_the_previewed_prompt(url, monkeypatch):
    sent = {}
    monkeypatch.setattr(server.ai, "_post", lambda u, body, headers, timeout: sent.update(url=u, body=body, headers=headers)
                        or {"content": [{"type": "text", "text": "Looks good."}]})
    body = {"network": _example(), "mode": "ask", "question": "Where is the STP root?", "focus": "CORE-SW1"}
    pv = call(url, "/api/ai/preview", body)[1]
    assert call(url, "/api/prefs", {"local_only": False})[0] == 200  # the user chose to allow the Claude API
    assert call(url, "/api/ai/ask", {**body, "provider": {"kind": "claude"}})[1]["errors"][0].startswith("Add a Claude API key")
    job = call(url, "/api/ai/ask", {**body, "provider": {"kind": "claude", "model": "claude-haiku-5-5", "api_key": "sk-x"}})[1]["job"]
    j = _wait(url, job)
    assert j["result"] == {"answer": "Looks good."} and "sk-x" not in json.dumps(j)
    assert sent["body"]["system"] == pv["system"] and sent["body"]["messages"][0]["content"] == pv["user"]
    assert sent["body"]["model"] == "claude-haiku-5-5" and sent["headers"]["x-api-key"] == "sk-x"


def test_cve_job_and_cached_result_in_build(url, monkeypatch, tmp_path):
    from pathlib import Path
    real = json.loads((Path(__file__).parent / "fixtures" / "cve" / "nvd_iosxe_17.9.4a.json").read_text())
    monkeypatch.setattr(server.cve, "CACHE", tmp_path / "c.json")
    monkeypatch.setattr(server.cve, "http", lambda *a, **k: real)
    assert call(url, "/api/cve", {"version": "latest"})[0] == 400
    j = _wait(url, call(url, "/api/cve", {"version": "17.09.04a"})[1]["job"])
    assert j["error"] is None and j["result"]["counts"]["Critical"] == 3
    net = _example()
    net["devices"][0]["os_version"] = "17.9.4a"
    built = call(url, "/api/build", net)[1]
    assert built[net["devices"][0]["hostname"]]["cve"]["source"] == "NVD"
    assert built[net["devices"][1]["hostname"]]["cve"] is None


def test_settings_return_names_only(url, monkeypatch):
    store = {}
    from oneconfig import vault
    monkeypatch.setattr(vault, "available", lambda: True)
    monkeypatch.setattr(vault, "names", lambda n: sorted(k for (net, k) in store if net == n))
    monkeypatch.setattr(vault, "put_many", lambda n, vals: store.update({(n, k): v for k, v in vals.items()}))
    monkeypatch.setattr(vault, "get_many", lambda n, want: {k: store[(n, k)] for k in want if (n, k) in store})
    monkeypatch.setattr(vault, "forget", lambda n, k: store.pop((n, k), None))
    code, r = call(url, "/api/settings", {"values": {"claude_api_key": "sk-secret", "evil": "x"}})
    assert code == 200 and r == {"keychain": True, "saved": ["claude_api_key"]} and "sk-secret" not in json.dumps(r)
    assert server._app_keys({}) == {"claude_api_key": "sk-secret"}
    assert server._app_keys({"keys": {"claude_api_key": "sk-typed"}})["claude_api_key"] == "sk-typed"
    assert call(url, "/api/settings", {"forget": ["claude_api_key"]})[1]["saved"] == []


def test_snmp_targets_walk_the_scope_not_the_typed_range():
    from ipaddress import ip_network
    scope = [ip_network("10.99.0.0/30")]
    t = time.time()
    assert server._ips("10.0.0.0/8, 10.99.0.2", scope) == ["10.99.0.1", "10.99.0.2"]
    assert server._ips("2001:db8::/64", scope) == []
    assert time.time() - t < 1


def test_short_secrets_are_refused_before_planning(url):
    from oneconfig import push
    net = _example()
    needs = call(url, "/api/push/needs", {"network": net, "hostnames": ["CORE-SW1"]})[1]["needs"]
    values = {p: ("ops" if p in push.IDENTIFIERS else "Long-Enough-9") for p in needs} | {"ENABLE-SECRET": "abc"}
    code, body = call(url, "/api/push/plan", {"network": net, "hostnames": ["CORE-SW1"], "values": values,
                                              "login": {"username": "admin", "password": "x"}})
    assert code == 400 and body["errors"] == [f"Use at least {push.MIN_SECRET} characters for: ENABLE-SECRET"]


def test_api_needs_the_launch_token(url):
    """Another account or program on this computer can reach 127.0.0.1 but not read the launch file, so it gets nothing."""
    assert call(url, "/api/audit", {"config": "hostname X"}, {"X-OneConfig-Token": "guess"})[0] == 401
    assert call(url, "/api/settings", None, {"X-OneConfig-Token": ""})[0] == 401
    for path in ("/", "/app.js"):  # the page and its code are served without the token, and neither carries it
        with urllib.request.urlopen(url + path) as r:
            assert server.TOKEN not in r.read().decode()


def test_launch_file_is_private(tmp_path, monkeypatch):
    import os
    import stat
    from pathlib import Path
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    f = server.launch_file(8470)
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600 and f"#t={server.TOKEN}" in f.read_text()


def test_keychain_is_per_network_not_per_name(url, monkeypatch, tmp_path):
    """Two networks with the default name must not share saved secrets or logins."""
    import keyring
    from keyring.backend import KeyringBackend
    from oneconfig import vault

    class Mem(KeyringBackend):
        priority, store = 1, {}
        def get_password(self, s, u): return self.store.get((s, u))  # noqa: E704
        def set_password(self, s, u, p): self.store[(s, u)] = p  # noqa: E704
        def delete_password(self, s, u): self.store.pop((s, u), None)  # noqa: E704
    old = keyring.get_keyring()
    keyring.set_keyring(Mem())
    monkeypatch.setattr(vault, "INDEX", tmp_path / "names.json")
    try:
        a, b = _example() | {"id": "11111111-1111-4111-8111-111111111111"}, _example() | {"id": "22222222-2222-4222-8222-222222222222"}
        vault.put_many(a["id"], {"TACACS-KEY": "customer-A-key"})
        vault.put_login(a["id"], {"username": "a-admin", "password": "A-pass-1234"})
        need = lambda n: call(url, "/api/push/needs", {"network": n, "hostnames": ["CORE-SW1"]})[1]  # noqa: E731
        assert "TACACS-KEY" in need(a)["saved"] and need(a)["login_saved"]
        assert need(b)["saved"] == [] and not need(b)["login_saved"]  # same name, different network
        assert need(_example())["keychain"] is False  # no id: no keychain at all
    finally:
        keyring.set_keyring(old)


def test_short_secret_is_not_remembered(url, monkeypatch, tmp_path):
    from oneconfig import push, vault
    saved = []
    monkeypatch.setattr(vault, "put_many", lambda ns, vals: saved.append(vals))
    net = _example() | {"id": "33333333-3333-4333-8333-333333333333"}
    needs = call(url, "/api/push/needs", {"network": net, "hostnames": ["CORE-SW1"]})[1]["needs"]
    values = {p: ("ops" if p in push.IDENTIFIERS else "Long-Enough-9") for p in needs} | {"ENABLE-SECRET": "abc"}
    code, _ = call(url, "/api/push/plan", {"network": net, "hostnames": ["CORE-SW1"], "values": values, "remember": True,
                                           "login": {"username": "admin", "password": "x"}})
    assert code == 400 and saved == []  # refused, and nothing reached the keychain


def test_dashboard_prefs_round_trip_and_validation(url, monkeypatch, tmp_path):
    monkeypatch.setattr(server, "PREFS", tmp_path / "ui.json")
    assert call(url, "/api/prefs") == (200, {})
    good = {"local_only": True, "theme": "ember", "preset": "Overview", "layouts": {"Overview": [["map", "l"], ["health", "t"]], "My view": [["cves", "s"]]}}
    assert call(url, "/api/prefs", good) == (200, good)
    assert call(url, "/api/prefs") == (200, good)
    assert (tmp_path / "ui.json").stat().st_mode & 0o077 == 0  # only this user can read it
    for bad in ({"theme": "<script>"}, {"layouts": {"x": [["map", "huge"]]}}, {"layouts": {"x": [["../etc", "s"]]}},
                {"layouts": {"x": [["map", "s"]] * 13}}, {"layouts": "nope"}):
        assert call(url, "/api/prefs", bad)[0] == 400, bad
    assert call(url, "/api/prefs") == (200, good)  # a refused write leaves the saved file alone
    assert call(url, "/api/prefs", {"layouts": {"x": [["map", "s"]] * 12}})[0] == 200  # the limit itself is fine


def test_unsafe_secret_values_are_refused_before_planning(url):
    from oneconfig import push
    net = _example()
    needs = call(url, "/api/push/needs", {"network": net, "hostnames": ["CORE-SW1"]})[1]["needs"]
    values = {p: ("ops" if p in push.IDENTIFIERS else "Long-Enough-9") for p in needs} | {"ENABLE-SECRET": "Long-Enough-9\nno aaa new-model"}
    code, body = call(url, "/api/push/plan", {"network": net, "hostnames": ["CORE-SW1"], "values": values,
                                              "login": {"username": "admin", "password": "x"}})
    assert code == 400 and body["errors"][0].endswith(": ENABLE-SECRET")


def _raw(url, length, body=b"{}"):
    import socket
    host, port = url.removeprefix("http://").split(":")
    s = socket.create_connection((host, int(port)))
    s.settimeout(5)
    s.sendall(b"POST /api/build HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
              + f"X-OneConfig-Token: {server.TOKEN}\r\nContent-Length: {length}\r\n\r\n".encode() + body)
    try:
        return s.recv(64).split(b" ")[1]
    finally:
        s.close()


def test_malformed_requests_still_get_an_answer(url):
    assert call(url, "/api/cklb", {"stig": 5})[0] == 400  # a TypeError inside used to drop the connection
    assert call(url, "/api/push/plan", {"network": {"devices": [], "links": []}, "hostnames": 5})[0] == 400
    assert _raw(url, "-1") == b"400"  # read(-1) used to wait for the client to hang up
    assert _raw(url, "lots") == b"400"


def test_plans_expire_are_single_use_and_drop_secrets(url, monkeypatch):
    from oneconfig import push
    seen = {}

    def fake_apply(planned, values, login, removals=(), **kw):
        seen["removals"], seen["values"] = list(removals), dict(values)
        return {"hostname": planned["hostname"], "status": "pushed", "snapshot": "s1", "login": login}
    monkeypatch.setattr(push, "apply_device", fake_apply)
    device = {"hostname": "R1", "ip": "10.0.0.1", "add": ["x"], "candidate": "x", "remove": ["no a", "no snmp-server community secret1"]}
    server.PLANS["p1"] = {"values": {"ENABLE-SECRET": "Long-Enough-9"}, "login": {"username": "u"}, "devices": {"R1": device},
                          "at": time.monotonic()}
    job = call(url, "/api/push/apply", {"plan": "p1", "hostnames": ["R1"], "removals": {"R1": [1, 7, "no a", True]}})[1]["job"]
    while not server.JOBS[job]["done"]:
        time.sleep(0.05)
    assert seen["removals"] == ["no snmp-server community secret1"]  # positions only; out-of-range and strings ignored
    assert seen["values"] == {"ENABLE-SECRET": "Long-Enough-9"}
    pl = server.PLANS["p1"]
    assert pl["values"] == {} and "candidate" not in device and "add" not in device  # what a rollback doesn't need is gone
    assert call(url, "/api/push/apply", {"plan": "p1", "hostnames": ["R1"]})[0] == 400  # single use
    pl["at"] -= server.PLAN_TTL + 1
    assert call(url, "/api/push/rollback", {"plan": "p1", "hostname": "R1"})[0] == 400 and "p1" not in server.PLANS  # expired


def test_ai_key_is_not_sent_over_plain_http(url):
    call(url, "/api/prefs", {"local_only": False})
    code, body = call(url, "/api/ai/ask", {"network": _example(), "mode": "design",
                                            "provider": {"kind": "openai", "base_url": "http://llm.example.com/v1", "api_key": "k"}})
    assert code == 400 and "https" in body["errors"][0]


def test_page_has_no_dev_data_toggle(url):
    page = ""
    for path in ("/", "/app.js"):
        with urllib.request.urlopen(url + path) as r:
            page += r.read().decode()
    assert "DEVDATA" not in page and "oneconfig.dev" not in page


def test_push_needs_lists_each_devices_values(url):
    net = _example()
    code, body = call(url, "/api/push/needs", {"network": net, "hostnames": ["EDGE-R1", "ACC-SW1"]})
    assert code == 200 and set(body["per_device"]) == {"EDGE-R1", "ACC-SW1"}
    assert sorted({p for v in body["per_device"].values() for p in v}) == body["needs"]


def test_backups_lists_names_and_times_only(url, monkeypatch, tmp_path):
    from oneconfig import push
    monkeypatch.setattr(push, "BACKUPS", tmp_path)
    for f in ("CORE-SW1-20261023-090000.cfg", "CORE-SW1-20261024-101500.cfg.enc", "R1-20261020-080000.cfg.enc", "notes.txt"):
        (tmp_path / f).write_text("hostname X\nenable secret 9 $9$abc\n")
    code, body = call(url, "/api/backups")
    assert code == 200 and body == {"CORE-SW1": {"latest": "20261024-101500", "count": 2, "encrypted": False},  # one plain, one encrypted
                                    "R1": {"latest": "20261020-080000", "count": 1, "encrypted": True}}
    assert "secret" not in json.dumps(body)  # names and times, never contents
    monkeypatch.setattr(push, "BACKUPS", tmp_path / "missing")
    assert call(url, "/api/backups") == (200, {})


def test_network_data_stays_on_this_computer_by_default(url, monkeypatch):
    sent = []
    monkeypatch.setattr(server.ai, "_post", lambda u, *a: sent.append(u) or {"choices": [{"message": {"content": "ok"}}]})
    body = {"network": _example(), "mode": "design"}
    for provider in ({"kind": "claude", "api_key": "sk-x"}, {"kind": "openai", "base_url": "https://llm.example.com/v1"},
                     {"kind": "openai", "base_url": "http://192.168.1.50:11434/v1"}):
        code, out = call(url, "/api/ai/ask", {**body, "provider": provider})
        assert code == 400 and "on this computer" in out["errors"][0], provider
    _wait(url, call(url, "/api/ai/ask", {**body, "provider": {"kind": "openai", "base_url": "http://localhost:11434/v1"}})[1]["job"])
    assert sent == ["http://localhost:11434/v1/chat/completions"]  # only the local server was ever contacted
    assert call(url, "/api/prefs", {"local_only": "no"})[0] == 400


def test_responses_carry_security_headers(url):
    def heads(path, token=True):
        req = urllib.request.Request(url + path, headers={"X-OneConfig-Token": server.TOKEN} if token else {})
        with urllib.request.urlopen(req) as r:
            return r.headers
    page, api = heads("/", token=False), heads("/api/prefs")
    for hd in (page, api):
        assert hd["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in hd["Content-Security-Policy"]
        assert hd["Cache-Control"] == "no-store" and hd["X-Content-Type-Options"] == "nosniff" and "Python" not in hd["Server"]
    assert "connect-src 'self'" in page["Content-Security-Policy"] and "default-src 'none'" in page["Content-Security-Policy"]


def test_state_folder_and_files_are_private(tmp_path, monkeypatch):
    import os
    import stat
    from pathlib import Path

    from oneconfig import cve, vault
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    (tmp_path / ".oneconfig").mkdir(mode=0o755)
    server.launch_file(8470)
    assert stat.S_IMODE(os.stat(tmp_path / ".oneconfig").st_mode) == 0o700  # tightened even if it existed open
    monkeypatch.setattr(vault, "INDEX", tmp_path / ".oneconfig" / "secret-names.json")
    vault._save_index({"net": ["ENABLE-SECRET"]})
    monkeypatch.setattr(cve, "CACHE", tmp_path / ".oneconfig" / "cve-cache.json")
    cve.lookup("17.9.4a", get=lambda *a, **k: {"vulnerabilities": [], "totalResults": 0})
    for f in ("secret-names.json", "cve-cache.json"):
        assert stat.S_IMODE(os.stat(tmp_path / ".oneconfig" / f).st_mode) == 0o600, f


def _signed(url, path, body=None, session=""):
    return call(url, path, body, {"X-OneConfig-Session": session})


def test_accounts_roles_and_the_audit_trail(url):
    from oneconfig import trail
    assert call(url, "/api/me") == (200, {"accounts": False, "user": "local", "role": "admin"})  # no accounts: works as before
    code, out = call(url, "/api/users", {"action": "add", "name": "ana", "password": "short", "role": "admin"})
    assert code == 400 and "10 characters" in out["errors"][0]
    assert call(url, "/api/users", {"action": "add", "name": "ana", "password": "viewer-only-1", "role": "viewer"})[0] == 400  # first must be admin
    code, first = call(url, "/api/users", {"action": "add", "name": "ana", "password": "Admin-Pass-123", "role": "admin"})
    assert code == 200 and first["role"] == "admin" and first["session"]  # the first admin is signed straight in
    admin = first["session"]
    # from now on every request needs a session
    req = urllib.request.Request(url + "/api/prefs", headers={"X-OneConfig-Token": server.TOKEN})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req)
    assert e.value.code == 401 and e.value.headers["X-OneConfig-Login"] == "required"
    assert _signed(url, "/api/users", {"action": "add", "name": "vic", "password": "Viewer-Pass-123", "role": "viewer"}, admin)[0] == 200
    assert _signed(url, "/api/users", {"action": "add", "name": "ola", "password": "Operator-Pass-1", "role": "operator"}, admin)[0] == 200
    assert call(url, "/api/login", {"user": "vic", "password": "wrong-password"})[0] == 401
    vic = call(url, "/api/login", {"user": "vic", "password": "Viewer-Pass-123"})[1]["session"]
    ola = call(url, "/api/login", {"user": "ola", "password": "Operator-Pass-1"})[1]["session"]
    net = _example()
    assert _signed(url, "/api/build", net, vic)[0] == 200  # viewers look and build
    for path, body in (("/api/discover", {"method": "sweep", "scope": "127.0.0.1"}), ("/api/push/plan", {"network": net, "hostnames": ["CORE-SW1"]}),
                       ("/api/cve", {"version": "17.9.4a"}), ("/api/settings", {})):
        code, out = _signed(url, path, body, vic)
        assert code == 403 and "viewer" in out["errors"][0], path  # but can't touch devices, keys or the internet
    assert _signed(url, "/api/settings", {}, ola)[0] == 403  # operators can't manage API keys
    assert _signed(url, "/api/users", {"action": "role", "name": "vic", "role": "admin"}, ola)[0] == 403
    assert _signed(url, "/api/prefs", {"local_only": False}, ola)[0] == 403  # only an admin lets data leave
    assert _signed(url, "/api/users", {"action": "remove", "name": "ana"}, admin)[0] == 400  # last admin stays
    code, mine = _signed(url, "/api/users", {"action": "password", "name": "vic", "current": "Viewer-Pass-123", "password": "Viewer-Pass-456"}, vic)
    assert code == 200 and _signed(url, "/api/build", net, vic)[0] == 401  # a new password ends the old session
    assert _signed(url, "/api/build", net, mine["session"])[0] == 200
    assert call(url, "/api/logout", {}, {"X-OneConfig-Session": ola})[0] == 200 and _signed(url, "/api/build", net, ola)[0] == 401
    # the trail: who did what, chained and signed, nothing secret
    code, t = _signed(url, "/api/audit-trail", None, admin)
    actions = [(e["actor"], e["action"]) for e in t["items"]]
    assert code == 200 and t["ok"] and t["signed"] and ("vic", "sign-in failed") in actions and ("ana", "add user") in actions
    assert "Viewer-Pass" not in json.dumps(t) and _signed(url, "/api/audit-trail", None, mine["session"])[0] == 403  # viewers can't read it
    lines = trail.LOG.read_text().splitlines()
    trail.LOG.write_text("\n".join(lines[:2] + [lines[2].replace('"ana"', '"mallory"')] + lines[3:]) + "\n")  # someone edits a line
    assert _signed(url, "/api/audit-trail", None, admin)[1]["broken_at"] == 2


def test_history_keeps_distinct_versions_privately(url):
    import os
    import stat

    from oneconfig import history
    net = {**_example(), "id": "6f1c1d2e-0000-4000-8000-000000000001"}
    assert call(url, "/api/history/save", {"network": net, "reason": "edited"})[1]["saved"] is True
    assert call(url, "/api/history/save", {"network": net})[1]["saved"] is False  # nothing changed: no new version
    smaller = {**net, "devices": net["devices"][:2]}
    assert call(url, "/api/history/save", {"network": smaller, "reason": "before deleting ACC-SW1"})[1]["saved"] is True
    code, versions = call(url, "/api/history/list", {"id": net["id"]})
    assert code == 200 and [v["devices"] for v in versions] == [2, 4] and versions[0]["reason"] == "before deleting ACC-SW1"
    back = call(url, "/api/history/get", {"id": net["id"], "version": versions[1]["version"]})[1]
    assert [d["hostname"] for d in back["devices"]] == [d["hostname"] for d in net["devices"]]
    for bad in ({"id": "../../etc", "version": versions[0]["version"]}, {"id": net["id"], "version": "../x"}):
        assert call(url, "/api/history/get", bad)[0] == 400
    folder = history.DIR / net["id"]
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700 and all(stat.S_IMODE(os.stat(f).st_mode) == 0o600 for f in folder.iterdir())


def test_tests_never_touch_the_real_state_folder():
    """Every file OneConfig keeps is redirected during tests (conftest). A new one that isn't fails here."""
    from pathlib import Path

    from oneconfig import cve, discover, history, push, trail, users, vault
    real = Path.home() / ".oneconfig"
    paths = {"prefs": server.PREFS, "known_hosts": discover.KNOWN_HOSTS, "trail": trail.LOG, "users": users.FILE, "history": history.DIR,
             "secret names": vault.INDEX, "backups": push.BACKUPS, "cve cache": cve.CACHE}
    leaks = {k: str(p) for k, p in paths.items() if real in Path(p).parents or Path(p) == real}
    assert not leaks, leaks


def test_each_account_has_its_own_dashboard(url):
    import json as _json
    call(url, "/api/prefs", {"theme": "tactics", "layouts": {"Mine": [["health", "t"]]}})  # the owner, before accounts
    admin = call(url, "/api/users", {"action": "add", "name": "ana", "password": "Admin-Pass-123", "role": "admin"})[1]["session"]
    _signed(url, "/api/users", {"action": "add", "name": "vic", "password": "Viewer-Pass-123", "role": "viewer"}, admin)
    vic = call(url, "/api/login", {"user": "vic", "password": "Viewer-Pass-123"})[1]["session"]
    assert _signed(url, "/api/prefs", None, vic)[1]["theme"] == "tactics"  # a new account starts from the owner's dashboard
    assert _signed(url, "/api/prefs", {"theme": "ember", "layouts": {}}, vic)[0] == 200
    assert _signed(url, "/api/prefs", None, admin)[1]["theme"] == "tactics"  # the viewer's change stays the viewer's
    assert _signed(url, "/api/prefs", None, vic)[1]["theme"] == "ember"
    assert _signed(url, "/api/prefs", {"local_only": False, "layouts": {}}, admin)[0] == 200
    assert _signed(url, "/api/prefs", None, vic)[1]["local_only"] is False  # the keep-data-local switch is shared
    saved = _json.loads(server.PREFS.read_text())
    assert set(saved["users"]) == {"local", "ana", "vic"}


def test_old_settings_files_become_the_owners_dashboard(url):
    server.PREFS.write_text(json.dumps({"theme": "diorama", "preset": "Security", "layouts": {"Security": [["stig", "s"]]}}))
    assert call(url, "/api/prefs")[1] == {"theme": "diorama", "preset": "Security", "layouts": {"Security": [["stig", "s"]]}}


def test_a_failed_login_on_one_device_keeps_the_record_of_the_others(url, monkeypatch):
    from oneconfig import push, trail

    def fake_apply(planned, values, login, **kw):
        if planned["hostname"] == "R2":
            raise ConnectionRefusedError("SSH refused")  # not a PushError: used to escape the loop
        return {"hostname": planned["hostname"], "status": "pushed", "snapshot": "s1", "login": login}
    monkeypatch.setattr(push, "apply_device", fake_apply)
    devs = {h: {"hostname": h, "ip": ip, "add": ["x"], "candidate": "x", "remove": []} for h, ip in (("R1", "10.0.0.1"), ("R2", "10.0.0.2"))}
    server.PLANS["p2"] = {"values": {"ENABLE-SECRET": "Long-Enough-9"}, "login": {"username": "u"}, "devices": devs, "at": time.monotonic()}
    job = call(url, "/api/push/apply", {"plan": "p2", "hostnames": ["R1", "R2"]})[1]["job"]
    while not server.JOBS[job]["done"]:
        time.sleep(0.05)
    res = {r["hostname"]: r for r in server.JOBS[job]["result"]["results"]}
    assert res["R1"]["status"] == "pushed" and "ConnectionRefusedError" in res["R2"]["error"]
    assert trail.read()[-1]["detail"] == {"results": {"R1": "pushed", "R2": "failed"}}  # the push to R1 is in the audit log
    assert server.PLANS["p2"]["values"] == {}  # and the secrets are dropped


def test_the_page_allows_no_inline_script(url):
    with urllib.request.urlopen(url + "/") as r:
        csp, page = r.headers["Content-Security-Policy"], r.read().decode()
    script = next(p for p in csp.split(";") if p.strip().startswith("script-src"))
    assert script.split() == ["script-src", "'self'"] and "<script>" not in page  # code comes only from /app.js
    with urllib.request.urlopen(url + "/app.js") as r:
        assert r.headers["Content-Type"].startswith("text/javascript") and r.headers["X-Content-Type-Options"] == "nosniff"
