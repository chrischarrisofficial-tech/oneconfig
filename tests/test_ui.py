"""Browser tests of the UI against the real local server (Playwright). Skipped when Playwright isn't installed:
pip install playwright && playwright install chromium"""
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sync_api = pytest.importorskip("playwright.sync_api")
keyring = pytest.importorskip("keyring")
from keyring.backend import KeyringBackend  # noqa: E402

from fakelab import PASSWORD, USER, FakeDevice, start_ssh  # noqa: E402
from oneconfig import ai, cve, push, server, vault  # noqa: E402

FIX = Path(__file__).parent / "fixtures"


class MemKeyring(KeyringBackend):
    priority = 1

    def __init__(self):
        self.d = {}

    def get_password(self, s, u):
        return self.d.get((s, u))

    def set_password(self, s, u, p):
        self.d[(s, u)] = p

    def delete_password(self, s, u):
        self.d.pop((s, u), None)


@pytest.fixture
def app(monkeypatch, tmp_path):
    kr, old = MemKeyring(), keyring.get_keyring()
    keyring.set_keyring(kr)
    monkeypatch.setattr(vault, "INDEX", tmp_path / "names.json")
    monkeypatch.setattr(push, "BACKUPS", tmp_path / "backups")
    monkeypatch.setattr(cve, "CACHE", tmp_path / "cve.json")
    monkeypatch.setattr(server, "PREFS", tmp_path / "ui.json")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    errors = []
    with sync_api.sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # browser binary not installed
            pytest.skip(f"Chromium not available: {e}")
        page = browser.new_page(viewport={"width": 1500, "height": 1000}, bypass_csp=True)  # wait_for_function evals; the app never does (see test_page_runs_under_its_own_csp)
        page.on("console", lambda m: m.type == "error" and "status of 400" not in m.text and "status of 401" not in m.text and errors.append(m.text))  # 400 = validation shown in the UI; 401 = the stale-key test
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("dialog", lambda d: (errors.append(f"browser dialog: {d.message}"), d.dismiss()))  # the app asks in-page; a native one is a bug
        page.goto(f"http://127.0.0.1:{srv.server_address[1]}/#t={server.TOKEN}")
        page.wait_for_selector('g.node[data-h="ACC-SW1"]')
        yield page, kr
        browser.close()
    srv.shutdown()
    keyring.set_keyring(old)
    assert errors == []


def _field(page, label):
    return page.locator(f'label.fld:has-text("{label}") input')


def _set(page, label, value):
    _field(page, label).fill(value)
    _field(page, label).press("Tab")


def test_push_flow_blocks_lockout_then_pushes_ticked_removals_and_rolls_back(app, monkeypatch):
    pg, kr = app
    dev = FakeDevice("ACC-SW1", (FIX / "brownfield_acc1.cfg").read_text(), seconds_per_minute=30)
    port = start_ssh(dev)
    real = push.connect
    monkeypatch.setattr(push, "connect", lambda ip, login, **kw: real("127.0.0.1", login, port=port, timeout=8, nos=kw.get("nos", "ios-xe")))
    pg.click('g.node[data-h="ACC-SW1"]')
    pg.click('.levels button:has-text("Intermediate")')
    _set(pg, "Management IP", "10.99.0.11")
    pg.wait_for_timeout(500)

    def plan(first):
        pg.click('#cmd button:has-text("Push")')
        if first:
            for h in ("EDGE-R1", "CORE-SW1", "ACC-SW2"):
                assert pg.locator(f'#modal label.chk:has-text("{h}") input').is_disabled()  # no management IP
            _field(pg, "Username").fill(USER)
            pg.locator('#modal label.fld:has-text("Password") input').first.fill(PASSWORD)
            pg.locator('#modal label.chk:has-text("Remember this login") input').check()
        pg.click('#modal button:has-text("Next: secrets")')
        pg.wait_for_selector('#modal h3:has-text("3. Secrets")')
        if first:
            for f in pg.locator('#modal label.fld').all():
                name = f.locator("span").inner_text()
                f.locator("input").fill({"ADMIN-USER": "admin", "SNMP-USER": "oneconfig"}.get(name, f"Lab-{name}-Value-9"))
            pg.locator('#modal label.chk:has-text("Remember new values") input').check()
        else:  # second run: everything comes from the keychain
            assert pg.locator('#modal input[placeholder="saved in keychain"]').count() == 9
        pg.click('#modal button:has-text("Plan (read-only)")')
        pg.wait_for_selector('#modal h3:has-text("4. Review")', timeout=60000)

    plan(first=True)
    assert "outside the management subnet" in pg.inner_text("#modal")  # this computer is 127.0.0.1
    pg.locator("#modal").press("Escape")
    box = pg.locator("svg#topo").bounding_box()
    pg.click("svg#topo", position={"x": box["width"] - 12, "y": box["height"] - 12})  # empty corner: deselect, network settings
    pg.click('button[role=tab]:has-text("Security")')
    _set(pg, "Mgmt subnet", "127.0.0.0/8")
    pg.wait_for_timeout(500)
    plan(first=False)
    txt = pg.inner_text("#modal")
    assert "+ vtp mode off" in txt and "− no snmp-server community <redacted>" in txt
    assert "Lab-ENABLE-SECRET-Value-9" not in pg.content()  # secrets never reach the page
    assert "community public" not in pg.content() and "community private" not in pg.content()  # nor the device's own
    pg.locator(f'#modal .rmlist label.chk:has-text("#{hashlib.sha256(b"no snmp-server community public").hexdigest()[:6]}") input').check()
    pg.click('#modal button:has-text("Push to 1 device")')
    pg.click('#ask button:has-text("Push now")')  # OneConfig's own confirm, not the browser's
    pg.wait_for_selector('#modal h3:has-text("Results")', timeout=120000)
    assert "Snapshot flash:oneconfig-archive-1" in pg.inner_text("#modal")
    run = dev.cfg.text()
    assert "community public" not in run and "community private" in run and dev.startup  # only the ticked removal
    pg.click('#modal button:has-text("Roll back")')
    pg.click('#ask button:has-text("Roll back")')
    pg.wait_for_function("document.querySelector('#modal').innerText.includes('logged in again after the rollback')", timeout=60000)
    assert "snmp-server community public RO" in dev.cfg.text()
    nid = pg.evaluate("net.id")  # saved under this network's own id, not its name
    assert f"{nid}/@login" in {u for _, u in kr.d} and not any(u.startswith("Campus Starter/") for _, u in kr.d)


def test_cve_keys_and_advisor(app, monkeypatch):
    pg, kr = app
    nvd = json.loads((FIX / "cve" / "nvd_iosxe_17.9.4a.json").read_text())
    monkeypatch.setattr(cve, "http", lambda *a, **k: nvd)
    seen = []
    answer = "Change on ACC-SW1.\n\n```\ninterface GigabitEthernet1/0/5\n switchport access vlan 20\n```\nRisk: the port flaps once."

    class Fake(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
            out = {"content": [{"type": "text", "text": "Claude says: fix CAT I first."}]} if self.path == "/v1/messages" \
                else {"choices": [{"message": {"content": answer}}]}
            raw = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass
    fake = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    furl = f"http://127.0.0.1:{fake.server_address[1]}"
    monkeypatch.setattr(ai, "CLAUDE_URL", furl + "/v1/messages")

    # CVE check from the Config tab
    pg.click('g.node[data-h="EDGE-R1"]')
    pg.click('.levels button:has-text("Intermediate")')
    _set(pg, "OS version", "17.09.04a")
    pg.wait_for_timeout(600)
    pg.click('button[role=tab]:has-text("Config")')
    pg.click('button:has-text("Check now")')
    pg.wait_for_selector('.chip:has-text("Critical: 3")', timeout=20000)
    assert pg.locator('aside details.finding:has-text("CVE-2026-20272")').count() == 1

    # API keys go to the keychain; only names come back
    pg.click('#cmd button:has-text("File")')
    pg.click('#cmd button:has-text("API keys")')
    _set(pg, "Claude API key", "sk-ant-test-Secret-42")
    pg.click('#modal button:has-text("Save")')
    pg.wait_for_timeout(400)
    pg.click('#cmd button:has-text("File")')
    pg.click('#cmd button:has-text("API keys")')
    pg.wait_for_selector('#modal input[placeholder="saved"]')
    assert "sk-ant-test-Secret-42" not in pg.content()
    pg.locator("#modal").press("Escape")

    # local model: preview is exactly what's sent
    pg.click('#cmd button:has-text("Advisor")')
    _set(pg, "Server URL", furl + "/v1")
    pg.locator('#modal label.fld:has-text("Task") select').select_option("draft")
    pg.locator('#modal label.fld:has-text("Scope") select').select_option("ACC-SW1")
    pg.locator("#modal textarea").fill("Move Gi1/0/5 to VLAN 20")
    pg.click("#modal button:has-text(\"Preview what's sent\")")
    pg.wait_for_selector('#modal h3:has-text("tokens")')
    prev = pg.inner_text("#modal pre")
    assert "User request: Move Gi1/0/5 to VLAN 20" in prev and "<ENABLE-SECRET>" in prev
    pg.click('#modal button:has-text("Ask")')
    pg.wait_for_selector("#modal .answer pre", timeout=20000)
    assert "switchport access vlan 20" in pg.inner_text("#modal .answer pre")
    assert seen[-1][0] == "/v1/chat/completions" and seen[-1][2]["messages"][1]["content"] in prev
    pg.locator("#modal").press("Escape")

    # Claude with the saved key, never typed into the Advisor
    pg.click('#cmd button:has-text("Advisor")')
    assert pg.locator('#modal label.fld:has-text("Provider") option[value=claude]').count() == 0  # kept on this computer by default
    pg.locator('#modal label.fld:has-text("Keep my network data") input').uncheck()
    pg.wait_for_function("PREF.local_only === false")
    pg.locator('#modal label.fld:has-text("Provider") select').select_option("claude")
    pg.locator('#modal label.fld:has-text("Task") select').select_option("explain")
    pg.click('#modal button:has-text("Ask")')
    pg.wait_for_selector('#modal .answer:has-text("Claude says")', timeout=20000)
    path, hdr, body = seen[-1]
    assert path == "/v1/messages" and hdr["x-api-key"] == "sk-ant-test-Secret-42" and hdr["anthropic-version"] == "2023-06-01"
    assert body["model"] == "claude-sonnet-5-5" and "Explain the open findings" in body["system"]
    assert "sk-ant" not in (pg.evaluate("localStorage.getItem('oneconfig.ai')") or "")
    fake.shutdown()


def test_platform_switch_renders_nxos_and_audits_eos(app):
    pg, _ = app
    pg.click('g.node[data-h="ACC-SW1"]')
    pg.locator('label.fld:has-text("Platform") select').select_option("nx-os")
    pg.wait_for_selector('text=voice VLANs for IOS-XE only')  # ACC-SW1's desk port has a voice VLAN: explained, not generated
    pg.locator('label.fld:has-text("Platform") select').select_option("ios-xe")
    pg.click('g.node[data-h="CORE-SW1"]')
    pg.locator('label.fld:has-text("Platform") select').select_option("nx-os")
    pg.wait_for_function("document.querySelector('g.node[data-h=\"CORE-SW1\"]').textContent.includes('NX-OS')")
    pg.click('button[role=tab]:has-text("Config")')
    pg.wait_for_selector('pre.config:has-text("feature lacp")')
    cfg = pg.inner_text("pre.config")
    assert "(l3switch, NX-OS)" in cfg and "ip router ospf 1 area 0.0.0.0" in cfg
    assert "interface Ethernet1/" in cfg and "GigabitEthernet" not in cfg  # ports renamed with the platform
    assert "NXOS NDM V3R6" in pg.inner_text("aside")
    pg.click('#cmd button:has-text("Audit")')
    pg.locator('#modal label.fld:has-text("Operating system") select').select_option("eos")
    pg.locator('#modal label.fld:has-text("STIG platform") select').select_option("switch")
    pg.locator("#modal textarea").fill("hostname LEAF1\nmanagement telnet\n   no shutdown\ninterface Ethernet1\n   switchport mode access\n")
    pg.click('#modal button:has-text("Run audit")')
    pg.wait_for_selector('#modal :text("EOS NDM V2R2")')
    txt = pg.inner_text("#modal")
    assert "Telnet enabled" in txt and "ARST-ND-000340" in txt
    pg.locator("#modal").press("Escape")
    pg.click('#cmd button:has-text("Build")')
    pg.click('#cmd button:has-text("Switch")')  # a new device takes the selected device's OS
    pg.click('button[role=tab]:has-text("Interfaces")')
    pg.click('button:has-text("Add interface")')
    pg.wait_for_selector('aside :text("Ethernet1/1")')


def test_platform_switch_to_junos_renames_ports_and_renders_set_form(app):
    pg, _ = app
    pg.click('g.node[data-h="EDGE-R1"]')
    pg.locator('label.fld:has-text("Platform") select').select_option("junos")
    pg.wait_for_function("document.querySelector('g.node[data-h=\"EDGE-R1\"]').textContent.includes('Junos')")
    pg.click('button[role=tab]:has-text("Config")')
    pg.wait_for_selector('pre.config:has-text("set system host-name EDGE-R1")')
    cfg = pg.inner_text("pre.config")
    assert "set interfaces ge-0/0/0 unit 0 family inet address 203.0.113.2/30" in cfg and "lo0 unit 0 family inet address" in cfg
    assert "GigabitEthernet" not in cfg and "Loopback0" not in cfg
    assert "JUNOS RTR NDM V3R2" in pg.inner_text("aside")
    pg.click('button[role=tab]:has-text("Interfaces")')
    pg.click('button:has-text("Add interface")')
    pg.wait_for_selector('text=ge-0/0/2')  # next free Junos port counts from 0


def test_firewall_example_rules_tab_and_new_firewall(app):
    pg, _ = app
    pg.evaluate("() => { loadExample('edge'); }")  # don't wait on its promise: it waits for the confirm below
    pg.click('#ask button:has-text("Replace")')
    pg.wait_for_selector('g.node[data-h="EDGE-FW1"]')
    pg.click('g.node[data-h="EDGE-FW1"]')
    tabs = pg.locator("#panel .tabs button[role=tab]").all_inner_texts()
    assert tabs[:5] == ["General", "Interfaces", "Zones", "Objects", "Rules"] and "ACLs" not in tabs
    pg.click('button[role=tab]:has-text("Rules")')
    pg.click('button:has-text("Add rule")')
    pg.locator('details[open] label.fld:has-text("From zone") select').select_option("DMZ")
    pg.locator('details[open] label.fld:has-text("To zone") select').select_option("INSIDE")
    pg.locator('details[open] label.fld:has-text("Action") select').select_option("deny")
    pg.click('button[role=tab]:has-text("Config")')
    pg.wait_for_selector('pre.config:has-text("access-list DMZ_IN remark RULE-6")')
    cfg = pg.inner_text("pre.config")
    assert "access-list DMZ_IN extended deny ip any4 object-group ZONE-INSIDE-NETS log" not in cfg  # INSIDE runs OSPF: an open zone
    assert "access-group OUTSIDE_IN in interface OUTSIDE" in cfg and "failover lan unit primary" in cfg
    assert "ASA NDM V2R5" in pg.inner_text("aside")
    pg.evaluate("addDevice('firewall')")
    pg.wait_for_selector('g.node[data-h="FW1"]')
    assert "ASA" in pg.locator('g.node[data-h="FW1"]').text_content()


def test_firewall_switches_from_asa_to_panos(app):
    pg, _ = app
    pg.evaluate("() => { loadExample('edge'); }")  # don't wait on its promise: it waits for the confirm below
    pg.click('#ask button:has-text("Replace")')
    pg.wait_for_selector('g.node[data-h="EDGE-FW1"]')
    pg.click('g.node[data-h="EDGE-FW1"]')
    pg.locator('label.fld:has-text("Platform") select').select_option("panos")
    pg.wait_for_function("document.querySelector('g.node[data-h=\"EDGE-FW1\"]').textContent.includes('PAN-OS')")
    pg.click('button[role=tab]:has-text("Config")')
    pg.wait_for_selector('pre.config:has-text("set deviceconfig system hostname EDGE-FW1")')
    cfg = pg.inner_text("pre.config")
    assert "set zone OUTSIDE network layer3 ethernet1/1" in cfg and "set network interface ethernet ethernet1/8 ha" in cfg
    assert "MANAGEMENT" not in cfg and "GigabitEthernet" not in cfg and "standby" not in cfg
    assert "PAN NDM V3R4" in pg.inner_text("aside")


def test_firewall_switches_from_asa_to_fortigate(app):
    pg, _ = app
    pg.evaluate("() => { loadExample('edge'); }")  # don't wait on its promise: it waits for the confirm below
    pg.click('#ask button:has-text("Replace")')
    pg.wait_for_selector('g.node[data-h="EDGE-FW1"]')
    pg.click('g.node[data-h="EDGE-FW1"]')
    pg.locator('label.fld:has-text("Platform") select').select_option("fortios")
    pg.wait_for_function("document.querySelector('g.node[data-h=\"EDGE-FW1\"]').textContent.includes('FortiOS')")
    pg.click('button[role=tab]:has-text("Config")')
    pg.wait_for_selector('pre.config:has-text("set hostname")')
    cfg = pg.inner_text("pre.config")
    assert '    edit "OUTSIDE"\n        set interface "port1"' in cfg and 'set hbdev "port8" 50' in cfg
    assert "MANAGEMENT" not in cfg and "GigabitEthernet" not in cfg
    assert "FORTI NDM V1R6 · FORTI FW V1R5" in pg.inner_text("aside")


def test_stig_checklist_downloads(app):
    pg, _ = app
    pg.evaluate("() => { loadExample('edge'); }")  # don't wait on its promise: it waits for the confirm below
    pg.click('#ask button:has-text("Replace")')
    pg.wait_for_selector('g.node[data-h="EDGE-FW1"]')
    pg.click('g.node[data-h="EDGE-FW1"]')
    pg.click('button[role=tab]:has-text("Config")')
    with pg.expect_download() as dl:
        pg.click('button:has-text("Download checklist (.cklb)")')
    assert dl.value.suggested_filename == "EDGE-FW1.cklb"
    c = json.loads(Path(dl.value.path()).read_text())
    assert c["target_data"]["host_name"] == "EDGE-FW1" and [s["stig_id"] for s in c["stigs"]][0] == "Cisco_ASA_NDM_STIG"


def test_opened_file_cannot_inject_into_the_map(app):
    """Device positions are drawn into SVG markup: a shared network file must not be able to add an event handler."""
    pg, _ = app
    pg.evaluate("""setNet({devices:[{hostname:"A", role:"router", x:'0) " onfocus="window.pwned=1', y:'1" onclick="window.pwned=1'}]})""")
    pg.wait_for_selector('g.node[data-h="A"]')
    g = pg.locator('g.node[data-h="A"]')
    assert g.get_attribute("onfocus") is None and g.get_attribute("onclick") is None and g.get_attribute("transform") == "translate(0,0)"


def test_dashboard_is_customizable_and_saved(app):
    pg, _ = app
    assert pg.locator('#dash .w[data-w="health"]').count() == 1
    pg.click("#customize")
    pg.click('#dash .w[data-w="links"] button[aria-label="Remove Links"]')
    assert pg.locator('#dash .w[data-w="links"]').count() == 0
    pg.click('.lib button:has-text("+ Links")')  # back from the widget library
    assert pg.locator('#dash .w[data-w="links"]').count() == 1
    pg.click('#dash .w[data-w="devices"] button[aria-label="Resize Devices"]')
    assert "w2" in pg.get_attribute('#dash .w[data-w="devices"]', "class")
    pg.click('.lib button:has-text("Security")')  # another layout
    assert pg.locator('#dash .w[data-w="top"]').count() == 1 and pg.locator('#dash .w[data-w="links"]').count() == 0
    pg.select_option("#theme", "twilight")
    pg.click("#customize")  # Done
    for _ in range(50):  # saved a moment after the last change
        p = server.prefs_get()
        if p.get("theme") == "twilight":
            break
        pg.wait_for_timeout(100)
    assert p["theme"] == "twilight" and p["preset"] == "Security" and ["devices", "w"] in p["layouts"]["Overview"]
    pg.reload()
    pg.wait_for_selector('g.node[data-h="ACC-SW1"]')
    assert pg.evaluate("document.documentElement.dataset.theme") == "twilight" and pg.locator('#dash .w[data-w="top"]').count() == 1
    pg.click('g.node[data-h="CORE-SW1"]')  # widgets follow the selection
    assert "CORE-SW1" in pg.inner_text('#dash .w[data-w="selected"]')


def _drag_to_trash(pg, host):
    node = pg.locator(f'g.node[data-h="{host}"] rect.slab').bounding_box()
    trash = pg.locator("#trash").bounding_box()
    pg.mouse.move(node["x"] + node["width"] / 2, node["y"] + node["height"] / 2)
    pg.mouse.down()
    pg.mouse.move(trash["x"] + 23, trash["y"] + 23, steps=8)
    pg.wait_for_function("document.querySelector('#trash').classList.contains('hot')")  # Chrome delivers the last move on the next frame
    pg.mouse.up()


def test_delete_from_the_panel_and_by_dragging_to_the_trash(app):
    pg, _ = app
    pg.click('g.node[data-h="ACC-SW2"]')
    pg.click('#panel button:has-text("Delete device")')
    pg.click('#ask button:has-text("Delete")')  # an in-page dialog: embedded browsers that block confirm() still delete
    pg.wait_for_selector('g.node[data-h="ACC-SW2"]', state="detached")
    assert pg.evaluate("net.links.some(l => l.a === 'ACC-SW2' || l.b === 'ACC-SW2')") is False

    before = pg.evaluate("[dev('ACC-SW1').x, dev('ACC-SW1').y]")
    _drag_to_trash(pg, "ACC-SW1")
    pg.click('#ask button:has-text("Cancel")')  # cancelled: it stays, back where it was
    assert pg.evaluate("[dev('ACC-SW1').x, dev('ACC-SW1').y]") == before
    _drag_to_trash(pg, "ACC-SW1")
    pg.click('#ask button:has-text("Delete")')
    pg.wait_for_selector('g.node[data-h="ACC-SW1"]', state="detached")
    assert pg.evaluate("JSON.parse(localStorage.getItem('oneconfig.net')).devices.some(d => d.hostname === 'ACC-SW1')") is False


def _slab(pg, host):
    b = pg.locator(f'g.node[data-h="{host}"] rect.slab').bounding_box()
    return b["x"] + b["width"] / 2, b["y"] + b["height"] / 2, b["width"]


def test_map_pans_and_zooms(app):
    pg, _ = app
    box = pg.locator("svg#topo").bounding_box()
    x0, y0, w0 = _slab(pg, "CORE-SW1")
    pg.mouse.move(box["x"] + box["width"] - 30, box["y"] + 30)  # empty space: drag pans
    pg.mouse.down()
    pg.mouse.move(box["x"] + box["width"] - 90, box["y"] + 70, steps=6)
    pg.mouse.up()
    x1, y1, _ = _slab(pg, "CORE-SW1")
    assert round(x1 - x0) == -60 and round(y1 - y0) == 40
    pg.mouse.move(x1, y1)
    pg.mouse.wheel(0, -300)  # zoom in around the pointer: the device under it stays put and grows
    pg.wait_for_timeout(100)
    x2, y2, w2 = _slab(pg, "CORE-SW1")
    assert w2 > w0 * 1.3 and abs(x2 - x1) < 2 and abs(y2 - y1) < 2
    pg.click('#zoomctl button[data-z="out"]')
    assert _slab(pg, "CORE-SW1")[2] < w2
    pg.evaluate("drawCanvas()")  # a rebuild keeps the user's view
    assert w0 < _slab(pg, "CORE-SW1")[2] < w2
    pg.click('#zoomctl button[data-z="fit"]')
    assert abs(_slab(pg, "CORE-SW1")[2] - w0) < 1
    pg.click('g.node[data-h="EDGE-R1"]')
    pg.mouse.click(box["x"] + box["width"] - 30, box["y"] + 30)  # a click without dragging still deselects
    assert pg.evaluate("sel") is None


def test_half_screen_window_keeps_the_map_and_opens_the_panel_as_a_drawer(app):
    pg, _ = app
    pg.set_viewport_size({"width": 900, "height": 1000})  # half of a 1800px screen

    def drawer(open_):  # waits out the slide
        pg.wait_for_function("v => (getComputedStyle(document.querySelector('aside')).visibility === 'visible') === v", arg=open_)
    drawer(False)
    assert pg.evaluate("document.querySelector('header').scrollWidth <= innerWidth")
    pg.click('g.node[data-h="CORE-SW1"]')  # picking a device opens the drawer
    drawer(True)
    assert pg.locator("#panel h2").inner_text() == "CORE-SW1"
    pg.click("#panel .pclose")
    drawer(False)
    pg.click("#panelbtn")  # and the header button brings it back
    drawer(True)
    pg.keyboard.press("Escape")
    drawer(False)
    assert pg.evaluate("[...document.querySelectorAll('#dash .w')].every(t => t.scrollHeight <= t.clientHeight + 1)")


def test_engineering_widgets(app):
    pg, _ = app
    tile = lambda k: pg.locator(f'#dash .w[data-w="{k}"]').inner_text()  # noqa: E731
    pg.click("#customize")
    pg.click('.lib button:has-text("Engineering")')  # the new widgets have their own layout
    pg.click("#customize")
    pg.wait_for_function("SIDE.per && Object.keys(SIDE.per).length === 4")  # push needs came back from the server
    assert "All 3 links check out" in tile("linkchecks")
    assert "0 of 4 devices ready to push" in tile("pushready") and "No management IP" in tile("pushready")
    assert "VLAN 10" in tile("vlans") and "OSPF 10.255.0.1" in tile("routes")
    assert "4 devices with no version" in tile("versions") and "No firewalls" in tile("fwrules") and "4 devices never backed up" in tile("backups")
    pg.evaluate("dev('ACC-SW2').interfaces.find(i => i.name === 'GigabitEthernet1/0/48').trunk_vlans = '10'; changed()")
    pg.wait_for_function("document.querySelector('#dash .w[data-w=linkchecks]').innerText.includes('Allowed VLANs differ')")
    pg.locator('#dash .w[data-w="linkchecks"] .item').first.click()  # a problem opens that device's interfaces
    assert pg.evaluate("[sel, tab]") == ["CORE-SW1", "interfaces"]

    spare = pg.evaluate("""[...document.querySelectorAll('#dash .w[data-w] .list')].map(l => {
      const t = l.closest('.w'); return t.getBoundingClientRect().bottom - l.getBoundingClientRect().bottom - parseFloat(getComputedStyle(t).paddingBottom); })""")
    step = pg.evaluate("(g => parseFloat(g.gridAutoRows) + parseFloat(g.rowGap))(getComputedStyle(document.querySelector('#dash')))")
    assert spare and max(spare) <= step + 2, (spare, step)  # within one quarter step of the tile's edge: no big empty band


def test_a_layout_holds_at_most_12_widgets(app):
    pg, _ = app
    pg.click("#customize")
    assert "11 of 12 used" in pg.inner_text(".lib")
    pg.locator(".lib .items button").first.click()  # the twelfth
    assert "12 of 12 used" in pg.inner_text(".lib") and pg.locator(".lib .items button").count() == 0
    assert "the most it can" in pg.inner_text(".lib .items")


def test_add_a_device_by_brand_and_model(app):
    pg, _ = app
    pg.click('#cmd button:has-text("Build")')
    pg.click('#cmd .fly button:has-text("By brand and model")')
    pg.select_option('#modal select[aria-label="Brand"]', "Juniper")
    pg.select_option('#modal select[aria-label="Model"]', "QFX5120")
    assert "layer 3 switch running Junos" in pg.inner_text("#modal")
    pg.fill('#modal input[aria-label="Hostname"]', "CORE-SW1")  # taken
    pg.click('#modal button:has-text("Add to map")')
    assert "already a device called CORE-SW1" in pg.inner_text("#modal")
    pg.fill('#modal input[aria-label="Hostname"]', "DC-SPINE1")
    pg.click('#modal button:has-text("Add to map")')
    pg.wait_for_selector('g.node[data-h="DC-SPINE1"]')
    d = pg.evaluate("dev('DC-SPINE1')")
    assert (d["role"], d["platform"], d["model"]) == ("l3switch", "junos", "QFX5120")
    assert "QFX5120" in pg.inner_text("#panel .ptitle")
    pg.wait_for_function("built['DC-SPINE1'] !== undefined")  # the server accepts the model and builds it


def test_page_runs_under_its_own_csp(app):
    """No bypass here: the real Content-Security-Policy, and the app must load, draw and build without a single violation."""
    pg, _ = app
    with pg.context.browser.new_page(viewport={"width": 1500, "height": 1000}) as strict:
        problems = []
        strict.on("console", lambda m: m.type == "error" and problems.append(m.text))
        strict.on("pageerror", lambda e: problems.append(str(e)))
        strict.goto(pg.url.split("#")[0] + "#t=" + server.TOKEN)
        strict.wait_for_selector('g.node[data-h="ACC-SW1"]')
        strict.wait_for_timeout(1500)  # the first build and the side calls come back
        assert strict.evaluate("Object.keys(built).length") == 4 and problems == [], problems
        # a name that slipped past esc() would land as markup like this; the policy refuses its inline handler
        strict.evaluate("""() => { const d = document.createElement("div");
            d.innerHTML = '<img src="data:image/png;base64,AA" onerror="window.pwned = 1">'; document.body.append(d); }""")
        strict.wait_for_timeout(300)
        assert strict.evaluate("window.pwned") is None and any("Content Security Policy" in p for p in problems), problems


def test_a_tab_with_an_old_key_says_so(app):
    pg, _ = app
    pg.route("**/api/prefs", lambda route: route.fulfill(status=401, body='{"error":"x"}', content_type="application/json"))
    pg.evaluate("() => { fetch('/api/prefs'); }")
    pg.wait_for_selector("#stale")
    assert "was restarted" in pg.inner_text("#stale")
    pg.unroute("**/api/prefs")


def _file_menu(pg, item):
    pg.click('#cmd button:has-text("File")')
    pg.click(f'#cmd .fly button:has-text("{item}")')


def test_accounts_sign_in_and_audit_log(app):
    pg, _ = app
    _file_menu(pg, "Users")
    _field(pg, "User name").fill("ana")
    pg.locator('#modal label.fld:has-text("Password") input').first.fill("Admin-Pass-123")
    pg.click('#modal button:has-text("Create admin")')
    pg.wait_for_selector('#who:has-text("ana")')  # signed straight in as the first admin
    pg.reload()
    pg.wait_for_selector('#who:has-text("ana")')  # a reload in the same tab stays signed in
    pg.click('#who button:has-text("Sign out")')
    pg.wait_for_selector("#signin")  # accounts are on: signed out, nothing works until you sign in
    pg.fill('#signin input[aria-label="User name"]', "ana")
    pg.fill('#signin input[aria-label="Password"]', "wrong-password!")
    pg.click('#signin button:has-text("Sign in")')
    pg.wait_for_selector('#signin .errors:has-text("Wrong user name or password")')
    pg.fill('#signin input[aria-label="Password"]', "Admin-Pass-123")
    pg.click('#signin button:has-text("Sign in")')
    pg.wait_for_selector('g.node[data-h="ACC-SW1"]')
    assert "admin" in pg.inner_text("#who")
    _file_menu(pg, "Audit log")
    pg.wait_for_selector("#modal table.trail")
    log = pg.inner_text("#modal")
    assert "chain intact" in log and "add user" in log and "sign-in failed" in log and "Admin-Pass" not in log
    with pg.context.browser.new_page() as other:  # another tab with the launch link but no session: sign-in, not the app
        other.goto(pg.url.split("#")[0] + "#t=" + server.TOKEN)
        other.wait_for_selector("#signin")
        assert other.locator('g.node').count() == 0


def test_history_brings_back_a_deleted_device(app):
    pg, _ = app
    pg.click('g.node[data-h="ACC-SW2"]')
    pg.click('#panel button:has-text("Delete device")')
    pg.click('#ask button:has-text("Delete")')
    pg.wait_for_selector('g.node[data-h="ACC-SW2"]', state="detached")
    _file_menu(pg, "History")
    pg.wait_for_selector('#modal .devrow:has-text("before deleting ACC-SW2")')
    pg.locator('#modal .devrow:has-text("before deleting ACC-SW2") button:has-text("Restore")').click()
    pg.click('#ask button:has-text("Restore")')
    pg.wait_for_selector('g.node[data-h="ACC-SW2"]')
    assert pg.evaluate("net.links.some(l => l.b === 'ACC-SW2')")  # its links came back with it


def test_ip_plan_flags_a_duplicate_address(app):
    pg, _ = app
    pg.click("#customize")
    pg.click('.lib button:has-text("Engineering")')
    pg.click("#customize")
    assert "no duplicates or overlaps" in pg.inner_text('#dash .w[data-w="ipplan"]')
    pg.evaluate("dev('ACC-SW2').interfaces.push({name:'Vlan10', mode:'routed', ip:'10.10.0.1/24'}); changed()")  # CORE-SW1's Vlan10 address
    pg.wait_for_function("document.querySelector('#dash .w[data-w=ipplan]').innerText.includes('10.10.0.1 is used twice')")


def test_known_models_get_their_real_port_names(app):
    pg, _ = app
    pg.click('#cmd button:has-text("Build")')
    pg.click('#cmd .fly button:has-text("By brand and model")')
    pg.select_option('#modal select[aria-label="Model"]', "Catalyst 9300")
    pg.fill('#modal input[aria-label="Hostname"]', "IDF-SW9")
    pg.click('#modal button:has-text("Add to map")')
    pg.wait_for_selector('g.node[data-h="IDF-SW9"]')
    assert "48 × Gi1/0/1–48" in pg.inner_text("#panel")
    assert pg.evaluate("[nextIf(dev('IDF-SW9'), true), nextIf(dev('IDF-SW9'))]") == ["TenGigabitEthernet1/1/1", "GigabitEthernet1/0/1"]
