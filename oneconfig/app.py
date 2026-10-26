"""OneConfig as a desktop app: the same local server, shown in its own window instead of a browser tab.

The server runs on a background thread for as long as the window is open. The window is given the launch key
directly (in the URL fragment, which never reaches the server's logs), so no launch file or browser is involved."""
import threading
from http.server import ThreadingHTTPServer

from . import server

PORT = 8470  # the usual port, so the page's per-viewer settings (kept per address) carry over between launches


def _start_server() -> int:
    try:
        srv = ThreadingHTTPServer(("127.0.0.1", PORT), server.Handler)
    except OSError:  # `oneconfig serve` (or another program) already has it: any free port works the same
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    server.private_dir()
    threading.Thread(target=srv.serve_forever, daemon=True).start()  # daemon: it ends when the window closes
    return srv.server_address[1]


def selfcheck() -> int:
    """`OneConfig.app/Contents/MacOS/OneConfig --selfcheck`: proves the packed app has what PyInstaller can't see
    by following imports (data files, parsers loaded by name, the keychain backend), without opening a window."""
    import json
    checks = {}

    def check(name, fn):
        try:
            checks[name] = f"ok: {fn()}"
        except Exception as e:
            checks[name] = f"FAILED: {type(e).__name__}: {e}"

    def configs():
        from .model import Network
        from .render import render
        from .stig import stig_audit
        net = Network.model_validate(json.loads((server.HERE / "examples" / "campus.json").read_text()))
        d = net.devices[0]
        return f"{d.hostname} renders, STIG {stig_audit(render(d, net), d.role, None, d.platform)['summary']['compliance']}%"
    check("templates, examples and STIG rules", configs)
    check("page", lambda: f"{len((server.HERE / 'ui' / 'app.js').read_bytes()):,} bytes of app.js")
    check("show output parsers", lambda: len(__import__("oneconfig.discover", fromlist=["_parse"])._parse(
        "show ip interface brief", "Interface  IP-Address  OK? Method Status  Protocol\nGi1  10.0.0.1  YES manual up  up\n")))
    check("SNMP engine and MIBs", lambda: f"{len(__import__('pysnmp.hlapi.v3arch.asyncio', fromlist=['SnmpEngine']).SnmpEngine().get_mib_builder().mibSymbols)} MIB modules")
    check("OS keychain", lambda: type(__import__("keyring").get_keyring()).__module__)
    check("SSH drivers", lambda: f"{len(__import__('netmiko').platforms)} platforms")
    print(json.dumps(checks, indent=1))
    return 0 if all(v.startswith("ok") for v in checks.values()) else 1


def main():
    import sys
    if "--selfcheck" in sys.argv:
        raise SystemExit(selfcheck())
    import webview
    port = _start_server()
    webview.settings["ALLOW_DOWNLOADS"] = True  # File > Save network and Export configs
    webview.create_window("OneConfig", f"http://127.0.0.1:{port}/#t={server.TOKEN}", width=1440, height=900, min_size=(720, 560))
    webview.start(private_mode=False)  # keep the page's own settings between launches


if __name__ == "__main__":
    main()
