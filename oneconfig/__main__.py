import argparse
import json
import sys
from pathlib import Path

from .audit import audit
from .model import Network
from .render import render_all
from .server import serve
from .stig import stig_audit


def main():
    p = argparse.ArgumentParser(prog="oneconfig")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="open the visual builder")
    s.add_argument("--port", type=int, default=8470)
    s.add_argument("--no-browser", action="store_true")
    b = sub.add_parser("build", help="render configs from a network JSON file")
    b.add_argument("network")
    b.add_argument("-o", "--out", default="configs")
    a = sub.add_parser("audit", help="audit a config file (e.g. show running-config output)")
    a.add_argument("config")
    a.add_argument("--os", choices=["ios-xe", "nx-os", "asa", "panos", "fortios", "eos", "junos"], default="ios-xe")
    t = sub.add_parser("stig", help="check a config against the DISA STIGs (IOS-XE, NX-OS, ASA, PAN-OS, FortiOS, Arista EOS or Junos)")
    t.add_argument("config")
    t.add_argument("--platform", choices=["router", "l3switch", "switch", "firewall"], required=True)
    t.add_argument("--os", choices=["ios-xe", "nx-os", "asa", "panos", "fortios", "eos", "junos"], default="ios-xe")
    t.add_argument("--external", default="", help="comma-separated external interfaces (turns on perimeter checks)")
    t.add_argument("--all", action="store_true", help="list every rule, not just open and manual ones")
    t.add_argument("--cklb", metavar="FILE", help="also write a DISA STIG Viewer 3 checklist (.cklb)")
    t.add_argument("--host", help="device name in the checklist (default: the config file's name)")
    d = sub.add_parser("discover", help="find devices: sweep, ssh, snmp or serial")
    d.add_argument("method", choices=["sweep", "ssh", "snmp", "serial"])
    d.add_argument("--scope", default="", help="networks discovery may touch, e.g. 10.99.0.0/24 (sweep, ssh, snmp)")
    d.add_argument("--seeds", default="", help="ssh: devices to start from; snmp: targets")
    d.add_argument("--username", default="")
    d.add_argument("--community", default="", help="SNMPv2c community (prompted if omitted for snmp)")
    d.add_argument("--port", default="", help="serial port, e.g. /dev/ttyUSB0 or COM3")
    d.add_argument("--baud", type=int, default=9600)
    d.add_argument("-o", "--out", help="save discovered devices and links as a network JSON file")
    k = sub.add_parser("backup", help="print a running-config backup that a push saved (decrypts .enc files with the keychain key)")
    k.add_argument("file")
    u = sub.add_parser("users", help="local accounts: list them, or reset (delete all accounts, back to no sign-in)")
    u.add_argument("action", choices=["list", "reset"])
    args = p.parse_args()

    if args.cmd == "serve":
        serve(args.port, not args.no_browser)
    elif args.cmd == "backup":
        from .seal import unseal
        print(unseal(Path(args.file).read_bytes()), end="")
    elif args.cmd == "users":
        from . import trail, users
        if args.action == "list":
            for x in users.listing():
                print(f"{x['name']:24} {x['role']}")
        else:  # whoever can delete files in ~/.oneconfig owns this install anyway; this is the locked-out admin's way back
            users.FILE.unlink(missing_ok=True)
            trail.record("local", "reset accounts", "from the command line")
            print("All accounts deleted. OneConfig no longer asks anyone to sign in.")
    elif args.cmd == "build":
        net = Network.model_validate_json(Path(args.network).read_text())
        out = Path(args.out)
        out.mkdir(exist_ok=True)
        platforms = {d.hostname: d.platform for d in net.devices}
        for host, cfg in render_all(net).items():
            (out / f"{host}.cfg").write_text(cfg)
            print(f"{host:20} score {audit(cfg, platforms[host])['score']:3}  -> {out / host}.cfg")
    elif args.cmd == "discover":
        import getpass
        from . import discover as D
        log = lambda m: print(m, file=sys.stderr)  # noqa: E731
        ask = lambda prompt: getpass.getpass(prompt)  # noqa: E731
        if args.method == "sweep":
            for hst in D.sweep(D.parse_scope(args.scope), log=log):
                print(f"{hst['ip']:16} {', '.join(map(str, hst['ports']))}")
            return
        if args.method == "snmp":
            scope = D.parse_scope(args.scope)
            nodes = D.snmp_discover(args.seeds.replace(",", " ").split(), scope,
                                    {"community": args.community or ask("SNMP community: ")}, log=log)
        else:
            creds = {"username": args.username or input("Username: "), "password": ask("Password: "),
                     "secret": ask("Enable secret (blank if none): ")}
            nodes = (D.ssh_walk(args.seeds.replace(",", " ").split(), D.parse_scope(args.scope), creds, log=log)
                     if args.method == "ssh" else D.serial_discover(args.port, args.baud, creds, log=log))
        for r in D.summarize(nodes):
            stig = f"STIG {r['stig']['summary']['compliance']}%" if "stig" in r else ""
            print(f"{'reached ' if r['reached'] else 'neighbor'} {r['hostname']:20} {r['role']:9} {r['mgmt_ip'] or '-':16} "
                  f"{r['platform']:16} {r['version']:10} {stig}")
        if args.out:
            Path(args.out).write_text(json.dumps({"name": "Discovered network", **D.to_fragment(nodes)}, indent=2))
            print(f"Saved {args.out}. Open it in the app with File > Open network.", file=sys.stderr)
    elif args.cmd == "stig":
        ext = [x.strip() for x in args.external.split(",") if x.strip()]
        r = stig_audit(Path(args.config).read_text(), args.platform, {"external": ext} if ext else None, args.os)
        s = r["summary"]
        if args.cklb:
            from .cklb import checklist
            Path(args.cklb).write_text(json.dumps(checklist(r, args.host or Path(args.config).stem), indent=1))
            print(f"Wrote {args.cklb}", file=sys.stderr)
        print(" + ".join(f"{b['id'].replace('_', ' ')} V{b['version']}R{b['release']}" for b in r["benchmarks"]))
        print(f"Compliance {s['compliance']}%  open CAT I {s['open']['CAT I']} / CAT II {s['open']['CAT II']} / CAT III "
              f"{s['open']['CAT III']}  not a finding {s['not_a_finding']}  N/A {s['not_applicable']}  not reviewed {s['not_reviewed']}")
        for x in r["results"]:
            if args.all or x["status"] in ("open", "not_reviewed"):
                print(f"\n[{x['status'].upper()}] {x['cat']} {x['id']} ({x['vuln']}) {x['title']}\n  {x['detail']}")
                if x["fix"]:
                    print("  fix:\n    " + x["fix"].replace("\n", "\n    "))
        sys.exit(1 if any(s["open"].values()) else 0)
    else:
        r = audit(Path(args.config).read_text(), args.os)
        print(f"Security score: {r['score']}/100")
        for f in r["findings"]:
            print(f"\n[{f['severity'].upper()}] {f['title']}  {f['where']}\n  why: {f['why']}")
            if f["fix"]:
                print("  fix:\n    " + f["fix"].replace("\n", "\n    "))
        sys.exit(1 if any(f["severity"] in ("critical", "high") for f in r["findings"]) else 0)


if __name__ == "__main__":
    main()
