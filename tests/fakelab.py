"""Fake IOS-XE devices for discovery tests: an SSH server (paramiko) and a serial console (pty)."""
import copy
import os
import re
import secrets
import socket
import threading
import time
from pathlib import Path

import paramiko

FIX = Path(__file__).parent / "fixtures"
USER, PASSWORD = "admin", "Lab-Pass-123!"
_KEY = paramiko.RSAKey.generate(2048)


def _version(host, hw):
    return (FIX / "core_version.txt").read_text().replace("CORE-SW1", host).replace("C9300-48P", hw)


def _cdp_entry(dev_id, ip, platform, caps, local, remote):
    return (f"-------------------------\nDevice ID: {dev_id}\nEntry address(es): \n  IP address: {ip}\n"
            f"Platform: cisco {platform},  Capabilities: {caps} \nInterface: {local},  Port ID (outgoing port): {remote}\n"
            f"Holdtime : 150 sec\n\nVersion :\nCisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), "
            f"Version 17.9.4a, RELEASE SOFTWARE (fc3)\n\nadvertisement version: 2\nManagement address(es): \n  IP address: {ip}\n\n")


def lab(core_config=""):
    """CORE-SW1 sees EDGE-R1 + ACC-SW1 (CDP, two links) and ACC-SW2 (LLDP only)."""
    core_up = _cdp_entry("CORE-SW1.corp.local", "10.99.0.1", "C9300-48P", "Router Switch IGMP", "GigabitEthernet1/0/47", "GigabitEthernet1/0/2") + \
        _cdp_entry("CORE-SW1.corp.local", "10.99.0.1", "C9300-48P", "Router Switch IGMP", "GigabitEthernet1/0/48", "GigabitEthernet1/0/3")
    lldp_acc2 = ("------------------------------------------------\nLocal Intf: Gi1/0/48\nChassis id: 00a3.d1e8.0001\n"
                 "Port id: Gi1/0/4\nPort Description: to ACC-SW2\nSystem Name: CORE-SW1.corp.local\n\nSystem Description: \n"
                 "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)\n\n"
                 "Time remaining: 101 seconds\nSystem Capabilities: B,R\nEnabled Capabilities: B,R\nManagement Addresses:\n"
                 "    IP: 10.99.0.1\nAuto Negotiation - supported, enabled\nVlan ID: - not advertised\n\n\nTotal entries displayed: 1\n")
    return {
        "10.99.0.1": {"hostname": "CORE-SW1", "show version": _version("CORE-SW1", "C9300-48P"),
                      "show cdp neighbors detail": (FIX / "core_cdp.txt").read_text(),
                      "show lldp neighbors detail": (FIX / "core_lldp.txt").read_text(),
                      "show running-config": core_config or "hostname CORE-SW1\nip routing\n"},
        "10.99.0.11": {"hostname": "ACC-SW1", "show version": _version("ACC-SW1", "C9200L-48P-4G"),
                       "show cdp neighbors detail": core_up, "show lldp neighbors detail": "% LLDP is not enabled",
                       "show running-config": "hostname ACC-SW1\ninterface GigabitEthernet1/0/1\n switchport mode access\n switchport access vlan 10\n"},
        "10.99.0.12": {"hostname": "ACC-SW2", "show version": _version("ACC-SW2", "C9200L-48P-4G"),
                       "show cdp neighbors detail": "% CDP is not enabled", "show lldp neighbors detail": lldp_acc2,
                       "show running-config": "hostname ACC-SW2\n"},
    }


def dc_lab():
    """DC-SPINE1 (NX-OS) and DC-LEAF1 (Arista EOS) see each other over LLDP. Outputs are real device output from
    ntc-templates' test data, with names and addresses changed to fit together."""
    F = FIX / "dc"
    return {
        "10.99.1.1": {"hostname": "DC-SPINE1", "show version": (F / "nxos_version.txt").read_text(), "show cdp neighbors detail": "",
                      "show lldp neighbors detail": (F / "nxos_lldp.txt").read_text(),
                      "show running-config": (F / "nxos_running.txt").read_text()},
        "10.99.1.11": {"hostname": "DC-LEAF1", "show version": (F / "eos_version.txt").read_text(),
                       "show cdp neighbors detail": "% Invalid input (at token 1: 'cdp')",
                       "show lldp neighbors detail": (F / "eos_lldp.txt").read_text(),
                       "show running-config": (F / "eos_running.txt").read_text()},
    }


def junos_lab():
    """JUN-EDGE1 (MX) and JUN-ACC1 (EX) see each other over LLDP; the MX also sees an access point. Junos's LLDP
    summary carries no management address, so the walk needs both as seeds."""
    F = FIX / "junos"
    edge = ("set system host-name JUN-EDGE1\nset interfaces ge-0/0/1 description \"to JUN-ACC1\"\n"
            "set interfaces ge-0/0/1 unit 0 family inet address 10.0.2.1/30\nset interfaces lo0 unit 0 family inet address 10.255.2.1/32\n"
            "set protocols ospf area 0.0.0.0 interface ge-0/0/1.0\n")
    acc = ("set system host-name JUN-ACC1\nset vlans USERS vlan-id 10\n"
           "set interfaces ge-0/0/0 unit 0 family ethernet-switching interface-mode access\n"
           "set interfaces ge-0/0/0 unit 0 family ethernet-switching vlan members USERS\nset interfaces ge-0/0/5 disable\n"
           "set interfaces ge-0/0/5 unit 0 family ethernet-switching vlan members USERS\n"
           "set interfaces ge-0/0/47 unit 0 family ethernet-switching interface-mode trunk\n"
           "set interfaces ge-0/0/47 unit 0 family ethernet-switching vlan members 10\n")
    run = "show configuration | display set | no-more"
    return {
        "10.99.2.1": {"hostname": "JUN-EDGE1", "prompt": "admin@JUN-EDGE1>", "show version": (F / "mx_version.txt").read_text(),
                      "show lldp neighbors | no-more": (F / "mx_lldp.txt").read_text(), run: edge},
        "10.99.2.11": {"hostname": "JUN-ACC1", "prompt": "admin@JUN-ACC1>", "show version": (F / "ex_version.txt").read_text(),
                       "show lldp neighbors | no-more": (F / "ex_lldp.txt").read_text(), run: acc},
    }


class FakeIOS:
    def __init__(self, dev):
        self.dev = dev

    def reply(self, line):
        line = line.strip()
        if not line or line.startswith("terminal"):
            return ""
        return self.dev.get(line, "% Invalid input detected at '^' marker.").replace("\n", "\r\n")

    @property
    def prompt(self):
        return self.dev.get("prompt") or f"{self.dev['hostname']}#"


def _serve_channel(chan, ios: FakeIOS, login=False):
    """Echo input like IOS does, answer each line, print the prompt."""
    write = chan.send if hasattr(chan, "send") else chan
    stage = "user" if login else "cli"
    buf = ""
    if not login:
        write(f"\r\n{ios.prompt}".encode())
    while True:
        try:
            data = chan.recv(1024) if hasattr(chan, "recv") else None
        except OSError:
            return
        if not data:
            return
        for ch in data.decode(errors="ignore"):
            if ch not in "\r\n":
                buf += ch
                if stage != "pass":
                    write(ch.encode())
                continue
            line, buf = buf, ""
            if stage == "user":
                if line:
                    stage = "pass"
                    write(b"\r\nPassword: ")
                else:
                    write(b"\r\n\r\nUser Access Verification\r\n\r\nUsername: ")
            elif stage == "pass":
                stage = "cli" if line == PASSWORD else "user"
                write(f"\r\n{ios.prompt}".encode() if stage == "cli" else b"\r\n% Login invalid\r\n\r\nUsername: ")
            else:
                out = ios.reply(line)
                write((f"\r\n{out}" if out else "").encode() + f"\r\n{ios.prompt}".encode())


class _Server(paramiko.ServerInterface):
    def __init__(self, auth=None):
        self.auth = auth or (lambda u, p: (u, p) == (USER, PASSWORD))

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if self.auth(username, password) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,keyboard-interactive"  # PAN-OS logins (netmiko's PAN-OS driver) are keyboard-interactive

    def check_auth_interactive(self, username, submethods):
        self._user = username
        q = paramiko.InteractiveQuery()
        q.add_prompt("Password: ", False)
        return q

    def check_auth_interactive_response(self, responses):
        return paramiko.AUTH_SUCCESSFUL if responses and self.auth(self._user, responses[0]) else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        return True


def start_ssh(dev) -> int:
    """Run one fake device on 127.0.0.1; returns its port."""
    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)

    def accept_loop():
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    def handle(conn):
        t = paramiko.Transport(conn)
        t.add_server_key(_KEY)
        try:
            stateful = isinstance(dev, (FakeDevice, FakeJunos, FakePan, FakeForti))
            t.start_server(server=_Server(dev.authorize if stateful else None))
            chan = t.accept(20)
            if chan:
                _serve_channel(chan, dev.session() if stateful else FakeIOS(dev))
        except Exception:
            pass
        finally:
            t.close()
    threading.Thread(target=accept_loop, daemon=True).start()
    return sock.getsockname()[1]


class _PtyChan:
    def __init__(self, fd):
        self.fd = fd

    def recv(self, n):
        return os.read(self.fd, n)

    def send(self, b):
        os.write(self.fd, b)


def start_console(dev) -> str:
    """A fake console cable: returns a /dev/pts path pyserial can open."""
    master, slave = os.openpty()
    import tty
    tty.setraw(slave)
    threading.Thread(target=_serve_channel, args=(_PtyChan(master), FakeIOS(dev), True), daemon=True).start()
    return os.ttyname(slave)


# ---------------------------------------------------------------- a device that actually applies config
import hashlib
import re as _re

_SINGLE = _re.compile(r"^(remote-as|idle-timeout|connection limit|password minimum length|session-limit|ssh login-attempts|"
                      r"hostname|ip domain name|switchport access vlan|switchport voice vlan|switchport trunk allowed vlan|"
                      r"switchport trunk native vlan|switchport mode|description|ip address|exec-timeout|access-class \S+|"
                      r"transport input|transport output|logging buffered|logging trap|spanning-tree mode|vtp mode|"
                      r"aaa authentication login default(?! fallback)|aaa authorization exec default|login block-for|"
                      r"ip ssh server algorithm mac|ip ssh server algorithm encryption|ip ospf \d+ area|ip ospf authentication|"
                      r"router-id|bgp router-id|ip dhcp snooping vlan|ip arp inspection vlan|send-lifetime|accept-lifetime|"
                      r"key-string|cryptographic-algorithm|path|maximum|switchport port-security maximum|storm-control broadcast|"
                      r"storm-control multicast|auto-cost reference-bandwidth|enable secret|enable algorithm-type|key(?= (?!chain|\d))|min-length)\b")
_HASHED = [(_re.compile(r"^(username \S+ .*?role \S+ )secret 0 (\S+)$"), "{0}secret sha512 $6${h}"),  # EOS
           (_re.compile(r"^(username \S+ )password 0 (\S+)( role .*)?$"), "{0}password 5 $5${h}"),  # NX-OS
           (_re.compile(r"^((?:tacacs|radius)-server host \S+ key) 0 (\S+)(.*)$"), "{0} 7 {h}"),
           (_re.compile(r"^(password) 0 (\S+)$"), "{0} 3 {h}"),  # NX-OS BGP neighbor
           (_re.compile(r"^(neighbor \S+ password) 0 (\S+)$"), "{0} 7 {h}"),  # EOS
           (_re.compile(r"^(key-string) 0 (\S+)$"), "{0} 7 {h}"),
           (_re.compile(r"^(ip ospf message-digest-key \d+ \S+) 0 (\S+)$"), "{0} 7 {h}"),
           (_re.compile(r"^(ntp authentication-key \d+ \S+) 0 (\S+)$"), "{0} 7 {h}"),
           (_re.compile(r"^(enable) algorithm-type \S+ secret (.+)$"), "{0} secret 9 $9${h}"),
           (_re.compile(r"^(username \S+ .*?)(?:algorithm-type \S+ )?secret (?!9 )(.+)$"), "{0}secret 9 $9${h}"),
           (_re.compile(r"^(key-string) (?!7 )(.+)$"), "{0} 7 {h}"),
           (_re.compile(r"^(key) (?!7 |chain|\d+$)(.+)$"), "{0} 7 {h}"),
           (_re.compile(r"^(ntp authentication-key \d+ \S+) (?!7 )(.+)$"), "{0} 7 {h}"),
           (_re.compile(r"^(authentication mode hmac-sha-256) (?!7 )(.+)$"), "{0} 7 {h}")]
_REMOVABLE = _re.compile(r"^(username|snmp-server|ntp server|logging host|logging \d|tacacs server|radius server|ip route|"
                         r"ip access-list|ip prefix-list|vlan \d|enable password|neighbor \S+ password|interface|key chain)")
_DEFAULT_OFF = {"service config", "ip dns server", "ip mask-reply", "ip directed-broadcast", "shutdown", "lldp transmit", "lldp receive"}


class FakeConfig:
    """Running-config state with enough IOS semantics for push tests."""
    def __init__(self, text="", users_in_config=False):
        self.users_in_config = users_in_config  # NX-OS and EOS show SNMPv3 users in the running config
        self.root = []  # [line, children]
        self.eos_banners = False
        self.banners = {}
        self.snmp_users = set()
        self.passwords = {}
        self.apply(text.splitlines(), raw=True)

    def _key(self, line):
        m = _SINGLE.match(line)
        if not m:
            return None
        if line.startswith("ip ospf authentication") or line.startswith("enable "):
            return m.group(1).split()[0:2]
        return m.group(1)

    def _key_full(self, line):
        """Like _key, but usernames are single-valued per name (IOS replaces the whole line)."""
        if line.startswith("username "):
            return ("username", line.split()[1])
        return self._key(line)

    def apply(self, lines, raw=False):
        """Apply config lines. Indentation sets the context, like OneConfig's push format. Returns errors."""
        stack, errors, it = [(-1, self.root)], [], iter(lines)
        for line in it:
            if not line.strip() or _re.match(r"(!|end$|exit$|Building configuration|Current configuration|version )", line.strip()):
                continue
            if _re.match(r"^banner (login|motd)$", line.strip()):  # EOS style
                body = []
                for nxt in it:
                    if nxt.strip() == "EOF":
                        break
                    body.append(nxt)
                self.banners[line.strip().split()[1]] = "\n".join(body).strip()
                self.eos_banners = True
                stack = [(-1, self.root)]
                continue
            m = _re.match(r"^banner (\w+) (\^C|\^|%|#)(.*)$", line.strip())
            if m:
                kind, delim, rest = m.groups()
                body = [rest] if rest else []
                for nxt in it:
                    if delim in nxt:
                        break
                    body.append(nxt)
                self.banners[kind] = "\n".join(body).strip()
                stack = [(-1, self.root)]
                continue
            depth = len(line) - len(line.lstrip(" "))
            cmd = _re.sub(r"\s+", " ", line.strip())
            while stack[-1][0] >= depth:
                stack.pop()
            kids = stack[-1][1]
            if cmd.startswith("snmp-server user ") and not self.users_in_config:
                self.snmp_users.add(cmd.split()[2])
                continue
            if cmd.startswith("no "):
                tgt = cmd[3:]
                gone = [n for n in kids if n[0] == tgt or n[0].startswith(tgt + " ")]
                for n in gone:
                    kids.remove(n)
                if not _REMOVABLE.match(tgt) and tgt not in _DEFAULT_OFF and not any(n[0] == cmd for n in kids):
                    kids.append([cmd, []])
                continue
            if not raw:
                for rx, fmt in _HASHED:
                    hm = rx.match(cmd)
                    if hm:
                        if cmd.startswith("username "):
                            self.passwords[cmd.split()[1]] = hm.group(2)
                        h = hashlib.sha256(hm.group(2).encode()).hexdigest()[:16].upper()
                        cmd = fmt.format(hm.group(1), h=h) + ((hm.group(3) or "") if hm.re.groups >= 3 else "")
                        break
            # an explicit setting replaces its "no" form and any previous value of a single-valued setting
            kids[:] = [n for n in kids if n[0] != "no " + cmd]
            key = self._key_full(cmd)
            node = next((n for n in kids if n[0] == cmd), None)
            if node is None and key:
                node = next((n for n in kids if self._key_full(n[0]) == key), None)
                if node:
                    node[0] = cmd
            if node is None:
                node = [cmd, []]
                kids.append(node)
            stack.append((depth, node[1]))
        return errors

    def text(self):
        out = []

        def walk(nodes, d, acl):
            for i, (line, kids) in enumerate(nodes):
                shown = f"{(i + 1) * 10} {line}" if acl and _re.match(r"(permit|deny) ", line) else line
                out.append(" " * d + shown)
                walk(kids, d + 1, line.startswith("ip access-list"))
        walk(self.root, 0, False)
        for kind, body in self.banners.items():
            out += [f"banner {kind}", body, "EOF"] if self.eos_banners else [f"banner {kind} ^C", body, "^C"]
        return "Building configuration...\n\nCurrent configuration : 4242 bytes\n!\nversion 17.9\n" + "\n".join(out) + "\nend\n"


# ---------------------------------------------------------------- a stateful device over SSH, for push tests
import re
import ipaddress


class FakeDevice:
    """Keeps a running config across sessions and implements archive, revert timer, confirm, replace and
    write memory. Logins obey the device's own VTY access-class and local passwords, so a bad push really
    locks the next session out."""
    def __init__(self, hostname, running="", outputs=None, seconds_per_minute=1.0, flavor="ios"):
        self.flavor = flavor  # "ios", "nxos" or "eos"
        self.hostname, self.cfg, self.outputs = hostname, FakeConfig(running, users_in_config=flavor != "ios"), outputs or {}
        self.files, self.checkpoints = {}, {}
        self.archives, self.pre, self.timer, self.startup, self.scale = {}, None, None, None, seconds_per_minute
        self.lock = threading.RLock()
        self.commands = []

    def snapshot(self):
        return copy.deepcopy((self.cfg.root, self.cfg.banners, self.cfg.snmp_users, self.cfg.passwords))

    def restore(self, snap):
        self.cfg.root, self.cfg.banners, self.cfg.snmp_users, self.cfg.passwords = copy.deepcopy(snap)

    def _block(self, prefix):
        return next((k for line, k in self.cfg.root if line.startswith(prefix)), None)

    def archive_path(self):
        arch = self._block("archive")
        return next((x[0].split()[1] for x in arch or [] if x[0].startswith("path ")), None)

    def authorize(self, user, password, client="127.0.0.1"):
        with self.lock:
            vty = [x for line, k in self.cfg.root if line.startswith("line vty 0 ") or line in ("line vty", "management ssh") for x in k]
            acl = next((x[0].split()[-2] for x in reversed(vty) if _re.match(r"(access-class|ip access-group) \S+ in$", x[0])), None)
            if acl:
                entries = self._block(f"ip access-list standard {acl}") or self._block(f"ip access-list {acl}") or []
                nets = [ipaddress.ip_network(f"{x[0].split()[1]}/{x[0].split()[2]}") if "/" not in x[0] else
                        ipaddress.ip_network(next(w for w in x[0].split() if "/" in w)) for x in entries
                        if x[0].startswith("permit ") and len(x[0].split()) >= 3]
                if not any(ipaddress.ip_address(client) in n for n in nets):
                    return False
            want = self.cfg.passwords.get(user, PASSWORD if user == USER else None)
            return want is not None and password == want

    def session(self):
        return _Session(self)

    def _auto_revert(self):
        with self.lock:
            if self.pre is not None:
                self.restore(self.pre)
                self.pre = None


class _Session:
    def __init__(self, dev):
        self.dev, self.mode, self.buf, self.sess = dev, "exec", [], None

    @property
    def prompt(self):
        if self.mode == "session":
            return f"{self.dev.hostname}(config-s-{self.sess[:6]})#"
        return f"{self.dev.hostname}(config)#" if self.mode == "config" else f"{self.dev.hostname}#"

    def _timer(self, seconds, d):
        d.timer = threading.Timer(seconds, d._auto_revert)
        d.timer.daemon = True
        d.timer.start()

    def reply(self, line):
        d, s = self.dev, line.strip()
        with d.lock:
            d.commands.append(line)
            if self.mode == "session":  # EOS configuration session: nothing applies until commit
                if s.startswith("bogus"):
                    return "% Invalid input (at token 0: 'bogus')"
                if s == "abort":
                    self.buf, self.mode = [], "exec"
                    return ""
                m = re.match(r"commit timer (\d+):(\d+):(\d+)$", s)
                if m or s == "commit":
                    d.pre = d.snapshot() if m else None
                    d.cfg.apply(self.buf)
                    self.buf, self.mode = [], "exec"
                    if m:
                        self._timer((int(m[1]) * 60 + int(m[2]) + int(m[3]) / 60) * d.scale, d)
                    return ""
                self.buf.append(line.rstrip())
                return ""
            if d.flavor == "eos" and s.startswith("terminal"):
                return "Pagination disabled." if "length" in s else "Width set to 511 columns."
            m = re.match(r"dir ((?:boot)?flash:)$", s)
            if m:
                return "\n".join(f"  1234  Oct 17 2026 {f[len(m[1]):]}" for f in d.files if f.startswith(m[1]))
            m = re.match(r"delete ((?:boot)?flash:\S+)(?: no-prompt)?$", s)
            if m:
                return "" if d.files.pop(m[1], None) is not None else f"% No such file {m[1]}"
            if d.flavor == "nxos" and s == "show checkpoint summary":
                return "User Checkpoint Summary\n" + "\n".join(f"{i}) {n}:\nCreated by admin" for i, n in enumerate(d.checkpoints, 1))
            m = re.match(r"no checkpoint (\S+)$", s)
            if d.flavor == "nxos" and m:
                return "" if d.checkpoints.pop(m[1], None) is not None else f"% Checkpoint {m[1]} does not exist"
            if d.flavor == "eos":
                m = re.match(r"configure session (\S+)(?: (commit|abort))?$", s)
                if m and not m[2]:
                    self.mode, self.sess = "session", m[1]
                    return ""
                if m and m[2] == "commit":
                    if d.timer:
                        d.timer.cancel()
                    d.pre = None
                    return ""
                if m:  # whether EOS can abort a timer-committed session isn't documented: the fake says no, the timer decides
                    return "% Cannot abort a committed session"
                m = re.match(r"copy running-config (flash:\S+)$", s)
                if m:
                    d.files[m[1]] = d.snapshot()
                    return "Copy completed successfully."
                m = re.match(r"configure replace (flash:\S+)$", s)
                if m:
                    if m[1] not in d.files:
                        return f"% Error opening {m[1]} (No such file or directory)"
                    d.restore(d.files[m[1]])
                    return ""
            if d.flavor == "nxos":
                m = re.match(r"checkpoint (\S+)$", s)
                if m:
                    d.checkpoints[m[1]] = d.snapshot()
                    return "...........Done"
                m = re.match(r"rollback running-config checkpoint (\S+)$", s)
                if m:
                    if m[1] not in d.checkpoints:
                        return f"% Checkpoint {m[1]} does not exist"
                    d.restore(d.checkpoints[m[1]])
                    return "Collecting Running-Config\nGenerating Rollback Patch\nExecuting Rollback Patch\nVerification is Successful.\n\nRollback completed successfully."
                m = re.match(r"copy running-config (bootflash:\S+)$", s)
                if m:
                    d.files[m[1]] = d.snapshot()
                    return "Copy complete."
                m = re.match(r"configure replace (bootflash:\S+) verbose commit-timeout (\d+)$", s)
                if m:
                    if d.pre is not None:
                        return "% Configure replace is in progress"
                    d.pre = d.snapshot()
                    d.restore(d.files[m[1]])
                    self._timer(int(m[2]) / 60 * d.scale, d)
                    return "Configure replace completed successfully. Please run 'show config-replace log exec' to see the commands executed."
                if s == "configure replace commit":
                    if d.timer:
                        d.timer.cancel()
                    d.pre = None
                    return ""
            if self.mode == "config":
                if s.startswith("bogus"):
                    return "                    ^\n% Invalid input detected at '^' marker."
                if s == "end":
                    d.cfg.apply(self.buf)
                    self.buf, self.mode = [], "exec"
                else:
                    self.buf.append(line.rstrip())
                return ""
            if not s or s.startswith("terminal"):
                return ""
            if s in ("configure terminal", "conf t"):
                self.mode = "config"
                return "Enter configuration commands, one per line.  End with CNTL/Z."
            m = re.match(r"configure terminal revert timer (\d+)$", s)
            if m:
                if not d.archive_path():
                    return "% Archive path not configured. Please configure archive path."
                d.pre = d.snapshot()
                d.timer = threading.Timer(int(m.group(1)) * d.scale, d._auto_revert)
                d.timer.daemon = True
                d.timer.start()
                self.mode = "config"
                return f"Rollback Confirmed Change: Rollback will begin after {m.group(1)} minutes of inactivity or idle time"
            if s == "configure confirm":
                if d.timer:
                    d.timer.cancel()
                d.pre = None
                return ""
            if s == "configure revert now":
                if d.timer:
                    d.timer.cancel()
                if d.pre is not None:
                    d.restore(d.pre)
                    d.pre = None
                return "Rollback Done"
            if s == "archive config":
                path = d.archive_path()
                if not path:
                    return "% No archive path specified"
                d.archives[f"{path}-{len(d.archives) + 1}"] = d.snapshot()
                return ""
            if s == "show archive":
                names = list(d.archives)
                rows = [f"   {i}        {n}" + ("  <- Most Recent" if i == len(names) else "") for i, n in enumerate(names, 1)]
                return "The maximum archive configurations allowed is 14.\n Archive #  Name\n" + "\n".join(rows)
            m = re.match(r"configure replace (\S+) force$", s)
            if m:
                if m.group(1) not in d.archives:
                    return f"%Error opening {m.group(1)} (No such file or directory)"
                d.restore(d.archives[m.group(1)])
                return "Total number of passes: 1\nRollback Done"
            if s in ("write memory", "write mem", "copy running-config startup-config"):
                d.startup = d.cfg.text()
                return "Building configuration...\n[OK]"
            if s == "show running-config":  # NX-OS and EOS print the current time at the top, like the real ones
                now = time.strftime("%a %b %d %H:%M:%S %Y") + f".{time.time_ns()}"
                head = {"nxos": f"!Command: show running-config\n!Time: {now}\n\n", "eos": f"! Command: show running-config\n! Time: {now}\n"}
                return head.get(d.flavor, "") + d.cfg.text()
            if s == "show snmp user":
                return "\n\n".join(f"User name: {u}\nEngine ID: 800000090300\nstorage-type: nonvolatile        active"
                                     for u in sorted(d.cfg.snmp_users))
            if s == "show ip interface brief" and d.flavor != "ios":
                rows = (['IP Interface Status for VRF "default"(1)', "Interface            IP Address      Interface Status"]
                        if d.flavor == "nxos" else ["Interface              IP Address         Status     Protocol         MTU"])
                for ln, kids in d.cfg.root:
                    ip = next((x[0].split()[2] for x in kids if x[0].startswith("ip address ")), None)
                    if ln.startswith("interface ") and ip:
                        up = not any(x[0] == "shutdown" for x in kids)
                        rows.append(f"{ln.split()[1]:<21}{ip.split('/')[0]:<16}protocol-{'up' if up else 'down'}/link-{'up' if up else 'down'}/admin-{'up' if up else 'down'}"
                                    if d.flavor == "nxos" else f"{ln.split()[1]:<23}{ip:<19}{'up' if up else 'adminDown':<11}{'up' if up else 'down':<15}1500")
                return "\n".join(rows)
            if s == "show ip interface brief":
                rows = ["Interface              IP-Address      OK? Method Status                Protocol"]
                for ln, kids in d.cfg.root:
                    if ln.startswith("interface "):
                        ip = next((x[0].split()[2] for x in kids if x[0].startswith("ip address ")), "unassigned")
                        shut = any(x[0] == "shutdown" for x in kids)
                        rows.append(f"{ln.split()[1]:<23}{ip:<16}YES NVRAM  {'administratively down' if shut else 'up':<22}{'down' if shut else 'up'}")
                return "\n".join(rows)
            if s in d.outputs:
                return d.outputs[s]
            return "% Invalid input detected at '^' marker."


# ---------------------------------------------------------------- a stateful Junos device
_J_SECRET = re.compile(r'^(set .* (?:secret|authentication-key|authentication-password|privacy-password|value|password|ascii-text)) "(?!\$9\$)([^"]*)"$')
_J_SINGLE = re.compile(r"^set (.*) (host-name|domain-name|time-zone|connection-limit|max-sessions-per-connection|tries-before-disconnect|"
                       r"lockout-period|minimum-\S+|format|message|idle-timeout|secret|encrypted-password|value|type|class|description|"
                       r"router-id|autonomous-system|reference-bandwidth|peer-as|start-time|algorithm|native-vlan-id|interface-mode|"
                       r"bandwidth-limit|burst-size-limit|authentication-algorithm|authentication-key-chain|local-address|ttl) "
                       r'(\S+|"[^"]*")$')  # a leaf: the keyword and exactly one value


def _j_apply(cfg: list, line: str) -> str | None:
    """Apply one set/delete statement to a list of set lines. Returns an error message, or None."""
    line = re.sub(r"\s+", " ", line.strip())
    if "bogus" in line:
        return "                      ^\nsyntax error."
    if line.startswith("delete "):
        tgt = "set " + line[len("delete "):]
        cfg[:] = [l for l in cfg if l != tgt and not l.startswith(tgt + " ")]
        return None
    if not line.startswith("set "):
        return "unknown command."
    m = _J_SECRET.match(line)
    if m:  # Junos stores secrets encrypted ($9$) and shows them that way
        line = f'{m[1]} "$9${hashlib.sha256(m[2].encode()).hexdigest()[:16]}"'
    s = _J_SINGLE.match(line)
    if s:
        cfg[:] = [l for l in cfg if not l.startswith(f"set {s[1]} {s[2]} ")]
    if line not in cfg:
        cfg.append(line)
    return None


class FakeJunos:
    """Running and candidate configurations, commit / commit check / commit confirmed (with its timer), rollback N,
    configuration files in /var/tmp, and logins that obey the device's own lo0 filter and SHA-512 local passwords."""
    def __init__(self, hostname, running="", seconds_per_minute=1.0):
        self.hostname, self.scale = hostname, seconds_per_minute
        self.running = []
        for l in running.splitlines():
            if l.strip():
                _j_apply(self.running, l)
        self.history, self.files, self.pre, self.timer = [], {}, None, None
        self.lock = threading.RLock()
        self.commands = []

    def text(self):
        return "\n".join(self.running) + "\n"

    def authorize(self, user, password, client="127.0.0.1"):
        from oneconfig.junos import sha512_verify
        with self.lock:
            cfg = self.running
            if "set interfaces lo0 unit 0 family inet filter input PROTECT-RE" in cfg:
                src = [l.split()[-1] for l in cfg if l.startswith("set firewall family inet filter PROTECT-RE term SSH from source-prefix-list ")]
                nets = [ipaddress.ip_network(l.split()[-1]) for l in cfg for s in src if l.startswith(f"set policy-options prefix-list {s} ")]
                if src and not any(ipaddress.ip_address(client) in n for n in nets):
                    return False
            h = next((l.split('"')[1] for l in cfg if l.startswith(f"set system login user {user} authentication encrypted-password ")), None)
            return sha512_verify(password, h) if h else (user, password) == (USER, PASSWORD)

    def session(self):
        return _JunosSession(self)

    def _auto_revert(self):
        with self.lock:
            if self.pre is not None:
                self.history.insert(0, self.running)
                self.running, self.pre = self.pre, None


class _JunosSession:
    def __init__(self, dev):
        self.dev, self.cand, self.confirming = dev, None, False

    @property
    def prompt(self):
        p = f"{USER}@{self.dev.hostname}"
        return f"\r\n[edit]\r\n{p}# " if self.cand is not None else f"{p}> "

    def reply(self, line):
        d, s = self.dev, line.strip()
        with d.lock:
            d.commands.append(s)
            if self.confirming:
                self.confirming = False
                if s == "yes":
                    self.cand = None
                    return "Exiting configuration mode"
                return ""
            if s.startswith("set cli screen-width"):
                return "Screen width set to 511"
            if s.startswith("set cli screen-length"):
                return "Screen length set to 0"
            if s.startswith("set cli complete-on-space"):
                return "Disabling complete-on-space"
            if not s:
                return ""
            if self.cand is not None:
                return self._config(s)
            if s in ("configure exclusive", "configure", "configure private"):
                self.cand = list(d.running)
                return "warning: uncommitted changes will be discarded on exit\nEntering configuration mode"
            m = re.match(r"show configuration \| save (\S+)$", s)
            if m:
                d.files[m[1]] = list(d.running)
                return f"Wrote {len(d.running)} lines of output to '{m[1]}'"
            if s.startswith("show configuration | display set"):
                return d.text()
            m = re.match(r"file list (/var/tmp/)$", s)
            if m:
                return "/var/tmp/:\n" + "\n".join(f[len(m[1]):] for f in d.files if f.startswith(m[1]))
            m = re.match(r"file delete (\S+)$", s)
            if m:
                return "" if d.files.pop(m[1], None) is not None else f"error: Could not delete {m[1]}: No such file or directory"
            if s.startswith("show version"):
                return (FIX / "junos" / "mx_version.txt").read_text().replace("JUN-EDGE1", d.hostname)
            if s == "show interfaces terse":
                rows = ["Interface               Admin Link Proto    Local                 Remote"]
                st = lambda up: "up    up" if up else "down  down"  # noqa: E731
                hw = [f"ge-0/0/{i}" for i in range(48)] + ["irb", "lo0"]  # real Junos lists every port, configured or not
                for n in dict.fromkeys(hw + [l.split()[2] for l in d.running if l.startswith("set interfaces ")]):
                    up = f"set interfaces {n} disable" not in d.running
                    rows.append(f"{n:<24}{'up    down' if n.startswith('ae') and up else st(up)}")  # no LACP partner in the lab
                    for m in re.finditer(rf"^set interfaces {re.escape(n)} unit (\d+) family inet address (\S+)$", d.text(), re.M):
                        u_up = up and f"set interfaces {n} unit {m[1]} disable" not in d.running
                        rows.append(f"{n}.{m[1]:<{23 - len(n)}}{st(u_up)}   inet     {m[2]}")
                return "\n".join(rows)
            if s in ("show ospf neighbor", "show bgp summary"):
                return ""
            return "                      ^\nunknown command."

    def _config(self, s):
        d = self.dev
        if s in ("exit configuration-mode", "exit", "quit"):
            if self.cand != d.running:
                self.confirming = True
                return "The configuration has been changed but not committed\nExit with uncommitted changes? [yes,no] (yes) "
            self.cand = None
            return "Exiting configuration mode"
        m = re.match(r"rollback (\d+)$", s)
        if m:
            n = int(m[1])
            if n and n > len(d.history):
                return f"error: rollback {n} does not exist"
            self.cand = list(d.running if n == 0 else d.history[n - 1])
            return "load complete"
        m = re.match(r"load override (\S+)$", s)
        if m:
            if m[1] not in d.files:
                return f"error: Could not open configuration file: {m[1]}"
            self.cand = list(d.files[m[1]])
            return "load complete"
        if s == "commit check":
            return "configuration check succeeds"
        m = re.match(r'commit( confirmed (\d+))?( comment ".*")?$', s)
        if m:
            if m[1]:
                if d.pre is not None:
                    return "error: commit confirmed is already pending"
                d.pre = list(d.running)
                d.timer = threading.Timer(int(m[2]) * d.scale, d._auto_revert)
                d.timer.daemon = True
                d.timer.start()
            else:
                if d.timer:
                    d.timer.cancel()
                d.pre = None
            d.history.insert(0, d.running)
            d.running = list(self.cand)
            return ("configuration check succeeds\n" +
                    (f"commit confirmed will be automatically rolled back in {m[2]} minutes unless confirmed\n" if m[1] else "") +
                    "commit complete" + (f"\n\n# commit confirmed will be rolled back in {m[2]} minutes" if m[1] else ""))
        return _j_apply(self.cand, s) or ""



# ---------------------------------------------------------------- PAN-OS
_P_LISTS = re.compile(r" (layer3|interface|static|members|source|destination|application|service|from|to|severity|send-syslog|"
                      r"filter type|permitted-ip) \S+$")


def _p_apply(cfg: list, line: str):
    """One configure-mode line against a list of set lines (lists expanded to one line per member)."""
    line = re.sub(r"\s+", " ", line.strip())
    if line.startswith("delete "):
        path = "set " + line[7:]
        cfg[:] = [l for l in cfg if l != path and not l.startswith(path + " ")]
        return ""
    if line.startswith("move "):
        m = re.match(r"move rulebase (\S+) rules (\S+) bottom$", line)
        if not m:
            return "Invalid syntax."
        pre = f"set rulebase {m[1]} rules {m[2]} "
        mine = [l for l in cfg if l.startswith(pre)]
        cfg[:] = [l for l in cfg if not l.startswith(pre)] + mine
        return ""
    if not line.startswith("set ") or line.startswith(("set bogus", "set deviceconfig bogus")):
        return "Invalid syntax."
    m = re.match(r"^(.*?) \[ (.*) \]$", line)
    for x in ([f"{m[1]} {v}" for v in m[2].split()] if m else [line]):
        x = x.replace('"', "")
        prefix = x.rsplit(" ", 1)[0]
        if not _P_LISTS.search(x):  # a single value replaces the old one
            cfg[:] = [l for l in cfg if l.rsplit(" ", 1)[0] != prefix]
        if x not in cfg:
            cfg.append(x)
    return ""


class FakePan:
    """Running and candidate configurations (set form), named snapshots, commit, `show config diff`, and logins that
    use the device's own local-user-database phash (SHA-256 crypt) once the push sets it."""
    def __init__(self, hostname, running=""):
        self.hostname, self.running, self.files, self.commands = hostname, [], {}, []
        for l in running.splitlines():
            if l.strip():
                _p_apply(self.running, l)
        self.lock = threading.RLock()
        self.dirty = None  # someone else's uncommitted candidate

    def text(self):
        return "\n".join(self.running) + "\n"

    def authorize(self, user, password, client="127.0.0.1"):
        from oneconfig.junos import sha256_verify
        with self.lock:
            h = next((l.split()[-1] for l in self.running if l.startswith(f"set shared local-user-database user {user} phash ")), None)
            return sha256_verify(password, h) if h else (user, password) == (USER, PASSWORD)

    def session(self):
        return _PanSession(self)


class _PanSession:
    def __init__(self, dev):
        self.dev, self.cand = dev, None

    @property
    def prompt(self):
        p = f"{USER}@{self.dev.hostname}"
        return f"\r\n[edit]\r\n{p}# " if self.cand is not None else f"{p}> "

    def reply(self, line):
        d, s = self.dev, line.strip()
        with d.lock:
            d.commands.append(s)
            if not s or s.startswith(("set cli ", "terminal ")):
                return ""
            if self.cand is not None:
                return self._config(s)
            if s == "configure":
                self.cand = list(d.dirty if d.dirty is not None else d.running)
                return "Entering configuration mode"
            if s == "show system info":
                return (FIX / "panos" / "show_system_info.txt").read_text().replace("EDGE-FW2", d.hostname)
            if s == "show config running":
                return d.text()
            if s == "show interface all":
                rows = ["total configured hardware interfaces: 8", "", "name                    id    speed/duplex/state            mac address",
                        "--------------------------------------------------------------------------------"]
                for n in range(1, 9):
                    up = f"set network interface ethernet ethernet1/{n} link-state down" not in d.running
                    rows.append(f"ethernet1/{n:<15} {15 + n:<5} 1000/full/{'up' if up else 'down':<16} 00:1b:17:00:01:1{n}")
                return "\n".join(rows + ["", "total configured logical interfaces: 0", ""])
            if s.startswith(("show routing protocol", "show version")):
                return "" if not s.startswith("show version") else "Unknown command: version"
            return "Unknown command: " + s.split()[0]

    def _config(self, s):
        d = self.dev
        if s in ("exit", "quit"):
            self.cand = None
            return "Exiting configuration mode"
        if s == "show config diff":
            return "\n".join(f"+ {l}" for l in self.cand if l not in d.running) if self.cand != d.running else ""
        m = re.match(r"save config to (\S+)$", s)
        if m:
            d.files[m[1]] = list(self.cand)
            return f"Config saved to {m[1]}"
        m = re.match(r"load config from (\S+)$", s)
        if m:
            if m[1] not in d.files:
                return f"Server error : Config file {m[1]} does not exist"
            self.cand = list(d.files[m[1]])
            return "Config loaded from " + m[1]
        if s == "revert config":
            self.cand = list(d.running)
            return "Candidate configuration reverted"
        if s.startswith("commit"):
            d.running, d.dirty = list(self.cand), None
            return "Commit job 7 is in progress. Use Ctrl+C to return to command prompt\n....55%....100%\nConfiguration committed successfully"
        return _p_apply(self.cand, s)


# ---------------------------------------------------------------- FortiGate
def _f_render(node, depth=0):
    pad, out = "    " * depth, []
    for _, line in node["sets"].values():
        out.append(pad + line)
    for name, sub in node["subs"].items():
        out += [f"{pad}config {name}", *_f_render(sub, depth + 1), f"{pad}end"]
    for k, e in (node["entries"] or {}).items():
        out += [f"{pad}edit {k if k.isdigit() else chr(34) + k + chr(34)}", *_f_render(e, depth + 1), f"{pad}next"]
    return out


class FakeForti:
    """A FortiGate: running and saved configurations, the revert timer (cfg-save revert: unsaved changes are lost when
    the firewall reboots), configuration transactions, flash revisions, and logins checked against system admin."""
    def __init__(self, hostname, running="", disk=True):
        from oneconfig.diff import fos_tree
        self.hostname, self.disk, self.commands, self.revisions, self.reboots = hostname, disk, [], [], 0
        self.running = fos_tree(running)
        self.saved = copy.deepcopy(self.running)
        self.lock = threading.RLock()

    def text(self):  # a FortiGate re-encrypts every stored secret each time it shows the config
        return "\n".join(re.sub(r"\bENC \S+", lambda m: "ENC " + secrets.token_urlsafe(24), l) for l in _f_render(self.running)) + "\n"

    def get(self, path, field, default=None):
        node = self.running
        for name in path:
            node = node["subs"].get(name) if name in node["subs"] else (node["entries"] or {}).get(name)
            if node is None:
                return default
        return node["sets"].get(field, (default, ""))[0]

    def authorize(self, user, password, client="127.0.0.1"):
        with self.lock:
            pw = self.get(["system admin", user], "password")
            if pw and pw[0] != "ENC":  # set in this lab: plain text until the firewall hashes it
                return pw == [password]
            return (user, password) == (USER, PASSWORD)  # the fixture's own ENC hash stands for the lab password

    def reboot(self):
        """What the revert timer or execute cfg reload does: unsaved changes are gone."""
        self.running, self.reboots = copy.deepcopy(self.saved), self.reboots + 1

    def session(self):
        return _FortiSession(self)


class _FortiSession:
    def __init__(self, dev):
        self.dev, self.stack, self.txn, self.ask = dev, [], None, None

    @property
    def prompt(self):
        return f"{self.dev.hostname} # "

    def _root(self):
        return self.txn if self.txn is not None else self.dev.running

    def reply(self, line):
        d, s = self.dev, line.strip()
        with d.lock:
            d.commands.append(s)
            if self.ask:
                todo, self.ask = self.ask, None
                return todo() if s == "y" else "Command aborted."
            if not s:
                return ""
            if s.split()[0] in ("config", "edit", "set", "unset", "append", "delete", "move", "next", "end") or self.stack:
                return self._config(s)
            status = (FIX / "fortios" / "get_system_status.txt").read_text().replace("EDGE-FW2", d.hostname)
            if not d.disk:
                status = status.replace("Log hard disk: Available", "Log hard disk: Not available")
            if s == "get system status":
                return status
            m = re.match(r"get system status \| grep (\w+)$", s)
            if m:
                return "\n".join(l for l in status.splitlines() if m[1] in l)
            if s == "get system console":
                return f"output              : {(d.get(['system console'], 'output') or ['more'])[0]}"
            if s == "show full-configuration":
                return d.text()
            if s == "get system interface physical":
                down = lambda n: d.get(["system interface", n], "status") == ["down"]  # noqa: E731
                return "== [onboard]\n" + "".join(f"        ==[port{n}]\n                status: {'down' if down(f'port{n}') else 'up'}\n"
                                                   for n in range(1, 9))  # every hardware port is listed, configured or not
            if s.startswith("get router info"):
                return ""
            m = re.match(r'execute backup config flash "?([^"]+)"?$', s)
            if m:
                d.revisions.append((m[1], copy.deepcopy(d.running)))
                return "Config file backed up to flash."
            if s == "execute revision list config":
                return "ID  TIME                ADMIN   FIRMWARE VERSION    SIZE(KB)  IS_RUNNING  COMMENT\n" + "".join(
                    f"{n:>4}  2026-10-22 10:00:00 admin   v7.4.4-build2662    120       no          {c}\n" for n, (c, _) in enumerate(d.revisions, 1))
            m = re.match(r"execute restore config flash (\d+)$", s)
            if m:
                if not 0 < int(m[1]) <= len(d.revisions):
                    return "Command fail. Return code -1"

                def restore():
                    d.saved = copy.deepcopy(d.revisions[int(m[1]) - 1][1])
                    d.reboot()
                    return "Restoring revision. System is rebooting..."
                self.ask = restore
                return "This operation will overwrite the current setting and could possibly reboot the system!\nDo you want to continue? (y/n)"
            if s == "execute cfg save":
                d.saved = copy.deepcopy(d.running)
                return ""
            if s == "execute cfg reload":
                self.ask = lambda: (d.reboot(), "configs re-loaded. system will reboot.")[1]
                return "This operation will reboot the system !\nDo you want to continue? (y/n)"
            m = re.match(r"execute config-transaction (start|commit|abort)", s)
            if m:
                if m[1] == "start":
                    self.txn = copy.deepcopy(d.running)
                elif m[1] == "commit" and self.txn is not None:
                    d.running, self.txn = self.txn, None
                    self._autosave()
                else:
                    self.txn = None
                return f"Transaction {m[1]}ed." if m[1] != "abort" else "Transaction aborted."
            return "Unknown action 0\nCommand fail. Return code -1"

    def _autosave(self):
        from oneconfig.diff import _fnode
        d = self.dev
        if self.txn is not None:
            return
        if (d.get(["system global"], "cfg-save") or ["automatic"]) != ["revert"]:
            d.saved = copy.deepcopy(d.running)
        else:  # switching to revert mode is itself saved (it survives a reboot); later changes aren't
            d.saved["subs"].setdefault("system global", _fnode())["sets"]["cfg-save"] = (["revert"], "set cfg-save revert")

    def _config(self, s):
        from oneconfig.diff import _fnode
        import shlex
        words = shlex.split(s)
        cmd, args = words[0], words[1:]
        cur = self.stack[-1][0] if self.stack else self._root()
        if cmd == "config":
            self.stack.append((cur["subs"].setdefault(" ".join(args), _fnode()), "config"))
        elif cmd == "edit":
            cur["entries"] = cur["entries"] if cur["entries"] is not None else {}
            self.stack.append((cur["entries"].setdefault(args[0], _fnode()), "edit"))
        elif cmd == "next":
            if self.stack and self.stack[-1][1] == "edit":
                self.stack.pop()
        elif cmd == "end":
            if self.stack and self.stack[-1][1] == "edit":
                self.stack.pop()
            if self.stack:
                self.stack.pop()
            if not self.stack:
                self._autosave()
        elif cmd in ("set", "append"):
            if "bogus" in args[0]:
                return "command parse error before '" + args[0] + "'\nCommand fail. Return code -61"
            cur["sets"][args[0]] = (args[1:], s)
        elif cmd == "unset":
            cur["sets"].pop(args[0], None)
        elif cmd == "delete":
            (cur["entries"] or {}).pop(args[0], None)
        elif cmd == "move":  # move A after|before B
            e = cur["entries"] or {}
            if args[0] in e and args[2] in e:
                item = e.pop(args[0])
                keys = list(e)
                i = keys.index(args[2]) + (1 if args[1] == "after" else 0)
                cur["entries"] = {k: (item if k == args[0] else e[k]) for k in keys[:i] + [args[0]] + keys[i:]}
        return ""
