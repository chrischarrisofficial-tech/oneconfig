"""Local-only HTTP server for the UI. Binds to 127.0.0.1 and rejects foreign Host headers
(blocks DNS-rebinding), so no other machine or website can drive it."""
import contextvars
import json
import re
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network
from pathlib import Path

from pydantic import ValidationError

from . import ai, cve, history, private, trail, users
from .audit import audit
from .model import Network
from .render import context, render
from .cklb import checklist
from .stig import stig_audit

HERE = Path(__file__).parent
MAX_BODY = 2_000_000
# Every /api/ call must carry this. The browser gets it from a launch file only this user can read, so another
# account or program on the same computer can't drive the server (it would get your saved logins).
TOKEN = secrets.token_urlsafe(32)
ACTOR = contextvars.ContextVar("actor", default="local")  # who is making this request, for the audit trail


def note(action, detail=None, actor=None, log=None):
    """Audit trail entry for the person behind the current request (or the one who started a job). In a request the
    failure is returned as the error: discover, plan, CVE checks and Advisor questions are recorded before they start,
    so they don't start. A job that has already done its work says so in its log instead."""
    from .vault import KeyUnavailable
    try:
        trail.record(actor or ACTOR.get(), action, detail)
    except (OSError, KeyUnavailable) as e:
        if log is None:
            raise RuntimeError(f"The audit log couldn't be written. {e}") from None
        log(f"Warning: this wasn't recorded in the audit log. {e}")


def build(body: dict) -> dict:
    net = Network.model_validate(body)
    out = {}
    for d in net.devices:
        c = render(d, net)
        out[d.hostname] = {"config": c, **audit(c, d.platform), "stig": stig_audit(c, d.role, context(d, net), d.platform),
                           "cve": cve.cached(d.os_version, d.platform) if d.os_version else None}
    return out


def audit_pasted(body: dict) -> dict:
    cfg = str(body.get("config", ""))
    if len(cfg) > MAX_BODY:
        raise ValueError("config too large")
    out = audit(cfg, str(body.get("os") or "ios-xe"))
    platform = body.get("platform")
    if platform:
        ext = [x.strip() for x in str(body.get("external", "")).split(",") if x.strip()]
        out["stig"] = stig_audit(cfg, platform, {"external": ext} if ext else None, str(body.get("os") or "ios-xe"))
    return out


JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()


def _ips(text, scope):
    """IPs and CIDRs typed by the user, kept only if inside scope. Walks the scope (capped at MAX_HOSTS),
    never the typed range, so a 10.0.0.0/8 or IPv6 /64 target can't hang the server."""
    out = []
    for tok in re.split(r"[,\s]+", text or ""):
        if tok:
            net = ip_network(tok, strict=False)
            out += [str(h) for s in scope for h in (s.hosts() if s.num_addresses > 2 else s) if h in net]
    return list(dict.fromkeys(out))


def start_discovery(body: dict) -> str:
    """Validate up front (so typos fail fast), then run the discovery in a background thread."""
    from . import discover as D
    method = body.get("method")
    s = lambda k, d="": str(body.get(k) or d).strip()  # noqa: E731
    creds = {"username": s("username"), "password": str(body.get("password") or ""), "secret": str(body.get("secret") or "")}
    if method == "sweep":
        scope = D.parse_scope(s("scope"))
        run = lambda log: {"hosts": D.sweep(scope, log=log)}  # noqa: E731
    elif method == "ssh":
        scope = D.parse_scope(s("scope"))
        seeds = [str(ip_address(x)) for x in re.split(r"[,\s]+", s("seeds")) if x]  # walk enforces scope
        if not seeds or not creds["username"]:
            raise ValueError("SSH discovery needs at least one seed address and a username")
        run = lambda log: _nodes(D.ssh_walk(seeds, scope, creds, max_devices=int(body.get("max_devices") or 200), log=log))  # noqa: E731
    elif method == "snmp":
        scope = D.parse_scope(s("scope"))
        targets = _ips(s("targets"), scope)
        if not targets:
            raise ValueError("No SNMP targets inside the scope")
        snmp = ({"user": s("user"), "auth_key": str(body.get("auth_key") or ""), "priv_key": str(body.get("priv_key") or ""),
                 "priv": s("priv", "aes256")} if s("version") == "3" else {"community": str(body.get("community") or "")})
        run = lambda log: _nodes(D.snmp_discover(targets, scope, snmp, log=log))  # noqa: E731
    elif method == "serial":
        if not s("port"):
            raise ValueError("Pick a serial port")
        run = lambda log: _nodes(D.serial_discover(s("port"), int(body.get("baud") or 9600), creds, log=log))  # noqa: E731
    else:
        raise ValueError("method must be sweep, ssh, snmp or serial")
    note("discover", {"method": method, "scope": s("scope"), "seeds": s("seeds"), "targets": s("targets"), "port": s("port")})
    return _job(run)


PLANS: dict[str, dict] = {}  # server memory only: holds filled candidates and login, never sent to the browser
PLAN_TTL = 30 * 60  # seconds a plan (and the secrets and login it holds) is kept


def _plan(pid) -> dict | None:
    """A live plan, or None. Expired plans are dropped on the way, so their secrets leave memory."""
    now = time.monotonic()
    for k in [k for k, v in PLANS.items() if now - v["at"] > PLAN_TTL]:
        PLANS.pop(k, None)
    return PLANS.get(str(pid))


def _job(run) -> str:
    job = secrets.token_urlsafe(12)
    state = {"log": [], "done": False, "error": None, "result": None}
    with _JOBS_LOCK:
        for old in list(JOBS)[:-19]:
            JOBS.pop(old)
        JOBS[job] = state

    def worker():
        try:
            state["result"] = run(state["log"].append)
        except Exception as e:  # report every failure to the UI
            state["error"] = f"{type(e).__name__}: {e}" if not e.__class__.__name__ == "PushError" else str(e)
        state["done"] = True
    threading.Thread(target=worker, daemon=True).start()
    return job


def _ns(net):
    """Keychain namespace: the network's own id, never its name ("My Network" would share one customer's secrets
    with the next). A network without an id gets no keychain."""
    return net.id or None


def push_needs(body: dict) -> dict:
    """Which placeholders the selected devices need, and which the keychain already has (names only)."""
    from . import push, vault
    net = Network.model_validate(body["network"])
    devs = [d for d in net.devices if d.hostname in set(body.get("hostnames") or [])]
    per = {d.hostname: push.placeholders(render(d, net)) for d in devs}
    needs = sorted({p for v in per.values() for p in v})
    saved = vault.names(_ns(net)) if _ns(net) else []
    return {"needs": needs, "per_device": per, "saved": saved, "keychain": vault.available() and bool(_ns(net)), "login_saved": "@login" in saved}


def backups() -> dict:
    """Running-config backups that pushes saved, per hostname: newest first and how many. Names and times only."""
    from . import push
    out = {}
    for f in sorted(push.BACKUPS.glob("*.cfg*"), reverse=True) if push.BACKUPS.is_dir() else []:
        m = re.match(r"^(.+)-(\d{8}-\d{6})\.cfg(?:\.enc)?$", f.name)
        if m:
            b = out.setdefault(m[1], {"latest": None, "count": 0})
            b["count"] += 1
            b["latest"] = max(b["latest"] or "", m[2])
            b["encrypted"] = b.get("encrypted", True) and f.name.endswith(".enc")
    return out


def _secrets(net, body, needed):
    """Typed values win over saved ones. Nothing is saved here: start_plan saves once the values pass its checks."""
    from . import vault
    given = {k: v for k, v in (body.get("values") or {}).items() if isinstance(v, str) and v}
    return given, {**(vault.get_many(_ns(net), needed) if _ns(net) else {}), **given}


def _login(net, body):
    from . import vault
    login = {k: str((body.get("login") or {}).get(k) or "") for k in ("username", "password", "secret")}
    if not login["password"]:
        saved = vault.get_login(_ns(net)) if _ns(net) else None
        if not saved:
            raise ValueError("Enter the device login, or save it in the keychain first")
        login = saved
    elif (body.get("login") or {}).get("remember") and _ns(net):
        vault.put_login(_ns(net), login)
    if not login["username"]:
        raise ValueError("Enter a username for the device login")
    return login


def start_plan(body: dict) -> str:
    from . import push
    net = Network.model_validate(body["network"])
    devs = [d for d in net.devices if d.hostname in set(body.get("hostnames") or [])]
    if not devs:
        raise ValueError("Pick at least one device")
    needed = sorted({p for d in devs for p in push.placeholders(render(d, net))})
    given, values = _secrets(net, body, needed)
    missing = [p for p in needed if not values.get(p)]
    if missing:
        raise ValueError("Missing values for: " + ", ".join(missing))
    short = [p for p in needed if p not in push.IDENTIFIERS and len(values[p]) < push.MIN_SECRET]
    if short:
        raise ValueError(f"Use at least {push.MIN_SECRET} characters for: " + ", ".join(short))
    if bad := sorted({p for d in devs for p in push.bad_values(values, push.placeholders(render(d, net)), d.platform)}):
        raise ValueError(f"These values can't contain {push.BAD_VALUE_HELP}: " + ", ".join(bad))
    if body.get("remember") and given and _ns(net):
        from . import vault
        vault.put_many(_ns(net), given)
    login = _login(net, body)
    note("plan", {"devices": [d.hostname for d in devs]})

    def run(log):
        plans = {}
        for d in devs:
            log(f"{d.hostname}: reading the running config from {d.mgmt_ip or '(no management IP)'}")
            try:
                plans[d.hostname] = push.plan_device(d, net, login, values)
            except Exception as e:  # one unreachable device shouldn't hide the others' plans
                plans[d.hostname] = {"hostname": d.hostname, "blockers": [f"{type(e).__name__}: {str(e)[:200]}"]}
            p = plans[d.hostname]
            log(f"{d.hostname}: {len(p.get('add', []))} lines to add, {len(p.get('remove', []))} optional removals, "
                f"{len(p.get('blockers', []))} blockers")
        pid = secrets.token_urlsafe(12)
        PLANS[pid] = {"values": values, "login": login, "devices": plans, "at": time.monotonic()}
        for old in list(PLANS)[:-10]:
            PLANS.pop(old)
        shown = [{k: v for k, v in p.items() if k not in ("candidate", "add", "remove", "running_sha")} for p in plans.values()]
        return {"plan": pid, "devices": shown}
    return _job(run)


def start_apply(body: dict) -> str:
    from . import push
    pl = _plan(body.get("plan"))
    if not pl or pl.get("applied"):
        raise ValueError("That plan has expired or was already pushed. Plan again.")
    hosts = [h for h in body.get("hostnames") or [] if h in pl["devices"]]
    if not hosts:
        raise ValueError("Pick at least one planned device")
    picked = body.get("removals") or {}  # per device: positions in the plan's removal list, as the browser saw it masked
    removals = {h: [pl["devices"][h]["remove"][i] for i in picked.get(h) or [] if type(i) is int and 0 <= i < len(pl["devices"][h].get("remove", []))]
                for h in hosts}
    pl["applied"] = True
    actor = ACTOR.get()

    def run(log):
        results = []
        for h in hosts:
            log(f"--- {h}")
            try:
                r = push.apply_device(pl["devices"][h], pl["values"], pl["login"],
                                      removals=removals[h], save=body.get("save", True),
                                      revert_minutes=max(1, min(30, int(body.get("revert_minutes") or 5))), log=log)
                pl["devices"][h]["result"] = r
                results.append({k: v for k, v in r.items() if k != "login"})
            except Exception as e:  # not only PushError: a failed login on one device must not lose the record of the others
                err = str(e) if isinstance(e, push.PushError) else f"{type(e).__name__}: {str(e)[:200]}"
                log(f"{h}: FAILED: {err}")
                results.append({"hostname": h, "status": "failed", "error": err})
                if body.get("stop_on_failure", True):
                    log("Stopping: the remaining devices were not touched.")
                    results += [{"hostname": x, "status": "skipped"} for x in hosts[hosts.index(h) + 1:]]
                    break
        note("push", {"results": {r["hostname"]: r["status"] for r in results}}, actor, log)
        pl["values"] = {}  # a rollback needs only the login and the snapshot, not the filled configs or their secrets
        for d in pl["devices"].values():
            d.pop("candidate", None), d.pop("add", None)
        return {"results": results}
    return _job(run)


def start_rollback(body: dict) -> str:
    from . import push
    pl = _plan(body.get("plan"))
    h = str(body.get("hostname"))
    r = (pl or {}).get("devices", {}).get(h, {}).get("result")
    if not r or not r.get("snapshot"):
        raise ValueError("Nothing to roll back for that device in this session")
    ip, actor = pl["devices"][h]["ip"], ACTOR.get()

    def run(log):
        try:
            out = push.rollback_device(ip, r["login"], r["snapshot"], save=body.get("save", True), log=log, nos=r.get("os", "ios-xe"),
                                       fallback_login=pl["login"])
        except Exception as e:
            note("rollback", {"device": h, "snapshot": r["snapshot"], "result": f"failed: {str(e)[:120]}"}, actor, log)
            raise
        note("rollback", {"device": h, "snapshot": r["snapshot"], "result": "rolled back"}, actor, log)
        return out
    return _job(run)


APP = "@app"  # keychain namespace for OneConfig's own API keys
APP_KEYS = ("cisco_client_id", "cisco_client_secret", "nvd_api_key", "claude_api_key", "local_api_key")


def settings_get() -> dict:
    from . import vault
    return {"keychain": vault.available(), "saved": [n for n in vault.names(APP) if n in APP_KEYS]}


def settings_post(body: dict) -> dict:
    from . import vault
    for n in body.get("forget") or []:
        if n in APP_KEYS:
            vault.forget(APP, n)
    vals = {k: v.strip() for k, v in (body.get("values") or {}).items() if k in APP_KEYS and isinstance(v, str) and v.strip()}
    if vals:
        vault.put_many(APP, vals)
    gone = [n for n in body.get("forget") or [] if n in APP_KEYS]
    if vals or gone:
        note("api keys", {"saved": sorted(vals), "forgotten": gone})  # names only, never the keys
    return settings_get()


def _app_keys(body) -> dict:
    """Keys typed for this run win; otherwise the keychain. Values never go back to the browser."""
    given = {k: v.strip() for k, v in (body.get("keys") or {}).items() if k in APP_KEYS and isinstance(v, str) and v.strip()}
    try:
        from . import vault
        saved = vault.get_many(APP, [k for k in APP_KEYS if k not in given])
    except ImportError:  # keyring extra not installed
        saved = {}
    return {**saved, **given}


def start_cve(body: dict) -> str:
    nos = str(body.get("os") or "ios-xe")
    if nos not in cve.VERSION:
        raise ValueError("os must be ios-xe, nx-os, asa, panos, fortios, eos or junos")
    version = cve.check_version(str(body.get("version") or ""), nos)
    keys = _app_keys(body)
    note("cve check", {"os": nos, "version": version})

    def run(log):
        via = "Palo Alto Networks" if nos == "panos" else "Cisco PSIRT openVuln" if nos in cve.CISCO_OSTYPE and keys.get("cisco_client_id") else "NVD"
        log(f"Looking up {version} via {via}")
        return cve.lookup(version, keys, refresh=bool(body.get("refresh")), nos=nos)
    return _job(run)


def ai_preview(body: dict) -> dict:
    system, user = ai.build_prompt(Network.model_validate(body["network"]), str(body.get("mode")),
                                   str(body.get("question") or ""), body.get("focus") or None)
    chars = len(system) + len(user)
    return {"system": system, "user": user, "chars": chars, "tokens": chars // 4}  # ~4 characters per token


def start_ai(body: dict) -> str:
    pv = ai_preview(body)  # validates before the job starts
    p = body.get("provider") or {}
    kind = p.get("kind")
    key = "claude_api_key" if kind == "claude" else "local_api_key"
    provider = {"kind": kind, "model": str(p.get("model") or "").strip(), "base_url": str(p.get("base_url") or "").strip(),
                "api_key": _app_keys({"keys": {key: p.get("api_key") or ""}}).get(key, "")}
    if kind not in ("claude", "openai"):
        raise ValueError("Pick a provider")
    if local_only() and (kind == "claude" or not ai.is_loopback((provider["base_url"] or "http://localhost:11434/v1"))):
        raise ValueError("Keep my network data on this computer is on, so the Advisor can use only an AI server on this computer "
                         "(localhost). Turn it off in the Advisor to send to the Claude API or another machine.")
    if kind == "openai":  # checked here too, so a bad address fails before the job starts
        ai.check_base_url((provider["base_url"] or "http://localhost:11434/v1").rstrip("/"), bool(provider["api_key"]))
    if kind == "claude" and not provider["api_key"]:
        raise ValueError("Add a Claude API key (File > API keys, or type one for this run)")

    note("advisor", {"provider": "Claude API" if kind == "claude" else (provider["base_url"] or "http://localhost:11434/v1"), "chars": pv["chars"]})

    def run(log):
        where = "Claude API" if kind == "claude" else (provider["base_url"] or "http://localhost:11434/v1")
        log(f"Sending {pv['chars']:,} characters (~{pv['tokens']:,} tokens) to {where} ({provider['model'] or 'default model'})")
        return {"answer": ai.complete(provider, pv["system"], pv["user"])}
    return _job(run)


# Dashboard layout and theme: a small file next to the other OneConfig state, so it survives restarts and
# isn't tied to one browser profile. Validated shape only; the UI decides what the names mean.
PREFS = Path.home() / ".oneconfig" / "ui.json"
_NAME = re.compile(r"^[A-Za-z0-9 _-]{1,32}$")
_WIDGET = re.compile(r"^[a-z]{1,16}$")
MAX_WIDGETS = 12  # per layout: about one screen; more goes in another layout


def _prefs_file() -> dict:
    """{"local_only": bool, "users": {name: {theme, preset, layouts}}}: one shared switch, a dashboard per person.
    Files from before accounts held one person's dashboard at the top level: that becomes "local"'s."""
    try:
        d = json.loads(PREFS.read_text())
    except (OSError, ValueError):
        return {"users": {}}
    if "users" not in d:
        d = {**({"local_only": d["local_only"]} if "local_only" in d else {}),
             "users": {"local": {k: d[k] for k in ("theme", "preset", "layouts") if k in d}} if any(k in d for k in ("theme", "preset", "layouts")) else {}}
    return d


def prefs_get(user: str = "local") -> dict:
    d = _prefs_file()
    mine = d["users"].get(user) or d["users"].get("local") or {}  # a new account starts from the owner's dashboard
    return {**({"local_only": d["local_only"]} if "local_only" in d else {}), **mine}


def local_only() -> bool:
    """On unless the user turned it off: the Advisor may then use only an AI server on this computer."""
    return _prefs_file().get("local_only", True) is not False


def prefs_post(body: dict, role: str = "admin", user: str = "local") -> dict:
    """Saves this user's dashboard; only an admin changes the shared keep-data-local switch."""
    out, switch = {}, local_only()
    if "local_only" in body:
        if not isinstance(body["local_only"], bool):
            raise ValueError("local_only: true or false")
        if body["local_only"] != switch and role != "admin":
            raise PermissionError("Only an admin can change whether network data may leave this computer.")
    for k in ("theme", "preset"):
        if k in body:
            if not isinstance(body[k], str) or not _NAME.match(body[k]):
                raise ValueError(f"{k}: not a valid name")
            out[k] = body[k]
    layouts = body.get("layouts", {})
    if not isinstance(layouts, dict) or len(layouts) > 12:
        raise ValueError("layouts: at most 12 named layouts")
    out["layouts"] = {}
    for name, tiles in layouts.items():
        if not _NAME.match(str(name)) or not isinstance(tiles, list) or len(tiles) > MAX_WIDGETS:
            raise ValueError(f"layouts.{name}: at most {MAX_WIDGETS} widgets")
        if not all(isinstance(t, list) and len(t) == 2 and isinstance(t[0], str) and _WIDGET.match(t[0]) and t[1] in ("s", "t", "w", "l")
                   for t in tiles):
            raise ValueError(f"layouts.{name}: each widget is [name, size]")
        out["layouts"][name] = tiles
    d = _prefs_file()
    if body.get("local_only", switch) != switch:
        note("keep data local", "on" if body["local_only"] else "off")
    d["local_only"] = body.get("local_only", switch)  # a layout save doesn't reset it
    d["users"][user] = out
    private.write(PREFS, json.dumps(d))
    return {"local_only": d["local_only"], **out}


def users_post(body: dict, who: dict) -> dict:
    """Account management. Anyone signed in may change their own password; everything else is for admins.
    The very first account (always an admin) signs straight in, so turning accounts on can't lock you out."""
    action, name = body.get("action"), str(body.get("name") or "")
    if action == "password" and name == who["user"] and users.enabled():
        if not users.check(name, str(body.get("current") or "")):
            raise PermissionError("Your current password is wrong.")
        users.set_password(name, str(body.get("password") or ""))
        note("change password", {"user": name})
        return users.sign_in(name, str(body.get("password") or ""))
    if who["role"] != "admin":
        raise PermissionError("Only an admin can manage accounts.")
    first = not users.enabled()
    if action == "add":
        users.add(name, str(body.get("password") or ""), str(body.get("role") or ""))
        note("add user", {"user": name, "role": body.get("role")})
        if first:
            return {**users.sign_in(name, str(body.get("password") or "")), "users": users.listing()}
    elif action == "role":
        users.set_role(name, str(body.get("role") or ""))
        note("change role", {"user": name, "role": body.get("role")})
    elif action == "remove":
        users.remove(name)
        note("remove user", {"user": name})
    elif action == "password":
        users.set_password(name, str(body.get("password") or ""))
        note("reset password", {"user": name})
    else:
        raise ValueError("action must be add, role, remove or password")
    return {"users": users.listing()}


def _nodes(nodes):
    from .discover import summarize, to_fragment
    return {"rows": summarize(nodes), "fragment": to_fragment(nodes)}


# The page may run only its own inline code, talk only to this server, and be shown by no other site (no framing,
# so no clickjacking); nothing it loads or sends can go anywhere else. Every response: never cached, never sniffed.
PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; font-src data:; img-src data: blob:; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version, sys_version = "OneConfig", ""  # don't advertise the Python version

    def _send(self, code, data, ctype="application/json"):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Content-Security-Policy", PAGE_CSP if ctype.startswith("text/html") else "default-src 'none'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(raw)

    def _local(self):
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
        return host in ("127.0.0.1", "localhost")

    def _token(self):
        return secrets.compare_digest(self.headers.get("X-OneConfig-Token") or "", TOKEN)

    def _who(self):
        """The signed-in user and role; with no accounts set up, whoever holds the launch key is the admin."""
        if not users.enabled():
            return {"user": "local", "role": "admin"}
        return users.session(self.headers.get("X-OneConfig-Session"))

    def _deny(self, who, need):
        if who is None:  # accounts exist and this request has no live session: the page shows its sign-in box
            self.send_response(401)
            self.send_header("X-OneConfig-Login", "required")
            body = json.dumps({"error": "Sign in to OneConfig"}).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return True
        if not users.allowed(who["role"], need):
            self._send(403, {"errors": [f"Your role ({who['role']}) can't do this; it needs {need}."]})
            return True
        return False

    GET_ROLES = {"/api/example": "viewer", "/api/example/edge": "viewer", "/api/settings": "admin", "/api/prefs": "viewer",
                 "/api/backups": "viewer", "/api/serial-ports": "operator", "/api/audit-trail": "operator", "/api/users": "admin"}

    def do_GET(self):
        if not self._local():
            return self._send(403, {"error": "forbidden host"})
        if self.path in ("/", "/index.html"):
            return self._send(200, (HERE / "ui" / "index.html").read_bytes(), "text/html; charset=utf-8")
        if self.path == "/app.js":  # the page's code in its own file, so the policy can refuse every inline script
            return self._send(200, (HERE / "ui" / "app.js").read_bytes(), "text/javascript; charset=utf-8")
        if not self._token():
            return self._send(401, {"error": "open OneConfig from the link `oneconfig serve` printed"})
        who = self._who()
        if self.path == "/api/me":
            return self._send(200, {"accounts": users.enabled(), **({"user": who["user"], "role": who["role"]} if who else {})})
        need = "viewer" if self.path.startswith("/api/jobs/") else self.GET_ROLES.get(self.path)
        if need is None:
            return self._send(404, {"error": "not found"})
        if self._deny(who, need):
            return
        ACTOR.set(who["user"])
        if self.path in ("/api/example", "/api/example/edge"):
            return self._send(200, (HERE / "examples" / ("edge.json" if self.path.endswith("/edge") else "campus.json")).read_bytes())
        if self.path.startswith("/api/jobs/"):
            job = JOBS.get(self.path.rsplit("/", 1)[1])
            return self._send(200, job) if job else self._send(404, {"error": "no such job"})
        if self.path == "/api/settings":
            try:
                return self._send(200, settings_get())
            except ImportError:
                return self._send(200, {"keychain": False, "saved": []})
        if self.path == "/api/prefs":
            return self._send(200, prefs_get(who["user"]))
        if self.path == "/api/backups":
            return self._send(200, backups())
        if self.path == "/api/audit-trail":
            return self._send(200, {"items": trail.read(), **trail.verify()})
        if self.path == "/api/users":
            return self._send(200, users.listing())
        try:
            from .discover import serial_ports
            return self._send(200, serial_ports())
        except ImportError:
            return self._send(200, [])

    POST_ROLES = {"/api/build": "viewer", "/api/audit": "viewer", "/api/cklb": "viewer", "/api/push/needs": "viewer",
                  "/api/ai/preview": "viewer", "/api/prefs": "viewer", "/api/history/save": "viewer", "/api/history/list": "viewer",
                  "/api/history/get": "viewer", "/api/history/restored": "viewer", "/api/discover": "operator", "/api/push/plan": "operator",
                  "/api/push/apply": "operator", "/api/push/rollback": "operator", "/api/cve": "operator", "/api/ai/ask": "operator",
                  "/api/settings": "admin", "/api/users": "viewer"}  # /api/users: anyone may change their own password; the rest is checked inside

    def do_POST(self):
        if not self._local():
            return self._send(403, {"error": "forbidden host"})
        # CSRF guard: a web page can't send a JSON content type or a local Origin cross-site without a
        # CORS preflight, which this server never approves. Without this, any site could make it scan your network.
        origin = self.headers.get("Origin")
        if not (self.headers.get("Content-Type") or "").startswith("application/json") or \
                (origin and re.sub(r":\d+$", "", origin) not in ("http://127.0.0.1", "http://localhost")):
            return self._send(403, {"error": "forbidden origin"})
        if not self._token():
            return self._send(401, {"error": "open OneConfig from the link `oneconfig serve` printed"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n < 0:  # read(-1) would wait for the client to hang up
            return self._send(400, {"error": "bad Content-Length"})
        if n > MAX_BODY:
            return self._send(413, {"error": "too large"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            if self.path == "/api/login":
                s = users.sign_in(str(body.get("user") or ""), str(body.get("password") or ""))
                note("sign in" if s else "sign-in failed", "", str(body.get("user") or "")[:32])
                return self._send(200, s) if s else self._send(401, {"errors": ["Wrong user name or password."]})
            if self.path == "/api/logout":
                who = users.session(self.headers.get("X-OneConfig-Session"))
                users.sign_out(self.headers.get("X-OneConfig-Session"))
                if who:
                    note("sign out", "", who["user"])
                return self._send(200, {})
            who, need = self._who(), self.POST_ROLES.get(self.path)
            if need is None:
                return self._send(404, {"error": "not found"})
            if self._deny(who, need):
                return
            ACTOR.set(who["user"])
            if self.path == "/api/build":
                return self._send(200, build(body))
            if self.path == "/api/audit":
                return self._send(200, audit_pasted(body))
            if self.path == "/api/cklb":
                return self._send(200, checklist(body["stig"], str(body.get("host") or "device"), str(body.get("ip") or ""),
                                                 str(body.get("source") or "the running configuration")))
            if self.path == "/api/discover":
                return self._send(200, {"job": start_discovery(body)})
            if self.path == "/api/push/needs":
                return self._send(200, push_needs(body))
            if self.path == "/api/push/plan":
                return self._send(200, {"job": start_plan(body)})
            if self.path == "/api/push/apply":
                return self._send(200, {"job": start_apply(body)})
            if self.path == "/api/push/rollback":
                return self._send(200, {"job": start_rollback(body)})
            if self.path == "/api/cve":
                return self._send(200, {"job": start_cve(body)})
            if self.path == "/api/ai/preview":
                return self._send(200, ai_preview(body))
            if self.path == "/api/ai/ask":
                return self._send(200, {"job": start_ai(body)})
            if self.path == "/api/settings":
                return self._send(200, settings_post(body))
            if self.path == "/api/prefs":
                return self._send(200, prefs_post(body, who["role"], who["user"]))
            if self.path == "/api/history/save":
                return self._send(200, history.save(body["network"], str(body.get("reason") or "")))
            if self.path == "/api/history/list":
                return self._send(200, history.listing(str(body.get("id") or "")))
            if self.path == "/api/history/get":
                return self._send(200, history.get(str(body.get("id") or ""), str(body.get("version") or "")))
            if self.path == "/api/history/restored":
                note("restore network", {"version": str(body.get("version") or "")[:32], "devices": int(body.get("devices") or 0)})
                return self._send(200, {})
            return self._send(200, users_post(body, who))
        except PermissionError as e:
            self._send(403, {"errors": [str(e)]})
        except ValidationError as e:
            self._send(400, {"errors": [f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors()]})
        except (ValueError, AttributeError, KeyError, TypeError, IndexError, RuntimeError) as e:  # malformed input
            self._send(400, {"errors": [str(e)]})
        except ImportError:
            self._send(400, {"errors": ["Discovery needs the optional extras: pip install -e \".[discover]\""]})
        except Exception as e:  # never drop the connection without an answer
            self._send(500, {"errors": [f"Internal error ({type(e).__name__})"]})

    def log_message(self, *a):
        pass


def private_dir() -> Path:
    """~/.oneconfig, readable by this account only: it holds backups, host keys, the launch key and settings."""
    return private.folder(Path.home() / ".oneconfig")


def launch_file(port) -> Path:
    """A page only this user can read that forwards the browser to the app with the token in the URL fragment
    (#t=...). A fragment is never sent to a server, and the file's path, not the token, is what the browser's
    process arguments show."""
    return private.write(private_dir() / "open.html", f'<meta http-equiv="refresh" content="0;url=http://127.0.0.1:{port}/#t={TOKEN}">')


def serve(port=8470, open_browser=True):
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    f = launch_file(srv.server_address[1])
    print(f"OneConfig running at http://127.0.0.1:{srv.server_address[1]}/  (Ctrl+C to stop)\nOpen it with: {f.as_uri()}")
    if open_browser:
        webbrowser.open(f.as_uri())
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
