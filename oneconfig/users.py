"""Local user accounts and roles. With no accounts OneConfig works as before (whoever opens it from the launch link is
in charge). Once an admin is created, every request also needs a signed-in session, and the server checks the role.

viewer   look at everything, build and audit configs, keep their own dashboard
operator also discover, plan, push, roll back, check CVEs and ask the Advisor
admin    also manage accounts and the API keys

Passwords are stored as scrypt hashes in ~/.oneconfig/users.json (this account only); sessions live in memory and
end after 12 idle hours or a sign-out."""
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from pathlib import Path

from . import private

FILE = Path.home() / ".oneconfig" / "users.json"
ROLES = ("viewer", "operator", "admin")
MIN_PASSWORD = 10
IDLE = 12 * 3600
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_LOCK = threading.Lock()
SESSIONS: dict[str, dict] = {}
_FAILS: dict[str, list] = {}  # name -> recent failed sign-in times, to slow guessing


def _load() -> dict:
    try:
        return json.loads(FILE.read_text()).get("users", {})
    except (OSError, ValueError):
        return {}


def _save(users: dict):
    private.write(FILE, json.dumps({"users": users}, indent=1))


def _hash(password: str, salt: bytes) -> str:
    return hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32).hex()


def enabled() -> bool:
    return bool(_load())


def listing() -> list[dict]:
    return [{"name": n, "role": u["role"]} for n, u in sorted(_load().items())]


def _check_new(name, password, role):
    if not _NAME.match(name or ""):
        raise ValueError("A user name is letters, digits, dot, dash or underscore, up to 32 characters.")
    if role not in ROLES:
        raise ValueError("Role must be viewer, operator or admin.")
    if len(password or "") < MIN_PASSWORD:
        raise ValueError(f"Use a password of at least {MIN_PASSWORD} characters.")


def add(name: str, password: str, role: str):
    _check_new(name, password, role)
    with _LOCK:
        users = _load()
        if name in users:
            raise ValueError(f"There is already a user called {name}.")
        if not users and role != "admin":
            raise ValueError("The first account must be an admin, or nobody could manage accounts.")
        salt = secrets.token_bytes(16)
        users[name] = {"role": role, "salt": salt.hex(), "hash": _hash(password, salt)}
        _save(users)


def _admins_after(users, name, role):
    return sum(1 for n, u in users.items() if (role if n == name else u["role"]) == "admin")


def set_role(name: str, role: str):
    if role not in ROLES:
        raise ValueError("Role must be viewer, operator or admin.")
    with _LOCK:
        users = _load()
        if name not in users:
            raise ValueError(f"No user called {name}.")
        if _admins_after(users, name, role) == 0:
            raise ValueError("Keep at least one admin.")
        users[name]["role"] = role
        _save(users)
    for s in list(SESSIONS.values()):  # a copy: another request may sign in while this runs
        if s["user"] == name:
            s["role"] = role


def remove(name: str):
    with _LOCK:
        users = _load()
        if name not in users:
            raise ValueError(f"No user called {name}.")
        if len(users) > 1 and _admins_after(users, name, "gone") == 0:
            raise ValueError("Keep at least one admin.")
        del users[name]
        _save(users)
    for t in [t for t, s in list(SESSIONS.items()) if s["user"] == name]:
        SESSIONS.pop(t, None)


def set_password(name: str, password: str):
    if len(password or "") < MIN_PASSWORD:
        raise ValueError(f"Use a password of at least {MIN_PASSWORD} characters.")
    with _LOCK:
        users = _load()
        if name not in users:
            raise ValueError(f"No user called {name}.")
        salt = secrets.token_bytes(16)
        users[name].update(salt=salt.hex(), hash=_hash(password, salt))
        _save(users)
    for t in [t for t, s in list(SESSIONS.items()) if s["user"] == name]:
        SESSIONS.pop(t, None)  # a new password signs out the old sessions


def check(name: str, password: str) -> str | None:
    """The user's role if the password is right, else None. Constant time per attempt; repeated failures slow down."""
    now = time.monotonic()
    recent = [t for t in _FAILS.get(name or "", []) if now - t < 60]
    if len(recent) >= 5:
        time.sleep(2)  # five wrong guesses in a minute: every further try waits
    u = _load().get(name or "")
    salt, want = (bytes.fromhex(u["salt"]), u["hash"]) if u else (b"x" * 16, "0" * 64)
    ok = hmac.compare_digest(_hash(password or "", salt), want) and bool(u)
    if not ok:
        if len(_FAILS) > 1000:  # many made-up names: don't let the table grow without end
            _FAILS.clear()
        _FAILS[name or ""] = recent + [now]
        return None
    _FAILS.pop(name, None)
    return u["role"]


def sign_in(name: str, password: str) -> dict | None:
    role = check(name, password)
    if not role:
        return None
    token, now = secrets.token_urlsafe(32), time.monotonic()
    for t in [t for t, s in list(SESSIONS.items()) if now - s["seen"] > IDLE]:  # sessions from closed tabs don't pile up
        SESSIONS.pop(t, None)
    SESSIONS[token] = {"user": name, "role": role, "seen": now}
    return {"session": token, "user": name, "role": role}


def session(token: str | None) -> dict | None:
    s = SESSIONS.get(token or "")
    if not s or time.monotonic() - s["seen"] > IDLE:
        SESSIONS.pop(token or "", None)
        return None
    s["seen"] = time.monotonic()
    return s


def sign_out(token: str | None):
    SESSIONS.pop(token or "", None)


def allowed(role: str, need: str) -> bool:
    return ROLES.index(role) >= ROLES.index(need)
