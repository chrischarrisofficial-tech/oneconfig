"""Secrets in the OS keychain (macOS Keychain, Windows Credential Manager, Linux Secret Service) via `keyring`.

Values never leave this machine and are never sent back to the browser. A small index file stores which
*names* exist per network (keyring can't list entries); it never contains values."""
import json
from pathlib import Path

SERVICE = "oneconfig"
INDEX = Path.home() / ".oneconfig" / "secret-names.json"
LOGIN = "@login"


def _kr():
    import keyring
    from keyring.backends import fail
    kr = keyring.get_keyring()
    return None if isinstance(kr, fail.Keyring) else kr


def available() -> bool:
    try:
        return _kr() is not None
    except Exception:  # broken keyring install
        return False


def _index():
    try:
        return json.loads(INDEX.read_text())
    except (OSError, ValueError):
        return {}


def _save_index(idx):
    """Names only, but still this account's business: private folder, private file."""
    from . import private
    private.write(INDEX, json.dumps(idx, indent=1))


def names(network: str) -> list[str]:
    return sorted(_index().get(network, []))


def get_many(network: str, wanted) -> dict:
    kr = _kr()
    if not kr:
        return {}
    out = {}
    for n in wanted:
        v = kr.get_password(SERVICE, f"{network}/{n}")
        if v:
            out[n] = v
    return out


def put_many(network: str, values: dict):
    kr = _kr()
    if not kr:
        raise RuntimeError("No OS keychain is available on this computer, so secrets can't be remembered.")
    idx = _index()
    have = set(idx.get(network, []))
    for n, v in values.items():
        if v:
            kr.set_password(SERVICE, f"{network}/{n}", v)
            have.add(n)
    idx[network] = sorted(have)
    _save_index(idx)


def forget(network: str, name: str):
    kr = _kr()
    if kr:
        try:
            kr.delete_password(SERVICE, f"{network}/{name}")
        except Exception:  # already gone
            pass
    idx = _index()
    idx[network] = [n for n in idx.get(network, []) if n != name]
    _save_index(idx)


def get_login(network: str) -> dict | None:
    v = get_many(network, [LOGIN]).get(LOGIN)
    return json.loads(v) if v else None


def put_login(network: str, login: dict):
    put_many(network, {LOGIN: json.dumps({k: login.get(k, "") for k in ("username", "password", "secret")})})


class KeyUnavailable(RuntimeError):
    """A key OneConfig signs or encrypts with can't be used right now."""


def app_key(name: str, make, may_create: bool) -> str | None:
    """OneConfig's own secret `name` (the audit log's signing key, the backup key). None when this computer has no
    keychain. A keychain error, or a missing key that data was already made with, raises KeyUnavailable: replacing
    the key would make that data unverifiable or unreadable, so it is never done silently."""
    if not available():
        return None
    try:
        v = get_many("@app", [name]).get(name)
    except Exception as e:  # locked, denied, broken backend
        raise KeyUnavailable(f"The OS keychain couldn't be read ({type(e).__name__}). Unlock it and try again.") from None
    if v:
        return v
    if not may_create:
        raise KeyUnavailable(f"OneConfig's {name.replace('_', ' ')} is missing from the OS keychain, and data made with it already "
                             "exists. Restore the keychain item (service oneconfig, account @app/" + name + ") to use that data.")
    v = make()
    put_many("@app", {name: v})
    return v
