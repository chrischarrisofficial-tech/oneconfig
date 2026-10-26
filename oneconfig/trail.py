"""Audit trail: who planned, pushed, rolled back, discovered or changed settings, and when.

One JSON line per event in ~/.oneconfig/audit-trail.jsonl (this account only). Each line carries the hash of the line
before it and its own MAC, keyed with a secret held in the OS keychain: editing, removing or reordering a line breaks
the chain, and the MACs can't be redone without the keychain. Without a keychain the chain is plain SHA-256, which
still shows accidental damage but not a careful forger. Nothing secret is ever written here."""
import hashlib
import hmac
import json
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import private

LOG = Path.home() / ".oneconfig" / "audit-trail.jsonl"
KEY_NAME = "audit_key"
_LOCK = threading.Lock()


def _key(create: bool, rows):
    """The signing key; None only when this computer has no keychain and nothing was signed before. A new key is made
    only for a log with no signed lines, so an existing log is never re-keyed and never continued unsigned."""
    from . import vault
    signed = any(e.get("keyed") for e in rows)
    k = vault.app_key(KEY_NAME, lambda: secrets.token_hex(32), create and not signed)
    if k is None and signed:
        raise vault.KeyUnavailable("This audit log is signed, but there is no OS keychain here to sign new entries.")
    return k.encode() if k else None


def _mac(key, body: str) -> str:
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest() if key else hashlib.sha256(body.encode()).hexdigest()


def _lines():
    try:
        return [json.loads(x) for x in LOG.read_text().splitlines() if x.strip()]
    except (OSError, ValueError):
        return []


def record(actor: str, action: str, detail=None) -> dict:
    """Append one event. detail is short and never holds a secret (names, hosts, counts, results)."""
    with _LOCK:
        rows = _lines()
        key = _key(True, rows)  # raises rather than write an unsigned line into a signed log
        prev = (rows or [{"mac": ""}])[-1]["mac"]
        e = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "actor": actor or "local", "action": action,
             "detail": detail if detail is not None else "", "prev": prev}
        e["keyed"] = bool(key)
        e["mac"] = _mac(key, json.dumps(e, sort_keys=True))
        with private.touch(LOG).open("a") as f:
            f.write(json.dumps(e, sort_keys=True) + "\n")
        return e


def verify() -> dict:
    """Walk the chain. ok is False at the first line that was edited, removed or put out of order. Never makes a key:
    when the key can't be read, the links between lines are still checked and checked is False (signatures unchecked)."""
    from . import vault
    rows, prev, signed = _lines(), "", False
    try:
        key, checked = _key(False, rows), True
    except vault.KeyUnavailable as e:
        key, checked, why = None, False, str(e)
    for i, e in enumerate(rows):
        body = {k: v for k, v in e.items() if k != "mac"}
        signed |= bool(e.get("keyed"))
        bad_mac = (checked or not e.get("keyed")) and not hmac.compare_digest(
            _mac(key if e.get("keyed") else None, json.dumps(body, sort_keys=True)), e.get("mac", ""))
        if e.get("prev") != prev or (signed and not e.get("keyed")) or bad_mac:  # an unsigned line after signed ones is a forgery
            return {"ok": False, "entries": len(rows), "broken_at": i, "signed": signed, "checked": checked}
        prev = e["mac"]
    return {"ok": True, "entries": len(rows), "broken_at": None, "signed": bool(rows) and all(e.get("keyed") for e in rows),
            "checked": checked, **({} if checked else {"why": why})}


def read(limit=300) -> list[dict]:
    return [{k: e[k] for k in ("at", "actor", "action", "detail")} for e in reversed(_lines()[-limit:])]
