"""Saved versions of each network, so a delete, a replaced map or a loaded example can be undone.

The page sends its network after changes (at most every 20 seconds) and right before anything that replaces or
removes devices. Each network keeps its last KEEP edits and, separately, its last KEEP "before …" versions under
~/.oneconfig/history/<network id>/
(this account only). A version is the network design OneConfig already holds in the page: no secrets."""
import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import private

DIR = Path.home() / ".oneconfig" / "history"
KEEP = 100
_ID = re.compile(r"^[0-9a-f-]{36}$")
_VER = re.compile(r"^\d{8}-\d{6}-\d{6}(-[ek])?$")  # -k: a "before …" version, -e: an edit (older files have neither)
_LOCK = threading.Lock()


def _folder(net_id: str) -> Path:
    if not _ID.match(net_id or ""):
        raise ValueError("network id: not a network OneConfig made")
    return DIR / net_id


def _digest(network: dict) -> str:
    return hashlib.sha256(json.dumps({k: v for k, v in network.items() if k != "id"}, sort_keys=True).encode()).hexdigest()


def save(network: dict, reason: str = "") -> dict:
    """Keep this version unless it's the same as the newest one. Returns {"saved": bool, "version": ...}."""
    d = _folder(str(network.get("id", "")))
    digest = _digest(network)
    with _LOCK:
        private.folder(d)
        files = sorted(d.glob("*.json"))
        if files and json.loads(files[-1].read_text()).get("digest") == digest:
            return {"saved": False, "version": files[-1].stem}
        kind = "k" if str(reason).startswith("before") else "e"
        ver = datetime.now(timezone.utc).strftime(f"%Y%m%d-%H%M%S-%f-{kind}")
        private.write(d / f"{ver}.json", json.dumps({"version": ver, "reason": str(reason)[:80], "digest": digest, "network": network}))
        # Edits and "before …" versions are pruned separately: a long editing session can't push out the version saved
        # just before a delete or a replaced map, which is the one people come back for.
        for keep in (True, False):
            same = [f for f in sorted(d.glob("*.json")) if f.stem.endswith("-k") == keep]
            for old in same[:max(0, len(same) - KEEP)]:
                old.unlink()
        return {"saved": True, "version": ver}


def listing(net_id: str) -> list[dict]:
    """Newest first: when, why, and enough to recognise it (device count, names)."""
    out = []
    for f in sorted(_folder(net_id).glob("*.json"), reverse=True):
        try:
            v = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        devs = [d.get("hostname", "?") for d in v["network"].get("devices", [])]
        out.append({"version": v["version"], "reason": v.get("reason", ""), "devices": len(devs), "names": devs[:12],
                    "links": len(v["network"].get("links", [])), "name": v["network"].get("name", "")})
    return out


def get(net_id: str, version: str) -> dict:
    if not _VER.match(version or ""):
        raise ValueError("version: not one of this network's saved versions")
    f = _folder(net_id) / f"{version}.json"
    if not f.is_file():
        raise ValueError("That version isn't saved any more.")
    return json.loads(f.read_text())["network"]
