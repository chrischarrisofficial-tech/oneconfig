"""Writing OneConfig's state so only this account can read it: every folder it creates is 0700, every file 0600,
and a file is written in full to a temporary name first, so a crash never leaves half of one."""
import os
from pathlib import Path


def folder(p: Path) -> Path:
    """p and any missing parents, created private; p itself is tightened if it already existed open."""
    missing = []
    while not p.exists() and p != p.parent:
        missing.append(p)
        p = p.parent
    for d in reversed(missing):
        d.mkdir(mode=0o700, exist_ok=True)
    target = missing[0] if missing else p
    target.chmod(0o700)
    return target


def touch(path: Path) -> Path:
    """An existing or new private file (for appending)."""
    folder(path.parent)
    path.touch(mode=0o600)
    path.chmod(0o600)
    return path


def write(path: Path, data: str | bytes) -> Path:
    tmp = touch(path.with_name(path.name + ".tmp"))
    tmp.write_bytes(data.encode() if isinstance(data, str) else data)
    os.replace(tmp, path)
    return path
