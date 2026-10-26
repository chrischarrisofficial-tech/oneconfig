"""The state OneConfig keeps on disk and in the keychain: audit log keys, backup keys, history, accounts, private files."""
import os
import stat

import keyring
import pytest

from oneconfig import history, private, seal, trail, users, vault


def _drop(name):
    keyring.get_keyring().delete_password(vault.SERVICE, f"@app/{name}")


def test_a_signed_log_is_never_re_keyed_or_continued_unsigned():
    trail.record("ana", "sign in")
    trail.record("ana", "plan", {"devices": ["R1"]})
    _drop(trail.KEY_NAME)  # the keychain item is lost (new Mac, clean-up)
    with pytest.raises(vault.KeyUnavailable, match="missing"):
        trail.record("ana", "push")
    assert len(trail.LOG.read_text().splitlines()) == 2  # nothing written unsigned
    v = trail.verify()
    assert v["ok"] and not v["checked"] and "missing" in v["why"]  # links still checked; not called "changed"
    assert keyring.get_keyring().get_password(vault.SERVICE, f"@app/{trail.KEY_NAME}") is None  # verify made no new key


def test_a_keychain_error_stops_the_write(monkeypatch):
    trail.record("ana", "sign in")
    kr = keyring.get_keyring()

    def locked(*a):
        raise RuntimeError("keychain locked")
    monkeypatch.setattr(kr, "get_password", locked)
    with pytest.raises(vault.KeyUnavailable, match="couldn't be read"):
        trail.record("ana", "plan")
    assert len(trail.LOG.read_text().splitlines()) == 1


def test_backups_keep_their_key():
    data, enc = seal.seal("hostname R1\n")  # first backup: the key is made
    assert enc and seal.unseal(data) == "hostname R1\n"
    _drop(seal.KEY_NAME)
    with pytest.raises(vault.KeyUnavailable, match="missing"):
        seal.seal("hostname R1\n", encrypted_before=True)  # a new key would orphan the old backups: refuse
    assert keyring.get_keyring().get_password(vault.SERVICE, f"@app/{seal.KEY_NAME}") is None
    with pytest.raises(vault.KeyUnavailable):
        seal.unseal(data)


def test_before_versions_outlast_a_long_editing_session(monkeypatch):
    monkeypatch.setattr(history, "KEEP", 3)
    nid = "6f1c1d2e-0000-4000-8000-000000000002"
    history.save({"id": nid, "devices": [{"hostname": "R1"}]}, "before deleting R2")
    for n in range(6):  # lots of edits afterwards
        history.save({"id": nid, "devices": [{"hostname": "R1", "x": n}]}, "edited")
    reasons = [v["reason"] for v in history.listing(nid)]
    assert reasons.count("edited") == 3 and "before deleting R2" in reasons


def test_idle_sessions_are_cleared_on_the_next_sign_in(monkeypatch):
    users.add("ana", "Admin-Pass-123", "admin")
    old = users.sign_in("ana", "Admin-Pass-123")["session"]
    users.SESSIONS[old]["seen"] -= users.IDLE + 1
    users.sign_in("ana", "Admin-Pass-123")
    assert old not in users.SESSIONS and len(users.SESSIONS) == 1


def test_private_folders_and_files(tmp_path):
    f = private.write(tmp_path / "a" / "b" / "c.json", "{}")
    for p in (tmp_path / "a", tmp_path / "a" / "b"):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o700, p  # every folder it made, not just the last one
    assert stat.S_IMODE(os.stat(f).st_mode) == 0o600 and not (f.parent / "c.json.tmp").exists()
