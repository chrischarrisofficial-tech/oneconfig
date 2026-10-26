import pytest


class _MemKeyring:
    """An in-memory keychain, so no test ever reads or writes the real OS keychain."""
    priority = 1

    def __init__(self):
        self.d = {}

    def get_password(self, s, u):
        return self.d.get((s, u))

    def set_password(self, s, u, p):
        self.d[(s, u)] = p

    def delete_password(self, s, u):
        self.d.pop((s, u), None)


@pytest.fixture(autouse=True)
def _private_state(tmp_path, monkeypatch):
    """Keep SSH host keys, settings, accounts, the audit trail, history and keychain entries out of the real
    ~/.oneconfig and the real OS keychain: tests can't depend on, or change, them."""
    from oneconfig import cve, discover, history, push, server, trail, users, vault
    monkeypatch.setattr(discover, "KNOWN_HOSTS", tmp_path / "known_hosts")
    monkeypatch.setattr(server, "PREFS", tmp_path / "ui.json")
    monkeypatch.setattr(trail, "LOG", tmp_path / "audit-trail.jsonl")
    monkeypatch.setattr(users, "FILE", tmp_path / "users.json")
    monkeypatch.setattr(users, "SESSIONS", {})
    monkeypatch.setattr(history, "DIR", tmp_path / "history")
    monkeypatch.setattr(vault, "INDEX", tmp_path / "secret-names.json")
    monkeypatch.setattr(push, "BACKUPS", tmp_path / "backups")
    monkeypatch.setattr(cve, "CACHE", tmp_path / "cve-cache.json")
    try:
        import keyring
        from keyring.backend import KeyringBackend
    except ImportError:
        yield
        return
    mem = type("MemKeyring", (_MemKeyring, KeyringBackend), {})()
    old = keyring.get_keyring()
    keyring.set_keyring(mem)
    yield
    keyring.set_keyring(old)
