"""Encryption at rest for running-config backups (they hold password hashes, SNMP and routing keys).

Fernet (AES-128-CBC + HMAC-SHA256, from the `cryptography` package that SSH support already installs) with a key
kept in the OS keychain, created on first use. Without a keychain or the package, backups stay plain text in the
private folder, and the caller is told so."""
KEY_NAME = "backup_key"
MAGIC = b"gAAAAA"  # every Fernet token starts like this


def _fernet(may_create: bool):
    """None when encryption isn't possible here (no keychain, or no cryptography package). Raises KeyUnavailable on a
    keychain error, or when the key is gone but backups were already encrypted with it: a new key would hide that."""
    from . import vault
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    k = vault.app_key(KEY_NAME, lambda: Fernet.generate_key().decode(), may_create)
    return Fernet(k.encode()) if k else None


def seal(text: str, encrypted_before: bool = False) -> tuple[bytes, bool]:
    """(bytes to write, encrypted?). encrypted_before: earlier backups are encrypted, so this one must be too."""
    from . import vault
    f = _fernet(may_create=not encrypted_before)
    if not f and encrypted_before:
        raise vault.KeyUnavailable("Earlier backups are encrypted, but encryption isn't available here (keychain or cryptography package missing).")
    return (f.encrypt(text.encode()), True) if f else (text.encode(), False)


def unseal(data: bytes) -> str:
    if not data.startswith(MAGIC):
        return data.decode()  # an older plain backup
    f = _fernet(may_create=False)
    if not f:
        raise ValueError("This backup is encrypted with a key from the OS keychain, which isn't available here.")
    return f.decrypt(data).decode()
