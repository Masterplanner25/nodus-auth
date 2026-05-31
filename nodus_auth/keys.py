"""Platform API key generation and hashing."""
from __future__ import annotations

import hashlib
import secrets

_KEY_PREFIX = "nodus_"
_KEY_TOKEN_BYTES = 32  # 32 bytes → 43-char url-safe base64


def hash_key(raw_key: str) -> str:
    """Return the SHA-256 hex digest of *raw_key*."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_key(*, prefix: str = _KEY_PREFIX) -> tuple[str, str]:
    """Generate a new platform API key.

    Returns ``(raw_key, key_hash)``.  *raw_key* is the plaintext key to
    deliver to the caller — it is never stored.  *key_hash* is the SHA-256
    hex digest to store in the database.
    """
    token = secrets.token_urlsafe(_KEY_TOKEN_BYTES)
    raw_key = f"{prefix}{token}"
    return raw_key, hash_key(raw_key)
