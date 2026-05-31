"""JWT token creation, decoding, and key rotation."""
from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt as _jwt

from .config import AuthSettings


class InvalidTokenError(Exception):
    """Raised when a JWT cannot be decoded, is expired, or fails verification."""


class KeyRing:
    """Two-slot JWT signing key ring supporting zero-downtime rotation.

    Signing always uses the active key.  Verification tries active first, then
    previous (within the grace window) so tokens issued with the old key remain
    valid while clients refresh.
    """

    def __init__(
        self,
        active: str,
        previous: Optional[str] = None,
        grace_hours: int = 24,
    ) -> None:
        self._lock = threading.RLock()
        self._active = active
        self._previous = previous
        self._previous_expires: Optional[datetime] = None
        self._grace_hours = grace_hours
        if previous:
            self._previous_expires = datetime.now(timezone.utc) + timedelta(
                hours=grace_hours
            )

    @property
    def active_key(self) -> str:
        with self._lock:
            return self._active

    def rotate(self, new_key: str) -> None:
        """Promote active → previous (with expiry), set *new_key* as active."""
        with self._lock:
            if new_key == self._active:
                return
            self._previous = self._active
            self._previous_expires = datetime.now(timezone.utc) + timedelta(
                hours=self._grace_hours
            )
            self._active = new_key

    def verify_keys(self) -> list[str]:
        """Return keys to try for verification, most recent first."""
        with self._lock:
            keys = [self._active]
            if self._previous and self._previous_expires:
                if datetime.now(timezone.utc) < self._previous_expires:
                    keys.append(self._previous)
                else:
                    self._previous = None
                    self._previous_expires = None
            return keys

    def reload_from_env(self) -> bool:
        """Reload active key from SECRET_KEY env var. Returns True if key changed."""
        new_key = os.getenv("SECRET_KEY", "")
        if not new_key or new_key == self._active:
            return False
        self.rotate(new_key)
        return True


def create_access_token(
    data: dict,
    *,
    settings: Optional[AuthSettings] = None,
    key_ring: Optional[KeyRing] = None,
    expires_delta: Optional[timedelta] = None,
    token_version: int = 0,
) -> str:
    """Encode a JWT access token.

    Args:
        data: Claims to encode (e.g. ``{"sub": user_id}``).
        settings: Auth settings; defaults to ``AuthSettings()`` (reads env vars).
        key_ring: Optional pre-configured KeyRing.  When provided, the active
            key from the ring is used instead of ``settings.SECRET_KEY``.
        expires_delta: Token lifetime.  Defaults to
            ``settings.ACCESS_TOKEN_EXPIRE_MINUTES``.
        token_version: Stamped as ``"tv"`` claim for token invalidation.
    """
    cfg = settings or AuthSettings()
    signing_key = key_ring.active_key if key_ring is not None else cfg.SECRET_KEY
    to_encode = dict(data)
    to_encode["tv"] = token_version
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=cfg.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    return _jwt.encode(to_encode, signing_key, algorithm=cfg.ALGORITHM)


def decode_access_token(
    token: str,
    *,
    settings: Optional[AuthSettings] = None,
    key_ring: Optional[KeyRing] = None,
) -> dict:
    """Decode and verify a JWT access token.

    When a ``KeyRing`` is provided, all keys in the ring are tried in order
    (active first, then previous within its grace window).  This allows tokens
    signed with a recently-rotated key to remain valid during the grace period.

    Raises:
        InvalidTokenError: If the token is malformed, expired, or cannot be
            verified by any available key.
    """
    cfg = settings or AuthSettings()
    keys = key_ring.verify_keys() if key_ring is not None else [cfg.SECRET_KEY]
    last_exc: Optional[Exception] = None
    for key in keys:
        try:
            return _jwt.decode(token, key, algorithms=[cfg.ALGORITHM])
        except JWTError as exc:
            last_exc = exc
    raise InvalidTokenError("Invalid or expired token") from last_exc
