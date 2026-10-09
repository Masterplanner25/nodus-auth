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


class InsecureKeyError(Exception):
    """Raised when asymmetric key material is supplied for an HMAC algorithm.

    Deliberately **not** an `InvalidTokenError`. A caller treats an invalid token
    as a 401 and carries on; this is a misconfiguration that makes every token
    forgeable, so it has to be loud — and it must not be swallowed by the
    key-ring loop in `decode_access_token`, which catches `JWTError`.
    """


#: HMAC algorithms, where the "key" is a shared secret rather than a keypair.
_HMAC_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})

_PEM_MARKER = b"-----BEGIN"
_OPENSSH_PREFIXES = (b"ssh-rsa", b"ssh-ed25519", b"ssh-dss", b"ecdsa-sha2-")


def _is_der_sequence(raw: bytes) -> bool:
    """Does *raw* look like a complete DER SEQUENCE — so, ASN.1 key material?

    Checked structurally rather than by first byte alone. `0x30` is also ASCII
    `"0"`, so a secret beginning with that character would false-positive — and a
    false positive here refuses a legitimate deployment, which for most users is
    worse than the CVE being guarded. Requiring the declared length to account
    for exactly the whole buffer is what makes it safe: a random secret
    essentially never carries a self-consistent DER header over its own length.
    """
    if len(raw) < 2 or raw[0] != 0x30:
        return False
    length_byte = raw[1]
    if length_byte < 0x80:                        # short form
        return 2 + length_byte == len(raw)
    count = length_byte & 0x7F
    if count == 0 or count > 4 or len(raw) < 2 + count:
        return False                             # 0x80 is indefinite: not DER
    declared = int.from_bytes(raw[2:2 + count], "big")
    return 2 + count + declared == len(raw)


def _looks_asymmetric(key: object) -> bool:
    """Is *key* an RSA/EC/Ed25519 key rather than a shared secret?

    Structural, because `cryptography` is only an *extra* of python-jose and so
    cannot be imported here — a guard that needs an optional dependency is a
    guard that is absent exactly where someone installed the lean set.
    """
    if hasattr(key, "public_bytes") or hasattr(key, "private_bytes"):
        return True                              # a `cryptography` key object
    if isinstance(key, str):
        # BOTH encodings, because a DER key that reached a `str` field -- which
        # is what `AuthSettings.SECRET_KEY` is -- was almost certainly decoded as
        # latin-1, the only lossless byte-to-str mapping. Re-encoding it as UTF-8
        # changes every byte above 0x7F and destroys the ASN.1 length, so a
        # utf-8-only check misses exactly the case that gets DER into config.
        # Found by the signing test failing, not by reading this.
        candidates = [key.encode("utf-8", errors="surrogateescape")]
        try:
            candidates.append(key.encode("latin-1"))
        except UnicodeEncodeError:
            pass                                 # not byte-for-byte text
    elif isinstance(key, (bytes, bytearray)):
        candidates = [bytes(key)]
    else:
        return False                             # a dict JWK, an int, …
    for raw in candidates:
        head = raw.lstrip()
        if (
            head.startswith(_PEM_MARKER)
            or head.startswith(_OPENSSH_PREFIXES)
            or _is_der_sequence(raw)
        ):
            return True
    return False


def _require_secret_for_hmac(key: object, algorithm: str) -> None:
    """Refuse asymmetric key material under an HMAC algorithm (CVE-2026-85394).

    **python-jose does not do this reliably, and no release does.** Its 3.4.0
    guard (for CVE-2024-33663) rejects PEM and OpenSSH public keys used as HMAC
    secrets and **misses DER**, which CVE-2026-85394 records as a bypass with
    `last_affected: 3.5.0` and no fixed version — 3.5.0 being the newest release.

    Reproduced on 3.5.0: signing *and* verifying `HS256` with a DER-encoded RSA
    **public** key is accepted, so anyone holding the public key — which is
    public — can mint a token for any subject.

    Called from **both** sites that hand a key to jose, sign and verify, because
    "a correct check on one of two paths" is the shape this ecosystem keeps
    re-learning. The signing side is not attacker-reachable, but refusing there
    turns the same misconfiguration into an error at setup rather than a silent
    forgery later.
    """
    if algorithm in _HMAC_ALGORITHMS and _looks_asymmetric(key):
        raise InsecureKeyError(
            f"{algorithm} is an HMAC algorithm and needs a shared secret, but the "
            f"key supplied is asymmetric key material (RSA/EC/Ed25519). "
            f"python-jose would use it as the HMAC secret, and a public key is "
            f"public, so every token would be forgeable (CVE-2026-85394, which "
            f"has no fixed release). Use a random secret for HS* — see "
            f"generate_key() — or an asymmetric algorithm such as RS256 for a "
            f"keypair."
        )


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
    _require_secret_for_hmac(signing_key, cfg.ALGORITHM)
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
        # Before the try, not inside it: an `InsecureKeyError` must not be
        # mistaken for "this key did not verify the token" and absorbed into the
        # next iteration. A forgeable key ring has to stop the request.
        _require_secret_for_hmac(key, cfg.ALGORITHM)
        try:
            return _jwt.decode(token, key, algorithms=[cfg.ALGORITHM])
        except JWTError as exc:
            last_exc = exc
    raise InvalidTokenError("Invalid or expired token") from last_exc
