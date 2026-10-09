"""JWT token creation, decoding, and key rotation."""
from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

# `jwt` here is PyJWT, not this module: Python 3 resolves imports absolutely, so
# a module named `nodus_auth.jwt` importing `jwt` gets the top-level package.
# Pinned by `test_pyjwt_backend.py::test_the_backend_is_pyjwt_not_this_module`,
# because the day that stops being true the failure is a bewildering one.
import jwt as _jwt
from jwt import PyJWTError

from .config import AuthSettings


class AuthError(Exception):
    """Base for every error this package raises.

    Added with the move off python-jose (#1). Before it, a caller had to catch
    `InvalidTokenError` *and* whatever the JWT library happened to raise from the
    signing path, which meant importing that library to name its exceptions —
    coupling the caller to a dependency this package has now changed once and
    may change again.
    """


class InvalidTokenError(AuthError):
    """Raised when a JWT cannot be decoded, is expired, or fails verification."""


class TokenCreationError(AuthError):
    """Raised when a token cannot be signed — almost always a misconfiguration.

    Separate from `InvalidTokenError` because the two call for opposite
    responses: an invalid token is a 401 for the caller, while a token that
    cannot be *created* is the server's own setup being wrong, and answering 401
    to it would blame the client for an operator's mistake.
    """


class InsecureKeyError(AuthError):
    """Raised when asymmetric key material is supplied for an HMAC algorithm.

    Deliberately **not** an `InvalidTokenError`. A caller treats an invalid token
    as a 401 and carries on; this is a misconfiguration that makes every token
    forgeable, so it has to be loud — and it must not be swallowed by the
    key-ring loop in `decode_access_token`, which catches the library's error.
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

    Structural, because `cryptography` is an *extra* of the JWT library rather
    than a dependency of it — true of PyJWT as it was of python-jose — so it
    cannot be imported here. A guard that needs an optional dependency is a
    guard that is absent exactly where someone installed the lean set.

    That is not a hypothetical: it is precisely how PyJWT's own DER check fails.
    `HMACAlgorithm._is_der_key` opens with `if not has_crypto: return False`, so
    on an install without the extra it refuses nothing.
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
    """Refuse asymmetric key material under an HMAC algorithm.

    An HMAC algorithm uses whatever key it is handed as the shared secret. Hand
    it a **public** key and every token becomes forgeable by anyone holding that
    key, which is everyone. Both JWT libraries this package has used shipped a
    guard against it and both shipped a bypass of their own guard:

    - python-jose 3.4.0 guarded PEM and OpenSSH and **missed DER** —
      CVE-2026-85394, `last_affected: 3.5.0`, **no fixed release**.
    - PyJWT had the identical DER bypass (CVE-2026-102271) and fixed it in
      2.14.0, which is part of why `>=2.15.1` is the floor.

    **The guard stays because PyJWT's fix does not reach this package.** Two
    independent reasons, both measured on PyJWT 2.15.1 rather than inferred:

    - **A `str` key is not checked.** `prepare_key` calls `force_bytes`, which
      is `key.encode("utf-8")` for a `str`. `AuthSettings.SECRET_KEY` is
      annotated `str`, and the one lossless way DER reaches a `str` is latin-1,
      so what PyJWT finally HMACs with is `key.encode("utf-8")` — no longer
      parseable as DER, and past its check. An attacker derives those same bytes
      from the *public* key as deterministically as the server does. PEM and
      OpenSSH survive this path only because they are ASCII, so the re-encoding
      is a no-op; DER is the one encoding it destroys.
    - **Without the `crypto` extra the DER check does not exist.**
      `_is_der_key` opens with `if not has_crypto: return False`, and
      `cryptography` is an extra of PyJWT, so a plain `pip install PyJWT`
      accepts DER *bytes* too. We do not require that extra.

    A `str` is the only way DER gets into this package's configuration, so on
    its own the upstream fix would leave the whole reachable path open.

    Called from **both** sites that hand a key to the library, sign and verify,
    because "a correct check on one of two paths" is the shape this ecosystem
    keeps re-learning. The signing side is not attacker-reachable, but refusing
    there turns the same misconfiguration into an error at setup rather than a
    silent forgery later.
    """
    if algorithm in _HMAC_ALGORITHMS and _looks_asymmetric(key):
        raise InsecureKeyError(
            f"{algorithm} is an HMAC algorithm and needs a shared secret, but the "
            f"key supplied is asymmetric key material (RSA/EC/Ed25519). It would "
            f"be used as the HMAC secret, and a public key is public, so every "
            f"token would be forgeable (CVE-2026-85394 in python-jose, "
            f"CVE-2026-102271 in PyJWT). Use a random secret for HS* — see "
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
    try:
        return _jwt.encode(to_encode, signing_key, algorithm=cfg.ALGORITHM)
    except (PyJWTError, NotImplementedError) as exc:
        # The signing path used to let the library's own exception through, so a
        # caller wanting to handle it had to name a type from a dependency this
        # package has now changed once. Wrapping it is what makes the backend an
        # implementation detail rather than part of the contract.
        #
        # `NotImplementedError` is in the tuple because it is what PyJWT raises
        # for an unsupported ALGORITHM -- the single most likely misconfiguration
        # here -- and it is **not** a `PyJWTError`. Caught by running it; a
        # `PyJWTError`-only clause reads as complete and misses the main case.
        #
        # A `TypeError` from an unserializable claim is deliberately left to
        # propagate: that is the caller's payload, not the server's setup, and
        # reporting it as a creation failure would send an operator to inspect a
        # configuration that is fine.
        raise TokenCreationError(
            f"Could not sign a token with algorithm {cfg.ALGORITHM!r}: {exc}"
        ) from exc


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
        except PyJWTError as exc:
            last_exc = exc
    raise InvalidTokenError("Invalid or expired token") from last_exc
