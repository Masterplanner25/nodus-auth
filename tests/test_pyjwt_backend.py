"""The JWT backend is PyJWT, at a floor whose protections are checked here.

The floor is the point. PyJWT has 47 advisories to python-jose's 5 — the honest
reading of which is that it is heavily researched and fixes land, where
python-jose has a critical with `last_affected: 3.5.0` and no release above it.
That trade only holds while the floor stays high enough to exclude the fixed
ones, and `>=2.15.1` is not self-evidently high enough to a future reader
weighing a downgrade for some resolver conflict.

So each test below asserts a *behaviour* the floor buys rather than a version
string. Lower the floor past 2.14.0 and `test_the_library_also_refuses_der_bytes`
goes red; the version number alone would have stayed green.

See `test_hmac_key_guard.py` for the half of this PyJWT does **not** cover.
"""
from __future__ import annotations

import base64
import json
import pathlib
import sys
import warnings

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from nodus_auth import (
    AuthError,
    AuthSettings,
    InvalidTokenError,
    TokenCreationError,
    create_access_token,
    decode_access_token,
    generate_key,
)
from nodus_auth import jwt as nodus_jwt

REPO = pathlib.Path(__file__).resolve().parent.parent


# --- which library are we actually calling? ----------------------------------

def test_the_backend_is_pyjwt_not_this_module():
    """`nodus_auth/jwt.py` imports `jwt`, and resolves it to PyJWT.

    Python 3 resolves imports absolutely, so `import jwt` inside a module named
    `nodus_auth.jwt` gets the top-level package — correct, and worth pinning,
    because the day it stops being true the failure is bewildering: the module
    would import itself and every attribute lookup would fail on something that
    looks like it should exist.
    """
    assert nodus_jwt._jwt is pyjwt
    assert nodus_jwt._jwt is not nodus_jwt
    assert nodus_jwt._jwt.__name__ == "jwt"
    assert hasattr(nodus_jwt._jwt, "PyJWTError")


def test_python_jose_is_not_a_dependency():
    """The migration is not done while the old library is still declared.

    Checked against the file rather than the environment: a developer venv keeps
    python-jose installed long after nothing needs it, so `import jose`
    succeeding proves nothing about what a consumer gets.
    """
    deps = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    start = deps.index("dependencies = [")
    block = deps[start:deps.index("]", start)]
    # Comments stripped: the block carries a note explaining the swap, which
    # names the old library. The first run of this test failed on that note,
    # which is the right failure to have had -- it reads declarations now.
    declared = "\n".join(
        line for line in block.splitlines() if not line.strip().startswith("#")
    )
    assert "jose" not in declared.lower(), (
        "python-jose is still a declared dependency; the backend moved to PyJWT"
    )
    assert "PyJWT>=2.15.1" in declared, (
        "the floor must stay at 2.15.1 or above -- see this module's docstring"
    )


# --- what the floor buys, asserted as behaviour ------------------------------

@pytest.fixture(scope="module")
def der_public():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_the_library_also_refuses_der_bytes(der_public):
    """CVE-2026-102271, fixed in PyJWT 2.14.0.

    Our own guard would catch this first in real use, so this calls PyJWT
    directly — the question is whether the library underneath is one that
    refuses, which is what makes `>=2.14.0` part of the floor. Drop below it and
    this is the test that notices.
    """
    with pytest.raises(pyjwt.InvalidKeyError):
        pyjwt.encode({"sub": "attacker"}, der_public, algorithm="HS256")


def test_the_library_refuses_an_empty_hmac_secret():
    """An unset SECRET_KEY must not silently become a key everyone knows."""
    with pytest.raises(pyjwt.InvalidKeyError):
        pyjwt.encode({"sub": "x"}, "", algorithm="HS256")


def test_alg_none_is_refused_by_the_library_not_only_by_our_allowlist():
    """Defence in depth on the oldest JWT attack there is.

    `decode_access_token` passes `algorithms=[cfg.ALGORITHM]`, so an `alg: none`
    token is rejected as a disallowed algorithm — but that protection lives at
    one call site and would evaporate if someone widened the allowlist. PyJWT
    also refuses `none` with a key present, which is the part no call site can
    undo.
    """
    def seg(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    token = (seg(json.dumps({"alg": "none", "typ": "JWT"}).encode()) + "."
             + seg(json.dumps({"sub": "attacker"}).encode()) + ".")
    _, secret = generate_key()

    with pytest.raises(pyjwt.InvalidAlgorithmError):   # our allowlist
        pyjwt.decode(token, secret, algorithms=["HS256"])
    with pytest.raises(pyjwt.InvalidKeyError):         # and the library itself
        pyjwt.decode(token, secret, algorithms=["none"])


def test_the_default_dev_secret_is_long_enough_to_not_warn():
    """RFC 7518 §3.2: an HMAC key should be at least the hash output, 32 bytes.

    The default was 31 — one byte under — so PyJWT emitted
    `InsecureKeyLengthWarning` on every call in development. A warning that
    fires constantly on a value nobody is meant to keep trains people to ignore
    the warning, which is worse than not having it.
    """
    secret = AuthSettings().SECRET_KEY
    assert len(secret.encode("utf-8")) >= 32, "back under the RFC 7518 floor"

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        create_access_token({"sub": "alice"}, settings=AuthSettings())
    assert [w for w in caught if "InsecureKeyLength" in w.category.__name__] == []


def test_generate_key_is_long_enough_too():
    _, secret = generate_key()
    assert len(secret.encode("utf-8")) >= 32


# --- no library exception reaches a caller -----------------------------------

def test_an_unsupported_algorithm_raises_token_creation_error():
    """The most likely misconfiguration, and the one that escaped.

    PyJWT answers an unknown algorithm with `NotImplementedError`, which is
    **not** a `PyJWTError` — so an `except PyJWTError` clause reads as complete
    and lets exactly this case through. Found by running it.
    """
    cfg = AuthSettings(SECRET_KEY="x" * 40, ALGORITHM="NOPE256")
    with pytest.raises(TokenCreationError):
        create_access_token({"sub": "alice"}, settings=cfg)


def test_a_sign_failure_is_catchable_without_importing_the_backend():
    """What the wrapper is for: `AuthError` is the whole contract.

    A caller should never have to name a type from whichever JWT library is
    underneath — that is the coupling this migration had to break, having now
    changed the library once.
    """
    cfg = AuthSettings(SECRET_KEY="x" * 40, ALGORITHM="NOPE256")
    with pytest.raises(AuthError):
        create_access_token({"sub": "alice"}, settings=cfg)

    assert issubclass(TokenCreationError, AuthError)
    assert issubclass(InvalidTokenError, AuthError)
    assert not issubclass(TokenCreationError, InvalidTokenError), (
        "a token that cannot be signed is the server's fault, not a 401"
    )


def test_a_malformed_token_raises_invalid_token_error():
    cfg = AuthSettings(SECRET_KEY="x" * 40, ALGORITHM="HS256")
    for bad in ("", "not.a.token", "a.b.c", "x" * 200):
        with pytest.raises(InvalidTokenError):
            decode_access_token(bad, settings=cfg)


def test_no_pyjwt_exception_escapes_either_public_call():
    """The negative form of the two tests above, over both entry points.

    Written as a sweep because the sign path had no wrapper at all until this
    migration: the decode path wrapped its errors and the encode path did not,
    which is the one-of-two-paths shape in miniature.
    """
    cfg_bad_alg = AuthSettings(SECRET_KEY="x" * 40, ALGORITHM="NOPE256")
    cfg = AuthSettings(SECRET_KEY="x" * 40, ALGORITHM="HS256")

    for label, call in (
        ("encode, bad algorithm",
         lambda: create_access_token({"sub": "a"}, settings=cfg_bad_alg)),
        ("decode, bad algorithm",
         lambda: decode_access_token("a.b.c", settings=cfg_bad_alg)),
        ("decode, malformed", lambda: decode_access_token("nope", settings=cfg)),
        ("decode, wrong signature",
         lambda: decode_access_token(
             create_access_token({"sub": "a"}, settings=cfg),
             settings=AuthSettings(SECRET_KEY="y" * 40, ALGORITHM="HS256"))),
    ):
        try:
            call()
        except AuthError:
            pass
        except pyjwt.PyJWTError as exc:
            pytest.fail(f"{label}: PyJWT's {type(exc).__name__} reached the caller")
        except NotImplementedError:
            pytest.fail(f"{label}: PyJWT's NotImplementedError reached the caller")
        else:
            pytest.fail(f"{label}: expected a failure and got none")


# --- the round trip, so none of the above passes on a broken build -----------

def test_the_happy_path_still_works_on_pyjwt():
    _, secret = generate_key()
    cfg = AuthSettings(SECRET_KEY=secret, ALGORITHM="HS256")
    token = create_access_token({"sub": "alice"}, settings=cfg, token_version=3)
    claims = decode_access_token(token, settings=cfg)
    assert claims["sub"] == "alice"
    assert claims["tv"] == 3
    assert isinstance(token, str), "PyJWT returns str; python-jose did too"


def test_an_expired_token_is_an_invalid_token():
    from datetime import timedelta

    _, secret = generate_key()
    cfg = AuthSettings(SECRET_KEY=secret, ALGORITHM="HS256")
    token = create_access_token({"sub": "alice"}, settings=cfg,
                                expires_delta=timedelta(seconds=-30))
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings=cfg)


def test_an_asymmetric_algorithm_round_trips():
    """RS256 needs PyJWT's `crypto` extra; `cryptography` is present either way
    as a test dependency, so this is a real check that the extra's absence from
    our own install does not break the asymmetric path for someone who has it."""
    if "RS256" not in pyjwt.algorithms.get_default_algorithms():
        pytest.skip("cryptography not available to PyJWT")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    token = create_access_token(
        {"sub": "carol"}, settings=AuthSettings(SECRET_KEY=priv, ALGORITHM="RS256"))
    claims = decode_access_token(
        token, settings=AuthSettings(SECRET_KEY=pub, ALGORITHM="RS256"))
    assert claims["sub"] == "carol"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__, "-q"]))
