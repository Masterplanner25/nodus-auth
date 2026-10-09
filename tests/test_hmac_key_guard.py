"""An HMAC algorithm refuses asymmetric key material.

An HMAC algorithm uses whatever key it is handed as the shared secret, so a
**public** key makes every token forgeable by anyone holding it — which, for a
public key, is everyone. Both JWT libraries this package has used guarded
against that and both shipped a bypass of their own guard: python-jose missed
DER (CVE-2026-85394, no fixed release), and PyJWT had the identical DER bypass
(CVE-2026-102271) and fixed it in 2.14.0.

**The guard stays on PyJWT because PyJWT's fix does not cover the shape this
package has.** PyJWT inspects the key only as `bytes`; `AuthSettings.SECRET_KEY`
is a `str`, and the one lossless way DER reaches a `str` is latin-1, so what
PyJWT finally HMACs with is `key.encode("utf-8")` — no longer DER, and past its
check. Measured on 2.15.1:

    jwt.decode(forged, der)                   -> InvalidKeyError   (refused)
    jwt.decode(forged, der.decode("latin-1")) -> sub='attacker'    (ACCEPTED)

An attacker derives those same bytes from the public key exactly as
deterministically as the server does, so the str form is the reachable path —
and it is the only way DER gets into this package's configuration.

**The attack is forged by hand here, with `hmac`.** It used to be built by
asking python-jose to sign with a DER key, which it would. Neither library will
now, so borrowing one to build the attack would make this file assert a
library's willingness to help rather than our refusal to accept — and an
attacker does not use our dependencies. `test_the_forgery_helper_really_forges`
is the control that keeps the hand-rolled token honest.

**The false-positive tests matter more than the exploit test.** Refusing a
legitimate secret breaks a working deployment, which for almost every user is
worse than the CVE — and `0x30`, the DER SEQUENCE tag, is also ASCII `"0"`, so a
naive first-byte check would reject a secret beginning with that character. The
detector requires a self-consistent ASN.1 length covering the whole buffer, and
the adversarial cases below are what hold it to that.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from nodus_auth import (
    AuthSettings,
    InsecureKeyError,
    InvalidTokenError,
    KeyRing,
    create_access_token,
    decode_access_token,
    generate_key,
)
from nodus_auth.jwt import _looks_asymmetric


def _forge_hs256(claims: dict, key: bytes) -> str:
    """Mint an HS256 token with *key* as the HMAC secret, without a JWT library.

    Twelve lines of `hmac`, which is the point: no library has to agree to
    produce the attack for the attack to exist.
    """
    def seg(raw: bytes) -> bytes:
        return base64.urlsafe_b64encode(raw).rstrip(b"=")

    header = seg(json.dumps({"alg": "HS256", "typ": "JWT"},
                            separators=(",", ":")).encode())
    payload = seg(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = header + b"." + payload
    signature = seg(hmac.new(key, signing_input, hashlib.sha256).digest())
    return (signing_input + b"." + signature).decode()


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _pub(key, encoding, fmt):
    return key.public_key().public_bytes(encoding, fmt)


def _der_public(key):
    return _pub(key, serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)


# --- the exploit, closed -----------------------------------------------------

# closes: CVE-2026-85394
def test_a_der_public_key_is_refused_on_verify(rsa_key):
    """The reproduced forgery, with the key as `bytes`.

    PyJWT refuses this one too (`InvalidKeyError`, fixed in 2.14.0), so what the
    assertion pins is that *our* guard answers first and answers with something
    a caller cannot mistake for a bad token. Remove the guard and this raises
    `InvalidTokenError` instead — the key ring absorbs the library's error.
    """
    der = _der_public(rsa_key)
    forged = _forge_hs256({"sub": "attacker"}, der)
    with pytest.raises(InsecureKeyError):
        decode_access_token(forged, key_ring=KeyRing(active=der))


def test_a_der_public_key_as_a_str_is_refused_on_verify(rsa_key):
    """The reachable path, and the one PyJWT 2.15.1 still accepts.

    `SECRET_KEY` is a `str`, so DER arrives latin-1-decoded and PyJWT's check —
    which looks at `bytes` — never sees DER at all. Measured: without this guard
    the decode below returns `sub='attacker'`. This is the test that justifies
    keeping ~40 lines of guard after migrating to a maintained library.
    """
    key_str = _der_public(rsa_key).decode("latin-1")
    forged = _forge_hs256({"sub": "attacker"}, key_str.encode("utf-8"))
    with pytest.raises(InsecureKeyError):
        decode_access_token(forged, settings=AuthSettings(
            SECRET_KEY=key_str, ALGORITHM="HS256"))
    with pytest.raises(InsecureKeyError):
        decode_access_token(forged, key_ring=KeyRing(active=key_str))


def test_the_forgery_helper_really_forges():
    """Control for the exploit tests: `_forge_hs256` makes a *valid* token.

    Without it those tests pass on a helper that emits garbage — any refusal
    satisfies `pytest.raises`, including a refusal for being malformed, which
    would say nothing about the guard. Here the same helper and a legitimate
    secret produce a token the real decode path accepts.
    """
    _, secret = generate_key()
    token = _forge_hs256({"sub": "alice", "tv": 0}, secret.encode("utf-8"))
    cfg = AuthSettings(SECRET_KEY=secret, ALGORITHM="HS256")
    assert decode_access_token(token, settings=cfg)["sub"] == "alice"


def test_a_der_public_key_is_refused_on_sign(rsa_key):
    """Both sites that hand a key to the library, not just the exploitable one.

    Signing is not attacker-reachable, but refusing here turns the same
    misconfiguration into an error at setup rather than a silent forgery later.
    """
    cfg = AuthSettings(SECRET_KEY=_der_public(rsa_key).decode("latin-1"),
                       ALGORITHM="HS256")
    with pytest.raises(InsecureKeyError):
        create_access_token({"sub": "alice"}, settings=cfg)


def test_the_refusal_is_not_an_invalid_token(rsa_key):
    """It must not be absorbed as 'this key did not verify'.

    `decode_access_token` loops the key ring catching the library's error and
    raises `InvalidTokenError` at the end. A caller treats that as a 401 and
    carries on; a forgeable key ring has to stop the request instead.
    """
    der = _der_public(rsa_key)
    forged = _forge_hs256({"sub": "attacker"}, der)
    with pytest.raises(InsecureKeyError):
        decode_access_token(forged, key_ring=KeyRing(active=der, previous=der))

    # The hierarchy is the assertion, not the raise above. `pytest.raises(
    # InsecureKeyError)` passes just as happily if this becomes a *kind of*
    # `InvalidTokenError` -- and then a caller doing
    #
    #     except InvalidTokenError: return 401
    #
    # answers 401 to a forgeable key ring, which is the single thing this error
    # exists to prevent. Found by making that change and watching all 75 tests
    # stay green.
    assert not issubclass(InsecureKeyError, InvalidTokenError), (
        "InsecureKeyError must not be catchable as InvalidTokenError: a "
        "misconfiguration that makes every token forgeable cannot be absorbed "
        "by a caller's 401 path"
    )


@pytest.mark.parametrize("label", [
    "pub_der", "pub_pem", "pub_openssh", "priv_der", "priv_pem",
    "ed25519_pub_der", "key_object",
])
def test_every_asymmetric_encoding_is_detected(rsa_key, label):
    ed = ed25519.Ed25519PrivateKey.generate()
    keys = {
        "pub_der": _der_public(rsa_key),
        "pub_pem": _pub(rsa_key, serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo),
        "pub_openssh": _pub(rsa_key, serialization.Encoding.OpenSSH,
                            serialization.PublicFormat.OpenSSH),
        "priv_der": rsa_key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()),
        "priv_pem": rsa_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()),
        "ed25519_pub_der": ed.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo),
        "key_object": rsa_key.public_key(),
    }
    assert _looks_asymmetric(keys[label]), f"{label} slipped past the detector"


# --- and the half that protects working deployments --------------------------

@pytest.mark.parametrize("secret", [
    pytest.param(generate_key()[1], id="generate_key"),
    pytest.param(AuthSettings().SECRET_KEY, id="default_dev_secret"),
    pytest.param(secrets.token_urlsafe(32), id="token_urlsafe"),
    pytest.param(secrets.token_hex(32), id="token_hex"),
    pytest.param(os.urandom(32), id="raw_bytes"),
    pytest.param("s3cret", id="short"),
    pytest.param("x", id="one_char"),
    # 0x30 is the DER SEQUENCE tag and also ASCII "0": a first-byte check would
    # reject both of these, and both are legitimate secrets.
    pytest.param("0" + secrets.token_urlsafe(24), id="leading_zero_char"),
    pytest.param(bytes([0x30]) + os.urandom(31), id="leading_0x30_byte"),
    # A self-consistent-looking header whose declared length does NOT cover the
    # buffer: the case that makes the length check load-bearing.
    pytest.param(bytes([0x30, 29]) + os.urandom(30), id="der_header_wrong_length"),
])
def test_real_secrets_are_not_refused(secret):
    assert not _looks_asymmetric(secret), (
        "a legitimate secret was classified as asymmetric key material; this "
        "refuses a working deployment"
    )


def test_a_normal_hs256_round_trip_still_works():
    """The control. Without it the suite above passes on a build where every
    HS256 configuration is refused."""
    _, secret = generate_key()
    cfg = AuthSettings(SECRET_KEY=secret, ALGORITHM="HS256")
    token = create_access_token({"sub": "alice"}, settings=cfg)
    assert decode_access_token(token, settings=cfg)["sub"] == "alice"


def test_a_key_ring_round_trip_still_works():
    _, active = generate_key()
    _, previous = generate_key()
    ring = KeyRing(active=active, previous=previous)
    token = create_access_token({"sub": "bob"}, key_ring=ring)
    assert decode_access_token(token, key_ring=ring)["sub"] == "bob"


def test_an_asymmetric_algorithm_is_left_alone(rsa_key):
    """The guard is about HMAC only. RS256 with a keypair is the correct setup
    and must not be refused — the check keys off the algorithm, not the key."""
    pem_priv = rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    pem_pub = _pub(rsa_key, serialization.Encoding.PEM,
                   serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    cfg_sign = AuthSettings(SECRET_KEY=pem_priv, ALGORITHM="RS256")
    cfg_verify = AuthSettings(SECRET_KEY=pem_pub, ALGORITHM="RS256")
    token = create_access_token({"sub": "carol"}, settings=cfg_sign)
    assert decode_access_token(token, settings=cfg_verify)["sub"] == "carol"
