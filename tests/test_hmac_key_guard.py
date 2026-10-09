"""An HMAC algorithm refuses asymmetric key material (CVE-2026-85394).

python-jose uses whatever key it is given as the HMAC secret. Its 3.4.0 guard
(for CVE-2024-33663) rejects PEM and OpenSSH public keys used that way and
**misses DER** — CVE-2026-85394, `last_affected: 3.5.0`, **no fixed release**,
3.5.0 being the newest. A public key is public, so under that configuration
anyone can mint a token for any subject.

Reproduced on python-jose 3.5.0 before the guard existed:

    jwt.decode(forged, der_public_key, algorithms=["HS256"])  -> accepted
    decode_access_token(forged, key_ring=KeyRing(active=der)) -> sub='attacker'

So this package does the check python-jose cannot be relied on for.

**The false-positive tests matter more than the exploit test.** Refusing a
legitimate secret breaks a working deployment, which for almost every user is
worse than the CVE — and `0x30`, the DER SEQUENCE tag, is also ASCII `"0"`, so a
naive first-byte check would reject a secret beginning with that character. The
detector requires a self-consistent ASN.1 length covering the whole buffer, and
the adversarial cases below are what hold it to that.
"""
from __future__ import annotations

import os
import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from jose import jwt as jose_jwt

from nodus_auth import (
    AuthSettings,
    InsecureKeyError,
    KeyRing,
    create_access_token,
    decode_access_token,
    generate_key,
)
from nodus_auth.jwt import _looks_asymmetric


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
    """The reproduced forgery. Without the guard this returns sub='attacker'."""
    der = _der_public(rsa_key)
    forged = jose_jwt.encode({"sub": "attacker"}, der, algorithm="HS256")
    with pytest.raises(InsecureKeyError):
        decode_access_token(forged, key_ring=KeyRing(active=der))


def test_a_der_public_key_is_refused_on_sign(rsa_key):
    """Both sites that hand a key to jose, not just the exploitable one.

    Signing is not attacker-reachable, but refusing here turns the same
    misconfiguration into an error at setup rather than a silent forgery later.
    """
    cfg = AuthSettings(SECRET_KEY=_der_public(rsa_key).decode("latin-1"),
                       ALGORITHM="HS256")
    with pytest.raises(InsecureKeyError):
        create_access_token({"sub": "alice"}, settings=cfg)


def test_the_refusal_is_not_an_invalid_token(rsa_key):
    """It must not be absorbed as 'this key did not verify'.

    `decode_access_token` loops the key ring catching `JWTError` and raises
    `InvalidTokenError` at the end. A caller treats that as a 401 and carries on;
    a forgeable key ring has to stop the request instead.
    """
    der = _der_public(rsa_key)
    forged = jose_jwt.encode({"sub": "attacker"}, der, algorithm="HS256")
    with pytest.raises(InsecureKeyError):
        decode_access_token(forged, key_ring=KeyRing(active=der, previous=der))


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
