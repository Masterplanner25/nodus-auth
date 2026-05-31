from __future__ import annotations

import time
from datetime import timedelta

import pytest

from nodus_auth import (
    AuthSettings,
    InvalidTokenError,
    KeyRing,
    create_access_token,
    decode_access_token,
)


@pytest.fixture
def settings():
    return AuthSettings(SECRET_KEY="test-secret-key")


# ── create / decode round-trip ────────────────────────────────────────────────

def test_round_trip(settings):
    token = create_access_token({"sub": "user-1"}, settings=settings)
    payload = decode_access_token(token, settings=settings)
    assert payload["sub"] == "user-1"


def test_token_version_in_claims(settings):
    token = create_access_token({"sub": "u1"}, settings=settings, token_version=7)
    payload = decode_access_token(token, settings=settings)
    assert payload["tv"] == 7


def test_expired_token_raises(settings):
    token = create_access_token(
        {"sub": "u1"}, settings=settings, expires_delta=timedelta(seconds=-1)
    )
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings=settings)


def test_wrong_key_raises(settings):
    token = create_access_token({"sub": "u1"}, settings=settings)
    wrong = AuthSettings(SECRET_KEY="completely-different-key")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings=wrong)


def test_malformed_token_raises(settings):
    with pytest.raises(InvalidTokenError):
        decode_access_token("not.a.jwt", settings=settings)


# ── KeyRing rotation ──────────────────────────────────────────────────────────

def test_key_ring_round_trip(settings):
    ring = KeyRing(active=settings.SECRET_KEY)
    token = create_access_token({"sub": "u1"}, settings=settings, key_ring=ring)
    payload = decode_access_token(token, settings=settings, key_ring=ring)
    assert payload["sub"] == "u1"


def test_key_ring_grace_period(settings):
    ring = KeyRing(active=settings.SECRET_KEY, grace_hours=1)
    # Mint token with old key
    token = create_access_token({"sub": "u1"}, settings=settings, key_ring=ring)
    # Rotate to new key
    ring.rotate("new-secret-key")
    # Token signed with old key still verifiable during grace period
    payload = decode_access_token(token, settings=settings, key_ring=ring)
    assert payload["sub"] == "u1"


def test_key_ring_expired_previous_key_rejected():
    ring = KeyRing(active="key-A", grace_hours=0)
    cfg = AuthSettings(SECRET_KEY="key-A")
    token = create_access_token({"sub": "u1"}, settings=cfg, key_ring=ring)
    ring.rotate("key-B")
    # grace_hours=0 means previous expires immediately; wait for it
    time.sleep(0.01)
    cfg_b = AuthSettings(SECRET_KEY="key-B")
    with pytest.raises(InvalidTokenError):
        decode_access_token(token, settings=cfg_b, key_ring=ring)


def test_key_ring_active_key_property(settings):
    ring = KeyRing(active=settings.SECRET_KEY)
    assert ring.active_key == settings.SECRET_KEY
    ring.rotate("new-key")
    assert ring.active_key == "new-key"


def test_key_ring_rotate_noop_on_same_key(settings):
    ring = KeyRing(active=settings.SECRET_KEY)
    ring.rotate(settings.SECRET_KEY)
    assert ring.active_key == settings.SECRET_KEY
    assert ring._previous is None
