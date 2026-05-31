import uuid

import pytest

from nodus_auth import (
    AuthPrincipal,
    LoginRequest,
    RegisterRequest,
    Scopes,
    TokenResponse,
    parse_user_id,
    parse_user_ids,
    require_user_id,
)


# ── Pydantic schemas ──────────────────────────────────────────────────────────

def test_login_request():
    req = LoginRequest(email="a@b.com", password="pw")
    assert req.email == "a@b.com"


def test_register_request_optional_username():
    req = RegisterRequest(email="a@b.com", password="pw")
    assert req.username is None


def test_token_response_default_type():
    r = TokenResponse(access_token="tok")
    assert r.token_type == "bearer"


# ── Scopes ────────────────────────────────────────────────────────────────────

def test_scopes_all_contains_all_constants():
    assert Scopes.PLATFORM_ADMIN in Scopes.ALL
    assert Scopes.FLOW_EXECUTE in Scopes.ALL
    assert len(Scopes.ALL) == 7


# ── AuthPrincipal ─────────────────────────────────────────────────────────────

def test_jwt_principal_has_all_scopes():
    p = AuthPrincipal(user_id="u1", auth_type="jwt")
    assert p.has_scope(Scopes.FLOW_READ) is True
    assert p.has_scope("anything") is True


def test_api_key_principal_scope_check():
    p = AuthPrincipal(user_id="u1", auth_type="api_key", scopes=[Scopes.MEMORY_READ])
    assert p.has_scope(Scopes.MEMORY_READ) is True
    assert p.has_scope(Scopes.FLOW_EXECUTE) is False


def test_api_key_with_platform_admin_has_all_scopes():
    p = AuthPrincipal(user_id="u1", auth_type="api_key", scopes=[Scopes.PLATFORM_ADMIN])
    assert p.has_scope(Scopes.FLOW_EXECUTE) is True
    assert p.has_scope(Scopes.MEMORY_WRITE) is True


# ── user_ids ──────────────────────────────────────────────────────────────────

def test_parse_user_id_from_string():
    uid = uuid.uuid4()
    assert parse_user_id(str(uid)) == uid


def test_parse_user_id_from_uuid():
    uid = uuid.uuid4()
    assert parse_user_id(uid) is uid


def test_parse_user_id_none():
    assert parse_user_id(None) is None


def test_parse_user_id_empty():
    assert parse_user_id("") is None


def test_parse_user_id_invalid():
    assert parse_user_id("not-a-uuid") is None


def test_require_user_id_raises_on_invalid():
    with pytest.raises(ValueError):
        require_user_id("bad")


def test_parse_user_ids_skips_invalid():
    uid = uuid.uuid4()
    result = parse_user_ids([str(uid), "bad", None, uid])
    assert result == [uid, uid]
