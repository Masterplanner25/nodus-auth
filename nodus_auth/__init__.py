"""nodus-auth — JWT, API key auth, bcrypt, scoped principals.

Core JWT:
    KeyRing              — two-slot signing key ring with rotation support
    create_access_token  — encode a JWT with configurable expiry
    decode_access_token  — decode + verify a JWT (tries all keys in ring)

Errors (all subclasses of AuthError, so one except clause catches the package):
    AuthError            — base; catch this rather than the JWT library's types
    InvalidTokenError    — raised on malformed / expired tokens (a 401)
    TokenCreationError   — raised when a token cannot be signed (a 500)
    InsecureKeyError     — raised when an HMAC algorithm is given an asymmetric key

Password:
    hash_password        — bcrypt hash via passlib
    verify_password      — bcrypt verify

API key utilities:
    hash_key             — SHA-256 hex digest of a raw key
    generate_key         — generate (raw_key, key_hash) pair

Schemas:
    LoginRequest         — Pydantic model
    RegisterRequest      — Pydantic model
    TokenResponse        — Pydantic model
    AuthPrincipal        — resolved identity (jwt or api_key)
    Scopes               — well-known scope string constants

Utilities:
    parse_user_id        — parse str/UUID/None → UUID | None
    require_user_id      — parse, raise ValueError on failure
    parse_user_ids       — batch parse, skip failures

Config:
    AuthSettings         — pydantic-settings for SECRET_KEY, ALGORITHM, expiry
"""
from .config import AuthSettings
from .jwt import (
    AuthError,
    InsecureKeyError,
    InvalidTokenError,
    KeyRing,
    TokenCreationError,
    create_access_token,
    decode_access_token,
)
from .keys import generate_key, hash_key
from .password import hash_password, verify_password
from .schemas import AuthPrincipal, LoginRequest, RegisterRequest, Scopes, TokenResponse
from .user_ids import parse_user_id, parse_user_ids, require_user_id

__all__ = [
    # Config
    "AuthSettings",
    # JWT
    "AuthError",
    "InsecureKeyError",
    "InvalidTokenError",
    "KeyRing",
    "TokenCreationError",
    "create_access_token",
    "decode_access_token",
    # Keys
    "generate_key",
    "hash_key",
    # Password
    "hash_password",
    "verify_password",
    # Schemas
    "AuthPrincipal",
    "LoginRequest",
    "RegisterRequest",
    "Scopes",
    "TokenResponse",
    # User IDs
    "parse_user_id",
    "parse_user_ids",
    "require_user_id",
]
