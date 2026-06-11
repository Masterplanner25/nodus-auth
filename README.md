# nodus-auth

**JWT issuance/validation, API key hashing, bcrypt passwords, and scoped
principals for AI-native platforms.**

Standalone auth primitives — no FastAPI required. All core functions work
with any Python web framework or no framework at all.

> **Status:** v0.1.0 — published on [PyPI](https://pypi.org/project/nodus-auth/).

---

## Install

```bash
pip install nodus-auth
```

> **bcrypt version note:** This package pins `bcrypt>=4.0.1,<5.0` because
> `passlib 1.7.4` is incompatible with bcrypt 5.x. Do not upgrade bcrypt
> beyond 4.x in the same environment.

---

## What it provides

| Component | Purpose |
|---|---|
| `KeyRing` / `create_access_token` / `decode_access_token` | JWT issuance and verification with key rotation |
| `hash_password` / `verify_password` | bcrypt password hashing via passlib |
| `generate_key` / `hash_key` | API key generation and SHA-256 storage hash |
| `AuthPrincipal` / `Scopes` | Resolved identity with scope-based access control |
| `LoginRequest` / `RegisterRequest` / `TokenResponse` | Pydantic request/response schemas |
| `parse_user_id` / `require_user_id` | UUID parsing helpers |
| `AuthSettings` | pydantic-settings config for SECRET_KEY, ALGORITHM, expiry |

---

## JWT tokens

```python
from nodus_auth import AuthSettings, create_access_token, decode_access_token, InvalidTokenError

settings = AuthSettings(SECRET_KEY="my-secret-key-32-chars-minimum")
token = create_access_token({"sub": "user-123"}, settings=settings)

try:
    payload = decode_access_token(token, settings=settings)
    user_id = payload["sub"]
except InvalidTokenError:
    # expired, malformed, or wrong key
    ...
```

### Key rotation

```python
from nodus_auth import KeyRing, create_access_token, decode_access_token, AuthSettings

ring = KeyRing(active="key-v1", grace_hours=24)
settings = AuthSettings(SECRET_KEY="key-v1")
token = create_access_token({"sub": "u1"}, settings=settings, key_ring=ring)

ring.rotate("key-v2")  # tokens signed with key-v1 still verify for 24 hours
payload = decode_access_token(token, settings=settings, key_ring=ring)  # OK
```

`decode_access_token` tries the active key first, then any keys within their
grace period. Tokens outside their grace window raise `InvalidTokenError`.

---

## Passwords

```python
from nodus_auth import hash_password, verify_password

hashed = hash_password("correct-horse-battery-staple")
assert verify_password("correct-horse-battery-staple", hashed)
assert not verify_password("wrong-password", hashed)
```

---

## API keys

```python
from nodus_auth import generate_key, hash_key

raw_key, key_hash = generate_key()
# Deliver raw_key to the caller once; store key_hash in the database
assert hash_key(raw_key) == key_hash
```

`generate_key()` uses `secrets.token_urlsafe`. The raw key is never stored;
the SHA-256 hash is used for all comparisons.

---

## Scoped principals

```python
from nodus_auth import AuthPrincipal, Scopes

principal = AuthPrincipal(
    user_id="user-123",
    auth_type="api_key",
    scopes=[Scopes.MEMORY_READ, Scopes.FLOW_EXECUTE],
)
assert principal.has_scope(Scopes.FLOW_EXECUTE)
assert not principal.has_scope(Scopes.PLATFORM_ADMIN)
```

`auth_type` is `"jwt"` or `"api_key"`. `Scopes` provides well-known constants:
`MEMORY_READ`, `MEMORY_WRITE`, `FLOW_EXECUTE`, `FLOW_CREATE`, `PLATFORM_ADMIN`.

---

## AuthSettings

```python
from nodus_auth import AuthSettings

# Reads from environment variables: SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
settings = AuthSettings()

# Or explicit:
settings = AuthSettings(
    SECRET_KEY="...",
    ALGORITHM="HS256",
    ACCESS_TOKEN_EXPIRE_MINUTES=60,
)
```

---

## User ID helpers

```python
from nodus_auth import parse_user_id, require_user_id, parse_user_ids
import uuid

parse_user_id("550e8400-e29b-41d4-a716-446655440000")  # → UUID
parse_user_id(None)                                     # → None
require_user_id("not-a-uuid")                           # raises ValueError
parse_user_ids(["uid-1", "bad", "uid-2"])              # → [UUID, UUID]  (skips failures)
```

---

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `python-jose` | ≥3.5.0 | JWT encoding/decoding |
| `passlib` | ≥1.7.4 | bcrypt password context |
| `bcrypt` | ≥4.0.1,<5.0 | bcrypt backend (passlib 1.7.4 incompatible with 5.x) |
| `pydantic` | ≥2.0.0 | Schemas |
| `pydantic-settings` | ≥2.0.0 | `AuthSettings` from env vars |

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

---

## License

MIT — see [LICENSE](LICENSE).
