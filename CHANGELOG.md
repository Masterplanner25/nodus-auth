# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.1.0] — 2026-05-30

Initial release.

### Added

- **KeyRing** — two-slot signing key ring with grace-period rotation.
  `active` key + optional `previous` key valid for `grace_hours`.
  `rotate(new_key)` promotes active to previous.

- **`create_access_token(payload, settings, key_ring?)`** — encode a JWT
  with configurable expiry. Uses `python-jose` with HS256 (default).

- **`decode_access_token(token, settings, key_ring?)`** — decode and verify.
  Tries active key first, then previous key within grace window.
  Raises `InvalidTokenError` on malformed, expired, or wrong-key tokens.

- **`hash_password(plain)` / `verify_password(plain, hashed)`** — bcrypt
  via `passlib.context.CryptContext`. bcrypt pinned `<5.0` due to
  passlib 1.7.4 incompatibility with bcrypt 5.x.

- **`generate_key()`** — returns `(raw_key, key_hash)` pair.
  Raw key via `secrets.token_urlsafe`; hash via SHA-256.

- **`hash_key(raw_key)`** — SHA-256 hex digest for database storage.

- **`AuthPrincipal`** — resolved identity with `user_id`, `auth_type`
  (`"jwt"` or `"api_key"`), `scopes` list, and `has_scope(scope)`.

- **`Scopes`** — well-known constants: `MEMORY_READ`, `MEMORY_WRITE`,
  `FLOW_EXECUTE`, `FLOW_CREATE`, `PLATFORM_ADMIN`.

- **`LoginRequest` / `RegisterRequest` / `TokenResponse`** — Pydantic v2
  request/response schemas.

- **`AuthSettings`** — pydantic-settings v2 config. Reads `SECRET_KEY`,
  `ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES` from environment.

- **`parse_user_id` / `require_user_id` / `parse_user_ids`** — UUID parsing
  helpers with None-safe and batch variants.

- **36 tests** across four test files (jwt, keys, password, schemas).

- **Dependencies:** `python-jose>=3.5.0`, `passlib>=1.7.4`,
  `bcrypt>=4.0.1,<5.0`, `pydantic>=2.0.0`, `pydantic-settings>=2.0.0`.

[0.1.0]: https://github.com/Masterplanner25/nodus-auth/releases/tag/v0.1.0
