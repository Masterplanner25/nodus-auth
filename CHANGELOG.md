# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security

- **An HMAC algorithm now refuses asymmetric key material
  (`InsecureKeyError`).** python-jose uses whatever key it is handed as the HMAC
  secret. Its 3.4.0 guard — added for CVE-2024-33663 — rejects PEM and OpenSSH
  public keys used that way and **misses DER**. That bypass is
  **CVE-2026-85394 / GHSA-3qf3-8w2g-rqmx (CRITICAL)**, recorded with
  `last_affected: 3.5.0` and **no fixed release**; 3.5.0 is the newest python-jose
  on PyPI, so there is nowhere to upgrade to.

  Reproduced against python-jose 3.5.0 before this change — a DER-encoded RSA
  **public** key used as an `HS256` secret was accepted on both sign and verify,
  and through this package:

  ```
  decode_access_token(forged, key_ring=KeyRing(active=der_public_key))
    -> sub='attacker'
  ```

  A public key is public, so under that configuration anyone could mint a token
  for any subject. `nodus-auth` now performs the check python-jose cannot be
  relied on for, at **both** sites that hand a key to jose.

  **The default configuration was never affected.** `ALGORITHM` defaults to
  `HS256` with a shared secret, `generate_key()` produces random symmetric
  secrets, and every decode already passed an explicit single-algorithm
  allowlist (`algorithms=[ALGORITHM]`) — so `alg: none` and algorithm
  *substitution* were already rejected, verified by test. The reachable path was
  a deployer supplying asymmetric key material as the verification key, which
  `KeyRing(active=...)` accepted because its `str` annotation is not enforced.

  `InsecureKeyError` is deliberately **not** an `InvalidTokenError`: a caller
  treats an invalid token as a 401 and carries on, and this is a
  misconfiguration that makes every token forgeable, so it must not be absorbed
  by the key-ring loop.

  An asymmetric algorithm with a keypair (`RS256` and a PEM) is the correct
  setup and is untouched — the check keys off the algorithm, not the key.

- **`pydantic-settings` floor raised to `>=2.14.2`** for **CVE-2026-58203 /
  GHSA-4xgf-cpjx-pc3j (MODERATE)**: `NestedSecretsSettingsSource` followed
  symlinks out of `secrets_dir`, allowing a local file read and bypassing
  `secrets_dir_max_size` (introduced 2.12.0, fixed 2.14.2). Not reachable through
  `AuthSettings`, which declares no `secrets_dir` — but the old `>=2.0.0` floor
  admitted an affected version into a consumer's tree, and **2.14.1 was what this
  checkout had installed**, so the exposure was real rather than theoretical.

  The other four python-jose advisories (CVE-2024-33663, CVE-2024-33664,
  CVE-2024-29370, CVE-2016-7036) are all excluded by the existing `>=3.5.0`
  floor; each was fixed in 3.4.0 or earlier.

### Added

- `InsecureKeyError`, exported from the package root.
- `tests/test_hmac_key_guard.py` — 23 tests. The **false-positive** half is the
  larger one: `0x30` is the DER SEQUENCE tag and also ASCII `"0"`, so a
  first-byte check would refuse a secret beginning with that character, and
  refusing a legitimate secret breaks a working deployment. The detector
  requires a self-consistent ASN.1 length covering the whole buffer, and those
  tests are what hold it there — verified by neutering the check to its naive
  form, which fails exactly them.


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
