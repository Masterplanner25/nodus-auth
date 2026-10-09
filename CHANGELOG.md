# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Docs

- **Corrected why the HMAC key guard is not redundant with PyJWT's.** 0.2.0 said
  PyJWT "inspects the key only when it is `bytes`", which is true and
  incomplete: `_is_der_key` opens with `if not has_crypto: return False`, and
  `cryptography` is an *extra* of PyJWT, so on a plain `pip install PyJWT` the
  DER branch of its guard never runs for any key type.

  No behaviour change — the guard here is structural and crypto-free, so it
  already covered both cases. Found while writing the upstream report, which is
  the argument for writing one: the explanation had to be good enough for the
  maintainers of the library it was about.

  `tests/test_pyjwt_backend.py::test_the_guard_does_not_need_cryptography` pins
  the property that makes it cover the second case.

---

## [0.2.0] — 2026-10-08

The JWT backend moved from `python-jose` to `PyJWT`, and an HMAC algorithm now
refuses asymmetric key material. Both halves are about one attack, and the
second is why the first is not enough on its own.

### Changed

- **The JWT backend is now `PyJWT>=2.15.1`; `python-jose` is gone.**

  `python-jose` carries **CVE-2026-85394 / GHSA-3qf3-8w2g-rqmx (CRITICAL)** with
  `last_affected: 3.5.0` and **no fixed release** — 3.5.0 being its newest
  release and its last, 2025-05-28. There was nowhere to upgrade to.

  The argument for PyJWT is not that it is safer by design. **It shipped the
  identical bug** — CVE-2026-102271, a DER-encoded public key accepted as an
  HMAC secret, bypassing its own CVE-2022-29217 guard — and **fixed it in
  2.14.0.** Same class of mistake; one project shipped the fix.

  The honest counterweight: PyJWT has far more advisories than python-jose, most
  of the recent ones in `PyJWKClient` / JWK-set handling — remote JWKS fetching,
  SSRF, malformed JWK parsing — **none of which this package touches.** It uses
  one import and two calls with a static key and no JWKS. Every one of those
  advisories is fixed in 2.15.1; python-jose's critical is fixed in nothing.

  **So the floor carries the safety and has to keep moving.** `>=2.14.0` for the
  DER bypass, `>=2.15.0` for CVE-2026-102275 and CVE-2026-101918. It is
  `>=2.15.1`, and `tests/test_pyjwt_backend.py` asserts the *behaviours* the
  floor buys rather than the version string, so lowering it goes red.

  **For callers, this is source-compatible unless you caught a `jose`
  exception.** `create_access_token` and `decode_access_token` keep their
  signatures and return types, and `decode_access_token` still raises
  `InvalidTokenError`. See the new `AuthError` below for the sign path.

- **Default `SECRET_KEY` lengthened to 49 bytes.** It was 31 — one byte under
  RFC 7518 §3.2's 32-byte floor for SHA-256 — so PyJWT emitted
  `InsecureKeyLengthWarning` on every call in development. A warning that fires
  constantly on a value nobody is meant to keep trains people to ignore the
  warning. Only affects deployments that never set `SECRET_KEY`, which were
  already signing with a published constant.

### Security

- **An HMAC algorithm now refuses asymmetric key material
  (`InsecureKeyError`), at both the signing and the verifying call site.**

  An HMAC algorithm uses whatever key it is handed as the shared secret. Hand it
  a **public** key and every token is forgeable by anyone holding that key,
  which for a public key is everyone. Reproduced against python-jose 3.5.0
  before the guard existed:

  ```
  decode_access_token(forged, key_ring=KeyRing(active=der_public_key))
    -> sub='attacker'
  ```

  **The guard stays after the migration, because PyJWT's fix does not cover the
  shape this package has.** Two independent reasons, both measured on PyJWT
  2.15.1:

  ```
  jwt.decode(forged, der)                    -> InvalidKeyError  (refused)
  jwt.decode(forged, der.decode("latin-1"))  -> sub='attacker'   (ACCEPTED)
  ```

  `prepare_key` calls `force_bytes`, which is `key.encode("utf-8")` for a
  `str` — and `AuthSettings.SECRET_KEY` is annotated `str`, reachable from DER
  only via latin-1. So the bytes PyJWT finally HMACs with no longer parse as
  DER. PEM and OpenSSH survive that same path only because they are ASCII and
  the re-encoding is a no-op; DER is the one encoding it destroys.

  And **without PyJWT's `crypto` extra the DER check does not run at all**:
  `_is_der_key` opens with `if not has_crypto: return False`, so a plain
  `pip install PyJWT` accepts DER `bytes` as well. We do not require that extra.

  An attacker derives those bytes from the public key exactly as
  deterministically as the server does, and a `str` is the only way DER gets
  into this package's configuration — so on its own the upstream fix would have
  left the reachable path open.

  **The default configuration was never affected.** `ALGORITHM` defaults to
  `HS256` with a shared secret, `generate_key()` produces random symmetric
  secrets, and every decode passes an explicit single-algorithm allowlist
  (`algorithms=[ALGORITHM]`) — so `alg: none` and algorithm *substitution* were
  already rejected, verified by test. The reachable path was a deployer
  supplying asymmetric key material as the verification key, which
  `KeyRing(active=...)` accepted because its `str` annotation is not enforced.

  `InsecureKeyError` is deliberately **not** an `InvalidTokenError`: a caller
  treats an invalid token as a 401 and carries on, and this is a
  misconfiguration that makes every token forgeable. An asymmetric algorithm
  with a keypair (`RS256` and a PEM) is the correct setup and is untouched — the
  check keys off the algorithm, not the key.

- **`pydantic-settings` floor raised to `>=2.14.2`** for **CVE-2026-58203 /
  GHSA-4xgf-cpjx-pc3j (MODERATE)**: `NestedSecretsSettingsSource` followed
  symlinks out of `secrets_dir`, allowing a local file read and bypassing
  `secrets_dir_max_size` (introduced 2.12.0, fixed 2.14.2). Not reachable through
  `AuthSettings`, which declares no `secrets_dir` — but the old `>=2.0.0` floor
  admitted an affected version into a consumer's tree, and **2.14.1 was what this
  checkout had installed**, so the exposure was real rather than theoretical.

  The other four python-jose advisories (CVE-2024-33663, CVE-2024-33664,
  CVE-2024-29370, CVE-2016-7036) were all excluded by the old `>=3.5.0` floor
  and are moot now that the dependency is gone.

### Added

- **`AuthError`**, the base for every error this package raises, and
  **`TokenCreationError`** for a token that cannot be signed. Both exported from
  the package root.

  `create_access_token` used to let the JWT library's own exception through — so
  a caller wanting to handle a bad `ALGORITHM` had to import that library and
  name a type from it. `decode_access_token` wrapped its errors and the sign
  path did not, which is a check on one of two paths. `AuthError` is now the
  whole contract and the backend is an implementation detail.

  `TokenCreationError` is **not** an `InvalidTokenError`: a token that cannot be
  created is the server's setup being wrong, and answering 401 to it would blame
  the client for an operator's mistake.

  A `TypeError` from an unserializable claim still propagates, deliberately —
  that is the caller's payload, not the server's configuration.

- `InsecureKeyError`, exported from the package root.
- `tests/test_hmac_key_guard.py` — the attack is forged by hand with `hmac`,
  because neither library will produce it any more and borrowing one to build it
  would make the file assert a library's willingness to help rather than our
  refusal to accept. The **false-positive** half is the larger one: `0x30` is
  the DER SEQUENCE tag and also ASCII `"0"`, so a first-byte check would refuse
  a secret beginning with that character, and refusing a legitimate secret
  breaks a working deployment. The detector requires a self-consistent ASN.1
  length covering the whole buffer.
- `tests/test_pyjwt_backend.py` — that the backend is PyJWT and not this
  same-named module, that python-jose is no longer declared, and one behaviour
  per protection the floor buys.

  Ten decisions in this release were verified by breaking each one in turn and
  checking the right tests went red. One did not: making `InsecureKeyError` a
  subclass of `InvalidTokenError` left all 75 tests green, because
  `pytest.raises(InsecureKeyError)` passes either way — so the thing that error
  exists for was never actually asserted. The hierarchy is checked explicitly
  now.

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
