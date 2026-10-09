# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Known constraints

- `bcrypt` is pinned `<5.0` due to a `passlib` 1.7.4 incompatibility.
  This is a known limitation, not a vulnerability.

- **`python-jose` carries an unfixed critical advisory, and we guard around it.**
  CVE-2026-85394 / GHSA-3qf3-8w2g-rqmx: the guard python-jose added in 3.4.0
  against using an asymmetric public key as an HMAC secret is bypassable when
  the key is DER-encoded. The advisory records `last_affected: 3.5.0` with **no
  fixed version**, and 3.5.0 is the newest release — so pinning higher is not an
  option.

  `nodus-auth` performs that check itself and raises `InsecureKeyError`, at both
  the signing and verifying call sites. Reproduced against 3.5.0 and pinned by
  `tests/test_hmac_key_guard.py`.

  **What this means for you.** The default configuration — `HS256` with a shared
  secret from `generate_key()` — was never exposed, and every decode passes an
  explicit single-algorithm allowlist, so algorithm substitution and `alg: none`
  are rejected. If you configure an HMAC algorithm, the key must be a secret; if
  you want a keypair, use an asymmetric algorithm such as `RS256`. Supplying a
  keypair under `HS*` is now an error rather than a silent forgery.

  Migrating off `python-jose` is under evaluation, since the project has had a
  critical advisory unfixed and 3.5.0 remains its latest release.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately to: **shawnknight@the-master-plan.com**

Include a description, steps to reproduce, and potential impact.
You will receive a response within 72 hours.
